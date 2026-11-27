use {super::*, std::sync::atomic::AtomicU64};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_temp_dir() -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "veil-sqlite-test-{}-{}-{n}",
        std::process::id(),
        now_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn sqlite_init_applies_wal_and_0600_perms() {
    let dir = unique_temp_dir();
    let worker_dir = dir.clone();
    let conn = tokio::task::spawn_blocking(move || open_sqlite_blocking(&worker_dir))
        .await
        .unwrap()
        .unwrap();
    let journal: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(journal.to_lowercase(), "wal");
    let synchronous: i64 = conn
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .unwrap();
    assert_eq!(synchronous, 1);
    let busy: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .unwrap();
    assert_eq!(busy, SQLITE_BUSY_TIMEOUT_MS);
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, SQLITE_USER_VERSION);
    drop(conn);

    let outcome = init_sqlite(&dir).await.unwrap();
    assert!(outcome.sqlite_ok);

    assert_eq!(file_mode(&dir.join(SQLITE_FILE_NAME)), 0o600);
    for suffix in ["-wal", "-shm"] {
        let p = dir.join(format!("{SQLITE_FILE_NAME}{suffix}"));
        if p.exists() {
            assert_eq!(file_mode(&p), 0o600, "{}", p.display());
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn no_space_classifier_detects_sqlite_full() {
    let full = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(13),
        Some("database or disk is full".to_string()),
    );
    assert!(is_no_space_error(&anyhow::Error::from(full)));
    assert!(is_no_space_error(&anyhow::anyhow!(
        "ENOSPC: No space left on device"
    )));
    assert!(!is_no_space_error(&anyhow::anyhow!("boom")));
}

#[test]
fn disk_full_degrades_without_crash() {
    let full = anyhow::Error::from(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(13),
        Some("database or disk is full".to_string()),
    ));
    let outcome =
        outcome_from_open_result(PathBuf::from("/data/metrics.sqlite"), Err(full)).unwrap();
    assert!(!outcome.sqlite_ok);
    assert!(outcome.sqlite_error.as_deref().unwrap().contains("ENOSPC"));
}

#[test]
fn non_disk_full_error_propagates() {
    let outcome = outcome_from_open_result(
        PathBuf::from("/data/metrics.sqlite"),
        Err(anyhow::anyhow!("boom")),
    );
    assert!(outcome.is_err());
}

#[tokio::test]
async fn http_client_singleton_shared_across_forwards() {
    let dir = unique_temp_dir();
    let env = std::collections::HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        ("DATA_DIR".to_string(), dir.to_string_lossy().into_owned()),
    ]);
    let state = AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("m.sqlite"),
        },
    );
    let again = state.clone();
    assert!(Arc::ptr_eq(&state.http_client, &again.http_client));
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    let url = format!("http://{addr}/");
    for _ in 0..2 {
        let resp = again.http_client.get(&url).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }
    handle.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn http_client_build_failure_visible() {
    let captured: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let client = finish_http_client_with(
        || Err("injected-construct-failure".to_string()),
        |msg| captured.lock().unwrap().push(msg.to_string()),
    );
    let logs = captured.lock().unwrap();
    assert_eq!(logs.len(), 1, "注入失败须恰一条 warn");
    assert!(
        logs[0].contains("injected-construct-failure"),
        "warn 须含失败原因，实际 {:?}",
        logs[0]
    );
    assert!(
        client.get("http://127.0.0.1:1/").build().is_ok(),
        "降级客户端须仍可用"
    );
}

#[tokio::test]
async fn stream_client_has_no_total_timeout() {
    // 流式 client 无总超时——总时长 > `HTTP_TIMEOUT_SECS` 的慢流仍两帧俱达。
    let cfg = config_with_timeout_secs(1);
    let stream = build_stream_http_client(&cfg);
    let (url, server) = slow_sse_server(std::time::Duration::from_millis(1500)).await;
    let resp = stream
        .get(&url)
        .send()
        .await
        .expect("流式 client 须拿到响应头");
    let body = resp.bytes().await.expect("长流不得因总超时被截断");
    server.abort();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("data: first") && text.contains("data: second"),
        "两帧均须到达，实际 {text:?}"
    );
}

#[tokio::test]
async fn nonstream_keeps_total_timeout() {
    // 非流 client 保持 `HTTP_TIMEOUT_SECS` 总超时——慢体读取映射为报错。
    let cfg = config_with_timeout_secs(1);
    let client = build_http_client(&cfg);
    let (url, server) = slow_sse_server(std::time::Duration::from_millis(1500)).await;
    let resp = client.get(&url).send().await.expect("须先拿到响应头");
    let err = resp.bytes().await;
    server.abort();
    assert!(
        err.is_err(),
        "非流 client 须按 HTTP_TIMEOUT_SECS 超时，实际 {:?}",
        err.map(|b| b.len())
    );
}

/// 测试装配：以指定 `HTTP_TIMEOUT_SECS` 构造合法 `Config`。
fn config_with_timeout_secs(secs: u64) -> Config {
    let env = std::collections::HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        ("HTTP_TIMEOUT_SECS".to_string(), secs.to_string()),
    ]);
    Config::load_from(&env).expect("测试配置须合法")
}

/// 测试上游：响应头后先发一帧，`delay` 后再发第二帧并关闭（总时长 > 超时预算）。
async fn slow_sse_server(delay: std::time::Duration) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let head =
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(b"data: first\n\n").await.is_err() {
                continue;
            }
            let _ = sock.flush().await;
            tokio::time::sleep(delay).await;
            let _ = sock.write_all(b"data: second\n\n").await;
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

#[test]
fn vault_and_detector_singletons_shared_across_clones() {
    let env = std::collections::HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
    ]);
    let state = AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from("/tmp/x.sqlite"),
        },
    );
    let again = state.clone();
    assert!(Arc::ptr_eq(&state.vault, &again.vault));
    assert!(Arc::ptr_eq(&state.detector, &again.detector));
    // 同一 vault 注册复用：跨请求同秘密同 token。
    let first = state.vault.register("跨请求秘密-abc123").unwrap();
    let second = again.vault.register("跨请求秘密-abc123").unwrap();
    assert_eq!(first, second);
    assert!(first.starts_with("__CRED_"));
}

/// 测试后端：`clear_cache` 即上锁，使 `lock` 清理后可断言凭据取用失败。
#[derive(Debug)]
struct LockableKeePass {
    unlocked: AtomicBool,
}

impl LockableKeePass {
    fn new(unlocked: bool) -> Self {
        Self {
            unlocked: AtomicBool::new(unlocked),
        }
    }
}

impl KeePassBackend for LockableKeePass {
    fn is_unlocked(&self) -> bool { self.unlocked.load(Ordering::SeqCst) }

    fn fetch_entry(
        &self,
        title: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::keepass::EntrySnapshot>> + Send + '_>,
    > {
        Box::pin(async move {
            if !self.unlocked.load(Ordering::SeqCst) {
                return Err(VeilError::Unavailable {
                    message: "KeePass 密码库未载入".to_string(),
                });
            }
            Ok(crate::keepass::EntrySnapshot {
                title,
                username: "u".to_string(),
                password: "p".to_string(),
                url: String::new(),
                custom: Vec::new(),
            })
        })
    }

    fn clear_cache(&self) { self.unlocked.store(false, Ordering::SeqCst); }
}

fn state_with_keepass(backend: Arc<dyn KeePassBackend>) -> AppState {
    let env = std::collections::HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
    ]);
    AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from("/tmp/x.sqlite"),
        },
    )
    .with_keepass(backend)
}

#[tokio::test]
async fn lock_cleanup_clears_vault() {
    use crate::service::matrix::{MatrixBot, MatrixBranch, TextCommand};
    let state = state_with_keepass(Arc::new(LockableKeePass::new(true)));
    state.vault.register("lock-secret-1234").unwrap();
    state
        .pending
        .insert(crate::approval::PendingRecord::new("k1", "reason"));
    state
        .approval
        .submit_branch("$evt-lock", MatrixBranch::Credential)
        .await;
    let reply =
        MatrixBot::handle_text_command_full(&state.approval, TextCommand::Lock, &state).await;
    let reply = reply.expect("lock 须有回执");
    assert!(!reply.contains("已锁定"), "lock 不得宣称已锁定: {reply}");
    assert!(
        reply.contains("未决 1 单已按拒绝落定"),
        "lock 须报告按拒绝落定的票数: {reply}"
    );
    assert!(state.vault.is_empty(), "lock 后口令缓存须清空");
    assert_eq!(state.pending.len(), 0, "lock 后内存 pending 须清零");
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "lock 后矩阵 pending 须清零"
    );
    assert!(
        state.keepass.fetch_entry("网易".to_string()).await.is_err(),
        "lock 后凭据取用须失败"
    );
}

#[tokio::test]
async fn lock_clears_master_password_cache() {
    // lock 清理须清除并零化 TPM 派生主密码缓存；取用须重新经 TPM 解封。
    let dir = unique_temp_dir();
    let db_path = dir.join("lock-mpc.kdbx");
    // Mock TPM 的解封值即 `veil-dev-mock-tpm-seal`（见 `service/tpm.rs::startup_tpm_in`）。
    crate::keepass::build_test_kdbx(
        &db_path,
        b"veil-dev-mock-tpm-seal",
        &[("网易", "u", "s", "", vec![])],
    );
    let (provider, cache) = crate::keepass::tpm_password_provider_with_cache(dir.clone(), true);
    let backend = crate::keepass::RealKeePass::new(db_path, None, provider)
        .with_master_password_cache(cache.clone());
    let state = state_with_keepass(Arc::new(backend));
    state
        .keepass
        .fetch_entry("网易".to_string())
        .await
        .expect("首次取用须经 TPM 解封成功");
    assert!(cache.has_cached(), "取用后 TPM 主密码缓存须已填充");
    assert!(
        crate::service::matrix::GatewayCleanup::master_password_cached(&state),
        "status 须能读到真实的主密码缓存载入状态"
    );
    let reply = crate::service::matrix::MatrixBot::handle_text_command_full(
        &state.approval,
        crate::service::matrix::TextCommand::Lock,
        &state,
    )
    .await
    .expect("lock 须有回执");
    assert!(
        reply.contains("主密码缓存: 已载入→未载入"),
        "lock 回执须报告主密码缓存清理前后状态: {reply}"
    );
    assert!(!cache.has_cached(), "lock 后 TPM 主密码缓存须清空");
    assert!(
        !crate::service::matrix::GatewayCleanup::master_password_cached(&state),
        "lock 后 status 须读到未载入"
    );
    state
        .keepass
        .fetch_entry("网易".to_string())
        .await
        .expect("lock 后取用须重新经 TPM 解封成功");
    assert!(cache.has_cached(), "重新解封后缓存须回填");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn forget_clears_token_map_counted() {
    use crate::service::matrix::{MatrixBot, TextCommand};
    let state = state_with_keepass(Arc::new(LockableKeePass::new(true)));
    state.vault.register("forget-secret-a1").unwrap();
    state.vault.register("forget-secret-b2").unwrap();
    assert_eq!(state.vault.len(), 2);
    let reply = MatrixBot::handle_text_command_full(&state.approval, TextCommand::Forget, &state)
        .await
        .expect("forget 须有回执");
    assert!(reply.contains('2'), "回执计数须与清理数一致: {reply}");
    assert!(state.vault.is_empty(), "forget 后 token 映射须清空");
}

#[test]
fn audit_policy_injected_singleton_reused() {
    let state = state_with_keepass(Arc::new(LockableKeePass::new(true)));
    let policy = Arc::new(crate::service::audit::AuditPolicy::default_policy());
    let state = state.with_audit_policy(policy.clone());
    let cloned = state.clone();
    assert!(Arc::ptr_eq(&state.audit_policy, &cloned.audit_policy));
    assert!(Arc::ptr_eq(&state.audit_policy, &policy));
}

fn minimal_env() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
    ])
}

fn outcome_for(dir: &Path) -> SqliteOutcome {
    SqliteOutcome {
        sqlite_ok: true,
        sqlite_error: None,
        db_path: dir.join("m.sqlite"),
    }
}

/// 损坏注册表加载失败须上抛拒启动（`error` 日志 + `new` panic），不得静默空表。
#[test]
fn registry_load_failure_fails_startup() {
    let dir = unique_temp_dir();
    let path = dir.join("caller_registry.json");
    std::fs::write(&path, b"{ not a registry").unwrap();
    let mut env = minimal_env();
    env.insert(
        "CALLER_REGISTRY_PATH".to_string(),
        path.to_string_lossy().into_owned(),
    );
    let err = AppState::try_new(Config::load_from(&env).unwrap(), outcome_for(&dir)).unwrap_err();
    assert!(
        err.to_string().contains("注册表"),
        "错误须指明注册表加载失败: {err}"
    );
    // 生产入口 `new` 以 panic 终止启动（fail-fast，exit 非零）。
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = AppState::new(Config::load_from(&env).unwrap(), outcome_for(&dir));
    }));
    assert!(panicked.is_err(), "损坏注册表须拒绝启动");
    std::fs::remove_dir_all(&dir).ok();
}

/// 完整性 sha256 失配同样拒启动；合法注册表正常启动、行为不变。
#[test]
fn registry_corrupt_startup_rejected() {
    let dir = unique_temp_dir();
    let path = dir.join("caller_registry.json");
    std::fs::write(&path, br#"{"entries":{},"sha256":"deadbeef"}"#).unwrap();
    let mut env = minimal_env();
    env.insert(
        "CALLER_REGISTRY_PATH".to_string(),
        path.to_string_lossy().into_owned(),
    );
    assert!(
        AppState::try_new(Config::load_from(&env).unwrap(), outcome_for(&dir)).is_err(),
        "sha256 失配须拒绝启动"
    );
    CallerRegistry::empty().save_to(&path).unwrap();
    let state = AppState::try_new(Config::load_from(&env).unwrap(), outcome_for(&dir)).unwrap();
    assert_eq!(state.registry_path, path, "合法注册表正常启动");
    std::fs::remove_dir_all(&dir).ok();
}

/// 自定义 PII 规则在 `AppState` 构建时注入运行时检测器（非仅启动校验）。
#[test]
fn custom_pii_runtime_injected() {
    let dir = unique_temp_dir();
    let rules = dir.join("rules.json");
    std::fs::write(
        &rules,
        r#"[{"name":"emp_no","pattern":"(?P<emp_no>工号\\d{6})"}]"#,
    )
    .unwrap();
    let mut env = minimal_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        rules.to_string_lossy().into_owned(),
    );
    let state = AppState::try_new(Config::load_from(&env).unwrap(), outcome_for(&dir)).unwrap();
    assert!(
        state
            .detector
            .custom_names_snapshot()
            .iter()
            .any(|i| i == "emp_no"),
        "配置的自定义规则须在运行时注入生效"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// 配置自定义规则/字典 → 运行时命中 → 健康面可观测的端到端回归。
#[tokio::test]
async fn custom_pii_e2e_hit_visible() {
    let dir = unique_temp_dir();
    let rules = dir.join("rules.json");
    std::fs::write(
        &rules,
        r#"[{"name":"emp_no","pattern":"(?P<emp_no>工号\\d{6})"}]"#,
    )
    .unwrap();
    let dict = dir.join("dict.txt");
    std::fs::write(&dict, "张三\n").unwrap();
    let mut env = minimal_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        rules.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        dict.to_string_lossy().into_owned(),
    );
    let state = AppState::try_new(Config::load_from(&env).unwrap(), outcome_for(&dir)).unwrap();
    let hits = state
        .detector
        .scan_spans(
            "员工工号123456，联系张三。",
            &std::collections::HashMap::new(),
        )
        .await;
    assert!(
        hits.iter().any(|h| h.0 == "emp_no"),
        "运行时命中须含自定义 kind: {hits:?}"
    );
    assert!(
        hits.iter().any(|h| h.1 == "张三"),
        "字典命中须在运行时可见: {hits:?}"
    );
    let body = crate::handler::health_handler(axum::extract::State(state.clone()))
        .await
        .0;
    assert_eq!(
        body["pii_custom_disabled"], 0,
        "命中在健康面可见且无停用: {body}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn app_state_debug_redacts_conversation_secret() {
    // `AppState` 手工 `Debug` 不得泄漏 `conversation_secret` 的字节/hex。
    let mut env = minimal_env();
    env.insert("PII_SCOPE_MODE".to_string(), "conversation".to_string());
    let state = AppState::try_new(
        Config::load_from(&env).unwrap(),
        outcome_for(Path::new("/tmp")),
    )
    .unwrap();
    assert_eq!(
        state.conversation_secret.len(),
        32,
        "conversation 模式须 32 字节密钥"
    );
    let secret = &*state.conversation_secret;
    let debug = format!("{state:?}");
    assert!(
        !debug.contains(&hex::encode(secret)),
        "Debug 不得泄漏密钥 hex: {debug}"
    );
    assert!(
        !debug.contains(&format!("{secret:?}")),
        "Debug 不得泄漏密钥字节: {debug}"
    );
    assert!(debug.contains("[redacted]"), "须显式标注已脱敏");
}

#[test]
fn conversation_secret_generated_in_request_mode() {
    // `request` 模式同样无条件生成 32 字节会话密钥（别名表键与出站 HMAC 依赖它，
    // 空密钥会让域分离失效）。
    let state = AppState::try_new(
        Config::load_from(&minimal_env()).unwrap(),
        outcome_for(Path::new("/tmp")),
    )
    .expect("AppState 装配须成功");
    assert!(
        !state.config.pii_scope_mode.is_conversation(),
        "前置：默认 request 模式"
    );
    assert!(
        state.conversation_scope_store.is_none(),
        "request 模式 MUST NOT 装配 ConversationScopeStore"
    );
    assert_eq!(
        state.conversation_secret.len(),
        32,
        "request 模式亦须 32 字节密钥"
    );
    assert!(
        state.conversation_secret.iter().any(|b| *b != 0),
        "密钥不得全零"
    );
}

#[test]
fn request_log_shares_metrics_db_path() {
    // 请求日志与 metrics 同库同文件（不同表），且沿用配置面的开关与保留期。
    let dir = unique_temp_dir();
    let state = AppState::try_new(
        Config::load_from(&minimal_env()).unwrap(),
        outcome_for(&dir),
    )
    .expect("AppState 装配须成功");
    assert_eq!(
        state.request_log.db_path(),
        state.db_path.as_path(),
        "请求日志须与 metrics 共用 metrics.sqlite"
    );
    assert_eq!(
        state.request_log.enabled(),
        state.config.request_log_enabled,
        "启用值须取自配置"
    );
    assert_eq!(
        state.request_log.retention_days(),
        state.config.request_log_retention_days,
        "保留期须取自配置"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn conversation_secret_fallback_is_full_nonzero_32_bytes() {
    // SysRng 失败回退须产出完整 32 字节且无零填充（不留半成键）。
    let (buf, os_ok) = conversation_secret_bytes(|_| false);
    assert!(!os_ok, "注入失败须报告熵源不可用");
    assert_eq!(buf.len(), 32);
    assert!(buf.iter().any(|b| *b != 0), "回退密钥不得全零");
    assert!(
        buf[16..].iter().any(|b| *b != 0),
        "回退不得遗留上半 16 字节为零"
    );
    // 成功分支：原样返回注入填充值。
    let (ok, flag) = conversation_secret_bytes(|b| {
        b.fill(0xAB);
        true
    });
    assert!(flag);
    assert!(ok.iter().all(|b| *b == 0xAB));
}

#[tokio::test]
async fn lock_cleanup_reports_zero_pii_scopes_in_request_mode() {
    // request 模式不装配会话作用域存储：回执中的 0 是真实值（None → 0），非占位符。
    let state = state_with_keepass(Arc::new(LockableKeePass::new(true)));
    assert!(
        state.conversation_scope_store.is_none(),
        "request 模式须不装配 ConversationScopeStore"
    );
    let reply = crate::service::matrix::MatrixBot::handle_text_command_full(
        &state.approval,
        crate::service::matrix::TextCommand::Lock,
        &state,
    )
    .await
    .expect("lock 须有回执");
    assert!(
        reply.contains("PII 会话作用域 0 个"),
        "request 模式下回执须报 0 个作用域: {reply}"
    );
    assert!(
        reply.contains("会话别名 0 条"),
        "request 模式下别名表亦为空，回执须报 0 条: {reply}"
    );
}

#[tokio::test]
async fn lock_cleanup_clears_pii_conversation_scopes() {
    // conversation 模式：lock 须真的清空会话作用域并报真实条数。
    let state = state_with_keepass(Arc::new(LockableKeePass::new(true)));
    let store = Arc::new(crate::service::redaction::ConversationScopeStore::new(
        8,
        std::time::Duration::from_secs(1800),
    ));
    let keys = [0u8, 1, 2].map(|i| {
        crate::service::redaction::conversation_key::scoped_key(
            b"lock-scope-secret",
            "tenant-lock",
            &format!("conv-lock-{i}"),
        )
    });
    for key in &keys {
        store.get_or_insert(key);
    }
    assert_eq!(store.len(), keys.len(), "前置：须有 3 条会话作用域");
    let mut sampled = state.clone();
    sampled.conversation_scope_store = Some(Arc::clone(&store));

    // 别名表：预置条目以断言「lock 同时清空两表并分别报条数」。
    let alias = sampled.session_alias_map.clone();
    let alias_keys = [0u8, 1].map(|i| {
        crate::service::redaction::conversation_key::scoped_key(
            b"lock-alias-secret",
            "tenant-lock",
            &format!("resp-lock-{i}"),
        )
    });
    for key in &alias_keys {
        alias.bind(
            b"lock-alias-secret",
            "tenant-lock",
            &format!("upstream-{}", key.as_str()),
            key,
        );
    }
    assert_eq!(alias.len(), alias_keys.len(), "前置：须有 2 条别名");

    let report = crate::service::matrix::GatewayCleanup::lock_cleanup(&sampled);
    assert_eq!(report.pii_scopes_cleared, keys.len(), "须报真实清理条数");
    assert_eq!(store.len(), 0, "lock 后会话作用域须清空");
    assert_eq!(
        report.alias_entries_cleared,
        alias_keys.len(),
        "别名表清理条数须与作用域条数分别可观测"
    );
    assert_eq!(alias.len(), 0, "lock 后别名表须清空");

    let reply = crate::service::matrix::MatrixBot::handle_text_command_full(
        &sampled.approval,
        crate::service::matrix::TextCommand::Lock,
        &sampled,
    )
    .await
    .expect("lock 须有回执");
    assert!(
        reply.contains("PII 会话作用域 0 个"),
        "二次 lock 时作用域已空，回执须报 0: {reply}"
    );
    assert!(
        reply.contains("会话别名 0 条"),
        "二次 lock 时别名表已空，回执须报 0: {reply}"
    );
    assert!(
        reply.contains("口令缓存"),
        "既有口令缓存文案须保留: {reply}"
    );
    assert!(
        reply.contains("未决 0 单已按拒绝落定"),
        "既有未决票数文案须保留: {reply}"
    );
}

#[derive(Debug, Default)]
struct ReloadProbeKeePass {
    reloads: std::sync::atomic::AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}

impl KeePassBackend for ReloadProbeKeePass {
    fn is_unlocked(&self) -> bool { true }

    fn fetch_entry(
        &self,
        title: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::keepass::EntrySnapshot>> + Send + '_>,
    > {
        Box::pin(async move {
            Ok(crate::keepass::EntrySnapshot {
                title,
                username: String::new(),
                password: String::new(),
                url: String::new(),
                custom: Vec::new(),
            })
        })
    }

    fn reload(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<crate::keepass::ReloadOutcome>>>
                + Send
                + '_,
        >,
    > {
        self.reloads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let fail = self.fail.load(std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            if fail {
                return Err(crate::error::VeilError::KeePass {
                    message: "probe reload failure".to_string(),
                });
            }
            Ok(None)
        })
    }
}

#[tokio::test]
async fn reload_keepass_clears_vault_and_reports_count() {
    let backend = Arc::new(ReloadProbeKeePass::default());
    let state = state_with_keepass(backend.clone());
    state.vault.register("reload-secret-1234").unwrap();
    state.vault.register("reload-secret-5678").unwrap();
    let report = state.reload_keepass().await.expect("重载须成功");
    assert_eq!(backend.reloads.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(report.tokens_invalidated, 2);
    assert_eq!(report.db_path, None);
    assert!(state.vault.is_empty(), "成功重载须作废全部 token");
}

#[tokio::test]
async fn reload_keepass_failure_keeps_tokens() {
    let backend = Arc::new(ReloadProbeKeePass::default());
    backend
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let state = state_with_keepass(backend);
    let token = state.vault.register("reload-secret-9012").unwrap();
    assert!(state.reload_keepass().await.is_err(), "失败重载须返回错误");
    assert_eq!(
        state.vault.restore_one(&token).as_deref(),
        Some("reload-secret-9012"),
        "失败重载不得清空既有 token 映射"
    );
}

#[tokio::test]
async fn reload_keepass_elapsed_covers_backend_wait() {
    let backend = Arc::new(BlockingReloadKeePass::new());
    let state = state_with_keepass(backend.clone());
    let task = tokio::spawn({
        let state = state.clone();
        async move { state.reload_keepass().await }
    });
    let _started = backend.started.acquire().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    backend.release.add_permits(1);
    let report = task.await.expect("重载任务须完成").expect("重载须成功");
    assert!(
        report.elapsed_ms >= 50,
        "elapsed_ms 须覆盖后端等待（实际 {}ms）",
        report.elapsed_ms
    );
}

#[derive(Debug)]
struct BlockingReloadKeePass {
    calls: std::sync::atomic::AtomicUsize,
    started: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

impl BlockingReloadKeePass {
    fn new() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            started: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

impl KeePassBackend for BlockingReloadKeePass {
    fn is_unlocked(&self) -> bool { true }

    fn fetch_entry(
        &self,
        title: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::keepass::EntrySnapshot>> + Send + '_>,
    > {
        Box::pin(async move {
            Ok(crate::keepass::EntrySnapshot {
                title,
                username: String::new(),
                password: String::new(),
                url: String::new(),
                custom: Vec::new(),
            })
        })
    }

    fn reload(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<crate::keepass::ReloadOutcome>>>
                + Send
                + '_,
        >,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let started = self.started.clone();
        let release = self.release.clone();
        Box::pin(async move {
            started.add_permits(1);
            let _permit = release.acquire().await;
            Ok(None)
        })
    }
}

#[tokio::test]
async fn hangup_loop_reloads_each_event_and_stops_on_shutdown() {
    let backend = Arc::new(ReloadProbeKeePass::default());
    let state = state_with_keepass(backend.clone());
    state.vault.register("signal-secret-1234").unwrap();
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task = tokio::spawn(crate::state::hangup_reload_loop(
        state.clone(),
        busy.clone(),
        events_rx,
        shutdown_rx,
    ));
    events_tx.send(()).await.unwrap();
    for _ in 0..200 {
        if backend.reloads.load(std::sync::atomic::Ordering::SeqCst) >= 1
            && !busy.load(std::sync::atomic::Ordering::SeqCst)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(crate::state::forward_if_idle(&busy, &events_tx).is_ok());
    for _ in 0..100 {
        if backend.reloads.load(std::sync::atomic::Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        backend.reloads.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "每个信号事件恰触发一次重载"
    );
    assert!(state.vault.is_empty());
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("停机广播后 SIGHUP 循环须退出")
        .expect("循环任务不得 panic");
}

#[tokio::test]
async fn hangup_loop_skips_events_while_reload_is_running() {
    let backend = Arc::new(BlockingReloadKeePass::new());
    let state = state_with_keepass(backend.clone());
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task = tokio::spawn(crate::state::hangup_reload_loop(
        state,
        busy.clone(),
        events_rx,
        shutdown_rx,
    ));
    assert!(crate::state::forward_if_idle(&busy, &events_tx).is_ok());
    let _started = backend.started.acquire().await.unwrap();
    assert_eq!(
        crate::state::forward_if_idle(&busy, &events_tx),
        Err(crate::state::ForwardSkip::Busy),
        "重载进行中信号须被单飞闸丢弃"
    );
    backend.release.add_permits(1);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        backend.calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "重载进行中收到的信号须跳过，不得叠加解密"
    );
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("停机广播后 SIGHUP 循环须退出")
        .expect("循环任务不得 panic");
}

#[tokio::test]
async fn reload_keepass_leaves_pending_pii_and_aliases_intact() {
    let mut env = minimal_env();
    env.insert("PII_SCOPE_MODE".to_string(), "conversation".to_string());
    let state = AppState::new(
        Config::load_from(&env).unwrap(),
        outcome_for(Path::new("/tmp")),
    )
    .with_keepass(Arc::new(ReloadProbeKeePass::default()));
    state
        .pending
        .insert(crate::approval::PendingRecord::new("reload-k", "reason"));
    let store = state
        .conversation_scope_store
        .as_ref()
        .expect("conversation 模式须装配会话作用域");
    let key = crate::service::redaction::conversation_key::ConversationKey::for_test("reload-conv");
    let _ = store.get_or_insert(&key);
    let _ = state.session_alias_map.bind(
        state.conversation_secret.as_ref(),
        "tenant",
        "$upstream",
        &key,
    );
    let before = (
        state.pending.len(),
        store.len(),
        state.session_alias_map.len(),
    );
    assert_eq!(before, (1, 1, 1), "前置：三类状态各 1 条");
    state.reload_keepass().await.expect("重载须成功");
    assert_eq!(
        (
            state.pending.len(),
            store.len(),
            state.session_alias_map.len()
        ),
        before,
        "重载不得清理 pending / PII 会话作用域 / 会话别名"
    );
}
