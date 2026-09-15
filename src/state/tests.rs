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
    // T3/D3：流式 client 无总超时——总时长 > `HTTP_TIMEOUT_SECS` 的慢流仍两帧俱达。
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
    // T3/D3：非流 client 保持 `HTTP_TIMEOUT_SECS` 总超时——慢体读取映射为报错。
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

/// T3 测试装配：以指定 `HTTP_TIMEOUT_SECS` 构造合法 `Config`。
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

/// T3 测试上游：响应头后先发一帧，`delay` 后再发第二帧并关闭（总时长 > 超时预算）。
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
    assert!(first.starts_with("__VG_CRED_"));
}

/// `C6` 测试后端：`clear_cache` 即上锁，使 `lock` 清理后可断言凭据取用失败。
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
                    message: "KeePass 未解锁".to_string(),
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
    assert!(reply.is_some_and(|s| s.contains("🔒 Proxy 已锁定")));
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
    // AUTH-5：lock 清理须清除并零化 TPM 派生主密码缓存；取用须重新经 TPM 解封。
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
    let _ = crate::service::matrix::GatewayCleanup::lock_cleanup(&state);
    assert!(!cache.has_cached(), "lock 后 TPM 主密码缓存须清空");
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

/// `CRD-1`：损坏注册表加载失败须上抛拒启动（`error` 日志 + `new` panic），不得静默空表。
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

/// `CRD-1`：完整性 sha256 失配同样拒启动；合法注册表正常启动、行为不变。
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

/// `DCD-1`：自定义 PII 规则在 `AppState` 构建时注入运行时检测器（非仅启动校验）。
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
            .contains(&"emp_no".to_string()),
        "配置的自定义规则须在运行时注入生效"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// `DCD-1`：配置自定义规则/字典 → 运行时命中 → 健康面可观测的端到端回归。
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
