#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split(
        "vault_ops.rs",
        include_str!("../vault_ops.rs"),
    );
    crate::test_support::file_len_under_800_or_split(
        "vault_ops/tests.rs",
        include_str!("tests.rs"),
    );
}

mod hardening;
mod retry;
mod rollback;
mod ttl;

use {
    super::{
        apply_register_approval,
        emergency_revoke,
        register_caller_extended,
        register_caller_with_approval,
        revoke_caller_with_approval,
    },
    crate::{
        config::Config,
        error::{Result, VeilError},
        registry::RegisterParams,
        service::{
            credential::{
                AppStateParts,
                RegistrationView,
                approval::{DecisionSlot, credential_decision_slot},
                handle_credential,
                test_support::*,
            },
            matrix::{MatrixBranch, ReactionInput, ReactionOutcome},
        },
        state::{AppState, SqliteOutcome},
    },
    std::{path::PathBuf, sync::Arc},
};

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "veil-vault-ops-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn state_with_registry_path(path: &std::path::Path) -> AppState {
    let path_str = path.to_string_lossy().into_owned();
    cred_state(&cred_env(&[("CALLER_REGISTRY_PATH", path_str.as_str())]))
}

fn params(path: &str, hash: &str) -> RegisterParams {
    RegisterParams {
        caller_path: path.to_string(),
        caller_hash: hash.to_string(),
        ..RegisterParams::default()
    }
}

/// 等待出现一个不在 `before` 中的 pending event（成功落定不清票，须排除旧票）。
async fn wait_new_event_id(state: &AppState, before: &[String]) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let ids = state.approval.pending_event_ids().await;
        if let Some(id) = ids.into_iter().find(|id| !before.contains(id)) {
            return id;
        }
        assert!(std::time::Instant::now() < deadline, "审批建单超时");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// 阻塞模式下发起注册并经真实 reaction 落定，返回注册结果。
async fn react_blocking_register(
    state: &AppState,
    path: &str,
    hash: &str,
    key: &str,
) -> Result<RegistrationView> {
    let source = hash.to_string();
    react_blocking_register_with(state, params(path, hash), source, key).await
}

/// 同 [`react_blocking_register`]，但由调用方给定完整注册参数（含请求声明的 TTL）。
async fn react_blocking_register_with(
    state: &AppState,
    p: RegisterParams,
    source: String,
    key: &str,
) -> Result<RegistrationView> {
    let before = state.approval.pending_event_ids().await;
    let worker = state.clone();
    let handle =
        tokio::spawn(async move { register_caller_with_approval(&worker, &p, &source).await });
    let event_id = wait_new_event_id(state, &before).await;
    let input = ReactionInput {
        target_event_id: event_id,
        key: key.to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 1,
    };
    let outcome = state
        .approval
        .on_reaction(&input, "@bot:example.com", "!r:example.com", 0)
        .await;
    assert!(
        matches!(outcome, ReactionOutcome::Applied { .. }),
        "reaction({key}) 须落定: {outcome:?}"
    );
    handle.await.expect("任务不崩")
}

async fn wait_until_revoked(state: &AppState, path: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if state
            .registry
            .read()
            .await
            .lookup_by_path(path)
            .is_some_and(|e| e.revoked)
        {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "吊销落定超时: {path}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_registration_view_rejects_revoked_entry() {
    let state = cred_state(&cred_env(&[]));
    let path = "/s/view-revoked.sh";
    register_caller_extended(&state, &params(path, "view-h1"), "view-src")
        .await
        .unwrap();
    let ok = super::read_registration_view(&state, path)
        .await
        .expect("未吊销条目须可回读");
    assert_eq!(ok.caller_path, path);
    assert!(!ok.revoked, "未吊销条目视图须保持非吊销");

    state.registry.write().await.revoke(path).unwrap();
    let err = super::read_registration_view(&state, path)
        .await
        .expect_err("已吊销条目不得作为批准结果返回");
    match &err {
        VeilError::Auth { message } => {
            assert!(
                message.contains("保持吊销"),
                "错误须说明条目保持吊销: {message}"
            );
        }
        other => panic!("已吊销条目须返回 Auth(403 语义)，实得: {other:?}"),
    }
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_save_not_blocking_reads() {
    use std::sync::atomic::Ordering;
    let dir = unique_dir("slow-save");
    let path = dir.join("caller_registry.json");
    let state = state_with_registry_path(&path);
    crate::registry::SAVE_TEST_DELAY_MS.store(500, Ordering::SeqCst);
    let starts_before = crate::registry::SAVE_TEST_WRITE_STARTS.load(Ordering::SeqCst);
    let s = state.clone();
    let handle = tokio::spawn(async move {
        register_caller_extended(&s, &params("/s/slow.sh", "slow-h1"), "slow-save-test").await
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while crate::registry::SAVE_TEST_WRITE_STARTS.load(Ordering::SeqCst) == starts_before {
        assert!(std::time::Instant::now() < deadline, "落盘未在超时内开始");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let t0 = std::time::Instant::now();
    let guard = state.registry().read().await;
    let waited = t0.elapsed();
    drop(guard);
    crate::registry::SAVE_TEST_DELAY_MS.store(0, Ordering::SeqCst);
    assert!(
        waited < std::time::Duration::from_millis(250),
        "读路径等待 {waited:?}，疑似被落盘/写锁阻塞"
    );
    handle.await.unwrap().unwrap();
    let loaded = crate::registry::CallerRegistry::load_from(&path).unwrap();
    assert_eq!(loaded.len(), 1, "落盘完成后文件须可加载");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn save_order_preserved() {
    let dir = unique_dir("save-order");
    let path = dir.join("caller_registry.json");
    let state = state_with_registry_path(&path);
    let mut set = tokio::task::JoinSet::new();
    for i in 0..8 {
        let s = state.clone();
        set.spawn(async move {
            register_caller_extended(
                &s,
                &params(&format!("/s/order-{i}.sh"), &format!("order-h{i}")),
                &format!("order-test-{i}"),
            )
            .await
        });
    }
    while let Some(r) = set.join_next().await {
        r.expect("任务不得 panic").expect("注册须成功");
    }
    let loaded = crate::registry::CallerRegistry::load_from(&path).unwrap();
    assert_eq!(loaded.len(), 8, "全序点须保证终态落盘含全部并发写");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_offlock_hash() {
    use std::sync::atomic::Ordering;
    let dir = unique_dir("offlock");
    let script = dir.join("job.sh");
    std::fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
    let registry_path = dir.join("caller_registry.json");
    let state = state_with_registry_path(&registry_path);
    crate::registry::BIND_READ_DELAY_MS.store(500, Ordering::SeqCst);
    crate::registry::BIND_READ_ENTERED.store(false, Ordering::SeqCst);
    let s = state.clone();
    let script_path = script.to_string_lossy().into_owned();
    let script_path_for_task = script_path.clone();
    let handle = tokio::spawn(async move {
        register_caller_extended(
            &s,
            &params(&script_path_for_task, "offlock-h"),
            "offlock-test",
        )
        .await
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !crate::registry::BIND_READ_ENTERED.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "脚本读取未在超时内开始"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let t0 = std::time::Instant::now();
    let guard = state.registry().write().await;
    let waited = t0.elapsed();
    drop(guard);
    crate::registry::BIND_READ_DELAY_MS.store(0, Ordering::SeqCst);
    assert!(
        waited < std::time::Duration::from_millis(250),
        "写锁被读盘阻塞 {waited:?}，读取须在锁外"
    );
    handle.await.unwrap().unwrap();
    let loaded = crate::registry::CallerRegistry::load_from(&registry_path).unwrap();
    let entry = loaded.lookup_by_path(&script_path).expect("注册条目须在");
    assert_eq!(
        entry.script_sha256,
        crate::registry::script_sha256_of_bytes(b"#!/bin/sh\necho hi\n"),
        "锁外完成后写入的 script_sha256 须为真实文件哈希"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn save_failure_observable() {
    let dir = unique_dir("save-fail");
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"not a dir").unwrap();
    let path = blocker.join("caller_registry.json");
    let state = state_with_registry_path(&path);
    let view = register_caller_extended(&state, &params("/s/fail.sh", "fail-h1"), "fail-test")
        .await
        .expect("落盘失败不得使注册接口失败（best-effort）");
    assert_eq!(view.caller_path, "/s/fail.sh");
    assert!(
        state
            .registry()
            .read()
            .await
            .lookup_by_path("/s/fail.sh")
            .is_some(),
        "内存态须保留"
    );
    assert!(!path.exists(), "失败不得产生落盘文件");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn real_backend_missing_entry_returns_404() {
    use zeroize::Zeroizing;
    let dir = std::env::temp_dir().join(format!(
        "veil-service-keepass-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("svc.kdbx");
    crate::keepass::build_test_kdbx(&db_path, b"svc-pw", &[("网易", "u", "s", "", vec![])]);
    let provider: crate::keepass::PasswordProvider =
        std::sync::Arc::new(|| Ok(Zeroizing::new(b"svc-pw".to_vec())));
    let env = cred_env(&[]);
    let state = AppState::new(
        Config::load_from(&env).unwrap(),
        crate::state::SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("x.sqlite"),
        },
    )
    .with_keepass(Arc::new(crate::keepass::RealKeePass::new(
        db_path, None, provider,
    )));
    let mut allowed = entries_for("网易", &[]);
    allowed.insert("不存在".to_string(), vec![]);
    enrolled_with_entries(&state, "/s/svc.sh", "svc1", allowed).await;
    let mut missing = body("svc1", "/s/svc.sh", None);
    missing.entry = Some("不存在".to_string());
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &missing)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
    assert!(err.to_string().contains("不存在"));
    enroll_allow(&state, "/s/svc2.sh", "svc2").await;
    let mut ok_body = body("svc2", "/s/svc2.sh", None);
    ok_body.field = None;
    ok_body.fields = None;
    let ok = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &ok_body)
        .await
        .unwrap();
    assert_eq!(ok.get("title").and_then(|v| v.as_str()), Some("网易"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn locked_returns_503() {
    let env = cred_env(&[]);
    let locked = AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from("/tmp/x.sqlite"),
        },
    );
    enroll_allow(&locked, "/s/k.sh", "k1").await;
    let err = handle_credential(
        &locked,
        &headers("gethash", Some("s3cr3t")),
        &body("k1", "/s/k.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn keepass_failure_notice_names_entry_and_reason() {
    use zeroize::Zeroizing;
    let sink = CountingSink::new();
    let env = cred_env(&[]);
    let dir = unique_dir("keepass-failure");
    let broken_db = dir.join("broken.kdbx");
    std::fs::write(&broken_db, b"not-a-kdbx").unwrap();
    let provider: crate::keepass::PasswordProvider =
        Arc::new(|| Ok(Zeroizing::new(b"pw".to_vec())));
    let state = inject_sink(
        AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
        .with_keepass(Arc::new(crate::keepass::RealKeePass::new(
            broken_db, None, provider,
        ))),
        sink.clone(),
    );
    enroll_allow(&state, "/s/kf.sh", "kf1").await;
    state.notify.start();
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("kf1", "/s/kf.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );

    let mut texts = Vec::new();
    for _ in 0..200 {
        texts = sink.texts();
        if !texts.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    state.notify.shutdown();

    let text = texts.join("\n");
    assert!(text.contains("❎ 凭据取用失败：网易"), "{text}");
    assert!(text.contains("原因："), "失败原因须同现: {text}");
    assert!(!text.contains("!r:example.com"), "正文不得含房间号: {text}");
    assert!(!text.contains("sha256:"), "正文不得含哈希: {text}");
    assert!(!text.contains("可选反应"), "通知不得带图例: {text}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_requires_approval() {
    let state = cred_state(&cred_env(&[]));
    let err =
        register_caller_with_approval(&state, &params("/s/reg-approval.sh", "reg-h1"), "reg-src")
            .await
            .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(state.pending.len(), 1, "默认模式须建单");
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/reg-approval.sh")
            .is_some(),
        "落盘条目须在中立态（未审批前不视为注册完成）"
    );

    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let state = cred_state(&env);
    let before = state.approval.pending_event_ids().await;
    let worker = state.clone();
    let mut handle = tokio::spawn(async move {
        register_caller_with_approval(&worker, &params("/s/reg-block.sh", "reg-h2"), "reg-src")
            .await
    });
    let event_id = wait_new_event_id(&state, &before).await;
    let pending = tokio::time::timeout(std::time::Duration::from_millis(150), &mut handle).await;
    assert!(pending.is_err(), "阻塞模式在 reaction 前不得返回");
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    let view = handle.await.unwrap().unwrap();
    assert!(view.enabled && !view.revoked, "✅ 后同请求须返回启用条目");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_approval_three_state() {
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let state = cred_state(&env);

    let ok = react_blocking_register(&state, "/s/tri-ok.sh", "tri-h-ok", "✅")
        .await
        .expect("✅ 须批准");
    assert!(ok.enabled && !ok.revoked, "✅ 置 enabled");

    let always = react_blocking_register(&state, "/s/tri-always.sh", "tri-h-always", "♾️")
        .await
        .expect("♾️ 须落定");
    assert!(always.enabled && !always.revoked, "♾️ 激活");
    assert_eq!(
        always.allow_mode,
        Some(crate::config::AutoApprove::Allow),
        "♾️ 置持久放行"
    );

    let no = react_blocking_register(&state, "/s/tri-no.sh", "tri-h-no", "❎").await;
    assert!(no.is_err(), "❎ 须拒绝");
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/tri-no.sh")
            .is_some_and(|e| e.revoked),
        "❎ 置 revoked"
    );

    register_caller_extended(&state, &params("/s/tri-timeout.sh", "tri-h-to"), "tri-src")
        .await
        .unwrap();
    apply_register_approval(&state, "/s/tri-timeout.sh", None).await;
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/tri-timeout.sh")
            .is_some_and(|e| e.revoked),
        "超时须按吊销落定"
    );
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("tri-h-to", "/s/tri-timeout.sh", None),
    )
    .await
    .unwrap_err();
    assert!(
        err.status_code().is_client_error(),
        "超时吊销后取用须被拒: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_approval_does_not_revive_revoked_entry_with_check() {
    let state = cred_state(&cred_env(&[]));
    register_caller_extended(
        &state,
        &params("/s/revive-ok.sh", "revive-h1"),
        "revive-src",
    )
    .await
    .unwrap();
    {
        let mut registry = state.registry.write().await;
        registry.revoke("/s/revive-ok.sh").unwrap();
        registry
            .set_allow_mode("/s/revive-ok.sh", Some(crate::config::AutoApprove::Pending))
            .unwrap();
    }
    apply_register_approval(&state, "/s/revive-ok.sh", Some((true, false))).await;
    let registry = state.registry.read().await;
    let entry = registry
        .lookup_by_path("/s/revive-ok.sh")
        .expect("条目须在");
    assert!(entry.revoked, "✅ 不得复活已吊销条目");
    assert!(!entry.enabled, "已吊销条目须保持未启用");
    assert_eq!(
        entry.allow_mode,
        Some(crate::config::AutoApprove::Pending),
        "✅ 不得改写已吊销条目的 allow_mode"
    );
    assert_eq!(entry.status_emoji(), "❎", "已吊销条目徽标须为 ❎");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_approval_always_does_not_revive_revoked_entry() {
    let state = cred_state(&cred_env(&[]));
    register_caller_extended(
        &state,
        &params("/s/revive-always.sh", "revive-h2"),
        "revive-src",
    )
    .await
    .unwrap();
    {
        let mut registry = state.registry.write().await;
        registry.revoke("/s/revive-always.sh").unwrap();
    }
    apply_register_approval(&state, "/s/revive-always.sh", Some((true, true))).await;
    let registry = state.registry.read().await;
    let entry = registry
        .lookup_by_path("/s/revive-always.sh")
        .expect("条目须在");
    assert!(entry.revoked, "♾️ 不得复活已吊销条目");
    assert!(!entry.enabled, "已吊销条目须保持未启用");
    assert_ne!(
        entry.allow_mode,
        Some(crate::config::AutoApprove::Allow),
        "♾️ 不得把已吊销条目的 allow_mode 改写为 Allow"
    );
    assert_eq!(entry.status_emoji(), "❎", "已吊销条目徽标须为 ❎");
}

/// 迟到 `✅` 的闭环回归：批准命中已吊销条目时须返回 `403`，不得伪造注册成功。
///
/// 走查结论：真实 re-register 在 `register_caller_extended` 判重处即早退
/// `VeilError::Conflict { message: "调用方已注册: <path>" }`（`lookup_by_path`
/// 命中含已吊销条目，早于 `submit_pending_with_branch` 建 Register 票），
/// 因此 `react_blocking_register` 无法驱动已注册路径；此处按生产阻塞链原序
/// 重放「Register 票 → `✅` → ask → apply_register_approval → 回读」。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_register_approval_after_revoke_returns_forbidden() {
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    let path = "/s/late-revive.sh";
    let enrolled = register_caller_extended(&state, &params(path, "late-h1"), "late-src")
        .await
        .expect("中立条目须先落盘");
    assert!(!enrolled.enabled && !enrolled.revoked, "注册须先落中立态");
    state.registry.write().await.revoke(path).unwrap();

    // 已吊销路径不可重新建 Register 票：真实早退为判重 Conflict（HTTP 409）。
    let conflict = register_caller_with_approval(&state, &params(path, "late-h2"), "late-src")
        .await
        .expect_err("已注册路径不得再建 Register 票");
    assert_eq!(conflict.status_code(), axum::http::StatusCode::CONFLICT);
    assert!(
        conflict.to_string().contains("调用方已注册"),
        "早退原因须为判重 Conflict: {conflict:?}"
    );
    assert!(
        state.approval.pending_event_ids().await.is_empty(),
        "判重早退前不得建单"
    );

    // 按生产顺序重放同一张票：Register 建票 → ✅ 落定 → 阻塞问询 → 落定回写。
    let event_id = "$late-register-approval";
    assert!(
        state
            .approval
            .submit_branch(event_id, MatrixBranch::Register)
            .await,
        "Register 票须可登记"
    );
    let input = ReactionInput {
        target_event_id: event_id.to_string(),
        key: "✅".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 1,
    };
    let outcome = state
        .approval
        .on_reaction(&input, "@bot:example.com", "!r:example.com", 0)
        .await;
    assert!(
        matches!(
            outcome,
            ReactionOutcome::Applied {
                approved: true,
                always: false
            }
        ),
        "✅ 须落定为批准: {outcome:?}"
    );
    let decision = state
        .approval
        .ask(event_id, std::time::Duration::from_secs(1))
        .await;
    assert_eq!(decision, Some(true), "阻塞问询须读到 ✅ 决议");
    let auto = state
        .approval
        .applied_always(event_id)
        .await
        .unwrap_or(false);
    apply_register_approval(&state, path, decision.map(|ok| (ok, auto))).await;

    let err = super::read_registration_view(&state, path)
        .await
        .expect_err("迟到 ✅ 命中已吊销条目须返回 403，不得伪造成功");
    match &err {
        VeilError::Auth { message } => {
            assert!(
                message.contains("保持吊销"),
                "错误须说明条目保持吊销: {message}"
            );
        }
        other => panic!("已吊销条目批准后须返回 Auth(403 语义)，实得: {other:?}"),
    }
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);

    let registry = state.registry.read().await;
    let entry = registry.lookup_by_path(path).expect("条目须在");
    assert!(entry.revoked, "迟到 ✅ 不得复活已吊销条目");
    assert!(!entry.enabled, "已吊销条目须保持未启用");
    assert_eq!(entry.status_emoji(), "❎", "已吊销条目徽标须为 ❎");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_requires_approval() {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let state = cred_state(&env);
    register_caller_extended(&state, &params("/s/rev-appr.sh", "rev-h1"), "rev-src-1")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/rev-appr.sh", true)
        .unwrap();

    let before = state.approval.pending_event_ids().await;
    let err = revoke_caller_with_approval(&state, "/s/rev-appr.sh")
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path("/s/rev-appr.sh").unwrap();
        assert!(entry.enabled && !entry.revoked, "未获批准须保持原状");
    }
    let event_id = wait_new_event_id(&state, &before).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    wait_until_revoked(&state, "/s/rev-appr.sh").await;
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/rev-appr.sh")
            .unwrap()
            .revoked,
        "✅ 后须执行吊销"
    );

    register_caller_extended(&state, &params("/s/rev-no.sh", "rev-h2"), "rev-src-2")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/rev-no.sh", true)
        .unwrap();
    let before = state.approval.pending_event_ids().await;
    revoke_caller_with_approval(&state, "/s/rev-no.sh")
        .await
        .unwrap_err();
    let event_id = wait_new_event_id(&state, &before).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", false)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/rev-no.sh")
            .unwrap()
            .enabled,
        "❎ 后须保持原状"
    );
}

async fn react(state: &AppState, event_id: &str, key: &str) {
    let input = ReactionInput {
        target_event_id: event_id.to_string(),
        key: key.to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 1,
    };
    let outcome = state
        .approval
        .on_reaction(&input, "@bot:example.com", "!r:example.com", 0)
        .await;
    assert!(
        matches!(outcome, ReactionOutcome::Applied { .. }),
        "reaction({key}) 须落定: {outcome:?}"
    );
}

async fn emergency_revoke_public_ip(state: &AppState, key: &str) -> Result<RegistrationView> {
    emergency_revoke(state, key, None).await
}

async fn wait_decision_slot(state: &AppState, key: &str, want: DecisionSlot) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if credential_decision_slot(state, key) == Some(want) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "决策表未在超时内落定 {key}: {want:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn short_timeout_state() -> AppState {
    let mut config = Config::load_from(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]))
        .expect("测试 config 可加载");
    config.credential_approval_timeout_secs = 1;
    inject_sink(
        AppState::new(
            config,
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
        .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked())),
        InjectSink::success(),
    )
}

#[tokio::test]
async fn emergency_revoke_async_202_closure() {
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    register_caller_extended(&state, &params("/s/em-closure.sh", "em-h1"), "em-src-1")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/em-closure.sh", true)
        .unwrap();
    let key = "/s/em-closure.sh";
    let pending_key = format!("revoke:{key}");

    // 未决：首次 202；重试复用既有票（pending_len 不增）。
    let first = emergency_revoke_public_ip(&state, key).await.unwrap_err();
    assert_eq!(first.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(state.approval.pending_len().await, 1);
    let event_id = wait_new_event_id(&state, &[]).await;
    let retry = emergency_revoke_public_ip(&state, key).await.unwrap_err();
    assert_eq!(
        retry.status_code(),
        axum::http::StatusCode::ACCEPTED,
        "未决重试须 202"
    );
    assert_eq!(
        state.approval.pending_len().await,
        1,
        "未决重试不得重复建单"
    );

    // 批准：重试执行吊销，条目 revoked=true/enabled=false。
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    wait_decision_slot(&state, &pending_key, DecisionSlot::Approved).await;
    let view = emergency_revoke_public_ip(&state, key).await.unwrap();
    assert!(view.revoked && !view.enabled, "批准后须执行吊销: {view:?}");

    // 拒绝：403 且条目原状。
    register_caller_extended(&state, &params("/s/em-deny.sh", "em-h2"), "em-src-2")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/em-deny.sh", true)
        .unwrap();
    let deny_key = "/s/em-deny.sh";
    let err = emergency_revoke_public_ip(&state, deny_key)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    let deny_event = wait_new_event_id(&state, &[]).await;
    state
        .approval
        .resolve(&deny_event, "@admin:example.com", false)
        .await;
    wait_decision_slot(&state, &format!("revoke:{deny_key}"), DecisionSlot::Denied).await;
    let denied = emergency_revoke_public_ip(&state, deny_key)
        .await
        .unwrap_err();
    assert_eq!(denied.status_code(), axum::http::StatusCode::FORBIDDEN);
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path(deny_key).unwrap();
        assert!(entry.enabled && !entry.revoked, "拒绝后条目须原状");
    }

    // 超时：403。
    let to_state = short_timeout_state();
    register_caller_extended(&to_state, &params("/s/em-to.sh", "em-h3"), "em-src-3")
        .await
        .unwrap();
    to_state
        .registry
        .write()
        .await
        .set_enabled("/s/em-to.sh", true)
        .unwrap();
    let to_key = "/s/em-to.sh";
    let err = emergency_revoke_public_ip(&to_state, to_key)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    let to_pk = format!("revoke:{to_key}");
    wait_decision_slot(&to_state, &to_pk, DecisionSlot::TimedOut).await;
    let timed = emergency_revoke_public_ip(&to_state, to_key)
        .await
        .unwrap_err();
    assert_eq!(timed.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emergency_revoke_202_e2e() {
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));

    // 场景 1：202 → ✅ → 同请求重试吊销生效。
    register_caller_extended(&state, &params("/s/e2e-rev-ok.sh", "e2e-h1"), "e2e-src-1")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/e2e-rev-ok.sh", true)
        .unwrap();
    let ok_key = "/s/e2e-rev-ok.sh";
    let err = emergency_revoke_public_ip(&state, ok_key)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    let event_id = wait_new_event_id(&state, &[]).await;
    react(&state, &event_id, "✅").await;
    wait_decision_slot(&state, &format!("revoke:{ok_key}"), DecisionSlot::Approved).await;
    let view = emergency_revoke_public_ip(&state, ok_key).await.unwrap();
    assert_eq!(view.status, "❎");
    assert!(view.revoked && !view.enabled, "✅ 后重试须吊销生效");

    // 场景 2：❎ → 重试 403 且条目原状。
    register_caller_extended(&state, &params("/s/e2e-rev-no.sh", "e2e-h2"), "e2e-src-2")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/e2e-rev-no.sh", true)
        .unwrap();
    let no_key = "/s/e2e-rev-no.sh";
    let err = emergency_revoke_public_ip(&state, no_key)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    let event_id = wait_new_event_id(&state, &[]).await;
    react(&state, &event_id, "❎").await;
    wait_decision_slot(&state, &format!("revoke:{no_key}"), DecisionSlot::Denied).await;
    let denied = emergency_revoke_public_ip(&state, no_key)
        .await
        .unwrap_err();
    assert_eq!(denied.status_code(), axum::http::StatusCode::FORBIDDEN);
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path(no_key).unwrap();
        assert!(entry.enabled && !entry.revoked, "❎ 后条目须原状");
    }

    // 场景 2b：♾️ 不受理 → 票保持未决，重试仍 202 且条目原状。
    register_caller_extended(&state, &params("/s/e2e-rev-auto.sh", "e2e-h5"), "e2e-src-5")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/e2e-rev-auto.sh", true)
        .unwrap();
    let auto_key = "/s/e2e-rev-auto.sh";
    let err = emergency_revoke_public_ip(&state, auto_key)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    let auto_event = wait_new_event_id(&state, &[]).await;
    let outcome = {
        let input = ReactionInput {
            target_event_id: auto_event.clone(),
            key: "♾️".to_string(),
            sender: "@admin:example.com".to_string(),
            room_id: "!r:example.com".to_string(),
            server_ts_ms: 1,
        };
        state
            .approval
            .on_reaction(&input, "@bot:example.com", "!r:example.com", 0)
            .await
    };
    assert!(
        matches!(outcome, ReactionOutcome::Notify(_)),
        "♾️ 在吊销分支须回执不落定: {outcome:?}"
    );
    assert_eq!(
        credential_decision_slot(&state, &format!("revoke:{auto_key}")),
        Some(DecisionSlot::Pending),
        "不受理后票须保持未决"
    );
    let auto_retry = emergency_revoke_public_ip(&state, auto_key)
        .await
        .unwrap_err();
    assert_eq!(
        auto_retry.status_code(),
        axum::http::StatusCode::ACCEPTED,
        "重试仍为 202 + E_PENDING"
    );
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path(auto_key).unwrap();
        assert!(entry.enabled && !entry.revoked, "♾️ 后条目须原状");
    }
    state.approval.remove(&auto_event).await;

    // 场景 4：未决 → 重试 202 且不新建第二单。
    register_caller_extended(&state, &params("/s/e2e-rev-pd.sh", "e2e-h4"), "e2e-src-4")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/e2e-rev-pd.sh", true)
        .unwrap();
    let pd_key = "/s/e2e-rev-pd.sh";
    let err = emergency_revoke_public_ip(&state, pd_key)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    let pd_event = wait_new_event_id(&state, &[]).await;
    let retry = emergency_revoke_public_ip(&state, pd_key)
        .await
        .unwrap_err();
    assert_eq!(retry.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(state.approval.pending_len().await, 1, "不得新建第二单");
    assert_eq!(
        state.approval.pending_event_ids().await,
        vec![pd_event.clone()],
        "复用既有真实 event id"
    );
    state
        .approval
        .resolve(&pd_event, "@admin:example.com", false)
        .await;

    // 场景 3：无回复至超时 → 重试 403。
    let to_state = short_timeout_state();
    register_caller_extended(
        &to_state,
        &params("/s/e2e-rev-to.sh", "e2e-h3"),
        "e2e-src-3",
    )
    .await
    .unwrap();
    to_state
        .registry
        .write()
        .await
        .set_enabled("/s/e2e-rev-to.sh", true)
        .unwrap();
    let to_key = "/s/e2e-rev-to.sh";
    let err = emergency_revoke_public_ip(&to_state, to_key)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    let to_pk = format!("revoke:{to_key}");
    wait_decision_slot(&to_state, &to_pk, DecisionSlot::TimedOut).await;
    let timed = emergency_revoke_public_ip(&to_state, to_key)
        .await
        .unwrap_err();
    assert_eq!(timed.status_code(), axum::http::StatusCode::FORBIDDEN);
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 读取条目的授权窗口（`(authorized_at, authorized_ttl_secs)`）。
async fn authorization_window(state: &AppState, path: &str) -> (Option<u64>, Option<u64>) {
    let reg = state.registry.read().await;
    let entry = reg.lookup_by_path(path).expect("条目须存在");
    (entry.authorized_at, entry.authorized_ttl_secs)
}
