//! 授权窗口（TTL）语义测试：落定写点、请求声明优先级、续期保持。

use {
    super::{
        apply_register_approval,
        authorization_window,
        cred_env,
        cred_state,
        current_unix_secs,
        params,
        react_blocking_register,
        react_blocking_register_with,
        register_caller_extended,
    },
    crate::service::credential::AppStateParts,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approval_check_writes_ttl_and_infinity_writes_none() {
    // `✅` 写「落定时刻 + 配置 TTL」；`♾️` 永远不设期限（TTL 为 None）。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
        ("AUTHORIZATION_TTL_SECS", "3600"),
    ]);
    let state = cred_state(&env);
    assert_eq!(
        state.config().authorization_ttl,
        Some(3_600),
        "前置：配置 TTL 须生效"
    );
    let before = current_unix_secs();

    react_blocking_register(&state, "/s/ttl-ok.sh", "ttl-h-ok", "✅")
        .await
        .expect("✅ 须批准");
    let (at, ttl) = authorization_window(&state, "/s/ttl-ok.sh").await;
    let at = at.expect("✅ 须写 authorized_at");
    assert!(at >= before, "authorized_at 须为落定时刻: {at} >= {before}");
    assert_eq!(ttl, Some(3_600), "✅ 须写配置 TTL");

    react_blocking_register(&state, "/s/ttl-always.sh", "ttl-h-always", "♾️")
        .await
        .expect("♾️ 须落定");
    let (at, ttl) = authorization_window(&state, "/s/ttl-always.sh").await;
    assert!(at.is_some(), "♾️ 亦须写 authorized_at");
    assert_eq!(ttl, None, "♾️ 须为无期限");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approval_check_without_ttl_config_writes_no_deadline() {
    // 未配置 TTL 时 `✅` 写 `authorized_at` 但 `authorized_ttl_secs = None`（无期限）。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let state = cred_state(&env);
    assert_eq!(state.config().authorization_ttl, None);
    react_blocking_register(&state, "/s/ttl-none.sh", "ttl-h-none", "✅")
        .await
        .expect("✅ 须批准");
    let (at, ttl) = authorization_window(&state, "/s/ttl-none.sh").await;
    assert!(at.is_some());
    assert_eq!(ttl, None, "缺省无期限");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reject_and_timeout_do_not_write_authorization_window() {
    // `❎` 与超时不写授权窗口：窗口变更只能来自批准路径。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
        ("AUTHORIZATION_TTL_SECS", "3600"),
    ]);
    let state = cred_state(&env);
    let _ = react_blocking_register(&state, "/s/ttl-no.sh", "ttl-h-no", "❎").await;
    let (at, _) = authorization_window(&state, "/s/ttl-no.sh").await;
    assert_eq!(at, None, "❎ 不得写 authorized_at（窗口不生效）");

    register_caller_extended(&state, &params("/s/ttl-to.sh", "ttl-h-to"), "ttl-src")
        .await
        .unwrap();
    let (at, _) = authorization_window(&state, "/s/ttl-to.sh").await;
    assert_eq!(at, None, "未批准条目不得写 authorized_at（窗口不生效）");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_unbounded_request_survives_nonzero_config_ttl() {
    // 请求显式 `0` 表示「本条无期限」，不得被全局配置窗口顶替。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
        ("AUTHORIZATION_TTL_SECS", "3600"),
    ]);
    let state = cred_state(&env);
    assert_eq!(state.config().authorization_ttl, Some(3_600));
    let mut p = params("/s/ttl-explicit-zero.sh", "ttl-h-zero");
    p.authorization_ttl = crate::registry::AuthorizationTtl::Unbounded;
    react_blocking_register_with(&state, p, "ttl-zero-src".to_string(), "✅")
        .await
        .expect("✅ 须批准");
    let (at, ttl) = authorization_window(&state, "/s/ttl-explicit-zero.sh").await;
    assert!(at.is_some(), "批准须写 authorized_at");
    assert_eq!(ttl, None, "显式 0 须保持无期限，不得回落配置 3600");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_request_ttl_wins_over_config_ttl() {
    // 请求声明 600 优先于全局 3600。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
        ("AUTHORIZATION_TTL_SECS", "3600"),
    ]);
    let state = cred_state(&env);
    let mut p = params("/s/ttl-explicit-600.sh", "ttl-h-600");
    p.authorization_ttl = crate::registry::AuthorizationTtl::Secs(600);
    react_blocking_register_with(&state, p, "ttl-600-src".to_string(), "✅")
        .await
        .expect("✅ 须批准");
    let (_, ttl) = authorization_window(&state, "/s/ttl-explicit-600.sh").await;
    assert_eq!(ttl, Some(600), "请求声明值须优先于全局配置");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reapproval_refreshes_authorized_at_and_keeps_ttl() {
    // 到期后重新批准即续期：`authorized_at` 刷新，TTL 保持原值（不被配置覆盖）。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let state = cred_state(&env);
    let path = "/s/ttl-renew.sh";
    register_caller_extended(&state, &params(path, "ttl-h-renew"), "ttl-src")
        .await
        .unwrap();
    let stale_at = current_unix_secs().saturating_sub(7_200);
    state
        .registry
        .write()
        .await
        .set_authorization_window(path, Some(stale_at), Some(3_600))
        .unwrap();

    let before = current_unix_secs();
    apply_register_approval(&state, path, Some((true, false))).await;
    let (at, ttl) = authorization_window(&state, path).await;
    let at = at.expect("批准须写 authorized_at");
    assert!(at >= before, "续期须刷新 authorized_at: {at} >= {before}");
    assert_eq!(ttl, Some(3_600), "续期须保留原 TTL");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reapproval_keeps_unbounded_entry_unbounded() {
    // 原本无期限的条目续期后仍为无期限。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
        ("AUTHORIZATION_TTL_SECS", "3600"),
    ]);
    let state = cred_state(&env);
    let path = "/s/ttl-unbounded.sh";
    register_caller_extended(&state, &params(path, "ttl-h-unbounded"), "ttl-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_authorization_window(path, Some(current_unix_secs()), None)
        .unwrap();
    apply_register_approval(&state, path, Some((true, false))).await;
    let (_, ttl) = authorization_window(&state, path).await;
    assert_eq!(ttl, None, "续期不得把无期限条目改成有期限");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn infinity_then_check_keeps_entry_unbounded() {
    // `♾️` 先落定为无期限；后续 `✅`（续期路径）不得把它改成有期限，
    // 即便全局配置了非 0 TTL。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
        ("AUTHORIZATION_TTL_SECS", "3600"),
    ]);
    let state = cred_state(&env);
    let path = "/s/ttl-inf-then-check.sh";
    react_blocking_register(&state, path, "ttl-h-inf-check", "♾️")
        .await
        .expect("♾️ 须落定");
    let (at, ttl) = authorization_window(&state, path).await;
    assert!(at.is_some(), "♾️ 须写 authorized_at");
    assert_eq!(ttl, None, "♾️ 须为无期限");

    apply_register_approval(&state, path, Some((true, false))).await;
    let (at2, ttl2) = authorization_window(&state, path).await;
    assert!(at2.is_some(), "✅ 续期须刷新 authorized_at");
    assert_eq!(ttl2, None, "✅ 不得把无期限条目改成配置 TTL");
}
