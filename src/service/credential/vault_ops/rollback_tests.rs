//! `AUTH-6` 注册审批发送失败原子回滚回归（自 `vault_ops/tests.rs` 拆出，
//! 使 tests.rs 保持 800 行红线内）。

use {
    super::{register_caller_extended, register_caller_with_approval},
    crate::{
        registry::RegisterParams,
        service::credential::test_support::{
            InjectSink,
            cred_env,
            cred_state,
            cred_state_with_sink,
        },
    },
    axum::http::StatusCode,
};

fn params(path: &str, hash: &str) -> RegisterParams {
    RegisterParams {
        caller_path: path.to_string(),
        caller_hash: hash.to_string(),
        ..RegisterParams::default()
    }
}

#[tokio::test]
async fn register_send_failure_rolls_back_entry() {
    // AUTH-6：建单/发送失败回滚已落条目，无孤儿、不误伤其它条目。
    let state = cred_state_with_sink(&cred_env(&[]), InjectSink::failing());
    register_caller_extended(&state, &params("/s/keep.sh", "keep-h"), "keep-src")
        .await
        .unwrap();
    let err = register_caller_with_approval(&state, &params("/s/rollback.sh", "rb-h1"), "rb-src")
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    {
        let registry = state.registry.read().await;
        assert!(
            registry.lookup_by_path("/s/rollback.sh").is_none(),
            "发送失败不得遗留孤儿注册条目"
        );
        assert!(
            registry.lookup_by_path("/s/keep.sh").is_some(),
            "回滚不得误伤其它条目"
        );
    }
    assert_eq!(state.pending.len(), 0, "失败不得残留内存 pending");
}

#[tokio::test]
async fn register_can_retry_after_send_failure() {
    // AUTH-6：回滚后同一 `caller_path` 可再次发起注册。
    let state = cred_state_with_sink(&cred_env(&[]), InjectSink::failing());
    register_caller_with_approval(&state, &params("/s/retry.sh", "rt-h1"), "rt-src")
        .await
        .unwrap_err();
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/retry.sh")
            .is_none(),
        "失败后须已回滚"
    );
    let view = register_caller_extended(&state, &params("/s/retry.sh", "rt-h2"), "rt-retry-src")
        .await
        .expect("回滚后 caller_path 须可重试");
    assert_eq!(view.caller_path, "/s/retry.sh");
}

#[tokio::test]
async fn register_send_success_still_pending_or_activates() {
    // AUTH-6 回归：发送成功路径三态落定不变（默认 202 建单，条目保留）。
    let state = cred_state(&cred_env(&[]));
    let err = register_caller_with_approval(&state, &params("/s/ok-send.sh", "os-h1"), "os-src")
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/ok-send.sh")
            .is_some(),
        "成功路径条目须保留"
    );
    assert_eq!(state.pending.len(), 1, "成功路径须建单");
}
