//! 凭据面加固回归（自 `vault_ops/tests.rs` 拆出，保持 800 行红线内）：
//! 管理 token 恒时等长比较与「网络位置不再构成放行依据」。

use {
    super::super::{emergency_revoke, register_caller},
    crate::service::credential::test_support::{cred_env, cred_state},
    axum::http::StatusCode,
};

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

#[tokio::test]
async fn admin_token_length_indistinguishable() {
    let state = cred_state(&cred_env(&[]));
    let path = "/s/admin-len.sh";
    register_caller(&state, path, "admin-len-h", "admin-len-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled(path, true)
        .unwrap();

    assert!(crate::auth::secret_eq(ADMIN_TOKEN, ADMIN_TOKEN));
    let candidates = [
        "",
        "x",
        "observability-admin-token-012345678",
        "observability-admin-token-01234567890",
        "Observability-Admin-Token-0123456789",
        &ADMIN_TOKEN[..ADMIN_TOKEN.len() - 1],
    ];
    for candidate in candidates {
        assert!(!crate::auth::secret_eq(candidate, ADMIN_TOKEN));
        let err = emergency_revoke(&state, path, Some(candidate))
            .await
            .unwrap_err();
        assert_eq!(
            err.status_code(),
            StatusCode::ACCEPTED,
            "非等值候选 {candidate:?} 须转审批，结果不因长度不等而可分辨"
        );
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path(path).expect("条目须在");
        assert!(entry.enabled && !entry.revoked, "未放行前条目须原状");
        drop(registry);
    }

    let view = emergency_revoke(&state, path, Some(ADMIN_TOKEN))
        .await
        .unwrap();
    assert_eq!(view.status, "❎");
    assert!(view.revoked && !view.enabled, "等值管理 token 须直接吊销");
}

#[tokio::test]
async fn network_position_no_longer_unlocks_emergency_revoke() {
    let state = cred_state(&cred_env(&[]));
    let path = "/s/mapped-loop.sh";
    register_caller(&state, path, "mapped-h", "mapped-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled(path, true)
        .unwrap();

    let err = emergency_revoke(&state, path, None).await.unwrap_err();
    assert_eq!(
        err.status_code(),
        StatusCode::ACCEPTED,
        "无 token 一律转审批，与来源无关"
    );
    let registry = state.registry.read().await;
    let entry = registry.lookup_by_path(path).expect("条目须在");
    assert!(entry.enabled && !entry.revoked, "来源不得触发直接吊销");
}
