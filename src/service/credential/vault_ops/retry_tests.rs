use {
    super::{emergency_revoke, register_caller_extended, revoke_caller_with_approval},
    crate::{
        registry::RegisterParams,
        service::{
            credential::{
                approval::{DecisionSlot, credential_decision_slot},
                test_support::*,
            },
            matrix::ReactionInput,
        },
        state::AppState,
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

async fn enable(state: &AppState, path: &str) {
    state
        .registry
        .write()
        .await
        .set_enabled(path, true)
        .unwrap();
}

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
        matches!(
            outcome,
            crate::service::matrix::ReactionOutcome::Applied { .. }
        ),
        "reaction({key}) 须落定: {outcome:?}"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_202_retry_semantics() {
    // CRD-6：常规吊销未决重试幂等（同 202、不重复建单）；终态重试返回终态。
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    let key = "/s/rev-retry.sh";
    register_caller_extended(&state, &params(key, "rr-h1"), "rr-src")
        .await
        .unwrap();
    enable(&state, key).await;

    let first = revoke_caller_with_approval(&state, key).await.unwrap_err();
    assert_eq!(first.status_code(), StatusCode::ACCEPTED);
    assert_eq!(state.approval.pending_len().await, 1);
    let before = state.approval.pending_event_ids().await;
    let event_id = wait_new_event_id(&state, &[]).await;
    let retry = revoke_caller_with_approval(&state, key).await.unwrap_err();
    assert_eq!(retry.status_code(), StatusCode::ACCEPTED, "未决重试须 202");
    assert_eq!(
        state.approval.pending_len().await,
        1,
        "未决重试不得重复建单"
    );
    assert_eq!(
        state.approval.pending_event_ids().await,
        before,
        "未决重试须复用同一票"
    );

    react(&state, &event_id, "✅").await;
    wait_decision_slot(&state, &format!("revoke:{key}"), DecisionSlot::Approved).await;
    let view = revoke_caller_with_approval(&state, key).await.unwrap();
    assert!(
        view.revoked && !view.enabled,
        "✅ 后重试须吊销生效: {view:?}"
    );

    let deny_key = "/s/rev-retry-no.sh";
    register_caller_extended(&state, &params(deny_key, "rr-h2"), "rr-src2")
        .await
        .unwrap();
    enable(&state, deny_key).await;
    let before = state.approval.pending_event_ids().await;
    revoke_caller_with_approval(&state, deny_key)
        .await
        .unwrap_err();
    let deny_event = wait_new_event_id(&state, &before).await;
    react(&state, &deny_event, "❎").await;
    wait_decision_slot(&state, &format!("revoke:{deny_key}"), DecisionSlot::Denied).await;
    let denied = revoke_caller_with_approval(&state, deny_key)
        .await
        .unwrap_err();
    assert_eq!(denied.status_code(), StatusCode::FORBIDDEN);
    let registry = state.registry.read().await;
    let entry = registry.lookup_by_path(deny_key).unwrap();
    assert!(entry.enabled && !entry.revoked, "❎ 后条目须原状");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emergency_revoke_token_source() {
    // CRD-7：紧急吊销仅认 OBSERVABILITY_ADMIN_TOKEN；CREDENTIAL_ADMIN_TOKEN 不再放行。
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    let key = "/s/em-token.sh";
    register_caller_extended(&state, &params(key, "et-h1"), "et-src")
        .await
        .unwrap();
    enable(&state, key).await;

    let old = emergency_revoke(
        &state,
        key,
        Some("legacy-credential-admin-token"),
        Some("203.0.113.9"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        old.status_code(),
        StatusCode::ACCEPTED,
        "旧 token 源不得直接吊销（须转审批）"
    );
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path(key).unwrap();
        assert!(entry.enabled && !entry.revoked, "旧 token 源不得吊销条目");
    }

    let view = emergency_revoke(
        &state,
        key,
        Some("observability-admin-token-0123456789"),
        Some("203.0.113.9"),
    )
    .await
    .unwrap();
    assert!(
        view.revoked && !view.enabled,
        "OBSERVABILITY_ADMIN_TOKEN 须放行: {view:?}"
    );
}
