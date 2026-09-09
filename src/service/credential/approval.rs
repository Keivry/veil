//! 审批/pending 链：建单、双模问询、哈希变更通知、问询口径。
//!
//! H3.1 owner 声明：双模执行（`approval_dual_mode`）归本文件；单据存储与问询
//! trait 归 `crate::approval`（经其 `ApprovalGateway/PendingRecord` 接口协作），
//! 分支流转归 `service::matrix`；三处互不垫片。

use {
    super::{super::matrix, AppStateParts, vault_ops::query_keepass},
    crate::{
        approval::{ApprovalGateway as _, NoopApproval, PendingRecord},
        error::{Result, VeilError},
    },
    std::time::Duration,
};

fn approval_event_id(key: &str, reason: &str) -> String {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash as _, Hasher as _},
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    (key, reason, nanos).hash(&mut hasher);
    format!("$veil-{nanos}-{:08x}", hasher.finish() & 0xffff_ffff)
}

async fn submit_pending(state: &impl AppStateParts, key: &str, reason: &str) -> String {
    let record = PendingRecord::new(key, reason);
    let gateway = NoopApproval;
    let _ = gateway.request_approval(&record);
    state.pending().insert(record);
    let event_id = approval_event_id(key, reason);
    let branch = matrix::MatrixBranch::from_reason(reason);
    state.approval().submit_branch(&event_id, branch).await;
    let bot = matrix::MatrixBot::with_client(
        state.config().homeserver.clone(),
        state.config().room_id.clone(),
        state.config().matrix_access_token.clone(),
        state.http_client().as_ref().clone(),
    );
    let summary = format!("{reason} :: {key}");
    let text = bot.format_approval(branch, None, &summary);
    tracing::info!("审批已发送: event {event_id} 原因 {reason}");
    tokio::spawn(async move {
        if let Err(err) = bot.send_text(&text).await {
            tracing::warn!("审批消息发送失败: {err:#}");
        }
    });
    event_id
}

pub(crate) async fn record_pending(
    state: &impl AppStateParts,
    key: &str,
    reason: &str,
) -> VeilError {
    submit_pending(state, key, reason).await;
    VeilError::PendingApproval {
        message: format!("已转 Matrix 人工审批: {reason}"),
    }
}

pub(crate) async fn approval_dual_mode(
    state: &impl AppStateParts,
    key: &str,
    reason: &str,
    entry: &str,
    field: Option<&str>,
    use_token: bool,
) -> Result<serde_json::Value> {
    if !state.config().credential_block_wait {
        return Err(record_pending(state, key, reason).await);
    }
    let event_id = submit_pending(state, key, reason).await;
    let timeout =
        Duration::from_secs(state.config().credential_approval_timeout_secs.max(1) as u64);
    match state.approval().ask(&event_id, timeout).await {
        Some(true) => query_keepass(state, entry, field, use_token).await,
        Some(false) => Err(VeilError::Auth {
            message: "凭据审批被拒绝".to_string(),
        }),
        None => Err(VeilError::Auth {
            message: "凭据审批超时，按拒绝处理".to_string(),
        }),
    }
}

pub(crate) fn notify_hash_change(state: &impl AppStateParts, key: &str, detail: &str) {
    let bot = matrix::MatrixBot::with_client(
        state.config().homeserver.clone(),
        state.config().room_id.clone(),
        state.config().matrix_access_token.clone(),
        state.http_client().as_ref().clone(),
    );
    let summary = format!("哈希变更 :: {key} :: {detail}");
    let text = bot.format_approval(matrix::MatrixBranch::Credential, None, &summary);
    tokio::spawn(async move {
        let _ = bot.send_text(&text).await;
    });
    tracing::warn!("调用方哈希变更通知: {summary}");
}

/// 凭据审批问询（300s 超时口径）：超时/发送失败返回 None，调用方按 rejected 处理。
pub async fn await_credential_approval(state: &impl AppStateParts, event_id: &str) -> Option<bool> {
    let timeout = state.approval().credential_timeout();
    state.approval().ask(event_id, timeout).await
}

/// 审计审批问询（`AUDIT_TIMEOUT` 口径，默认 90s）：超时返回 None，调用方按 rejected 处理。
pub async fn await_audit_approval(state: &impl AppStateParts, event_id: &str) -> Option<bool> {
    state.approval().ask_audit(event_id).await
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::service::credential::{
            approve_hash_change,
            emergency_revoke,
            handle_credential,
            register_caller,
            revoke_caller,
            test_support::*,
        },
    };

    #[tokio::test]
    async fn enrolled_hash_tamper_turns_to_approval_202() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "goodhash", "test-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/a.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/a.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
    }

    #[tokio::test]
    async fn auto_approve_false_rejects_403() {
        let env = cred_env(&[("AUTO_APPROVE", "false")]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "goodhash", "test-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/a.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("goodhash", "/s/a.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn auto_approve_none_turns_to_202() {
        let env = cred_env(&[("AUTO_APPROVE", "none")]);
        let state = cred_state(&env);
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("fresh", "/s/fresh.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn credential_only_entry_approve_blocked_forbidden() {
        let env = cred_env(&[("VEIL_ENTRY_MODE", "credential-only")]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "h1", "test-src")
            .await
            .unwrap();
        let err = approve_hash_change(&state, "/s/a.sh", "h2")
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn emergency_revoke_exemptions_and_approval_flow() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "h1", "src-a")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/a.sh", true)
            .unwrap();
        let view = emergency_revoke(
            &state,
            "/s/a.sh",
            Some("observability-admin-token-0123456789"),
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(view.status, "❎");
        register_caller(&state, "/s/b.sh", "h2", "src-b")
            .await
            .unwrap();
        let err = emergency_revoke(&state, "/s/b.sh", None, Some("203.0.113.9"), false)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn approval_ticket_uses_matrix_gateway_with_split_timeouts() {
        use std::time::Duration;
        let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
        let state = cred_state(&env);
        assert_eq!(state.approval.pending_len().await, 0);
        register_caller(&state, "/s/w.sh", "goodhash", "wire-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/w.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/w.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.approval.pending_len().await, 1);
        assert_eq!(
            state.approval.credential_timeout(),
            Duration::from_secs(300)
        );
        assert_eq!(state.approval.audit_timeout(), Duration::from_secs(90));
        state.approval.submit("$wire-ev").await;
        state
            .approval
            .resolve("$wire-ev", "@admin:example.com", true)
            .await;
        let _ = state.approval.submit("$wire-ev2").await;
        assert_eq!(
            await_credential_approval(&state, "$wire-ev").await,
            Some(true)
        );
        assert_eq!(
            state
                .approval
                .ask("$wire-ev2", Duration::from_millis(50))
                .await,
            None
        );
        assert_eq!(state.approval.pending_len().await, 2);
    }

    #[tokio::test]
    async fn audit_ask_uses_audit_timeout() {
        let mut env = cred_env(&[]);
        env.insert("AUDIT_TIMEOUT".to_string(), "1".to_string());
        let state = cred_state(&env);
        assert_eq!(
            state.approval.audit_timeout(),
            std::time::Duration::from_secs(1)
        );
        state.approval.submit("$audit-ev").await;
        assert_eq!(
            await_audit_approval(&state, "$audit-ev-missing").await,
            None
        );
        assert_eq!(state.approval.pending_len().await, 1);
    }

    #[tokio::test]
    async fn send_failure_still_returns_202_with_ticket() {
        let env = cred_env(&[
            ("APPROVAL_WHITELIST", "@admin:example.com"),
            ("HOMESERVER", "http://127.0.0.1:9"),
        ]);
        let state = cred_state(&env);
        register_caller(&state, "/s/down.sh", "goodhash", "wire-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/down.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/down.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.approval.pending_len().await, 1);
    }

    #[tokio::test]
    async fn hash_tamper_turns_to_approval_202_with_notify() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        enrolled_with_entries(
            &state,
            "/s/tamper.sh",
            "goodhash",
            entries_for("网易", &["授权码"]),
        )
        .await;
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/tamper.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
    }

    #[tokio::test]
    async fn old_hash_within_grace_allows() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        enrolled_with_entries(
            &state,
            "/s/grace.sh",
            "h1",
            entries_for("网易", &["授权码"]),
        )
        .await;
        state
            .registry
            .write()
            .await
            .approve_hash_change("/s/grace.sh", "h2")
            .unwrap();
        let out = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("h1", "/s/grace.sh", None),
        )
        .await
        .unwrap();
        assert!(credential_value(&out).starts_with("__VG_CRED_"));
    }

    #[tokio::test]
    async fn revoked_caller_hash_mismatch_still_403() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/r.sh", "goodhash", "rev-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/r.sh", true)
            .unwrap();
        revoke_caller(&state, "/s/r.sh").await.unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/r.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
        assert!(state.pending.is_empty());
    }

    #[tokio::test]
    async fn blocking_mode_approval_returns_credential_for_same_request() {
        let env = cred_env(&[
            ("CREDENTIAL_BLOCK_WAIT", "1"),
            ("APPROVAL_WHITELIST", "@admin:example.com"),
        ]);
        let state = cred_state(&env);
        register_caller(&state, "/s/b.sh", "goodhash", "blk-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/b.sh", true)
            .unwrap();
        let worker = state.clone();
        let handle = tokio::spawn(async move {
            handle_credential(
                &worker,
                &headers("gethash", Some("s3cr3t")),
                &body("badhash", "/s/b.sh", None),
            )
            .await
        });
        let event_id = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let ids = state.approval.pending_event_ids().await;
                if let Some(id) = ids.into_iter().next() {
                    return id;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("阻塞模须先建单");
        state
            .approval
            .resolve(&event_id, "@admin:example.com", true)
            .await;
        let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("阻塞问询须在批准后返回")
            .expect("任务不崩")
            .expect("批准后同请求须返回凭据");
        assert!(credential_value(&out).starts_with("__VG_CRED_"));
    }
}
