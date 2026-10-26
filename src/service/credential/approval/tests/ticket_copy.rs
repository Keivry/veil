//! 票面/通知文案回归：结构化渲染接入各分支后，正文组成与禁用元素的口径。

use {
    crate::{
        registry::{AuthorizationTtl, RegisterParams},
        service::credential::{
            handle_credential,
            register_caller_extended,
            register_caller_with_approval,
            revoke_caller_with_approval,
            test_support::*,
        },
    },
    axum::http::StatusCode,
};

const ROOM_ID: &str = "!r:example.com";

fn assert_clean(text: &str) {
    assert!(!text.contains(ROOM_ID), "正文不得含房间号: {text}");
    assert!(!text.contains("sha256:"), "正文不得含完整哈希: {text}");
    assert!(!text.contains("可选反应"), "正文不得含图例字段名: {text}");
}

#[tokio::test]
async fn enrolled_pending_ticket_shows_registered_name() {
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    enrolled_with_entries(
        &state,
        "/s/named.sh",
        "named-h",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .set_allow_mode("/s/named.sh", Some(crate::config::AutoApprove::Pending))
        .unwrap();
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("named-h", "/s/named.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);

    let text = sink.texts().join("\n");
    assert!(text.contains("凭据请求：网易 / 授权码"), "{text}");
    assert!(text.contains("test（/s/named.sh）"), "{text}");
    assert!(text.contains("人工审批模式"), "{text}");
    assert!(!text.contains("auto_approve_none"), "{text}");
    assert!(!text.contains("（未注册）"), "{text}");
    assert_clean(&text);
}

#[tokio::test]
async fn hash_mismatch_ticket_carries_short_hash_pair_only() {
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    let expected = "sha256:50f7f169d22f9acad3a8354414698d40700acc0e9776f71952facf23f6b21b38";
    let actual = "sha256:d58c1f7a00112233445566778899aabbccddeeff00112233445566778899aabb";
    enrolled_with_entries(
        &state,
        "/s/hash.sh",
        expected,
        entries_for("网易", &["授权码"]),
    )
    .await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(actual, "/s/hash.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);

    let text = sink.texts().join("\n");
    assert!(text.contains("凭据请求：网易 / 授权码"), "{text}");
    assert!(text.contains("脚本哈希已变更"), "{text}");
    assert!(
        text.contains("test（/s/hash.sh）"),
        "哈希失配须仍取到注册 name: {text}"
    );
    assert!(text.contains("哈希：50f7f169 → d58c1f7a"), "{text}");
    assert!(!text.contains("hash_mismatch"), "{text}");
    assert!(!text.contains(expected), "不得出现完整哈希: {text}");
    assert!(!text.contains(actual), "不得出现完整哈希: {text}");
    assert_clean(&text);
}

#[tokio::test]
async fn non_hash_ticket_contains_no_hash_fragment() {
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("sha256:50f7f169d22f9acad", "/s/new.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);

    let text = sink.texts().join("\n");
    assert!(text.contains("（未注册）"), "{text}");
    assert!(!text.contains("哈希"), "未注册票不得出现哈希行: {text}");
    assert!(!text.contains("50f7f169"), "{text}");
    assert_clean(&text);
}

#[tokio::test]
async fn hash_change_notice_has_no_legend_or_hash() {
    let sink = CountingSink::new();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    state.notify.start();

    super::super::notify_hash_change(&state, "/s/grace.sh", "已静默降级人工审批", Some(false));
    let mut texts = Vec::new();
    for _ in 0..100 {
        texts = sink.texts();
        if !texts.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    state.notify.shutdown();

    let text = texts.join("\n");
    assert!(text.contains("❎ 哈希变更：/s/grace.sh"), "{text}");
    assert!(text.contains("已静默降级人工审批"), "{text}");
    assert!(!text.contains("✅ 批准本次"), "通知不得带图例: {text}");
    assert!(!text.contains('♾'), "{text}");
    assert_clean(&text);
}

#[tokio::test]
async fn register_ticket_shows_authorization_window() {
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    let params = RegisterParams {
        caller_path: "/s/reg.sh".to_string(),
        caller_hash: "reg-h".to_string(),
        name: "构建脚本".to_string(),
        entries: entries_for("网易", &["授权码"]),
        authorization_ttl: AuthorizationTtl::Secs(600),
        ..RegisterParams::default()
    };
    let err = register_caller_with_approval(&state, &params, "reg-src")
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);

    let text = sink.texts().join("\n");
    assert!(text.contains("⏳ 注册请求：构建脚本"), "{text}");
    assert!(text.contains("授权窗口：600s"), "{text}");
    assert!(text.contains('♾'), "注册票须含持久放行图例: {text}");
    assert_clean(&text);
}

#[tokio::test]
async fn revoke_ticket_first_line_names_entry() {
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    register_caller_extended(
        &state,
        &RegisterParams {
            caller_path: "/s/rev.sh".to_string(),
            caller_hash: "rev-h".to_string(),
            name: "构建脚本".to_string(),
            ..RegisterParams::default()
        },
        "rev-src",
    )
    .await
    .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/rev.sh", true)
        .unwrap();
    let err = revoke_caller_with_approval(&state, "/s/rev.sh")
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);

    let text = sink.texts().join("\n");
    assert!(text.starts_with("⏳ 吊销请求：构建脚本"), "{text}");
    assert!(!text.contains('♾'), "吊销票不得含 ♾️: {text}");
    assert_clean(&text);
}

#[tokio::test]
async fn expired_authorization_ticket_says_window_expired() {
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    let path = "/s/exp-ticket.sh";
    enrolled_with_entries(&state, path, "exp-h", entries_for("网易", &["授权码"])).await;
    state
        .registry
        .write()
        .await
        .set_allow_mode(path, Some(crate::config::AutoApprove::Allow))
        .unwrap();
    let expired_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(7_201);
    state
        .registry
        .write()
        .await
        .set_authorization_window(path, Some(expired_at), Some(3_600))
        .unwrap();
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("exp-h", path, None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);

    let text = sink.texts().join("\n");
    assert!(text.contains("授权已到期"), "{text}");
    assert!(!text.contains("authorization_expired"), "{text}");
    assert_clean(&text);
}

#[tokio::test]
async fn emergency_revoke_ticket_names_caller_and_reads_enrolled() {
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    register_caller_extended(
        &state,
        &RegisterParams {
            caller_path: "/s/em.sh".to_string(),
            caller_hash: "em-h".to_string(),
            name: "应急脚本".to_string(),
            ..RegisterParams::default()
        },
        "em-src",
    )
    .await
    .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/em.sh", true)
        .unwrap();
    let err = crate::service::emergency_revoke(&state, "/s/em.sh", None)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);

    let text = sink.texts().join("\n");
    assert!(text.contains("吊销请求：应急脚本"), "{text}");
    assert!(text.contains("应急脚本（/s/em.sh）"), "{text}");
    assert!(!text.contains("（未注册）"), "{text}");
    assert_clean(&text);
}

#[tokio::test]
async fn command_ticket_with_unregistered_caller_keeps_downstream_label() {
    let ctx = crate::service::matrix::TicketContext {
        branch: crate::service::matrix::MatrixBranch::Command,
        subject: "restart-service @ host-1",
        caller: crate::service::matrix::CallerIdentity {
            path: "/opt/ci/agent.sh",
            name: Some("hermes"),
            desc: None,
            enrolled: false,
        },
        reason: "command_invoke",
        facts: &[],
    };
    let text = crate::service::matrix::render_ticket(&ctx);
    assert!(
        text.contains("命令请求：restart-service @ host-1"),
        "{text}"
    );
    assert!(
        text.contains("hermes（/opt/ci/agent.sh）（未注册）"),
        "下游身份不得丢失: {text}"
    );
    assert!(!text.contains("command_invoke"), "{text}");
    assert!(!text.contains("!r:"), "{text}");
}

#[tokio::test]
async fn pending_error_message_does_not_echo_control_chars() {
    // `subject` 来自请求体（entry/field 用户可控）：换行等控制字符若原样进入
    // `E_PENDING` 文案与日志，可伪造日志行，故须与票面同一口径脱敏。
    let sink = InjectSink::success();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    let mut req = body("gethash", "/s/inj.sh", None);
    req.entry = Some("网易\n伪造日志行".to_string());
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &req)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    let msg = format!("{err:?}");
    assert!(!msg.contains('\n'), "错误文案不得含换行: {msg}");
    assert!(
        msg.contains("E_PENDING") || msg.contains("人工审批"),
        "{msg}"
    );
}
