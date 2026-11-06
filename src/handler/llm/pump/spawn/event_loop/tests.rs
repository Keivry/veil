//! 非 Chat `data: [DONE]` 非事件回归（自 `tests.rs` 拆出守 800 行红线）。

use {
    crate::{
        handler::llm::tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{
            block_inject,
            llm_gateway::{GatewayMetrics, Protocol},
            redaction::Scope,
        },
    },
    std::sync::Arc,
};

/// 会话级作用域：canonical 存在 → 挂写回且 `conversation_scope = true`
/// （与生产 `build_request_scope` 的 `conversation` 模式分支同形）。
fn conversation_scope() -> Arc<Scope> {
    let canonical = crate::service::redaction::scoped_key(b"secret", "tenant-fp", "anchor-1");
    let identity = crate::service::session_identity::SessionIdentity {
        anchor: Some(crate::service::session_identity::SessionAnchor {
            value: "anchor-1".to_string(),
            source: crate::service::session_identity::AnchorSource::Header,
        }),
        canonical: Some(canonical),
        tenant_fingerprint: "tenant-fp".to_string(),
        scope: crate::service::session_identity::SessionScope::Session,
        source: crate::service::session_identity::SessionSource::Header,
        log_source: crate::service::session_identity::SessionSource::Header,
        log_scope: crate::service::session_identity::SessionScope::Session,
        log_user: None,
        request_carried_conversation: false,
    };
    let writeback = crate::service::redaction::writeback::ConversationWriteback::new(
        identity,
        Arc::<[u8]>::from(&b"secret"[..]),
        Arc::new(crate::service::redaction::session_alias::SessionAliasMap::new(8)),
    );
    Arc::new(Scope::new().with_conversation(writeback, true))
}

#[tokio::test]
async fn streaming_writeback_miss_counts_once_on_responses_terminal_without_id() {
    // `conversation` 模式 Responses 终端无 id → 恰计一次；
    // 缺写回上下文（`request` 模式）同形流 → 恒 0（不误计）。
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"hi\"}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"\",\"status\":\"completed\",\"output\":[]}}\n\n".to_vec();

    let (url, server) = loopback_server(200, "text/event-stream", sse.clone()).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (_scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, conversation_scope(), vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, _frames) = collect_pump(upstream, ctx).await;
    server.abort();
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        1,
        "conversation + Responses 终端缺 id 须恰计一次"
    );

    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, _frames) = collect_pump(upstream, ctx).await;
    server.abort();
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "无写回上下文 MUST NOT 计入"
    );
}

#[tokio::test]
async fn responses_display_anchor_ignores_top_level_id() {
    // Responses 展示锚点与绑定路径同口径：只认 `response.id`，事件顶层
    // `id` 不参与，也不得被合成终端复用。
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"id\":\"not-a-response-id\",\"delta\":\"hi\"}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_o, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("\"response\":{\"id\":\"not-a-response-id\""),
        "合成终端不得复用事件顶层 id: {joined}"
    );
    assert!(
        joined.contains("unknown_"),
        "缺 response.id 须回退未知 id: {joined}"
    );
    assert_eq!(
        metrics.conv_missing_count("truncated"),
        1,
        "无 response.id 须计缺失"
    );
}

#[tokio::test]
async fn non_chat_done_is_non_event_official_terminal_flows() {
    // `data: [DONE]` 仅 Chat 为终端标记；非 Chat 视为非事件（不置终端、
    // 不透出），官方终端照常产出，下游无 `[DONE]` 且终端恰一。
    let client = reqwest::Client::new();

    // ① Responses：[DONE] 在前、无官方终端 → 合成恰一 response.failed，下游无 [DONE]。
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"hi\"}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "非 Chat 不得透出 [DONE]: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "须恰一官方终端: {joined}"
    );
    assert!(joined.contains("response.failed"), "缺合成终端: {joined}");

    // ② Anthropic：[DONE] 在前、message_stop 在后 → message_stop 照常透出恰一。
    let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"model\":\"claude\"}}\n\ndata: [DONE]\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_o, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "Anthropic 不得透出 [DONE]: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_stop\"").count(),
        1,
        "官方 message_stop 须恰一且不被 [DONE] 抑制: {joined}"
    );
    assert_eq!(
        metrics.sse_event_total(),
        2,
        "message_start + message_stop 各计 1；[DONE] 非事件不计（已声明计数变更）"
    );

    // ③ Responses：官方终端在前、[DONE] 在后 → 官方终端恰一、无 [DONE]。
    let sse = b"data: {\"type\":\"response.completed\",\"sequence_number\":0,\"response\":{\"id\":\"r1\",\"status\":\"completed\",\"output\":[]}}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "终端后 [DONE] 不得透出: {joined}"
    );
    assert_eq!(
        joined.matches("response.completed").count(),
        1,
        "官方终端须恰一: {joined}"
    );
}

#[tokio::test]
async fn done_only_stream_is_vacuum_for_non_chat_chat_terminal_unchanged() {
    // Oracle weak-test ④：上游唯一载荷为 `data: [DONE]` 的真空流——非 Chat 视 `[DONE]`
    // 为非事件、零有效帧，走真空流最小终止；Chat 仍以 `[DONE]` 为终端原样透出。
    let client = reqwest::Client::new();
    let sse = b"data: [DONE]\n\n".to_vec();

    // ① Responses：下游无 [DONE]，恰一 failed 家族终端。
    let (url, server) = loopback_server(200, "text/event-stream", sse.clone()).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "Responses 真空 [DONE] 不得透出: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 须恰一 failed 家族终端: {joined}"
    );
    assert!(
        joined.contains("response.failed"),
        "缺 response.failed: {joined}"
    );
    assert!(
        !joined.contains("response.completed") && !joined.contains("response.incomplete"),
        "不得合成 completed/incomplete: {joined}"
    );

    // ② Anthropic：下游无 [DONE]，最小 message_start + message_stop。
    let (url, server) = loopback_server(200, "text/event-stream", sse.clone()).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "Anthropic 真空 [DONE] 不得透出: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_start\"").count(),
        1,
        "Anthropic 须恰一 message_start: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_stop\"").count(),
        1,
        "Anthropic 须恰一 message_stop: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "anthropic"),
        1,
        "Anthropic 终端恰一: {joined}"
    );
    assert!(
        !joined.contains("content_block"),
        "真空流不得含 content_block_*: {joined}"
    );

    // ③ Chat：`[DONE]` 仍为终端标记，原样透出恰一。
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    server.abort();
    let joined = frames.join("");
    assert!(
        joined.contains("data: [DONE]"),
        "Chat 须原样透出 [DONE] 终端: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "Chat 终端恰一: {joined}"
    );
}

#[tokio::test]
async fn streaming_binds_response_id_from_created_frame() {
    // 流式首个 `response.created` 即捕获并绑定 `response.id`（即使后续流中断，
    // 已捕获绑定仍在）；收尾不再重复计数任何 miss。
    const SECRET: &[u8] = b"stream-bind-secret";
    let sse = b"data: {\"type\":\"response.created\",\"sequence_number\":1,\"response\":{\"id\":\"resp_stream_1\",\"status\":\"in_progress\",\"output\":[]}}\n\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"delta\":\"hi\"}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":3,\"response\":{\"id\":\"resp_stream_1\",\"status\":\"completed\",\"output\":[]}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();

    let alias = Arc::new(crate::service::redaction::session_alias::SessionAliasMap::new(8));
    let canonical = crate::service::redaction::scoped_key(SECRET, "tenant-fp", "anchor-1");
    let identity = crate::service::session_identity::SessionIdentity {
        anchor: Some(crate::service::session_identity::SessionAnchor {
            value: "anchor-1".to_string(),
            source: crate::service::session_identity::AnchorSource::Header,
        }),
        canonical: Some(canonical.clone()),
        tenant_fingerprint: "tenant-fp".to_string(),
        scope: crate::service::session_identity::SessionScope::Session,
        source: crate::service::session_identity::SessionSource::Header,
        log_source: crate::service::session_identity::SessionSource::Header,
        log_scope: crate::service::session_identity::SessionScope::Session,
        log_user: None,
        request_carried_conversation: false,
    };
    let writeback = crate::service::redaction::writeback::ConversationWriteback::new(
        identity,
        Arc::<[u8]>::from(SECRET),
        alias.clone(),
    );
    let scope = Arc::new(Scope::with_opts(false).with_conversation(writeback, true));

    let (_fresh_scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(joined.contains("resp_stream_1"), "{joined}");

    assert_eq!(
        alias.resolve(SECRET, "tenant-fp", "resp_stream_1"),
        Some(canonical),
        "流式 response.id 须绑定到请求时 canonical"
    );
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "正常完成且已捕获 id MUST NOT 计写回失败"
    );
    assert_eq!(metrics.session_bind_miss_count(), 0);
}

#[tokio::test]
async fn truncated_stream_never_counts_writeback_miss() {
    // 截断流（无上游终端帧 → 合成终端 → `truncated_mode` 置位）MUST NOT 计
    // `conversation_writeback_miss`，即便会话级作用域存在且没拿到 `response.id`。
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"hi\"}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, conversation_scope(), vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let _ = scope;
    let joined = frames.join("");
    assert!(
        joined.contains("response.failed") || joined.contains(r#""incomplete""#),
        "前置：缺终端帧的流须被合成为截断终端: {joined}"
    );
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "截断流 MUST NOT 计写回失败"
    );
}

#[tokio::test]
async fn truncated_stream_keeps_already_captured_binding_and_counts_no_miss() {
    // tasks 6.5：首帧 `response.created` 已捕获并绑定 `response.id`，随后流被截断
    // ——已捕获绑定 MUST 保留，且截断收尾 MUST NOT 计 `conversation_writeback_miss`。
    const SECRET: &[u8] = b"truncated-bind-secret";
    let sse = b"data: {\"type\":\"response.created\",\"sequence_number\":1,\"response\":{\"id\":\"resp_before_cut\",\"status\":\"in_progress\",\"output\":[]}}\n\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"delta\":\"hi\"}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();

    let alias = Arc::new(crate::service::redaction::session_alias::SessionAliasMap::new(8));
    let canonical = crate::service::redaction::scoped_key(SECRET, "tenant-fp", "anchor-1");
    let identity = crate::service::session_identity::SessionIdentity {
        anchor: Some(crate::service::session_identity::SessionAnchor {
            value: "anchor-1".to_string(),
            source: crate::service::session_identity::AnchorSource::Header,
        }),
        canonical: Some(canonical.clone()),
        tenant_fingerprint: "tenant-fp".to_string(),
        scope: crate::service::session_identity::SessionScope::Session,
        source: crate::service::session_identity::SessionSource::Header,
        log_source: crate::service::session_identity::SessionSource::Header,
        log_scope: crate::service::session_identity::SessionScope::Session,
        log_user: None,
        request_carried_conversation: false,
    };
    let writeback = crate::service::redaction::writeback::ConversationWriteback::new(
        identity,
        Arc::<[u8]>::from(SECRET),
        alias.clone(),
    );
    let scope = Arc::new(Scope::with_opts(false).with_conversation(writeback, true));

    let (_fresh_scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(
        joined.contains("resp_before_cut"),
        "首帧内容须已透出: {joined}"
    );

    assert_eq!(
        alias.resolve(SECRET, "tenant-fp", "resp_before_cut"),
        Some(canonical),
        "截断 MUST NOT 回滚已捕获的绑定"
    );
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "截断流 MUST NOT 计写回失败"
    );
    assert_eq!(metrics.session_bind_miss_count(), 0);
}

#[tokio::test]
async fn repeated_stream_frames_bind_idempotently() {
    // tasks 6.5：`response.created` 与 `response.completed` 携带同一 `response.id` /
    // `conversation.id` 时重复帧须幂等（`AlreadyBound` 不计数、不多写条目）。
    const SECRET: &[u8] = b"repeated-frame-secret";
    let sse = b"data: {\"type\":\"response.created\",\"sequence_number\":1,\"response\":{\"id\":\"resp_rep\",\"conversation\":{\"id\":\"conv_rep\"},\"status\":\"in_progress\",\"output\":[]}}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"resp_rep\",\"conversation\":{\"id\":\"conv_rep\"},\"status\":\"completed\",\"output\":[]}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();

    let alias = Arc::new(crate::service::redaction::session_alias::SessionAliasMap::new(8));
    let canonical = crate::service::redaction::scoped_key(SECRET, "tenant-fp", "anchor-rep");
    let identity = crate::service::session_identity::SessionIdentity {
        anchor: Some(crate::service::session_identity::SessionAnchor {
            value: "anchor-rep".to_string(),
            source: crate::service::session_identity::AnchorSource::Header,
        }),
        canonical: Some(canonical.clone()),
        tenant_fingerprint: "tenant-fp".to_string(),
        scope: crate::service::session_identity::SessionScope::Session,
        source: crate::service::session_identity::SessionSource::Header,
        log_source: crate::service::session_identity::SessionSource::Header,
        log_scope: crate::service::session_identity::SessionScope::Session,
        log_user: None,
        request_carried_conversation: false,
    };
    let writeback = crate::service::redaction::writeback::ConversationWriteback::new(
        identity,
        Arc::<[u8]>::from(SECRET),
        alias.clone(),
    );
    let scope = Arc::new(Scope::with_opts(false).with_conversation(writeback, true));

    let (_fresh_scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, _frames) = collect_pump(upstream, ctx).await;
    server.abort();

    assert_eq!(alias.len(), 2, "重复帧须幂等（仅两条条目）");
    assert_eq!(
        alias.resolve(SECRET, "tenant-fp", "resp_rep"),
        Some(canonical.clone())
    );
    assert_eq!(
        alias.resolve(SECRET, "tenant-fp", "conv_rep"),
        Some(canonical)
    );
    assert_eq!(
        metrics.session_alias_conflict_count(),
        0,
        "重复帧不得计冲突"
    );
    assert_eq!(metrics.conversation_writeback_miss_count(), 0);
    assert_eq!(metrics.session_bind_miss_count(), 0);
}

#[tokio::test]
async fn chat_and_anthropic_streams_never_count_session_misses() {
    // Chat/Anthropic 流即便缺可用 id 也 MUST NOT 写别名或计任何 session miss。
    for (protocol, sse) in [
        (
            Protocol::Chat,
            b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec(),
        ),
        (
            Protocol::Anthropic,
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"c\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec(),
        ),
    ] {
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
        let (scope, vault, detector) = fresh_arcs();
        let metrics = Arc::new(GatewayMetrics::default());
        let mut ctx = pump_ctx(protocol, conversation_scope(), vault, detector);
        ctx.req.gateway_metrics = metrics.clone();
        let (_o, _frames) = collect_pump(upstream, ctx).await;
        server.abort();
        let _ = scope;
        assert_eq!(
            metrics.conversation_writeback_miss_count(),
            0,
            "{protocol:?} MUST NOT 计写回失败"
        );
        assert_eq!(
            metrics.session_bind_miss_count(),
            0,
            "{protocol:?} MUST NOT 计绑定缺失"
        );
    }
}
