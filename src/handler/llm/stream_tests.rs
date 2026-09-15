//! 流泵集成单测（D2 自 `mod.rs` 拆出；`#[cfg(test)]` 门控，见 `mod.rs` 声明）。

use {
    super::pump::{
        PumpOutcome,
        RequestCtx,
        StreamPumpCtx,
        build_sse_response,
        should_synthesize_empty_stream,
        spawn_stream_pump,
    },
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        service::{
            block_inject,
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    axum::http::{StatusCode, header},
    serde_json::Value,
    std::{sync::Arc, time::Instant},
};

pub(super) fn fresh_arcs() -> (Arc<Scope>, Arc<CredentialVault>, Arc<PiiDetector>) {
    (
        Arc::new(Scope::new()),
        Arc::new(CredentialVault::new()),
        Arc::new(PiiDetector::new()),
    )
}

pub(super) fn pump_ctx(
    protocol: Protocol,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
) -> StreamPumpCtx {
    StreamPumpCtx {
        req: RequestCtx {
            protocol,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Off,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: crate::service::audit::AuditSink::test_arc(),
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            pending: Arc::new(PendingApprovals::default()),
            normalized_out: false,
        },
        hold_max: 1_048_576,
        pii_boundary_chars: 64,
        init_conv: None,
        req_model: String::new(),
    }
}

/// 回环上游：固定状态码/内容类型/体，供流泵回放单测（无外网依赖）。
pub(super) async fn loopback_server(
    status: u16,
    content_type: &str,
    body: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        502 => "Bad Gateway",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(&body).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

/// 中途传输错误上游：声明 `content-length` 大于实际写入体后关闭连接，
/// 触发 reqwest `chunk()` 返回 `Err`（S5/D5 观测回归用）。
pub(super) async fn broken_body_server(
    content_type: &str,
    declared_len: usize,
    body: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {declared_len}\r\nconnection: close\r\n\r\n"
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            let _ = sock.write_all(&body).await;
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

pub(super) async fn collect_pump(
    upstream: reqwest::Response,
    ctx: StreamPumpCtx,
) -> (PumpOutcome, Vec<String>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let handle = spawn_stream_pump(upstream, tx, ctx);
    let outcome = handle.await.expect("流泵任务不得崩");
    let mut frames = Vec::new();
    while let Some(f) = rx.recv().await {
        frames.push(f);
    }
    (outcome, frames)
}

#[tokio::test]
async fn tss03_truncated_tool_fragments_never_reach_downstream() {
    // P0-3.3 E2E：chat 流中途截断（无 finish、无 DONE），残缺 tool 不到下游，
    // 记 `truncated_tool_dropped`，不伪造成功终止（open-ended）。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-t1","function":{"name":"get_weather","arguments":"{\"city\":\""}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"BJ\"}"}}]}}]}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let ctx = StreamPumpCtx {
        req: RequestCtx {
            protocol: Protocol::Chat,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Block,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: crate::service::audit::AuditSink::test_arc(),
            gateway_metrics: metrics.clone(),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            pending: Arc::new(PendingApprovals::default()),
            normalized_out: false,
        },
        hold_max: 1_048_576,
        pii_boundary_chars: 64,
        init_conv: None,
        req_model: String::new(),
    };
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    assert!(!outcome.block_injected, "截断丢弃非阻断，不得注阻断帧");
    let joined = frames.join("");
    assert!(
        !joined.contains("get_weather"),
        "残缺工具名得到下游: {joined}"
    );
    assert!(
        !joined.contains("call-t1"),
        "残缺调用 id 得到下游: {joined}"
    );
    assert!(!joined.contains("city"), "残缺参数得到下游: {joined}");
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "D6：Chat 截断须补恰一 [DONE] 收尾: {joined}"
    );
    assert_eq!(
        metrics.truncated_tool_dropped_count(),
        2,
        "两帧残缺分片须计数"
    );
    server.abort();
}

#[tokio::test]
async fn tss03_completed_tool_stream_flushes_buffered_fragments() {
    // P0-3.3 E2E 对照：完整 tool 流（partial + finish + DONE）须放行缓冲分片，
    // 下游可重组完整调用，不记截断丢弃。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-t2","function":{"name":"get_weather","arguments":"{\"city\":\""}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"BJ\"}"}}]}}]}

data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let ctx = StreamPumpCtx {
        req: RequestCtx {
            protocol: Protocol::Chat,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Block,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: crate::service::audit::AuditSink::test_arc(),
            gateway_metrics: metrics.clone(),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            pending: Arc::new(PendingApprovals::default()),
            normalized_out: false,
        },
        hold_max: 1_048_576,
        pii_boundary_chars: 64,
        init_conv: None,
        req_model: String::new(),
    };
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    assert!(!outcome.block_injected, "良性工具调用不得阻断");
    let joined = frames.join("");
    assert!(joined.contains("get_weather"), "完整调用须放行: {joined}");
    assert!(joined.contains("city"), "缓冲参数须放行: {joined}");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "完整流恰一终止帧"
    );
    assert_eq!(
        metrics.truncated_tool_dropped_count(),
        0,
        "完整流不得记截断丢弃"
    );
    server.abort();
}

#[tokio::test]
async fn stream_pump_clean_finish_emits_exactly_one_terminal_frame() {
    let sse =
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    assert!(!outcome.block_injected);
    let joined = frames.join("");
    assert!(joined.contains("hi"), "录制流内容须泵到下游");
    let done_count = frames.iter().filter(|f| f.contains("data: [DONE]")).count();
    assert_eq!(done_count, 1, "正常收尾恰一个终止帧，不追加多余终止");
    assert!(
        frames.last().is_some_and(|f| f.contains("data: [DONE]")),
        "下游须以终止帧收尾"
    );
    server.abort();
}

#[tokio::test]
async fn cross_frame_split_phone_number_boundary_hold_masks() {
    let sse = b"data: {\"choices\":[{\"delta\":{\"content\":\"call 138\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"12345678 ok\"}}]}\n\ndata: [DONE]\n\n"
        .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (cscope, cvault, cdetector) = (scope.clone(), vault.clone(), detector.clone());
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    assert!(!outcome.block_injected);
    let mut decoded = String::new();
    for f in &frames {
        for line in f.lines() {
            let Some(payload) = line.strip_prefix("data: ") else {
                continue;
            };
            if payload.trim() == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload)
                && let Some(c) = v
                    .pointer("/choices/0/delta/content")
                    .and_then(|x| x.as_str())
            {
                decoded.push_str(c);
            }
        }
    }
    assert!(
        !decoded.contains("13812345678"),
        "解码拼接后不得复原完整手机号: {decoded}"
    );
    assert!(decoded.contains("call "), "非敏感前缀须保留: {decoded}");
    assert!(decoded.contains("ok"), "非敏感后缀须保留: {decoded}");
    // 对照：逐帧脱敏（无边界 hold）对切分残片漏检，拼接可复原原文。
    let f1 = cscope
        .redact_response_new_pii(&cvault, &cdetector, "call 138")
        .await;
    let f2 = cscope
        .redact_response_new_pii(&cvault, &cdetector, "12345678 ok")
        .await;
    assert!(
        format!("{f1}{f2}").contains("13812345678"),
        "对照组须复现漏检，否则本用例无回归价值"
    );
    server.abort();
}

#[tokio::test]
async fn fidelity_fields_passthrough_unmodified() {
    let sse = b"data: {\"id\":\"chatcmpl-xyz\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"m-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chatcmpl-xyz\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"m-test\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
        .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    assert!(!outcome.block_injected);
    let joined = frames.join("");
    for key in [
        "\"chatcmpl-xyz\"",
        "\"chat.completion.chunk\"",
        "1700000000",
        "\"m-test\"",
        "\"stop\"",
    ] {
        assert!(
            joined.contains(key),
            "保真字段须原样透传，缺 {key}: {joined}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn stream_pump_residue_sent_skips_secondary_empty_stream_frame() {
    // 无尾空行半帧：事件循环无分发（`forwarded==0`），残余路径直发下游。
    // 旧守门（`forwarded==0`）误触发二次空流合成；新守门以状态位为准跳过。
    let half = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", half).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let joined = frames.join("");
    assert!(joined.contains("hi"), "残余半帧须送达下游");
    assert!(!outcome.block_injected, "残余已发不得再合成空流阻断帧");
    assert!(!joined.contains("empty-stream"), "全流不得出现二次空流合成");
    server.abort();
}

#[tokio::test]
async fn vacuum_stream_chat_synthesizes_single_done() {
    // P2/D2：chat 零字节零残余时补恰一 `data: [DONE]`（不伪造内容/usage），
    // 下游可解析收尾；终端标记落位。
    let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let joined = frames.join("");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "真空流恰一 [DONE]: {joined}"
    );
    assert!(!joined.contains("\"delta\""), "不得伪造内容帧: {joined}");
    assert!(outcome.block_injected, "合成终端须置位 block_injected");
    assert!(outcome.terminal_injected, "终端标记须落位");
    server.abort();
}

#[tokio::test]
async fn vacuum_stream_responses_still_synthesizes_failed() {
    // C8 真空流 E2E 对照：responses 零字节时仍合成 failed 终端（失败语义）。
    let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(outcome.block_injected, "responses 真空流须合成 failed 终端");
    assert!(
        joined.contains("response.failed"),
        "须含 failed 终端: {joined}"
    );
    assert!(
        !joined.contains("response.completed"),
        "不得伪造完成: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn empty_data_heartbeat_frames_dropped_not_forwarded() {
    // L17 + P2：纯空 `data:` 心跳（`event:` 独占帧 / 空 data 帧）不得透传；
    // 空帧不计入 `any_frame_sent`，chat 真空守门仍补恰一 `[DONE]` 收尾。
    // 注：裸 `data:\n\n` 由解析器直接过滤，本分支覆盖带 `event:` 的空帧形态。
    let up_body = b"event: ping\n\nevent: message\ndata:\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", up_body).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let joined = frames.join("");
    assert!(
        !joined.contains("event: ping") && !joined.contains("event: message"),
        "空心跳帧不得透传: {joined}"
    );
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "空心跳流仍走真空守门补 [DONE]: {joined}"
    );
    assert!(outcome.block_injected, "合成终端须置位 block_injected");
    assert!(outcome.terminal_injected, "终端标记须落位");
    server.abort();
}

#[tokio::test]
async fn comment_only_heartbeat_does_not_gate_empty_synthesis_e11() {
    // E11/D6：纯 `:` 注释心跳透传但不置位 `any_frame_sent`；
    // responses 纯心跳仍合成 failed 终端（守门
    // `should_synthesize_empty_stream(false,false,false)` 为真）。
    assert!(should_synthesize_empty_stream(false, false, false));
    let up_body = b": ping\n\n: keepalive\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", up_body).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(joined.contains(": ping"), "注释帧须透传: {joined}");
    assert!(
        joined.contains("response.failed"),
        "纯心跳流仍须合成终端: {joined}"
    );
    assert!(outcome.block_injected, "合成终端须置位 block_injected");
    server.abort();
}

#[tokio::test]
async fn pump_terminal_reuses_request_conv_e12() {
    // E12/D7 + P4：泵内 `error` 合成单帧 failed 时复用请求会话而非合成随机值。
    let sse = b"data: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.init_conv = Some("resp_req_9".to_string());
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(
        joined.contains("resp_req_9"),
        "终端帧须复用请求会话: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn thinking_and_signature_opaque_passthrough_values_match() {
    // D5 回归：thinking/signature/redacted_thinking 为次要事件，不进 hold 不审计；
    // 网关 JSON 归一化仅调序，敏感字节值须原样透出。
    let sse = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm...\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig-bytes-123\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"redacted_thinking\",\"redacted_data\":\"eHh4\"}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    assert!(!outcome.block_injected, "次要事件不得触发阻断");
    let joined = frames.join("");
    assert_eq!(
        joined.matches("\"thinking\":\"hmm...\"").count()
            + joined.matches("\"signature\":\"sig-bytes-123\"").count()
            + joined.matches("\"redacted_data\":\"eHh4\"").count(),
        3,
        "三帧 opaque 值须原样透出不丢弃（Fast 攒批可同帧）: {joined}"
    );
    let mut values = Vec::new();
    for f in &frames {
        for line in f.lines() {
            if let Some(payload) = line.strip_prefix("data: ") {
                let v: Value = serde_json::from_str(payload).expect("下游帧须为合法 JSON");
                if let Some(t) = v
                    .get("delta")
                    .and_then(|d| d.get("thinking"))
                    .and_then(|x| x.as_str())
                {
                    values.push(t.to_string());
                }
                if let Some(s) = v
                    .get("delta")
                    .and_then(|d| d.get("signature"))
                    .and_then(|x| x.as_str())
                {
                    values.push(s.to_string());
                }
                if let Some(r) = v.get("redacted_data").and_then(|x| x.as_str()) {
                    values.push(r.to_string());
                }
            }
        }
    }
    assert_eq!(
        values,
        vec![
            "hmm...".to_string(),
            "sig-bytes-123".to_string(),
            "eHh4".to_string()
        ]
    );
    server.abort();
}

#[tokio::test]
async fn responses_incomplete_passthrough() {
    // P4/D4：`response.incomplete` 原样透传（保留 `incomplete_details`）并作为唯一终端，
    // 其后无数据帧、无合成 `response.failed`、不转换。
    let sse = b"data: {\"type\":\"response.incomplete\",\"sequence_number\":4,\"response\":{\"id\":\"r9\",\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":5,\"delta\":\"late\"}\n\ndata: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(
        joined.contains("\"status\":\"incomplete\""),
        "incomplete 须原样透传: {joined}"
    );
    assert!(
        joined.contains("incomplete_details") && joined.contains("max_output_tokens"),
        "incomplete_details 不得丢: {joined}"
    );
    assert!(
        !joined.contains("response.failed"),
        "不得合成 failed: {joined}"
    );
    assert!(!joined.contains("late"), "终端后数据帧不得透出: {joined}");
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.incomplete"))
            .count(),
        1,
        "incomplete 恰一: {joined}"
    );
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.completed") || f.contains("response.failed"))
            .count(),
        0,
        "不得出现其他终端: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn sse_response_builder_headers_compliant() {
    let (_tx, rx) = tokio::sync::mpsc::channel::<String>(64);
    let pump = tokio::spawn(async { std::future::pending::<PumpOutcome>().await });
    let resp = build_sse_response(rx, true, pump);
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|v| v.to_str().ok()),
        Some("json-whitespace")
    );
}

#[tokio::test]
async fn stream_transport_error_observed() {
    // S5/D5：`chunk()` 返回 `Err` 时须记 warn + 截断观测，不静默按 EOF 退出；
    // Chat 按 D6 补恰一 `[DONE]` 收尾。
    let body = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\xe7\x94\xb2\"}}]}\n\n"
        .to_vec();
    let (url, server) = broken_body_server("text/event-stream", body.len() + 128, body).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(joined.contains('甲'), "已收分片须保留: {joined}");
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "传输错误须按 Chat 策略补恰一 [DONE]: {joined}"
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "chunk Err 须置截断观测（open_ended）"
    );
    server.abort();
}

#[tokio::test]
async fn midstream_truncation_terminal_matrix() {
    // D6/S11：三协议中途断流（chunk Err）终端口径矩阵。
    // Chat 补恰一 [DONE]（open_ended）；Anthropic 不合成 message_stop（open_ended）；
    // Responses 合成恰一 response.failed（synthesized_failed）。
    let chat = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\xe7\x94\xb2\"}}]}\n\n"
        .to_vec();
    let (url, server) = broken_body_server("text/event-stream", chat.len() + 128, chat).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "Chat 断流须补恰一 [DONE]: {}",
        frames.join("")
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "Chat 记 open_ended"
    );
    server.abort();

    let anthropic = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\xe7\x94\xb2\"}}\n\n".to_vec();
    let (url, server) =
        broken_body_server("text/event-stream", anthropic.len() + 128, anthropic).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "anthropic"),
        0,
        "Anthropic 断流不得合成 message_stop: {}",
        frames.join("")
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "Anthropic 记 open_ended"
    );
    server.abort();

    let responses = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"\xe7\x94\xb2\"}\n\n".to_vec();
    let (url, server) =
        broken_body_server("text/event-stream", responses.len() + 128, responses).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 断流须合成恰一 response.failed: {}",
        frames.join("")
    );
    assert_eq!(
        metrics.truncated_count("synthesized_failed"),
        1,
        "Responses 记 synthesized_failed"
    );
    server.abort();
}
