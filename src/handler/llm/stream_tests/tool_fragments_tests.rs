//! P0-3.3 工具分片截断/完成 E2E（自 `stream_tests.rs` 拆出，测试名与断言不变）。

use {super::*, crate::service::block_inject};

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
            redact_only: false,
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
            redact_only: false,
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
