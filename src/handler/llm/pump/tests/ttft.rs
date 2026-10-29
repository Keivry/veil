//! TTFT 定格回归：滞留帧 flush 不得无条件定格；纯工具调用流 `ttft_ms`/`tps` 为 `None`。

use {
    super::super::{synth_flush, ttft::TtftTracker},
    crate::{
        handler::llm::{
            tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
            trace::{RequestTrace, StreamLog},
        },
        service::{
            llm_gateway::{GatewayMetrics, Protocol},
            request_log::{RequestFilter, RequestLog, RequestRow},
        },
    },
    std::{sync::Arc, time::Instant},
};

#[tokio::test]
async fn synth_flush_bookkeeping_residual_does_not_set_ttft() {
    // 缺陷回归：Fast 攒批下 `finish_reason` 块与 `[DONE]` 同样滞留到 EOF，
    // flush 若无条件 `note_content` 会把纯簿记残余钉成流末 TTFT（零可见 token 的
    // 纯工具调用流因此得到伪造的 `ttft_ms`/`tps`）。
    let metrics = GatewayMetrics::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    let ttft = TtftTracker::new(Instant::now());
    let mut agg =
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"
            .to_string();
    let outcome = synth_flush::midstream_terminal(
        Protocol::Chat,
        &["data: [DONE]\n\n".to_string()],
        None,
        &mut agg,
        &tx,
        &metrics,
        &ttft,
    )
    .await;
    drop(tx);
    let mut joined = String::new();
    while let Some(f) = rx.recv().await {
        joined.push_str(&f);
    }
    assert!(joined.contains("tool_calls"), "滞留帧须下发: {joined}");
    assert!(outcome.terminal_sent, "Chat 合成 [DONE] 成功须置终端位");
    assert_eq!(
        ttft.first_ms(),
        None,
        "簿记滞留帧不承载生成 token，flush 不得定格 TTFT"
    );
}

#[tokio::test]
async fn synth_flush_settles_ttft_already_marked_by_content_frame() {
    // 对照：内容帧在入 `agg` 时已由 `event_loop` 按 `carries_output_token` 置位，
    // flush 只负责「下发成功后落首个时延」——该路径仍须定格。
    let metrics = GatewayMetrics::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    let ttft = TtftTracker::new(Instant::now());
    let mut agg =
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"only-via-flush\"}}]}\n\n"
            .to_string();
    // 等价于 `event_loop` 对 `carries_output_token` 为真的帧所做的标记。
    ttft.note_content();
    let outcome = synth_flush::midstream_terminal(
        Protocol::Chat,
        &["data: [DONE]\n\n".to_string()],
        None,
        &mut agg,
        &tx,
        &metrics,
        &ttft,
    )
    .await;
    drop(tx);
    let mut joined = String::new();
    while let Some(f) = rx.recv().await {
        joined.push_str(&f);
    }
    assert!(
        joined.contains("only-via-flush"),
        "flush 须实际下发: {joined}"
    );
    assert!(outcome.terminal_sent, "Chat 合成 [DONE] 成功须置终端位");
    assert!(agg.is_empty(), "flush 后 agg 须被 take 清空");
    assert!(
        ttft.first_ms().is_some(),
        "内容帧已置位时 flush 须落首个时延"
    );
}

#[tokio::test]
async fn synth_flush_without_content_leaves_ttft_unset() {
    // 对照：无滞留内容（纯合成 [DONE]）不是 token，TTFT 保持未采样。
    let metrics = GatewayMetrics::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    let ttft = TtftTracker::new(Instant::now());
    let mut agg = String::new();
    synth_flush::midstream_terminal(
        Protocol::Chat,
        &["data: [DONE]\n\n".to_string()],
        None,
        &mut agg,
        &tx,
        &metrics,
        &ttft,
    )
    .await;
    drop(tx);
    let mut joined = String::new();
    while let Some(f) = rx.recv().await {
        joined.push_str(&f);
    }
    assert!(joined.contains("[DONE]"), "终端帧须下发: {joined}");
    assert_eq!(ttft.first_ms(), None, "合成 [DONE] 不构成 token");
}

/// 跑一条 Chat SSE 流并取回唯一落库行（`ttft_ms`/`tps` 是行的派生字段）。
async fn only_row_after_stream(sse: &[u8]) -> RequestRow {
    let path = std::env::temp_dir().join(format!(
        "veil-ttft-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&path);
    let log = Arc::new(RequestLog::new(path.clone(), true, 0));
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.stream_log = Some(StreamLog {
        guard: log.stream_guard(
            RequestTrace::new(
                "req-ttft".to_string(),
                Protocol::Chat,
                None,
                false,
                Instant::now(),
            )
            .into_row(),
        ),
        request_log: Arc::clone(&log),
        upstream_status: 200,
    });
    let (url, server) = loopback_server(200, "text/event-stream", sse.to_vec()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let _ = collect_pump(upstream, ctx).await;
    server.abort();
    log.flush_blocking().expect("刷盘须成功");
    let page = log
        .query(&RequestFilter {
            limit: Some(10),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    let _ = std::fs::remove_file(&path);
    assert_eq!(page.rows.len(), 1, "须恰好一行: {page:?}");
    page.rows.into_iter().next().expect("已断言恰一行")
}

#[tokio::test]
async fn pure_tool_call_stream_has_no_ttft_and_no_tps() {
    // 规范回归（`openspec/changes/fix-llm-observability/specs/request-log/spec.md`）：
    // 首个生成 token 帧未下发（纯工具调用流）时 `ttft_ms` SHALL 为 `NULL`；
    // TPS 窗口依赖 TTFT，故同样为 `None`。
    let sse = concat!(
        "data: {\"id\":\"c1\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":",
        "[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",",
        "\"arguments\":\"{\\\"city\\\":\\\"BJ\\\"}\"}}]}}]}\n\n",
        "data: {\"id\":\"c1\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},",
        "\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":5,",
        "\"completion_tokens\":7,\"total_tokens\":12}}\n\n",
        "data: [DONE]\n\n"
    );
    let row = only_row_after_stream(sse.as_bytes()).await;
    assert_eq!(
        row.ttft_ms, None,
        "纯工具调用流无生成 token 帧，ttft_ms 须为 NULL: {row:?}"
    );
    assert_eq!(row.tps, None, "ttft 不可测时 tps 须为 None: {row:?}");
    assert_eq!(row.completion_tokens, 7, "工具参数 token 照常计数: {row:?}");
}

#[tokio::test]
async fn tool_call_args_split_placeholder_residual_does_not_set_ttft() {
    // 规范回归（`fix-llm-observability` request-log spec）：纯工具调用流的形参含
    // token 形态残片（`__PII_`）时会生成 carry 残段，「[DONE] 前回吐」若无条件定格就会
    // 在流末伪造 `ttft_ms`。回吐帧与终端同口径按 `carries_output_token` 判定。
    let sse = concat!(
        "data: {\"id\":\"c4\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":",
        "[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"f\",",
        "\"arguments\":\"__PII_\"}}]}}]}\n\n",
        "data: {\"id\":\"c4\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},",
        "\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":5,",
        "\"completion_tokens\":7,\"total_tokens\":12}}\n\n",
        "data: [DONE]\n\n"
    );
    let row = only_row_after_stream(sse.as_bytes()).await;
    assert_eq!(
        row.ttft_ms, None,
        "工具形参残段不是生成 token，ttft_ms 须为 NULL: {row:?}"
    );
    assert_eq!(row.tps, None, "ttft 不可测时 tps 须为 None: {row:?}");
}

#[tokio::test]
async fn content_delta_beside_tool_placeholder_residual_still_settles_ttft() {
    // 对照：同一流里既有真实内容增量、又有工具形参残段时，内容增量仍须定格
    // （守卫只排除不承载生成 token 的帧，不因残段存在而整体失效）。
    let sse = concat!(
        "data: {\"id\":\"c5\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: {\"id\":\"c5\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":",
        "[{\"index\":0,\"function\":{\"arguments\":\"__C\"}}]}}]}\n\n",
        "data: {\"id\":\"c5\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},",
        "\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":5,",
        "\"completion_tokens\":7,\"total_tokens\":12}}\n\n",
        "data: [DONE]\n\n"
    );
    let row = only_row_after_stream(sse.as_bytes()).await;
    assert!(
        row.ttft_ms.is_some(),
        "内容增量须定格 TTFT（残段存在不改变判据）: {row:?}"
    );
}

#[tokio::test]
async fn single_content_token_stream_still_settles_ttft() {
    // 对照：一条内容增量即构成首个生成 token，`ttft_ms`/`tps` 须有值。
    let sse = concat!(
        "data: {\"id\":\"c2\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: {\"id\":\"c2\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},",
        "\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,",
        "\"completion_tokens\":7,\"total_tokens\":12}}\n\n",
        "data: [DONE]\n\n"
    );
    let row = only_row_after_stream(sse.as_bytes()).await;
    assert!(row.ttft_ms.is_some(), "内容增量下行须定格 TTFT: {row:?}");
    // `tps` 由公式派生（窗口为零时本机快流可为 `None`）——只锁一致性，不锁墙钟。
    assert_eq!(
        row.tps,
        crate::service::request_log::tokens_per_sec(
            row.completion_tokens,
            row.latency_ms,
            row.ttft_ms
        ),
        "tps 须与 (completion_tokens, latency, ttft) 公式一致: {row:?}"
    );
}
