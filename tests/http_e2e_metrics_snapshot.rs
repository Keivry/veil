//! 指标快照形状 e2e（B5.3）：`/_admin/metrics` 字段类型/取值与 `series` 一致，
//! 空窗零值不崩溃、seed 后 series 行求和与快照一致。

use {
    common::{serve, test_app},
    std::time::{SystemTime, UNIX_EPOCH},
    veil::service::{
        credential::AppStateParts,
        llm_gateway::{Protocol, Usage},
        metrics::ChatRecord,
    },
};

mod common;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn usage(p: u64, c: u64, t: u64) -> Usage {
    Usage {
        prompt_tokens: p,
        completion_tokens: c,
        total_tokens: t,
        total_explicit: true,
        cached_read: 0,
        cached_write: 0,
    }
}

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

async fn get_json(client: &reqwest::Client, base: &str, path: &str) -> (u16, serde_json::Value) {
    let resp = client
        .get(format!("{base}{path}"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

#[tokio::test]
async fn b5_snapshot_shape_matches_series_and_empty_window_ok() {
    let (app, state) = test_app(&[]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    // 空窗快照：200 且零值（存在性 + 类型/取值），不崩溃。
    let (status, body) = get_json(&client, &base, "/_admin/metrics").await;
    assert_eq!(status, 200);
    assert_eq!(body["ok"], true);
    assert_eq!(body["requests"], 0);
    assert!(
        body["is_precise"].as_bool().is_some(),
        "is_precise 须为布尔: {body}"
    );
    assert_eq!(body["is_precise"], false, "空窗不得标精确");
    for field in ["sse_events", "ring_len", "dropped", "p95_ms"] {
        assert_eq!(
            body[field].as_u64(),
            Some(0),
            "空窗 {field} 须数值零: {body}"
        );
    }
    for field in [
        "prompt",
        "completion",
        "total",
        "cached_read",
        "cached_write",
        "unknown",
    ] {
        assert_eq!(
            body["tokens"][field].as_u64(),
            Some(0),
            "空窗 tokens.{field} 须数值零: {body}"
        );
    }
    for field in ["silent_discard", "open_ended", "synthesized_failed"] {
        assert_eq!(
            body["truncated"][field].as_u64(),
            Some(0),
            "空窗 truncated.{field} 须数值零: {body}"
        );
    }
    assert!(
        body["latency_buckets"]
            .as_array()
            .is_some_and(|a| a.len() == 12 && a.iter().all(|v| v.as_u64() == Some(0))),
        "latency_buckets 须 12 桶全零: {body}"
    );
    for field in ["per_protocol", "per_model"] {
        assert!(
            body[field]
                .as_object()
                .is_some_and(|m| m.is_empty() && m.values().all(|v| v.is_u64())),
            "空窗 {field} 须空对象: {body}"
        );
    }
    for field in ["chat/completions", "v1/messages", "v1/responses"] {
        assert_eq!(
            body["chat_tail_lenient"][field].as_u64(),
            Some(0),
            "chat_tail_lenient.{field} 须数值零: {body}"
        );
    }
    // ARC-2：审批决策表只读观测键存在且为数值（空窗零值）。
    for field in ["approval_decision_overflow_total", "decision_table_size"] {
        assert_eq!(
            body[field].as_u64(),
            Some(0),
            "空窗 {field} 须数值零: {body}"
        );
    }
    // series 空窗同样 200：三粒度 points 为空数组（形状 + 零值语义）。
    for granularity in ["daily", "hourly", "five_min"] {
        let (status, series) = get_json(
            &client,
            &base,
            &format!("/_admin/series?granularity={granularity}"),
        )
        .await;
        assert_eq!(status, 200, "{granularity}");
        assert_eq!(series["granularity"], granularity);
        assert!(
            series["points"].as_array().is_some_and(|a| a.is_empty()),
            "{granularity} 空窗 points 须空数组: {series}"
        );
    }

    // seed 已知用量：快照取值 + series 行求和一致性（非仅形状）。
    let ts = now_secs();
    let u1 = usage(10, 5, 15);
    let u2 = usage(4, 2, 6);
    state.admin_state().metrics.record_chat(ChatRecord {
        protocol: Protocol::Chat,
        model: "snap-m",
        latency_ms: 12,
        usage: Some(&u1),
        truncated_mode: None,
        is_precise: true,
        ts_secs: ts,
    });
    state.admin_state().metrics.record_chat(ChatRecord {
        protocol: Protocol::Responses,
        model: "snap-m",
        latency_ms: 20,
        usage: Some(&u2),
        truncated_mode: Some("open_ended"),
        is_precise: true,
        ts_secs: ts,
    });
    state.admin_state().metrics.flush().await.unwrap();

    let (status, snap) = get_json(&client, &base, "/_admin/metrics").await;
    assert_eq!(status, 200);
    assert_eq!(snap["requests"], 2);
    assert_eq!(snap["tokens"]["prompt"], 14);
    assert_eq!(snap["tokens"]["completion"], 7);
    assert_eq!(snap["tokens"]["total"], 21);
    assert!(snap["is_precise"].is_boolean());
    assert_eq!(snap["ring_len"], 2, "ring_len 须反映两样本");
    assert_eq!(snap["per_protocol"]["chat/completions"], 1);
    assert_eq!(snap["per_protocol"]["v1/responses"], 1);
    assert_eq!(snap["per_model"]["snap-m"], 2);
    assert_eq!(snap["tokens"]["cached_read"], 0);
    assert_eq!(snap["tokens"]["cached_write"], 0);
    // 协议分桶求和须等于 requests（非空窗业务值，不止 shape）。
    let proto_sum: u64 = snap["per_protocol"]
        .as_object()
        .expect("per_protocol 须对象")
        .values()
        .map(|v| v.as_u64().expect("协议桶须数值"))
        .sum();
    assert_eq!(proto_sum, snap["requests"].as_u64().unwrap());
    assert_eq!(snap["truncated"]["open_ended"], 1);
    assert_eq!(snap["truncated"]["silent_discard"], 0);
    assert_eq!(snap["truncated"]["synthesized_failed"], 0);

    let (status, series) = get_json(&client, &base, "/_admin/series?granularity=daily").await;
    assert_eq!(status, 200);
    let points = series["points"].as_array().expect("points 须数组");
    assert_eq!(points.len(), 2, "两协议各一行: {series}");
    let sum_requests: u64 = points.iter().map(|p| p["requests"].as_u64().unwrap()).sum();
    let sum_total: u64 = points
        .iter()
        .map(|p| p["total_tokens"].as_u64().unwrap())
        .sum();
    assert_eq!(
        sum_requests,
        snap["requests"].as_u64().unwrap(),
        "series 行 requests 求和须等于快照 requests: {series} vs {snap}"
    );
    assert_eq!(
        sum_total,
        snap["tokens"]["total"].as_u64().unwrap(),
        "series 行 total_tokens 求和须等于快照 tokens.total: {series} vs {snap}"
    );
    handle.abort();
}

/// mock 上游 SSE：四帧（首帧 tool_calls 完成事件 + 两内容 + `[DONE]`）。
/// 首帧即完成事件使审计 hold 提前 `mark_completed`，其后逐事件独立发送，
/// 帧数可精确对拍 `sse_events`。
async fn mock_upstream_sse() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|| async {
            let body = "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
                        data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"sse-1\"}}]}\n\n\
                        data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"sse-2\"}}]}\n\n\
                        data: [DONE]\n\n";
            (
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                body,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn sse_snapshot_shape_after_stream() {
    // T4/D4：消费一条 mock SSE 流后读取 `/_admin/metrics`：`sse_events` 相对基线
    // 精确增加（= 下游收到 data 帧数）、`per_protocol` 行存在、快照三列类型/取值。
    // `PII_RESPONSE_SIDE=0` 关闭响应侧边界 hold（直通），使每事件一次发送；
    // 否则边界 hold 会延迟一帧并在终端合并发送，帧数不可精确对拍。
    let (upstream, uhandle) = mock_upstream_sse().await;
    let (app, _state) = test_app(&[
        ("LLM_UPSTREAM", upstream.as_str()),
        ("PII_RESPONSE_SIDE", "0"),
    ]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let (status, before) = get_json(&client, &base, "/_admin/metrics").await;
    assert_eq!(status, 200);
    let baseline = before["sse_events"].as_u64().expect("sse_events 须数值");
    assert_eq!(baseline, 0, "基线 sse_events 须为零: {before}");

    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(
            "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = tokio::time::timeout(std::time::Duration::from_secs(15), resp.text())
        .await
        .expect("下游 SSE 须在 15s 内闭合")
        .unwrap();
    let downstream_frames = body
        .lines()
        .filter(|l| l.trim_start().starts_with("data:"))
        .count();
    assert_eq!(downstream_frames, 4, "mock 流须四帧到下游: {body}");

    let (status, after) = get_json(&client, &base, "/_admin/metrics").await;
    assert_eq!(status, 200);
    let delta = after["sse_events"].as_u64().expect("sse_events 须数值") - baseline;
    assert_eq!(
        delta, downstream_frames as u64,
        "sse_events 增量须等于下游收到帧数: after={after} body={body:?}"
    );
    assert_eq!(
        after["per_protocol"]["chat/completions"], 1,
        "per_protocol 对应行须存在: {after}"
    );
    assert!(
        after["truncated"]["silent_discard"].is_u64()
            && after["truncated"]["open_ended"].is_u64()
            && after["truncated"]["synthesized_failed"].is_u64(),
        "truncated 三 mode 须数值: {after}"
    );
    assert_eq!(after["truncated"]["open_ended"], 0);
    assert!(after["chat_tail_lenient"].is_object());
    for key in ["chat/completions", "v1/messages", "v1/responses"] {
        assert!(
            after["chat_tail_lenient"][key].is_u64(),
            "chat_tail_lenient.{key} 须数值: {after}"
        );
    }
    assert!(
        after["is_precise"].is_boolean(),
        "is_precise 须布尔: {after}"
    );

    uhandle.abort();
    handle.abort();
}
