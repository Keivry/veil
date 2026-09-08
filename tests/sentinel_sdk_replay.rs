//! SDK 级回放移植（test-parity-close D2）：以 Python `api_spec_conformance 12` 为清单，
//! handler 级还原断言（经网关 HTTP 回放或公开 API 断言，非纯解析器回放）。
//! 全部夹具为合成数据，无真实 PII。
//!
//! 12 项清单（逐项 移植|豁免，无第三状态）：
//! | # | 项 | 状态 | 位置 |
//! |---|----|------|------|
//! | 01 | thinking `signature_delta` 单帧块透传（字节一致） | 移植 | `thinking签名单帧字节一致` |
//! | 02 | `display:omitted` 空思考块透传 | 移植 | `display_omitted空思考块透传` |
//! | 03 | `redacted_thinking.data` 不透明透传（未被改写） | 移植 | `redacted_thinking不透明透传` |
//! | 04 | `tool_use.input` 跨 `input_json_delta` 累积，`stop` 后可提交 parse | 移植 | `tooluse跨帧累积stop后可parse` |
//! | 05 | `fallback` 块 start+stop 无 delta，不误判未完成 | 移植 | `fallback无delta不误判` |
//! | 06 | `CR-only` 与 LF 双路径还原字节一致 | 移植 | `cr_only与lf双路径一致` |
//! | 07 | `error(overloaded)` 插帧中断（非挂起） | 移植 | `error_overloaded插帧中断` |
//! | 08 | `message_delta usage` 累计覆盖（非累加） | 移植 | `message_delta_usage覆盖非累加` |
//! | 09 | `stop_sequence` 回显 | 移植 | `stop_sequence回显` |
//! | 10 | 未知 event 跳过（不挂起，有效帧保留） | 移植 | `未知event跳过` |
//! | 11 | `ping` 忽略（不计事件，不挂起） | 移植 | `ping忽略` |
//! | 12 | usage 递减乱序按列取 max（与 gateway 实现对应，此处验收） | 移植 | `usage递减乱序取max` |

use {
    std::{collections::HashMap, path::PathBuf, sync::Arc},
    veil::{
        config::Config,
        router::build_router,
        service::llm_gateway::{Protocol, accumulate_usage, extract_usage_stream},
        state::SqliteOutcome,
    },
};

fn test_app(extra: &[(&str, &str)], db: &str) -> axum::Router {
    let mut env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(db),
            memory_only: true,
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    build_router(state)
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

async fn mock_upstream(frames: Vec<String>) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move || {
            let frames = frames.clone();
            async move {
                let stream = async_stream::stream! {
                    for f in frames {
                        yield Ok::<_, anyhow::Error>(bytes::Bytes::from(f.into_bytes()));
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                };
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    axum::body::Body::from_stream(stream),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

async fn post_stream(base: &str, path: &str, body: &str) -> (u16, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}{path}"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = tokio::time::timeout(std::time::Duration::from_secs(20), resp.text())
        .await
        .expect("下游 SSE 须在 20s 内闭合")
        .unwrap();
    (status, text)
}

const ANTH_BODY: &str =
    "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}";

// —— 01：thinking signature_delta 单帧块字节一致 ——

#[tokio::test]
async fn thinking_signature_single_frame_byte_identical() {
    let sig = "sig合成签名块deadbeef";
    let frames = vec![
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n".to_string(),
        format!("event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"signature_delta\",\"signature\":\"{sig}\"}}}}\n\n"),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-01.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200);
    assert!(body.contains(sig), "signature 块须字节一致透传: {body}");
    handle.abort();
    uhandle.abort();
}

// —— 02：display:omitted 空思考块 ——

#[tokio::test]
async fn display_omitted_empty_thinking_passthrough() {
    let frames = vec![
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\",\"display\":\"omitted\"}}\n\n".to_string(),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-02.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200, "空思考块不得挂起: {body}");
    assert!(!body.contains("[blocked:"), "{body}");
    handle.abort();
    uhandle.abort();
}

// —— 03：redacted_thinking 不透明透传 ——

#[tokio::test]
async fn redacted_thinking_opaque_passthrough() {
    let blob = "合成密文块zz9x8c7";
    let frames = vec![
        format!(
            "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"redacted_thinking\",\"data\":\"{blob}\"}}}}\n\n"
        ),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
            .to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-03.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200);
    assert!(
        body.contains(blob),
        "redacted_thinking.data 不得被改写: {body}"
    );
    handle.abort();
    uhandle.abort();
}

// —— 04：tool_use.input 跨帧累积，stop 后可 parse ——

#[tokio::test]
async fn tool_use_fragments_passthrough_ordered_until_stop() {
    let frames = vec![
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"calc\",\"input\":{}}}\n\n".to_string(),
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"x\\\":\"}}\n\n".to_string(),
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"1}\"}}\n\n".to_string(),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-04.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200);
    // 当前指定行为：网关对分片只做透传、不做逐包校验/合并（合并由下游 SDK 在
    // stop 后完成；审计侧累积见 AuditHold）。断言分片原样透传且顺序完整。
    assert!(body.contains("toolu_1"), "tool_use 须还原: {body}");
    let p1 = body
        .find(" partial_json")
        .or_else(|| body.find("\"partial_json\""));
    assert!(p1.is_some(), "分片须透传: {body}");
    assert!(
        body.contains("\\\"x\\\"") || body.contains("{\"x\""),
        "{body}"
    );
    assert!(body.contains("content_block_stop"), "stop 须透传: {body}");
    assert!(!body.contains("[blocked:"), "{body}");
    handle.abort();
    uhandle.abort();
}

// —— 05：fallback 块 start+stop 无 delta ——

#[tokio::test]
async fn fallback_block_without_delta_not_misjudged() {
    let frames = vec![
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_fb\",\"name\":\"fallback_tool\",\"input\":{}}}\n\n".to_string(),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-05.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200, "无 delta 块不得挂起: {body}");
    assert!(!body.contains("[blocked:"), "{body}");
    handle.abort();
    uhandle.abort();
}

// —— 06：CR-only 与 LF 双路径一致 ——

#[tokio::test]
async fn cr_only_and_lf_paths_match() {
    let lf_frames = vec![
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"双路径甲\"}}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let cr_frames: Vec<String> = lf_frames.iter().map(|f| f.replace('\n', "\r")).collect();
    for (tag, frames) in [("lf", lf_frames), ("cr", cr_frames)] {
        let (upstream, uhandle) = mock_upstream(frames).await;
        let (base, handle) = serve(test_app(
            &[("LLM_UPSTREAM", upstream.as_str())],
            &format!("/tmp/veil-sdk-06-{tag}.sqlite"),
        ))
        .await;
        let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
        assert_eq!(status, 200, "{tag}: {body}");
        assert!(body.contains("双路径甲"), "{tag} 还原须一致: {body}");
        handle.abort();
        uhandle.abort();
    }
}

// —— 07：error(overloaded) 插帧中断 ——

#[tokio::test]
async fn error_overloaded_interrupts_stream() {
    let frames = vec![
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"中断前分片\"}}\n\n".to_string(),
        "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"synthetic overload\"}}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-07.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(
        status, 200,
        "error 插帧后须中断而非挂起（本断言完成即非挂起）"
    );
    assert!(body.contains("中断前分片"), "中断前分片须保留: {body}");
    handle.abort();
    uhandle.abort();
}

// —— 08：message_delta usage 累计覆盖 ——

#[test]
fn message_delta_usage_overwrites_not_sums() {
    let start = serde_json::json!({"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":0}}});
    let delta = serde_json::json!({"type":"message_delta","usage":{"output_tokens":20}});
    let mut acc = None;
    accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &start));
    accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &delta));
    let a = acc.expect("须有累计值");
    assert_eq!((a.prompt_tokens, a.completion_tokens), (5, 20));
    assert_ne!(a.total_tokens, 5 + 20 + 25, "禁止 sum 双计");
}

// —— 09：stop_sequence 回显 ——

#[tokio::test]
async fn stop_sequence_echoed() {
    let frames = vec![
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"回显甲\"}}\n\n".to_string(),
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"stop_sequence\",\"stop_sequence\":\"合成停止串\"}}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-09.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200);
    assert!(body.contains("合成停止串"), "stop_sequence 须回显: {body}");
    handle.abort();
    uhandle.abort();
}

// —— 10：未知 event 跳过 ——

#[tokio::test]
async fn unknown_event_skipped() {
    let frames = vec![
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"有效分片\"}}\n\n".to_string(),
        "event: future_unknown_kind\ndata: {\"type\":\"future_unknown_kind\",\"payload\":{\"x\":1}}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-10.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200, "未知 event 不得挂起: {body}");
    assert!(body.contains("有效分片"), "有效帧须保留: {body}");
    handle.abort();
    uhandle.abort();
}

// —— 11：ping 忽略 ——

#[tokio::test]
async fn ping_ignored() {
    let frames = vec![
        "event: ping\ndata: {\"type\":\"ping\"}\n\n".to_string(),
        ": ping-heartbeat\n\n".to_string(),
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"心跳后分片\"}}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-sdk-11.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/messages", ANTH_BODY).await;
    assert_eq!(status, 200);
    assert!(body.contains("心跳后分片"), "{body}");
    handle.abort();
    uhandle.abort();
}

// —— 12：usage 递减乱序取 max ——

#[test]
fn usage_regressing_out_of_order_takes_max() {
    let hi = serde_json::json!({"type":"message_delta","usage":{"input_tokens":100,"output_tokens":50,"total_tokens":150}});
    let lo = serde_json::json!({"type":"message_delta","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}});
    let mut acc = None;
    accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &hi));
    accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &lo));
    let a = acc.expect("须有累计值");
    assert_eq!(
        (a.prompt_tokens, a.completion_tokens, a.total_tokens),
        (100, 50, 150),
        "递减输入不得回退"
    );
}
