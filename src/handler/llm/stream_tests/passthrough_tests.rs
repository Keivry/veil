//! 帧保真/透传 E2E（自 `stream_tests.rs` 拆出，测试名与断言不变）。

use {super::*, serde_json::Value};

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
