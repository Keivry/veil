//! 流式任务回归：终端真实 index、opaque carry 与干净收尾判定。

use {
    super::super::event::{is_anthropic_opaque_event, is_anthropic_thinking_event},
    crate::{
        config::AuditMode,
        handler::llm::tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol},
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    serde_json::Value,
    std::sync::Arc,
};

mod terminal_eof;

#[tokio::test]
async fn anthropic_terminal_block_real_index() {
    // 终端最终审计阻断 Anthropic 时用真实 content block index，
    // 多块流不再硬编码 0 导致错位。
    let sse = br#"event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a","name":"run","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\"}"}}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"b","name":"exec","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.audit_mode = AuditMode::Block;
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(outcome.block_injected, "终端最终审计须注入阻断帧: {joined}");
    assert!(
        joined.contains("\"index\":1"),
        "阻断帧须用真实 index 1: {joined}"
    );
    assert!(
        !joined.contains("\"index\":0"),
        "不得硬编码 index 0: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_start\"").count(),
        1,
        "上游 message_start 已下行，合成须省略首帧: {joined}"
    );
    let ms_at = joined
        .find("\"type\":\"message_start\"")
        .expect("须含 message_start");
    let cbs_at = joined
        .find("content_block_start")
        .expect("须含 content_block_start");
    assert!(ms_at < cbs_at, "message_start 须为下游首帧: {joined}");
    server.abort();
}

#[tokio::test]
async fn anthropic_terminal_block_without_upstream_head_keeps_full_synth() {
    // 上游无 `message_start`（非规范流）时阻断：合成五件套须完整，`message_start` 恰一。
    let sse = br#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a","name":"run","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\"}"}}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"b","name":"exec","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.audit_mode = AuditMode::Block;
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(outcome.block_injected, "危险 tool 须阻断: {joined}");
    assert_eq!(
        joined.matches("[blocked:").count(),
        1,
        "审计恰一次: {joined}"
    );
    assert!(!joined.contains("rm -rf"), "危险参数不得泄漏: {joined}");
    let mut types: Vec<String> = Vec::new();
    for f in &frames {
        for line in f.lines() {
            if let Some(p) = line.strip_prefix("data: ") {
                let v: serde_json::Value = serde_json::from_str(p).expect("下游帧须为合法 JSON");
                types.push(v["type"].as_str().unwrap_or("").to_string());
            }
        }
    }
    assert_eq!(
        types,
        vec![
            "message_start",
            "content_block_start",
            "content_block_stop",
            "message_delta",
            "message_stop"
        ],
        "上游无 message_start 时须产出完整合成五件套: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_start\"").count(),
        1,
        "message_start 恰一: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn opaque_branch_token_carry() {
    // thinking 明文 opaque 增量接入 TokenCarry，跨帧切开的凭证
    // token 缝合后经还原路径还原为明文；token 须由请求侧脱敏实际产出方可还原
    // （minted-set 授权，返回值经残缺清理剥离、不消费）。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let _ = scope
        .redact_request_plain(&vault, &detector, "my-secret-001")
        .await;
    // marker 内部切点（`__`│`CRED_...`）——旧实现要求帧内完整 marker 字面量，必漏。
    let (head, tail) = token.split_at(2);
    assert_eq!(head, "__");
    let sse = format!(
        r#"event: content_block_delta
data: {{"type":"content_block_delta","index":0,"delta":{{"type":"thinking_delta","thinking":"{head}"}}}}

event: content_block_delta
data: {{"type":"content_block_delta","index":0,"delta":{{"type":"thinking_delta","thinking":"{tail}"}}}}

event: message_stop
data: {{"type":"message_stop"}}

"#
    )
    .into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(
        joined.contains("my-secret-001"),
        "thinking 跨帧 token 须缝合还原: {joined}"
    );
    assert!(!joined.contains(&token), "token 不得残留: {joined}");
    server.abort();
}

#[test]
fn opaque_fallback_declared() {
    // signature/redacted 密文载体按 fail-closed 声明不接 carry。
    for raw in [
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc"}}"#,
        r#"{"type":"redacted_thinking","redacted_data":"abc"}"#,
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":"sig"}}"#,
    ] {
        let v: Value = serde_json::from_str(raw).expect("构造 JSON");
        assert!(is_anthropic_opaque_event(&v), "须为 opaque: {raw}");
        assert!(
            !is_anthropic_thinking_event(&v),
            "密文/签名载体不接 carry: {raw}"
        );
    }
    let thinking: Value = serde_json::from_str(
        r#"{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"x"}}"#,
    )
    .expect("构造 JSON");
    assert!(
        is_anthropic_thinking_event(&thinking),
        "thinking 明文可缝合"
    );
}

fn anthropic_json_delta_frame(partial: &str) -> String {
    let payload = serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "input_json_delta", "partial_json": partial}
    });
    format!("event: content_block_delta\ndata: {payload}\n\n")
}

/// 拼接 Anthropic 各帧 `delta.partial_json`。
fn anthropic_partial_json_concat(frames: &[String]) -> String {
    let mut out = String::new();
    for f in frames {
        for line in f.lines() {
            let Some(p) = line.strip_prefix("data: ") else {
                continue;
            };
            if let Ok(v) = serde_json::from_str::<Value>(p)
                && let Some(d) = v.pointer("/delta/partial_json").and_then(|x| x.as_str())
            {
                out.push_str(d);
            }
        }
    }
    out
}

#[tokio::test]
async fn anthropic_partial_json_cross_frame_restore() {
    // `input_json_delta.partial_json` 内 stringified JSON 跨帧切开的占位符须缝合还原，
    // 多层转义不破帧；token 须由请求侧脱敏实际产出方可还原（minted-set 授权）。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let _ = scope
        .redact_request_plain(&vault, &detector, "my-secret-001")
        .await;
    let head = &token[..6];
    let rest = &token[6..];
    let mut sse = String::new();
    sse.push_str(&anthropic_json_delta_frame(r#"{"cmd":""#));
    sse.push_str(&anthropic_json_delta_frame(head));
    sse.push_str(&anthropic_json_delta_frame(&format!("{rest}\"}}")));
    sse.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    server.abort();
    let decoded = anthropic_partial_json_concat(&frames);
    assert_eq!(
        decoded, r#"{"cmd":"my-secret-001"}"#,
        "partial_json 占位符须缝合还原: {frames:?}"
    );
    assert!(!decoded.contains(&token), "token 不得残留: {decoded}");
    assert!(
        frames.iter().all(|f| {
            f.lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .all(|p| serde_json::from_str::<Value>(p).is_ok())
        }),
        "每帧须为合法 JSON: {frames:?}"
    );
}

#[tokio::test]
async fn signature_opaque_split_fragment_fail_closed() {
    // signature 密文载体按声明 fail-closed 不接 carry：跨帧切开的分片不得还原明文，
    // 亦不得泄漏完整 token；行为由本测试锁定。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let _ = scope
        .redact_request_plain(&vault, &detector, "my-secret-001")
        .await;
    let sig_frame = |sig: &str| {
        let payload = serde_json::json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "signature_delta", "signature": sig}
        });
        format!("event: content_block_delta\ndata: {payload}\n\n")
    };
    let mut sse = String::new();
    sse.push_str(&sig_frame(&token[..6]));
    sse.push_str(&sig_frame(&token[6..]));
    sse.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("my-secret-001"),
        "密文载体不得还原明文: {joined}"
    );
    assert!(
        !joined.contains(&token),
        "不得泄漏完整 token 原文: {joined}"
    );
}

#[tokio::test]
async fn responses_output_text_cross_frame_restore() {
    // Responses `response.output_text.delta` 真实事件三分裂（含 marker 内部切点）须还原明文。
    let (scope, vault, detector) = fresh_arcs();
    let token = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let hex = &token["__PII_1_".len()..token.len() - 2];
    let mk = |seq: u64, delta: &str| {
        let payload = serde_json::json!({
            "type": "response.output_text.delta",
            "sequence_number": seq,
            "delta": delta
        });
        format!("event: response.output_text.delta\ndata: {payload}\n\n")
    };
    let mut sse = String::new();
    sse.push_str(&mk(1, "我的手机号是__"));
    sse.push_str(&mk(2, &format!("PII_1_{}", &hex[..3])));
    sse.push_str(&mk(3, &format!("{}__。", &hex[3..])));
    sse.push_str("event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":4,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n");
    let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let mut decoded = String::new();
    for f in &frames {
        for line in f.lines() {
            let Some(p) = line.strip_prefix("data: ") else {
                continue;
            };
            if let Ok(v) = serde_json::from_str::<Value>(p)
                && v.get("type").and_then(|x| x.as_str()) == Some("response.output_text.delta")
                && let Some(d) = v.get("delta").and_then(|x| x.as_str())
            {
                decoded.push_str(d);
            }
        }
    }
    assert_eq!(
        decoded, "我的手机号是13812345678。",
        "须还原明文: {frames:?}"
    );
    assert!(!decoded.contains("__PII_"), "残片不得泄漏: {decoded}");
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.completed"))
            .count(),
        1,
        "恰一 response.completed: {frames:?}"
    );
}

#[tokio::test]
async fn anthropic_normal_end_releases_residual_before_message_stop() {
    // 正常结束（message_stop）前 fail-open 回吐未配对残段：释放帧为合法
    // content_block_delta 且先于 message_stop；message_stop 仍恰一。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let _ = scope
        .redact_request_plain(&vault, &detector, "my-secret-001")
        .await;
    let head = &token[..6];
    let sse = format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"tail {head}\"}}}}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
    )
    .into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    let rel = joined.find(head).expect("须含释放残段");
    let stop = joined.find("message_stop").expect("须含 message_stop");
    assert!(rel < stop, "释放帧须先于终止帧: {joined}");
    assert_eq!(
        frames.iter().filter(|f| f.contains("message_stop")).count(),
        1,
        "恰一 message_stop: {joined}"
    );
    for f in &frames {
        for line in f.lines() {
            if let Some(p) = line.strip_prefix("data: ") {
                assert!(
                    serde_json::from_str::<Value>(p).is_ok(),
                    "帧须合法 JSON: {p}"
                );
            }
        }
    }
}

#[tokio::test]
async fn responses_normal_end_releases_residual_before_completed() {
    // 正常结束（response.completed）前 fail-open 回吐未配对残段，先于终止帧。
    let (scope, vault, detector) = fresh_arcs();
    let mk = |seq: u64, delta: &str| {
        let payload = serde_json::json!({
            "type": "response.output_text.delta",
            "sequence_number": seq,
            "delta": delta
        });
        format!("event: response.output_text.delta\ndata: {payload}\n\n")
    };
    let sse = format!(
        "{}{}",
        mk(1, "tail __PI"),
        "event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n"
    );
    let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    let rel = joined.find("__PI").expect("须含释放残段");
    let comp = joined.find("response.completed").expect("须含 completed");
    assert!(rel < comp, "释放帧须先于终止帧: {joined}");
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.completed"))
            .count(),
        1,
        "恰一 response.completed: {joined}"
    );
}

#[tokio::test]
async fn responses_function_call_arguments_cross_frame_restore() {
    // Responses `response.function_call_arguments.delta`（stringified JSON）跨帧切开须还原明文。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let _ = scope
        .redact_request_plain(&vault, &detector, "my-secret-001")
        .await;
    let mk = |seq: u64, delta: &str| {
        let payload = serde_json::json!({
            "type": "response.function_call_arguments.delta",
            "sequence_number": seq,
            "item_id": "fc_1",
            "output_index": 0,
            "delta": delta
        });
        format!("event: response.function_call_arguments.delta\ndata: {payload}\n\n")
    };
    let a1 = format!(r#"{{"city":"{}"#, "__");
    let a2 = format!(r#"{}"}}"#, &token[2..]);
    let sse = format!(
        "{}{}{}",
        mk(1, &a1),
        mk(2, &a2),
        "event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":3,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n"
    );
    let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let mut args = String::new();
    for f in &frames {
        for line in f.lines() {
            let Some(p) = line.strip_prefix("data: ") else {
                continue;
            };
            if let Ok(v) = serde_json::from_str::<Value>(p)
                && v.get("type").and_then(|x| x.as_str())
                    == Some("response.function_call_arguments.delta")
                && let Some(d) = v.get("delta").and_then(|x| x.as_str())
            {
                args.push_str(d);
            }
        }
    }
    assert_eq!(
        args, r#"{"city":"my-secret-001"}"#,
        "arguments 占位符须缝合还原: {frames:?}"
    );
    assert!(!args.contains(&token), "token 不得残留: {args}");
}

/// 以注入的 scope/vault/detector 回放 SSE 文本并收集下游帧。
async fn pump_frames_with(
    protocol: Protocol,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
    sse: String,
) -> Vec<String> {
    let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) =
        collect_pump(upstream, pump_ctx(protocol, scope, vault, detector)).await;
    server.abort();
    frames
}

/// 以 fresh scope/vault/detector 回放原始 SSE 字节并收集下游帧。
async fn pump_raw_sse_frames(protocol: Protocol, sse: Vec<u8>) -> Vec<String> {
    let (scope, vault, detector) = fresh_arcs();
    pump_frames_with(
        protocol,
        scope,
        vault,
        detector,
        String::from_utf8(sse).expect("测试 SSE 须为 UTF-8"),
    )
    .await
}

/// canonical Chat 增量帧：`finish_reason`/`index` 位于 `delta` 之后
/// （真实上游字段序，见 `handler/llm/tests.rs` 的保真 fixture）。
fn chat_canonical_frame(content: &str) -> String {
    let payload = serde_json::json!({
        "id": "chatcmpl-abc",
        "object": "chat.completion.chunk",
        "created": 1700000000_u64,
        "model": "m-test",
        "choices": [{"delta": {"content": content}, "index": 0, "finish_reason": null}]
    });
    format!("data: {payload}\n\n")
}

/// 拼接 Chat 各帧 `choices[0].delta.content`（`[DONE]` 跳过）。
fn chat_delta_value(frames: &[String]) -> String {
    let mut out = String::new();
    for f in frames {
        for line in f.lines() {
            let Some(p) = line.strip_prefix("data: ") else {
                continue;
            };
            if p.trim() == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(p)
                && let Some(c) = v
                    .pointer("/choices/0/delta/content")
                    .and_then(|x| x.as_str())
            {
                out.push_str(c);
            }
        }
    }
    out
}

/// canonical Chat 信封逐帧保真断言：每个 `chat.completion.chunk` 帧的信封字段
/// 与原帧逐字节一致，且恰有 `expected` 个内容帧。
fn assert_canonical_chat_envelope(frames: &[String], expected: usize) {
    let mut seen = 0usize;
    for f in frames {
        for line in f.lines() {
            let Some(p) = line.strip_prefix("data: ") else {
                continue;
            };
            if p.trim() == "[DONE]" {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(p) else {
                continue;
            };
            if v.get("object").and_then(|x| x.as_str()) != Some("chat.completion.chunk") {
                continue;
            }
            assert_eq!(v["id"], "chatcmpl-abc", "id 须保真: {p}");
            assert_eq!(v["object"], "chat.completion.chunk", "object 须保真: {p}");
            assert_eq!(v["created"], 1700000000, "created 须保真: {p}");
            assert_eq!(v["model"], "m-test", "model 须保真: {p}");
            assert_eq!(v["choices"][0]["index"], 0, "index 须保真: {p}");
            assert!(
                v["choices"][0]["finish_reason"].is_null(),
                "finish_reason 须保真: {p}"
            );
            seen += 1;
        }
    }
    assert_eq!(seen, expected, "信封帧数须一致: {frames:?}");
}

#[tokio::test]
async fn canonical_chat_envelope_pii_finish_reason_after_delta_restore() {
    // 真实 Chat 信封（`finish_reason`/`index` 位于 `delta` 之后）三分裂
    // `我的手机号是__` | `PII_1_<hex3>` | `<hex5>__。`：下游拼接为明文，
    // 信封逐帧保真，无 `__PII_` 残片。旧判据要求值后帧尾仅结构字符，
    // 本形态在修复前永不建立 pending（用例必红）。
    let (scope, vault, detector) = fresh_arcs();
    let token = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let hex = &token["__PII_1_".len()..token.len() - 2];
    let mut sse = String::new();
    for content in [
        "我的手机号是__".to_string(),
        format!("PII_1_{}", &hex[..3]),
        format!("{}__。", &hex[3..]),
    ] {
        sse.push_str(&chat_canonical_frame(&content));
    }
    sse.push_str("data: [DONE]\n\n");
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let decoded = chat_delta_value(&frames);
    assert_eq!(
        decoded, "我的手机号是13812345678。",
        "须还原明文: {frames:?}"
    );
    assert!(!decoded.contains("__PII_"), "残片不得泄漏: {decoded}");
    assert!(!decoded.contains('_'), "不得残留任何下划线: {decoded}");
    assert_canonical_chat_envelope(&frames, 3);
}

#[tokio::test]
async fn canonical_chat_envelope_cred_finish_reason_after_delta_restore() {
    // 真实 Chat 信封下凭证 token 三分裂（含 marker 内部切点）：下游还原明文，
    // 信封逐帧保真。
    let (scope, vault, detector) = fresh_arcs();
    let secret = "cross-frame-secret-xyz";
    let token = vault.register(secret).expect("注册恒成功");
    let _ = scope.redact_request_plain(&vault, &detector, secret).await;
    let head = &token[..5];
    let mid = &token[5..12];
    let tail = &token[12..];
    let mut sse = String::new();
    for content in [head, mid, tail] {
        sse.push_str(&chat_canonical_frame(content));
    }
    sse.push_str("data: [DONE]\n\n");
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let decoded = chat_delta_value(&frames);
    assert_eq!(decoded, secret, "须还原明文: {frames:?}");
    assert!(!decoded.contains("__CRED"), "残片不得泄漏: {decoded}");
    assert_canonical_chat_envelope(&frames, 3);
}

#[tokio::test]
async fn response_new_plaintext_passthrough_verbatim() {
    // 规范场景「响应新检出不还原」（随响应侧再脱敏删除取代）：上游自造明文 PII
    // 单帧原样透出——不掩码、不生成 `__PII_*__`；同流内本请求铸造的凭据 token
    // 仍经还原路径还原为明文（KEEP 不变量）。旧行为下该号码会被响应侧掩码，
    // 本用例必红——删除后由本正测锁定新语义。
    let (scope, vault, detector) = fresh_arcs();
    let secret = "passthrough-keep-secret-001";
    let token = vault.register(secret).expect("注册恒成功");
    let _ = scope.redact_request_plain(&vault, &detector, secret).await;
    let phone = "13800138000";
    let mut sse = String::new();
    sse.push_str(&chat_canonical_frame(&format!(
        "上游新明文 {phone} 与本请求令牌 {token}"
    )));
    sse.push_str("data: [DONE]\n\n");
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let decoded = chat_delta_value(&frames);
    assert_eq!(
        decoded.matches(phone).count(),
        1,
        "上游新明文 PII 须逐字透出: {decoded}"
    );
    assert!(decoded.contains(secret), "本请求 token 仍须还原: {decoded}");
    assert!(!decoded.contains(&token), "token 不得残留: {decoded}");
    assert!(!decoded.contains("__PII_"), "不得生成新占位符: {decoded}");
    assert!(!decoded.contains("****"), "明文不得被掩码: {decoded}");
    assert_canonical_chat_envelope(&frames, 1);
}

#[tokio::test]
async fn response_new_plaintext_passthrough_verbatim_cross_frame() {
    // 跨帧上游自造明文（`138001` | `38000`）拼接后逐字节等于原文：不切割、
    // 不丢弃、不掩码；同流内本请求铸造的 token 仍还原明文（KEEP 不变量）。
    let (scope, vault, detector) = fresh_arcs();
    let secret = "passthrough-keep-secret-002";
    let token = vault.register(secret).expect("注册恒成功");
    let _ = scope.redact_request_plain(&vault, &detector, secret).await;
    let mut sse = String::new();
    for content in ["上游明文 138001", "38000", token.as_str()] {
        sse.push_str(&chat_canonical_frame(content));
    }
    sse.push_str("data: [DONE]\n\n");
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let decoded = chat_delta_value(&frames);
    assert_eq!(
        decoded,
        format!("上游明文 13800138000{secret}"),
        "跨帧明文须逐字节拼接且 token 还原: {frames:?}"
    );
    assert!(!decoded.contains("__PII_"), "不得生成新占位符: {decoded}");
    assert!(!decoded.contains("****"), "明文不得被掩码: {decoded}");
    assert_canonical_chat_envelope(&frames, 3);
}

/// canonical Responses 文本增量事件：`sequence_number` 位于 `delta` 之后
/// （真实上游字段序），信封含 `item_id/output_index/content_index`。
fn responses_canonical_frame(seq: u64, delta: &str) -> String {
    let payload = serde_json::json!({
        "type": "response.output_text.delta",
        "item_id": "msg_1",
        "output_index": 0,
        "content_index": 0,
        "delta": delta,
        "sequence_number": seq
    });
    format!("event: response.output_text.delta\ndata: {payload}\n\n")
}

#[tokio::test]
async fn canonical_responses_envelope_sequence_after_delta_restore() {
    // 真实 Responses 增量事件（`sequence_number` 位于 `delta` 之后）三分裂：
    // 下游还原明文，`item_id/output_index/content_index/sequence_number` 信封保真，
    // 全程恰一 `response.completed`。旧判据下 `sequence_number` 位于值后帧尾，
    // 本形态在修复前永不建立 pending（用例必红）。
    let (scope, vault, detector) = fresh_arcs();
    let token = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let hex = &token["__PII_1_".len()..token.len() - 2];
    let mut sse = String::new();
    sse.push_str(&responses_canonical_frame(1, "我的手机号是__"));
    sse.push_str(&responses_canonical_frame(
        2,
        &format!("PII_1_{}", &hex[..3]),
    ));
    sse.push_str(&responses_canonical_frame(3, &format!("{}__。", &hex[3..])));
    sse.push_str("event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":4,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n");
    let frames = pump_frames_with(Protocol::Responses, scope, vault, detector, sse).await;
    let mut decoded = String::new();
    let mut envelope_frames = 0usize;
    for f in &frames {
        for line in f.lines() {
            let Some(p) = line.strip_prefix("data: ") else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<Value>(p) else {
                continue;
            };
            if v.get("type").and_then(|x| x.as_str()) != Some("response.output_text.delta") {
                continue;
            }
            assert_eq!(v["item_id"], "msg_1", "item_id 须保真: {p}");
            assert_eq!(v["output_index"], 0, "output_index 须保真: {p}");
            assert_eq!(v["content_index"], 0, "content_index 须保真: {p}");
            assert!(v["sequence_number"].is_u64(), "sequence_number 须保真: {p}");
            envelope_frames += 1;
            if let Some(d) = v.get("delta").and_then(|x| x.as_str()) {
                decoded.push_str(d);
            }
        }
    }
    assert_eq!(
        decoded, "我的手机号是13812345678。",
        "须还原明文: {frames:?}"
    );
    assert!(!decoded.contains("__PII_"), "残片不得泄漏: {decoded}");
    assert_eq!(envelope_frames, 3, "三帧信封须逐帧保真: {frames:?}");
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.completed"))
            .count(),
        1,
        "恰一 response.completed: {frames:?}"
    );
}

#[tokio::test]
async fn responses_terminator_text_tail_not_absorbed() {
    // canonical `response.completed` 的 `response.output[].content[].text`
    // 以 `__` 结尾：终止帧 SHALL NOT 建立新 pending（否则流末剥离窄化内容），
    // 该内容值须逐字节透传，且终止帧之后不得出现补充的释放帧。
    let sse = br#"event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"hello"}

event: response.completed
data: {"type":"response.completed","sequence_number":2,"response":{"id":"resp_1","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"tail__"}]}]}}

"#
    .to_vec();
    let frames = pump_raw_sse_frames(Protocol::Responses, sse).await;
    let joined = frames.join("");
    assert!(
        joined.contains("\"text\":\"tail__\""),
        "终止帧内容值须逐字节透传（不得被吸收剥离）: {joined}"
    );
    assert!(
        !joined.contains("resp-residual"),
        "终止帧之后不得合成释放帧: {joined}"
    );
    assert_eq!(
        crate::service::block_inject::terminal_count(&frames, "responses"),
        1,
        "恰一响应终端: {joined}"
    );
}

/// Chat 增量帧（自定义 delta 对象，含多 choices 形态）。
fn chat_frame_with(choices: serde_json::Value) -> String {
    let payload = serde_json::json!({
        "id": "chatcmpl-abc",
        "object": "chat.completion.chunk",
        "created": 1700000000_u64,
        "model": "m-test",
        "choices": choices
    });
    format!("data: {payload}\n\n")
}

/// 拼接每帧 `choices[<choice>].delta.<field>` 字符串值。
fn chat_choice_field(frames: &[String], choice: usize, field: &str) -> String {
    let mut out = String::new();
    for f in frames {
        for line in f.lines() {
            let Some(p) = line.strip_prefix("data: ") else {
                continue;
            };
            if p.trim() == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(p)
                && let Some(s) = v
                    .pointer(&format!("/choices/{choice}/delta/{field}"))
                    .and_then(|x| x.as_str())
            {
                out.push_str(s);
            }
        }
    }
    out
}

#[tokio::test]
async fn chat_a4_duplicate_reasoning_fields_cross_frame_restore() {
    // A4：同帧 `delta.reasoning` 与 `delta.reasoning_details[0].text` 各半 token、
    // 下帧各自续写 → 两字段均还原明文，零 `__PII_` 残片。
    let (scope, vault, detector) = fresh_arcs();
    let token = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let head = &token[..6];
    let rest = &token[6..];
    let frame = |reasoning: &str, text: &str| {
        chat_frame_with(serde_json::json!([{
            "index": 0,
            "delta": {
                "reasoning": reasoning,
                "reasoning_details": [{"index": 0, "type": "reasoning.text", "text": text}]
            },
            "finish_reason": null
        }]))
    };
    let sse = format!("{}{}data: [DONE]\n\n", frame(head, head), frame(rest, rest));
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let reasoning = chat_choice_field(&frames, 0, "reasoning");
    let text = chat_choice_field(&frames, 0, "reasoning_details/0/text");
    assert_eq!(reasoning, "13812345678", "reasoning 须还原明文: {frames:?}");
    assert_eq!(
        text, "13812345678",
        "reasoning_details.text 须还原: {frames:?}"
    );
    assert!(
        !reasoning.contains("__PII_") && !text.contains("__PII_"),
        "残片不得泄漏"
    );
}

#[tokio::test]
async fn chat_a4_complete_field_not_polluted_by_split_field() {
    // A4 边界：仅 reasoning_details.text 被切开、reasoning 本帧完整 →
    // 完整字段不建立 stale 持有，下帧不被旧残段污染。
    let (scope, vault, detector) = fresh_arcs();
    let token = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let head = &token[..6];
    let rest = &token[6..];
    let full = token.as_str();
    let frame = |reasoning: &str, text: &str| {
        chat_frame_with(serde_json::json!([{
            "index": 0,
            "delta": {
                "reasoning": reasoning,
                "reasoning_details": [{"index": 0, "text": text}]
            },
            "finish_reason": null
        }]))
    };
    let sse = format!(
        "{}{}data: [DONE]\n\n",
        frame(full, head),
        frame("next", rest)
    );
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let reasoning = chat_choice_field(&frames, 0, "reasoning");
    let text = chat_choice_field(&frames, 0, "reasoning_details/0/text");
    assert_eq!(
        reasoning, "13812345678next",
        "完整字段须原样且不被污染: {frames:?}"
    );
    assert_eq!(text, "13812345678", "被切字段须还原明文: {frames:?}");
    assert!(!reasoning.contains("__PII_") && !text.contains("__PII_"));
}

#[tokio::test]
async fn chat_a1_multi_choices_cross_frame_restore() {
    // A1：`n>1` choices 各含半 token，互不覆盖，各 index 独立还原。
    let (scope, vault, detector) = fresh_arcs();
    let t0 = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let t1 = scope
        .pii_scope()
        .register("13900139000")
        .expect("注册恒成功");
    let frame = |c0: &str, c1: &str| {
        chat_frame_with(serde_json::json!([
            {"index": 0, "delta": {"content": c0}},
            {"index": 1, "delta": {"content": c1}}
        ]))
    };
    let sse = format!(
        "{}{}data: [DONE]\n\n",
        frame(&t0[..6], &t1[..6]),
        frame(&t0[6..], &t1[6..])
    );
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    assert_eq!(chat_choice_field(&frames, 0, "content"), "13812345678");
    assert_eq!(chat_choice_field(&frames, 1, "content"), "13900139000");
}

#[tokio::test]
async fn responses_a3_multi_output_index_release_keeps_index() {
    // A3：`output_index=1` 的未配对残段在 `response.completed` 前释放，
    // 释放帧落在原 `output_index`（非硬编码 0）。
    let sse = concat!(
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"output_index\":1,\"content_index\":0,\"item_id\":\"msg_1\",\"delta\":\"__PI\",\"sequence_number\":1}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n",
    );
    let frames = pump_raw_sse_frames(Protocol::Responses, sse.as_bytes().to_vec()).await;
    let release = frames
        .iter()
        .flat_map(|f| f.lines())
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|p| serde_json::from_str::<Value>(p).ok())
        .find(|v| v.get("delta").and_then(|d| d.as_str()) == Some("__PI"))
        .expect("须合成释放帧");
    assert_eq!(release["type"], "response.output_text.delta");
    assert_eq!(release["output_index"], 1, "释放须落原 output_index");
    assert_eq!(release["item_id"], "msg_1");
    let joined = frames.join("");
    let rel = joined.find("\"delta\":\"__PI\"").expect("须含释放残段");
    let comp = joined.find("response.completed").expect("须含 completed");
    assert!(rel < comp, "释放帧须先于终止帧: {joined}");
}

#[tokio::test]
async fn responses_reasoning_summary_release_carrier() {
    // B 结论：Responses `reasoning_summary*` 残段落 `response.reasoning_summary_text.delta`
    // 载体（携带 output_index/summary_index/item_id），由集成用例锁定。
    let sse = concat!(
        "event: response.reasoning_summary_text.delta\n",
        "data: {\"type\":\"response.reasoning_summary_text.delta\",\"output_index\":2,\"summary_index\":1,\"item_id\":\"rs_1\",\"delta\":\"__PI\",\"sequence_number\":1}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n",
    );
    let frames = pump_raw_sse_frames(Protocol::Responses, sse.as_bytes().to_vec()).await;
    let release = frames
        .iter()
        .flat_map(|f| f.lines())
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|p| serde_json::from_str::<Value>(p).ok())
        .find(|v| v.get("delta").and_then(|d| d.as_str()) == Some("__PI"))
        .expect("须合成 reasoning_summary 释放帧");
    assert_eq!(release["type"], "response.reasoning_summary_text.delta");
    assert_eq!(release["output_index"], 2);
    assert_eq!(release["summary_index"], 1);
    assert_eq!(release["item_id"], "rs_1");
}

#[tokio::test]
async fn anthropic_multi_content_block_interleaved_restore() {
    // Anthropic 多 `content_block` 交错：按根 `index` 区分，各块独立缝合与还原。
    let (scope, vault, detector) = fresh_arcs();
    let secret = "block-secret-xyz-001";
    let token = vault.register(secret).expect("注册恒成功");
    let _ = scope.redact_request_plain(&vault, &detector, secret).await;
    let head = &token[..6];
    let rest = &token[6..];
    let frame = |idx: u64, partial: &str| {
        let payload = serde_json::json!({
            "type": "content_block_delta",
            "index": idx,
            "delta": {"type": "input_json_delta", "partial_json": partial}
        });
        format!("event: content_block_delta\ndata: {payload}\n\n")
    };
    let sse = format!(
        "{}{}{}{}event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n",
        frame(0, head),
        frame(1, head),
        frame(0, rest),
        frame(1, rest),
    );
    let frames = pump_frames_with(Protocol::Anthropic, scope, vault, detector, sse).await;
    let concat_by_index = |idx: u64| -> String {
        let mut out = String::new();
        for f in &frames {
            for line in f.lines() {
                let Some(p) = line.strip_prefix("data: ") else {
                    continue;
                };
                if let Ok(v) = serde_json::from_str::<Value>(p)
                    && v.get("index").and_then(|x| x.as_u64()) == Some(idx)
                    && v.get("type").and_then(|x| x.as_str()) == Some("content_block_delta")
                    && let Some(d) = v.pointer("/delta/partial_json").and_then(|x| x.as_str())
                {
                    out.push_str(d);
                }
            }
        }
        out
    };
    assert_eq!(concat_by_index(0), secret, "block 0 须还原: {frames:?}");
    assert_eq!(concat_by_index(1), secret, "block 1 须还原: {frames:?}");
}

#[tokio::test]
async fn chat_done_releases_residual_before_terminal() {
    // 显式 `data: [DONE]` 回归：未配对残段释放帧先于终止帧，帧序不变。
    let sse = format!("{}data: [DONE]\n\n", chat_canonical_frame("tail __PI"));
    let frames = pump_raw_sse_frames(Protocol::Chat, sse.into_bytes()).await;
    let joined = frames.join("");
    let rel = joined.find("\"__PI\"").expect("须含释放残段: {joined}");
    let done = joined.find("data: [DONE]").expect("须含 [DONE]");
    assert!(rel < done, "释放帧须先于 [DONE]: {joined}");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "恰一 [DONE]: {joined}"
    );
}

#[tokio::test]
async fn non_json_frame_does_not_participate_in_carry() {
    // 非 JSON 帧（`parse_event_data` 为 `None`）不参与路径判定：直通且不建立持有，
    // 既有 carry 不受影响，跨帧 token 仍在下一 JSON 帧续完并还原。
    let (scope, vault, detector) = fresh_arcs();
    let token = scope
        .pii_scope()
        .register("13812345678")
        .expect("注册恒成功");
    let head = &token[..6];
    let rest = &token[6..];
    let sse = format!(
        "{}data: not-json-raw\n\n{}data: [DONE]\n\n",
        chat_canonical_frame(head),
        chat_canonical_frame(rest),
    );
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let joined = frames.join("");
    assert!(
        joined.contains("not-json-raw"),
        "非 JSON 帧须直通: {joined}"
    );
    assert_eq!(
        chat_delta_value(&frames),
        "13812345678",
        "须还原明文: {joined}"
    );
    assert!(!joined.contains("__PII_"), "残片不得泄漏: {joined}");
}

#[tokio::test]
async fn carry_over_limit_dropped_metrics_wired() {
    // 条目上界（16）外的新候选经 `TokenCarry` 计数并在 event_loop 排入网关指标。
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut delta = serde_json::Map::new();
    for i in 0..17 {
        delta.insert(format!("f{i}"), serde_json::json!("__PII_1_ab"));
    }
    let payload = serde_json::json!({
        "id": "c", "object": "chat.completion.chunk", "created": 1_u64, "model": "m",
        "choices": [{"index": 0, "delta": Value::Object(delta), "finish_reason": null}]
    });
    let sse = format!("data: {payload}\n\ndata: [DONE]\n\n");
    let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, _frames) = collect_pump(upstream, ctx).await;
    server.abort();
    assert_eq!(
        metrics.carry_over_limit_dropped_count(),
        1,
        "超 16 条目的失败候选须计一次"
    );
}

#[tokio::test]
async fn exit_passthrough_unregistered_token_on_non_json_arm() {
    // 非 JSON 帧走 `restore_response_with_spans`（plain 臂）：未注册完整 PII token
    // 原样透传（不再遮蔽），非 token 文本保留。
    let (scope, vault, detector) = fresh_arcs();
    let sse = "data: 联系邮箱是__PII_2_3bd028ca__。\n\ndata: [DONE]\n\n".to_string();
    let frames = pump_frames_with(Protocol::Chat, scope, vault, detector, sse).await;
    let joined = frames.join("");
    assert!(
        joined.contains("__PII_2_3bd028ca__"),
        "非 JSON 臂未注册 token 须原样透传: {joined}"
    );
    assert!(
        joined.contains("联系邮箱是"),
        "非 token 文本须保留: {joined}"
    );
}
