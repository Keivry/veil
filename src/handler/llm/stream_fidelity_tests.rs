//! 流式保真/还原单测（H2/D1、M2/M3 簇；自 `stream_tests.rs` 拆出，测试名与断言不变）。

use {
    super::{
        pump::{RequestCtx, StreamPumpCtx},
        stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
    },
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::Scope,
            sse::SseParser,
        },
    },
    axum::http::StatusCode,
    serde_json::Value,
    std::{sync::Arc, time::Instant},
};
/// H2/D1 断言辅助：注册指定明文凭据，回放单帧 JSON 响应并收集下游帧与指标。
async fn pump_secret_text_frame(secret: &str) -> (Vec<String>, Arc<GatewayMetrics>) {
    let vault = Arc::new(CredentialVault::new());
    let token = vault.register(secret).expect("注册恒成功");
    let sse = format!("data: {{\"text\":\"{token}\"}}\n\ndata: [DONE]\n\n").into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let metrics = Arc::new(GatewayMetrics::default());
    let detector = Arc::new(PiiDetector::new());
    let scope = Arc::new(Scope::new());
    // B3：请求侧脱敏铸造 token（响应还原仅授权本请求实际产出）。
    let _ = scope.redact_request(&vault, &detector, secret).await;
    let ctx = StreamPumpCtx {
        req: RequestCtx {
            protocol: Protocol::Chat,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Off,
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
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    (frames, metrics)
}

fn restored_frame_payloads(frames: &[String]) -> Vec<String> {
    frames
        .iter()
        .flat_map(|f| f.lines())
        .filter_map(|l| l.strip_prefix("data: ").map(str::to_string))
        .collect()
}

fn restored_text_value(frames: &[String]) -> String {
    for payload in restored_frame_payloads(frames) {
        if let Ok(v) = serde_json::from_str::<Value>(&payload)
            && let Some(t) = v.get("text").and_then(|x| x.as_str())
        {
            return t.to_string();
        }
    }
    panic!("下游须含可解析的 text 帧: {frames:?}");
}

#[tokio::test]
async fn stream_restore_quotes_escaped() {
    // H2/D1：明文含 `"` 时写回按 RFC 8259 转义（`\"`），下游帧仍为合法 JSON
    // 且解析后字符串逐字符等于原始明文。
    let (frames, metrics) = pump_secret_text_frame("pa\"ss").await;
    let joined = frames.join("");
    assert!(
        joined.contains("pa\\\"ss"),
        "写回须为 JSON 转义形态: {joined}"
    );
    assert_eq!(restored_text_value(&frames), "pa\"ss", "解析后须语义等价");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");
}

#[tokio::test]
async fn stream_restore_special_chars() {
    // H2/D1 四场景：②反斜杠 ③换行控制字符（E2E）+ ④病态回退（守门直测，
    // 还原后仍破损）——每场景断言合法 JSON / 转义形态 / 回退计数 / 不破帧。
    let (frames, metrics) = pump_secret_text_frame("ab\\cd").await;
    let joined = frames.join("");
    assert!(joined.contains("ab\\\\cd"), "反斜杠须转义: {joined}");
    assert_eq!(restored_text_value(&frames), "ab\\cd", "语义等价");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");
    assert!(
        restored_frame_payloads(&frames)
            .iter()
            .filter(|p| p.trim() != "[DONE]")
            .all(|p| serde_json::from_str::<Value>(p).is_ok()),
        "帧不得破损: {frames:?}"
    );

    let (frames, metrics) = pump_secret_text_frame("line1\nline2").await;
    let joined = frames.join("");
    assert!(
        joined.contains("line1\\nline2"),
        "换行须为 \\n 转义: {joined}"
    );
    assert!(
        !joined.contains("line1\nline2"),
        "不得出现裸控制字符: {joined}"
    );
    assert_eq!(restored_text_value(&frames), "line1\nline2", "语义等价");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");

    let m = GatewayMetrics::default();
    let placeholder = r#"{"text":"__VG_CRED_000001__"}"#;
    let out = super::pump::spawn::guard_restored_frame(
        r#"{"text":"pa"ss"}"#.to_string(),
        placeholder,
        &m,
    );
    assert_eq!(out, placeholder, "病态还原须回退占位符帧（不破帧）");
    assert!(out.contains("__VG_CRED_"), "占位符须保留: {out}");
    assert!(
        serde_json::from_str::<Value>(&out).is_ok(),
        "回退帧须可解析"
    );
    assert_eq!(m.restore_fallback_count(), 1, "回退须计数 +1");
}

#[tokio::test]
async fn responses_error_preserves_code_param() {
    // D5/M2：上游 error 对象诊断字段（code/type/param/message）保留进合成
    // `response.failed.response.error`；恰一终端、不注入 output_index。
    let sse = br#"data: {"type":"error","error":{"type":"error","code":"rate_limit_exceeded","param":"model","message":"slow down"}}

"#
    .to_vec();
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
    let payload = frames
        .iter()
        .flat_map(|f| f.lines())
        .find_map(|l| {
            l.strip_prefix("data: ")
                .filter(|p| p.contains("response.failed"))
        })
        .expect("须合成 response.failed");
    let v: Value = serde_json::from_str(payload).expect("合成帧须合法 JSON");
    assert_eq!(v["response"]["error"]["code"], "rate_limit_exceeded");
    assert_eq!(v["response"]["error"]["param"], "model");
    assert_eq!(v["response"]["error"]["message"], "slow down");
    assert_eq!(v["response"]["error"]["type"], "error");
    assert_eq!(v["response"]["status"], "failed");
    assert!(v["response"].get("output_index").is_none());
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.failed"))
            .count(),
        1,
        "恰一终端: {joined}"
    );
    assert!(!joined.contains("response.completed"));
    server.abort();
}

#[tokio::test]
async fn opaque_frames_bypass_scan() {
    // M3/D6：signature_delta / redacted_thinking 帧跳过响应侧扫描与重序列化，
    // 输出载荷字节 == 上游载荷字节（PII 形密文不被掩码、不注入 `__PII_`）。
    let sig = r#"{"type":"content_block_delta","index":1,"delta":{"type":"signature_delta","signature":"sig-13812345678-abc"}}"#;
    let red = r#"{"type":"redacted_thinking","redacted_data":"CAIS13812345678xyz"}"#;
    let sse = format!(
        "event: content_block_delta\ndata: {sig}\n\nevent: content_block_delta\ndata: {red}\n\n"
    )
    .into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(
        !joined.contains("__PII_"),
        "opaque 帧不得注入占位符: {joined}"
    );
    for expected in [sig, red] {
        assert!(
            joined.contains(expected),
            "载荷须逐字节一致\n期望: {expected}\n实得: {joined}"
        );
    }
    server.abort();
}

async fn pump_sse_with_vault(
    protocol: Protocol,
    vault: Arc<CredentialVault>,
    sse: Vec<u8>,
) -> Vec<String> {
    pump_sse_with_vault_minted(protocol, vault, None, sse).await
}

/// B3 变体：`mint_secret` 非空时先经请求侧脱敏铸造该凭据 token，
/// 建立「token 为本请求实际产出」的响应还原授权前置。
async fn pump_sse_with_vault_minted(
    protocol: Protocol,
    vault: Arc<CredentialVault>,
    mint_secret: Option<&str>,
    sse: Vec<u8>,
) -> Vec<String> {
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let detector = Arc::new(PiiDetector::new());
    let scope = Arc::new(Scope::new());
    if let Some(secret) = mint_secret {
        let _ = scope.redact_request(&vault, &detector, secret).await;
    }
    let ctx = StreamPumpCtx {
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
    };
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    frames
}

#[tokio::test]
async fn redacted_thinking_pii_shaped_cipher_not_masked() {
    // M3/D6：`redacted_thinking.data` 密文含 PII 形数字串时原样透传，
    // 无 `__PII_` 注入、无字节改写。
    let payload = r#"{"type":"redacted_thinking","redacted_data":"13812345678-8.8.8.8-cipher"}"#;
    let sse = format!("event: content_block_delta\ndata: {payload}\n\n").into_bytes();
    let frames =
        pump_sse_with_vault(Protocol::Anthropic, Arc::new(CredentialVault::new()), sse).await;
    let joined = frames.join("");
    assert!(joined.contains(payload), "密文须逐字节透传: {joined}");
    assert!(!joined.contains("__PII_"), "不得掩码: {joined}");
}

#[tokio::test]
async fn thinking_delta_token_restore_no_reorder() {
    // M3/D6：`thinking_delta` 内已注册 token 精确还原为明文，帧其余字节与上游
    // 一致（不触发 JSON 键序/数字变化、无二次重排）。
    let vault = Arc::new(CredentialVault::new());
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let payload = format!(
        r#"{{"type":"content_block_delta","index":1,"delta":{{"type":"thinking_delta","thinking":"思考 {token} 完毕"}}}}"#
    );
    let sse = format!("event: content_block_delta\ndata: {payload}\n\n").into_bytes();
    let frames =
        pump_sse_with_vault_minted(Protocol::Anthropic, vault, Some("my-secret-001"), sse).await;
    let expected = payload.replace(&token, "my-secret-001");
    let joined = frames.join("");
    assert!(
        joined.contains(&expected),
        "token 须还原且其余字节一致\n期望: {expected}\n实得: {joined}"
    );
    assert!(!joined.contains(&token), "token 不得残留: {joined}");
}

#[tokio::test]
async fn real_wire_redacted_content_block_start_not_masked() {
    // M3/D6 补漏：真实 wire 形态的 opaque 载体位于 `content_block.type`
    //（`content_block_start` 的 `redacted_thinking`/`thinking`），既非顶层
    // `type` 亦非 `delta.type`；密文含 PII 形数字串时须逐字节透传、无 `__PII_`。
    let redacted = r#"{"type":"content_block_start","index":0,"content_block":{"type":"redacted_thinking","data":"13812345678-8.8.8.8-cipher"}}"#;
    let thinking = r#"{"type":"content_block_start","index":1,"content_block":{"type":"thinking","thinking":"","signature":"sig-13812345678-8.8.8.8-cipher"}}"#;
    let sse = format!(
        "event: content_block_start\ndata: {redacted}\n\nevent: content_block_start\ndata: {thinking}\n\n"
    )
    .into_bytes();
    let frames =
        pump_sse_with_vault(Protocol::Anthropic, Arc::new(CredentialVault::new()), sse).await;
    let joined = frames.join("");
    assert!(
        !joined.contains("__PII_"),
        "opaque 帧不得注入占位符: {joined}"
    );
    for expected in [redacted, thinking] {
        assert!(
            joined.contains(expected),
            "载荷须逐字节一致\n期望: {expected}\n实得: {joined}"
        );
    }
}

#[tokio::test]
async fn go_sse_terminal_transparent() {
    // GO/D8.5：三协议流恒以终止帧闭合（无 SSE 消费代码的 Go 客户端视为正常
    // 结束，不重试不挂起）：Chat 恰一 `[DONE]`、Anthropic 恰一 `message_stop`、
    // Responses 终端恰一（含 `response.failed`）。
    use crate::service::block_inject;
    let chat = block_inject::ensure_event_lines(block_inject::chat_block_frames("audit"));
    assert_eq!(block_inject::count_done(&chat), 1, "Chat 恰一 [DONE]");
    let anthropic =
        block_inject::ensure_event_lines(block_inject::anthropic_block_frames("audit", 0));
    assert_eq!(
        anthropic
            .iter()
            .filter(|f| f.contains("message_stop"))
            .count(),
        1,
        "Anthropic 恰一 message_stop"
    );
    let resp = block_inject::ensure_event_lines(block_inject::responses_block_frames("r1"));
    assert_eq!(
        block_inject::terminal_count(&resp, "responses"),
        1,
        "Responses 终端恰一"
    );
    assert!(
        resp.join("").contains("response.completed") || resp.join("").contains("response.failed"),
        "须含唯一终止类型"
    );
}

/// 4.1/S4 辅助：抽取下游各帧 `choices[0].delta.content` 并拼接。
fn delta_contents(frames: &[String]) -> String {
    let mut out = String::new();
    for f in frames {
        for line in f.lines() {
            let Some(payload) = line.strip_prefix("data: ") else {
                continue;
            };
            if payload.trim() == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(payload)
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

#[tokio::test]
async fn cross_frame_token_stitch_cred() {
    // 4.1/S4/D4：token 以两个合法 JSON 内容值跨帧切开（`__VG_CRE` + `D_000001__`）；
    // 下游须收到还原明文，且无残缺前缀、无续段残片、无完整 token 泄漏。
    let vault = Arc::new(CredentialVault::new());
    let token = vault
        .register("cross-frame-secret-xyz")
        .expect("注册恒成功");
    assert_eq!(token, "__VG_CRED_000001__", "首注册 token 形态");
    let (head, tail) = token.split_at(8);
    assert_eq!(head, "__VG_CRE");
    let sse = format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{head}\"}}}}]}}\n\ndata: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{tail}\"}}}}]}}\n\ndata: [DONE]\n\n"
    )
    .into_bytes();
    let frames =
        pump_sse_with_vault_minted(Protocol::Chat, vault, Some("cross-frame-secret-xyz"), sse)
            .await;
    let decoded = delta_contents(&frames);
    assert_eq!(
        decoded, "cross-frame-secret-xyz",
        "跨帧 token 须还原为明文: {frames:?}"
    );
    assert!(!decoded.contains("__VG_CRE"), "残缺前缀不得残留: {decoded}");
    assert!(!decoded.contains(tail), "续段不得泄漏: {decoded}");
}

#[tokio::test]
async fn cross_frame_token_stitch_pii() {
    // 4.1/S4/D4：PII token 以两个合法 JSON 内容值跨帧切开，下游须收到还原明文。
    let (scope, vault, detector) = fresh_arcs();
    let token = scope
        .pii_scope()
        .register("13800138000", false)
        .expect("PII 注册恒成功");
    assert!(token.starts_with("__PII_1_"), "首注册 PII token: {token}");
    let (head, tail) = token.split_at("__PII_1_".len() + 3);
    let sse = format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{head}\"}}}}]}}\n\ndata: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{tail}\"}}}}]}}\n\ndata: [DONE]\n\n"
    )
    .into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (_outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    server.abort();
    let decoded = delta_contents(&frames);
    assert_eq!(decoded, "13800138000", "PII 跨帧须还原明文: {frames:?}");
    assert!(!decoded.contains("__PII_"), "token 残片不得泄漏: {decoded}");
}

#[tokio::test]
async fn cross_frame_residual_strip() {
    // 4.2/S4：流末未配对残缺前缀须按既有口径剥离——输出无残片、无明文/token 泄漏。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"content":"prefix __VG_CRE"}}]}

data: [DONE]

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    server.abort();
    let decoded = delta_contents(&frames);
    assert_eq!(decoded, "prefix ", "安全前缀须保留、残缺须剥离: {frames:?}");
    assert!(!decoded.contains("__VG"), "残缺前缀不得透出: {decoded}");
    assert!(
        frames.iter().all(|f| !f.contains("__VG")),
        "下游任何帧不得含残缺/token: {frames:?}"
    );
}

async fn pump_raw_sse_with_metrics(
    protocol: Protocol,
    sse: Vec<u8>,
) -> (Vec<String>, Arc<GatewayMetrics>) {
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let ctx = StreamPumpCtx {
        req: RequestCtx {
            protocol,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Off,
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
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    (frames, metrics)
}

#[tokio::test]
async fn sse_envelope_id_retry_passthrough() {
    // TRN-1：上游 `id:`/`retry:` 须在出口透出，非数字 `retry` 不透出。
    let sse = b"id: 42\nretry: 3000\ndata: {\"a\":1}\n\ndata: [DONE]\n\n".to_vec();
    let (frames, _m) = pump_raw_sse_with_metrics(Protocol::Chat, sse).await;
    let joined = frames.join("");
    assert!(joined.contains("id: 42"), "id 须透出: {joined}");
    assert!(joined.contains("retry: 3000"), "retry 须透出: {joined}");
    let bad = b"retry: 3x\ndata: {\"a\":1}\n\ndata: [DONE]\n\n".to_vec();
    let (bad_frames, _m2) = pump_raw_sse_with_metrics(Protocol::Chat, bad).await;
    assert!(
        !bad_frames.join("").contains("retry:"),
        "非数字 retry 不得透出: {bad_frames:?}"
    );
}

#[tokio::test]
async fn sse_id_sequence_passthrough() {
    // TRN-1：多事件流 `id` 值逐个透出、顺序与上游一致。
    let sse =
        b"id: 1\ndata: {\"a\":1}\n\nid: 2\ndata: {\"b\":2}\n\nid: 3\ndata: {\"c\":3}\n\ndata: [DONE]\n\n"
            .to_vec();
    let (frames, _m) = pump_raw_sse_with_metrics(Protocol::Chat, sse).await;
    let mut ids: Vec<String> = Vec::new();
    for f in &frames {
        let mut cur: Option<String> = None;
        for line in f.lines() {
            if let Some(id) = line.strip_prefix("id: ") {
                cur = Some(id.to_string());
            } else if let Some(d) = line.strip_prefix("data: ")
                && d.trim() != "[DONE]"
                && let Some(id) = cur.take()
            {
                ids.push(id);
            }
        }
    }
    assert_eq!(ids, ["1", "2", "3"], "id 序列须与上游投递一致: {frames:?}");
}

#[tokio::test]
async fn sse_split_envelope_counters_unchanged() {
    // TRN-1：分块信封流与同内容同块流的事件计数、`add_sse_event()` 与转发帧数逐一致。
    let split: &[u8] =
        b"event: x\n\ndata: {\"a\":1}\n\nevent: y\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\n";
    let whole: &[u8] =
        b"event: x\ndata: {\"a\":1}\n\nevent: y\ndata: {\"b\":2}\n\ndata: [DONE]\n\n";
    let parse_count = |raw: &[u8]| {
        let mut p = SseParser::new();
        let mut emitted = 0;
        for chunk in raw.chunks(3) {
            emitted += p.push_bytes(chunk).len();
        }
        (emitted, p.sse_event_count)
    };
    assert_eq!(
        parse_count(split),
        parse_count(whole),
        "sse_event_count 须一致"
    );
    let (split_frames, split_metrics) =
        pump_raw_sse_with_metrics(Protocol::Chat, split.to_vec()).await;
    let (whole_frames, whole_metrics) =
        pump_raw_sse_with_metrics(Protocol::Chat, whole.to_vec()).await;
    assert_eq!(
        split_frames.len(),
        whole_frames.len(),
        "forwarded 帧数须一致"
    );
    assert_eq!(
        split_metrics.sse_event_total(),
        whole_metrics.sse_event_total(),
        "add_sse_event 计数须一致"
    );
    assert_eq!(
        split_frames.join(""),
        whole_frames.join(""),
        "下游字节须一致"
    );
}

async fn loopback_server_with_headers(
    status: u16,
    content_type: &str,
    extra_headers: Vec<(&'static str, &'static str)>,
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
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
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

async fn passthrough_response(
    status: u16,
    content_type: &str,
    extra_headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
    max_bytes: usize,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let (url, server) =
        loopback_server_with_headers(status, content_type, extra_headers, body).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let metrics = GatewayMetrics::default();
    let resp = super::dispatch::stream_upstream_passthrough(
        upstream,
        false,
        Protocol::Chat,
        max_bytes,
        &metrics,
    )
    .await;
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("下游体须可读")
        .to_vec();
    server.abort();
    (status, headers, bytes)
}

#[tokio::test]
async fn stream_passthrough_oversize_bounded() {
    // TRN-3：非错误状态超限 => 502 response_too_large，不转发超限字节。
    let body = vec![b'x'; 64];
    let (status, _h, got) = passthrough_response(200, "application/json", vec![], body, 8).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "非错误超限须 502");
    let text = String::from_utf8_lossy(&got);
    assert!(text.contains("response_too_large"), "{text}");
}

#[tokio::test]
async fn stream_passthrough_error_oversize_passthrough_unchanged() {
    // TRN-3：4xx/5xx 错误体超限仍保状态保字节透传，不改写为 502。
    let body = vec![b'e'; 64];
    let (status, _h, got) =
        passthrough_response(500, "application/json", vec![], body.clone(), 8).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "错误状态须保原码"
    );
    assert_eq!(got, body, "错误正文字节须逐字节一致");
}

#[tokio::test]
async fn stream_passthrough_within_limit_bytes() {
    // TRN-3：上限内状态与正文字节逐字节一致。
    let body = b"{\"ok\":true}".to_vec();
    let (status, _h, got) =
        passthrough_response(200, "application/json", vec![], body.clone(), 64).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, body, "上限内字节须逐一致");
}

#[tokio::test]
async fn stream_passthrough_strips_internal_headers() {
    // TRN-4：上游注入 `x-veil-debug` 不出现于下游。
    let body = b"{}".to_vec();
    let (status, headers, _got) = passthrough_response(
        200,
        "application/json",
        vec![("x-veil-debug", "leak")],
        body,
        64,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get("x-veil-debug").is_none(),
        "上游内部头不得泄漏: {headers:?}"
    );
}

#[tokio::test]
async fn stream_passthrough_internal_header_override() {
    // TRN-4：上游伪 `x-veil-protocol` 被剔除，下游为网关自置值。
    let body = b"{}".to_vec();
    let (_status, headers, _got) = passthrough_response(
        200,
        "application/json",
        vec![("x-veil-protocol", "forged")],
        body,
        64,
    )
    .await;
    assert_eq!(
        headers.get("x-veil-protocol").and_then(|v| v.to_str().ok()),
        Some("chat"),
        "须为网关自置值: {headers:?}"
    );
}
