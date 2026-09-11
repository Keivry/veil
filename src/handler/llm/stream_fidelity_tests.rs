//! 流式保真/还原单测（H2/D1、M2/M3 簇；自 `stream_tests.rs` 拆出，测试名与断言不变）。

use {
    super::{
        pump::StreamPumpCtx,
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
        },
    },
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
    let ctx = StreamPumpCtx {
        protocol: Protocol::Chat,
        scope: Arc::new(Scope::new()),
        vault,
        detector: Arc::new(PiiDetector::new()),
        audit_mode: AuditMode::Off,
        audit_policy_file: None,
        approval_whitelist: Vec::new(),
        hold_max: 1_048_576,
        pii_boundary_chars: 64,
        gateway_metrics: metrics.clone(),
        admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
            "/tmp/veil-gateway-units-test.sqlite",
        ))),
        sqlite_precise: false,
        req_start: Instant::now(),
        pending: Arc::new(PendingApprovals::default()),
        init_conv: None,
        normalized_out: false,
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
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let ctx = StreamPumpCtx {
        protocol,
        scope: Arc::new(Scope::new()),
        vault,
        detector: Arc::new(PiiDetector::new()),
        audit_mode: AuditMode::Off,
        audit_policy_file: None,
        approval_whitelist: Vec::new(),
        hold_max: 1_048_576,
        pii_boundary_chars: 64,
        gateway_metrics: Arc::new(GatewayMetrics::default()),
        admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
            "/tmp/veil-gateway-units-test.sqlite",
        ))),
        sqlite_precise: false,
        req_start: Instant::now(),
        pending: Arc::new(PendingApprovals::default()),
        init_conv: None,
        normalized_out: false,
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
    let frames = pump_sse_with_vault(Protocol::Anthropic, vault, sse).await;
    let expected = payload.replace(&token, "my-secret-001");
    let joined = frames.join("");
    assert!(
        joined.contains(&expected),
        "token 须还原且其余字节一致\n期望: {expected}\n实得: {joined}"
    );
    assert!(!joined.contains(&token), "token 不得残留: {joined}");
}

#[tokio::test]
async fn go_sse_terminal_transparent() {
    // GO/D8.5：三协议流恒以终止帧闭合（无 SSE 消费代码的 Go 客户端视为正常
    // 结束，不重试不挂起）：Chat 恰一 `[DONE]`、Anthropic 恰一 `message_stop`、
    // Responses 终端恰一（含 `response.failed`）。
    use crate::service::block_inject;
    let chat = block_inject::ensure_event_lines(block_inject::chat_block_frames("audit"));
    assert_eq!(block_inject::count_done(&chat), 1, "Chat 恰一 [DONE]");
    let anthropic = block_inject::ensure_event_lines(block_inject::anthropic_block_frames("audit"));
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
