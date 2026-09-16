//! D/B-2（Q5）：还原后帧统一守卫出口——`json_aware_line` 复核 → 守卫
//! （失败回退占位符帧）→ `feed_output_frame`。残余帧（`terminal.rs`）与正常帧
//! （`event_loop.rs` 两臂）共用，杜绝任一路径裸喂未守卫载荷。落点避开
//! `event_loop.rs`（当前 753 行，B-2 体量约束），亦不落
//! `service/redaction/restore_guard.rs`（保持其零 axum 依赖边界）。

use {
    super::frame_feed::{feed_output_frame, guard_restored_frame_parsed},
    crate::service::{
        credential_vault::CredentialVault,
        llm_gateway::GatewayMetrics,
        pii::PiiDetector,
        redaction::{BoundaryHold, PrefixHold},
        sse::json_aware_line,
    },
    serde_json::Value,
};

/// 帧出口目的地（借用聚合，规避 `too_many_arguments`，与 `TerminalCtx` 同法）。
pub(super) struct FrameSink<'a, F>
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    pub prefix_hold: &'a mut PrefixHold,
    pub boundary: &'a mut BoundaryHold,
    pub detector: &'a PiiDetector,
    pub vault: &'a CredentialVault,
    pub boundary_spans: &'a F,
    pub agg: &'a mut String,
}

/// 还原后帧输入：`prefix` 信封前缀（残余帧为空串）；`restored` 为还原/脱敏后
/// 载荷；`placeholder` 为还原前占位符帧（守卫失败回退目标）；`placeholder_parsed`
/// 为占位符帧解析产物（ARH-2：复用避免二次解析）；`json_aware` 为是否经
/// `json_aware_line` 复核（opaque 帧按 M3/D6 跳过）；`feed` 为是否立即送入出口
/// （tool 分片缓冲路径先取守卫产物、稍后重放，故不即时喂出）。
pub(super) struct RestoredFrame<'a> {
    pub prefix: &'a str,
    pub restored: String,
    pub placeholder: &'a str,
    pub placeholder_parsed: Option<&'a Value>,
    pub json_aware: bool,
    pub feed: bool,
}

/// D/Q5：还原后帧统一守卫出口：
/// 1. `json_aware` 为真时经 `json_aware_line` 复核（H1/D2：合法 JSON 原样返回， 不二次
///    `loads→walk→dumps`）；
/// 2. `guard_restored_frame_parsed`（含 metrics + warn）——还原后 JSON 破损 fail-closed
///    回退**占位符帧**，绝不把非法 JSON 送下游；
/// 3. `feed` 为真时经 `feed_output_frame` 送入出口。
///
/// 返回（守卫后载荷，本帧是否有非空数据放行）。tool 分片缓冲路径以返回值复用
/// 同一守卫产物（`feed == false` 时 `emitted` 恒为假）。
pub(super) async fn emit_restored_json_frame<F>(
    sink: &mut FrameSink<'_, F>,
    frame: RestoredFrame<'_>,
    metrics: &GatewayMetrics,
) -> (String, bool)
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    let restored = if frame.json_aware {
        json_aware_line(&frame.restored, |s| s)
    } else {
        frame.restored
    };
    let guarded = guard_restored_frame_parsed(
        restored,
        frame.placeholder,
        frame.placeholder_parsed,
        metrics,
    );
    if !frame.feed {
        return (guarded, false);
    }
    let emitted = feed_output_frame(
        sink.prefix_hold,
        sink.boundary,
        sink.detector,
        sink.vault,
        sink.boundary_spans,
        sink.agg,
        (frame.prefix.to_string(), guarded.clone()),
    )
    .await;
    (guarded, emitted)
}

#[cfg(test)]
mod tests {
    use {
        super::{super::frame_feed::residual_frame_payload, *},
        crate::{
            handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
            service::{
                llm_gateway::Protocol,
                sse::{SseParser, data_frame},
            },
        },
    };

    #[tokio::test]
    async fn residual_frame_guard_fallback() {
        // D/Q5：残余帧守卫失败须回退占位符帧（而非裸喂非法 JSON）并记 metrics；
        // 正常帧共用同一 helper 时等价放行、不触发回退。
        let metrics = GatewayMetrics::default();
        let detector = PiiDetector::new();
        let vault = CredentialVault::new();
        let mut prefix_hold = PrefixHold::new(detector.partial_prefix_hints());
        let mut boundary = BoundaryHold::new(0);
        let spans = |_: &str, _: usize| Vec::<(usize, usize)>::new();
        let mut agg = String::new();
        let placeholder =
            residual_frame_payload("data: {\"a\":\"__VG_CRED_000001__\"}").expect("完整残余须放行");
        let broken = "{\"a\":\"p@ss\"q\"}".to_string();
        let (guarded, emitted) = emit_restored_json_frame(
            &mut FrameSink {
                prefix_hold: &mut prefix_hold,
                boundary: &mut boundary,
                detector: &detector,
                vault: &vault,
                boundary_spans: &spans,
                agg: &mut agg,
            },
            RestoredFrame {
                prefix: "",
                restored: broken,
                placeholder: &placeholder,
                placeholder_parsed: None,
                json_aware: true,
                feed: true,
            },
            &metrics,
        )
        .await;
        assert_eq!(guarded, placeholder, "守卫失败须回退占位符帧");
        assert!(emitted, "回退帧须放行");
        assert_eq!(
            metrics.restore_fallback_count(),
            1,
            "须记 restore_fallback 计数"
        );
        assert!(agg.contains(&placeholder), "输出须为占位符帧: {agg:?}");
        assert!(
            !agg.contains("\"p@ss\"q\""),
            "非法 JSON 不得裸喂下游: {agg:?}"
        );

        let mut agg2 = String::new();
        let (ok, emitted2) = emit_restored_json_frame(
            &mut FrameSink {
                prefix_hold: &mut prefix_hold,
                boundary: &mut boundary,
                detector: &detector,
                vault: &vault,
                boundary_spans: &spans,
                agg: &mut agg2,
            },
            RestoredFrame {
                prefix: "event: x\n",
                restored: "{\"a\":\"plain\"}".to_string(),
                placeholder: "{\"a\":\"__VG_CRED_000001__\"}",
                placeholder_parsed: None,
                json_aware: true,
                feed: true,
            },
            &metrics,
        )
        .await;
        assert_eq!(ok, "{\"a\":\"plain\"}");
        assert!(emitted2);
        assert!(
            agg2.contains("event: x\ndata: {\"a\":\"plain\"}\n\n"),
            "正常帧出口须等价: {agg2:?}"
        );
        assert_eq!(metrics.restore_fallback_count(), 1, "合法帧不新增回退计数");
    }

    #[tokio::test]
    async fn sse_protocol_roundtrip_invariants() {
        // K①/E：CR 载荷出口↔解析往返——含裸 CR/CRLF 的载荷经出口拆分与解析侧
        // 单 `\n` 连接后为**已声明 LF 归一**值，恰一事件、无 `event:` 名错配
        // （不主张逐字节恒等）。
        for (payload, expected) in [("a\nb", "a\nb"), ("a\r\nb", "a\nb"), ("a\rb", "a\nb")] {
            let frame = data_frame("", payload);
            let mut parser = SseParser::new();
            let events = parser.push_bytes(frame.as_bytes());
            assert_eq!(events.len(), 1, "恰一事件: {payload:?} -> {frame:?}");
            assert_eq!(
                events[0].data, expected,
                "含 CR 载荷须 LF 归一: {payload:?}"
            );
            assert!(
                events[0].event_type.is_none(),
                "无 event 名错配: {payload:?}"
            );
        }

        // K②/M：纯 `event:` 洪泛——溢出清空整队（fail-safe：宁缺信封不错标），
        // 后续 `data` 帧不得错配任何已丢 `event:` 标签。
        {
            let mut parser = SseParser::new();
            let mut sse = String::new();
            for i in 0..9 {
                sse.push_str(&format!("event: e{i}\n\n"));
            }
            sse.push_str("data: {\"a\":1}\n\n");
            let events = parser.push_bytes(sse.as_bytes());
            assert_eq!(events.len(), 1, "纯 event 块不产出事件，仅 data 帧");
            assert!(
                events[0].event_type.is_none(),
                "洪泛溢出后 data 帧不得错配 event 标签: {:?}",
                events[0].event_type
            );
            assert_eq!(events[0].data, "{\"a\":1}");
            assert!(
                parser.take_pending_events_dropped() > 0,
                "溢出须递增丢弃计数"
            );
        }

        // K③：redact↔restore 组合——请求侧脱敏产出的 token 经响应侧还原回明文；
        // 非本请求 minted token 按 B3 请求级授权剥离，不借进程单例还原。
        {
            let (scope, vault, detector) = fresh_arcs();
            let secret = "redact-restore-secret";
            let _token = vault.register(secret).expect("注册恒成功");
            let body = format!("{{\"v\":\"{secret}\"}}");
            let (redacted, _normalized) = scope
                .redact_request_with_report(&vault, &detector, &body)
                .await;
            assert!(
                !redacted.contains(secret),
                "请求侧脱敏须移除明文: {redacted}"
            );
            assert!(
                redacted.contains("__VG_CRED_"),
                "请求侧脱敏须产出 token: {redacted}"
            );
            let (restored, _spans) = scope.restore_response_with_spans_json(&vault, &redacted);
            assert_eq!(restored, body, "本请求 minted token 须还原回原明文 JSON");
            let outsider_token = vault.register("outsider-secret").expect("注册恒成功");
            let outsider_body = format!("{{\"v\":\"{outsider_token}\"}}");
            let (kept, _spans) = scope.restore_response_with_spans_json(&vault, &outsider_body);
            assert!(
                !kept.contains("outsider-secret"),
                "未授权 token 不得还原为明文: {kept}"
            );
        }

        // K④：opaque 帧字节恒等（`event_loop.rs` opaque 臂）——Anthropic
        // `signature_delta` 仅做字节级还原，载荷逐字节透出（JSON 转义不破）。
        {
            let payload = r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig\"x\\y"}}"#;
            let sse = format!("event: content_block_delta\ndata: {payload}\n\n");
            let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
            let upstream = reqwest::Client::new()
                .get(&url)
                .send()
                .await
                .expect("回环上游须可达");
            let (scope, vault, detector) = fresh_arcs();
            let (_outcome, frames) = collect_pump(
                upstream,
                pump_ctx(Protocol::Anthropic, scope, vault, detector),
            )
            .await;
            server.abort();
            let downstream = frames
                .iter()
                .flat_map(|f| f.lines())
                .find_map(|l| {
                    l.strip_prefix("data: ")
                        .filter(|p| p.contains("signature_delta"))
                })
                .expect("opaque 帧须送达下游");
            assert_eq!(downstream, payload, "opaque 帧载荷须字节恒等透出");
        }
    }
}
