//! D/B-2（Q5）：还原后帧统一守卫出口——`json_aware_line` 复核 → 守卫与回退阶梯
//! （R8-03/D2：掩码占位符帧；D11：签名/密文载体字节恒等）→ 出口喂入。残余帧
//! （`terminal.rs`）与正常帧（`event_loop.rs` 两臂）共用，杜绝任一路径裸喂未守卫
//! 载荷。落点避开 `event_loop.rs`（体量约束），亦不落
//! `service/redaction/restore_guard.rs`（保持其零 axum 依赖边界）。

use {
    super::frame_feed::{
        feed_output_frame,
        feed_seam_transparent_frame,
        guard_restored_frame_parsed,
    },
    crate::service::{
        credential_vault::CredentialVault,
        llm_gateway::GatewayMetrics,
        pii::PiiDetector,
        redaction::{BoundaryHold, PrefixHold, Scope},
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
    /// R8-03/D2：守卫失败时掩码回退（`redact_response_new_pii_with_skip`）的作用域。
    pub scope: &'a Scope,
    pub boundary_spans: &'a F,
    pub agg: &'a mut String,
}

/// 还原后帧输入：`prefix` 信封前缀（残余帧为空串）；`restored` 为还原/脱敏后
/// 载荷；`placeholder` 为还原前占位符帧（守卫失败回退目标）；`placeholder_parsed`
/// 为占位符帧解析产物（ARH-2：复用避免二次解析）；`json_aware` 为是否经
/// `json_aware_line` 复核（opaque 帧按 M3/D6 跳过）；`mask_fallback` 为守卫失败
/// 回退目标——`true` 掩码占位符帧（常规/残余臂），`false` 字节恒等回退上游原始帧
/// （D11：opaque 签名/密文载体臂，并旁路跨缝掩码）；`feed` 为是否立即送入出口
/// （tool 分片缓冲路径先取守卫产物、稍后重放，故不即时喂出）。
pub(super) struct RestoredFrame<'a> {
    pub prefix: &'a str,
    pub restored: String,
    pub placeholder: &'a str,
    pub placeholder_parsed: Option<&'a Value>,
    pub json_aware: bool,
    pub mask_fallback: bool,
    pub feed: bool,
}

/// D/Q5 + R8-03/D2 + D11：还原后帧统一守卫出口：
/// 1. `json_aware` 为真时经 `json_aware_line` 复核（H1/D2：合法 JSON 原样返回，不二次
///    `loads→walk→dumps`）；
/// 2. 守卫通过用 `mask(restore(frame))` 产物；失败：常规臂（`mask_fallback:true`）回退
///    **已应用响应侧新 PII 掩码**的占位符帧，掩码回退再失败则丢帧（不 `feed`、不下发）； opaque
///    臂（`mask_fallback:false`）字节恒等回退 `placeholder`，不丢帧、不施掩码； 两臂失败均 `warn` +
///    `record_restore_fallback` 恰一次；
/// 3. `feed` 为真时送入出口：常规臂经 `feed_output_frame`（跨缝掩码），opaque 臂经
///    `feed_seam_transparent_frame`（无掩码直通，R8-08/D9）。
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
    let guarded =
        if guard_restored_frame_parsed(&restored, frame.placeholder, frame.placeholder_parsed) {
            restored
        } else if !frame.mask_fallback {
            // D11：签名/密文载体帧守卫失败 SHALL 字节恒等回退上游原始帧——不丢帧
            //（保签名连续性）、不施掩码，记 warn + `restore_fallback` 恰一次。
            tracing::warn!("签名/密文载体帧还原守卫失败，按字节恒等回退上游原始帧（D11 豁免）");
            metrics.record_restore_fallback();
            frame.placeholder.to_string()
        } else {
            // R8-03/D2 阶梯②：回退已应用响应侧新 PII 掩码的占位符帧（掩码为 ASCII
            // 替换、不破 JSON），绝不回退未掩码正文。
            tracing::warn!("流式还原后 JSON 校验失败，回退已掩码占位符帧（fail-closed）");
            metrics.record_restore_fallback();
            let masked = sink
                .scope
                .redact_response_new_pii_with_skip(
                    sink.vault,
                    sink.detector,
                    frame.placeholder,
                    &[],
                )
                .await;
            if sink.scope.pii_unavailable() {
                // 阶梯③：掩码回退本身失败（PII 注册熵源/内部故障）——丢帧，不 `feed`、
                // 不下发，SHALL NOT 下发未掩码正文或破损帧。
                tracing::warn!("占位符帧掩码回退失败（PII 不可用），该帧丢弃（fail-closed）");
                return (String::new(), false);
            }
            masked
        };
    if !frame.feed {
        return (guarded, false);
    }
    let emitted = if frame.mask_fallback {
        feed_output_frame(
            sink.prefix_hold,
            sink.boundary,
            sink.detector,
            sink.vault,
            sink.boundary_spans,
            sink.agg,
            (frame.prefix.to_string(), guarded.clone()),
        )
        .await
    } else {
        feed_seam_transparent_frame(
            sink.prefix_hold,
            sink.boundary,
            sink.boundary_spans,
            sink.agg,
            (frame.prefix.to_string(), guarded.clone()),
        )
    };
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
                redaction::Scope,
                sse::{SseParser, data_frame},
            },
        },
    };

    #[tokio::test]
    async fn residual_frame_guard_fallback() {
        // D/Q5 + R8-03/D2：残余帧守卫失败须回退已掩码占位符帧（而非裸喂非法
        // JSON）并记 metrics；正常帧共用同一 helper 时等价放行、不触发回退。
        let metrics = GatewayMetrics::default();
        let scope = Scope::new();
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
                scope: &scope,
                boundary_spans: &spans,
                agg: &mut agg,
            },
            RestoredFrame {
                prefix: "",
                restored: broken,
                placeholder: &placeholder,
                placeholder_parsed: None,
                json_aware: true,
                mask_fallback: true,
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
                scope: &scope,
                boundary_spans: &spans,
                agg: &mut agg2,
            },
            RestoredFrame {
                prefix: "event: x\n",
                restored: "{\"a\":\"plain\"}".to_string(),
                placeholder: "{\"a\":\"__VG_CRED_000001__\"}",
                placeholder_parsed: None,
                json_aware: true,
                mask_fallback: true,
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

    #[tokio::test]
    async fn guard_failure_fallback_is_masked_and_counted_once() {
        // R8-03/D2 阶梯②：守卫失败回退**已应用响应侧新 PII 掩码**的占位符帧——
        // 下游零新检出 PII 明文、JSON 合法、`restore_fallback` 恰 +1。
        let metrics = GatewayMetrics::default();
        let scope = Scope::new();
        let detector = PiiDetector::new();
        let vault = CredentialVault::new();
        let mut prefix_hold = PrefixHold::new(detector.partial_prefix_hints());
        let mut boundary = BoundaryHold::new(0);
        let spans = |_: &str, _: usize| Vec::<(usize, usize)>::new();
        let mut agg = String::new();
        let phone = "13812345678";
        let placeholder = format!(r#"{{"text":"{phone}"}}"#);
        let broken = r#"{"text":"pa"ss"}"#.to_string();
        let (guarded, emitted) = emit_restored_json_frame(
            &mut FrameSink {
                prefix_hold: &mut prefix_hold,
                boundary: &mut boundary,
                detector: &detector,
                vault: &vault,
                scope: &scope,
                boundary_spans: &spans,
                agg: &mut agg,
            },
            RestoredFrame {
                prefix: "data: ",
                restored: broken,
                placeholder: &placeholder,
                placeholder_parsed: None,
                json_aware: true,
                mask_fallback: true,
                feed: true,
            },
            &metrics,
        )
        .await;
        assert!(emitted, "掩码回退帧须放行");
        assert!(!guarded.contains(phone), "零新检出 PII 明文: {guarded}");
        assert!(
            guarded.contains("__PII_"),
            "须为响应侧掩码 token 形态: {guarded}"
        );
        assert!(
            serde_json::from_str::<Value>(&guarded).is_ok(),
            "回退体须合法 JSON: {guarded}"
        );
        assert!(!agg.contains(phone), "下游不得出现明文: {agg}");
        assert_eq!(metrics.restore_fallback_count(), 1, "回退须恰记一次");
    }

    #[tokio::test]
    async fn opaque_guard_failure_falls_back_byte_identical() {
        // D11：`mask_fallback:false`（签名/密文载体臂）守卫失败 → 字节恒等回退
        // 上游原始帧，不丢帧、不施掩码，`restore_fallback` 恰 +1。
        let metrics = GatewayMetrics::default();
        let scope = Scope::new();
        let detector = PiiDetector::new();
        let vault = CredentialVault::new();
        let mut prefix_hold = PrefixHold::new(detector.partial_prefix_hints());
        let mut boundary = BoundaryHold::new(64);
        let spans = |_: &str, _: usize| Vec::<(usize, usize)>::new();
        let mut agg = String::new();
        let upstream_frame = r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig 13812345678 \"x"}}"#;
        let broken = r#"{"type":"content_block_delta","delta":{broken"#.to_string();
        let (guarded, emitted) = emit_restored_json_frame(
            &mut FrameSink {
                prefix_hold: &mut prefix_hold,
                boundary: &mut boundary,
                detector: &detector,
                vault: &vault,
                scope: &scope,
                boundary_spans: &spans,
                agg: &mut agg,
            },
            RestoredFrame {
                prefix: "event: content_block_delta\n",
                restored: broken,
                placeholder: upstream_frame,
                placeholder_parsed: None,
                json_aware: false,
                mask_fallback: false,
                feed: true,
            },
            &metrics,
        )
        .await;
        assert_eq!(guarded, upstream_frame, "守卫失败须字节恒等回退上游帧");
        assert!(emitted, "载体帧不得丢弃");
        assert!(
            agg.contains(upstream_frame),
            "直通输出须含原始帧字节: {agg}"
        );
        assert!(!agg.contains('*'), "不得施加掩码: {agg}");
        assert_eq!(metrics.restore_fallback_count(), 1, "回退须恰记一次");
    }

    #[tokio::test]
    async fn seam_transparent_frame_not_rewritten_by_mask_span_bytes() {
        // R8-08/D9：载体帧（`mask_fallback:false`）跨缝直通——滞留常规帧先放行，
        // 载体帧不进 `PrefixHold`/`BoundaryHold`，其字节 SHALL NOT 被
        // `mask_span_bytes` 改写；对照普通路径（`feed_output_frame`）同一跨缝
        // hint 两侧均被掩码，证明直通为独立通路而非检测失效。
        use super::super::frame_feed::feed_output_frame;

        let scope = Scope::new();
        let detector = PiiDetector::new();
        detector.load_custom_patterns(&[("tag".to_string(), r"TAG-\d+".to_string())]);
        let vault = CredentialVault::new();
        let spans = |_: &str, _: usize| Vec::<(usize, usize)>::new();

        let mut plain_hold = PrefixHold::new(detector.partial_prefix_hints());
        let mut plain_boundary = BoundaryHold::new(64);
        let mut plain_agg = String::new();
        for data in [r#"{"a":"TA"}"#, r#"{"a":"G-123"}"#] {
            feed_output_frame(
                &mut plain_hold,
                &mut plain_boundary,
                &detector,
                &vault,
                &spans,
                &mut plain_agg,
                ("data: ".to_string(), data.to_string()),
            )
            .await;
        }
        assert!(
            !plain_agg.contains("G-123"),
            "对照路径跨缝 hint 须掩码: {plain_agg}"
        );

        let mut prefix_hold = PrefixHold::new(detector.partial_prefix_hints());
        let mut boundary = BoundaryHold::new(64);
        let mut agg = String::new();
        let metrics = GatewayMetrics::default();
        let carrier = r#"{"a":"G-123"}"#;
        let (_g1, _e1) = emit_restored_json_frame(
            &mut FrameSink {
                prefix_hold: &mut prefix_hold,
                boundary: &mut boundary,
                detector: &detector,
                vault: &vault,
                scope: &scope,
                boundary_spans: &spans,
                agg: &mut agg,
            },
            RestoredFrame {
                prefix: "data: ",
                restored: r#"{"a":"TA"}"#.to_string(),
                placeholder: r#"{"a":"TA"}"#,
                placeholder_parsed: None,
                json_aware: false,
                mask_fallback: true,
                feed: true,
            },
            &metrics,
        )
        .await;
        let (g2, e2) = emit_restored_json_frame(
            &mut FrameSink {
                prefix_hold: &mut prefix_hold,
                boundary: &mut boundary,
                detector: &detector,
                vault: &vault,
                scope: &scope,
                boundary_spans: &spans,
                agg: &mut agg,
            },
            RestoredFrame {
                prefix: "data: ",
                restored: carrier.to_string(),
                placeholder: carrier,
                placeholder_parsed: None,
                json_aware: false,
                mask_fallback: false,
                feed: true,
            },
            &metrics,
        )
        .await;
        assert_eq!(g2, carrier, "载体帧守卫产物须字节恒等");
        assert!(e2, "载体帧须放行");
        assert!(
            agg.contains(&format!("data: {carrier}\n\n")),
            "载体帧须逐字节直通: {agg}"
        );
        assert!(
            !agg.contains('*'),
            "直通帧不得被 mask_span_bytes 改写: {agg}"
        );
        assert_eq!(metrics.restore_fallback_count(), 0, "守卫通过不回退");
    }
}
