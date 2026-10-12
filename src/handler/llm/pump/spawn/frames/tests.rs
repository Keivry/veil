use {
    super::*,
    crate::{
        handler::llm::tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{
            llm_gateway::Protocol,
            sse::{SseParser, data_frame},
        },
    },
};

#[test]
fn inner_json_broken_fallback() {
    // 还原后外层合法但 stringified JSON 内层破损时，守卫回退还原前
    // 占位符帧并记 `restore_fallback`，token 形态保留、不静默透传。
    let metrics = GatewayMetrics::default();
    let placeholder = r#"{"arguments":"{\"k\":\"__CRED_000001__\"}"}"#;
    let broken = r#"{"arguments":"{\"k\":\"p@ss\"q\"}"}"#;
    assert!(
        serde_json::from_str::<Value>(broken).is_ok(),
        "破损帧外层须仍可解析（构造前提）"
    );
    let out = guard_restored_frame(broken.to_string(), placeholder, &metrics);
    assert_eq!(out, placeholder, "内层破损须回退占位符帧");
    assert_eq!(metrics.restore_fallback_count(), 1);
}

#[test]
fn outer_valid_inner_broken_no_silent_passthrough() {
    // 外层合法不得掩盖内层破损，破损内层不被静默透传。
    let metrics = GatewayMetrics::default();
    let placeholder = r#"{"arguments":"{\"k\":\"__CRED_000001__\"}"}"#;
    let broken = r#"{"arguments":"{\"k\":\"p@ss\"q\"}"}"#;
    let out = guard_restored_frame(broken.to_string(), placeholder, &metrics);
    assert_ne!(out, broken, "破损内层不得静默透传");
    assert!(
        out.contains("__CRED_000001__"),
        "回退须保留 token 形态: {out}"
    );
}

#[test]
fn residual_frame_no_duplicate_prefix() {
    // 完整残余剥 `data:` 前缀后放行，帧内恒恰一前缀。
    let payload = residual_frame_payload("data: {\"a\":1}").expect("完整残余须保留");
    assert_eq!(payload, "{\"a\":1}", "须剥已存在的 data: 前缀");
    let mut agg = String::new();
    feed_output_frame(&mut agg, "", &payload);
    assert_eq!(agg, "data: {\"a\":1}\n\n");
    assert_eq!(agg.matches("data:").count(), 1, "不得二次加前缀: {agg:?}");
    assert!(
        residual_frame_payload("data: {\"a\": 1").is_none(),
        "半帧须丢弃"
    );
}

#[test]
fn residual_frame_bom_prefixed_complete_json_accepted() {
    // BOM 前缀完整 JSON 残余经中央 `jloads` 接受；半帧/非 JSON 仍丢弃。
    assert_eq!(
        residual_frame_payload("\u{feff}{\"a\":1}").as_deref(),
        Some("{\"a\":1}")
    );
    assert_eq!(
        residual_frame_payload("\u{feff}data: {\"a\":1}").as_deref(),
        Some("{\"a\":1}")
    );
    assert!(
        residual_frame_payload("\u{feff}{\"a\": 1").is_none(),
        "BOM 前缀半帧仍须丢弃"
    );
    assert!(
        residual_frame_payload("\u{feff}not json").is_none(),
        "BOM 前缀非 JSON 仍须丢弃"
    );
}

#[test]
fn residual_frame_cr_only() {
    // CR-only 完整残余可放行（trim 收敛），CR-only 半帧须丢弃。
    assert_eq!(
        residual_frame_payload("data: {\"a\":1}\r").as_deref(),
        Some("{\"a\":1}")
    );
    assert_eq!(
        residual_frame_payload("{\"a\":1}\r").as_deref(),
        Some("{\"a\":1}")
    );
    assert!(
        residual_frame_payload("data: {\"a\": 1\r").is_none(),
        "CR-only 半帧须丢弃"
    );
    assert!(
        residual_frame_payload("data: [DONE]").is_none(),
        "DONE 残余须丢弃"
    );
}

#[tokio::test]
async fn residual_frame_guard_fallback() {
    // 残余帧守卫失败须回退占位符帧（而非裸喂非法 JSON）并记 metrics；
    // 正常帧共用同一 helper 时等价放行、不触发回退。
    let metrics = GatewayMetrics::default();
    let mut agg = String::new();
    let placeholder =
        residual_frame_payload("data: {\"a\":\"__CRED_000001__\"}").expect("完整残余须放行");
    let broken = "{\"a\":\"p@ss\"q\"}".to_string();
    let (guarded, emitted) = emit_restored_json_frame(
        &mut FrameSink { agg: &mut agg },
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
        &mut FrameSink { agg: &mut agg2 },
        RestoredFrame {
            prefix: "event: x\n",
            restored: "{\"a\":\"plain\"}".to_string(),
            placeholder: "{\"a\":\"__CRED_000001__\"}",
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
    // 非本请求 minted token 按请求级授权剥离，不借进程单例还原。
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
            redacted.contains("__CRED_"),
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
        assert_eq!(downstream, payload, "opaque 帧须字节恒等透出");
    }
}
