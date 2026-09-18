//! 流泵帧出口辅助（P1/D2 自 `spawn.rs` 拆出）：还原守卫 + 前缀 hold 喂入与排空。

use {
    crate::service::{
        credential_vault::CredentialVault,
        json_walk::{jloads, strip_bom},
        pii::PiiDetector,
        redaction::{BoundaryHold, PrefixHold, restore_guard::restore_guard_ok},
        sse::{classify_residue, data_frame},
    },
    serde_json::Value,
};

#[cfg(test)]
use crate::service::llm_gateway::GatewayMetrics;

/// CHC-2/D7：截断残余帧归一化——对齐 Python `_llm.py:2718-2720`「丢弃残余」：
/// 先剥 BOM 与已存在的 `data:` 前缀，再要求载荷为**完整 JSON 容器**；半帧
/// （如 `data: {"a": 1`）、CR-only 半帧与非 JSON 残余一律返回 `None` 丢弃，
/// 杜绝把裸残余二次加 `data:` 前缀转发（下游 `JSONDecodeError`）。
pub(super) fn residual_frame_payload(raw: &str) -> Option<String> {
    let classified = classify_residue(raw)?;
    let trimmed = strip_bom(classified.trim()).trim();
    let payload = trimmed
        .strip_prefix("data:")
        .map(str::trim_start)
        .unwrap_or(trimmed);
    if (payload.starts_with('{') || payload.starts_with('[')) && jloads(payload).is_ok() {
        Some(payload.to_string())
    } else {
        None
    }
}

/// H2/D1 兜底回退（**测试专用**包装；生产回退阶梯见
/// `restore_emit::emit_restored_json_frame`）：还原后帧 `jloads` 校验（BOM 感知）；
/// 失败时回退**还原前占位符帧**（fail-closed，token 形态保留、不破帧），记 warn +
/// `restore_fallback` 计数，对齐非流 `retry_stripped` 回退语义。
#[cfg(test)]
pub(crate) fn guard_restored_frame(
    restored: String,
    placeholder_frame: &str,
    metrics: &GatewayMetrics,
) -> String {
    if guard_restored_frame_parsed(&restored, placeholder_frame, None) {
        return restored;
    }
    tracing::warn!("流式还原后 JSON 校验失败，已回退还原前占位符帧（fail-closed）");
    metrics.record_restore_fallback();
    placeholder_frame.to_string()
}

/// ARH-2（7.1）：调用方已持有占位符帧的解析产物时复用，避免同帧二次解析。
/// R8-03/D2：纯判定（无回退逻辑与指标副作用），回退阶梯由
/// `restore_emit::emit_restored_json_frame` 单一承载。
pub(crate) fn guard_restored_frame_parsed(
    restored: &str,
    placeholder_frame: &str,
    placeholder_parsed: Option<&Value>,
) -> bool {
    restore_guard_ok(restored, placeholder_frame, placeholder_parsed)
}

/// 把一帧送入边界 hold，仅在可放行时并入 `agg`；返回本轮是否有非空数据放行
/// （供审计 pending 抑制判定，语义同拆分前的 `!out_data.is_empty()`）。
fn push_frame(
    boundary: &mut BoundaryHold,
    boundary_spans: &impl Fn(&str, usize) -> Vec<(usize, usize)>,
    agg: &mut String,
    prefix: String,
    data: String,
) -> bool {
    let (out_prefix, out_data) = boundary.push(prefix, data, boundary_spans);
    let nonempty = !out_data.is_empty();
    if nonempty || !boundary.has_held() {
        agg.push_str(&data_frame(&out_prefix, &out_data));
    }
    nonempty
}

/// P1/D2：帧先经自定义规则跨帧前缀 hold，再送入边界 hold；
/// 无 hint（无自定义规则/字典）时直通，零行为变化。返回是否有非空数据放行。
pub(super) async fn feed_output_frame(
    prefix_hold: &mut PrefixHold,
    boundary: &mut BoundaryHold,
    detector: &PiiDetector,
    vault: &CredentialVault,
    boundary_spans: &impl Fn(&str, usize) -> Vec<(usize, usize)>,
    agg: &mut String,
    frame: (String, String),
) -> bool {
    let (prefix, data) = frame;
    if prefix_hold.is_empty() {
        return push_frame(boundary, boundary_spans, agg, prefix, data);
    }
    let preview = prefix_hold.preview(&data);
    let cred_map = vault.p2t_snapshot();
    let extra: Vec<(usize, usize)> = detector
        .scan_custom(&preview, cred_map.map())
        .await
        .into_iter()
        .map(|(_, _, s, e)| (s, e))
        .collect();
    let mut emitted = false;
    for (p, d) in prefix_hold.push(prefix, data, &extra) {
        emitted |= push_frame(boundary, boundary_spans, agg, p, d);
    }
    emitted
}

/// R8-08/D9：签名/密文载体帧**无掩码直通**——先排空 `PrefixHold`/`BoundaryHold`
/// 滞留的常规帧（沿正常缝窗掩码口径放行，保序，不影响其他帧的跨缝检测口径），
/// 载体帧本身不进 hold、不经 `mask_span_bytes`，逐字节并入 `agg`；后续帧从空 hold
/// 状态重启。返回本帧是否有非空数据放行。
pub(super) fn feed_seam_transparent_frame(
    prefix_hold: &mut PrefixHold,
    boundary: &mut BoundaryHold,
    boundary_spans: &impl Fn(&str, usize) -> Vec<(usize, usize)>,
    agg: &mut String,
    frame: (String, String),
) -> bool {
    for (p, d) in prefix_hold.flush() {
        push_frame(boundary, boundary_spans, agg, p, d);
    }
    if let Some((fp, fd)) = boundary.flush() {
        agg.push_str(&data_frame(&fp, &fd));
    }
    let (prefix, data) = frame;
    let nonempty = !data.is_empty();
    agg.push_str(&data_frame(&prefix, &data));
    nonempty
}

/// 终止/合成终端前把前缀 hold 滞留帧排入边界 hold（保序、不丢内容）。
pub(super) fn drain_prefix_hold(
    prefix_hold: &mut PrefixHold,
    boundary: &mut BoundaryHold,
    boundary_spans: &impl Fn(&str, usize) -> Vec<(usize, usize)>,
    agg: &mut String,
) {
    for (p, d) in prefix_hold.flush() {
        push_frame(boundary, boundary_spans, agg, p, d);
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::service::{
            credential_vault::CredentialVault,
            pii::detector::test_support::detector,
        },
    };

    #[tokio::test]
    async fn custom_rule_cross_frame_hold_e2e() {
        // F12/D12：自定义规则经 `feed_output_frame` 跨帧拼接后命中——首帧半截滞留不泄，
        // 续帧缝合完整命中并掩码后放行（端到端覆盖真实帧出口路径）。
        let detector = detector();
        detector.load_custom_patterns(&[("tag".to_string(), r"TAG-\d+".to_string())]);
        let mut prefix_hold = PrefixHold::new(detector.partial_prefix_hints());
        let mut boundary = BoundaryHold::new(0);
        let vault = CredentialVault::new();
        let spans = |_: &str, _: usize| Vec::<(usize, usize)>::new();
        let mut agg = String::new();
        let first = feed_output_frame(
            &mut prefix_hold,
            &mut boundary,
            &detector,
            &vault,
            &spans,
            &mut agg,
            ("data: ".to_string(), "TA".to_string()),
        )
        .await;
        assert!(!first && agg.is_empty(), "半截首帧不得先泄: {agg:?}");
        let second = feed_output_frame(
            &mut prefix_hold,
            &mut boundary,
            &detector,
            &vault,
            &spans,
            &mut agg,
            ("data: ".to_string(), "G-123".to_string()),
        )
        .await;
        assert!(second, "续接后须放行");
        assert!(!agg.contains("TAG-123"), "跨帧自定义规则命中须掩码: {agg}");
        assert!(!prefix_hold.has_held());
    }

    #[test]
    fn inner_json_broken_fallback() {
        // RED-1：还原后外层合法但 stringified JSON 内层破损时，守卫回退还原前
        // 占位符帧并记 `restore_fallback`，token 形态保留、不静默透传。
        let metrics = GatewayMetrics::default();
        let placeholder = r#"{"arguments":"{\"k\":\"__VG_CRED_000001__\"}"}"#;
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
        // RED-1：外层合法不得掩盖内层破损，破损内层不被静默透传。
        let metrics = GatewayMetrics::default();
        let placeholder = r#"{"arguments":"{\"k\":\"__VG_CRED_000001__\"}"}"#;
        let broken = r#"{"arguments":"{\"k\":\"p@ss\"q\"}"}"#;
        let out = guard_restored_frame(broken.to_string(), placeholder, &metrics);
        assert_ne!(out, broken, "破损内层不得静默透传");
        assert!(
            out.contains("__VG_CRED_000001__"),
            "回退须保留 token 形态: {out}"
        );
    }

    #[test]
    fn residual_frame_no_duplicate_prefix() {
        // CHC-2/D7：完整残余剥 `data:` 前缀后放行，帧内恒恰一前缀。
        let payload = residual_frame_payload("data: {\"a\":1}").expect("完整残余须保留");
        assert_eq!(payload, "{\"a\":1}", "须剥已存在的 data: 前缀");
        let mut boundary = BoundaryHold::new(0);
        let spans = |_: &str, _: usize| Vec::<(usize, usize)>::new();
        let mut agg = String::new();
        push_frame(&mut boundary, &spans, &mut agg, String::new(), payload);
        assert_eq!(agg, "data: {\"a\":1}\n\n");
        assert_eq!(agg.matches("data:").count(), 1, "不得二次加前缀: {agg:?}");
        assert!(
            residual_frame_payload("data: {\"a\": 1").is_none(),
            "半帧须按 Python 丢弃"
        );
    }

    #[test]
    fn residual_frame_bom_prefixed_complete_json_accepted() {
        // R5-23/D1：BOM 前缀完整 JSON 残余经中央 `jloads` 接受；半帧/非 JSON 仍丢弃。
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
        // CHC-2/D7：CR-only 完整残余可放行（trim 收敛），CR-only 半帧须丢弃。
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
}
