//! 流泵帧出口辅助（P1/D2 自 `spawn.rs` 拆出）：还原守卫 + 前缀 hold 喂入与排空。

use {
    crate::service::{
        credential_vault::CredentialVault,
        json_walk::strip_bom,
        llm_gateway::GatewayMetrics,
        pii::PiiDetector,
        redaction::{BoundaryHold, PrefixHold},
    },
    serde_json::Value,
};

/// H2/D1 兜底回退：还原后帧 `jloads` 校验（BOM 感知）；失败时回退**还原前占位符帧**
/// （fail-closed，token 形态保留、不破帧），记 warn + `restore_fallback` 计数，
/// 对齐非流 `retry_stripped` 回退语义（`nonstream.rs::retry_stripped`）。
pub(crate) fn guard_restored_frame(
    restored: String,
    placeholder_frame: &str,
    metrics: &GatewayMetrics,
) -> String {
    if serde_json::from_str::<Value>(strip_bom(&restored)).is_ok() {
        return restored;
    }
    tracing::warn!("流式还原后 JSON 校验失败，已回退还原前占位符帧（fail-closed）");
    metrics.record_restore_fallback();
    placeholder_frame.to_string()
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
        agg.push_str(&out_prefix);
        agg.push_str(&format!("data: {out_data}\n\n"));
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
}
