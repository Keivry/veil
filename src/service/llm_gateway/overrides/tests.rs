//! `overrides` 纯应用逻辑单测（协议映射、三段覆盖矩阵与合并模式两态）。

use {super::*, axum::http::HeaderMap, serde_json::json, std::collections::BTreeMap};

/// 空头表（`HeaderValueSpec` 泛型），测试构造用。
fn empty_headers() -> HeaderMap<crate::config::HeaderValueSpec> { HeaderMap::with_capacity(0) }

/// 构造三段覆盖（测试用）。
fn rules(default: &[(&str, Value)], override_: &[(&str, Value)], drop: &[&str]) -> ParamOverrides {
    ParamOverrides {
        default: default
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect(),
        r#override: override_
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect(),
        drop: drop.iter().map(|key| (*key).to_string()).collect(),
    }
}

/// 构造仅含单协议规则的覆盖表（测试用）。
fn target_with(protocol: ParamProtocol, rules: ParamOverrides) -> UpstreamOverrides {
    let mut params = BTreeMap::new();
    params.insert(protocol, rules);
    UpstreamOverrides {
        headers: empty_headers(),
        params,
        override_existing: true,
        user_agent: None,
        drop_headers: Vec::new(),
    }
}

/// 构造 JSON 对象（测试用）。
fn object(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

#[test]
fn default_fills_only_missing_and_preserves_client_value() {
    let mut body = object(&[("temperature", json!(0.2))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(
            &[("temperature", json!(0.7)), ("top_p", json!(0.9))],
            &[],
            &[],
        ),
        true,
    );
    assert!(changed, "top_p 缺失须补齐，如实报告变化");
    assert_eq!(body.get("temperature"), Some(&json!(0.2)), "客户端值须保留");
    assert_eq!(body.get("top_p"), Some(&json!(0.9)));

    // 全部键已存在（值不同）时 default 不覆盖、不报变化。
    let mut body = object(&[("temperature", json!(0.2))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(&[("temperature", json!(0.7))], &[], &[]),
        true,
    );
    assert!(!changed, "default 不得覆盖既有键");
    assert_eq!(body.get("temperature"), Some(&json!(0.2)));
}

#[test]
fn override_always_replaces_even_when_present() {
    let mut body = object(&[("reasoning_effort", json!("low"))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(&[], &[("reasoning_effort", json!("high"))], &[]),
        true,
    );
    assert!(changed);
    assert_eq!(body.get("reasoning_effort"), Some(&json!("high")));

    let mut body = object(&[("temperature", json!(0.7))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(&[], &[("temperature", json!(0.7))], &[]),
        true,
    );
    assert!(!changed, "值相同不得报告变化（免无谓重序列化）");
    assert_eq!(body.get("temperature"), Some(&json!(0.7)));
}

#[test]
fn drop_removes_present_key_and_ignores_absent() {
    let mut body = object(&[("service_tier", json!("auto")), ("model", json!("m"))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(&[], &[], &["service_tier", "absent"]),
        true,
    );
    assert!(changed, "命中删除须报告变化");
    assert!(body.get("service_tier").is_none(), "键须被删除");
    assert_eq!(body.get("model"), Some(&json!("m")), "未列键须保留");

    let mut body = object(&[("model", json!("m"))]);
    let changed = apply_param_overrides(&mut body, &rules(&[], &[], &["absent"]), true);
    assert!(!changed, "缺失键静默忽略且不报告变化");
}

#[test]
fn later_section_wins_for_same_key() {
    // default → override：override 胜。
    let mut body = Map::new();
    let changed = apply_param_overrides(
        &mut body,
        &rules(
            &[("temperature", json!(0.1))],
            &[("temperature", json!(0.9))],
            &[],
        ),
        true,
    );
    assert!(changed);
    assert_eq!(body.get("temperature"), Some(&json!(0.9)));

    // override → drop：drop 胜（最终删除）。
    let mut body = object(&[("temperature", json!(0.1))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(&[], &[("temperature", json!(0.9))], &["temperature"]),
        true,
    );
    assert!(changed);
    assert!(body.get("temperature").is_none(), "后段 drop 须生效");
}

#[test]
fn empty_rules_report_unchanged() {
    let mut body = object(&[("model", json!("m"))]);
    let changed = apply_param_overrides(&mut body, &rules(&[], &[], &[]), true);
    assert!(!changed, "空规则不得报告变化");
}

#[test]
fn merge_mode_preserves_client_values_and_adds_missing_keys() {
    // 合并模式（override_existing = false）：客户端已有键（值不同）恒保留；
    // 缺失键新增（default 与 override 两段同权，均为「仅补缺」）。
    let mut body = object(&[("temperature", json!(0.5)), ("model", json!("m"))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(
            &[("top_p", json!(0.9)), ("temperature", json!(0.7))],
            &[("temperature", json!(0.2))],
            &[],
        ),
        false,
    );
    assert!(changed, "缺失键 top_p 须新增，如实报告变化");
    assert_eq!(
        body.get("temperature"),
        Some(&json!(0.5)),
        "客户端值须原样保留（override 段不得覆盖）"
    );
    assert_eq!(body.get("top_p"), Some(&json!(0.9)));
    assert_eq!(body.get("model"), Some(&json!("m")));
}

#[test]
fn merge_mode_missing_key_uses_later_config_segment() {
    // 客户端未带该键时，同键 default + override 取后段值（仅配置段之间后段生效）。
    let mut body = Map::new();
    let changed = apply_param_overrides(
        &mut body,
        &rules(
            &[("temperature", json!(0.1))],
            &[("temperature", json!(0.9))],
            &[],
        ),
        false,
    );
    assert!(changed);
    assert_eq!(body.get("temperature"), Some(&json!(0.9)));

    // 两段值相同：仅新增一次、不重复改写。
    let mut body = Map::new();
    let changed = apply_param_overrides(
        &mut body,
        &rules(
            &[("temperature", json!(0.9))],
            &[("temperature", json!(0.9))],
            &[],
        ),
        false,
    );
    assert!(changed);
    assert_eq!(body.get("temperature"), Some(&json!(0.9)));
}

#[test]
fn merge_mode_drop_still_removes_and_noop_reports_false() {
    // drop 不受开关影响（两态均删除）。
    let mut body = object(&[("service_tier", json!("auto"))]);
    let changed = apply_param_overrides(&mut body, &rules(&[], &[], &["service_tier"]), false);
    assert!(changed, "drop 在合并模式仍须删除");
    assert!(body.get("service_tier").is_none());

    // 客户端已有值：无论与配置同值还是不同值，均保留且不报变化。
    let mut body = object(&[("temperature", json!(0.7))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(&[], &[("temperature", json!(0.7))], &[]),
        false,
    );
    assert!(!changed, "客户端已有值且与配置同值：无实际变化");
    let mut body = object(&[("temperature", json!(0.5))]);
    let changed = apply_param_overrides(
        &mut body,
        &rules(&[], &[("temperature", json!(0.7))], &[]),
        false,
    );
    assert!(!changed, "客户端值须原样保留且不报变化");
    assert_eq!(body.get("temperature"), Some(&json!(0.5)));
}

#[test]
fn protocol_mapping_covers_dialog_protocols_only() {
    assert_eq!(param_protocol(Protocol::Chat), Some(ParamProtocol::Chat));
    assert_eq!(
        param_protocol(Protocol::Anthropic),
        Some(ParamProtocol::Anthropic)
    );
    assert_eq!(
        param_protocol(Protocol::Responses),
        Some(ParamProtocol::Responses)
    );
    assert_eq!(param_protocol(Protocol::NonDialog), None, "透传协议不注入");
}

#[test]
fn matched_params_requires_matching_protocol_declaration() {
    // 仅声明 anthropic：chat 请求不得命中（协议不匹配不注入）。
    let overrides = target_with(
        ParamProtocol::Anthropic,
        rules(&[], &[("thinking", json!({"type": "enabled"}))], &[]),
    );
    assert!(
        matched_params(Some(&overrides), Protocol::Chat).is_none(),
        "协议不匹配须为 None"
    );
    assert!(
        matched_params(Some(&overrides), Protocol::Anthropic).is_some(),
        "同协议须命中"
    );
    assert!(
        matched_params(Some(&overrides), Protocol::NonDialog).is_none(),
        "NonDialog 恒不命中"
    );
    assert!(
        matched_params(None, Protocol::Chat).is_none(),
        "无覆盖须为 None"
    );
}
