//! `header_replace` 条件替换的直接用例：逐值精确匹配、多值保序、逗号拼接不拆分、
//! 字面 `to`（不插值）、`models` 门控与执行顺序（drop → replace → headers → UA）。

use {
    super::super::super::{UpstreamOverrides, forward_headers},
    crate::{
        config::HeaderReplaceRule,
        handler::llm::test_support::{expand_ctx, expand_ctx_with, no_expand},
        service::llm_gateway::GatewayMetrics,
    },
    axum::http::{HeaderMap, HeaderValue},
};

/// 构造单条头替换规则（`models` 缺省 = 全模型）。
fn rule(name: &str, from: &str, to: &str) -> HeaderReplaceRule {
    HeaderReplaceRule {
        name: name.to_string(),
        from: from.to_string(),
        to: to.to_string(),
        models: None,
    }
}

/// 以给定规则构造覆盖表（其余通道为空）。
fn overrides_with(rules: Vec<HeaderReplaceRule>) -> UpstreamOverrides {
    UpstreamOverrides {
        header_replace: rules,
        ..UpstreamOverrides::default()
    }
}

/// 空入站头表（`ExpandCtx` 借用的长生命周期来源）。
static EMPTY_INBOUND: std::sync::OnceLock<HeaderMap> = std::sync::OnceLock::new();

fn empty_inbound() -> &'static HeaderMap { EMPTY_INBOUND.get_or_init(HeaderMap::new) }

fn value_of(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn values_of(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect()
}

#[test]
fn header_replace_rewrites_exact_single_value() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-reasoning-effort", HeaderValue::from_static("none"));
    client.insert("x-other", HeaderValue::from_static("keep"));
    let overrides = overrides_with(vec![rule("x-reasoning-effort", "none", "off")]);

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        value_of(&fwd, "x-reasoning-effort").as_deref(),
        Some("off"),
        "精确命中须改写"
    );
    assert_eq!(
        value_of(&fwd, "x-other").as_deref(),
        Some("keep"),
        "未涉及头须原样保留"
    );
}

#[test]
fn header_replace_is_case_sensitive_on_value() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-reasoning-effort", HeaderValue::from_static("None"));
    let overrides = overrides_with(vec![rule("x-reasoning-effort", "none", "off")]);

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        value_of(&fwd, "x-reasoning-effort").as_deref(),
        Some("None"),
        "值比较大小写敏感，不得命中"
    );
}

#[test]
fn header_replace_rewrites_each_multi_value_entry_and_preserves_order() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.append("x-effort", HeaderValue::from_static("none"));
    client.append("x-effort", HeaderValue::from_static("high"));
    client.append("x-effort", HeaderValue::from_static("none"));
    let overrides = overrides_with(vec![rule("x-effort", "none", "off")]);

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        values_of(&fwd, "x-effort"),
        vec!["off", "high", "off"],
        "每个值条目逐项替换，未匹配值保留且顺序不变"
    );
}

#[test]
fn header_replace_missing_header_is_not_injected() {
    let metrics = GatewayMetrics::default();
    let overrides = overrides_with(vec![rule("x-effort", "none", "off")]);

    let fwd = forward_headers(&HeaderMap::new(), &metrics, Some(&overrides), &no_expand());
    assert!(fwd.get("x-effort").is_none(), "头缺失须 no-op，绝不注入");
}

#[test]
fn header_replace_does_not_split_comma_joined_value() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-effort", HeaderValue::from_static("none, high"));
    let overrides = overrides_with(vec![rule("x-effort", "none", "off")]);

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        value_of(&fwd, "x-effort").as_deref(),
        Some("none, high"),
        "逗号拼接的单个值按整值精确比较，不命中且不拆分"
    );
}

#[test]
fn header_replace_to_is_literal_without_interpolation() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-effort", HeaderValue::from_static("none"));
    let mut inbound = HeaderMap::new();
    inbound.insert("x-session", HeaderValue::from_static("sess-1"));
    let overrides = overrides_with(vec![rule("x-effort", "none", "$conversation")]);

    let fwd = forward_headers(
        &client,
        &metrics,
        Some(&overrides),
        &expand_ctx_with(&inbound, None),
    );
    assert_eq!(
        value_of(&fwd, "x-effort").as_deref(),
        Some("$conversation"),
        "to 为字面值，不得展开"
    );
    assert_eq!(metrics.session_outbound_hmac_count(), 0, "字面值不计数");
}

#[test]
fn header_replace_models_gate_uses_expand_model() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-effort", HeaderValue::from_static("none"));
    let mut gated = rule("x-effort", "none", "off");
    gated.models = Some(vec!["deepseek-chat".to_string()]);
    let overrides = overrides_with(vec![gated]);

    let hit_expand = crate::handler::llm::ExpandCtx {
        model: Some("deepseek-chat".to_string()),
        ..expand_ctx(empty_inbound())
    };
    let fwd = forward_headers(&client, &metrics, Some(&overrides), &hit_expand);
    assert_eq!(
        value_of(&fwd, "x-effort").as_deref(),
        Some("off"),
        "模型精确匹配须生效"
    );

    for model in [Some("deepseek-reasoner"), Some("DeepSeek-Chat"), None] {
        let expand = crate::handler::llm::ExpandCtx {
            model: model.map(str::to_string),
            ..expand_ctx(empty_inbound())
        };
        let fwd = forward_headers(&client, &metrics, Some(&overrides), &expand);
        assert_eq!(
            value_of(&fwd, "x-effort").as_deref(),
            Some("none"),
            "模型不匹配/缺失须跳过: {model:?}"
        );
    }
}

#[test]
fn header_replace_is_order_independent_without_cascade() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-effort", HeaderValue::from_static("A"));

    for rules in [
        vec![rule("x-effort", "A", "B"), rule("x-effort", "B", "C")],
        vec![rule("x-effort", "B", "C"), rule("x-effort", "A", "B")],
    ] {
        let fwd = forward_headers(
            &client,
            &metrics,
            Some(&overrides_with(rules)),
            &no_expand(),
        );
        assert_eq!(
            value_of(&fwd, "x-effort").as_deref(),
            Some("B"),
            "仅基于应用前快照命中一层，不级联、与规则顺序无关"
        );
    }
}

#[test]
fn header_replace_runs_after_drop_and_before_config_headers() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-effort", HeaderValue::from_static("none"));
    client.insert("x-dropped", HeaderValue::from_static("none"));
    let mut overrides = overrides_with(vec![
        rule("x-effort", "none", "off"),
        rule("x-dropped", "none", "off"),
    ]);
    overrides.drop_headers = vec!["x-dropped".parse().expect("合法头名")];
    overrides.headers.insert(
        "x-config"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("config").into(),
    );

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert!(
        fwd.get("x-dropped").is_none(),
        "drop_headers 先删除，替换不得复活该头"
    );
    assert_eq!(
        value_of(&fwd, "x-effort").as_deref(),
        Some("off"),
        "替换在删除之后、注入之前生效"
    );
    assert_eq!(value_of(&fwd, "x-config").as_deref(), Some("config"));
}

#[test]
fn user_agent_wins_over_header_replace() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("user-agent", HeaderValue::from_static("none"));
    client.insert("x-effort", HeaderValue::from_static("none"));
    let mut overrides = overrides_with(vec![rule("x-effort", "none", "off")]);
    overrides.user_agent = Some(HeaderValue::from_static("opencode/1.18.33"));

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        value_of(&fwd, "user-agent").as_deref(),
        Some("opencode/1.18.33"),
        "配置 user_agent 恒胜（在替换之后写入）"
    );
    assert_eq!(
        value_of(&fwd, "x-effort").as_deref(),
        Some("off"),
        "非同名的替换规则照常生效"
    );
}

#[test]
fn header_replace_may_rewrite_session_header() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert(
        "x-opencode-session",
        HeaderValue::from_static("old-session"),
    );
    let overrides = overrides_with(vec![rule(
        "x-opencode-session",
        "old-session",
        "new-session",
    )]);

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        value_of(&fwd, "x-opencode-session").as_deref(),
        Some("new-session"),
        "会话头可被显式改写（非 x-veil-*）"
    );
}

#[test]
fn header_replace_skips_config_without_rules() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-effort", HeaderValue::from_static("none"));
    let overrides = UpstreamOverrides::default();

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        value_of(&fwd, "x-effort").as_deref(),
        Some("none"),
        "未声明规则时逐字节不变"
    );
}

#[test]
fn header_pipeline_order_is_drop_then_replace_then_headers_then_user_agent() {
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-effort", HeaderValue::from_static("none"));
    client.insert("x-dropped", HeaderValue::from_static("none"));
    client.insert("user-agent", HeaderValue::from_static("none"));
    let mut overrides = overrides_with(vec![
        rule("x-effort", "none", "off"),
        rule("x-dropped", "none", "off"),
    ]);
    overrides.drop_headers = vec![
        "x-dropped"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
    ];
    overrides.headers.insert(
        "x-config"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("config").into(),
    );
    overrides.user_agent = Some(HeaderValue::from_static("opencode/1.18.33"));

    let fwd = forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert!(fwd.get("x-dropped").is_none(), "① drop_headers 先删除");
    assert_eq!(value_of(&fwd, "x-effort").as_deref(), Some("off"), "② 替换");
    assert_eq!(
        value_of(&fwd, "x-config").as_deref(),
        Some("config"),
        "③ 注入配置头"
    );
    assert_eq!(
        value_of(&fwd, "user-agent").as_deref(),
        Some("opencode/1.18.33"),
        "④ user_agent 最后写入，恒胜"
    );
}
