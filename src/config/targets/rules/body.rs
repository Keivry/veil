//! body 条件替换规则（`params.<proto>.replace`）的加载期校验。
//!
//! 仅顶层标量精确替换：字段缺失/类型不符/值不等一律 no-op，不注入缺失字段、不级联。

use {
    super::{ReplaceRule, RuleSite, contains_pii_placeholder_shape, validate_rule_models},
    crate::{
        config::{
            file_layer::BOOTSTRAP_VAR,
            targets::{ParamSegments, RESERVED_PARAM_KEYS},
            validate::config_error,
        },
        error::Result,
    },
    serde_json::Value,
    std::collections::BTreeMap,
};

/// `replace.field` 的**额外**保留键（不施加于 `default`/`override`/`drop`，否则会拒绝
/// 既有合法配置；这些顶层键承载工具调用、会话续接、缓存与身份语义，条件改写会破坏
/// 上游状态机或计费口径）。
const REPLACE_RESERVED_PARAM_KEYS: [&str; 7] = [
    "tools",
    "previous_response_id",
    "conversation",
    "prompt_cache_key",
    "metadata",
    "user",
    "safety_identifier",
];

/// body `replace` 规则校验（错误消息指名字段与规则序号）：`field` 非空、无 `.`、
/// 不命中基线 7 键或 `replace` 扩展清单、不与同协议 `default`/`override`/`drop` 键重名；
/// `from`/`to` 仅标量且不等、非实际 PII 占位符形态；`(field, from)` 唯一；`models` 合法。
pub(crate) fn validate_replace(
    path: &str,
    raw: Option<&[ReplaceRule]>,
    segments: &ParamSegments,
) -> Result<Vec<ReplaceRule>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let occupied: BTreeMap<String, &'static str> = segments
        .default
        .iter()
        .flatten()
        .map(|(name, _)| (name.clone(), "default"))
        .chain(
            segments
                .r#override
                .iter()
                .flatten()
                .map(|(name, _)| (name.clone(), "override")),
        )
        .chain(
            segments
                .drop
                .iter()
                .flatten()
                .map(|name| (name.clone(), "drop")),
        )
        .collect();
    let mut rules: Vec<ReplaceRule> = Vec::with_capacity(raw.len());
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (index, rule) in raw.iter().enumerate() {
        let site = RuleSite {
            path,
            ordinal: index + 1,
            label: &rule.field,
        };
        let tag = site.tag();
        validate_replace_field(&site, &rule.field)?;
        if let Some(segment) = occupied.get(rule.field.as_str()) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{tag} 与同协议子表 {segment} 冲突（同字段歧义：条件替换会被后续段覆盖或删除），拒绝启动"
                ),
            ));
        }
        validate_replace_scalar(&site, "from", &rule.from)?;
        validate_replace_scalar(&site, "to", &rule.to)?;
        if rule.from == rule.to {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{tag} from 与 to 相等（{}），无替换语义，拒绝启动",
                    rule.from
                ),
            ));
        }
        let identity = (rule.field.clone(), rule.from.to_string());
        if let Some(previous) = seen.insert(identity, site.ordinal) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 第 {} 条规则与第 {previous} 条 (field, from) 重复（{:?}, {}），拒绝启动",
                    site.ordinal, rule.field, rule.from
                ),
            ));
        }
        validate_rule_models(&site, rule.models.as_deref())?;
        rules.push(rule.clone());
    }
    Ok(rules)
}

/// `field` 校验：非空、无 `.`（仅顶层键，不做路径表达式）、不命中基线或扩展保留键。
fn validate_replace_field(site: &RuleSite<'_>, field: &str) -> Result<()> {
    if field.is_empty() {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{} field 为空（须为顶层键名），拒绝启动", site.tag()),
        ));
    }
    if field.contains('.') {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{} field {field:?} 含 `.`（仅支持顶层键，不支持嵌套路径），拒绝启动",
                site.tag()
            ),
        ));
    }
    if RESERVED_PARAM_KEYS.contains(&field) || REPLACE_RESERVED_PARAM_KEYS.contains(&field) {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{} field {field:?} 为保留键（保护路由/SSE 泵/占位符注入/用量计费/会话状态口径），拒绝启动",
                site.tag()
            ),
        ));
    }
    Ok(())
}

/// `from`/`to` 标量校验：仅 JSON 字符串/数字/布尔（拒对象/数组/null），且非实际 PII
/// 占位符形态（字符串值按其文本判定）。
pub(crate) fn validate_replace_scalar(
    site: &RuleSite<'_>,
    field: &str,
    value: &Value,
) -> Result<()> {
    let tag = site.tag();
    match value {
        Value::String(text) if contains_pii_placeholder_shape(text) => Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{tag} {field} 为实际 PII 占位符形态（{text:?}），禁止与脱敏占位符交互，拒绝启动"
            ),
        )),
        Value::String(_) | Value::Number(_) | Value::Bool(_) => Ok(()),
        Value::Null => Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{tag} {field} 为 null（仅允许字符串/数字/布尔），拒绝启动"),
        )),
        Value::Array(_) | Value::Object(_) => Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{tag} {field} 非标量（仅允许字符串/数字/布尔，不支持数组/对象），拒绝启动"),
        )),
    }
}
