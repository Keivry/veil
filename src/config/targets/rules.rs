//! `[llm.targets]` 条件替换规则的 schema 与加载期校验。
//!
//! 两类规则：body（`params.<proto>.replace`，按请求体顶层标量精确替换，见 [`body`]）
//! 与 header（`header_replace`，按 `HeaderMap` 值条目精确替换，见 [`header`]）。二者
//! 共享精确匹配、只替换不注入、不级联、字面 `to`、模型门控与 PII token 禁止等语义。

pub mod body;
pub mod header;

pub(super) use body::validate_replace;
#[cfg(test)]
pub(crate) use body::validate_replace_scalar;
pub(crate) use header::{HeaderChannels, validate_header_replace};
use {
    super::{ParamOverrides, ParamProtocol, TargetKey},
    crate::{
        config::{file_layer::BOOTSTRAP_VAR, validate::config_error},
        error::Result,
    },
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::collections::BTreeMap,
};

/// 请求体条件替换规则（`[[llm.targets."<port>".params.<proto>.replace]]`）。
///
/// `from`/`to` 保留 JSON 标量类型（字符串/数字/布尔），比较为类型 + 精确值相等；
/// `models` 以 `Option` 承载，用于在加载期区分「未声明」与「声明为空数组」——后者
/// 必须拒启动。
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceRule {
    /// 请求体顶层键名。
    pub field: String,
    /// 命中值（仅 JSON 标量）。
    pub from: Value,
    /// 替换值（仅 JSON 标量）。
    pub to: Value,
    /// 模型门控（精确、大小写敏感；省略即不门控）。
    #[serde(default)]
    pub models: Option<Vec<String>>,
}

/// 出站头条件替换规则（`[[llm.targets."<port>".header_replace]]`）。
///
/// 按 `HeaderMap` 每个值条目逐值精确匹配并替换；不拆分逗号拼接的单个值。
/// `models` 的 `Option` 语义同 [`ReplaceRule::models`]。
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderReplaceRule {
    /// 出站头名。
    pub name: String,
    /// 命中值（精确字节相等）。
    pub from: String,
    /// 替换值（字面值，不做 `$` 插值）。
    pub to: String,
    /// 模型门控（精确、大小写敏感；省略即不门控）。
    #[serde(default)]
    pub models: Option<Vec<String>>,
}

/// 规则在配置中的定位（错误消息用）：完整键路径、1 基序号与规则标识（头名 / 字段名）。
pub(crate) struct RuleSite<'a> {
    pub(crate) path: &'a str,
    pub(crate) ordinal: usize,
    pub(crate) label: &'a str,
}

impl RuleSite<'_> {
    /// 错误消息前缀（`<路径> 第 N 条规则（<标识>）`）。
    fn tag(&self) -> String {
        let path = self.path;
        let ordinal = self.ordinal;
        let label = self.label;
        format!("{path} 第 {ordinal} 条规则（{label}）")
    }
}

/// 合并模式冲突校验：`override_existing = false` 与任一非空 `replace`/`header_replace`
/// 并存即拒启动，错误指名 `override_existing` 与首条冲突规则的位置。
pub(super) fn ensure_merge_mode_has_no_rules(
    key: TargetKey,
    params: &BTreeMap<ParamProtocol, ParamOverrides>,
    header_replace: &[HeaderReplaceRule],
) -> Result<()> {
    let prefix = key.path_prefix();
    for (protocol, overrides) in params {
        if !overrides.replace.is_empty() {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{prefix}.params.{}.replace 声明了条件替换规则，但同目标 override_existing = false（合并模式承诺不覆盖客户端值，条件替换会静默破坏该承诺），拒绝启动",
                    protocol.wire_name()
                ),
            ));
        }
    }
    if !header_replace.is_empty() {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{prefix}.header_replace 声明了条件替换规则，但同目标 override_existing = false（合并模式承诺不覆盖客户端值，条件替换会静默破坏该承诺），拒绝启动"
            ),
        ));
    }
    Ok(())
}

/// `models` 校验：省略合法（`None`）；声明则须为非空数组且元素均为非空字符串。
fn validate_rule_models(site: &RuleSite<'_>, models: Option<&[String]>) -> Result<()> {
    let Some(models) = models else {
        return Ok(());
    };
    if models.is_empty() {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{} models 为空数组（省略表示全模型；空数组无意义），拒绝启动",
                site.tag()
            ),
        ));
    }
    if models.iter().any(String::is_empty) {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{} models 含空字符串（模型名须精确非空），拒绝启动",
                site.tag()
            ),
        ));
    }
    Ok(())
}

/// 实际 PII 占位符形态判定：`__PII_<alnum/underscore>__` 或凭据私有前缀
/// （``）+ `<alnum/underscore>__`。
///
/// **不**以泛化 `*__` 判定——`"v1__"` 这类普通值必须放行。
pub(super) fn contains_pii_placeholder_shape(text: &str) -> bool {
    fn matches_shape(text: &str, prefix: &str) -> bool {
        text.match_indices(prefix).any(|(start, _)| {
            let rest = &text[start + prefix.len()..];
            let Some(end) = rest.find("__") else {
                return false;
            };
            let body = &rest[..end];
            !body.is_empty()
                && body
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    }
    matches_shape(text, crate::service::pii::PII_TOKEN_PREFIX)
        || matches_shape(text, crate::service::credential_vault::TOKEN_PREFIX)
}
