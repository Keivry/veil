//! header 条件替换规则（`header_replace`）的加载期校验。

use {
    super::{HeaderReplaceRule, RuleSite, contains_pii_placeholder_shape, validate_rule_models},
    crate::{
        config::{
            file_layer::BOOTSTRAP_VAR,
            targets::{HeaderValueSpec, TargetKey, denied_header_reason},
            validate::config_error,
        },
        error::Result,
    },
    axum::http::{HeaderMap, HeaderName, HeaderValue},
    std::collections::BTreeMap,
};

/// 目标已声明的头通道：`headers` 注入表、`drop_headers` 删除表与是否声明 `user_agent`。
/// `header_replace` 须与三者全部不冲突，否则规则要么被覆盖、要么永不命中（死配置）。
pub(crate) struct HeaderChannels<'a> {
    pub(crate) headers: &'a HeaderMap<HeaderValueSpec>,
    pub(crate) drop_headers: &'a [HeaderName],
    pub(crate) has_user_agent: bool,
}

/// `header_replace` 校验（错误消息指名头名与规则序号）：头名合法、非硬拒头、不与
/// `headers`/`drop_headers` 归一后重叠、目标声明 `user_agent` 时不得为 `user-agent`；
/// `from`/`to` 通过 HTTP 头值语义、互不相等、非实际 PII 占位符形态；`(name, from)` 唯一。
///
/// `header_replace` **允许**改写 `[session].headers` 中的非 `x-veil-*` 会话头：会话身份在
/// 到达时已确定，出站改写只影响上游缓存亲和（与 `[session]` 的结构性重叠不拒启动）。
pub(crate) fn validate_header_replace(
    key: TargetKey,
    raw: Option<&[HeaderReplaceRule]>,
    channels: &HeaderChannels<'_>,
) -> Result<Vec<HeaderReplaceRule>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let HeaderChannels {
        headers,
        drop_headers,
        has_user_agent,
    } = *channels;
    let prefix = key.path_prefix();
    let path = format!("{prefix}.header_replace");
    let mut rules: Vec<HeaderReplaceRule> = Vec::with_capacity(raw.len());
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (index, rule) in raw.iter().enumerate() {
        let ordinal = index + 1;
        let parsed_name = HeaderName::from_bytes(rule.name.as_bytes()).map_err(|_| {
            config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 第 {ordinal} 条规则 name {:?} 头名非法（不符合 http 头名语义），拒绝启动",
                    rule.name
                ),
            )
        })?;
        let normalized = parsed_name.as_str().to_string();
        if let Some(reason) = denied_header_reason(&normalized) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 第 {ordinal} 条规则 name {:?} 属硬拒清单（{reason}），禁止条件替换，拒绝启动",
                    rule.name
                ),
            ));
        }
        if headers.contains_key(&parsed_name) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 第 {ordinal} 条规则 name {:?} 与 {prefix}.headers 同名（条件替换会被配置头注入覆盖，属死配置），拒绝启动",
                    rule.name
                ),
            ));
        }
        if drop_headers.contains(&parsed_name) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 第 {ordinal} 条规则 name {:?} 与 {prefix}.drop_headers 同名（头已被删除，规则永不命中），拒绝启动",
                    rule.name
                ),
            ));
        }
        if has_user_agent && normalized == "user-agent" {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 第 {ordinal} 条规则 name {:?} 与 {prefix}.user_agent 归一后同为 user-agent（字段恒胜会覆盖规则，属死配置），拒绝启动",
                    rule.name
                ),
            ));
        }
        let site = RuleSite {
            path: &path,
            ordinal,
            label: &format!("name {:?}", rule.name),
        };
        validate_rule_header_value(&site, "from", &rule.from)?;
        validate_rule_header_value(&site, "to", &rule.to)?;
        if rule.from == rule.to {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{} from 与 to 相等（{:?}），无替换语义，拒绝启动",
                    site.tag(),
                    rule.from
                ),
            ));
        }
        let identity = (normalized.clone(), rule.from.clone());
        if let Some(previous) = seen.insert(identity, ordinal) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 第 {ordinal} 条规则与第 {previous} 条 (name, from) 重复（{:?}, {:?}），拒绝启动",
                    rule.name, rule.from
                ),
            ));
        }
        validate_rule_models(&site, rule.models.as_deref())?;
        rules.push(HeaderReplaceRule {
            name: normalized,
            from: rule.from.clone(),
            to: rule.to.clone(),
            models: rule.models.clone(),
        });
    }
    Ok(rules)
}

/// 规则头值校验：CR/LF 与非法字节按 HTTP 头值语义拒绝，实际 PII 占位符形态亦拒。
fn validate_rule_header_value(site: &RuleSite<'_>, field: &str, value: &str) -> Result<()> {
    let tag = site.tag();
    if value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{tag} {field} 含 CR/LF 等非法字节，拒绝启动"),
        ));
    }
    if HeaderValue::from_str(value).is_err() {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{tag} {field} 值非法（不符合 http 头值语义），拒绝启动"),
        ));
    }
    if contains_pii_placeholder_shape(value) {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{tag} {field} 为实际 PII 占位符形态（{value:?}），禁止与脱敏占位符交互，拒绝启动"
            ),
        ));
    }
    Ok(())
}
