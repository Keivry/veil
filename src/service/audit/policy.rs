//! 审计策略加载（自 `audit.rs` 拆出）：`AuditPolicy` + 极简 YAML 解析。

use {
    crate::{
        config::{AuditMode, Config, custom_file::strip_yaml_quotes},
        error::{Result, VeilError},
    },
    std::{collections::HashMap, path::Path},
};

/// 策略：内建危险规则 + 策略文件追加项 + allow/deny 名单 + 内网后缀 + 文件 `mode`。
#[derive(Debug, Clone, Default)]
pub struct AuditPolicy {
    /// 追加的危险子串（小写归一后匹配）。
    pub extra_block_substrings: Vec<String>,
    /// 追加的敏感路径前缀。
    pub extra_sensitive_paths: Vec<String>,
    /// 放行名单（tool 名精确匹配；危险内容仍先拦截，allow 仅表示无危险时放行）。
    pub allow: Vec<String>,
    /// 拒绝名单（tool 名精确匹配，优先于一切放行）。
    pub deny: Vec<String>,
    /// 内网域名后缀（命中则不判网络外传，如 `[".corp", ".internal"]`）。
    pub internal_suffixes: Vec<String>,
    /// 危险规则追加（`pattern/reason`，`network=true` 的命中须再过外部 host 判定）。
    pub extra_dangerous: Vec<DangerRule>,
    /// 策略文件声明的审计模式（`mode` 键）；缺省/空为 `None`（不改变 env 优先级）。
    pub mode: Option<AuditMode>,
    /// 启动/加载期进程 env 快照（`${VAR}`/`$VAR` 展开数据源）。
    pub env: HashMap<String, String>,
    /// 启动/加载期 `HOME` 快照（`~/` 展开数据源）；`None` 保留字面。
    pub home: Option<String>,
}

/// 策略文件危险规则项。
#[derive(Debug, Clone, Default)]
pub struct DangerRule {
    pub pattern: String,
    pub reason: String,
    pub network: bool,
}

impl AuditPolicy {
    pub fn default_policy() -> Self {
        Self {
            internal_suffixes: vec![".corp.example".to_string()],
            ..Self::default()
        }
    }

    /// 启动期 fail-fast 加载：`load_from_file` 的 `VeilError::Config`
    /// 原样上抛（不可读/未知键/孤立列表项/非法 `mode`/无法解析行/列表段形态错误），
    /// 成功时仅调用一次 `capture_process_env`。SHALL 用于生产启动边界，不降级默认策略。
    pub fn load_startup(path: Option<&Path>) -> Result<Self> {
        let mut policy = Self::load_from_file(path)?;
        policy.capture_process_env();
        Ok(policy)
    }

    /// 生效模式写回运行时配置（env 显式 > 文件 `mode` > `off`）。
    pub fn apply_effective_mode(&self, config: &mut Config) {
        let env_explicit = config.audit_mode_explicit.then_some(config.audit_mode);
        config.audit_mode = resolve_effective_mode(env_explicit, self.mode);
    }

    /// 捕获进程 env 快照（`HOME` 单列 + 全量 env）：唯一触碰进程环境的注入边界。
    pub fn capture_process_env(&mut self) {
        self.home = std::env::var("HOME").ok();
        self.env = std::env::vars().collect();
    }

    /// 从 `AUDIT_POLICY_FILE` 加载；`None`/空表示默认策略，非法文件返回 [`VeilError::Config`]。
    pub fn load_from_file(path: Option<&Path>) -> Result<Self> {
        let Some(p) = path.filter(|p| !p.as_os_str().is_empty()) else {
            return Ok(Self::default_policy());
        };
        let text = std::fs::read_to_string(p).map_err(|e| VeilError::Config {
            var: "AUDIT_POLICY_FILE".to_string(),
            message: format!("审计策略文件不可读 {}: {e}", p.display()),
        })?;
        if text.trim_start().starts_with('{') {
            return Self::parse_json_policy(&text);
        }
        Self::parse_minimal_yaml(&text)
    }

    /// 顶层 JSON 对象策略（与 YAML mapping 同解析、字段集合一致），
    /// fail-closed 语义不变——未知键、类型
    /// 不符、非法 `mode`、无法解析一律拒启动，不降级默认策略。
    fn parse_json_policy(text: &str) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| VeilError::Config {
                var: "AUDIT_POLICY_FILE".to_string(),
                message: format!("审计策略文件 JSON 解析失败: {e}"),
            })?;
        let obj = value.as_object().ok_or_else(|| VeilError::Config {
            var: "AUDIT_POLICY_FILE".to_string(),
            message: "审计策略文件顶层须为 JSON 对象".to_string(),
        })?;
        let mut policy = Self::default_policy();
        for (key, val) in obj {
            match key.as_str() {
                "allow" => policy.allow = json_string_list(val, key)?,
                "deny" => policy.deny = json_string_list(val, key)?,
                "internal_suffixes" => {
                    policy.internal_suffixes = json_string_list(val, key)?
                        .into_iter()
                        .map(|s| s.to_lowercase())
                        .collect();
                }
                "extra_block_substrings" => {
                    policy.extra_block_substrings = json_string_list(val, key)?
                        .into_iter()
                        .map(|s| s.to_lowercase())
                        .collect();
                }
                "extra_sensitive_paths" => {
                    policy.extra_sensitive_paths = json_string_list(val, key)?;
                }
                "mode" => policy.mode = json_mode(val)?,
                "dangerous" => policy.extra_dangerous = json_dangerous(val)?,
                other => {
                    return Err(VeilError::Config {
                        var: "AUDIT_POLICY_FILE".to_string(),
                        message: format!("审计策略文件未知键 {other:?}"),
                    });
                }
            }
        }
        Ok(policy)
    }

    /// 极简 YAML 子集解析（避免引入 yaml 重依赖）：
    /// 支持 `key: value` 与 `key:` + `- item` 列表；未知键忽略。
    /// `dangerous` 项兼容字符串形与对象形（`{pattern, reason, network}`）。
    fn parse_minimal_yaml(text: &str) -> Result<Self> {
        let mut policy = Self::default_policy();
        let mut section: Option<String> = None;
        let mut pending_dangerous: Option<DangerRule> = None;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(item) = line.strip_prefix("- ") {
                flush_dangerous(&mut policy, &mut pending_dangerous);
                let item = strip_yaml_quotes(item.trim());
                if item.is_empty() {
                    continue;
                }
                match section.as_deref() {
                    Some("extra_block_substrings") => {
                        policy.extra_block_substrings.push(item.to_lowercase());
                    }
                    Some("extra_sensitive_paths") => {
                        policy.extra_sensitive_paths.push(item);
                    }
                    Some("allow") => policy.allow.push(item),
                    Some("deny") => policy.deny.push(item),
                    Some("internal_suffixes") => {
                        policy.internal_suffixes.push(item.to_lowercase());
                    }
                    Some("dangerous") => {
                        if let Some(rule) = parse_dangerous_object(&item) {
                            policy.extra_dangerous.push(rule);
                        } else if let Some((key, value)) = object_field(&item) {
                            let mut rule = DangerRule::default();
                            set_dangerous_field(&mut rule, &key, &value);
                            pending_dangerous = Some(rule);
                        } else {
                            // `pattern` 或 `pattern => reason`（network 规则后缀 ` [network]`）。
                            let (pat, net) = match item.strip_suffix("[network]") {
                                Some(p) => (p.trim().to_string(), true),
                                None => (item.clone(), false),
                            };
                            let (pat, reason) = match pat.split_once("=>") {
                                Some((p, r)) => (p.trim().to_string(), r.trim().to_string()),
                                None => (pat.clone(), pat.clone()),
                            };
                            if !pat.is_empty() {
                                policy.extra_dangerous.push(DangerRule {
                                    pattern: pat,
                                    reason,
                                    network: net,
                                });
                            }
                        }
                    }
                    Some(other) => {
                        return Err(VeilError::Config {
                            var: "AUDIT_POLICY_FILE".to_string(),
                            message: format!(
                                "审计策略文件第 {} 行：未知列表段 [{other}]",
                                lineno + 1
                            ),
                        });
                    }
                    None => {
                        return Err(VeilError::Config {
                            var: "AUDIT_POLICY_FILE".to_string(),
                            message: format!(
                                "审计策略文件第 {} 行：列表项不在任何段下",
                                lineno + 1
                            ),
                        });
                    }
                }
                continue;
            }
            // 对象形块映射续行（`- pattern: ...` 后的 `reason:`/`network:` 缩进行）。
            if section.as_deref() == Some("dangerous")
                && let Some(rule) = pending_dangerous.as_mut()
                && let Some((k, v)) = line.split_once(':')
            {
                let key = strip_yaml_quotes(k.trim());
                if is_dangerous_field(&key) && !v.trim().is_empty() {
                    set_dangerous_field(rule, &key, &strip_yaml_quotes(v.trim()));
                    continue;
                }
            }
            flush_dangerous(&mut policy, &mut pending_dangerous);
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = strip_yaml_quotes(v.trim());
                match key.as_str() {
                    "extra_block_substrings"
                    | "extra_sensitive_paths"
                    | "allow"
                    | "deny"
                    | "internal_suffixes"
                    | "dangerous" => {
                        if !val.is_empty() {
                            return Err(VeilError::Config {
                                var: "AUDIT_POLICY_FILE".to_string(),
                                message: format!(
                                    "审计策略文件第 {} 行：[{key}] 须为列表段（`key:` 独占一行 + `- item`）",
                                    lineno + 1
                                ),
                            });
                        }
                        if key == "internal_suffixes" {
                            policy.internal_suffixes.clear();
                        }
                        section = Some(key);
                    }
                    "mode" => {
                        section = None;
                        policy.mode = match val.as_str() {
                            "off" => Some(AuditMode::Off),
                            "block" => Some(AuditMode::Block),
                            "approve" => Some(AuditMode::Approve),
                            "" => None,
                            _ => {
                                return Err(VeilError::Config {
                                    var: "AUDIT_POLICY_FILE".to_string(),
                                    message: format!(
                                        "审计策略文件第 {} 行：mode 非法 {val:?}（取值 off/block/approve）",
                                        lineno + 1
                                    ),
                                });
                            }
                        };
                    }
                    _ => {
                        return Err(VeilError::Config {
                            var: "AUDIT_POLICY_FILE".to_string(),
                            message: format!("审计策略文件第 {} 行：未知键 {key:?}", lineno + 1),
                        });
                    }
                }
                continue;
            }
            return Err(VeilError::Config {
                var: "AUDIT_POLICY_FILE".to_string(),
                message: format!("审计策略文件第 {} 行无法解析: {raw:?}", lineno + 1),
            });
        }
        flush_dangerous(&mut policy, &mut pending_dangerous);
        Ok(policy)
    }
}

/// 启动期最终生效模式：env 显式 > 文件 `mode` > 默认
/// `off`。 env 与文件同时显式且不一致时记 warn，以 env 为准，不静默。
pub fn resolve_effective_mode(
    env_explicit: Option<AuditMode>,
    file_mode: Option<AuditMode>,
) -> AuditMode {
    match (env_explicit, file_mode) {
        (Some(env), Some(file)) => {
            if env != file {
                tracing::warn!(
                    "审计模式冲突：env 显式 {env:?} 覆盖策略文件 mode {file:?}（以 env 为准）"
                );
            }
            env
        }
        (Some(env), None) => env,
        (None, Some(file)) => file,
        (None, None) => AuditMode::Off,
    }
}

const DANGEROUS_FIELDS: [&str; 3] = ["pattern", "reason", "network"];

fn is_dangerous_field(key: &str) -> bool { DANGEROUS_FIELDS.contains(&key) }

fn flush_dangerous(policy: &mut AuditPolicy, pending: &mut Option<DangerRule>) {
    let Some(mut rule) = pending.take() else {
        return;
    };
    if rule.pattern.is_empty() {
        return;
    }
    if rule.reason.is_empty() {
        rule.reason = rule.pattern.clone();
    }
    policy.extra_dangerous.push(rule);
}

fn set_dangerous_field(rule: &mut DangerRule, key: &str, value: &str) {
    match key {
        "pattern" => rule.pattern = value.to_string(),
        "reason" => rule.reason = value.to_string(),
        "network" => {
            rule.network = matches!(
                value.trim().to_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            )
        }
        _ => {}
    }
}

fn object_field(item: &str) -> Option<(String, String)> {
    let (k, v) = item.split_once(':')?;
    let key = strip_yaml_quotes(k.trim());
    if is_dangerous_field(&key) && !v.trim().is_empty() {
        Some((key, strip_yaml_quotes(v.trim())))
    } else {
        None
    }
}

fn parse_dangerous_object(item: &str) -> Option<DangerRule> {
    let t = item.trim();
    if !t.starts_with('{') || !t.ends_with('}') {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
        let pattern = v
            .get("pattern")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        if pattern.is_empty() {
            return None;
        }
        let reason = v
            .get("reason")
            .and_then(|r| r.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| pattern.clone());
        let network = v.get("network").and_then(|n| n.as_bool()).unwrap_or(false);
        return Some(DangerRule {
            pattern,
            reason,
            network,
        });
    }
    let mut rule = DangerRule::default();
    for pair in t[1..t.len() - 1].split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((k, v)) = pair.split_once(':') else {
            continue;
        };
        let key = strip_yaml_quotes(k.trim());
        if is_dangerous_field(&key) {
            set_dangerous_field(&mut rule, &key, &strip_yaml_quotes(v.trim()));
        }
    }
    if rule.pattern.is_empty() {
        None
    } else {
        Some(rule)
    }
}

fn policy_config_err(message: String) -> VeilError {
    VeilError::Config {
        var: "AUDIT_POLICY_FILE".to_string(),
        message,
    }
}

fn json_string_list(v: &serde_json::Value, key: &str) -> Result<Vec<String>> {
    let arr = v
        .as_array()
        .ok_or_else(|| policy_config_err(format!("审计策略文件 [{key}] 须为数组")))?;
    arr.iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| policy_config_err(format!("审计策略文件 [{key}] 数组项须为字符串")))
        })
        .collect()
}

fn json_mode(v: &serde_json::Value) -> Result<Option<AuditMode>> {
    let Some(s) = v.as_str() else {
        return Err(policy_config_err(
            "审计策略文件 mode 须为字符串".to_string(),
        ));
    };
    match s {
        "off" => Ok(Some(AuditMode::Off)),
        "block" => Ok(Some(AuditMode::Block)),
        "approve" => Ok(Some(AuditMode::Approve)),
        "" => Ok(None),
        _ => Err(policy_config_err(format!(
            "审计策略文件 mode 非法 {s:?}（取值 off/block/approve）"
        ))),
    }
}

fn json_dangerous(v: &serde_json::Value) -> Result<Vec<DangerRule>> {
    let arr = v
        .as_array()
        .ok_or_else(|| policy_config_err("审计策略文件 [dangerous] 须为数组".to_string()))?;
    let mut rules = Vec::new();
    for item in arr {
        if let Some(s) = item.as_str() {
            let (pat, net) = match s.strip_suffix("[network]") {
                Some(p) => (p.trim().to_string(), true),
                None => (s.to_string(), false),
            };
            let (pat, reason) = match pat.split_once("=>") {
                Some((p, r)) => (p.trim().to_string(), r.trim().to_string()),
                None => (pat.clone(), pat.clone()),
            };
            if !pat.is_empty() {
                rules.push(DangerRule {
                    pattern: pat,
                    reason,
                    network: net,
                });
            }
            continue;
        }
        if item.is_object() {
            if let Some(rule) = parse_dangerous_value(item) {
                rules.push(rule);
            }
            continue;
        }
        return Err(policy_config_err(
            "审计策略文件 dangerous 项须为字符串或对象".to_string(),
        ));
    }
    Ok(rules)
}

fn parse_dangerous_value(v: &serde_json::Value) -> Option<DangerRule> {
    let pattern = v.get("pattern").and_then(|p| p.as_str())?.to_string();
    if pattern.is_empty() {
        return None;
    }
    let reason = v
        .get("reason")
        .and_then(|r| r.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| pattern.clone());
    let network = v.get("network").and_then(|n| n.as_bool()).unwrap_or(false);
    Some(DangerRule {
        pattern,
        reason,
        network,
    })
}

#[cfg(test)]
mod tests;
