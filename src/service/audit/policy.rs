//! 审计策略加载（D2 自 `audit.rs` 拆出）：`AuditPolicy` + 极简 YAML 解析。

use {
    crate::error::{Result, VeilError},
    std::{collections::HashMap, path::Path},
};

/// 策略：内建危险规则 + 策略文件追加项 + allow/deny 名单 + 内网后缀。
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
    /// 启动/加载期进程 env 快照（`${VAR}`/`$VAR` 展开数据源，H3/D3）。
    pub env: HashMap<String, String>,
    /// 启动/加载期 `HOME` 快照（`~/` 展开数据源，H3/D3）；`None` 保留字面。
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
    pub fn default_policy() -> Self { Self::default() }

    /// 运行时加载：文件策略（缺省默认）加载后快照进程 `HOME`/env，供纯判定
    /// 读取（判定逻辑零进程 env 直读，H3/D3）。加载失败记 warn 并回退默认策略。
    pub fn load_for_runtime(path: Option<&Path>) -> Self {
        let mut policy = match Self::load_from_file(path) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!("审计策略文件加载失败，使用默认策略: {err}");
                Self::default_policy()
            }
        };
        policy.capture_process_env();
        policy
    }

    /// 捕获进程 env 快照（`HOME` 单列 + 全量 env）：唯一触碰进程环境的注入
    /// 边界，纯判定只读字段。测试以空/定制快照构造确定性用例。
    pub fn capture_process_env(&mut self) {
        self.home = std::env::var("HOME").ok();
        self.env = std::env::vars().collect();
    }

    /// 从 `AUDIT_POLICY_FILE` 加载；`None`/空表示默认策略。
    /// 非法文件返回 [`VeilError::Config`]（启动报错）。
    pub fn load_from_file(path: Option<&Path>) -> Result<Self> {
        let Some(p) = path else {
            return Ok(Self::default());
        };
        if p.as_os_str().is_empty() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(p).map_err(|e| VeilError::Config {
            var: "AUDIT_POLICY_FILE".to_string(),
            message: format!("审计策略文件不可读 {}: {e}", p.display()),
        })?;
        Self::parse_minimal_yaml(&text)
    }

    /// 极简 YAML 子集解析（避免引入 yaml 重依赖）：
    /// 支持 `key: value` 与 `key:` + `- item` 列表；未知键忽略。
    /// `dangerous` 项兼容字符串形与对象形（`{pattern, reason, network}`）。
    fn parse_minimal_yaml(text: &str) -> Result<Self> {
        let mut policy = Self::default();
        let mut section: Option<String> = None;
        let mut pending_dangerous: Option<DangerRule> = None;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(item) = line.strip_prefix("- ") {
                flush_dangerous(&mut policy, &mut pending_dangerous);
                let item = unquote(item.trim());
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
                let key = unquote(k.trim());
                if is_dangerous_field(&key) && !v.trim().is_empty() {
                    set_dangerous_field(rule, &key, &unquote(v.trim()));
                    continue;
                }
            }
            flush_dangerous(&mut policy, &mut pending_dangerous);
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = unquote(v.trim());
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
                        section = Some(key);
                    }
                    "mode" => {
                        section = None;
                        if !matches!(val.as_str(), "off" | "block" | "approve" | "") {
                            return Err(VeilError::Config {
                                var: "AUDIT_POLICY_FILE".to_string(),
                                message: format!(
                                    "审计策略文件第 {} 行：mode 非法 {val:?}（取值 off/block/approve）",
                                    lineno + 1
                                ),
                            });
                        }
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
    let key = unquote(k.trim());
    if is_dangerous_field(&key) && !v.trim().is_empty() {
        Some((key, unquote(v.trim())))
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
        let key = unquote(k.trim());
        if is_dangerous_field(&key) {
            set_dangerous_field(&mut rule, &key, &unquote(v.trim()));
        }
    }
    if rule.pattern.is_empty() {
        None
    } else {
        Some(rule)
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod policy_tests {
    use super::{super::is_dangerous, *};

    #[test]
    fn invalid_policy_file_fails_at_startup() {
        assert!(AuditPolicy::parse_minimal_yaml("mode: allow\n").is_err());
        assert!(AuditPolicy::parse_minimal_yaml("- 孤儿项\n").is_err());
        assert!(AuditPolicy::parse_minimal_yaml("未知键: 1\n").is_err());
        let ok =
            AuditPolicy::parse_minimal_yaml("mode: block\nextra_block_substrings:\n  - rm -rf /\n")
                .unwrap();
        assert_eq!(ok.extra_block_substrings, vec!["rm -rf /"]);
        let missing = std::path::Path::new("/nonexistent-veil-policy/policy.yaml");
        assert!(
            AuditPolicy::load_from_file(Some(missing)).is_err(),
            "不可读策略文件须拒启动（不降级为禁用审计）"
        );
    }

    #[test]
    fn audit_policy_object_form() {
        let flow = AuditPolicy::parse_minimal_yaml(
            "dangerous:\n  - {pattern: base64 -d, reason: 解码外传, network: true}\n",
        )
        .unwrap();
        assert_eq!(flow.extra_dangerous.len(), 1);
        assert_eq!(flow.extra_dangerous[0].pattern, "base64 -d");
        assert_eq!(flow.extra_dangerous[0].reason, "解码外传");
        assert!(flow.extra_dangerous[0].network);

        let block = AuditPolicy::parse_minimal_yaml(
            "dangerous:\n  - pattern: telnet\n    reason: 网络传输\n    network: true\n",
        )
        .unwrap();
        assert_eq!(block.extra_dangerous[0].pattern, "telnet");
        assert_eq!(block.extra_dangerous[0].reason, "网络传输");
        assert!(block.extra_dangerous[0].network);

        let dflt =
            AuditPolicy::parse_minimal_yaml("dangerous:\n  - pattern: curl\n    reason: 拉取\n")
                .unwrap();
        assert!(!dflt.extra_dangerous[0].network, "network 缺省 false");

        let json = AuditPolicy::parse_minimal_yaml(
            "dangerous:\n  - {\"pattern\": \"openssl\", \"reason\": \"解密\", \"network\": true}\n",
        )
        .unwrap();
        assert_eq!(json.extra_dangerous[0].pattern, "openssl");
        assert_eq!(json.extra_dangerous[0].reason, "解密");
        assert!(json.extra_dangerous[0].network);

        let mixed = AuditPolicy::parse_minimal_yaml(
            "dangerous:\n  - rm -rf / => 危险删除\n  - {pattern: mkfs, reason: 格式化, network: false}\n",
        )
        .unwrap();
        assert_eq!(mixed.extra_dangerous.len(), 2, "字符串形与对象形须并存");
        assert_eq!(mixed.extra_dangerous[0].pattern, "rm -rf /");
        assert_eq!(mixed.extra_dangerous[0].reason, "危险删除");

        let mut p = AuditPolicy::default_policy();
        p.extra_dangerous.push(DangerRule {
            pattern: "exfil-probe".to_string(),
            reason: "网络外传".to_string(),
            network: true,
        });
        p.internal_suffixes = vec!["corp.example".to_string()];
        assert!(
            is_dangerous("exec", "exfil-probe http://evil.example/x", &p).is_some(),
            "network=true 外部 host 须命中"
        );
        assert!(
            is_dangerous("exec", "exfil-probe http://svc.corp.example/x", &p).is_none(),
            "network=true 内网 host 须豁免"
        );
    }

    #[test]
    fn audit_policy_legacy_file() {
        let path = std::env::temp_dir().join(format!(
            "veil-policy-legacy-{}-{}.yaml",
            std::process::id(),
            line!()
        ));
        let text = "\
allow:
  - read_file
deny:
  - evil_tool
internal_suffixes:
  - .corp
dangerous:
  - {pattern: rm -rf, reason: 危险删除, network: false}
  - {pattern: curl, reason: 网络外传, network: true}
";
        std::fs::write(&path, text).unwrap();
        let loaded = AuditPolicy::load_from_file(Some(&path));
        std::fs::remove_file(&path).ok();
        let p = loaded.unwrap();
        assert_eq!(p.allow, vec!["read_file"]);
        assert_eq!(p.deny, vec!["evil_tool"]);
        assert_eq!(p.internal_suffixes, vec![".corp"]);
        assert_eq!(p.extra_dangerous.len(), 2);
        assert_eq!(p.extra_dangerous[0].pattern, "rm -rf");
        assert_eq!(p.extra_dangerous[0].reason, "危险删除");
        assert!(!p.extra_dangerous[0].network);
        assert_eq!(p.extra_dangerous[1].pattern, "curl");
        assert!(p.extra_dangerous[1].network);
        assert!(is_dangerous("exec", "rm -rf /tmp", &p).is_some());
    }

    #[test]
    fn policy_all_shapes_compat_loading() {
        let text = "allow:\n  - read_file\ndeny:\n  - evil\ninternal_suffixes:\n  - .corp\ndangerous:\n  - rm -rf / => 危险删除\n";
        let p = AuditPolicy::parse_minimal_yaml(text).unwrap();
        assert_eq!(p.allow, vec!["read_file"]);
        assert_eq!(p.deny, vec!["evil"]);
        assert_eq!(p.internal_suffixes, vec![".corp"]);
        assert_eq!(p.extra_dangerous.len(), 1);
        assert_eq!(p.extra_dangerous[0].reason, "危险删除");
        assert!(is_dangerous("exec", "rm -rf /tmp", &p).is_some());
    }
}
