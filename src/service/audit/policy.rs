//! 审计策略加载（D2 自 `audit.rs` 拆出）：`AuditPolicy` + 极简 YAML 解析。

use {
    crate::error::{Result, VeilError},
    std::path::Path,
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
    fn parse_minimal_yaml(text: &str) -> Result<Self> {
        let mut policy = Self::default();
        let mut section: Option<String> = None;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(item) = line.strip_prefix("- ") {
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
        Ok(policy)
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
