//! 注册 DTO→域纯映射（H4/D4）：输入原始 `entries`/`entry`/`field`/`fields`/
//! `allow_mode`/`auto`，输出 [`crate::registry::RegisterParams`] 的
//! `entries`/`allow_mode`。不依赖 handler DTO（`service -> handler` 边不存在），
//! 纯函数可独立单测；handler 仅提取原始字段并委派本模块。

use {serde_json::Value, std::collections::BTreeMap};

/// 解析单个 `entries` 值的字段列表（字符串/数组；非字符串项忽略）。
fn fields_from_value(fv: &Value) -> Vec<String> {
    match fv {
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                vec![]
            } else {
                vec![s.to_string()]
            }
        }
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        _ => vec![],
    }
}

/// 解析注册条目映射：对象/数组/字符串/单条目/`fields` 各形态，逐字段等价旧
/// handler 实现。`entries` 为空时回退单条目 `entry` + `field`/`fields`。
pub fn parse_register_entries(
    entries: Option<&Value>,
    entry: Option<&str>,
    field: Option<&str>,
    fields: Option<&Value>,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(v) = entries {
        match v {
            Value::Object(map) => {
                for (k, fv) in map {
                    let key = k.trim();
                    if key.is_empty() {
                        continue;
                    }
                    out.insert(key.to_string(), fields_from_value(fv));
                }
            }
            Value::Array(items) => {
                for item in items {
                    match item {
                        Value::String(s) => {
                            let s = s.trim();
                            if !s.is_empty() {
                                out.entry(s.to_string()).or_default();
                            }
                        }
                        Value::Object(map) => {
                            for (k, fv) in map {
                                let key = k.trim();
                                if key.is_empty() {
                                    continue;
                                }
                                out.insert(key.to_string(), fields_from_value(fv));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Value::String(s) => {
                let s = s.trim();
                if !s.is_empty() {
                    out.entry(s.to_string()).or_default();
                }
            }
            _ => {}
        }
    }
    if out.is_empty()
        && let Some(e) = entry.map(str::trim).filter(|s| !s.is_empty())
    {
        let mut merged: Vec<String> = vec![];
        if let Some(f) = field.map(str::trim).filter(|s| !s.is_empty()) {
            merged.push(f.to_string());
        }
        if let Some(fv) = fields {
            match fv {
                Value::String(s) => {
                    let s = s.trim();
                    if !s.is_empty() && !merged.contains(&s.to_string()) {
                        merged.push(s.to_string());
                    }
                }
                Value::Array(items) => {
                    for i in items {
                        if let Some(s) = i.as_str().map(str::trim).filter(|s| !s.is_empty())
                            && !merged.contains(&s.to_string())
                        {
                            merged.push(s.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        out.insert(e.to_string(), merged);
    }
    out
}

/// 解析放行模式：`allow_mode` 合法值优先（trim 后按 [`crate::config::AutoApprove`]
/// 解析），非法/空白回退 `auto`（`true` → `Allow`、`false` → `Deny`）；两者皆缺
/// 返回 `None`（沿用注册表既有默认）。
pub fn parse_register_allow_mode(
    allow_mode: Option<&str>,
    auto: Option<bool>,
) -> Option<crate::config::AutoApprove> {
    use std::str::FromStr as _;
    if let Some(raw) = allow_mode.map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(mode) = crate::config::AutoApprove::from_str(raw) {
            return Some(mode);
        }
        // `AUTH-10`：与 Go `get register --auto` / Python 默认 `manual` 契约对齐。
        match raw.to_lowercase().as_str() {
            "auto" => return Some(crate::config::AutoApprove::Allow),
            "manual" => return Some(crate::config::AutoApprove::Pending),
            _ => {
                tracing::warn!("未知 allow_mode {raw:?}，按兼容回退 auto 布尔/None 处理（AUTH-10）")
            }
        }
    }
    auto.map(|a| {
        if a {
            crate::config::AutoApprove::Allow
        } else {
            crate::config::AutoApprove::Deny
        }
    })
}

/// 注册 DTO 原始字段束（service 侧构造输入；长参数表以结构承载）。
#[derive(Debug, Clone, Copy)]
pub struct RegisterInputs<'a> {
    pub caller_path: &'a str,
    pub caller_hash: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub entries: Option<&'a Value>,
    pub entry: Option<&'a str>,
    pub field: Option<&'a str>,
    pub fields: Option<&'a Value>,
    pub allow_mode: Option<&'a str>,
    pub auto: Option<bool>,
}

/// D-4（6.6）越层收敛：字段 trim 与 [`crate::registry::RegisterParams`] 构造
/// 下沉本模块，handler 仅提取原始字段并委派；逐字段语义与旧 handler 实现等价
/// （`caller_path` 空白归一空串，其余 trim；`entries`/`allow_mode` 复用同批解析）。
pub fn parse_register_params(input: RegisterInputs<'_>) -> crate::registry::RegisterParams {
    crate::registry::RegisterParams {
        caller_path: if input.caller_path.trim().is_empty() {
            String::new()
        } else {
            input.caller_path.trim().to_string()
        },
        caller_hash: input.caller_hash.trim().to_string(),
        name: input.name.trim().to_string(),
        description: input.description.trim().to_string(),
        entries: parse_register_entries(input.entries, input.entry, input.field, input.fields),
        allow_mode: parse_register_allow_mode(input.allow_mode, input.auto),
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::config::AutoApprove, serde_json::json, std::collections::BTreeMap};

    fn expected(entry: &str, fields: &[&str]) -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([(
            entry.to_string(),
            fields.iter().map(|s| (*s).to_string()).collect(),
        )])
    }

    #[test]
    fn parse_register_params_trim() {
        // D-4（6.6）：字段 trim 与构造下沉后语义不变——四字段 trim、空白
        // `caller_path` 归一空串、`entries`/`allow_mode` 复用同批解析。
        let p = parse_register_params(RegisterInputs {
            caller_path: "  /srv/job.sh  ",
            caller_hash: " hash1 ",
            name: " 网易 ",
            description: " desc ",
            entries: None,
            entry: Some(" 网易 "),
            field: Some(" 授权码 "),
            fields: Some(&json!(["密码", " 授权码 "])),
            allow_mode: Some(" auto "),
            auto: Some(false),
        });
        assert_eq!(p.caller_path, "/srv/job.sh");
        assert_eq!(p.caller_hash, "hash1");
        assert_eq!(p.name, "网易");
        assert_eq!(p.description, "desc");
        assert_eq!(p.entries, expected("网易", &["授权码", "密码"]));
        assert_eq!(
            p.allow_mode,
            Some(AutoApprove::Allow),
            "auto 须优先布尔回退"
        );

        let p2 = parse_register_params(RegisterInputs {
            caller_path: "   ",
            caller_hash: "",
            name: "",
            description: "",
            entries: Some(&json!({" 腾讯 ": " 微信 "})),
            entry: None,
            field: None,
            fields: None,
            allow_mode: Some("bogus"),
            auto: Some(true),
        });
        assert_eq!(p2.caller_path, "", "空白 caller_path 归一空串");
        assert_eq!(p2.entries, expected("腾讯", &["微信"]));
        assert_eq!(
            p2.allow_mode,
            Some(AutoApprove::Allow),
            "非法 allow_mode 回退 auto"
        );
    }

    #[test]
    fn register_map_pure() {
        // 对象形（值字符串/数组/非法）。
        assert_eq!(
            parse_register_entries(Some(&json!({"网易": "授权码"})), None, None, None),
            expected("网易", &["授权码"])
        );
        assert_eq!(
            parse_register_entries(Some(&json!({"网易": ["授权码", "密码"]})), None, None, None),
            expected("网易", &["授权码", "密码"])
        );
        assert_eq!(
            parse_register_entries(Some(&json!({"网易": 42})), None, None, None),
            expected("网易", &[])
        );
        // 数组形：字符串项 + 对象项混合；纯字符串项字段为空。
        assert_eq!(
            parse_register_entries(
                Some(&json!(["网易", {"腾讯": ["a", "b"]}])),
                None,
                None,
                None
            ),
            BTreeMap::from([
                ("网易".to_string(), vec![]),
                ("腾讯".to_string(), vec!["a".to_string(), "b".to_string()]),
            ])
        );
        // 字符串形。
        assert_eq!(
            parse_register_entries(Some(&json!("网易")), None, None, None),
            expected("网易", &[])
        );
        // 空白键/空白字段剔除。
        assert_eq!(
            parse_register_entries(Some(&json!({"  ": "x", "k": "  "})), None, None, None),
            expected("k", &[])
        );
        assert_eq!(
            parse_register_entries(None, Some("网易"), Some("授权码"), Some(&json!("密码"))),
            expected("网易", &["授权码", "密码"])
        );
    }

    #[test]
    fn register_map_single_entry_and_fields_fallback() {
        // entries 为空 → 回退 entry + field + fields（字符串/数组去重）。
        assert_eq!(
            parse_register_entries(None, Some("网易"), Some("授权码"), Some(&json!("密码"))),
            expected("网易", &["授权码", "密码"])
        );
        assert_eq!(
            parse_register_entries(
                None,
                Some(" 网易 "),
                None,
                Some(&json!(["授权码", "授权码", " 密码 ", 1]))
            ),
            expected("网易", &["授权码", "密码"])
        );
        // entries 非空时不回退。
        assert_eq!(
            parse_register_entries(
                Some(&json!({"a": "b"})),
                Some("网易"),
                Some("授权码"),
                Some(&json!("密码"))
            ),
            expected("a", &["b"])
        );
        // entry 空白/缺失 → 空映射。
        assert_eq!(
            parse_register_entries(None, Some("   "), Some("授权码"), None),
            BTreeMap::new()
        );
        assert_eq!(
            parse_register_entries(None, None, None, None),
            BTreeMap::new()
        );
    }

    #[test]
    fn register_map_allow_mode_invalid_falls_back_to_auto() {
        assert_eq!(
            parse_register_allow_mode(Some("none"), None),
            Some(AutoApprove::Pending)
        );
        assert_eq!(
            parse_register_allow_mode(Some(" TRUE "), None),
            Some(AutoApprove::Allow)
        );
        // 非法/空白回退 auto。
        assert_eq!(
            parse_register_allow_mode(Some("bogus"), Some(false)),
            Some(AutoApprove::Deny)
        );
        assert_eq!(
            parse_register_allow_mode(Some("  "), Some(true)),
            Some(AutoApprove::Allow)
        );
        assert_eq!(parse_register_allow_mode(None, None), None);
        assert_eq!(parse_register_allow_mode(Some("bogus"), None), None);
    }

    #[test]
    fn register_allow_mode_accepts_auto_and_manual() {
        // AUTH-10：`auto`→放行、`manual`→审批，大小写不敏感且优先于布尔回退。
        assert_eq!(
            parse_register_allow_mode(Some("auto"), None),
            Some(AutoApprove::Allow)
        );
        assert_eq!(
            parse_register_allow_mode(Some(" AUTO "), None),
            Some(AutoApprove::Allow)
        );
        assert_eq!(
            parse_register_allow_mode(Some("manual"), None),
            Some(AutoApprove::Pending)
        );
        assert_eq!(
            parse_register_allow_mode(Some("Manual"), None),
            Some(AutoApprove::Pending)
        );
        assert_eq!(
            parse_register_allow_mode(Some("auto"), Some(false)),
            Some(AutoApprove::Allow),
            "auto 须优先于布尔回退"
        );
    }
}
