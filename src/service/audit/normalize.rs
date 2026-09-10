//! 参数规范化（D2 自 `audit.rs` 拆出）：空白/转义/拆链/变量/别名/`..` 词法管线。

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 参数规范化
// ---------------------------------------------------------------------------

/// 空白合并：连续空白折叠为单个空格并 trim（O(n) 单遍）。
pub fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_gap = true; // 首部空白直接丢弃，顺带 trim
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !in_gap {
                out.push(' ');
                in_gap = true;
            }
        } else {
            out.push(ch);
            in_gap = false;
        }
    }
    if in_gap {
        out.pop();
    }
    out
}

/// `\uXXXX` / `\xXX` 转义解码（O(n) 单遍扫描，无正则回溯）。
/// 非法转义原样保留；`\\` 先还原为 `\` 再处理由调用顺序保证（本函数只做一遍）。
pub fn unescape_hex_unicode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            let n = bytes[i + 1];
            if (n == b'u' || n == b'U')
                && i + 6 <= bytes.len()
                && let Ok(hex) = std::str::from_utf8(&bytes[i + 2..i + 6])
                && let Ok(cp) = u32::from_str_radix(hex, 16)
                && let Some(ch) = char::from_u32(cp)
            {
                out.push(ch);
                i += 6;
                continue;
            }
            if (n == b'x' || n == b'X')
                && i + 4 <= bytes.len()
                && let Ok(hex) = std::str::from_utf8(&bytes[i + 2..i + 4])
                && let Ok(cp) = u32::from_str_radix(hex, 16)
                && let Some(ch) = char::from_u32(cp)
            {
                out.push(ch);
                i += 4;
                continue;
            }
            if n == b'n' {
                out.push('\n');
                i += 2;
                continue;
            }
            if n == b't' {
                out.push('\t');
                i += 2;
                continue;
            }
            if n == b'\\' {
                out.push('\\');
                i += 2;
                continue;
            }
        }
        // 按字符推进（UTF-8 安全）。
        let ch_len = utf8_len(b);
        let end = (i + ch_len).min(bytes.len());
        if let Ok(chunk) = std::str::from_utf8(&bytes[i..end]) {
            out.push_str(chunk);
        }
        i = end;
    }
    out
}

pub(super) fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

/// 拆链：在引号外的 `;`、`&&`、`||`、`|` 处切分（O(n) 单遍，支持单双引号）。
pub fn split_chain(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            cur.push(ch);
            if ch == q {
                quote = None;
            } else if ch == '\\'
                && let Some(next) = chars.next()
            {
                cur.push(next);
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                cur.push(ch);
            }
            ';' => {
                parts.push(cur.trim().to_string());
                cur.clear();
            }
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                parts.push(cur.trim().to_string());
                cur.clear();
            }
            '|' => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                parts.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() || parts.is_empty() {
        parts.push(cur.trim().to_string());
    }
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

/// 单层变量展开：`$VAR` / `${VAR}` 只展开一层，不递归（防 `$A=$B` 链式炸开）。
pub fn expand_vars_single(s: &str, env: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }
        match chars.peek() {
            Some('{') => {
                chars.next();
                let mut name = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                if let Some(v) = env.get(&name) {
                    out.push_str(v);
                } else if let Ok(v) = std::env::var(&name) {
                    out.push_str(&v);
                } else {
                    out.push_str(&format!("${{{name}}}"));
                }
            }
            Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
                let mut name = String::new();
                while let Some(c) = chars.peek() {
                    if c.is_ascii_alphanumeric() || *c == '_' {
                        name.push(*c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(v) = env.get(&name) {
                    out.push_str(v);
                } else if let Ok(v) = std::env::var(&name) {
                    out.push_str(&v);
                } else {
                    out.push('$');
                    out.push_str(&name);
                }
            }
            _ => out.push('$'),
        }
    }
    out
}

/// 别名折叠：首词命中常用别名表时展开一层。
pub fn fold_alias(s: &str) -> String {
    let aliases: &[(&str, &str)] = &[
        ("ll", "ls -l"),
        ("la", "ls -a"),
        ("l", "ls"),
        ("please", "sudo"),
    ];
    let trimmed = s.trim_start();
    for (from, to) in aliases {
        if let Some(rest) = trimmed.strip_prefix(from)
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return format!("{to}{rest}");
        }
    }
    s.to_string()
}

/// `..` O(n) 词法规范化：栈式折叠，不触文件系统，不用正则。
/// 仅处理 `/` 分隔的词法层；保留前导 `/` 与尾部 `/` 语义无关紧要处归一。
pub fn normalize_dotdot(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|last| *last != "..") {
                    stack.pop();
                } else if !absolute {
                    stack.push("..");
                }
            }
            c => stack.push(c),
        }
    }
    let mut out = stack.join("/");
    if absolute {
        out.insert(0, '/');
    }
    if out.is_empty() {
        out.push_str(if absolute { "/" } else { "." });
    }
    out
}

/// 全规范化管线：转义 → 变量（单层） → 别名 → 空白合并。
pub fn canonicalize_args(args: &str, env: &HashMap<String, String>) -> String {
    let step = unescape_hex_unicode(args);
    let step = expand_vars_single(&step, env);
    let step = fold_alias(&step);
    collapse_whitespace(&step)
}

#[cfg(test)]
mod normalize_tests {
    use super::{
        super::{AuditPolicy, is_dangerous},
        *,
    };

    fn policy() -> AuditPolicy { AuditPolicy::default() }

    #[test]
    fn whitespace_collapse_and_escape_normalization_hit() {
        // 额外空白 + \x 转义伪装的 rm -rf / 仍被命中。
        let raw = "rm\\x20-\\u0072f   /";
        let canon = canonicalize_args(raw, &HashMap::new());
        assert!(canon.contains("rm -rf /"), "{canon}");
        assert!(is_dangerous("exec", raw, &policy()).is_some());
    }

    #[test]
    fn single_layer_variable_expansion_hit() {
        let mut env = HashMap::new();
        env.insert("CMD".to_string(), "rm -rf /".to_string());
        let canon = canonicalize_args("$CMD", &env);
        assert!(canon.contains("rm -rf /"), "{canon}");
        // 展开只做一层：值内再出现 $VAR 不递归。
        let mut env2 = HashMap::new();
        env2.insert("A".to_string(), "$B".to_string());
        assert_eq!(canonicalize_args("$A", &env2), "$B");
    }

    #[test]
    fn alias_folding_and_find_delete_without_backtracking() {
        assert!(fold_alias("ll /tmp").starts_with("ls -l"));
        // O(n) 定位：长串 find --delete 线性完成且命中。
        let big = format!("find /tmp -name '*.log' --delete # {}", "x".repeat(50_000));
        let t0 = std::time::Instant::now();
        let hit = is_dangerous("exec", &big, &policy());
        assert!(t0.elapsed().as_millis() < 1000, "须 O(n) 无回溯");
        assert!(hit.is_some());
        // .. 词法归一：/tmp/../etc/passwd 触敏感路径。
        assert!(super::super::touches_sensitive_path(
            "cat /tmp/../etc/passwd",
            &policy()
        ));
        assert_eq!(normalize_dotdot("/a/b/../c"), "/a/c");
        assert_eq!(normalize_dotdot("a/../../b"), "../b");
    }

    #[test]
    fn t5_dotdot_lexical_normalization() {
        assert_eq!(normalize_dotdot("/a/b/../c"), "/a/c");
        assert_eq!(normalize_dotdot("/a/./b"), "/a/b");
        assert_eq!(normalize_dotdot("a/../../b"), "../b");
        assert_eq!(normalize_dotdot("/../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_dotdot("/a//b"), "/a/b");
    }

    #[test]
    fn t5_dotdot_deep_nesting_linear_time() {
        let deep = format!("/a{}", "/../a".repeat(10_000));
        let start = std::time::Instant::now();
        let out = normalize_dotdot(&deep);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "O(n) 归一不得退化"
        );
        assert_eq!(out, "/a");
    }

    #[test]
    fn t5_dotdot_evasion_still_blocked() {
        use {
            super::super::{
                AuditVerdict,
                evaluate_with_whitelist,
                test_whitelist,
                touches_sensitive_path,
            },
            crate::config::AuditMode,
        };
        assert!(touches_sensitive_path("edit /etc/../etc/passwd", &policy()));
        assert!(!touches_sensitive_path("write /var/log/app.log", &policy()));
        assert!(touches_sensitive_path("write /etc/./shadow", &policy()));
        assert!(matches!(
            evaluate_with_whitelist(
                AuditMode::Block,
                "edit",
                "edit /etc/../etc/shadow",
                &policy(),
                test_whitelist()
            ),
            AuditVerdict::Block { .. }
        ));
    }
}
