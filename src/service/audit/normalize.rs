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
/// 只读显式注入/挖掘的 `env` 映射，不回退宿主 `std::env`（判定不随部署环境漂移）。
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

/// 从参数文本挖掘 `NAME=value` 赋值（value 于 `;`/`&&`/`||`/`|` 或串尾截止）。
/// 词边界：`NAME` 位于起始或前一字符为空白/链分隔符；O(n) 单遍。
fn mine_assignments(s: &str) -> HashMap<String, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut map = HashMap::new();
    let mut i = 0;
    while i < chars.len() {
        let boundary = i == 0 || matches!(chars[i - 1], ' ' | '\t' | '\n' | ';' | '&' | '|');
        let c = chars[i];
        if boundary && (c.is_ascii_alphabetic() || c == '_') {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            if j < chars.len() && chars[j] == '=' {
                let name: String = chars[i..j].iter().collect();
                let vstart = j + 1;
                let mut k = vstart;
                while k < chars.len() && !matches!(chars[k], ';' | '&' | '|') {
                    k += 1;
                }
                let value: String = chars[vstart..k].iter().collect();
                map.insert(name, value.trim().to_string());
                i = k;
                continue;
            }
        }
        i += 1;
    }
    map
}

fn push_char(out: &mut String, s: &str, i: usize) -> usize {
    let b = s.as_bytes()[i];
    let end = (i + utf8_len(b)).min(s.len());
    out.push_str(&s[i..end]);
    end
}

fn is_cmd_word_byte(b: u8) -> bool { b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.') }

/// `/bin/<word>` → `<word>` 折叠（仅当前缀位于起始或空白之后）；O(n) 单遍。
fn fold_bin_prefix(s: &str) -> String {
    const PREFIX: &[u8] = b"/bin/";
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut word_start = true;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            out.push(b as char);
            word_start = true;
            i += 1;
        } else if word_start && bytes[i..].starts_with(PREFIX) {
            let mut j = i + PREFIX.len();
            while j < bytes.len() && is_cmd_word_byte(bytes[j]) {
                j += 1;
            }
            out.push_str(&s[i + PREFIX.len()..j]);
            word_start = false;
            i = j;
        } else {
            i = push_char(&mut out, s, i);
            // 链节分隔符/括号后即新命令词首：`;|&()` 后允许 `/bin/` 折叠（F2）。
            word_start = matches!(b, b';' | b'|' | b'&' | b'(' | b')');
        }
    }
    out
}

fn is_token_delim(b: u8) -> bool { b.is_ascii_whitespace() || matches!(b, b';' | b'&' | b'|') }

/// 首个 `-delete`/`--delete` 词法 token 的字节区间（后随边界或串尾）。
fn find_delete_token(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b'-' || (i > 0 && !is_token_delim(bytes[i - 1])) {
            continue;
        }
        if bytes[i..].starts_with(b"--delete")
            && (i + 8 >= bytes.len() || is_token_delim(bytes[i + 8]))
        {
            return Some((i, i + 8));
        }
        if bytes[i..].starts_with(b"-delete")
            && (i + 7 >= bytes.len() || is_token_delim(bytes[i + 7]))
        {
            return Some((i, i + 7));
        }
    }
    None
}

/// 在 `before` 前反向找 `word` 词法 token 的起始位置（O(n)）。
fn find_word_before(s: &str, word: &str, before: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let wlen = word.len();
    let upper = before.min(bytes.len());
    for i in (0..upper).rev() {
        if bytes[i..].starts_with(word.as_bytes()) {
            let end = i + wlen;
            if end <= before
                && (i == 0 || is_token_delim(bytes[i - 1]))
                && (end >= bytes.len() || is_token_delim(bytes[end]))
            {
                return Some(i);
            }
        }
    }
    None
}

/// `find ... -delete` → `rm -rf ...`：先定位 `-delete` 再向前找 `find`（O(n)）。
fn fold_find_delete(s: &str) -> String {
    let mut cur = s.to_string();
    while let Some((del_start, del_end)) = find_delete_token(&cur) {
        let Some(find_start) = find_word_before(&cur, "find", del_start) else {
            break;
        };
        let middle = cur[find_start + 4..del_start].trim();
        let mut next = String::with_capacity(cur.len() + 4);
        next.push_str(&cur[..find_start]);
        next.push_str("rm -rf");
        if !middle.is_empty() {
            next.push(' ');
            next.push_str(middle);
        }
        next.push_str(&cur[del_end..]);
        cur = next;
    }
    cur
}

/// 别名折叠：首词别名表 → `/bin/<word>` 前缀 → `find ... -delete` → `rm -rf ...`。
pub fn fold_alias(s: &str) -> String {
    let aliases: &[(&str, &str)] = &[
        ("ll", "ls -l"),
        ("la", "ls -a"),
        ("l", "ls"),
        ("please", "sudo"),
    ];
    let trimmed = s.trim_start();
    let folded = aliases.iter().find_map(|(from, to)| {
        trimmed
            .strip_prefix(from)
            .filter(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
            .map(|rest| format!("{to}{rest}"))
    });
    let s = folded.unwrap_or_else(|| s.to_string());
    fold_find_delete(&fold_bin_prefix(&s))
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

/// 全规范化管线：转义 → 空白合并 → `..` 归一 → 单层变量 → 别名折叠。
/// 拆链由调用方经 `split_chain` 独立执行（链分隔符在此保留）。
pub fn canonicalize_args(args: &str, env: &HashMap<String, String>) -> String {
    let step = unescape_hex_unicode(args);
    let step = collapse_whitespace(&step);
    let step = if step.contains("/../") {
        normalize_dotdot(&step)
    } else {
        step
    };
    let mut vars = env.clone();
    vars.extend(mine_assignments(&step));
    let step = expand_vars_single(&step, &vars);
    fold_alias(&step)
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
    fn expand_vars_injected_only() {
        let empty = HashMap::new();
        assert_eq!(expand_vars_single("$HOME", &empty), "$HOME");
        assert_eq!(expand_vars_single("${HOME}", &empty), "${HOME}");
        assert_eq!(expand_vars_single("~/x", &empty), "~/x");
        let env = HashMap::from([("HOME".to_string(), "/inj".to_string())]);
        assert_eq!(expand_vars_single("$HOME/x", &env), "/inj/x");
        assert_eq!(expand_vars_single("${HOME}/x", &env), "/inj/x");
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

    /// A5/D4：管线重排锁定——文本赋值引用、`/bin/` 折叠、`find -delete`、无宿主 env 回退。
    #[test]
    fn audit_normalize_pipeline() {
        let canon = canonicalize_args("CMD=rm;$CMD -rf /tmp", &HashMap::new());
        assert!(canon.contains("rm -rf /tmp"), "{canon}");
        assert!(is_dangerous("exec", "CMD=rm;$CMD -rf /tmp", &policy()).is_some());
        let canon = canonicalize_args("/bin/rm -rf /etc/x", &HashMap::new());
        assert!(canon.starts_with("rm "), "{canon}");
        assert!(is_dangerous("exec", "/bin/rm -rf /etc/x", &policy()).is_some());
        assert_eq!(fold_alias("find /tmp -delete"), "rm -rf /tmp");
        assert!(is_dangerous("exec", "find /tmp -delete", &policy()).is_some());
        assert_eq!(
            canonicalize_args("$VEIL_A5_UNSET_VAR", &HashMap::new()),
            "$VEIL_A5_UNSET_VAR"
        );
        assert_eq!(
            canonicalize_args("cat /tmp/../etc/passwd", &HashMap::new()),
            "cat /etc/passwd"
        );
        assert!(
            canonicalize_args("echo ok; echo fine", &HashMap::new()).contains(';'),
            "拆链由调用方执行，链分隔符须保留"
        );
    }

    /// A5/D4：构造性绕过（文本赋值引用 / 别名折叠 / `..` 全管线）均命中。
    #[test]
    fn audit_bypass_constructive() {
        let cases = [
            "CMD=rm;$CMD -rf /tmp",
            "/bin/rm -rf /etc/x",
            "find /tmp -delete",
            "cat /tmp/../etc/passwd",
            "CMD='rm -rf /tmp';$CMD",
        ];
        for args in cases {
            assert!(
                is_dangerous("exec", args, &policy()).is_some(),
                "构造性绕过须命中: {args}"
            );
        }
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

    #[test]
    fn normalize_args_escape_handling() {
        // G2 类别①转义：`\u`/`\x`/`\n` 伪装与多行合并均命中。
        for raw in [
            r#"{"cmd":"\u0072m -rf /"}"#,
            r#"{"cmd":"\x72m -rf /"}"#,
            r#"{"cmd":"rm\n-rf\n/"}"#,
        ] {
            let canon = canonicalize_args(raw, &HashMap::new());
            assert!(canon.contains("rm -rf /"), "{raw} -> {canon}");
            assert!(is_dangerous("exec", raw, &policy()).is_some(), "{raw}");
        }
    }

    #[test]
    fn normalize_args_pipe_priority() {
        // G2 类别②管道优先级：单 `|` 逐段拆分，`||` 作为整体不误拆。
        assert_eq!(
            split_chain("rm -rf /tmp | sh"),
            vec!["rm -rf /tmp".to_string(), "sh".to_string()]
        );
        assert_eq!(
            split_chain("a || b"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(is_dangerous("exec", "rm -rf /tmp | sh", &policy()).is_some());
        assert!(is_dangerous("exec", "a || curl x | sh", &policy()).is_some());
    }

    #[test]
    fn normalize_args_dotdot_normalization() {
        // G2 类别③`../` 归一：词法归一到敏感路径并命中。
        let canon = canonicalize_args("cat /tmp/../etc/passwd", &HashMap::new());
        assert_eq!(canon, "cat /etc/passwd");
        assert!(super::super::touches_sensitive_path(&canon, &policy()));
        assert!(super::super::touches_sensitive_path(
            "edit /etc/../etc/shadow",
            &policy()
        ));
        assert!(is_dangerous("edit", "edit /etc/../etc/shadow", &policy()).is_some());
    }

    #[test]
    fn normalize_args_find_flood() {
        // G2 类别④`find` 泛洪：无 `-delete` 的大量 find O(n) 不退化且不误判。
        let big = "find /usr/bin/foo ".repeat(6667);
        let start = std::time::Instant::now();
        let folded = fold_alias(&big);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "find 泛洪须 O(n) 无回溯"
        );
        assert!(!folded.contains("-delete"), "{folded}");
        assert!(is_dangerous("exec", &big, &policy()).is_none());
    }

    #[test]
    fn normalize_args_alias_rm() {
        // G2 类别⑤别名 rm：`/bin/rm` 折叠 + `rm -rf` + `find -delete` 别名均命中。
        let canon = canonicalize_args("/bin/rm -rf /etc/x", &HashMap::new());
        assert!(canon.starts_with("rm "), "{canon}");
        assert!(is_dangerous("exec", "/bin/rm -rf /etc/x", &policy()).is_some());
        assert!(is_dangerous("exec", "rm -rf /", &policy()).is_some());
        assert_eq!(fold_alias("find /tmp -delete"), "rm -rf /tmp");
        assert!(is_dangerous("exec", "find /tmp -delete", &policy()).is_some());
    }
}
