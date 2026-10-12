//! 参数规范化（自 `audit.rs` 拆出）：空白/转义/拆链/变量/别名/`..` 词法管线。

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
            // 链节分隔符/括号后即新命令词首：`;|&()` 后允许 `/bin/` 折叠。
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
mod tests;
