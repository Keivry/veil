//! 危险规则判定（D2 自 `audit.rs` 拆出）：敏感路径/网络外传/预检与顶层判定。

use super::{
    normalize::{canonicalize_args, normalize_dotdot, split_chain},
    policy::AuditPolicy,
};

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
    "/boot/",
];

/// 关机/重启类裸词命令（D3）：按命令词形匹配，避免 `shutdown.sh` 类文件名词误报。
const DANGEROUS_BARE_COMMANDS: &[(&str, &str)] = &[
    ("shutdown", "系统关机"),
    ("reboot", "系统重启"),
    ("poweroff", "系统关机"),
];

/// `chmod`/`chown` 系统目录形态的目录前缀（D3 子串近似）。
const SYSTEM_DIRS: &[&str] = &["/etc", "/usr", "/bin", "/sbin", "/var", "/boot", "/lib"];

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
    // 1.1) 系统关机/重启：命令词形。
    for (word, reason) in DANGEROUS_BARE_COMMANDS {
        if is_command_word(&lower, word) {
            return Some(format!("危险 shell: {reason}"));
        }
    }
    // 1.1b) `dd` 命令词首匹配（F5/D5）：`add`/`cdd` 不误报，`dd if=... of=/dev/sda` 命中。
    if is_command_word(&lower, "dd") {
        return Some("危险 shell: 裸设备写入".to_string());
    }
    // 1.2) `rm` 递归强制删除：由根部形放宽为词形（任意目标）。
    if is_rm_recursive_force(&lower) {
        return Some("危险 shell: rm -rf 递归强制删除".to_string());
    }
    // 1.3) 解码类组合近似：`base64 -d`/`--decode`、`openssl -d`/`decode`/`decrypt`。
    if is_base64_decode(&lower) {
        return Some("危险 shell: base64 解码".to_string());
    }
    if is_openssl_decode(&lower) {
        return Some("危险 shell: openssl 解码".to_string());
    }
    // 1.4) chmod/chown 系统目录形态（子串近似）。
    if is_chmod_system_dir(&lower) {
        return Some("危险 shell: chmod 系统目录".to_string());
    }
    if is_chown_system_dir(&lower) {
        return Some("危险 shell: chown 系统目录".to_string());
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
    // 2) 敏感路径写入：写入口（写命令/重定向）且触及敏感前缀才判（`POL-8`/D8）。
    if is_sensitive_path_write(segment, policy) {
        return Some("敏感路径写入".to_string());
    }
    // 3) 网络外传：外发关键字 + 远程目标形态。
    if is_exfiltration(&lower) {
        return Some("网络外传".to_string());
    }
    None
}

fn is_network_pat(pat: &str) -> bool { pat == "curl" || pat == "wget" }

/// 命令词形定位（O(n) 无回溯）：命中则以起始/空白/命令分隔符为界，
/// 后随空白/分隔符/结束，避免 `.ssh/`、`shutdown.sh` 等路径/文件名词误报。
fn word_after_command<'a>(lower: &'a str, word: &str) -> Option<&'a str> {
    let bytes = lower.as_bytes();
    let w = word.as_bytes();
    if w.is_empty() {
        return None;
    }
    let pre_ok = |b: u8| {
        b.is_ascii_whitespace()
            || matches!(
                b,
                b';' | b'|' | b'&' | b'(' | b')' | b'"' | b'\'' | b'=' | b'$' | b'/'
            )
    };
    let post_ok = |b: u8| {
        b.is_ascii_whitespace() || matches!(b, b';' | b'|' | b'&' | b')' | b'"' | b'\'' | b'=')
    };
    let mut start = 0;
    while let Some(idx) = lower[start..].find(word) {
        let abs = start + idx;
        let before_ok = abs == 0 || pre_ok(bytes[abs - 1]);
        let after = abs + w.len();
        let after_ok = after == bytes.len() || post_ok(bytes[after]);
        if before_ok && after_ok {
            return Some(&lower[after..]);
        }
        start = abs + 1;
    }
    None
}

fn is_command_word(lower: &str, word: &str) -> bool { word_after_command(lower, word).is_some() }

/// `rm` + 递归强制标志组合（`-rf`/`-fr`/`-r -f` 等），任意目标；O(n) 无回溯。
fn is_rm_recursive_force(lower: &str) -> bool {
    let Some(rest) = word_after_command(lower, "rm") else {
        return false;
    };
    let mut recursive = false;
    let mut force = false;
    for tok in rest.split_whitespace() {
        if !tok.starts_with('-') {
            break;
        }
        if tok.contains('r') || tok.contains("recursive") {
            recursive = true;
        }
        if tok.contains('f') || tok.contains("force") {
            force = true;
        }
        if recursive && force {
            return true;
        }
    }
    false
}

fn is_base64_decode(lower: &str) -> bool {
    word_after_command(lower, "base64").is_some_and(|rest| {
        rest.split_whitespace()
            .any(|t| matches!(t, "-d" | "-D" | "--decode"))
    })
}

fn is_openssl_decode(lower: &str) -> bool {
    word_after_command(lower, "openssl").is_some_and(|rest| {
        rest.split_whitespace()
            .any(|t| matches!(t, "-d" | "-decode" | "-decrypt" | "decode" | "decrypt"))
    })
}

fn is_chmod_system_dir(lower: &str) -> bool {
    let Some(rest) = word_after_command(lower, "chmod") else {
        return false;
    };
    let mut mode_seen = false;
    for tok in rest.split_whitespace() {
        if tok.starts_with('-') {
            continue;
        }
        if !mode_seen {
            if (3..=4).contains(&tok.len()) && tok.bytes().all(|b| b.is_ascii_digit()) {
                mode_seen = true;
                continue;
            }
            return false;
        }
        return SYSTEM_DIRS.iter().any(|d| tok.starts_with(d));
    }
    false
}

fn is_chown_system_dir(lower: &str) -> bool {
    let Some(rest) = word_after_command(lower, "chown") else {
        return false;
    };
    let mut owner_seen = false;
    for tok in rest.split_whitespace() {
        if tok.starts_with('-') {
            continue;
        }
        if !owner_seen {
            owner_seen = true;
            continue;
        }
        return SYSTEM_DIRS.iter().any(|d| tok.starts_with(d));
    }
    false
}

fn piped_to_shell(lower: &str) -> bool {
    lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("| zsh")
        || lower.contains("| dash")
}

/// `POL-8`/D8 写入口集合（对照 Python `_audit.py:518` 逐字）：`write_file`/`patch`/
/// `echo`/`cat`/`tee`/`cp`/`mv`，叠加本仓既有写类工具名 `edit`/`write`/`apply_patch`/`save_file`。
const WRITE_COMMANDS: &[&str] = &[
    "write_file",
    "patch",
    "echo",
    "cat",
    "tee",
    "cp",
    "mv",
    "edit",
    "write",
    "apply_patch",
    "save_file",
];

/// `POL-8`/D8：写入意图判定——输出重定向（`>`）或写入口命令词命中。
fn has_write_intent(lower: &str) -> bool {
    lower.contains('>') || WRITE_COMMANDS.iter().any(|cmd| is_command_word(lower, cmd))
}

/// `POL-8`/D8：敏感路径写入＝写入意图 + 触及敏感前缀；纯只读命令触及敏感前缀不判。
pub fn is_sensitive_path_write(segment: &str, policy: &AuditPolicy) -> bool {
    has_write_intent(&segment.to_lowercase()) && touches_sensitive_path(segment, policy)
}

/// 敏感路径命中：O(n) 子串定位 + 词法 `..` 归一，禁全文正则回溯。
pub fn touches_sensitive_path(segment: &str, policy: &AuditPolicy) -> bool {
    let lowered = segment.to_lowercase();
    let haystacks: Vec<String> = extract_path_tokens(segment, policy)
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
/// `~/` 展开由注入的 home 唯一决定（零进程 env 直读，H3/D3）。
fn extract_path_tokens(segment: &str, policy: &AuditPolicy) -> Vec<String> {
    segment
        .split_whitespace()
        .filter(|t| t.contains('/') || t.starts_with('~') || t.starts_with('-'))
        .map(|t| {
            let t = t.trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == ';');
            expand_home(t, policy.home.as_deref())
        })
        .collect()
}

fn expand_home(t: &str, home: Option<&str>) -> String {
    if let Some(rest) = t.strip_prefix("~/")
        && let Some(home) = home
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
        || is_command_word(lower, "telnet")
        || is_command_word(lower, "ssh")
        || (lower.contains("curl") && (lower.contains("--data") || lower.contains(" -d ")))
        || (lower.contains("wget") && lower.contains("--post-data"))
        || is_command_word(lower, "nc")
        || is_command_word(lower, "ncat")
        || lower.contains("/dev/tcp/")
        || is_bare_fetch_exfil(lower)
}

/// `POL-6`/D6：裸 `curl`/`wget` 外传——命令词边界命中且后随远程目标形态
/// （`http(s)://`/`ftp://`，或 `-o`/`--output`/`>` 输出重定向）时判网络外传。
/// 命中外部 host 由 `is_dangerous` 的内网豁免分支放行（`internal_suffixes`）。
fn is_bare_fetch_exfil(lower: &str) -> bool {
    let has_remote_target = |rest: &str| {
        rest.contains("http://")
            || rest.contains("https://")
            || rest.contains("ftp://")
            || rest.contains("-o ")
            || rest.contains("--output")
            || rest.contains('>')
    };
    ["curl", "wget"]
        .iter()
        .any(|verb| word_after_command(lower, verb).is_some_and(has_remote_target))
}

/// 从 tool 参数提取网络目标 host（URL 或 `curl/wget/nc` 裸目标），不做 DNS 解析。
pub fn extract_host(args: &str) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    // URL 形态：先剥 scheme 再取 host（`svc.corp:8080/x` → `svc.corp:8080`，端口保留）。
    if let Some(pos) = args.find("https://").or_else(|| args.find("http://")) {
        let rest = &args[pos..];
        if let Some(after) = rest.split_once("://").map(|x| x.1) {
            let host = after
                .split(['/', ' ', '"', '\''].as_ref())
                .next()
                .unwrap_or("");
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }
    // 裸目标：`curl 8.8.8.8` / `curl evil.com`。
    for verb in ["curl", "wget", "nc", "ncat", "telnet"] {
        let mut search = args;
        while let Some(idx) = search.find(verb) {
            let after_verb = idx + verb.len();
            let before_ok = idx == 0 || !search.as_bytes()[idx - 1].is_ascii_alphanumeric();
            if !before_ok {
                search = &search[after_verb..];
                continue;
            }
            let rest = search[after_verb..].trim_start();
            if rest.starts_with('-') || rest.is_empty() {
                search = &search[after_verb..];
                continue;
            }
            let host: String = rest
                .split([' ', '"', '\'', ';', '|', '&'].as_ref())
                .next()
                .unwrap_or("")
                .to_string();
            if !host.is_empty() && !host.starts_with("http") {
                return Some(host);
            }
            search = &search[after_verb..];
        }
    }
    None
}

/// 内网后缀判定：命中 `internal_suffixes`（大小写不敏感）则不判外传。
pub fn is_internal_host(host: &str, internal_suffixes: &[String]) -> bool {
    let mut h = host.trim().to_lowercase();
    // 端口剥离（仅 host:port 单冒号形态，IPv6 字面量不动）。
    if h.matches(':').count() == 1
        && !h.starts_with('[')
        && let Some((bare, _)) = h.split_once(':')
    {
        h = bare.to_string();
    }
    let h = h
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_string();
    if h.is_empty() {
        return false;
    }
    if h == "localhost" || h.ends_with(".local") || h.ends_with(".internal") {
        return true;
    }
    internal_suffixes
        .iter()
        .any(|s| !s.is_empty() && h.ends_with(&s.to_lowercase()))
}

/// 审计预检（廉价同步前缀匹配）：tool 名命中危险前缀或参数前缀出现危险命令起始
/// 即返回 true（调用方暂停 flush，等待完整判定；未启用审计恒 false）。
pub fn audit_precheck(enabled: bool, tool_name: &str, args_prefix: &str) -> bool {
    if !enabled {
        return false;
    }
    const DANGEROUS_PREFIXES: &[&str] = &[
        "rm",
        "mkfs",
        "dd",
        "shutdown",
        "reboot",
        "poweroff",
        "chmod",
        "chown",
        "curl",
        "wget",
        "nc",
        "ncat",
        "telnet",
        "ssh",
        "base64",
        "openssl",
        "bash",
        "sh",
        "terminal",
        "execute_code",
    ];
    let tool_lower = tool_name.trim().to_lowercase();
    if DANGEROUS_PREFIXES.contains(&tool_lower.as_str()) {
        return true;
    }
    let stripped = args_prefix.trim_start().to_lowercase();
    // A14/D13：补齐 `find` 预检缝隙——tool 名精确 `find`，或参数含 `find ` 且出现
    // `-exec`/`-delete`/`--delete`（含 JSON 包装形）；普通 `find -name` 不触发误停。
    if tool_lower == "find"
        || (stripped.contains("find ")
            && (stripped.contains("-exec")
                || stripped.contains("-delete")
                || stripped.contains("--delete")))
    {
        return true;
    }
    if DANGEROUS_PREFIXES.iter().any(|p| {
        stripped == *p
            || stripped.starts_with(&format!("{p} "))
            || stripped.starts_with(&format!("{p}-"))
    }) {
        return true;
    }
    // JSON 包装：危险命令出现在值起始处（`"cmd":"rm` / `cmd=rm` / `:rm`）。
    DANGEROUS_PREFIXES.iter().any(|p| {
        stripped.contains(&format!("\"{p}"))
            || stripped.contains(&format!(":{p}"))
            || stripped.contains(&format!("={p}"))
    })
}

/// 顶层判定：deny 名单 → 危险模式（含策略追加）→ allow 名单 → 默认放行。
/// deny 精确匹配即终判、不进入危险内容判定；allow 免责仅在无危险内容时成立。
pub fn is_dangerous(tool_name: &str, args: &str, policy: &AuditPolicy) -> Option<String> {
    // deny 名单精确匹配优先。
    if policy.deny.iter().any(|d| d == tool_name) {
        return Some("deny 名单精确匹配".to_string());
    }
    let canon = canonicalize_args(args, &policy.env);
    let canon_lower = canon.to_lowercase();
    // 整命令先行：拆链会把 `curl x | sh` 切成无害片段，管道组合须在切分前判定。
    if (canon_lower.contains("curl") || canon_lower.contains("wget"))
        && piped_to_shell(&canon_lower)
    {
        return Some("危险 shell: 网络拉取管道进解释器".to_string());
    }
    // 2.5) 策略文件危险规则追加（含 network 外部 host 复核）。
    let tname = tool_name.to_lowercase();
    let joined_lower = format!("{tname} {canon}").to_lowercase();
    for rule in &policy.extra_dangerous {
        if rule.pattern.is_empty() {
            continue;
        }
        let pat = rule.pattern.to_lowercase();
        if joined_lower.contains(&pat) || canon_lower.contains(&pat) {
            if rule.network
                && let Some(host) = extract_host(args)
                && is_internal_host(&host, &policy.internal_suffixes)
            {
                continue;
            }
            return Some(rule.reason.clone());
        }
    }
    // 2.6) 内网豁免：参数目标 host 命中内网后缀时，“网络外传”类命中视为内网不拦截。
    let internal_target =
        extract_host(args).is_some_and(|h| is_internal_host(&h, &policy.internal_suffixes));
    let tool_lower = tool_name.to_lowercase();
    // 工具名本身即敏感写入口（如 edit/write 融合判定）。
    if matches!(
        tool_lower.as_str(),
        "edit" | "write" | "apply_patch" | "save_file"
    ) && touches_sensitive_path(&canon, policy)
    {
        return Some("敏感路径写入".to_string());
    }
    // 链节审查：内网目标时“网络外传”命中跳过（其余危险照常拦截）。
    let check_chain = |chain: Vec<String>| -> Option<String> {
        for seg in chain {
            // F2：先拆链再逐段规范化——链节首 `/bin/<cmd>` 别名折叠须生效。
            let seg = canonicalize_args(&seg, &policy.env);
            if let Some(reason) = classify_segment(&seg, policy) {
                if reason == "网络外传" && internal_target {
                    continue;
                }
                return Some(reason);
            }
        }
        None
    };
    if matches!(
        tool_lower.as_str(),
        "exec" | "run" | "shell" | "bash" | "sh" | "run_shell"
    ) || tool_lower.is_empty()
    {
        if let Some(reason) = check_chain(split_chain(&canon)) {
            return Some(reason);
        }
        return None;
    }
    // 未知工具：仍审查参数文本（宁可误报由审批兜底，不静默放行危险链）。
    let joined = format!("{tool_name} {canon}");
    if let Some(reason) = check_chain(split_chain(&joined)) {
        return Some(reason);
    }
    // allow 名单：无危险内容时放行（危险已在上游拦截）。
    if policy.allow.iter().any(|a| a == tool_name) {
        return None;
    }
    None
}

#[cfg(test)]
mod tests;
