//! 审计日志落盘（D2 自 `audit.rs` 拆出）：§6.3 先脱敏后截断 + 0600 轮转。

use {
    super::normalize::utf8_len,
    crate::error::{Result, VeilError},
    std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    },
};

// ---------------------------------------------------------------------------
// §6.3 审计日志
// ---------------------------------------------------------------------------

/// 审计日志单文件上限 10MB，保留 5 份。
pub const AUDIT_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// 轮转保留份数。
pub const AUDIT_LOG_KEEP: usize = 5;
/// 摘要截断上限（字符数，先脱敏后截断）。
/// R4 裁决：见 `metrics::SUMMARY_MAX_CHARS` 侧对称声明（1000 vs 4096 差异有意）。
pub const AUDIT_SUMMARY_TRUNCATE_CHARS: usize = 4096;
/// A9/D8：连续写失败熔断阈值——达阈值打 critical 告警并重置计数。
pub const AUDIT_BREAKER_THRESHOLD: u64 = 10;

/// 强化脱敏包装：先跑强化层回调，异常时返回 `[REDACTED:unverified]` 零明文落盘
/// （不透出原文，不回退明文；调用方须告警并按 fail-closed 处理主请求）。
pub fn sanitize_hardened(
    text: &str,
    hardened: impl FnOnce(&str) -> anyhow::Result<String>,
) -> String {
    match hardened(text) {
        Ok(out) => sanitize_for_log(&out),
        Err(e) => {
            tracing::error!("PII 强化层异常，摘要置占位符: {e:#}");
            "[REDACTED:unverified]".to_string()
        }
    }
}

/// 先脱敏后截断的摘要：剥 `\x00-\x1f`，掩盖密钥形态，零明文，UTF-8 安全截断。
/// R3 收敛声明：本函数为审计面唯一脱敏入口（审计日志/审批摘要/Matrix 通知），
/// 见 `redact_summary` 侧对称声明；两引擎契约分治，不合并。
pub fn sanitize_for_log(text: &str) -> String {
    // 1) 剥控制字符（含 \n/\r：JSONL 单行语义）。
    let stripped: String = text.chars().filter(|c| !c.is_control()).collect();
    // 2) 脱敏：sk- 密钥形态掩盖。
    let masked = mask_secret_forms(&stripped);
    // 3) 截断（字符级，UTF-8 安全）。
    truncate_chars(&masked, AUDIT_SUMMARY_TRUNCATE_CHARS)
}

fn mask_secret_forms(s: &str) -> String {
    // R1：在完整输入上脱敏（先脱敏后截断），截断由 `sanitize_for_log` 收口。
    // 近线性：整输入一次性 ASCII 小写预计算（字节对齐、非逐位置重建），供 `secret_kv_at` 复用；
    // 单趟前向扫描命中即产出占位符并跳过长度。
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // 私钥 PEM 块：整块（含头尾标记）置占位符。
        if let Some(len) = private_key_block_at(s, i) {
            out.push_str("[REDACTED:private_key]");
            i += len;
            continue;
        }
        // Bearer：保留关键字，仅掩盖 token 段；token 命中密钥前缀时交给前缀规则
        // （既有 `b9_deny_summary_dual_shapes` 断言 `Bearer sk-...` → `[REDACTED:secret]`）。
        if let Some((head_len, tok_len)) = bearer_at(s, i) {
            let tok_start = i + head_len;
            out.push_str(&s[i..tok_start]);
            if secret_prefix_at(&s[tok_start..]).is_none() {
                out.push_str("[REDACTED:bearer]");
                i = tok_start + tok_len;
            } else {
                i = tok_start;
            }
            continue;
        }
        // 裸 JWT（`eyJ...` 三段点分）形态。
        if let Some(len) = jwt_at(s, i) {
            out.push_str("[REDACTED:bearer]");
            i += len;
            continue;
        }
        // 邮箱（先于号码类，避免 `13800138000@x.com` 被手机规则截断）。
        if let Some(len) = email_at(s, i) {
            out.push_str("[REDACTED:email]");
            i += len;
            continue;
        }
        // 身份证（17 位数字 + `[0-9Xx]` 校验位，边界感知）。
        if let Some(len) = id_card_at(s, i) {
            out.push_str("[REDACTED:id_card]");
            i += len;
            continue;
        }
        // 手机号（`1[3-9]` + 9 位，边界感知）。
        if let Some(len) = phone_at(s, i) {
            out.push_str("[REDACTED:phone]");
            i += len;
            continue;
        }
        // sk- / sk_or_ / ghp_ / glpat- / xox?- 等密钥前缀：吞掉后续 [A-Za-z0-9-_]{8,}。
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
        if let Some((key_len, val_len)) = secret_kv_at(s, &lower, i) {
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
        "ghs_",
        "ghu_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
        "AKIA",
        "__VG_CRED_",
    ] {
        if s.starts_with(prefix) {
            return Some(prefix.len());
        }
    }
    None
}

/// 私钥 PEM 块：`-----BEGIN ... PRIVATE KEY----- ... -----END ... PRIVATE KEY-----`
/// 整块长度（含头尾标记）。
fn private_key_block_at(s: &str, i: usize) -> Option<usize> {
    let rest = &s[i..];
    let after_begin = rest.strip_prefix("-----BEGIN")?;
    let dashes1 = after_begin.find("-----")?;
    if !after_begin[..dashes1].contains("PRIVATE KEY") {
        return None;
    }
    let header_len = 5 + dashes1 + 5;
    let body = &rest[header_len..];
    let end_marker = body.find("-----END")?;
    let after_end = &body[end_marker + 8..];
    let dashes2 = after_end.find("-----")?;
    Some(header_len + end_marker + 8 + dashes2 + 5)
}

/// `Bearer <token>`：返回（关键字 + 空白段长度，token 段长度）。
fn bearer_at(s: &str, i: usize) -> Option<(usize, usize)> {
    let after = s[i..].strip_prefix("Bearer")?;
    let ws_len = after.bytes().take_while(u8::is_ascii_whitespace).count();
    if ws_len == 0 {
        return None;
    }
    let tok_start = 6 + ws_len;
    let tok_len = s[i + tok_start..]
        .bytes()
        .take_while(|b| !b.is_ascii_whitespace() && !matches!(*b, b',' | b'}' | b'"' | b'\''))
        .count();
    if tok_len == 0 {
        return None;
    }
    Some((tok_start, tok_len))
}

/// 裸 JWT：`eyJ` 起头、三段点分、字符集 `[A-Za-z0-9_-]`，边界不粘词字符。
fn jwt_at(s: &str, i: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
        return None;
    }
    if !s[i..].starts_with("eyJ") {
        return None;
    }
    let mut n = 0;
    let mut dots = 0;
    while i + n < bytes.len() {
        let b = bytes[i + n];
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            n += 1;
        } else if b == b'.' {
            dots += 1;
            n += 1;
        } else {
            break;
        }
    }
    if dots >= 2 { Some(n) } else { None }
}

/// 邮箱：`local@domain.tld`，前后边界不粘词字符。
/// R1/D1：完整输入扫描下，局部段按 RFC 5321 上限 64、域按 RFC 1035 上限 255 做有界搜索，
/// 避免逐位置全量 `find('@')`/local 校验/域扫描退化为 O(n²)。
fn email_at(s: &str, i: usize) -> Option<usize> {
    const LOCAL_MAX: usize = 64;
    const DOMAIN_MAX: usize = 255;
    let bytes = s.as_bytes();
    if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
        return None;
    }
    let local_hi = bytes
        .len()
        .min(i.saturating_add(LOCAL_MAX).saturating_add(1));
    let at = bytes[i..local_hi].iter().position(|&b| b == b'@')?;
    if at == 0 {
        return None;
    }
    let local = &s[i..i + at];
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'))
    {
        return None;
    }
    let dom_start = i + at + 1;
    let dom_hi = bytes.len().min(dom_start.saturating_add(DOMAIN_MAX));
    let dom_end = bytes[dom_start..dom_hi]
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')))
        .unwrap_or(dom_hi - dom_start);
    let dom = &s[dom_start..dom_start + dom_end];
    let dot = dom.rfind('.')?;
    let tld = &dom[dot + 1..];
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let end = dom_start + dom_end;
    if end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
        return None;
    }
    Some(end - i)
}

/// 身份证：17 位数字 + `[0-9Xx]`，前后边界不粘数字/字母。
fn id_card_at(s: &str, i: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
        return None;
    }
    if bytes.len() < i + 18 {
        return None;
    }
    if !bytes[i..i + 17].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let last = bytes[i + 17];
    if !(last.is_ascii_digit() || last == b'X' || last == b'x') {
        return None;
    }
    let end = i + 18;
    if end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
        return None;
    }
    Some(18)
}

/// 手机号：`1[3-9]` + 9 位，前后边界不粘数字。
fn phone_at(s: &str, i: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if i > 0 && bytes[i - 1].is_ascii_digit() {
        return None;
    }
    if bytes.len() < i + 11 || bytes[i] != b'1' {
        return None;
    }
    if !(b'3'..=b'9').contains(&bytes[i + 1]) {
        return None;
    }
    if !bytes[i..i + 11].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let end = i + 11;
    if end < bytes.len() && bytes[end].is_ascii_digit() {
        return None;
    }
    Some(11)
}

/// 匹配 `"key" : "value"` / `key= value` 中键为敏感词的形态，
/// 返回（键段长度，值段长度）。键段含分隔符，值段为待掩盖长度。
fn secret_kv_at(s: &str, lower: &str, i: usize) -> Option<(usize, usize)> {
    let s = &s[i..];
    let lower = &lower[i..];
    for key in [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "pwd",
        "access_key",
        "auth_key",
        "secret_key",
        "private_key",
    ] {
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

/// S4/D4：递归对事件 JSON 所有字符串值先脱敏后截断（4096 字符口径），
/// 使 `serde_json` 序列化后的落盘行恒为合法 JSON。
fn sanitize_event_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            *s = truncate_chars(&mask_secret_forms(s), AUDIT_SUMMARY_TRUNCATE_CHARS);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(sanitize_event_fields),
        serde_json::Value::Object(map) => map.values_mut().for_each(sanitize_event_fields),
        _ => {}
    }
}

/// JSONL 审计日志：0600、10MB x 5 轮转、写失败双层重试 + 熔断计数
/// （deny/allow 语义分治见 `AuditSink`，A9/D8）。
#[derive(Debug)]
pub struct AuditLogger {
    data_dir: PathBuf,
    /// 轮转阈值（生产恒为 [`AUDIT_LOG_MAX_BYTES`]；单测以小值触发轮转）。
    max_bytes: u64,
    breaker_count: AtomicU64,
}

impl AuditLogger {
    pub fn new(data_dir: PathBuf) -> Self { Self::with_max_bytes(data_dir, AUDIT_LOG_MAX_BYTES) }

    /// 指定轮转阈值构造（生产 `new` 走 10MB；单测以小阈值免写 10MB）。
    fn with_max_bytes(data_dir: PathBuf, max_bytes: u64) -> Self {
        Self {
            data_dir,
            max_bytes,
            breaker_count: AtomicU64::new(0),
        }
    }

    pub fn log_path(&self) -> PathBuf { self.data_dir.join("audit.log") }

    pub fn breaker_count(&self) -> u64 { self.breaker_count.load(Ordering::SeqCst) }

    /// 写一条审计事件：先脱敏后截断再落盘。
    /// 写失败先重试一次（双层第一层：缓冲重试），仍失败则熔断计数 +1
    /// （连续失败达 [`AUDIT_BREAKER_THRESHOLD`] 打 critical 告警并重置）并返回
    /// [`VeilError::Storage`]；写失败语义由调用方按 verdict 路径处置（A9/D8）。
    pub fn log_event(&self, event: &serde_json::Value) -> Result<()> {
        // S4/D4：序列化前对事件所有字符串值（递归）先脱敏后截断，落盘行恒为合法 JSON；
        // `sanitize_for_log` 保留为整串摘要/通知入口，不再作用于整行。
        let mut sanitized = event.clone();
        sanitize_event_fields(&mut sanitized);
        let mut line = serde_json::to_string(&sanitized).map_err(|e| VeilError::Storage {
            message: format!("审计事件序列化失败: {e}"),
        })?;
        line.push('\n');
        if let Err(e) = self.append_line(&line) {
            // 第一层：短暂退避后重试一次。
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Err(e2) = self.append_line(&line) {
                self.on_write_failure(&format!("{e} / {e2}"));
                return Err(VeilError::Storage {
                    message: format!("审计日志写失败（已重试）: {e} / {e2}"),
                });
            }
        }
        self.breaker_count.store(0, Ordering::SeqCst);
        Ok(())
    }

    /// 连续失败计数：成功落盘即归零（由 `log_event` 维护）；达阈值 critical + 重置。
    fn on_write_failure(&self, err: &str) {
        let n = self.breaker_count.fetch_add(1, Ordering::SeqCst) + 1;
        if n >= AUDIT_BREAKER_THRESHOLD {
            tracing::error!(
                critical = true,
                "审计日志连续 {n} 次写失败，触发熔断告警并重置计数: {err}"
            );
            self.breaker_count.store(0, Ordering::SeqCst);
        }
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
        if size < self.max_bytes {
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

#[cfg(test)]
mod log_tests {
    use super::*;

    #[test]
    fn audit_log_zero_plaintext_and_control_chars_stripped() {
        let dirty = "key sk-abcDEF1234567890\n\x00\x1f{\"password\":\"hunter2\"}";
        let clean = sanitize_for_log(dirty);
        assert!(!clean.contains("sk-abcDEF1234567890"), "{clean}");
        assert!(!clean.contains("hunter2"), "{clean}");
        assert!(!clean.chars().any(|c| c.is_control()), "{clean:?}");
        assert!(clean.contains("[REDACTED"), "{clean}");
    }

    #[test]
    fn b9_deny_summary_dual_shapes() {
        // B9：Bearer 头形态 deny 摘要脱敏且无明文，形态字段齐全。
        let bearer = "deny auth Authorization: Bearer sk-hunter2-secret-value reason=拒绝";
        let clean = sanitize_for_log(bearer);
        assert!(!clean.contains("hunter2"), "{clean}");
        assert!(clean.contains("[REDACTED:secret]"), "{clean}");
        assert!(clean.contains("Bearer"), "{clean}");
        assert!(clean.contains("拒绝"), "{clean}");
        // B9：键值 JSON 形态 deny 摘要同样脱敏且形态字段齐全。
        let kv = r#"deny {"secret":"s3cr3t-value","entry":"网易"}"#;
        let clean = sanitize_for_log(kv);
        assert!(!clean.contains("s3cr3t-value"), "{clean}");
        assert!(clean.contains("[REDACTED:*]"), "{clean}");
        assert!(clean.contains("\"secret\""), "{clean}");
        assert!(clean.contains("网易"), "{clean}");
        // B9 边缘：双形态齐全时各记各摘要不混淆。
        let both = format!("{bearer} {kv}");
        let clean = sanitize_for_log(&both);
        assert!(!clean.contains("hunter2"), "{clean}");
        assert!(!clean.contains("s3cr3t-value"), "{clean}");
        assert!(clean.contains("[REDACTED:secret]"), "{clean}");
        assert!(clean.contains("[REDACTED:*]"), "{clean}");
        assert!(clean.contains("Bearer"), "{clean}");
        assert!(clean.contains("\"secret\""), "{clean}");
    }

    #[test]
    fn audit_log_mode_0600_with_breaker_count() {
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
    fn summary_redacts_before_truncation_utf8_safe() {
        // R1 逐字口径：完整输入脱敏后再截断，长 sk- 输出与旧口径逐字一致。
        let long = format!("sk-{}尾", "a".repeat(9000));
        let clean = sanitize_for_log(&long);
        assert_eq!(clean, "[REDACTED:secret]尾");
        assert!(clean.chars().count() <= AUDIT_SUMMARY_TRUNCATE_CHARS);
        assert!(!clean.contains(&"a".repeat(100)));
    }

    #[test]
    fn long_non_secret_input_truncates_byte_identical() {
        // R1/1.3：未命中密钥形态的长输入，先脱敏后截断与旧口径逐字一致（前 4096 字符）。
        let input = "x".repeat(9000);
        let clean = sanitize_for_log(&input);
        assert_eq!(clean, "x".repeat(AUDIT_SUMMARY_TRUNCATE_CHARS));
    }

    #[test]
    fn long_pem_block_redacted() {
        // R1：>4096 字符 PEM 块须整体置占位符；旧口径先截断丢失 END 会泄漏 base64 私钥材料。
        let material = "A".repeat(5000);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{material}\n-----END PRIVATE KEY-----");
        let clean = sanitize_for_log(&pem);
        assert!(clean.contains("[REDACTED:private_key]"), "{clean}");
        assert!(!clean.contains(&"A".repeat(100)), "base64 明文残留");
    }

    #[test]
    fn audit_summary_linear_bound() {
        // F6/D6：对抗输入（逐位候选 + 远端 '@'）在 1MB 内须近似线性完成。
        let n = 200_000usize;
        let input = format!("{}@{}.1", ".".repeat(n), "a".repeat(n));
        let start = std::time::Instant::now();
        let clean = sanitize_for_log(&input);
        let elapsed = start.elapsed();
        assert!(clean.chars().count() <= AUDIT_SUMMARY_TRUNCATE_CHARS);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "摘要脱敏耗时 {elapsed:?} 超出近线性预期"
        );
    }

    #[test]
    fn mask_secret_forms_large_input() {
        // F6/D6：接近 `AUDIT_HOLD_MAX_BYTES` 的大输入仍掩盖密钥形态且零明文。
        let n = usize::try_from(crate::config::AUDIT_HOLD_MAX_BYTES_DEFAULT).unwrap_or(1_048_576);
        let mut input = String::with_capacity(n + 32);
        input.push_str("sk-hunter2secretvalue ");
        input.push_str(&"a".repeat(n));
        let clean = mask_secret_forms(&input);
        assert!(clean.contains("[REDACTED:secret]"), "大输入密钥形态须掩盖");
        assert!(!clean.contains("hunter2"), "大输入不得残留明文");
    }

    #[test]
    fn hardened_layer_error_yields_zero_plaintext_placeholder() {
        let out = sanitize_hardened("password=hunter2", |t| Ok(t.to_string()));
        assert!(!out.contains("hunter2"), "{out}");
        let bad = sanitize_hardened("password=hunter2", |_| Err(anyhow::anyhow!("强化层崩溃")));
        assert_eq!(bad, "[REDACTED:unverified]");
    }

    #[test]
    fn audit_log_rotate_five() {
        // A1/1.2：以小阈值触发轮转（免写 10MB），断言 audit.log.1 生成且备份份数上限 5。
        let dir = std::env::temp_dir().join(format!(
            "veil-audit-rotate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let logger = AuditLogger::with_max_bytes(dir.clone(), 128);
        for i in 0..400 {
            logger
                .log_event(&serde_json::json!({"n": i, "kind": "block"}))
                .unwrap();
        }
        assert!(dir.join("audit.log.1").exists(), "轮转后须生成 audit.log.1");
        let backups = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
            .count();
        assert!(
            backups <= AUDIT_LOG_KEEP,
            "备份份数上限 {AUDIT_LOG_KEEP}，实际 {backups}"
        );
        for line in std::fs::read_to_string(logger.log_path()).unwrap().lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_summary_forms() {
        let cases: [(&str, &str, &str); 8] = [
            ("phone", "call 13800138000 now", "[REDACTED:phone]"),
            ("id_card", "id 11010119900307123X end", "[REDACTED:id_card]"),
            ("email", "mail alice@example.com ok", "[REDACTED:email]"),
            (
                "bearer_jwt",
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.\
                 SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "[REDACTED:bearer]",
            ),
            (
                "private_key",
                "-----BEGIN RSA PRIVATE KEY-----MIIEsecretkeymaterial-----END RSA PRIVATE KEY-----",
                "[REDACTED:private_key]",
            ),
            (
                "glpat",
                "token glpat-abcDEF1234567890 end",
                "[REDACTED:secret]",
            ),
            ("ghs", "token ghs_abcDEF1234567890 end", "[REDACTED:secret]"),
            (
                "xoxs",
                "token xoxs-abcDEF1234567890 end",
                "[REDACTED:secret]",
            ),
        ];
        for (name, input, expect) in cases {
            let clean = sanitize_for_log(input);
            assert!(clean.contains(expect), "{name}: {clean}");
        }
        // 键值对扩展键：值段掩盖且不吞掉后续 JSON 字段。
        for key in ["pwd", "access_key", "auth_key", "secret_key", "private_key"] {
            let bare = format!("{key}=topsecretvalue");
            let clean = sanitize_for_log(&bare);
            assert!(clean.contains("[REDACTED:*]"), "{key}: {clean}");
            assert!(!clean.contains("topsecretvalue"), "{key}: {clean}");
            let json = format!(r#"{{"{key}":"topsecretvalue","entry":"网易"}}"#);
            let clean = sanitize_for_log(&json);
            assert!(clean.contains("[REDACTED:*]"), "{key}: {clean}");
            assert!(!clean.contains("topsecretvalue"), "{key}: {clean}");
            assert!(clean.contains("\"entry\""), "{key}: {clean}");
            assert!(clean.contains("网易"), "{key}: {clean}");
        }
    }

    #[test]
    fn audit_summary_zero_plaintext() {
        let samples = [
            "call 13800138000",
            "id 11010119900307123X",
            "mail alice@example.com",
            "Authorization: Bearer xtokenABC123456",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
            "-----BEGIN PRIVATE KEY-----MIIEsecretkeymaterial-----END PRIVATE KEY-----",
        ];
        let plaintexts = [
            "13800138000",
            "11010119900307123X",
            "alice@example.com",
            "xtokenABC123456",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
            "MIIEsecretkeymaterial",
        ];
        for (sample, plain) in samples.iter().zip(plaintexts) {
            let clean = sanitize_for_log(sample);
            assert!(!clean.contains(plain), "明文残留: {clean}");
            assert!(clean.contains("[REDACTED:"), "{clean}");
        }
    }

    #[test]
    fn t5_sanitize_hardened_never_leaks() {
        let out = sanitize_hardened("secret hunter2", |_| Err(anyhow::anyhow!("boom")));
        assert_eq!(out, "[REDACTED:unverified]");
        let ok = sanitize_hardened(r#"{"password":"hunter2"} sk-abcdef123456"#, |s| {
            Ok(s.to_string())
        });
        assert!(!ok.contains("hunter2"), "{ok}");
        assert!(!ok.contains("sk-abcdef123456"), "{ok}");
    }

    #[test]
    fn audit_overlong_line_valid_json() {
        let dir = std::env::temp_dir().join(format!("veil-audit-s4a-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let logger = AuditLogger::new(dir.clone());
        let cap = AUDIT_SUMMARY_TRUNCATE_CHARS;
        let event = serde_json::json!({"ev": "block", "reason": "危".repeat(8000), "nested": {"entry": "网易", "list": ["危险"]}});
        assert!(serde_json::to_string(&event).unwrap().chars().count() > cap);
        logger.log_event(&event).unwrap();
        let content = std::fs::read_to_string(logger.log_path()).unwrap();
        let line = content.lines().next().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(parsed["ev"], "block");
        assert!(parsed["reason"].as_str().unwrap().chars().count() <= cap);
        assert_eq!(parsed["nested"]["entry"], "网易");
        assert_eq!(parsed["nested"]["list"][0], "危险");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_overlong_zero_plaintext() {
        let dir = std::env::temp_dir().join(format!("veil-audit-s4b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let logger = AuditLogger::new(dir.clone());
        let secret = format!("sk-{}", "A1b2C3d4".repeat(700));
        let event = serde_json::json!({
            "ev": "block",
            "reason": format!("curl -d 'token={secret}' 目标 网易"),
            "note": format!("Authorization: Bearer {secret}"),
        });
        assert!(
            serde_json::to_string(&event).unwrap().chars().count() > AUDIT_SUMMARY_TRUNCATE_CHARS
        );
        logger.log_event(&event).unwrap();
        let content = std::fs::read_to_string(logger.log_path()).unwrap();
        let line = content.lines().next().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        let text = parsed.to_string();
        assert!(text.contains("[REDACTED:*]"), "{text}");
        assert!(text.contains("[REDACTED:secret]"), "{text}");
        assert!(
            !text.contains(&secret) && !text.contains(&"A1b2C3d4".repeat(100)),
            "明文残留: {text}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
