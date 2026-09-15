//! 审计日志落盘（D2 自 `audit.rs` 拆出）：§6.3 先脱敏后截断 + 0600 轮转。

use {
    super::normalize::utf8_len,
    crate::error::{Result, VeilError},
    std::{
        path::PathBuf,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
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
#[cfg(test)]
pub(crate) fn sanitize_hardened(
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
    /// 追加与轮转的互斥锁：串行化 `maybe_rotate` + 打开 + 写入，
    /// 使并发 `log_event` 不丢行、轮转不损坏（`TCP-1`）。
    write_lock: Mutex<()>,
}

impl AuditLogger {
    pub fn new(data_dir: PathBuf) -> Self { Self::with_max_bytes(data_dir, AUDIT_LOG_MAX_BYTES) }

    /// 指定轮转阈值构造（生产 `new` 走 10MB；单测以小阈值免写 10MB）。
    fn with_max_bytes(data_dir: PathBuf, max_bytes: u64) -> Self {
        Self {
            data_dir,
            max_bytes,
            breaker_count: AtomicU64::new(0),
            write_lock: Mutex::new(()),
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
        use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
        // 并发 `log_event`（`AuditSink` 在 `spawn_blocking` 中调用）下，
        // 轮转判定/重命名与追加必须作为一个临界区，否则可能丢行或损坏轮转产物。
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::fs::create_dir_all(&self.data_dir)?;
        self.maybe_rotate()?;
        let path = self.log_path();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
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
mod rotate_tests;

#[cfg(test)]
mod log_tests;
