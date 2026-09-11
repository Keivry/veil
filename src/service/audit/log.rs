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
        let long = format!("sk-{}尾", "a".repeat(9000));
        let clean = sanitize_for_log(&long);
        assert!(clean.chars().count() <= AUDIT_SUMMARY_TRUNCATE_CHARS);
        assert!(!clean.contains(&"a".repeat(100)));
        assert!(clean.contains("[REDACTED"));
    }

    #[test]
    fn hardened_layer_error_yields_zero_plaintext_placeholder() {
        let out = sanitize_hardened("password=hunter2", |t| Ok(t.to_string()));
        assert!(!out.contains("hunter2"), "{out}");
        let bad = sanitize_hardened("password=hunter2", |_| Err(anyhow::anyhow!("强化层崩溃")));
        assert_eq!(bad, "[REDACTED:unverified]");
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
}
