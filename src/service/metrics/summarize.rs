//! 摘要脱敏：`redact → truncate` 单一路径 + 测试共享 helpers。

/// 秘密 JSON 键形态（`{"password":"hunter2"}` 落盘须为脱敏后）。
/// 对标原仓 `_SECRET_PATTERNS`：覆盖常见键名 + JSON 冒号形态。
fn secret_key_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)("?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)"?\s*[:=]\s*"?)[^",}\s][^",}]*"#,
        )
        .expect("secret 正则恒合法")
    })
}

fn sk_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{8,}").expect("sk 正则恒合法")
    })
}

fn email_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2}")
            .expect("email 正则恒合法")
    })
}

fn placeholder_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"__VG_CRED_[0-9A-Za-z_]*__?|__PII_[0-9A-Za-z_]*__?")
            .expect("占位符正则恒合法")
    })
}

fn ipv4_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?-u:\b)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?-u:\b)")
            .expect("ipv4 正则恒合法")
    })
}

fn id_card_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?-u:\b)[0-9]{17}[0-9Xx](?-u:\b)").expect("id_card 正则恒合法")
    })
}

fn bank_card_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?-u:\b)[0-9]{13,19}(?-u:\b)").expect("bank_card 正则恒合法")
    })
}

/// 摘要脱敏（单一路径）：先脱敏后截断。
///
/// 顺序硬性 `redact → truncate`：`__PII__`/`__VG_CRED__`/`sk-`/email/秘密键值
/// → `[REDACTED:*]`，控制字符（`\x00-\x1f` 除 `\t\n`）剥离防伪造条目。
/// R3 收敛声明：本引擎专供管理面事件摘要（`AdminState::push_event`，保留
/// `\t\n` + `[REDACTED:*]` 词表）；审计 JSONL 日志用 `audit::sanitize_for_log`
/// （全剥控制字符 + 前缀保留掩码，两面单行语义不同）。两引擎输出契约不同，
/// 合并任一方向都会改变对端可观测面并打破既有单测，故收敛以“契约分治 + 互引”
/// 落定，不做引擎合并（行为不变优先于实现统一）。
pub fn redact_summary(text: &str) -> String {
    // 控制字符先剥离（防伪造条目），保留 \t \n。
    let cleaned: String = text
        .chars()
        .filter(|&c| !c.is_control() || c == '\t' || c == '\n')
        .collect();
    let s = placeholder_re().replace_all(&cleaned, "[REDACTED:placeholder]");
    let s = sk_re().replace_all(&s, "[REDACTED:api_key]");
    let s = email_re().replace_all(&s, "[REDACTED:email]");
    // TST-8 兜底：IPv4（4 段）/身份证（17 位 + 数字或 X）/卡号（13-19 位连续数字）
    // 三类形态，与 `sample_mask` 对应分支可检出形态同口径；身份证先于卡号
    // （18 位为卡号子集）。`(?-u:\b)` 使 CJK 相邻也能切边界。
    let s = ipv4_re().replace_all(&s, "[REDACTED:ipv4]");
    let s = id_card_re().replace_all(&s, "[REDACTED:id_card]");
    let s = bank_card_re().replace_all(&s, "[REDACTED:bank_card]");
    // JSON 键形态：保留键名与分隔符，只脱敏值部（`$1` 为键+分隔符捕获组）。
    let s = secret_key_re().replace_all(&s, "$1[REDACTED:secret]");
    s.into_owned()
}

/// UTF-8 半字符保护截断（按字符数，不切分 `char` 边界）。
pub fn truncate_utf8(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars).collect();
    format!("{kept}…[truncated]")
}

/// 摘要单一路径：`redact → truncate`。
pub fn summarize(text: &str, max_chars: usize) -> String {
    truncate_utf8(&redact_summary(text), max_chars)
}

/// 跨子模块测试共享：sqlite 临时库 + usage/束构造 helpers（其它子模块测试经
/// `crate::service::metrics::summarize::test_support` 复用）。
#[cfg(test)]
pub(crate) mod test_support {
    use {
        super::super::aggregate::{ChatRecord, ExtendedChatRecord, ExtendedUsage},
        crate::service::llm_gateway::{Protocol, Usage},
        std::path::PathBuf,
    };

    pub(crate) fn tmp_db(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("veil-metrics-test-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).ok();
        dir.join("metrics.sqlite")
    }

    pub(crate) fn usage(p: u64, c: u64, t: u64) -> Usage {
        Usage {
            prompt_tokens: p,
            completion_tokens: c,
            total_tokens: t,
            total_explicit: true,
            cached_read: 0,
            cached_write: 0,
        }
    }

    pub(crate) fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// 测试束构造（C13）：位置参数打包 `ChatRecord`，与生产束调用同构。
    pub(crate) fn chat_rec<'a>(
        protocol: Protocol,
        model: &'a str,
        latency_ms: u64,
        usage: Option<&'a Usage>,
        truncated_mode: Option<&'a str>,
        is_precise: bool,
        ts_secs: i64,
    ) -> ChatRecord<'a> {
        ChatRecord {
            protocol,
            model,
            latency_ms,
            usage,
            truncated_mode,
            is_precise,
            ts_secs,
        }
    }

    /// 测试束构造：位置参数打包 `ExtendedChatRecord`。
    pub(crate) fn ext_rec<'a>(
        protocol: Protocol,
        model: &'a str,
        latency_ms: u64,
        usage: Option<&'a ExtendedUsage>,
        truncated_mode: Option<&'a str>,
        is_precise: bool,
        ts_secs: i64,
    ) -> ExtendedChatRecord<'a> {
        ExtendedChatRecord {
            protocol,
            model,
            latency_ms,
            usage,
            truncated_mode,
            is_precise,
            ts_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{aggregate::is_precise_for_window, store::MetricsStore},
            test_support::{chat_rec, now, tmp_db, usage},
            *,
        },
        crate::service::llm_gateway::Protocol,
    };

    #[tokio::test]
    async fn series_since_and_protocol_filter_semantics() {
        let db = tmp_db("series-filter");
        let _ = std::fs::remove_file(&db);
        let ts = now();
        let store = MetricsStore::new(db.clone());
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            10,
            Some(&usage(1, 1, 2)),
            None,
            true,
            ts,
        ));
        store.record_chat(chat_rec(
            Protocol::Responses,
            "",
            10,
            Some(&usage(2, 2, 4)),
            None,
            true,
            ts,
        ));
        store.flush().await.unwrap();
        let chat_only = store
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            .unwrap();
        assert!(chat_only.iter().all(|p| p.protocol == "chat/completions"));
        assert_eq!(chat_only.iter().map(|p| p.requests).sum::<u64>(), 1);
        let all = store.query_series("daily", None, None).await.unwrap();
        assert!(all.iter().map(|p| p.requests).sum::<u64>() >= 2);
        let since_far = "d99999999".to_string();
        let empty = store
            .query_series("daily", Some(since_far), None)
            .await
            .unwrap();
        assert!(empty.is_empty());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn t9_24h_7d_approximate_caliber_locked() {
        assert!(is_precise_for_window(3600, 100));
        assert!(!is_precise_for_window(3599, 100));
        assert!(!is_precise_for_window(86400, 99));
        assert!(!is_precise_for_window(0, 0));
    }

    #[test]
    fn summarize_redacts_through_single_path() {
        // JSON 键形态落盘为脱敏后。
        let out = summarize(r#"{"password":"hunter2"}"#, 1000);
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("[REDACTED:secret]"), "{out}");
        // sk- / email / 占位符三类。
        let out2 = summarize(
            "key sk-abcDEF1234567890 mail a@b.com ph __PII_1_ab12cd34__ cr __VG_CRED_000001__",
            1000,
        );
        assert!(!out2.contains("sk-abcDEF"), "{out2}");
        assert!(!out2.contains("a@b.com"), "{out2}");
        assert!(!out2.contains("__PII_"), "{out2}");
        assert!(!out2.contains("__VG_CRED_"), "{out2}");
        // 控制字符不产生伪造条目。
        let out3 = summarize("a\x00b\x1fc", 1000);
        assert!(!out3.contains('\x00') && !out3.contains('\x1f'));
        // UTF-8 半字符保护：截断不切分 char。
        let cn = "中文摘要".repeat(500);
        let t = summarize(&cn, 10);
        assert!(t.chars().count() <= 24, "{t}");
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }

    #[test]
    fn redact_summary_redacts_ipv4() {
        let out = redact_summary("客户端 192.168.1.10 连接");
        assert!(!out.contains("192.168.1.10"), "{out}");
        assert!(out.contains("[REDACTED:ipv4]"), "{out}");
    }

    #[test]
    fn redact_summary_redacts_id_card() {
        let out = redact_summary("身份证 11010119900307123X 校验");
        assert!(!out.contains("11010119900307123X"), "{out}");
        assert!(out.contains("[REDACTED:id_card]"), "{out}");
    }

    #[test]
    fn redact_summary_redacts_bank_card() {
        let out = redact_summary("卡号 6225880123456789 转账");
        assert!(!out.contains("6225880123456789"), "{out}");
        assert!(out.contains("[REDACTED:bank_card]"), "{out}");
    }
}
