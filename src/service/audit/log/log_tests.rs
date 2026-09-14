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
    assert!(serde_json::to_string(&event).unwrap().chars().count() > AUDIT_SUMMARY_TRUNCATE_CHARS);
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

#[tokio::test]
async fn audit_dynamic_pii_zero_plaintext() {
    // TST-7：请求期动态映射（`Scope`/`detector` 实时生成的 `__PII_*__`）进审计记录/摘要 → 零明文。
    use crate::service::{
        credential_vault::CredentialVault,
        pii::detector::test_support,
        redaction::Scope,
    };
    let scope = Scope::new();
    let detector = test_support::detector();
    let vault = CredentialVault::new();
    let raw = "curl -d 'phone 13800138000 mail alice@example.com'";
    let redacted = scope.redact_request_plain(&vault, &detector, raw).await;
    let token_re = regex::Regex::new(r"__PII_\d+_[0-9a-f]{8}__").expect("占位符正则恒合法");
    assert!(
        token_re.is_match(&redacted),
        "须生成动态 __PII_*__ 占位符: {redacted}"
    );
    // 摘要路径零明文（复用 audit_summary_zero_plaintext 断言形态）。
    let clean = sanitize_for_log(&redacted);
    for plain in ["13800138000", "alice@example.com"] {
        assert!(
            !clean.contains(plain),
            "动态映射摘要残留明文 {plain}: {clean}"
        );
    }
    // 落盘审计记录零明文：事件同时携带动态占位符与同批原始明文（模拟 hold 捕获）。
    let dir = std::env::temp_dir().join(format!("veil-audit-tst7-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let logger = AuditLogger::new(dir.clone());
    logger
        .log_event(&serde_json::json!({
            "ev": "approve",
            "redacted": redacted,
            "raw_tool_args": raw,
        }))
        .unwrap();
    let content = std::fs::read_to_string(logger.log_path()).unwrap();
    let line = content.lines().next().unwrap();
    serde_json::from_str::<serde_json::Value>(line).expect("审计行须为合法 JSON");
    for plain in ["13800138000", "alice@example.com"] {
        assert!(
            !line.contains(plain),
            "审计记录残留动态明文 {plain}: {line}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}
