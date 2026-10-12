use {
    super::{super::test_whitelist, *},
    std::sync::atomic::{AtomicU64, Ordering},
};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("veil-audit-{tag}-{}-{n}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sink_with_logger(logger: AuditLogger, admin_dir: std::path::PathBuf) -> AuditSink {
    let admin = Arc::new(AdminState::new(
        admin_dir.join("metrics.sqlite"),
        crate::service::metrics::PiiSamplerConfig {
            enabled: false,
            persist: false,
            hmac_key: None,
        },
    ));
    AuditSink::new(Arc::new(logger), admin)
}

fn sink_in(dir: std::path::PathBuf) -> AuditSink {
    sink_with_logger(AuditLogger::new(dir.clone()), dir)
}

/// 生成一个必然写失败的日志目录（`audit.log` 为子目录 → `EISDIR`，不依赖运行 uid）。
fn unwritable_logger(admin_dir: &std::path::Path) -> AuditLogger {
    let bad = admin_dir.join("unwritable");
    std::fs::create_dir_all(bad.join("audit.log")).unwrap();
    AuditLogger::new(bad)
}

#[tokio::test]
async fn audit_log_wired() {
    // verdict 命中与放行均经单例落盘，不再零调用死码。
    let dir = unique_dir("wired");
    let sink = sink_in(dir.clone());
    let policy = AuditPolicy::default_policy();
    let v = sink
        .evaluate_and_record(
            AuditMode::Block,
            "exec",
            "rm -rf /",
            &policy,
            test_whitelist(),
            Some("chat"),
        )
        .await;
    assert!(matches!(v, AuditVerdict::Block { .. }), "{v:?}");
    let allow = sink
        .evaluate_and_record(
            AuditMode::Block,
            "exec",
            "echo ok",
            &policy,
            test_whitelist(),
            Some("chat"),
        )
        .await;
    assert_eq!(allow, AuditVerdict::Allow);
    let content = std::fs::read_to_string(dir.join("audit.log")).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2, "命中与放行各落一行: {content}");
    assert!(lines[0].contains("\"kind\":\"block\""), "{}", lines[0]);
    assert!(lines[1].contains("\"kind\":\"allow\""), "{}", lines[1]);
    for line in lines {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn audit_log_write_fail_semantics() {
    // deny 写失败保持结论（不降级）；allow 写失败不阻断主请求；
    // 两路径均熔断计数 +1，连续失败达阈值打 critical 并重置计数。
    let dir = unique_dir("fail");
    let sink = sink_with_logger(unwritable_logger(&dir), dir.clone());
    let policy = AuditPolicy::default_policy();

    let deny_outcome = sink
        .record_verdict(
            &AuditVerdict::Block {
                reason: "危险 shell".to_string(),
            },
            "exec",
            "rm -rf /",
            None,
        )
        .await;
    assert_eq!(deny_outcome, AuditWriteOutcome::DenyWriteFailed);
    assert_eq!(sink.breaker_count(), 1, "deny 写失败须计数 +1");

    let deny = sink
        .evaluate_and_record(
            AuditMode::Block,
            "exec",
            "rm -rf /",
            &policy,
            test_whitelist(),
            None,
        )
        .await;
    assert!(
        matches!(deny, AuditVerdict::Block { .. }),
        "deny 结论须保持"
    );
    assert_eq!(sink.breaker_count(), 2);

    let allow_outcome = sink
        .record_verdict(&AuditVerdict::Allow, "exec", "echo ok", None)
        .await;
    assert_eq!(allow_outcome, AuditWriteOutcome::AllowWriteFailed);
    assert_eq!(sink.breaker_count(), 3, "allow 写失败须计数 +1");

    let allow = sink
        .evaluate_and_record(
            AuditMode::Block,
            "exec",
            "echo ok",
            &policy,
            test_whitelist(),
            None,
        )
        .await;
    assert_eq!(allow, AuditVerdict::Allow, "allow 写失败不得阻断");
    assert_eq!(sink.breaker_count(), 4);

    // 连续失败达 10 次 → critical 告警并重置计数。
    for _ in 0..6 {
        let _ = sink
            .record_verdict(&AuditVerdict::Allow, "exec", "echo ok", None)
            .await;
    }
    assert_eq!(sink.breaker_count(), 0, "第 10 次连续失败须重置计数");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn audit_log_write_fail_injection() {
    // 故障注入覆盖 allow 与 deny 两路径及熔断计数。
    // 注入一：只读目录内 `audit.log` 为子目录（`EISDIR`，不依赖运行 uid）。
    // 注入二：`/proc` 不可写路径（`create/open` 恒失败）。
    let ro_dir = unique_dir("inj-ro");
    let proc_dir = unique_dir("inj-proc");
    let cases: [(&str, AuditLogger, std::path::PathBuf); 2] = [
        ("readonly-dir", unwritable_logger(&ro_dir), ro_dir.clone()),
        (
            "unwritable-path",
            AuditLogger::new(std::path::PathBuf::from("/proc/veil-nope-audit-inj")),
            proc_dir.clone(),
        ),
    ];
    for (tag, logger, admin_dir) in cases {
        let sink = sink_with_logger(logger, admin_dir);
        let deny = sink
            .record_verdict(
                &AuditVerdict::Block {
                    reason: "危险操作".to_string(),
                },
                "exec",
                "rm -rf /",
                None,
            )
            .await;
        assert_eq!(deny, AuditWriteOutcome::DenyWriteFailed, "{tag}");
        let allow = sink
            .record_verdict(&AuditVerdict::Allow, "exec", "echo ok", None)
            .await;
        assert_eq!(allow, AuditWriteOutcome::AllowWriteFailed, "{tag}");
        assert_eq!(sink.breaker_count(), 2, "{tag} 两路径各计数 +1");
    }
    std::fs::remove_dir_all(&ro_dir).ok();
    std::fs::remove_dir_all(&proc_dir).ok();
}

#[tokio::test]
async fn audit_event_ring_visible() {
    // 审计事件以 kind="audit" 推入 AdminState 事件环并可查询。
    let dir = unique_dir("ring");
    let sink = sink_in(dir.clone());
    let policy = AuditPolicy::default_policy();
    sink.evaluate_and_record(
        AuditMode::Block,
        "exec",
        "rm -rf /",
        &policy,
        test_whitelist(),
        Some("chat"),
    )
    .await;
    let events = sink.admin().query_events(Some("audit"), None, 10);
    assert_eq!(events.len(), 1, "命中事件须可查");
    assert_eq!(events[0].kind, "audit");
    assert_eq!(events[0].protocol.as_deref(), Some("chat"));
    assert!(
        sink.admin()
            .query_events(Some("block"), None, 10)
            .is_empty(),
        "非 audit kind 不得命中"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn off_mode_records_nothing() {
    // 审计关闭零落盘（off 直通语义不因接线改变）。
    let dir = unique_dir("off");
    let sink = sink_in(dir.clone());
    let policy = AuditPolicy::default_policy();
    let v = sink
        .evaluate_and_record(AuditMode::Off, "exec", "rm -rf /", &policy, &[], None)
        .await;
    assert_eq!(v, AuditVerdict::Allow);
    assert!(!dir.join("audit.log").exists(), "off 模式不得落盘");
    assert!(
        sink.admin()
            .query_events(Some("audit"), None, 10)
            .is_empty()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn audit_log_block_has_summary() {
    // Block/Allow 两类记录均含参数脱敏摘要，无明文。
    let dir = unique_dir("args-summary");
    let sink = sink_in(dir.clone());
    let policy = AuditPolicy::default_policy();
    let block = sink
        .evaluate_and_record(
            AuditMode::Block,
            "exec",
            "rm -rf / && call 13800138000",
            &policy,
            test_whitelist(),
            Some("chat"),
        )
        .await;
    assert!(matches!(block, AuditVerdict::Block { .. }), "{block:?}");
    let allow = sink
        .evaluate_and_record(
            AuditMode::Block,
            "exec",
            "echo 13800138000",
            &policy,
            test_whitelist(),
            Some("chat"),
        )
        .await;
    assert_eq!(allow, AuditVerdict::Allow);
    let content = std::fs::read_to_string(dir.join("audit.log")).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2, "Block/Allow 各落一行: {content}");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let args_summary = v
            .get("args_summary")
            .and_then(|s| s.as_str())
            .expect("记录须含 args_summary");
        assert!(!args_summary.is_empty(), "参数摘要须非空: {line}");
    }
    assert!(
        content.contains("[REDACTED:phone]"),
        "参数摘要须经 ten-form 脱敏: {content}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn audit_log_summary_no_plaintext() {
    // 摘要不含明文；文件权限维持 0600。
    use std::os::unix::fs::PermissionsExt as _;
    let dir = unique_dir("summary-no-plain");
    let sink = sink_in(dir.clone());
    let policy = AuditPolicy::default_policy();
    sink.evaluate_and_record(
        AuditMode::Block,
        "exec",
        "send sk-abcDEF1234567890 mail a@b.com",
        &policy,
        test_whitelist(),
        None,
    )
    .await;
    let content = std::fs::read_to_string(dir.join("audit.log")).unwrap();
    assert!(
        !content.contains("sk-abcDEF1234567890"),
        "摘要不得含 API key 明文: {content}"
    );
    assert!(
        !content.contains("a@b.com"),
        "摘要不得含邮箱明文: {content}"
    );
    let mode = std::fs::metadata(dir.join("audit.log"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "审计日志权限须为 0600");
    std::fs::remove_dir_all(&dir).ok();
}
