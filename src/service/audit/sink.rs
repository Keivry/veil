//! A1/D1：审计判定结果落盘接线（唯一生产写入口）。
//!
//! `AuditLogger::log_event` 含同步文件 IO 与 50ms 退避重试，不得在 async
//! 上下文直调；本模块以 `AuditSink` 单例（`AppState` 持有）承载：判定结果
//! 推 `AdminState` 事件环（`kind="audit"`，D9）并经 `spawn_blocking` 写
//! `DATA_DIR/audit.log`。写失败按路径语义处置（D8/A9 边界）：deny 命中保持
//! 结论 + error 告警；allow 不阻断主请求 + 熔断计数。

use {
    super::{
        log::{AuditLogger, sanitize_for_log},
        policy::AuditPolicy,
        verdict::{AuditVerdict, evaluate_with_whitelist},
    },
    crate::{config::AuditMode, service::admin::AdminState},
    std::sync::Arc,
};

/// 审计落盘结果：写失败按路径语义区分，调用方不因写失败改判。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditWriteOutcome {
    /// 落盘成功。
    Written,
    /// deny（`Block`/`NeedApproval`）路径写失败：结论保持，error 告警。
    DenyWriteFailed,
    /// allow 路径写失败：主请求不阻断，熔断计数 +1。
    AllowWriteFailed,
}

/// 审计落盘 + 事件环接线单例（`AppState` 持有，流式/非流共享）。
pub struct AuditSink {
    logger: Arc<AuditLogger>,
    admin: Arc<AdminState>,
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSink").finish()
    }
}

impl AuditSink {
    pub fn new(logger: Arc<AuditLogger>, admin: Arc<AdminState>) -> Self { Self { logger, admin } }

    /// 连续写失败熔断计数（转发 `AuditLogger`）。
    pub fn breaker_count(&self) -> u64 { self.logger.breaker_count() }

    /// 事件环只读（观测与测试）。
    pub fn admin(&self) -> &Arc<AdminState> { &self.admin }

    /// 判定 + 落盘 + 推环一体（流式/非流通用）：返回原 verdict，写失败不改结论。
    /// `mode=Off` 时不记录（审计关闭零落盘）。
    pub async fn evaluate_and_record(
        &self,
        mode: AuditMode,
        tool_name: &str,
        args: &str,
        policy: &AuditPolicy,
        whitelist: &[String],
        protocol: Option<&str>,
    ) -> AuditVerdict {
        let verdict = evaluate_with_whitelist(mode, tool_name, args, policy, whitelist);
        if !matches!(mode, AuditMode::Off) {
            self.record_verdict(&verdict, tool_name, args, protocol)
                .await;
        }
        verdict
    }

    /// 单条 verdict 落盘 + 推环；返回写结果（deny/allow 语义见模块文档）。
    /// APP-4/D18：每条记录（含 `Block`/`Allow`）补参数脱敏摘要——复用审计面
    /// ten-form 摘要引擎 `sanitize_for_log`，摘要生成先于落盘（先脱敏后写）。
    pub async fn record_verdict(
        &self,
        verdict: &AuditVerdict,
        tool_name: &str,
        args: &str,
        protocol: Option<&str>,
    ) -> AuditWriteOutcome {
        let deny = !matches!(verdict, AuditVerdict::Allow);
        let args_summary = sanitize_for_log(args);
        let (kind, reason, summary) = match verdict {
            AuditVerdict::Allow => ("allow", String::new(), format!("allow {tool_name}")),
            AuditVerdict::Block { reason } => (
                "block",
                reason.clone(),
                format!("block {tool_name}: {reason}"),
            ),
            AuditVerdict::NeedApproval { reason, summary } => {
                ("approval", reason.clone(), summary.clone())
            }
        };
        self.admin
            .push_event("audit", &summary, protocol.map(str::to_string));
        let event = serde_json::json!({
            "ts": now_secs(),
            "kind": kind,
            "tool": tool_name,
            "reason": reason,
            "summary": summary,
            "args_summary": args_summary,
        });
        let logger = self.logger.clone();
        match tokio::task::spawn_blocking(move || logger.log_event(&event)).await {
            Ok(Ok(())) => AuditWriteOutcome::Written,
            Ok(Err(e)) => self.write_failed(deny, &e.to_string()),
            Err(e) => self.write_failed(deny, &format!("审计落盘任务异常: {e}")),
        }
    }

    fn write_failed(&self, deny: bool, err: &str) -> AuditWriteOutcome {
        if deny {
            tracing::error!("审计命中事件落盘失败，保持结论不降级: {err}");
            AuditWriteOutcome::DenyWriteFailed
        } else {
            tracing::error!("审计放行事件落盘失败，不阻断主请求: {err}");
            AuditWriteOutcome::AllowWriteFailed
        }
    }

    /// 单测专用：临时目录 + 隔离事件环的落盘单例（handler 测试构造 ctx 用）。
    #[cfg(test)]
    pub fn test_arc() -> Arc<AuditSink> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("veil-audit-sink-wired-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let admin = Arc::new(AdminState::new(
            dir.join("metrics.sqlite"),
            crate::service::metrics::PiiSamplerConfig {
                enabled: false,
                persist: false,
                hmac_key: None,
            },
        ));
        Arc::new(AuditSink::new(Arc::new(AuditLogger::new(dir)), admin))
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod sink_tests {
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
        // A1/1.1：verdict 命中与放行均经单例落盘，不再零调用死码。
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
        // A9/D8：deny 写失败保持结论（不降级）；allow 写失败不阻断主请求；
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
        // A9/9.2：故障注入覆盖 allow 与 deny 两路径及熔断计数。
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
        // A1/1.4：审计事件以 kind="audit" 推入 AdminState 事件环并可查询。
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
        // APP-4/D18：Block/Allow 两类记录均含参数脱敏摘要，无明文。
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
        // APP-4/D18：摘要不含明文；文件权限维持 0600。
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
}
