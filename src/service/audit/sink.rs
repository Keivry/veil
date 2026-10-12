//! 审计判定结果落盘接线（唯一生产写入口）。
//!
//! `AuditLogger::log_event` 含同步文件 IO 与 50ms 退避重试，不得在 async
//! 上下文直调；本模块以 `AuditSink` 单例（`AppState` 持有）承载：判定结果
//! 推 `AdminState` 事件环（`kind="audit"`）并经 `spawn_blocking` 写
//! `DATA_DIR/audit.log`。写失败按路径语义处置：deny 命中保持
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
    /// 每条记录（含 `Block`/`Allow`）补参数脱敏摘要——复用审计面
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
mod tests;
