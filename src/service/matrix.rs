//! §6.2 审批流转（Matrix pending/超时）+ §6.5 Matrix Bot。
//!
//! - 白名单 MXID 正则 + 发送者校验 + event id 精确匹配 + 幂等。
//! - 超时：凭据 300s / 审计 90s（`AUDIT_TIMEOUT` 禁 110-130 沿用 config 校验，默认拒绝）。
//! - `_ask` 返回 None 即 rejected 并清理；孤儿 pending 60s 清扫 tokio 任务。
//! - Bot 经 `reqwest` 长轮询 sync 实现，不引入 matrix-sdk 重依赖；五分支
//!   解锁/注册/哈希变更/凭据/审计 + ✅❎🔓 映射 + 摘要脱敏无明文。
//!
//! 接线：`AppState.approval` 持有本网关（白名单/`AUDIT_TIMEOUT` 来自 `Config`）；
//! 凭据 handler 经 `service::record_pending` 建单（submit + Bot best-effort 发送，
//! 立即返回 202）；问询经 `service::await_credential_approval`（300s）/
//! `await_audit_approval`（90s 口径）；`main` 启动 `spawn_sweeper` 常驻清扫。

use {
    crate::approval::{ApprovalGateway, ApprovalOutcome, PendingRecord},
    std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    },
};

/// 凭据审批超时（秒），与审计分表，固定 300s。
pub const CREDENTIAL_TIMEOUT_SECS: u64 = 300;
/// 审计审批超时（秒）。
pub const AUDIT_TIMEOUT_SECS: u64 = 90;
/// 孤儿 pending 清扫阈值（秒）。
pub const ORPHAN_SWEEP_SECS: u64 = 60;

/// Matrix 五分支业务（未知分支忽略并记审计）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixBranch {
    Unlock,
    Register,
    HashChange,
    Credential,
    Audit,
    Unknown,
}

impl MatrixBranch {
    pub fn from_reason(reason: &str) -> Self {
        let r = reason.to_lowercase();
        if r.contains("unlock") || r.contains("解锁") {
            Self::Unlock
        } else if r.contains("register") || r.contains("注册") {
            Self::Register
        } else if r.contains("hash") || r.contains("哈希") {
            Self::HashChange
        } else if r.contains("credential") || r.contains("凭据") {
            Self::Credential
        } else if r.contains("audit") || r.contains("审计") {
            Self::Audit
        } else {
            Self::Unknown
        }
    }

    pub fn status_emoji_approved(&self) -> &'static str { "✅" }

    pub fn status_emoji_rejected(&self) -> &'static str { "❎" }

    pub fn status_emoji_pending(&self) -> &'static str { "🔓" }

    pub fn is_known(&self) -> bool { !matches!(self, Self::Unknown) }
}

/// 白名单校验：MXID 正则全匹配；任一命中即放行。非法正则一律拒绝。
pub fn is_mxid_allowed(mxid: &str, whitelist: &[String]) -> bool {
    for pattern in whitelist {
        match regex::Regex::new(pattern) {
            Ok(re) => {
                if re.is_match(mxid) {
                    return true;
                }
            }
            Err(_) => continue,
        }
    }
    false
}

#[derive(Debug, Clone)]
struct PendingEntry {
    created: Instant,
    decided: Option<bool>,
}

/// Matrix 审批网关：async 问询 + sync trait 兼容。
#[derive(Debug)]
pub struct MatrixApproval {
    whitelist: Vec<String>,
    audit_timeout: Duration,
    credential_timeout: Duration,
    pending: tokio::sync::Mutex<HashMap<String, PendingEntry>>,
}

impl MatrixApproval {
    pub fn new(whitelist: Vec<String>, audit_timeout_secs: u64) -> Self {
        Self {
            whitelist,
            audit_timeout: Duration::from_secs(audit_timeout_secs.max(1)),
            credential_timeout: Duration::from_secs(CREDENTIAL_TIMEOUT_SECS),
            pending: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn audit_timeout(&self) -> Duration { self.audit_timeout }

    pub fn credential_timeout(&self) -> Duration { self.credential_timeout }

    /// 登记一个待审批 event；已存在返回 false（幂等建单）。
    pub async fn submit(&self, event_id: &str) -> bool {
        let mut guard = self.pending.lock().await;
        if guard.contains_key(event_id) {
            return false;
        }
        guard.insert(
            event_id.to_string(),
            PendingEntry {
                created: Instant::now(),
                decided: None,
            },
        );
        true
    }

    /// reaction 落定：白名单 + event id 精确匹配 + 幂等。
    pub async fn resolve(&self, event_id: &str, sender: &str, approved: bool) -> ResolveOutcome {
        if !is_mxid_allowed(sender, &self.whitelist) {
            return ResolveOutcome::Ignored("发送者不在白名单");
        }
        let mut guard = self.pending.lock().await;
        match guard.get_mut(event_id) {
            None => ResolveOutcome::Ignored("event id 无精确匹配"),
            Some(entry) => {
                if entry.decided.is_some() {
                    return ResolveOutcome::Duplicate;
                }
                entry.decided = Some(approved);
                ResolveOutcome::Applied(approved)
            }
        }
    }

    /// 等待审批：超时/发送失败返回 None（调用方 MUST 按 rejected 处理并清理）。
    pub async fn ask(&self, event_id: &str, timeout: Duration) -> Option<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let guard = self.pending.lock().await;
                if let Some(entry) = guard.get(event_id)
                    && let Some(decided) = entry.decided
                {
                    return Some(decided);
                }
            }
            if Instant::now() >= deadline {
                self.remove(event_id).await;
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// 审计便捷问询（90s 超时口径）。
    pub async fn ask_audit(&self, event_id: &str) -> Option<bool> {
        let timeout = self.audit_timeout;
        self.ask(event_id, timeout).await
    }

    async fn remove(&self, event_id: &str) { self.pending.lock().await.remove(event_id); }

    /// 清扫孤儿 pending（超 60s 未决）；返回清理条数。
    pub async fn sweep_orphans(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let before = guard.len();
        guard.retain(|_, e| {
            e.decided.is_some() || e.created.elapsed() < Duration::from_secs(ORPHAN_SWEEP_SECS)
        });
        before - guard.len()
    }

    pub async fn pending_len(&self) -> usize { self.pending.lock().await.len() }

    /// 启动 60s 间隔清扫 tokio 任务；返回句柄（调用方持有，drop 即停）。
    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(ORPHAN_SWEEP_SECS));
            loop {
                ticker.tick().await;
                me.sweep_orphans().await;
            }
        })
    }
}

impl ApprovalGateway for MatrixApproval {
    fn request_approval(&self, _record: &PendingRecord) -> ApprovalOutcome {
        ApprovalOutcome::Pending
    }
}

/// reaction 落定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    Applied(bool),
    Ignored(&'static str),
    Duplicate,
}

/// Matrix Bot（reqwest 长轮询 sync，不引入 matrix-sdk）。
#[derive(Debug, Clone)]
pub struct MatrixBot {
    homeserver: String,
    room_id: String,
    access_token: String,
    client: reqwest::Client,
}

impl MatrixBot {
    pub fn new(homeserver: String, room_id: String, access_token: String) -> Self {
        Self {
            homeserver,
            room_id,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    fn auth_header(&self) -> String { format!("Bearer {}", self.access_token) }

    /// 审批消息正文：分支 + 状态标识 + 脱敏摘要（无明文）。
    pub fn format_approval(
        &self,
        branch: MatrixBranch,
        approved: Option<bool>,
        summary: &str,
    ) -> String {
        let mark = match approved {
            Some(true) => branch.status_emoji_approved(),
            Some(false) => branch.status_emoji_rejected(),
            None => branch.status_emoji_pending(),
        };
        let name = match branch {
            MatrixBranch::Unlock => "解锁",
            MatrixBranch::Register => "注册",
            MatrixBranch::HashChange => "哈希变更",
            MatrixBranch::Credential => "凭据",
            MatrixBranch::Audit => "审计",
            MatrixBranch::Unknown => "未知分支（已忽略）",
        };
        let clean = crate::service::audit::sanitize_for_log(summary);
        format!("{mark} [{name}] {room} :: {clean}", room = self.room_id)
    }

    /// 发送房间文本消息（发送失败返回 Err，调用方按审批超时路径默认拒绝）。
    pub async fn send_text(&self, text: &str) -> anyhow::Result<String> {
        let txn = format!("{}", chrono_txn());
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{txn}",
            self.homeserver.trim_end_matches('/'),
            url_encode(&self.room_id)
        );
        let resp = self
            .client
            .put(&url)
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!({"msgtype": "m.text", "body": text}))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Matrix 发送失败: {e}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("Matrix 发送失败: {}", resp.status());
        }
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
        Ok(body
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// 长轮询 sync 一次（timeout 30s），返回原始 JSON；调用方循环即得持续同步。
    pub async fn poll_sync(&self, since: Option<&str>) -> anyhow::Result<serde_json::Value> {
        let mut url = format!(
            "{}/_matrix/client/v3/sync?timeout=30000",
            self.homeserver.trim_end_matches('/')
        );
        if let Some(token) = since {
            url.push_str(&format!("&since={}", url_encode(token)));
        }
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Matrix sync 失败: {e}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("Matrix sync 失败: {}", resp.status());
        }
        resp.json()
            .await
            .map_err(|e| anyhow::anyhow!("Matrix sync 解析失败: {e}"))
    }
}

fn chrono_txn() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b':' | b'!') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval() -> MatrixApproval {
        MatrixApproval::new(
            vec!["^@admin:example\\.com$".to_string()],
            AUDIT_TIMEOUT_SECS,
        )
    }

    #[test]
    fn 白名单mxid正则与发送者校验() {
        let wl = vec!["^@admin:example\\.com$".to_string()];
        assert!(is_mxid_allowed("@admin:example.com", &wl));
        assert!(!is_mxid_allowed("@ghost:example.com", &wl));
        assert!(!is_mxid_allowed("@admin:example.com.evil.com", &wl));
        assert!(!is_mxid_allowed(
            "@admin:example.com",
            &["([invalid".to_string()]
        ));
    }

    #[test]
    fn 五分支映射与标识() {
        assert_eq!(MatrixBranch::from_reason("unlock"), MatrixBranch::Unlock);
        assert_eq!(
            MatrixBranch::from_reason("注册审批"),
            MatrixBranch::Register
        );
        assert_eq!(
            MatrixBranch::from_reason("hash-change"),
            MatrixBranch::HashChange
        );
        assert_eq!(
            MatrixBranch::from_reason("凭据下发"),
            MatrixBranch::Credential
        );
        assert_eq!(MatrixBranch::from_reason("audit-hold"), MatrixBranch::Audit);
        assert_eq!(MatrixBranch::from_reason("加急转交"), MatrixBranch::Unknown);
        assert!(!MatrixBranch::Unknown.is_known());
        assert_eq!(MatrixBranch::Audit.status_emoji_approved(), "✅");
        assert_eq!(MatrixBranch::Audit.status_emoji_rejected(), "❎");
        assert_eq!(MatrixBranch::Audit.status_emoji_pending(), "🔓");
    }

    #[test]
    fn 审批摘要无明文() {
        let bot = MatrixBot::new(
            "https://m.example.com".to_string(),
            "!r:example.com".to_string(),
            "tok".to_string(),
        );
        let msg = bot.format_approval(MatrixBranch::Audit, None, r#"rm -rf / password=hunter2"#);
        assert!(msg.contains("🔓"), "{msg}");
        assert!(!msg.contains("hunter2"), "{msg}");
    }

    #[tokio::test]
    async fn 审批通过拒绝幂等与失配忽略() {
        let gw = approval();
        assert!(gw.submit("$ev1").await);
        assert!(!gw.submit("$ev1").await);
        assert_eq!(
            gw.resolve("$ev1", "@ghost:example.com", true).await,
            ResolveOutcome::Ignored("发送者不在白名单")
        );
        assert_eq!(
            gw.resolve("$nope", "@admin:example.com", true).await,
            ResolveOutcome::Ignored("event id 无精确匹配")
        );
        assert_eq!(
            gw.resolve("$ev1", "@admin:example.com", true).await,
            ResolveOutcome::Applied(true)
        );
        assert_eq!(
            gw.resolve("$ev1", "@admin:example.com", false).await,
            ResolveOutcome::Duplicate
        );
        assert_eq!(gw.ask("$ev1", Duration::from_secs(1)).await, Some(true));
    }

    #[tokio::test]
    async fn 超时返回none并清理默认拒绝() {
        let gw = approval();
        gw.submit("$slow").await;
        let out = gw.ask("$slow", Duration::from_millis(120)).await;
        assert_eq!(out, None);
        assert_eq!(gw.pending_len().await, 0);
    }

    #[tokio::test]
    async fn 孤儿pending60s清扫回收() {
        let gw = approval();
        gw.submit("$orphan").await;
        {
            let mut guard = gw.pending.lock().await;
            if let Some(e) = guard.get_mut("$orphan") {
                e.created = Instant::now() - Duration::from_secs(ORPHAN_SWEEP_SECS + 1);
            }
        }
        assert_eq!(gw.sweep_orphans().await, 1);
        assert_eq!(gw.pending_len().await, 0);
    }

    #[test]
    fn 超时口径凭据300s审计90s() {
        assert_eq!(CREDENTIAL_TIMEOUT_SECS, 300);
        assert_eq!(AUDIT_TIMEOUT_SECS, 90);
        let gw = approval();
        assert_eq!(gw.audit_timeout(), Duration::from_secs(90));
        assert_eq!(gw.credential_timeout(), Duration::from_secs(300));
    }
}
