//! §6.2 审批流转（Matrix pending/超时）+ §6.5 Matrix Bot。
//!
//! - 白名单 MXID 精确匹配 + 发送者校验 + event id 精确匹配 + 幂等。
//! - 超时：凭据 300s / 审计 90s（`AUDIT_TIMEOUT` 禁 110-130 沿用 config 校验，默认拒绝）。
//! - `_ask` 返回 None 即 rejected 并清理；孤儿 pending 60s 清扫 tokio 任务。
//! - Bot 经 `reqwest` 长轮询 sync 实现，不引入 matrix-sdk 重依赖；五分支
//!   解锁/注册/哈希变更/凭据/审计 + ✅❎🔓 映射 + 摘要脱敏无明文。
//!
//! 接线：`AppState.approval` 持有本网关（白名单/`AUDIT_TIMEOUT` 来自 `Config`）；
//! 凭据 handler 经 `service::record_pending` 建单（submit + Bot best-effort 发送，
//! 立即返回 202）；问询经 `service::await_credential_approval`（300s）/
//! `await_audit_approval`（90s 口径）；`main` 启动 `spawn_sweeper` 常驻清扫 +
//! `MatrixBot::spawn_sync_loop` 常驻同步（since 持久化 + 指数退避 + 启动时间戳过滤）。

use {
    crate::approval::{ApprovalGateway, ApprovalOutcome, PendingRecord},
    std::{
        collections::HashMap,
        path::Path,
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

/// 白名单校验：MXID 精确成员匹配；任一相等即放行。
/// 非法格式成员在启动期由 `Config::load_from` 拒绝，此处仅做相等比较。
pub fn is_mxid_allowed(mxid: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|member| member == mxid)
}

/// 启动期 MXID 格式显式门禁：须形如 `@user:server` 且不含空白。
/// `Config::load_from` 已做同等校验，此函数供 Matrix 链路显式复核与单测。
pub fn validate_whitelist_mxids(whitelist: &[String]) -> Result<(), String> {
    for member in whitelist {
        if !is_valid_mxid(member) {
            return Err(format!(
                "APPROVAL_WHITELIST 成员格式非法: {member:?}（须形如 @user:server）"
            ));
        }
    }
    Ok(())
}

fn is_valid_mxid(s: &str) -> bool {
    let rest = s.strip_prefix('@').unwrap_or("");
    let mut parts = rest.split(':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(user), Some(server), None) => {
            !user.is_empty() && !server.is_empty() && !s.chars().any(|c| c.is_whitespace())
        }
        _ => false,
    }
}

/// reaction 表情常量（对标 Python `_sse.py`）。
pub const REACTION_APPROVE: &str = "✅";
/// reaction 表情常量（对标 Python `_sse.py`）。
pub const REACTION_REJECT: &str = "❎";
/// reaction 表情常量（注册场景自动放行，对标 Python `_sse.py`）。
pub const REACTION_AUTO_UNLOCK: &str = "🔓";
/// 文本指令：锁定（对标 Python `CMD_LOCK`）。
pub const CMD_LOCK: &str = "lock proxy";
/// 文本指令：状态（对标 Python `CMD_STATUS`）。
pub const CMD_STATUS: &str = "status";
/// 文本指令：遗忘（对标 Python `CMD_FORGET`）。
pub const CMD_FORGET: &str = "forget secrets";
/// sync 指数退避上限（秒，对标 Python `MAX_RETRY_DELAY`）。
pub const SYNC_MAX_BACKOFF_SECS: u64 = 60;
/// sync 长轮询超时（毫秒，对标 Python `SYNC_TIMEOUT`）。
pub const SYNC_TIMEOUT_MS: u64 = 30000;

#[derive(Debug, Clone)]
struct PendingEntry {
    created: Instant,
    decided: Option<bool>,
    branch: MatrixBranch,
}

/// reaction 落定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    Applied(bool),
    Ignored(&'static str),
    Duplicate,
}

/// reaction 五分支落定（含自动放行语义）：`🔓` 仅注册分支视为批准。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionOutcome {
    Applied { approved: bool, auto: bool },
    Ignored(&'static str),
    Duplicate,
}

/// 文本指令三元组（对标 Python `on_text`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextCommand {
    Lock,
    Status,
    Forget,
    Unknown,
}

/// 从 sync 解析出的 reaction 输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionInput {
    pub target_event_id: String,
    pub key: String,
    pub sender: String,
    pub room_id: String,
    pub server_ts_ms: u128,
}

/// 从 sync 解析出的文本输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextInput {
    pub body: String,
    pub sender: String,
    pub room_id: String,
    pub server_ts_ms: u128,
}

/// 文本指令解析：兼容 `lock proxy` 全形与 `lock` 短形。
pub fn parse_text_command(body: &str) -> TextCommand {
    let normalized = body.trim().to_lowercase();
    if normalized == CMD_LOCK || normalized == "lock" {
        TextCommand::Lock
    } else if normalized == CMD_STATUS || normalized == "status" {
        TextCommand::Status
    } else if normalized == CMD_FORGET || normalized == "forget" {
        TextCommand::Forget
    } else {
        TextCommand::Unknown
    }
}

/// reaction 表情到决议的分支映射：未知表情返回 None（调用方 no-op）。
pub fn reaction_to_decision(branch: MatrixBranch, key: &str) -> Option<(bool, bool)> {
    match branch {
        MatrixBranch::Unlock => match key {
            k if k == REACTION_APPROVE => Some((true, false)),
            k if k == REACTION_REJECT => Some((false, false)),
            _ => None,
        },
        MatrixBranch::Register | MatrixBranch::HashChange => match key {
            k if k == REACTION_AUTO_UNLOCK => Some((true, true)),
            k if k == REACTION_APPROVE => Some((true, false)),
            k if k == REACTION_REJECT => Some((false, false)),
            _ => None,
        },
        MatrixBranch::Credential | MatrixBranch::Audit => match key {
            k if k == REACTION_APPROVE => Some((true, false)),
            k if k == REACTION_REJECT => Some((false, false)),
            _ => None,
        },
        MatrixBranch::Unknown => None,
    }
}

/// sync 退避：失败次数指数增长，封顶 60s（纯函数，可单测）。
pub fn sync_backoff_secs(failures: u32) -> u64 {
    1u64.checked_shl(failures.min(10))
        .unwrap_or(u64::MAX)
        .clamp(1, SYNC_MAX_BACKOFF_SECS)
}

/// since token 读取：缺失/空/失败返回 None（调用方全量同步）。
pub fn load_since_token(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// since token 持久化：写失败返回 false（调用方降级为内存 token）。
pub fn save_since_token(path: &Path, token: &str) -> bool {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        tracing::warn!("sync token 目录创建失败 {}: {err}", parent.display());
        return false;
    }
    if let Err(err) = std::fs::write(path, token) {
        tracing::warn!("sync token 持久化失败 {}: {err}", path.display());
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("sync token chmod 0600 失败 {}: {err}", path.display());
        }
    }
    true
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
        self.submit_branch(event_id, MatrixBranch::Unknown).await
    }

    /// 按分支登记待审批 event；四段日志之“已发送”由调用方在发送后记录。
    pub async fn submit_branch(&self, event_id: &str, branch: MatrixBranch) -> bool {
        let mut guard = self.pending.lock().await;
        if guard.contains_key(event_id) {
            return false;
        }
        guard.insert(
            event_id.to_string(),
            PendingEntry {
                created: Instant::now(),
                decided: None,
                branch,
            },
        );
        true
    }

    async fn pending_branch(&self, event_id: &str) -> Option<MatrixBranch> {
        self.pending.lock().await.get(event_id).map(|e| e.branch)
    }

    /// reaction 落定：白名单 + event id 精确匹配 + 幂等。
    pub async fn resolve(&self, event_id: &str, sender: &str, approved: bool) -> ResolveOutcome {
        if !is_mxid_allowed(sender, &self.whitelist) {
            tracing::warn!("审批 reaction 被忽略: 发送者 {sender} 不在白名单");
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
                tracing::info!(
                    "审批结果: event {event_id} 发送者 {sender} 决议 {}",
                    if approved { "批准" } else { "拒绝" }
                );
                ResolveOutcome::Applied(approved)
            }
        }
    }

    /// `on_reaction` 五分支入口：房间/自反应/启动时间戳/表情/分支/白名单逐层过滤，
    /// 失配一律 no-op；命中后经 `resolve` 落定。
    pub async fn on_reaction(
        &self,
        input: &ReactionInput,
        own_user_id: &str,
        expected_room: &str,
        start_ts_ms: u128,
    ) -> ReactionOutcome {
        if input.room_id != expected_room {
            return ReactionOutcome::Ignored("非目标房间");
        }
        if input.server_ts_ms < start_ts_ms {
            return ReactionOutcome::Ignored("历史事件");
        }
        if !own_user_id.is_empty() && input.sender == own_user_id {
            return ReactionOutcome::Ignored("自反应");
        }
        if input.target_event_id.is_empty() {
            return ReactionOutcome::Ignored("event id 无精确匹配");
        }
        let branch = self.pending_branch(&input.target_event_id).await;
        let Some(branch) = branch else {
            return ReactionOutcome::Ignored("event id 无精确匹配");
        };
        if !branch.is_known() {
            return ReactionOutcome::Ignored("未知分支");
        }
        let Some((approved, auto)) = reaction_to_decision(branch, &input.key) else {
            return ReactionOutcome::Ignored("未知表情");
        };
        if !is_mxid_allowed(&input.sender, &self.whitelist) {
            tracing::warn!("审批 reaction 被忽略: 发送者 {} 不在白名单", input.sender);
            return ReactionOutcome::Ignored("发送者不在白名单");
        }
        match self
            .resolve(&input.target_event_id, &input.sender, approved)
            .await
        {
            ResolveOutcome::Applied(_) => ReactionOutcome::Applied { approved, auto },
            ResolveOutcome::Duplicate => ReactionOutcome::Duplicate,
            ResolveOutcome::Ignored(reason) => ReactionOutcome::Ignored(reason),
        }
    }

    /// `lock` 指令：未决单全部按拒绝落定并返回落定条数。
    pub async fn lock_reject_all(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let mut count = 0;
        for entry in guard.values_mut() {
            if entry.decided.is_none() {
                entry.decided = Some(false);
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!("审批锁定: {count} 单已按拒绝落定");
        }
        count
    }

    /// `lock` 全清：全部未决按拒绝落定后清空 pending 表（对标 Python `pending_requests.clear()`）。
    /// 网关接线人注意：`lock` 还须清理口令缓存 + KeePass 会话（`_kp=None` 对等）+
    /// PII scope 缓存，见 [`MatrixBot::handle_text_command_full`] 的 BREAKING 说明。
    pub async fn lock_clear_all(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let mut count = 0;
        for entry in guard.values_mut() {
            if entry.decided.is_none() {
                entry.decided = Some(false);
                count += 1;
            }
        }
        let total = guard.len();
        guard.clear();
        if total > 0 {
            tracing::info!("审批锁定全清: {total} 单清空（含已决），其中 {count} 未决按拒绝落定");
        }
        total
    }

    /// `forget` 指令：清理已决单并返回清理条数。
    pub async fn forget_decided(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let before = guard.len();
        guard.retain(|_, e| e.decided.is_none());
        let cleared = before - guard.len();
        if cleared > 0 {
            tracing::info!("审批遗忘: 已清理 {cleared} 单");
        }
        cleared
    }

    /// 等待审批：超时/发送失败返回 None（调用方 MUST 按 rejected 处理并清理）。
    /// 四段日志之“等待中/超时/结果”在此记录，“已发送”由建单调用方记录。
    pub async fn ask(&self, event_id: &str, timeout: Duration) -> Option<bool> {
        tracing::info!("审批等待中: event {event_id} 超时 {}s", timeout.as_secs());
        let deadline = Instant::now() + timeout;
        loop {
            {
                let guard = self.pending.lock().await;
                if let Some(entry) = guard.get(event_id)
                    && let Some(decided) = entry.decided
                {
                    tracing::info!(
                        "审批结果: event {event_id} 决议 {}",
                        if decided { "批准" } else { "拒绝" }
                    );
                    return Some(decided);
                }
            }
            if Instant::now() >= deadline {
                tracing::warn!(
                    "审批超时: event {event_id} 超时 {}s，按拒绝处理",
                    timeout.as_secs()
                );
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

    /// 待审批 event 列表（只读快照，凭据阻塞双模的测试/运维可观测用）。
    pub async fn pending_event_ids(&self) -> Vec<String> {
        self.pending.lock().await.keys().cloned().collect()
    }

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
        Self::with_client(homeserver, room_id, access_token, reqwest::Client::new())
    }

    pub fn with_client(
        homeserver: String,
        room_id: String,
        access_token: String,
        client: reqwest::Client,
    ) -> Self {
        Self {
            homeserver,
            room_id,
            access_token,
            client,
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
            "{}/_matrix/client/v3/sync?timeout={}",
            self.homeserver.trim_end_matches('/'),
            SYNC_TIMEOUT_MS,
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

    /// `GET /whoami` 查询 Bot 自身 MXID（自反应过滤用）；失败返回空串（过滤降级）。
    pub async fn whoami(&self) -> String {
        let url = format!(
            "{}/_matrix/client/v3/account/whoami",
            self.homeserver.trim_end_matches('/')
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await;
        let Ok(resp) = resp else { return String::new() };
        if !resp.status().is_success() {
            return String::new();
        }
        resp.json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| {
                v.get("user_id")
                    .and_then(|u| u.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default()
    }

    /// 文本指令执行（Python 口径全量版）：`lock`→`🔒 Proxy 已锁定`、
    /// `status`→`Proxy: {✅ 已解锁/🔒 未解锁} | 待审批: {n} | LLM secrets: {n}`、
    /// `forget`→`🧹 已清除 {n} 个 LLM 密码映射`。
    ///
    /// BREAKING 说明（注册/吊销/哈希变更审批链）：本库只做审批单流转；
    /// 注册-批准链的实际生效（`set_enabled(true)` / 吊销落盘）由网关侧在收到
    /// `ReactionOutcome::Applied` 后执行——若网关直接生效而不经审批，即为相对原仓的
    /// BREAKING（直接生效语义），须在发布说明中声明并给出风险说明。
    /// 网关接线人注意：
    /// - `lock` 除本函数落定外，还须清口令缓存 + KeePass 会话 + PII scope；
    /// - `status` 的 `unlocked/secrets` 由网关侧传入；
    /// - `forget` 的 `n` 为网关侧实际清除的 token 映射数（本函数只清审批单）。
    pub async fn handle_text_command_full(
        approval: &MatrixApproval,
        command: TextCommand,
        unlocked: bool,
        secrets: usize,
    ) -> Option<String> {
        match command {
            TextCommand::Lock => {
                let count = approval.lock_reject_all().await;
                approval.lock_clear_all().await;
                Some(format!("🔒 Proxy 已锁定（未决 {count} 单已按拒绝落定）"))
            }
            TextCommand::Status => {
                let pending = approval.pending_len().await;
                let s = if unlocked {
                    "✅ 已解锁"
                } else {
                    "🔒 未解锁"
                };
                Some(format!(
                    "Proxy: {s} | 待审批: {pending} | LLM secrets: {secrets}"
                ))
            }
            TextCommand::Forget => {
                let cleared = approval.forget_decided().await;
                Some(format!(
                    "🧹 已清除 {cleared} 个已决审批单（网关侧另清 {secrets} 个口令映射）"
                ))
            }
            TextCommand::Unknown => None,
        }
    }

    /// 文本指令执行（兼容版）：签名不变，内部走全量版（`unlocked=true/secrets=0`）。
    pub async fn handle_text_command(
        approval: &MatrixApproval,
        command: TextCommand,
    ) -> Option<String> {
        Self::handle_text_command_full(approval, command, true, 0).await
    }

    /// 常驻 sync 循环：since 持久化 + 指数退避 + 启动时间戳过滤。
    /// reaction 经 `MatrixApproval::on_reaction` 落定，文本指令经
    /// `handle_text_command` 执行；发送失败走审批超时默认拒绝路径。
    pub fn spawn_sync_loop(
        self,
        approval: Arc<MatrixApproval>,
        token_file: std::path::PathBuf,
        start_ts_ms: u128,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let own_user_id = self.whoami().await;
            if own_user_id.is_empty() {
                tracing::warn!("Matrix whoami 失败，自反应过滤降级为空");
            }
            let expected_room = self.room_id.clone();
            let mut since = load_since_token(&token_file);
            if since.is_some() {
                tracing::info!("Matrix sync 从持久化 token 恢复");
            }
            let mut failures: u32 = 0;
            loop {
                match self.poll_sync(since.as_deref()).await {
                    Ok(sync) => {
                        failures = 0;
                        if let Some(next) = sync
                            .get("next_batch")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                        {
                            since = Some(next.clone());
                            if !save_since_token(&token_file, &next) {
                                tracing::debug!("sync token 仅保留内存副本");
                            }
                        }
                        let (reactions, texts) = Self::parse_sync_events(&sync, &expected_room);
                        for input in reactions {
                            match approval
                                .on_reaction(&input, &own_user_id, &expected_room, start_ts_ms)
                                .await
                            {
                                ReactionOutcome::Applied { approved, auto } => {
                                    let verdict = if auto {
                                        "自动放行"
                                    } else if approved {
                                        "批准"
                                    } else {
                                        "拒绝"
                                    };
                                    tracing::info!(
                                        "审批 reaction 落定: {} {} → {verdict}",
                                        input.sender,
                                        input.target_event_id
                                    );
                                    let reply = format!(
                                        "{} 审批: {} → {verdict}",
                                        input.key, input.target_event_id
                                    );
                                    if let Err(err) = self.send_text(&reply).await {
                                        tracing::debug!("审批回执发送失败: {err:#}");
                                    }
                                }
                                ReactionOutcome::Ignored(reason) => {
                                    tracing::debug!(
                                        "审批 reaction 忽略({reason}): {} → {}",
                                        input.sender,
                                        input.target_event_id
                                    );
                                }
                                ReactionOutcome::Duplicate => {
                                    tracing::debug!(
                                        "审批 reaction 重复: {} → {}",
                                        input.sender,
                                        input.target_event_id
                                    );
                                }
                            }
                        }
                        for text in texts {
                            if text.room_id != expected_room {
                                continue;
                            }
                            if text.server_ts_ms < start_ts_ms {
                                continue;
                            }
                            if !own_user_id.is_empty() && text.sender == own_user_id {
                                continue;
                            }
                            let command = parse_text_command(&text.body);
                            if let Some(reply) = Self::handle_text_command(&approval, command).await
                                && let Err(err) = self.send_text(&reply).await
                            {
                                tracing::debug!("指令回执发送失败: {err:#}");
                            }
                        }
                    }
                    Err(err) => {
                        let delay = sync_backoff_secs(failures);
                        tracing::warn!("Matrix sync 失败，{delay}s 后重试: {err:#}");
                        failures = failures.saturating_add(1);
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    }
                }
            }
        })
    }

    /// sync 响应解析：提 reaction 与文本事件（纯函数，可单测）。
    /// 仅解析目标房间时间线；未知形态一律跳过（no-op）。
    pub fn parse_sync_events(
        sync: &serde_json::Value,
        expected_room: &str,
    ) -> (Vec<ReactionInput>, Vec<TextInput>) {
        let mut reactions = Vec::new();
        let mut texts = Vec::new();
        let Some(join) = sync.pointer("/rooms/join") else {
            return (reactions, texts);
        };
        let Some(rooms) = join.as_object() else {
            return (reactions, texts);
        };
        for (room_id, room) in rooms {
            if room_id != expected_room {
                continue;
            }
            let events = room.pointer("/timeline/events").and_then(|v| v.as_array());
            let Some(events) = events else { continue };
            for event in events {
                let kind = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let sender = event.get("sender").and_then(|v| v.as_str()).unwrap_or("");
                let server_ts = event
                    .get("origin_server_ts")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u128;
                if kind == "m.reaction" {
                    let relates = event.pointer("/content/m.relates_to");
                    let target = relates
                        .and_then(|r| r.get("event_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let key = relates
                        .and_then(|r| r.get("key"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if target.is_empty() || key.is_empty() {
                        continue;
                    }
                    if ![REACTION_APPROVE, REACTION_REJECT, REACTION_AUTO_UNLOCK].contains(&key) {
                        continue;
                    }
                    reactions.push(ReactionInput {
                        target_event_id: target.to_string(),
                        key: key.to_string(),
                        sender: sender.to_string(),
                        room_id: room_id.clone(),
                        server_ts_ms: server_ts,
                    });
                } else if kind == "m.room.message" {
                    let msgtype = event
                        .pointer("/content/msgtype")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if msgtype != "m.text" && msgtype != "m.notice" {
                        continue;
                    }
                    let body = event
                        .pointer("/content/body")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if body.trim().is_empty() {
                        continue;
                    }
                    texts.push(TextInput {
                        body: body.to_string(),
                        sender: sender.to_string(),
                        room_id: room_id.clone(),
                        server_ts_ms: server_ts,
                    });
                }
            }
        }
        (reactions, texts)
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
        MatrixApproval::new(vec!["@admin:example.com".to_string()], AUDIT_TIMEOUT_SECS)
    }

    #[test]
    fn 白名单精确匹配与伪造成员拒绝() {
        let wl = vec!["@admin:example.com".to_string()];
        assert!(is_mxid_allowed("@admin:example.com", &wl));
        assert!(!is_mxid_allowed("@ghost:example.com", &wl));
        assert!(!is_mxid_allowed("@admin:example.com.evil.com", &wl));
        assert!(!is_mxid_allowed("evil-@admin:example.comX", &wl));
        assert!(!is_mxid_allowed("@ADMIN:example.com", &wl));
        assert!(!is_mxid_allowed("@admin:example.com ", &wl));
    }

    #[test]
    fn 非法白名单成员启动门禁拒绝() {
        assert!(validate_whitelist_mxids(&["@admin:example.com".to_string()]).is_ok());
        assert!(validate_whitelist_mxids(&["@keivry@matrix.example".to_string()]).is_err());
        assert!(validate_whitelist_mxids(&["admin:example.com".to_string()]).is_err());
        assert!(validate_whitelist_mxids(&["@a: b".to_string()]).is_err());
    }

    #[test]
    fn 退避指数增长封顶60s() {
        assert_eq!(sync_backoff_secs(0), 1);
        assert_eq!(sync_backoff_secs(1), 2);
        assert_eq!(sync_backoff_secs(5), 32);
        assert_eq!(sync_backoff_secs(6), 60);
        assert_eq!(sync_backoff_secs(100), 60);
    }

    #[test]
    fn token持久化读写往返() {
        let dir = std::env::temp_dir().join(format!(
            "veil-sync-token-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let path = dir.join("sync_token");
        assert_eq!(load_since_token(&path), None);
        assert!(save_since_token(&path, "s123_456"));
        assert_eq!(load_since_token(&path).as_deref(), Some("s123_456"));
        assert!(save_since_token(&path, "s789_000"));
        assert_eq!(load_since_token(&path).as_deref(), Some("s789_000"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn 未知表情与未知分支映射noop() {
        assert_eq!(reaction_to_decision(MatrixBranch::Credential, "👍"), None);
        assert_eq!(reaction_to_decision(MatrixBranch::Unknown, "✅"), None);
        assert_eq!(reaction_to_decision(MatrixBranch::Credential, "🔓"), None);
        assert_eq!(
            reaction_to_decision(MatrixBranch::Register, "🔓"),
            Some((true, true))
        );
        assert_eq!(
            reaction_to_decision(MatrixBranch::Audit, "✅"),
            Some((true, false))
        );
        assert_eq!(
            reaction_to_decision(MatrixBranch::Audit, "❎"),
            Some((false, false))
        );
    }

    #[test]
    fn 文本三指令解析() {
        assert_eq!(parse_text_command("lock proxy"), TextCommand::Lock);
        assert_eq!(parse_text_command("  LOCK  "), TextCommand::Lock);
        assert_eq!(parse_text_command("status"), TextCommand::Status);
        assert_eq!(parse_text_command("forget secrets"), TextCommand::Forget);
        assert_eq!(parse_text_command("hello"), TextCommand::Unknown);
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

    #[tokio::test]
    async fn 未知事件与失配分支noop不改变状态() {
        let gw = approval();
        gw.submit_branch("$known", MatrixBranch::Credential).await;
        let unknown = ReactionInput {
            target_event_id: "$missing".to_string(),
            key: "✅".to_string(),
            sender: "@admin:example.com".to_string(),
            room_id: "!r:example.com".to_string(),
            server_ts_ms: 2000,
        };
        assert_eq!(
            gw.on_reaction(&unknown, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Ignored("event id 无精确匹配")
        );
        let wrong_room = ReactionInput {
            room_id: "!other:example.com".to_string(),
            ..unknown.clone()
        };
        assert_eq!(
            gw.on_reaction(&wrong_room, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Ignored("非目标房间")
        );
        let historic = ReactionInput {
            server_ts_ms: 500,
            ..unknown.clone()
        };
        assert_eq!(
            gw.on_reaction(&historic, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Ignored("历史事件")
        );
        let not_member = ReactionInput {
            target_event_id: "$known".to_string(),
            sender: "@ghost:example.com".to_string(),
            server_ts_ms: 2000,
            ..unknown.clone()
        };
        assert_eq!(
            gw.on_reaction(&not_member, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Ignored("发送者不在白名单")
        );
        assert_eq!(gw.pending_len().await, 1);
    }

    #[tokio::test]
    async fn 五分支reaction落定与三指令回显() {
        let gw = approval();
        gw.submit_branch("$cred", MatrixBranch::Credential).await;
        let approve = ReactionInput {
            target_event_id: "$cred".to_string(),
            key: "✅".to_string(),
            sender: "@admin:example.com".to_string(),
            room_id: "!r:example.com".to_string(),
            server_ts_ms: 2000,
        };
        assert_eq!(
            gw.on_reaction(&approve, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Applied {
                approved: true,
                auto: false
            }
        );
        assert_eq!(
            gw.on_reaction(&approve, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Duplicate
        );
        gw.submit_branch("$reg", MatrixBranch::Register).await;
        let auto = ReactionInput {
            target_event_id: "$reg".to_string(),
            key: "🔓".to_string(),
            ..approve.clone()
        };
        assert_eq!(
            gw.on_reaction(&auto, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Applied {
                approved: true,
                auto: true
            }
        );
        let self_echo = ReactionInput {
            sender: "@bot:example.com".to_string(),
            ..approve.clone()
        };
        assert_eq!(
            gw.on_reaction(&self_echo, "@bot:example.com", "!r:example.com", 1000)
                .await,
            ReactionOutcome::Ignored("自反应")
        );
        let locked = gw.lock_reject_all().await;
        assert_eq!(locked, 0);
        gw.submit_branch("$open", MatrixBranch::Audit).await;
        assert_eq!(gw.lock_reject_all().await, 1);
        assert_eq!(
            gw.ask("$open", Duration::from_millis(10)).await,
            Some(false)
        );
        let status = MatrixBot::handle_text_command(&gw, TextCommand::Status).await;
        assert!(status.is_some_and(|s| s.contains("待审批") && s.contains("LLM secrets")));
        let forget = MatrixBot::handle_text_command(&gw, TextCommand::Forget).await;
        assert!(forget.is_some_and(|s| s.contains("已清除")));
        assert_eq!(gw.pending_len().await, 0);
    }

    #[tokio::test]
    async fn lock全清无残留且文案对齐原仓() {
        let gw = approval();
        gw.submit_branch("$a", MatrixBranch::Credential).await;
        gw.submit_branch("$b", MatrixBranch::Audit).await;
        assert_eq!(
            gw.resolve("$a", "@admin:example.com", true).await,
            ResolveOutcome::Applied(true)
        );
        // 全清：已决 + 未决一并清空。
        assert_eq!(gw.lock_clear_all().await, 2);
        assert_eq!(gw.pending_len().await, 0);
        let lock = MatrixBot::handle_text_command_full(&gw, TextCommand::Lock, true, 0).await;
        assert!(lock.is_some_and(|s| s.contains("🔒 Proxy 已锁定")));
        let status = MatrixBot::handle_text_command_full(&gw, TextCommand::Status, false, 3).await;
        assert_eq!(
            status.as_deref(),
            Some("Proxy: 🔒 未解锁 | 待审批: 0 | LLM secrets: 3")
        );
    }

    #[test]
    fn sync解析提反应与文本并过滤非目标房间() {
        let sync = serde_json::json!({
            "next_batch": "s1",
            "rooms": {
                "join": {
                    "!r:example.com": {
                        "timeline": {
                            "events": [
                                {
                                    "type": "m.reaction",
                                    "sender": "@admin:example.com",
                                    "origin_server_ts": 2000,
                                    "content": {
                                        "m.relates_to": {
                                            "event_id": "$ev1",
                                            "key": "✅",
                                            "rel_type": "m.annotation"
                                        }
                                    }
                                },
                                {
                                    "type": "m.room.message",
                                    "sender": "@admin:example.com",
                                    "origin_server_ts": 2001,
                                    "content": {"msgtype": "m.text", "body": "status"}
                                },
                                {
                                    "type": "m.reaction",
                                    "sender": "@x:y",
                                    "origin_server_ts": 2002,
                                    "content": {
                                        "m.relates_to": {"event_id": "", "key": "✅"}
                                    }
                                }
                            ]
                        }
                    },
                    "!other:example.com": {
                        "timeline": {
                            "events": [
                                {
                                    "type": "m.reaction",
                                    "sender": "@admin:example.com",
                                    "origin_server_ts": 2003,
                                    "content": {
                                        "m.relates_to": {
                                            "event_id": "$ev9",
                                            "key": "✅",
                                            "rel_type": "m.annotation"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        });
        let (reactions, texts) = MatrixBot::parse_sync_events(&sync, "!r:example.com");
        assert_eq!(reactions.len(), 1);
        assert_eq!(reactions[0].target_event_id, "$ev1");
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].body, "status");
    }

    #[tokio::test]
    async fn 并发单ask同决议() {
        use std::sync::Arc;
        let gw = Arc::new(approval());
        gw.submit("$shared").await;
        let mut handles = Vec::new();
        for _ in 0..8 {
            let g = Arc::clone(&gw);
            handles.push(tokio::spawn(async move {
                g.ask("$shared", Duration::from_secs(5)).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            gw.resolve("$shared", "@admin:example.com", true).await,
            ResolveOutcome::Applied(true)
        );
        for h in handles {
            assert_eq!(h.await.unwrap(), Some(true), "单次落定须广播给全部等待者");
        }
    }

    #[tokio::test]
    async fn 解锁分支表情语义与超时清理() {
        assert_eq!(
            reaction_to_decision(MatrixBranch::Unlock, "✅"),
            Some((true, false))
        );
        assert_eq!(
            reaction_to_decision(MatrixBranch::Unlock, "❎"),
            Some((false, false))
        );
        assert_eq!(reaction_to_decision(MatrixBranch::Unlock, "🔓"), None);
        let gw = approval();
        gw.submit_branch("$unlock1", MatrixBranch::Unlock).await;
        assert_eq!(gw.ask("$unlock1", Duration::from_millis(80)).await, None);
        assert_eq!(gw.pending_len().await, 0);
    }

    #[test]
    fn 审批文案五分支三段无明文() {
        let bot = MatrixBot::new(
            "https://m.example.com".to_string(),
            "!r:example.com".to_string(),
            "tok".to_string(),
        );
        for (branch, name) in [
            (MatrixBranch::Unlock, "解锁"),
            (MatrixBranch::Register, "注册"),
            (MatrixBranch::HashChange, "哈希变更"),
            (MatrixBranch::Credential, "凭据"),
            (MatrixBranch::Audit, "审计"),
        ] {
            let pending = bot.format_approval(branch, None, "rm -rf / password=hunter2");
            assert!(pending.contains("🔓"), "{pending}");
            assert!(pending.contains(name), "{pending}");
            assert!(pending.contains("!r:example.com"), "{pending}");
            assert!(!pending.contains("hunter2"), "{pending}");
            let ok = bot.format_approval(branch, Some(true), "secret=hunter2");
            assert!(ok.contains("✅") && ok.contains(name), "{ok}");
            assert!(!ok.contains("hunter2"), "{ok}");
            let no = bot.format_approval(branch, Some(false), "token=hunter2");
            assert!(no.contains("❎") && no.contains(name), "{no}");
            assert!(!no.contains("hunter2"), "{no}");
        }
    }
}
