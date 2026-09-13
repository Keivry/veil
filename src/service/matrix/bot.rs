//! Matrix Bot：reqwest 长轮询 sync + 文本指令执行（D2 自 `matrix.rs` 拆出）。

use {
    super::{
        approval::MatrixApproval,
        branch::{
            MatrixBranch,
            REACTION_APPROVE,
            REACTION_AUTO_UNLOCK,
            REACTION_REJECT,
            ReactionInput,
            ReactionOutcome,
            SYNC_TIMEOUT_MS,
            TextCommand,
            TextInput,
            load_since_token,
            parse_text_command,
            save_since_token,
            sync_backoff_secs,
        },
    },
    std::{path::PathBuf, sync::Arc, time::Duration},
};

/// 网关侧清理回调（`C6`/D6）：Matrix 层不依赖 `AppState`，由网关实现注入，
/// 使 `lock`/`forget`/`status` 能读写真实的口令缓存、KeePass 会话与 token 映射。
pub trait GatewayCleanup: Send + Sync {
    /// `status`：KeePass 后端是否已解锁。
    fn keepass_unlocked(&self) -> bool;
    /// `status`：当前 token 映射条数（LLM secrets）。
    fn vault_len(&self) -> usize;
    /// `lock`：清口令缓存 + KeePass 会话 + 内存 pending；返回清掉的口令缓存条数。
    fn lock_cleanup(&self) -> usize;
    /// `forget`：清 token 映射；返回清掉的映射条数。
    fn forget_cleanup(&self) -> usize;
}

/// 固定清理量兜底（兼容入口与单测）：只读 `unlocked/secrets`，清理动作 no-op。
#[derive(Debug, Clone, Copy)]
pub struct FixedCleanup {
    pub unlocked: bool,
    pub secrets: usize,
}

impl GatewayCleanup for FixedCleanup {
    fn keepass_unlocked(&self) -> bool { self.unlocked }

    fn vault_len(&self) -> usize { self.secrets }

    fn lock_cleanup(&self) -> usize { 0 }

    fn forget_cleanup(&self) -> usize { 0 }
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

    /// 文本指令执行（`C6`/D6）：`lock`→清口令缓存 + KeePass 会话 + 双 pending；
    /// `status`→`Proxy: {✅ 已解锁/🔒 未解锁} | 待审批: {n} | LLM secrets: {n}`；
    /// `forget`→清 token 映射并以真实条数回执。
    ///
    /// BREAKING 说明（注册/吊销/哈希变更审批链）：本库只做审批单流转；
    /// 注册-批准链的实际生效（`set_enabled(true)` / 吊销落盘）由网关侧在收到
    /// `ReactionOutcome::Applied` 后执行——若网关直接生效而不经审批，即为相对原仓的
    /// BREAKING（直接生效语义），须在发布说明中声明并给出风险说明。
    pub async fn handle_text_command_full(
        approval: &MatrixApproval,
        command: TextCommand,
        cleanup: &dyn GatewayCleanup,
    ) -> Option<String> {
        match command {
            TextCommand::Lock => {
                let cleared = cleanup.lock_cleanup();
                let count = approval.lock_reject_all().await;
                approval.lock_clear_all().await;
                Some(format!(
                    "🔒 Proxy 已锁定（清口令缓存 {cleared} 条、未决 {count} 单已按拒绝落定）"
                ))
            }
            TextCommand::Status => {
                let pending = approval.pending_len().await;
                let s = if cleanup.keepass_unlocked() {
                    "✅ 已解锁"
                } else {
                    "🔒 未解锁"
                };
                Some(format!(
                    "Proxy: {s} | 待审批: {pending} | LLM secrets: {}",
                    cleanup.vault_len()
                ))
            }
            TextCommand::Forget => {
                let cleared = cleanup.forget_cleanup();
                let decided = approval.forget_decided().await;
                Some(format!(
                    "🧹 已清除 {cleared} 个 LLM 密码映射（另清 {decided} 个已决审批单）"
                ))
            }
            TextCommand::Unknown => None,
        }
    }

    /// 文本指令执行（兼容版）：签名不变，降级为固定清理量（`unlocked=true/secrets=0`）。
    pub async fn handle_text_command(
        approval: &MatrixApproval,
        command: TextCommand,
    ) -> Option<String> {
        let fixed = FixedCleanup {
            unlocked: true,
            secrets: 0,
        };
        Self::handle_text_command_full(approval, command, &fixed).await
    }

    /// 常驻 sync 循环：since 持久化 + 指数退避 + 启动时间戳过滤。
    /// reaction 经 `MatrixApproval::on_reaction` 落定，文本指令经
    /// `handle_text_command_full` + 网关注入的 `cleanup` 执行；
    /// 发送失败走审批超时默认拒绝路径。
    pub fn spawn_sync_loop(
        self,
        approval: Arc<MatrixApproval>,
        cleanup: Arc<dyn GatewayCleanup>,
        token_file: PathBuf,
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
                            if let Some(reply) =
                                Self::handle_text_command_full(&approval, command, cleanup.as_ref())
                                    .await
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
mod bot_tests {
    use super::*;

    #[test]
    fn approval_summary_contains_no_plaintext() {
        let bot = MatrixBot::new(
            "https://m.example.com".to_string(),
            "!r:example.com".to_string(),
            "tok".to_string(),
        );
        let msg = bot.format_approval(MatrixBranch::Audit, None, r#"rm -rf / password=hunter2"#);
        assert!(msg.contains("🔓"), "{msg}");
        assert!(!msg.contains("hunter2"), "{msg}");
    }

    #[test]
    fn sync_parses_reactions_and_text_filtering_other_rooms() {
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

    #[test]
    fn approval_copy_five_branches_three_stages_without_plaintext() {
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
