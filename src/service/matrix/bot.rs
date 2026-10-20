//! Matrix Bot：reqwest 长轮询 sync + 文本指令执行（自 `matrix.rs` 拆出）。

use {
    super::{
        approval::MatrixApproval,
        branch::{
            MatrixBranch,
            ReactionInput,
            ReactionOutcome,
            SYNC_TIMEOUT_MS,
            TextCommand,
            TextInput,
            load_since_token,
            parse_text_command,
            save_since_token,
            sync_backoff_secs,
            sync_request_timeout,
        },
    },
    std::{path::PathBuf, sync::Arc, time::Duration},
};

/// 网关侧清理回调：Matrix 层不依赖 `AppState`，由网关实现注入，
/// 使 `lock`/`forget`/`status` 能读写真实的口令缓存、KeePass 会话与 token 映射。
pub trait GatewayCleanup: Send + Sync {
    /// `status`：KeePass 库文件是否在位（不代表内存材料已载入）。
    fn keepass_unlocked(&self) -> bool;
    /// `status`/`lock`：TPM 派生主密码缓存是否已载入；无该缓存的实现默认 `false`。
    fn master_password_cached(&self) -> bool { false }
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

    fn branch_name(branch: MatrixBranch) -> &'static str {
        match branch {
            MatrixBranch::Register => "注册",
            MatrixBranch::HashChange => "哈希变更",
            MatrixBranch::Credential => "凭据",
            MatrixBranch::Command => "命令",
            MatrixBranch::Audit => "审计",
            MatrixBranch::Revoke => "吊销",
            MatrixBranch::Unknown => "未知分支（已忽略）",
        }
    }

    fn reaction_legend(branch: MatrixBranch) -> &'static str {
        match branch {
            MatrixBranch::Register => "✅ 激活（保留注册声明）/ ♾️ 激活并持久放行 / ❎ 吊销",
            MatrixBranch::HashChange => "✅ 批准并降级人工审批 / ♾️ 批准并置自动放行 / ❎ 禁用",
            MatrixBranch::Command => "✅ 批准本次 / ♾️ 批准并持久放行 / ❎ 拒绝",
            MatrixBranch::Revoke => "✅ 执行吊销 / ❎ 不吊销",
            MatrixBranch::Credential | MatrixBranch::Audit => "✅ 批准本次 / ❎ 拒绝",
            MatrixBranch::Unknown => "",
        }
    }

    /// 建单消息正文：分支 + 待审标识 + 脱敏摘要 + 该分支 reaction 图例。
    pub fn format_ticket(&self, branch: MatrixBranch, summary: &str) -> String {
        let clean = crate::service::audit::sanitize_for_log(summary);
        let name = Self::branch_name(branch);
        format!(
            "{mark} [{name}] {room} :: {clean}\n可选反应：{legend}",
            mark = branch.status_emoji_pending(),
            room = self.room_id,
            legend = Self::reaction_legend(branch)
        )
    }

    /// 无票通知正文（哈希变更/失败 spool）：分支 + 状态标识 + 脱敏摘要，不含图例。
    pub fn format_notice(
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
        let clean = crate::service::audit::sanitize_for_log(summary);
        format!(
            "{mark} [{name}] {room} :: {clean}",
            name = Self::branch_name(branch),
            room = self.room_id
        )
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

    /// 向指定事件预置 reaction（`m.annotation`），失败返回 Err 由调用方 best-effort 处理。
    pub async fn send_reaction(&self, event_id: &str, key: &str) -> anyhow::Result<()> {
        let txn = format!("{}", chrono_txn());
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.reaction/{txn}",
            self.homeserver.trim_end_matches('/'),
            url_encode(&self.room_id)
        );
        let resp = self
            .client
            .put(&url)
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!({
                "m.relates_to": {
                    "event_id": event_id,
                    "key": key,
                    "rel_type": "m.annotation"
                }
            }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Matrix reaction 发送失败: {e}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("Matrix reaction 发送失败: {}", resp.status());
        }
        Ok(())
    }

    /// 长轮询 sync 一次（服务端 `timeout=SYNC_TIMEOUT_MS`），返回原始
    /// JSON；调用方循环即得持续同步。 本请求带独立总超时（窗口 + RTT 余量），免被共享 client 的
    /// `HTTP_TIMEOUT_SECS` 截断。
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
            .timeout(sync_request_timeout())
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

    /// `GET /whoami` 查询 Bot 自身 MXID（自反应过滤用）；失败返回空串（调用方 fail-closed）。
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

    /// 文本指令执行：`lock`→清口令缓存 + KeePass 会话 + 双 pending，回执报告
    /// 清理条数、主密码缓存状态与按拒绝落定的票数（不宣称"锁定"）；
    /// `status`→`Proxy: 主密码缓存: {已载入/未载入} | 待审批: {n} | LLM secrets: {n}`；
    /// `forget`→清 token 映射并以真实条数回执。
    ///
    /// 审批链（注册/吊销/哈希变更）：本库只做审批单流转；
    /// 注册-批准链的实际生效（`set_enabled(true)` / 吊销落盘）由网关侧在收到
    /// `ReactionOutcome::Applied` 后执行——网关不经审批直接生效即绕过审批链，
    /// 属须显式声明的语义变更。
    pub async fn handle_text_command_full(
        approval: &MatrixApproval,
        command: TextCommand,
        cleanup: &dyn GatewayCleanup,
    ) -> Option<String> {
        match command {
            TextCommand::Lock => {
                let cached_before = cleanup.master_password_cached();
                let cleared = cleanup.lock_cleanup();
                let count = approval.lock_reject_all().await;
                approval.lock_clear_all().await;
                let master_state = match (cached_before, cleanup.master_password_cached()) {
                    (true, false) => "已载入→未载入",
                    (false, false) => "未载入",
                    (_, true) => "已载入（清理未生效）",
                };
                Some(format!(
                    "🧹 已清除内存口令材料（口令缓存 {cleared} 条、主密码缓存: {master_state}、未决 {count} 单已按拒绝落定）"
                ))
            }
            TextCommand::Status => {
                let pending = approval.pending_len().await;
                let cached = if cleanup.master_password_cached() {
                    "已载入"
                } else {
                    "未载入"
                };
                Some(format!(
                    "Proxy: 主密码缓存: {cached} | 待审批: {pending} | LLM secrets: {}",
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
    #[cfg(test)]
    pub(crate) async fn handle_text_command(
        approval: &MatrixApproval,
        command: TextCommand,
    ) -> Option<String> {
        let fixed = FixedCleanup {
            unlocked: true,
            secrets: 0,
        };
        Self::handle_text_command_full(approval, command, &fixed).await
    }

    /// 单个文本事件门控 + 执行：`whoami` 为空时丢弃全部文本指令
    /// （fail-closed，与自反应过滤同口径），返回 `None` 表示不产生回执。
    pub(crate) async fn handle_text_event(
        approval: &MatrixApproval,
        cleanup: &dyn GatewayCleanup,
        own_user_id: &str,
        expected_room: &str,
        start_ts_ms: u128,
        text: &TextInput,
    ) -> Option<String> {
        if own_user_id.is_empty()
            || text.room_id != expected_room
            || text.server_ts_ms < start_ts_ms
            || text.sender == own_user_id
        {
            return None;
        }
        Self::handle_text_command_full(approval, parse_text_command(&text.body), cleanup).await
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
            // `own_user_id` 决定自反应/自身文本过滤与 fail-closed 丢弃。启动瞬间 Matrix
            // 抖动会让它为空；若只探测一次，后续每轮都会丢弃全部事件直到进程重启
            // （sync token 已推进、事件不重放），审批将永久超时。故置空时按退避重试，
            // 重试成功前维持 fail-closed。
            let mut own_user_id = self.whoami().await;
            let mut whoami_failures: u32 = 0;
            if own_user_id.is_empty() {
                tracing::warn!(
                    "Matrix whoami 失败：自反应与自身文本过滤不可用，丢弃全部 reaction 与文本指令（fail-closed）；\
                     将按退避重试，成功前审批不会被落定"
                );
            }
            let expected_room = self.room_id.clone();
            let mut since = load_since_token(&token_file);
            if since.is_some() {
                tracing::info!("Matrix sync 从持久化 token 恢复");
            }
            let mut failures: u32 = 0;
            loop {
                if own_user_id.is_empty() {
                    own_user_id = self.whoami().await;
                    if own_user_id.is_empty() {
                        let delay = sync_backoff_secs(whoami_failures);
                        whoami_failures = whoami_failures.saturating_add(1);
                        tracing::debug!("Matrix whoami 仍失败，{delay}s 后重试");
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                        continue;
                    }
                    whoami_failures = 0;
                    tracing::info!(
                        "Matrix whoami 恢复（{own_user_id}）：自反应与自身文本过滤已启用"
                    );
                }
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
                            if own_user_id.is_empty() {
                                continue;
                            }
                            match approval
                                .on_reaction(&input, &own_user_id, &expected_room, start_ts_ms)
                                .await
                            {
                                ReactionOutcome::Applied { approved, always } => {
                                    let verdict = if always {
                                        "批准并持久放行"
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
                                ReactionOutcome::Notify(reason) => {
                                    let reply = format!(
                                        "{} 未被受理: {} → {reason}",
                                        input.key, input.target_event_id
                                    );
                                    if let Err(err) = self.send_text(&reply).await {
                                        tracing::debug!("审批回执发送失败: {err:#}");
                                    }
                                }
                                ReactionOutcome::Silent(reason) => {
                                    tracing::debug!(
                                        "审批 reaction 静默忽略({reason}): {} → {}",
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
                            if let Some(reply) = Self::handle_text_event(
                                &approval,
                                cleanup.as_ref(),
                                &own_user_id,
                                &expected_room,
                                start_ts_ms,
                                &text,
                            )
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
        let msg = bot.format_notice(MatrixBranch::Audit, None, r#"rm -rf / password=hunter2"#);
        assert!(msg.contains("⏳"), "{msg}");
        assert!(!msg.contains("hunter2"), "{msg}");
    }

    #[test]
    fn poll_sync_carries_request_timeout_overriding_client_total() {
        // 接线守卫：`send()` 前须挂 per-request 总超时，否则长轮询被共享 client 的
        // `HTTP_TIMEOUT_SECS`（默认 30s）截断为假失败（见 `sync_request_timeout`）。
        let src = include_str!("bot.rs");
        let poll = src
            .find("pub async fn poll_sync")
            .expect("poll_sync 定义点");
        let tail = &src[poll..];
        let timeout = tail
            .find(".timeout(sync_request_timeout())")
            .expect("sync 请求须带 per-request 总超时");
        let send = tail.find(".send()").expect("send 调用点");
        assert!(timeout < send, "per-request 超时须在 send 之前设置");
    }

    /// 行为级回归：client 级总超时 1s、服务端 1.5s 才回响应头。
    /// 普通请求须被 1s 截断（装置有效性），sync 请求须活过它（per-request 超时覆盖）。
    #[tokio::test]
    async fn poll_sync_outlives_client_total_timeout() {
        let client = crate::state::build_http_client(&config_with_timeout_secs(1));
        let (url, server) = slow_sync_server(std::time::Duration::from_millis(1500)).await;

        let plain = client.get(&url).send().await;
        assert!(
            plain.is_err(),
            "前提校验：1s client 总超时须对普通请求生效，实际 {plain:?}"
        );

        let bot =
            MatrixBot::with_client(url, "!r:example.com".to_string(), "tok".to_string(), client);
        let sync = bot
            .poll_sync(None)
            .await
            .expect("sync 须活过 client 总超时（per-request 超时覆盖）");
        server.abort();
        assert_eq!(
            sync.get("next_batch").and_then(|v| v.as_str()),
            Some("s1b"),
            "sync 响应须完整解析"
        );
    }

    /// 测试装配：以指定 `HTTP_TIMEOUT_SECS` 构造合法 `Config`。
    fn config_with_timeout_secs(secs: u64) -> crate::config::Config {
        let env = std::collections::HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://matrix.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
            ("HTTP_TIMEOUT_SECS".to_string(), secs.to_string()),
        ]);
        crate::config::Config::load_from(&env).expect("测试配置须合法")
    }

    /// 测试 homeserver：循环 accept，延迟 `delay` 后回 200 + 最小 sync JSON。
    async fn slow_sync_server(delay: std::time::Duration) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buf = vec![0u8; 4096];
                let _ = sock.read(&mut buf).await;
                tokio::time::sleep(delay).await;
                let body = r#"{"next_batch":"s1b"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (url, handle)
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
    fn approval_copy_branches_three_stages_without_plaintext() {
        let bot = MatrixBot::new(
            "https://m.example.com".to_string(),
            "!r:example.com".to_string(),
            "tok".to_string(),
        );
        for (branch, name) in [
            (MatrixBranch::Register, "注册"),
            (MatrixBranch::HashChange, "哈希变更"),
            (MatrixBranch::Credential, "凭据"),
            (MatrixBranch::Command, "命令"),
            (MatrixBranch::Audit, "审计"),
            (MatrixBranch::Revoke, "吊销"),
        ] {
            let pending = bot.format_notice(branch, None, "rm -rf / password=hunter2");
            assert!(pending.contains("⏳"), "{pending}");
            assert!(pending.contains(name), "{pending}");
            assert!(pending.contains("!r:example.com"), "{pending}");
            assert!(!pending.contains("hunter2"), "{pending}");
            let ok = bot.format_notice(branch, Some(true), "secret=hunter2");
            assert!(ok.contains("✅") && ok.contains(name), "{ok}");
            assert!(!ok.contains("hunter2"), "{ok}");
            let no = bot.format_notice(branch, Some(false), "token=hunter2");
            assert!(no.contains("❎") && no.contains(name), "{no}");
            assert!(!no.contains("hunter2"), "{no}");
        }
        let ticket = bot.format_ticket(MatrixBranch::Register, "注册 :: /s/a.sh");
        assert!(
            ticket.contains("可选反应") && ticket.contains("♾️"),
            "{ticket}"
        );
        let notice = bot.format_notice(MatrixBranch::Register, None, "注册 :: /s/a.sh");
        assert!(!notice.contains("可选反应"), "{notice}");
    }
}
