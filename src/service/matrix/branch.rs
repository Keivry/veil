//! Matrix 分支/白名单/reaction 解析 + sync 辅助纯函数（D2 自 `matrix.rs` 拆出）。

use std::path::Path;

/// DCD-4：MXID 校验单一实现——canonical 定义在 `config::validate`，此处重导出复用。
pub(crate) use crate::config::validate::is_valid_mxid;

/// 凭据审批超时（秒），与审计分表，固定 300s。
pub const CREDENTIAL_TIMEOUT_SECS: u64 = 300;
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
        } else if r.contains("register")
            || r.contains("注册")
            || r.contains("revoke")
            || r.contains("吊销")
        {
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

    /// `CRD-5`：该分支预置提示的 reaction 表情集（与 [`reaction_to_decision`] 受理集一致，
    /// 含注册/哈希变更分支的 `🔓`），供建单后预置、使审批人可点选。
    pub fn reaction_presets(&self) -> &'static [&'static str] {
        match self {
            Self::Register | Self::HashChange => {
                &[REACTION_AUTO_UNLOCK, REACTION_APPROVE, REACTION_REJECT]
            }
            Self::Unlock | Self::Credential | Self::Audit => &[REACTION_APPROVE, REACTION_REJECT],
            Self::Unknown => &[],
        }
    }
}

/// 白名单校验（`POL-5`/D5）：空白名单＝不过滤（对标 Python `_matrix.py:235,254`）；
/// 非空名单须精确成员匹配，任一相等即放行。
/// 非法格式成员在启动期由 `Config::load_from` 拒绝，此处仅做相等比较。
pub fn is_mxid_allowed(mxid: &str, whitelist: &[String]) -> bool {
    whitelist.is_empty() || whitelist.iter().any(|member| member == mxid)
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

#[cfg(test)]
mod branch_tests {
    use super::*;

    #[test]
    fn whitelist_exact_match_rejects_forged_members() {
        let wl = vec!["@admin:example.com".to_string()];
        assert!(is_mxid_allowed("@admin:example.com", &wl));
        assert!(!is_mxid_allowed("@ghost:example.com", &wl));
        assert!(!is_mxid_allowed("@admin:example.com.evil.com", &wl));
        assert!(!is_mxid_allowed("evil-@admin:example.comX", &wl));
        assert!(!is_mxid_allowed("@ADMIN:example.com", &wl));
        assert!(!is_mxid_allowed("@admin:example.com ", &wl));
    }

    #[test]
    fn is_mxid_allowed_empty_whitelist_no_filter() {
        // POL-5：空白名单＝不过滤；非空名单成员放行、非成员拒绝。
        assert!(
            is_mxid_allowed("@anyone:example.com", &[]),
            "空白名单不过滤"
        );
        let wl = vec!["@admin:example.com".to_string()];
        assert!(is_mxid_allowed("@admin:example.com", &wl));
        assert!(!is_mxid_allowed("@ghost:example.com", &wl));
    }

    #[test]
    fn invalid_whitelist_member_rejected_at_startup() {
        assert!(validate_whitelist_mxids(&["@admin:example.com".to_string()]).is_ok());
        assert!(validate_whitelist_mxids(&["@keivry@matrix.example".to_string()]).is_err());
        assert!(validate_whitelist_mxids(&["admin:example.com".to_string()]).is_err());
        assert!(validate_whitelist_mxids(&["@a: b".to_string()]).is_err());
    }

    #[test]
    fn is_valid_mxid_equivalence() {
        // DCD-4：合并为单一实现后判定须与合并前两份副本逐例等价。
        let cases = [
            ("@admin:example.com", true),
            ("@keivry:matrix.example.org", true),
            ("@a.b-c_d:x.y", true),
            ("@a@b:c", false),
            ("@keivry@matrix.example", false),
            ("admin:example.com", false),
            ("@a:", false),
            ("@:b", false),
            ("@a b:c", false),
            ("@a:b:c", false),
            ("", false),
            ("@", false),
        ];
        for (s, expected) in cases {
            assert_eq!(is_valid_mxid(s), expected, "单一实现判定漂移: {s:?}");
            assert_eq!(
                validate_whitelist_mxids(&[s.to_string()]).is_ok(),
                expected,
                "Matrix 门禁复用同一实现: {s:?}"
            );
        }
    }

    #[test]
    fn backoff_grows_exponentially_capped_at_60s() {
        assert_eq!(sync_backoff_secs(0), 1);
        assert_eq!(sync_backoff_secs(1), 2);
        assert_eq!(sync_backoff_secs(5), 32);
        assert_eq!(sync_backoff_secs(6), 60);
        assert_eq!(sync_backoff_secs(100), 60);
    }

    #[test]
    fn sync_token_persist_roundtrip() {
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
    fn unknown_emoji_and_branch_map_to_noop() {
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
    fn text_commands_parse_three_instructions() {
        assert_eq!(parse_text_command("lock proxy"), TextCommand::Lock);
        assert_eq!(parse_text_command("  LOCK  "), TextCommand::Lock);
        assert_eq!(parse_text_command("status"), TextCommand::Status);
        assert_eq!(parse_text_command("forget secrets"), TextCommand::Forget);
        assert_eq!(parse_text_command("hello"), TextCommand::Unknown);
    }

    #[test]
    fn five_branches_map_and_identify() {
        assert_eq!(MatrixBranch::from_reason("unlock"), MatrixBranch::Unlock);
        assert_eq!(
            MatrixBranch::from_reason("注册审批"),
            MatrixBranch::Register
        );
        // D2/C2：常规吊销复用 `Register` 分支的三态映射（`from_reason` 须识别）。
        assert_eq!(
            MatrixBranch::from_reason("revoke审批"),
            MatrixBranch::Register
        );
        assert_eq!(
            MatrixBranch::from_reason("吊销审批"),
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
}
