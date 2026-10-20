//! 网关侧清理接线（自 `bot.rs` 拆出，保持导出路径不变）。

/// `lock` 的清理结果：回执与日志据此报真实条数，不再靠单值 `usize` 猜测。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LockCleanupReport {
    pub vault_cleared: usize,
    pub pii_scopes_cleared: usize,
}

/// 网关侧清理回调：Matrix 层不依赖 `AppState`，由网关实现注入，
/// 使 `lock`/`forget`/`status` 能读写真实的口令缓存、KeePass 会话与 token 映射。
pub trait GatewayCleanup: Send + Sync {
    /// `status`：KeePass 库文件是否在位（不代表内存材料已载入）。
    fn keepass_unlocked(&self) -> bool;
    /// `status`/`lock`：TPM 派生主密码缓存是否已载入；无该缓存的实现默认 `false`。
    fn master_password_cached(&self) -> bool { false }
    /// `status`：当前 token 映射条数（LLM secrets）。
    fn vault_len(&self) -> usize;
    /// `lock`：清口令缓存 + KeePass 会话 + 内存 pending + PII 会话作用域。
    fn lock_cleanup(&self) -> LockCleanupReport;
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

    fn lock_cleanup(&self) -> LockCleanupReport { LockCleanupReport::default() }

    fn forget_cleanup(&self) -> usize { 0 }
}
