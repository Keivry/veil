//! 锁中毒恢复单一实现（`DCD-7`）。
//!
//! 原三份逐字复制 helper（`pii/scope.rs`、`pii/custom.rs`、`credential_vault.rs`）
//! 合并于此：`PoisonError::into_inner` 取回内部状态并首次 warn，绝不 panic。
//! 泛型 [`lock_or_recover`] 覆盖 `Mutex`/`RwLock` 读/写全部守卫类型。

use std::sync::{
    LockResult,
    PoisonError,
    atomic::{AtomicBool, Ordering},
};

/// 全局首次中毒告警位（进程级 once 语义；跨模块共享）。
static POISON_WARNED: AtomicBool = AtomicBool::new(false);

/// 首次恢复告警（返回是否首次）。注入标志位版本供测试隔离断言复用。
pub(crate) fn warn_poison_once_at(flag: &AtomicBool) -> bool {
    let first = !flag.swap(true, Ordering::Relaxed);
    if first {
        tracing::warn!("锁中毒，已 PoisonError::into_inner 恢复（首次告警）");
    }
    first
}

/// 锁访问统一入口：中毒即 `into_inner` 恢复并首次告警，绝不 panic。
pub(crate) fn lock_or_recover<T>(lock: LockResult<T>) -> T {
    lock.unwrap_or_else(|e: PoisonError<T>| {
        warn_poison_once_at(&POISON_WARNED);
        e.into_inner()
    })
}
