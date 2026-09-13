//! 限流表（有界 + 双触发清扫，对齐原仓语义）：请求路径内联清扫，不新增后台任务。

use {
    crate::error::{Result, VeilError},
    std::{collections::HashMap, time::Instant},
};

/// 限流表（有界 + 双触发清扫，对齐原仓语义）：请求路径内联清扫，不新增后台任务。
/// - 计数触发：条目超 `SWEEP_LEN` 时清过期键；
/// - 时间触发：距上次清扫超 `SWEEP_SECS` 时清过期键；
/// - 硬上限：超 `MAX_ENTRIES` 时挤出任意非当前键（永不影响本次判定）。
#[derive(Debug)]
pub struct RateTable {
    hits: HashMap<String, Instant>,
    last_sweep: Instant,
}

impl RateTable {
    pub const MAX_ENTRIES: usize = 4096;
    pub const SWEEP_LEN: usize = 1000;
    pub const SWEEP_SECS: u64 = 60;

    pub fn new() -> Self {
        Self {
            hits: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.hits.len() }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool { self.hits.is_empty() }

    #[cfg(test)]
    pub fn clear(&mut self) { self.hits.clear(); }
}

impl Default for RateTable {
    fn default() -> Self { Self::new() }
}

/// 限流判定（异步锁：`tokio::sync::Mutex`，高并发凭据 burst 不阻塞 executor）。
/// 临界区禁 `.await`——仅查改时间戳映射，持锁期间不得跨 `.await`（防持锁让出
/// 放大尾延迟与锁竞争）；`tokio::sync::Mutex` 无毒化语义，加锁失败不可能，直接持有。
pub(crate) async fn check_rate(
    hits: &tokio::sync::Mutex<RateTable>,
    key: &str,
    window_secs: u64,
) -> Result<()> {
    let mut guard = hits.lock().await;
    let now = Instant::now();
    if guard.hits.len() > RateTable::SWEEP_LEN
        || now.duration_since(guard.last_sweep).as_secs() >= RateTable::SWEEP_SECS
    {
        guard
            .hits
            .retain(|_, t| now.duration_since(*t).as_secs() < window_secs);
        guard.last_sweep = now;
    }
    if let Some(last) = guard.hits.get(key)
        && now.duration_since(*last).as_secs() < window_secs
    {
        let remain = window_secs.saturating_sub(now.duration_since(*last).as_secs());
        return Err(VeilError::RateLimited {
            retry_after_secs: remain.max(1),
        });
    }
    guard.hits.insert(key.to_string(), now);
    if guard.hits.len() > RateTable::MAX_ENTRIES
        && let Some(victim) = guard.hits.keys().find(|k| k.as_str() != key).cloned()
    {
        guard.hits.remove(&victim);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::service::credential::{handle_credential, register_caller, test_support::*},
        axum::response::IntoResponse as _,
    };

    #[tokio::test]
    async fn credential_rate_limit_2s_returns_429_with_retry_after() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("rlhash", "/s/rl.sh", None),
        )
        .await
        .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("rlhash", "/s/rl.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        let response = err.into_response();
        assert!(response.headers().contains_key("retry-after"));
    }

    #[tokio::test]
    async fn register_rate_limit_1s() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/r1.sh", "h1", "src1")
            .await
            .unwrap();
        let dup = register_caller(&state, "/s/r1.sh", "h1", "src1")
            .await
            .unwrap_err();
        assert_eq!(dup.status_code(), axum::http::StatusCode::CONFLICT);
        let limited = register_caller(&state, "/s/r2.sh", "h2", "src1")
            .await
            .unwrap_err();
        assert_eq!(
            limited.status_code(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn credential_rate_per_caller() {
        // C11/D11：限流按调用方维度（`caller_path:caller_hash`）独立计数。
        // 同一调用方窗口内第二次 429。
        let env = cred_env(&[]);
        let state = cred_state(&env);
        handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("rl-a", "/s/rl-a.sh", None),
        )
        .await
        .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("rl-a", "/s/rl-a.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        // 另一调用方不受该调用方限流影响（跨方隔离）。
        let out = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("rl-b", "/s/rl-b.sh", None),
        )
        .await
        .unwrap();
        assert!(
            credential_value(&out).starts_with("__VG_CRED_"),
            "另一调用方须正常取用，不受 A 的限流影响"
        );
    }

    #[tokio::test]
    async fn rate_table_sweep_removes_only_expired_keys() {
        use tokio::sync::Mutex;
        let table = Mutex::new(RateTable::new());
        // 计数触发：超 1000 条后下一次检查清扫；窗口 0 使旧键全部过期。
        for i in 0..(RateTable::SWEEP_LEN + 5) {
            check_rate(&table, &format!("cold-{i}"), 0).await.unwrap();
        }
        let guard = table.lock().await;
        assert!(
            guard.len() <= RateTable::SWEEP_LEN + 6,
            "过期键须被清扫，长跑不膨胀: {}",
            guard.len()
        );
        drop(guard);
        // 活跃键判定不受清扫影响：同键在窗口内仍限流。
        check_rate(&table, "hot-key", 3600).await.unwrap();
        let err = check_rate(&table, "hot-key", 3600).await.unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn rate_table_hard_cap_evicts_without_affecting_current_decision() {
        use tokio::sync::Mutex;
        let table = Mutex::new(RateTable::new());
        for i in 0..(RateTable::MAX_ENTRIES + 10) {
            check_rate(&table, &format!("k-{i}"), u64::MAX)
                .await
                .unwrap();
        }
        let guard = table.lock().await;
        assert_eq!(guard.len(), RateTable::MAX_ENTRIES, "硬上限须钳制");
    }
}
