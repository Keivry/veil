//! 逐请求日志（`llm_requests` + `request_model_rollup`）：会话标识、流式守卫、存储。
//!
//! 三子模块单向依赖：
//! - [`session`]：日志会话摘要（域分离 HMAC，纯函数，无 I/O）；身份优先级见
//!   `service::session_identity`；
//! - [`guard`]：流式请求的「恰好一行」守卫（`Drop` 补写 `client_aborted` 行并计数）；
//! - [`store`]：有界队列 + 批量落库 + rollup 投影 + 分页查询 + 保留期。
//!
//! 与 `service::metrics` 同库（`data_dir/metrics.sqlite`）不同表；`counted_metrics`
//! 是与 KPI `requests` 的唯一桥接（design §2）。本模块不含 HTTP 层与 `AppState` 装配。

pub mod guard;
pub mod session;
pub mod store;

pub use {
    crate::service::session_identity::{SessionScope, SessionSource},
    guard::{CLIENT_ABORTED_KIND, StreamGuard, StreamOutcome},
    session::{SESSION_ID_HEX_LEN, session_digest},
    store::{
        DEFAULT_LIMIT,
        FLUSH_BATCH_ROWS,
        FLUSH_INTERVAL_SECS,
        MAX_LIMIT,
        MAX_OFFSET,
        MIN_SESSION_PREFIX_CHARS,
        PURGE_INTERVAL_SECS,
        REQUEST_QUEUE_CAP,
        RequestFilter,
        RequestLog,
        RequestPage,
        RequestRow,
        StatusClass,
        cache_input_tokens,
        tokens_per_sec,
    },
};
