//! 逐请求日志（`llm_requests` + `request_model_rollup`）：会话标识、流式守卫、存储。
//!
//! 三子模块单向依赖：
//! - [`session`]：九档优先级 + HMAC 摘要（纯函数，无 I/O）；
//! - [`guard`]：流式请求的「恰好一行」守卫（`Drop` 补写 `client_aborted` 行并计数）；
//! - [`store`]：有界队列 + 批量落库 + rollup 投影 + 分页查询 + 保留期。
//!
//! 与 `service::metrics` 同库（`data_dir/metrics.sqlite`）不同表；`counted_metrics`
//! 是与 KPI `requests` 的唯一桥接（design §2）。本模块不含 HTTP 层与 `AppState` 装配。

pub mod guard;
pub mod session;
pub mod store;

pub use {
    guard::{CLIENT_ABORTED_KIND, StreamGuard, StreamOutcome},
    session::{
        PII_SCOPE_HEADER_FALLBACKS,
        SESSION_HEADER_FALLBACKS,
        SessionInputs,
        SessionScope,
        SessionSource,
        derive_session,
        pii_scope_header_name,
        pii_scope_header_present,
        resolve_pii_scope_header,
        resolve_session_header,
        session_header_present,
    },
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
