//! 六 admin 路由：鉴权 + 限流 + SSE + 事件查询。
//!
//! 唯一表（精确注册先于通配，MUST NOT 被 `/{*tail}` 吞没）：
//! `/_admin/`、`/_admin/health`、`/_admin/metrics`、`/_admin/series`、
//! `/_admin/events`、`/_admin/events/stream`；未知子路径 404。
//! 鉴权优先级 `X-Admin-Token` > `__Host-admin_token` Cookie >
//! `?access_token`（仅 SSE）；非 SSE 带 query 恒 401；HMAC 等长比较；
//! `OBSERVABILITY_ADMIN_TOKEN` 必填独立性沿用 `Config`。
//! 限流按直连对端 IP（`ConnectInfo`，不读代理头）：通用 10/min/IP 429 +
//! `Retry-After`；SSE 5 并发/IP + 60s ping + 5min 强制重连（axum SSE 语义
//! 与 §4 注释 keepalive 对齐：注释帧不计事件）。
//!
//! 限流契约（有意设计声明）：
//! - 速率维度：通用 admin 接口 `10/min/IP`，超限 `429` + `Retry-After`（秒）+ 错误码
//!   `E_RATE_LIMITED`；计数键为 TCP 直连对端 IP（`ConnectInfo`）， MUST NOT 读
//!   `X-Forwarded-For`/`X-Real-IP` 等代理头（防伪造逃逸，生产由 `main.rs` 经
//!   `into_make_service_with_connect_info` 注入真实对端）。
//!   豁免集三条（`admin_rate_exempt_paths()`）：`/_admin` 控制台壳、`/_admin/health`
//!   探针、`/_admin/events/stream` 长连接——三者不计数（页面一次刷新两请求，计入时 约 5
//!   次刷新即撞墙，且建连失败会退化为假「连接中」）。
//! - 并发维度：`/_admin/events/stream` 按 IP 限制并发 `5`，超限拒绝新连接 （`429` + `Retry-After:
//!   60`）且已建连接不受影响；`10/min` 为速率维度、 `5/IP`
//!   为并发维度，两者正交、独立计数，均为有意设计；SSE 不占速率维度。
//! - 通用 admin 豁免收紧为 `10/min`，系有意收敛，不视为回归。
//! - 超限头与指标锁定：头名 `retry-after`（HTTP 头大小写不敏感，即 `Retry-After`）；错误码
//!   `E_RATE_LIMITED`；SSE 并发水位经 `sse_current` 与网关 `sse_event_total` 观测。
//!
//! 子模块划分：`state` 聚合状态，`ratelimit` 速率限流，`sse` SSE 并发守卫
//! 与建连过滤，`events` 兼容映射与 token 等长比较；实现 axum `State` handler 的
//! 管理面逻辑归 `handler::admin`，本层不 import axum。旧路径
//! `crate::service::admin::X` 经重导出兼容。

pub mod events;
pub mod ratelimit;
pub mod sse;
pub mod state;

pub use {events::*, ratelimit::*, sse::*, state::*};
