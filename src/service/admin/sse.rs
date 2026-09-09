//! 管理面 SSE：并发守卫 + 实时推送 + 建连过滤。

use {
    super::{
        super::credential::AppStateParts,
        events::authorize,
        ratelimit::{check_admin_rate, rate_limited},
        state::AdminState,
    },
    crate::state::AppState,
    axum::{
        extract::{ConnectInfo, FromRequestParts, Query, State},
        http::{HeaderMap, request::Parts},
        response::{
            IntoResponse,
            Response,
            sse::{Event, KeepAlive, Sse},
        },
    },
    std::{
        collections::HashMap,
        net::{IpAddr, SocketAddr},
        sync::Mutex,
    },
};

/// SSE 并发上限/IP（并发维度；仅约束 `/_admin/events/stream` 同时在线数，
/// 与通用 10/min 速率限流正交，超限拒绝新连接且已建连接不受影响）。
pub const SSE_MAX_PER_IP: usize = 5;
/// SSE 保活 ping 间隔（60s）。
pub const SSE_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// SSE 强制重连（5min，服务端主动关闭）。
pub const SSE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(300);
/// SSE 推送节奏（对标原仓）：15s 快照全量 + 2s 增量推送。
/// 网关接线人注意：当前 `admin_events_stream` 为事件驱动直推（广播即到）；
/// 若需严格 15s/2s 节奏，网关侧在订阅循环加节流窗（BREAKING 声明备选：保持直推并文档化差异）。
pub const SSE_SNAPSHOT_SECS: u64 = 15;
/// SSE 增量推送间隔（秒）。
pub const SSE_DELTA_SECS: u64 = 2;

impl AdminState {
    /// SSE 并发守卫（5/IP）：调用方 MUST 持有至连接结束，`Drop` 自动释放；
    /// 满时返回 `None`（429）。禁止手动调 `release_sse_for`（双重释放会
    /// 错减他路计数；该方法仅保留作 `Drop` 内部语义的公开别名）。
    pub fn acquire_sse(&self, ip: IpAddr) -> Option<SseGuard> {
        let mut guard = self.sse_count.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&ip).copied().unwrap_or(0);
        if n >= SSE_MAX_PER_IP {
            return None;
        }
        guard.insert(ip, n + 1);
        Some(SseGuard {
            ip,
            slots: std::sync::Arc::clone(&self.sse_count),
        })
    }

    /// 释放 SSE 计数（`SseGuard::drop` 内部语义的公开别名；调用方禁止在
    /// 持有守卫时手动调用，否则与 `Drop` 双重释放错减计数）。
    pub fn release_sse_for(&self, ip: IpAddr) {
        let mut guard = self.sse_count.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&ip).copied().unwrap_or(0);
        if n <= 1 {
            guard.remove(&ip);
        } else {
            guard.insert(ip, n - 1);
        }
    }

    /// 当前 IP 的 SSE 并发数（单测用）。
    pub fn sse_current(&self, ip: IpAddr) -> usize {
        self.sse_count
            .lock()
            .map(|g| g.get(&ip).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// 订阅实时流。
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.broadcaster.subscribe()
    }
}

/// SSE 并发守卫：持有计数槽位，`Drop` 时自动释放（断连不泄漏）。
pub struct SseGuard {
    ip: IpAddr,
    slots: std::sync::Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SseGuard {
    fn drop(&mut self) {
        let mut guard = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&self.ip).copied().unwrap_or(0);
        if n <= 1 {
            guard.remove(&self.ip);
        } else {
            guard.insert(self.ip, n - 1);
        }
    }
}

/// 直连对端 IP 提取器（只读 `ConnectInfo`，MUST NOT 读代理头）。
///
/// `ConnectInfo` 缺失时回退本地回环（单测直调 `serve` 场景），生产入口
/// 由 `main.rs` 以 `into_make_service_with_connect_info` 注入真实对端。
pub struct PeerIp(pub IpAddr);

impl<S> FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));
        Ok(PeerIp(ip))
    }
}

/// SSE 建连过滤维度（`?model=&upstream=`；对标原仓建连参数绑定）。
/// 返回 `(model, upstream)`；空表示不过滤。`model` 按事件 `protocol` 子串匹配，
/// `upstream` 按事件摘要子串匹配（尽力过滤，形态不符的事件直通）。
#[derive(Debug, Clone, Default)]
pub struct SseFilter {
    pub model: Option<String>,
    pub upstream: Option<String>,
}

impl SseFilter {
    /// 从建连 query 解析过滤维度。
    pub fn from_query(query: &HashMap<String, String>) -> Self {
        Self {
            model: query.get("model").cloned().filter(|v| !v.is_empty()),
            upstream: query.get("upstream").cloned().filter(|v| !v.is_empty()),
        }
    }

    /// 事件 JSON 是否通过过滤（解析失败直通，不丢事件）。
    pub fn passes(&self, event_json: &str) -> bool {
        if self.model.is_none() && self.upstream.is_none() {
            return true;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(event_json) else {
            return true;
        };
        if let Some(m) = self.model.as_deref()
            && !v
                .get("protocol")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains(m))
        {
            return false;
        }
        if let Some(u) = self.upstream.as_deref()
            && !v
                .get("summary")
                .and_then(|s| s.as_str())
                .is_some_and(|s| s.contains(u))
        {
            return false;
        }
        true
    }
}

/// `GET /_admin/events/stream`：SSE 实时推送（query 鉴权仅此路由有效；
/// 建连 `?model=&upstream=` 过滤维度生效，见 [`SseFilter`]）。
pub async fn admin_events_stream(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
    }
    let qtok = query.get("access_token").cloned();
    let has_q = qtok.is_some();
    if let Some(r) = authorize(
        &state.config().observability_admin_token,
        &headers,
        qtok.as_deref(),
        has_q,
        true,
    ) {
        return r;
    }
    // 并发超限：拒绝新连接（429 + Retry-After: 60），不触已建连接计数。
    // 守卫 MUST 移入流中持有至结束，`Drop` 自动释放（断连不泄漏）。
    let sse_guard = match state.admin_state().acquire_sse(ip) {
        Some(g) => g,
        None => return rate_limited(60),
    };
    let rx = state.admin_state().subscribe();
    let admin = state.admin_state().clone();
    // 建连过滤维度（model/upstream）；近环回放与实时流同过滤。
    let filter = SseFilter::from_query(&query);
    // 近环回放（最近 20 条，已脱敏）。
    let backlog: Vec<String> = admin
        .query_events(None, None, 20)
        .into_iter()
        .rev()
        .filter_map(|e| serde_json::to_string(&e).ok())
        .filter(|s| filter.passes(s))
        .collect();
    let stream = async_stream::stream! {
        let _sse_guard = sse_guard;
        for item in backlog {
            yield Ok::<_, anyhow::Error>(Event::default().data(item).event("message"));
        }
        let mut rx = rx;
        let deadline = tokio::time::Instant::now() + SSE_MAX_AGE;
        loop {
            let timeout = tokio::time::timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), rx.recv()).await;
            match timeout {
                Ok(Ok(msg)) => {
                    if filter.passes(&msg) {
                        yield Ok::<_, anyhow::Error>(Event::default().data(msg).event("message"));
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        // 5min 强制重连：服务端关闭流，客户端按 retry 重连。
        // 计数释放由 `_sse_guard` 的 `Drop` 自动触发，不手动释放。
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(SSE_PING_INTERVAL).text("ping"))
        .into_response()
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{events::admin_series, state::test_support::test_ip},
            *,
        },
        crate::{
            config::Config,
            state::{AppState, SqliteOutcome},
        },
        axum::{
            extract::{Query, State},
            http::StatusCode,
            response::IntoResponse,
        },
        std::collections::HashMap,
    };

    #[tokio::test]
    async fn peer_ip_uses_direct_connection_ignores_proxy_headers() {
        use axum::extract::ConnectInfo;
        let addr: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let req = axum::http::Request::builder()
            .header("x-forwarded-for", "198.51.100.9")
            .header("x-real-ip", "198.51.100.9")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        parts.extensions.insert(ConnectInfo(addr));
        let peer = PeerIp::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(peer.0, addr.ip());
    }

    #[test]
    fn sse_cadence_constants_and_filter_dimensions() {
        assert_eq!(SSE_SNAPSHOT_SECS, 15);
        assert_eq!(SSE_DELTA_SECS, 2);
        let q: HashMap<String, String> = HashMap::from([
            ("model".to_string(), "chat".to_string()),
            ("upstream".to_string(), "u1".to_string()),
        ]);
        let f = SseFilter::from_query(&q);
        assert!(f.passes(r#"{"protocol":"chat/completions","summary":"u1 ok"}"#));
        assert!(!f.passes(r#"{"protocol":"v1/responses","summary":"u1 ok"}"#));
        assert!(!f.passes(r#"{"protocol":"chat/completions","summary":"other"}"#));
        // 形态不符直通不丢事件。
        assert!(f.passes("not-json"));
        let empty = SseFilter::from_query(&HashMap::new());
        assert!(empty.passes(r#"{"protocol":"x"}"#));
    }

    #[tokio::test]
    async fn series_model_upstream_compat_annotates_without_filtering() {
        let dir = std::env::temp_dir().join(format!("veil-admin-series-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let env = HashMap::from([
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
        ]);
        let state = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: dir.join("m.sqlite"),
                memory_only: false,
            },
        );
        let mut q: HashMap<String, String> = HashMap::new();
        q.insert("model".to_string(), "gpt-4".to_string());
        q.insert("upstream".to_string(), "https://x".to_string());
        q.insert("granularity".to_string(), "daily".to_string());
        let resp = admin_series(
            State(state),
            PeerIp(test_ip()),
            super::super::state::test_support::headers_with(
                Some("observability-admin-token-0123456789"),
                None,
            ),
            Query(q),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
        assert!(v.get("compat").is_some());
        assert!(v["points"].as_array().is_some());
    }
}
