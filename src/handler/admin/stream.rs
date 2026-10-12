//! 管理面 SSE 实时流 handler（自 `admin.rs` 拆出）：建连过滤 + 近环回放 +
//! 建连即推首帧快照 + 周期快照 + 收尾 `done`；并发守卫持有至流结束。

use {
    super::{
        AppState,
        AppStateParts,
        HashMap,
        HeaderMap,
        IntoResponse,
        Json,
        PeerIp,
        Query,
        Response,
        SseRecv,
        State,
        StatusCode,
        admin_done_frame,
        admin_event_frame,
        authorize,
        build_metrics_sse_payload,
        classify_sse_recv,
        json,
        peer_ip,
        rate_limited,
        sse_metrics_interval,
        with_security_headers,
    },
    crate::service::admin,
};

/// `GET /_admin/events/stream`：SSE 实时推送（query 鉴权仅此路由有效；
/// 建连 `?model=&upstream=` 过滤维度生效，见 `service::admin::SseFilter`）。
///
/// 推送节奏：建连即推一帧 `event: metrics` 快照 + 每 15s 周期快照
/// （取数失败降级不中断）+ 事件驱动直推（广播即到）。
/// 不占通用限流桶：长连接按「并发」而非「速率」计量，唯一门是 `5/IP` 并发上限。
pub async fn admin_events_stream(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = peer_ip(&addr);
    debug_assert!(admin::is_rate_exempt("/_admin/events/stream"));
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
    // 建连过滤维度（model/upstream）；近环回放与实时流同过滤。
    let filter = admin::SseFilter::from_query(&query);
    let range = query.get("range").cloned();
    // 非法 granularity 显式拒绝（不静默回退默认粒度）。
    let granularity = match query.get("granularity") {
        Some(g) if matches!(g.as_str(), "daily" | "hourly" | "five_min" | "5min") => g.clone(),
        Some(_) => {
            return with_security_headers(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": {"code": "E_BAD_REQUEST", "message": "granularity 取值 daily/hourly/five_min"}})),
                )
                    .into_response(),
            );
        }
        None => range
            .as_deref()
            .and_then(admin::compat_granularity_for_range)
            .unwrap_or("hourly")
            .to_string(),
    };
    // 并发超限：拒绝新连接（429 + Retry-After: 60），不触已建连接计数。
    // 守卫 MUST 移入流中持有至结束，`Drop` 自动释放（断连不泄漏）。
    let sse_guard = match state.admin_state().acquire_sse(ip) {
        Some(g) => g,
        None => return rate_limited(60),
    };
    let rx = state.admin_state().subscribe();
    let admin = state.admin_state().clone();
    // 近环回放（最近 20 条，已脱敏）。
    let backlog: Vec<String> = admin
        .query_events(None, None, 20)
        .into_iter()
        .rev()
        .filter_map(|e| serde_json::to_string(&e).ok())
        .filter(|s| filter.passes(s))
        .collect();
    let metrics_state = state.clone();
    let metrics_filter = filter.clone();
    let metrics_range = range.clone();
    let mut metrics_ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + sse_metrics_interval(),
        sse_metrics_interval(),
    );
    metrics_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let stream = async_stream::stream! {
        let _sse_guard = sse_guard;
        for item in backlog {
            yield Ok::<_, anyhow::Error>(admin_event_frame(item));
        }
        // 建连即推一帧快照：首屏（KPI/趋势/健康）不等 `SSE_METRICS_INTERVAL` 周期 tick，
        // 免空环时面板空置 15s；周期 tick 仍按原节拍续推。
        yield Ok::<_, anyhow::Error>(
            axum::response::sse::Event::default()
                .event("metrics")
                .data(
                    build_metrics_sse_payload(
                        &metrics_state,
                        &metrics_filter,
                        metrics_range.as_deref(),
                        &granularity,
                    )
                    .await
                    .to_string(),
                ),
        );
        let mut rx = rx;
        let deadline = tokio::time::Instant::now() + admin::SSE_MAX_AGE;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let until_deadline = deadline.saturating_duration_since(now);
            tokio::select! {
                _ = metrics_ticker.tick() => {
                    let payload = build_metrics_sse_payload(
                        &metrics_state,
                        &metrics_filter,
                        metrics_range.as_deref(),
                        &granularity,
                    )
                    .await;
                    yield Ok::<_, anyhow::Error>(
                        axum::response::sse::Event::default()
                            .event("metrics")
                            .data(payload.to_string()),
                    );
                }
                recv = rx.recv() => match classify_sse_recv(recv) {
                    SseRecv::Event(msg) => {
                        if filter.passes(&msg) {
                            yield Ok::<_, anyhow::Error>(admin_event_frame(msg));
                        }
                    }
                    SseRecv::Skip(skipped) => {
                        tracing::warn!(skipped, "管理面 SSE 订阅滞后，跳过缺口事件并继续");
                    }
                    SseRecv::Closed => break,
                },
                _ = tokio::time::sleep(until_deadline) => break,
            }
        }
        // 收尾恰一 `done` 终止帧，下游据此判定流结束。
        yield Ok::<_, anyhow::Error>(admin_done_frame());
        // 5min 强制重连：服务端关闭流，客户端按 retry 重连。
        // 计数释放由 `_sse_guard` 的 `Drop` 自动触发，不手动释放。
    };
    let resp = axum::response::sse::Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(admin::SSE_PING_INTERVAL)
                .text("ping"),
        )
        .into_response();
    let mut resp = with_security_headers(resp);
    // 禁用反向代理缓冲，防 SSE 被攒批延迟。
    if let Ok(v) = axum::http::HeaderValue::from_str("no") {
        resp.headers_mut().insert("x-accel-buffering", v);
    }
    resp
}
