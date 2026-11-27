//! `POST /reload`：操作员显式重载 KDBX。
//!
//! 鉴权只认 `X-Admin-Token` 请求头，MUST NOT 接受 Cookie 或 query：写动作若接受
//! Cookie 就重新引入 CSRF 面。管理面未启用的 404 由 `observability_gate` 统一判定。

use {
    crate::{
        handler::{PeerIp, admin as admin_http},
        service::{admin as admin_service, credential::AppStateParts},
        state::AppState,
    },
    axum::{
        Json,
        extract::State,
        http::HeaderMap,
        response::{IntoResponse, Response},
    },
    serde_json::json,
};

pub async fn reload_handler(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
) -> Response {
    let ip = addr
        .0
        .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]));
    if let Some(retry) = admin_service::check_admin_rate(&state, ip) {
        return admin_http::rate_limited(retry);
    }
    let expected = state.config().observability_admin_token.as_str();
    let provided = headers
        .get("x-admin-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    if expected.is_empty()
        || !provided.is_some_and(|got| admin_service::admin_token_eq(got, expected))
    {
        return admin_http::unauthorized("管理鉴权失败");
    }
    match state.reload_keepass().await {
        Ok(report) => {
            tracing::info!(
                trigger = "http",
                tokens_invalidated = report.tokens_invalidated,
                elapsed_ms = report.elapsed_ms,
                db_path = ?report.db_path,
                "KeePass 重载成功"
            );
            admin_http::with_security_headers(
                Json(json!({
                    "ok": true,
                    "db_path": report.db_path.map(|path| path.to_string_lossy().to_string()),
                    "tokens_invalidated": report.tokens_invalidated,
                    "elapsed_ms": report.elapsed_ms,
                }))
                .into_response(),
            )
        }
        Err(err) => {
            tracing::warn!("KeePass 重载失败: {err}");
            admin_http::with_security_headers(err.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn handler_body_reads_only_admin_header() {
        let src = include_str!("reload.rs");
        let body = src
            .split("pub async fn reload_handler")
            .nth(1)
            .expect("handler 函数体须存在");
        assert!(body.contains("x-admin-token"));
        for banned in ["Cookie", "cookie", "Query", "__Host-admin_token"] {
            assert!(!body.contains(banned), "写端点不得读取 {banned}");
        }
    }

    #[test]
    fn success_log_carries_trigger_elapsed_and_count() {
        let src = include_str!("reload.rs");
        let production = src.split("#[cfg(test)]").next().unwrap_or(src);
        for field in ["trigger = \"http\"", "elapsed_ms", "tokens_invalidated"] {
            assert!(production.contains(field), "成功日志须含字段 {field}");
        }
    }
}
