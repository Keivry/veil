//! 统一错误类型：`thiserror` 分类 + `anyhow` 上下文链。
//!
//! 映射口径（§1.2 验收）：
//! - 认证失败 → 403
//! - 上游错误 → 透传上游状态码
//! - 空响应体 → 502
//! - 未知/内部错误 → 500，且响应体不泄漏内部细节（仅记日志）。

use {
    axum::{
        Json,
        http::{HeaderValue, StatusCode},
        response::{IntoResponse, Response},
    },
    serde_json::json,
};

/// 全量错误分类，每类有唯一 [`VeilError::code`] 并进日志字段。
#[derive(Debug, thiserror::Error)]
pub enum VeilError {
    #[error("认证失败")]
    Auth { message: String },

    #[error("上游错误 {status}: {message}")]
    Upstream { status: u16, message: String },

    #[error("上游返回空响应体")]
    EmptyBody,

    #[error("配置错误[{var}]: {message}")]
    Config { var: String, message: String },

    #[error("存储错误: {message}")]
    Storage { message: String },

    #[error("内部错误")]
    Internal(#[from] anyhow::Error),

    /// §2：未鉴权（`GET /registrations` 等需鉴权接口）。
    #[error("未鉴权")]
    Unauthorized { message: String },

    /// §2：重复注册等资源冲突。
    #[error("资源冲突: {message}")]
    Conflict { message: String },

    /// §2：限流（429 + `Retry-After`）。
    #[error("请求过于频繁")]
    RateLimited { retry_after_secs: u64 },

    /// §2：自动放行 `None` 转 Matrix 审批挂起（202，本阶段记 pending 占位）。
    #[error("审批挂起")]
    PendingApproval { message: String },

    /// §2：KeePass 未解锁等服务不可用。
    #[error("服务不可用: {message}")]
    Unavailable { message: String },

    /// §2：请求体非法。
    #[error("请求非法: {message}")]
    BadRequest { message: String },
}

impl VeilError {
    /// 唯一错误码，用于日志字段与响应体。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Auth { .. } => "E_AUTH",
            Self::Upstream { .. } => "E_UPSTREAM",
            Self::EmptyBody => "E_EMPTY_BODY",
            Self::Config { .. } => "E_CONFIG",
            Self::Storage { .. } => "E_STORAGE",
            Self::Internal(_) => "E_INTERNAL",
            Self::Unauthorized { .. } => "E_UNAUTHORIZED",
            Self::Conflict { .. } => "E_CONFLICT",
            Self::RateLimited { .. } => "E_RATE_LIMITED",
            Self::PendingApproval { .. } => "E_PENDING",
            Self::Unavailable { .. } => "E_UNAVAILABLE",
            Self::BadRequest { .. } => "E_BAD_REQUEST",
        }
    }

    /// 错误到 HTTP 状态码的映射。
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Auth { .. } => StatusCode::FORBIDDEN,
            Self::Upstream { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Self::EmptyBody => StatusCode::BAD_GATEWAY,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::PendingApproval { .. } => StatusCode::ACCEPTED,
            Self::Unavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Config { .. } | Self::Storage { .. } | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// 把任意错误经 `anyhow` 上下文链包装为内部错误。
    /// 调用侧用 `.context("...")?` 追加上下文后经 `?` 自动转换。
    pub fn internal(err: impl Into<anyhow::Error>) -> Self { Self::Internal(err.into()) }

    /// 对外暴露的响应消息：500 系统一脱敏，不泄漏内部细节。
    fn public_message(&self) -> String {
        match self {
            Self::Auth { message }
            | Self::Upstream { message, .. }
            | Self::Config { message, .. } => message.clone(),
            Self::EmptyBody => "上游返回空响应体".to_string(),
            Self::Unauthorized { message }
            | Self::Conflict { message }
            | Self::PendingApproval { message }
            | Self::Unavailable { message }
            | Self::BadRequest { message } => message.clone(),
            Self::RateLimited { retry_after_secs } => {
                format!("请求过于频繁，请 {retry_after_secs}s 后重试")
            }
            Self::Storage { .. } | Self::Internal(_) => "内部错误".to_string(),
        }
    }
}

impl IntoResponse for VeilError {
    fn into_response(self) -> Response {
        tracing::error!(code = self.code(), error = ?self, "请求失败");
        let status = self.status_code();
        let body = Json(json!({
            "error": {
                "code": self.code(),
                "message": self.public_message(),
            }
        }));
        if let Self::RateLimited { retry_after_secs } = &self {
            let mut response = (status, body).into_response();
            if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert("retry-after", value);
            }
            response
        } else {
            (status, body).into_response()
        }
    }
}

/// 本 Crate 内统一的 `Result` 别名。
pub type Result<T, E = VeilError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 每类错误有唯一错误码() {
        let cases = [
            VeilError::Auth {
                message: "缺密钥".to_string(),
            },
            VeilError::Upstream {
                status: 502,
                message: "坏网关".to_string(),
            },
            VeilError::EmptyBody,
            VeilError::Config {
                var: "AUDIT_TIMEOUT".to_string(),
                message: "非法".to_string(),
            },
            VeilError::Storage {
                message: "写失败".to_string(),
            },
            VeilError::internal(anyhow::anyhow!("根因")),
        ];
        let mut codes: Vec<&str> = cases.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), cases.len(), "错误码必须唯一");
    }

    #[test]
    fn 认证失败映射403() {
        let err = VeilError::Auth {
            message: "三因子缺一".to_string(),
        };
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(err.code(), "E_AUTH");
    }

    #[test]
    fn 上游状态码透传() {
        for status in [401u16, 429, 502, 503] {
            let err = VeilError::Upstream {
                status,
                message: "上游直回".to_string(),
            };
            assert_eq!(err.status_code(), StatusCode::from_u16(status).unwrap());
        }
    }

    #[test]
    fn 空体映射502() {
        assert_eq!(VeilError::EmptyBody.status_code(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn 未知错误默认500且不泄漏细节() {
        let secret = "sk-绝密-12345";
        let err = VeilError::internal(anyhow::anyhow!(secret).context("网关中段断连"));
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!format!("{response:?}").contains(secret));
    }

    #[test]
    fn anyhow上下文链保留() {
        let err = VeilError::internal(anyhow::anyhow!("根因").context("中间层").context("外层"));
        let debug = format!("{err:?}");
        assert!(debug.contains("根因") && debug.contains("中间层") && debug.contains("外层"));
    }

    #[tokio::test]
    async fn 错误响应体携带错误码() {
        let response = VeilError::Auth {
            message: "拒绝".to_string(),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"]["code"], "E_AUTH");
    }
}
