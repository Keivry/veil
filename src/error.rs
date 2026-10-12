//! 统一错误类型：`thiserror` 分类 + `anyhow` 上下文链。
//!
//! 状态码集中表（`status_code()` 唯一实现，调用方不得另行映射）：
//! `PendingApproval→202` / `Auth→403` / `Unauthorized→401` / `Conflict→409` /
//! `RateLimited→429(+Retry-After)` / `BadRequest→400` /
//! `NotFound→404` / `EmptyBody→502` / `Unavailable→503` /
//! `Upstream→透传上游码` / 其余→500（响应体不泄漏内部细节，仅记日志）。
//! 例外：入口 body 超限 `413` 由网关入口直接构造（`payload_too_large`），
//! 不经本枚举（超限发生在 JSON 解析之前，无错误变体可承载）；限值见
//! `handler/llm/mod.rs GATEWAY_BODY_LIMIT_BYTES`（已归属 `config`，由该处原位
//! `pub use` 转发）。
//!
//! 映射口径：
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

    /// §3：限流（429 + `Retry-After`）。
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

    /// 条目或属性缺失 → 404（消息具名 entry/attribute）。
    #[error("未找到: {message}")]
    NotFound { message: String },

    /// 自动放行路径 KDBX 查询失败 → 500（对外脱敏，细节仅日志）。
    #[error("KeePass 内部错误: {message}")]
    KeePass { message: String },

    /// PII 脱敏熵源/内部故障 → fail-closed（`502`），不转发未脱敏正文。
    #[error("PII 脱敏不可用")]
    PiiUnavailable,
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
            Self::NotFound { .. } => "E_NOT_FOUND",
            Self::KeePass { .. } => "E_KEEPASS",
            Self::PiiUnavailable => "E_PII_UNAVAILABLE",
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
            Self::PiiUnavailable => StatusCode::BAD_GATEWAY,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::PendingApproval { .. } => StatusCode::ACCEPTED,
            Self::Unavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::KeePass { .. } => StatusCode::INTERNAL_SERVER_ERROR,
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
            Self::PiiUnavailable => "PII 脱敏不可用".to_string(),
            Self::Unauthorized { message }
            | Self::Conflict { message }
            | Self::PendingApproval { message }
            | Self::Unavailable { message }
            | Self::NotFound { message }
            | Self::BadRequest { message } => message.clone(),
            Self::RateLimited { retry_after_secs } => {
                format!("请求过于频繁，请 {retry_after_secs}s 后重试")
            }
            // KeePass 与其它 5xx 同口径脱敏——固定文案，内部细节仅进日志。
            Self::KeePass { .. } | Self::Storage { .. } | Self::Internal(_) => {
                "内部错误".to_string()
            }
        }
    }
}

impl IntoResponse for VeilError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        // 日志级别纪律：5xx 记 error（被告警规则捕获），其余（预期 4xx、
        // 202 审批挂起）记 warn，避免预期失败稀释真告警；`code` 字段保留。
        // PII 安全：4xx/202 变体 message 可含用户可控文本（KeePass 条目/属性名、
        // caller_path、注册 id 等），warn 分支 MUST NOT 以 `?self` 打印；5xx
        // 保持内部细节入日志（仅构造于 admin/state，不承载请求体）。
        if status.is_server_error() {
            tracing::error!(code = self.code(), error = ?self, "请求失败");
        } else {
            tracing::warn!(code = self.code(), "请求失败");
        }
        let message = self.public_message();
        let body = Json(json!({
            "error": {
                "code": self.code(),
                "message": message,
            },
            "error_detail": message,
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
mod tests;
