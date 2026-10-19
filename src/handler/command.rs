//! 命令面处理器：`GET /commands` 与 `POST /commands/{id}/invoke`。
//!
//! 纯透传层：头凭证与 DTO 归拢后委派 `service::command`；业务语义（认证、
//! 授权、参数校验、审批、执行、日志）全在服务层。

use {
    crate::{
        error::{Result, VeilError},
        service::{
            self,
            CredentialHeaders,
            command::{InvokeRequest, InvokeResult, Terminal},
        },
        state::AppState,
    },
    axum::{
        Json,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
    },
    serde_json::{Value, json},
};

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn command_headers(headers: &HeaderMap) -> CredentialHeaders {
    CredentialHeaders::new(
        header_str(headers, "x-veilctl-binary-hash"),
        header_str(headers, "x-veilctl-secret"),
    )
    .with_caller(
        header_str(headers, "x-caller-hash"),
        header_str(headers, "x-caller-path"),
    )
}

pub async fn commands_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let body = service::command::catalog(&state, &command_headers(&headers)).await?;
    Ok(Json(body))
}

pub async fn command_invoke_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<InvokeRequest>,
) -> Result<Response> {
    let result = service::command::invoke(&state, &command_headers(&headers), &id, request).await?;
    Ok(match result {
        InvokeResult::Pending { message } => (
            StatusCode::ACCEPTED,
            Json(json!({"ok": false, "error": {"code": "E_PENDING", "message": message}})),
        )
            .into_response(),
        InvokeResult::Terminal(terminal) => terminal_response(&id, terminal),
    })
}

fn terminal_response(command_id: &str, terminal: Terminal) -> Response {
    match terminal {
        Terminal::Executed { output, .. } => (
            StatusCode::OK,
            Json(json!({
                "ok": output.exit_code == Some(0) && !output.timed_out,
                "command": command_id,
                "exit_code": output.exit_code,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "duration_ms": output.duration_ms,
                "timed_out": output.timed_out,
                "truncated": output.truncated,
            })),
        )
            .into_response(),
        Terminal::Denied { message, .. } | Terminal::ExecError { message, .. } => {
            let err = VeilError::Auth { message };
            err.into_response()
        }
        Terminal::ApprovalTimeout { message, .. } => {
            let err = VeilError::Auth { message };
            err.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_prefer_veilctl_names() {
        let mut headers = HeaderMap::new();
        headers.insert("x-veilctl-binary-hash", "h".parse().unwrap());
        headers.insert("x-veilctl-secret", "s".parse().unwrap());
        headers.insert("x-caller-hash", "ch".parse().unwrap());
        headers.insert("x-caller-path", "/p".parse().unwrap());
        let parsed = command_headers(&headers);
        assert_eq!(parsed.binary_hash.as_deref(), Some("h"));
        assert_eq!(parsed.binary_secret.as_deref(), Some("s"));
        assert_eq!(parsed.caller_hash.as_deref(), Some("ch"));
        assert_eq!(parsed.caller_path.as_deref(), Some("/p"));
    }

    #[test]
    fn terminal_response_maps_status() {
        use crate::service::command::CommandOutput;
        let resp = terminal_response(
            "deploy",
            Terminal::Executed {
                approval_status: "not_required".to_string(),
                approval_event_id: None,
                output: CommandOutput {
                    exit_code: Some(0),
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                    duration_ms: 3,
                    timed_out: false,
                    truncated: false,
                },
            },
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = terminal_response(
            "deploy",
            Terminal::Denied {
                approval_status: "denied".to_string(),
                approval_event_id: Some("$e".to_string()),
                message: "拒绝".to_string(),
            },
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
