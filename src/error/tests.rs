use super::*;

#[test]
fn each_error_variant_has_unique_code() {
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
fn auth_error_maps_to_forbidden() {
    let err = VeilError::Auth {
        message: "三因子缺一".to_string(),
    };
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(err.code(), "E_AUTH");
}

#[test]
fn upstream_status_code_passthrough() {
    for status in [401u16, 429, 502, 503] {
        let err = VeilError::Upstream {
            status,
            message: "上游直回".to_string(),
        };
        assert_eq!(err.status_code(), StatusCode::from_u16(status).unwrap());
    }
}

#[test]
fn empty_body_maps_to_bad_gateway() {
    assert_eq!(VeilError::EmptyBody.status_code(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn pii_unavailable_maps_to_bad_gateway_with_code() {
    // 熵源故障 fail-closed 码固定为 502 + E_PII_UNAVAILABLE，错误体形态不改。
    let response = VeilError::PiiUnavailable.into_response();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["error"]["code"], "E_PII_UNAVAILABLE");
}

#[test]
fn internal_error_defaults_to_500_without_secret_leak() {
    let secret = "sk-绝密-12345";
    let err = VeilError::internal(anyhow::anyhow!(secret).context("网关中段断连"));
    assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!format!("{response:?}").contains(secret));
}

#[tokio::test]
async fn keepass_error_public_message_is_generic() {
    // KeePass 500 对外仅固定文案，不回传 KDBX 路径/异常细节；错误码保留 E_KEEPASS。
    let err = VeilError::KeePass {
        message: "库文件 /data/db/secret.kdbx 解密失败".to_string(),
    };
    assert_eq!(err.code(), "E_KEEPASS");
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["error"]["code"], "E_KEEPASS");
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("/data/db"), "响应体不得含 KDBX 路径: {text}");
    assert!(!text.contains("解密失败"), "响应体不得含异常细节: {text}");
}

#[tokio::test]
async fn keepass_internal_error_logged_not_exposed() {
    // 回归：500 仍记 error 日志（可排障），响应体不含内部细节。
    let detail = "/data/db/vault.kdbx 解密失败";
    let capture = LogCapture::default();
    let sink = capture.0.clone();
    let response = crate::test_support::with_capture_subscriber(capture, || {
        VeilError::KeePass {
            message: detail.to_string(),
        }
        .into_response()
    });
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let lines = sink.lock().unwrap().clone();
    assert_eq!(lines.len(), 1, "500 须恰记一条 error 日志: {lines:?}");
    assert!(
        lines[0].starts_with("ERROR"),
        "500 须记 error 日志: {lines:?}"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("/data/db"), "响应体不得含 KDBX 路径");
    assert!(!text.contains("解密失败"), "响应体不得含异常细节");
}

#[test]
fn anyhow_context_chain_preserved() {
    let err = VeilError::internal(anyhow::anyhow!("根因").context("中间层").context("外层"));
    let debug = format!("{err:?}");
    assert!(debug.contains("根因") && debug.contains("中间层") && debug.contains("外层"));
}

#[tokio::test]
async fn error_response_body_carries_code() {
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

#[tokio::test]
async fn error_body_carries_error_detail_mirror() {
    let response = VeilError::Auth {
        message: "拒绝".to_string(),
    }
    .into_response();
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["error"]["message"], "拒绝");
    assert_eq!(value["error_detail"], "拒绝");
    assert!(value["error_detail"].is_string());
}

/// 测试内 tracing 捕获订阅者：记录每条事件的「级别 + 字段渲染文本」。
/// `record_str` 须显式实现，否则 `code` 字段不可见、内容断言会变空洞。
#[derive(Clone, Default)]
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

struct FieldVisitor<'a>(&'a mut String);

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={value}", field.name());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = event.metadata().level().to_string();
        event.record(&mut FieldVisitor(&mut line));
        self.0.lock().unwrap().push(line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

fn captured_level_and_status(err: VeilError) -> (Vec<String>, StatusCode) {
    let capture = LogCapture::default();
    let sink = capture.0.clone();
    let status =
        crate::test_support::with_capture_subscriber(capture, move || err.into_response().status());
    let lines = sink.lock().unwrap().clone();
    (lines, status)
}

#[test]
fn four_xx_logs_warn_five_xx_logs_error() {
    // 4xx（预期失败）→ warn，状态码与错误体不变。
    for err in [
        VeilError::NotFound {
            message: "条目未找到".to_string(),
        },
        VeilError::BadRequest {
            message: "请求非法".to_string(),
        },
        VeilError::Auth {
            message: "缺密钥".to_string(),
        },
        // 上游透传 4xx 同样按非 5xx 记 warn。
        VeilError::Upstream {
            status: 401,
            message: "上游直回".to_string(),
        },
    ] {
        let expected = err.status_code();
        let (lines, status) = captured_level_and_status(err);
        assert_eq!(status, expected);
        assert_eq!(lines.len(), 1, "{status}: {lines:?}");
        assert!(lines[0].starts_with("WARN"), "{status}: {lines:?}");
    }
    // 5xx → error（被告警规则捕获）。
    for err in [
        VeilError::Internal(anyhow::anyhow!("根因")),
        VeilError::Storage {
            message: "写失败".to_string(),
        },
        VeilError::Upstream {
            status: 502,
            message: "坏网关".to_string(),
        },
    ] {
        let expected = err.status_code();
        let (lines, status) = captured_level_and_status(err);
        assert_eq!(status, expected);
        assert_eq!(lines.len(), 1, "{status}: {lines:?}");
        assert!(lines[0].starts_with("ERROR"), "{status}: {lines:?}");
    }
    // 202 审批挂起非 5xx，记 warn 不误报。
    let (lines, status) = captured_level_and_status(VeilError::PendingApproval {
        message: "待审".to_string(),
    });
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("WARN"), "{lines:?}");
    // 非 5xx warn 行不得含用户可控 message（`error = ?self` 已移出 warn
    // 分支），静态 `code` 保留；5xx error 行仍保留内部细节（排障口径）。
    let user_text = "KeePass 条目 私人邮箱-9f3a 未找到";
    let (lines, status) = captured_level_and_status(VeilError::NotFound {
        message: user_text.to_string(),
    });
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("WARN"), "{lines:?}");
    assert!(
        lines[0].contains("E_NOT_FOUND"),
        "warn 行须保留静态 code: {lines:?}"
    );
    assert!(
        !lines[0].contains(user_text),
        "warn 行不得含用户可控 message: {lines:?}"
    );
    let detail = "/data/db/vault.kdbx 解密失败";
    let (lines, status) = captured_level_and_status(VeilError::KeePass {
        message: detail.to_string(),
    });
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("ERROR"), "{lines:?}");
    assert!(
        lines[0].contains(detail),
        "5xx error 行须保留内部细节: {lines:?}"
    );
}
