//! R8-03/D2 非流还原回退阶梯单测：守卫失败回退已掩码占位符帧（零新检出 PII
//! 明文、`restore_fallback` 恰 +1）；掩码回退本身失败（熵源故障）→ 502
//! `E_PII_UNAVAILABLE` fail-closed，MUST NOT 回退未掩码正文。

use {
    super::test_ctx,
    crate::{
        error::VeilError,
        handler::llm::nonstream::restore_ladder,
        service::llm_gateway::{GatewayMetrics, Protocol},
    },
    axum::{body::to_bytes, http::StatusCode, response::IntoResponse},
    serde_json::Value,
    std::sync::Arc,
};

#[tokio::test]
async fn guard_failure_falls_back_to_masked_placeholder() {
    // 阶梯③：守卫破裂（`retry_stripped` 不可挽回）→ 回退已掩码占位符帧。
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = test_ctx(Protocol::Chat);
    ctx.req.gateway_metrics = metrics.clone();
    let phone = "13812345678";
    let placeholder = format!(r#"{{"content":"{phone}"}}"#);
    let broken = r#"{"content":"ab"cd"}"#.to_string();
    let out = restore_ladder(&ctx.req, broken, &placeholder)
        .await
        .expect("掩码回退须成功");
    assert!(!out.contains(phone), "零新检出 PII 明文: {out}");
    assert!(out.contains("__PII_"), "须为响应侧掩码 token: {out}");
    assert!(
        serde_json::from_str::<Value>(&out).is_ok(),
        "掩码回退体须合法 JSON: {out}"
    );
    assert_eq!(metrics.restore_fallback_count(), 1, "回退须恰 +1");
}

#[tokio::test]
async fn mask_fallback_failure_returns_pii_unavailable_502() {
    // 阶梯④：掩码回退本身失败（PII 注册熵源故障）→ `E_PII_UNAVAILABLE` 502。
    let ctx = test_ctx(Protocol::Chat);
    ctx.req.scope.pii_scope().force_entropy_failure(true);
    let placeholder = r#"{"content":"13812345678"}"#;
    let broken = r#"{"content":"ab"cd"}"#.to_string();
    let err = restore_ladder(&ctx.req, broken, placeholder)
        .await
        .expect_err("掩码回退失败须 fail-closed");
    assert!(
        matches!(err, VeilError::PiiUnavailable),
        "须 PiiUnavailable: {err:?}"
    );
    assert!(ctx.req.scope.pii_unavailable(), "熵源故障须置位");
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "须 502");
    let body = to_bytes(resp.into_body(), 4096)
        .await
        .expect("错误体须可读");
    assert!(
        String::from_utf8_lossy(&body).contains("E_PII_UNAVAILABLE"),
        "错误码须具名: {}",
        String::from_utf8_lossy(&body)
    );
}
