//! 请求改写单元（2.1）：纯函数改写，不触网络。

use {
    crate::{
        config::{Config, effective_placeholder_prompt},
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{self, Protocol, is_stream_body},
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    serde_json::Value,
    std::sync::Arc,
};

/// `request_rewrite` 的输出：改写后请求体 + 声明头（纯数据，不触网络）。
pub struct RewriteOutput {
    /// 改写后请求体（默认与输入字节等价，仅 token 子串替换/注入时变化）。
    pub body: Vec<u8>,
    /// 是否做了空白归一化（下游以 `x-veil-normalized` 声明）。
    pub normalized_out: bool,
    /// 客户端是否要求流式（`stream: true`）。
    pub stream_flag: bool,
    /// 改写后请求体中的会话标识（供阻断帧/截断帧复用）。
    pub init_conv: Option<String>,
}

/// 2.1 `request_rewrite` 纯改写：仅做 token 子串替换、stream 选项注入、
/// 占位符说明注入与声明头计算，MUST NOT 发起任何网络 I/O。
/// 仅在对话路径调用（`is_chat` 恒为真，保持原 `should_inject_placeholders(true, ..)` 语义）。
pub async fn request_rewrite(
    body_bytes: Vec<u8>,
    protocol: Protocol,
    config: &Config,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
) -> RewriteOutput {
    let original_valid = std::str::from_utf8(&body_bytes).is_ok();
    let original_text = String::from_utf8_lossy(&body_bytes).into_owned();
    let mut body_value: Option<Value> = serde_json::from_slice(&body_bytes).ok();
    let mut normalized_out = false;
    let mut body_bytes = body_bytes;
    let mut redacted_text = original_text.clone();
    if llm_gateway::should_inject_placeholders(
        true,
        config.redaction_enabled,
        !body_bytes.is_empty(),
    ) {
        redacted_text = scope
            .redact_request(&vault, &detector, &original_text)
            .await;
    }
    let need_inject = body_value
        .as_ref()
        .is_some_and(|v| llm_gateway::should_inject_stream_options(protocol, v));
    if need_inject {
        normalized_out = config.normalize_json_whitespace;
        if let Ok(mut v) = serde_json::from_str::<Value>(&redacted_text) {
            llm_gateway::inject_stream_options(&mut v);
            body_value = Some(v);
            body_bytes = serde_json::to_vec(body_value.as_ref().expect("刚注入的请求体"))
                .unwrap_or_default();
        } else if let Some(v) = body_value.as_ref() {
            body_bytes = serde_json::to_vec(v).unwrap_or_default();
        }
    } else if redacted_text != original_text && original_valid {
        body_bytes = redacted_text.into_bytes();
    } else if config.normalize_json_whitespace
        && let Some(v) = body_value.as_ref()
    {
        body_bytes = serde_json::to_vec(v).unwrap_or_default();
        normalized_out = true;
    }
    let stream_flag: bool = serde_json::from_slice::<Value>(&body_bytes)
        .ok()
        .as_ref()
        .is_some_and(is_stream_body)
        || body_value.as_ref().is_some_and(is_stream_body);
    if config.placeholder_prompt_enabled
        && llm_gateway::has_placeholder_tokens(&body_bytes)
        && let Ok(text) = std::str::from_utf8(&body_bytes)
        && let Some(injected) = llm_gateway::inject_placeholder_prompt(
            text,
            effective_placeholder_prompt(&config.placeholder_prompt_text),
            protocol,
        )
    {
        body_bytes = injected.into_bytes();
    }
    let init_conv = body_value.as_ref().and_then(llm_gateway::extract_conv_id);
    RewriteOutput {
        body: body_bytes,
        normalized_out,
        stream_flag,
        init_conv,
    }
}
