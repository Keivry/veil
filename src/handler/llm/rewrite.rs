//! 请求改写单元：纯函数改写，不触网络。

use {
    crate::{
        config::{Config, UpstreamOverrides, effective_placeholder_prompt},
        service::{
            credential_vault::CredentialVault,
            json_walk,
            llm_gateway::{self, Protocol, is_stream_body},
            pii::PiiDetector,
            redaction::{Scope, leaf::RedactionTally},
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
    /// 请求侧三项脱敏计数（透传至 `RequestCtx` 完成点，禁止重算）。
    pub tally: RedactionTally,
}

/// 生产请求体 JSON 解析统一经中央 `json_walk`——先按 UTF-8
/// 解码再剥前导 BOM，使 BOM 前缀体与非 BOM 体解析结果一致（不再落解析失败回退）。
fn parse_body_json(bytes: &[u8]) -> Option<Value> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| json_walk::jloads(json_walk::strip_bom(s)).ok())
}

/// 请求体重序列化安全编码：成功返回紧凑 JSON 字节；理论不可达的失败路径记一次
/// warn 并返回 `None`，调用方据此**保留原字节**（绝不静默产出空体）。
fn encode_json_body(value: &Value) -> Option<Vec<u8>> {
    match serde_json::to_vec(value) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            tracing::warn!(error = %err, "请求体 JSON 重序列化失败，保留原字节（不改写）");
            None
        }
    }
}

/// `body_value` 兜底编码：失败时退化为空体（保留既有 no-forwardable-content 语义）。
fn encode_json_or_empty(value: &Value) -> Vec<u8> {
    if let Some(bytes) = encode_json_body(value) {
        return bytes;
    }
    Vec::new()
}

/// `request_rewrite` 兼容入口：无目标覆盖（等价未声明 `[llm.targets]`），
/// 逐字保持既有行为；需要参数注入的调用方 SHALL 使用
/// [`request_rewrite_with_overrides`]。
pub async fn request_rewrite(
    body_bytes: Vec<u8>,
    protocol: Protocol,
    config: &Config,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
) -> RewriteOutput {
    request_rewrite_with_overrides(body_bytes, protocol, config, scope, vault, detector, None).await
}

/// `request_rewrite` 纯改写：仅做 token 子串替换、stream 选项注入、
/// 占位符说明注入、目标参数注入与声明头计算，MUST NOT 发起任何网络 I/O。
/// 仅在对话路径调用（`is_chat` 恒为真，保持原 `should_inject_placeholders(true, ..)` 语义）。
/// `overrides` 为单次 `resolve_target` 命中的同源覆盖；redact-only（count_tokens）
/// 调用方以 `None` 收窄，从而不注入 `params`（headers 注入不受此限）。
pub async fn request_rewrite_with_overrides(
    body_bytes: Vec<u8>,
    protocol: Protocol,
    config: &Config,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
    overrides: Option<&UpstreamOverrides>,
) -> RewriteOutput {
    let original_valid = std::str::from_utf8(&body_bytes).is_ok();
    let original_text = String::from_utf8_lossy(&body_bytes).into_owned();
    let body_value: Option<Value> = parse_body_json(&body_bytes);
    let mut normalized_out = false;
    let mut body_bytes = body_bytes;
    let mut redacted_text = original_text.clone();
    let mut redacted_reserialized = false;
    let mut tally = RedactionTally::default();
    if llm_gateway::should_inject_placeholders(
        true,
        config.redaction_enabled,
        !body_bytes.is_empty(),
    ) {
        // 报告「是否经 loads→walk→dumps 重序列化」，据此诚实置位声明头。
        // 请求侧报告同时携带三项计数，透传至完成点。
        let (text, reserialized, counts) = scope
            .redact_request_with_report_and_counts(&vault, &detector, &original_text)
            .await;
        redacted_text = text;
        redacted_reserialized = reserialized;
        tally = counts;
    }
    let need_inject = body_value
        .as_ref()
        .is_some_and(|v| llm_gateway::should_inject_stream_options(protocol, v));
    if need_inject {
        // 注入分支回退决策纯函数——重解析失败回退转发**脱敏字节**
        //（fail-closed，绝不回落未脱敏原文）；`normalized_out` 仅成功重序列化置位。
        let (bytes, normalized) =
            apply_stream_options_injection(&redacted_text, original_valid, body_value.as_ref());
        body_bytes = bytes;
        normalized_out = normalized;
    } else if redacted_text != original_text && original_valid {
        body_bytes = redacted_text.into_bytes();
        normalized_out = redacted_reserialized;
    } else if config.normalize_json_whitespace
        && let Some(v) = body_value.as_ref()
        && let Some(bytes) = encode_json_body(v)
    {
        body_bytes = bytes;
        normalized_out = true;
    }
    let stream_flag: bool = parse_body_json(&body_bytes)
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
        // 方案 A：占位符说明注入经 `inject_placeholder_prompt`
        // 内部 `to_string` 紧凑重序列化，字节已非等价，故置位 `normalized_out`
        //（工程参考 §7.7 置位条件③），下游按同一标志声明 `x-veil-normalized`。
        body_bytes = injected.into_bytes();
        normalized_out = true;
    }
    // 目标参数注入（design D4/D6/D7）：在脱敏替换与占位符说明注入**之后**、最终体
    // 确定之前执行；参数值为配置原文（不参与脱敏），已铸造的占位符 token 与说明
    // 不被改写。仅当协议命中 `params` 子表、请求体可解析为 JSON 对象且三段覆盖
    // 实际改变对象时紧凑重序列化并置位 `normalized_out`（与 stream_options 注入
    // 同口径）；非对象体或未发生变化时保持字节与标志不变，绝不拒绝请求。
    // 冲突策略随目标命中（`override_existing`）：恒胜（缺省）或合并（仅补缺）。
    let override_existing = overrides.is_none_or(|o| o.override_existing);
    let param_rules = llm_gateway::matched_params(overrides, protocol);
    if let Some(rules) = param_rules
        && let Some(mut value) = parse_body_json(&body_bytes)
        && value.as_object_mut().is_some_and(|object| {
            llm_gateway::apply_param_overrides(object, rules, override_existing)
        })
        && let Some(bytes) = encode_json_body(&value)
    {
        body_bytes = bytes;
        normalized_out = true;
    }
    let init_conv = body_value.as_ref().and_then(llm_gateway::extract_conv_id);
    RewriteOutput {
        body: body_bytes,
        normalized_out,
        stream_flag,
        init_conv,
        tally,
    }
}

/// 注入分支回退决策（纯函数）：重解析 `redacted_text` 成功 → 注入
/// `stream_options` 并紧凑重序列化（`(bytes, true)`）；序列化失败（理论不可达）→
/// 不返回空体，落入下方「原文有效 → 转发脱敏字节」回退（fail-closed，绝不外泄原文）；
/// 重解析失败且原文有效 → 转发**脱敏字节**且不置位；原文无效 →
/// 回退 `body_value` 序列化（既有行为）且不置位。
fn apply_stream_options_injection(
    redacted_text: &str,
    original_valid: bool,
    body_value: Option<&Value>,
) -> (Vec<u8>, bool) {
    if let Ok(mut v) = json_walk::jloads(json_walk::strip_bom(redacted_text)) {
        llm_gateway::inject_stream_options(&mut v);
        if let Some(bytes) = encode_json_body(&v) {
            return (bytes, true);
        }
    }
    if original_valid {
        return (redacted_text.as_bytes().to_vec(), false);
    }
    match body_value {
        Some(v) => (encode_json_or_empty(v), false),
        None => (Vec::new(), false),
    }
}

#[cfg(test)]
mod tests;
