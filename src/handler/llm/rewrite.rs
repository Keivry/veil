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
        // L15：注入即声明——本分支恒经 `to_vec` 重序列化（上下两子分支皆然），
        // 输出恒为紧凑 JSON，与配置开关无关，故无条件置位。
        normalized_out = true;
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
        // D1 方案 A（veil-review-llm-edge）：占位符说明注入经 `inject_placeholder_prompt`
        // 内部 `to_string` 紧凑重序列化，字节已非等价，故置位 `normalized_out`
        //（README §7.7 置位条件③），下游按同一标志声明 `x-veil-normalized`。
        body_bytes = injected.into_bytes();
        normalized_out = true;
    }
    let init_conv = body_value.as_ref().and_then(llm_gateway::extract_conv_id);
    RewriteOutput {
        body: body_bytes,
        normalized_out,
        stream_flag,
        init_conv,
    }
}

#[cfg(test)]
mod rewrite_unit_tests {
    use {
        super::request_rewrite,
        crate::{
            config::Config,
            service::{
                credential_vault::CredentialVault,
                llm_gateway::Protocol,
                pii::PiiDetector,
                redaction::Scope,
            },
        },
        std::{collections::HashMap, sync::Arc},
    };

    fn base_env() -> HashMap<String, String> {
        HashMap::from([
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
        ])
    }

    fn test_config(extra: &[(&str, &str)]) -> Config {
        let mut env = base_env();
        for (k, v) in extra {
            env.insert((*k).to_string(), (*v).to_string());
        }
        Config::load_from(&env).expect("测试配置须合法")
    }

    fn fresh_arcs() -> (Arc<Scope>, Arc<CredentialVault>, Arc<PiiDetector>) {
        (
            Arc::new(Scope::new()),
            Arc::new(CredentialVault::new()),
            Arc::new(PiiDetector::new()),
        )
    }

    #[tokio::test]
    async fn rewrite_stream_options_key_merge_preserves_user_keys() {
        // T1：用户自带 stream_options 其他键时按 key 合并，只补 include_usage。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","stream":true,"stream_options":{"other":1},"messages":[]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert!(out.stream_flag);
        assert!(out.normalized_out, "注入即重序列化，须声明 normalized");
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(v["stream_options"]["include_usage"], true);
        assert_eq!(v["stream_options"]["other"], 1);
    }

    #[tokio::test]
    async fn rewrite_stream_options_existing_false_not_overwritten() {
        // T1：既有 include_usage=false 不得被覆盖为 true（按 key 合并）。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{"model":"m","stream":true,"stream_options":{"include_usage":false},"messages":[]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(v["stream_options"]["include_usage"], false);
    }

    #[tokio::test]
    async fn rewrite_stream_options_non_object_replaced() {
        // T1：stream_options 非对象形态整体替换为 include_usage。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","stream":true,"stream_options":"yes","messages":[]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(v["stream_options"]["include_usage"], true);
    }

    #[tokio::test]
    async fn rewrite_anthropic_never_injects_stream_options() {
        // T1：Anthropic 协议永不注入 stream_options。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","stream":true,"messages":[]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Anthropic,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap_or_default();
        assert!(
            v.get("stream_options").is_none(),
            "Anthropic 不得注入 stream_options"
        );
    }

    #[tokio::test]
    async fn rewrite_placeholder_three_conditions_gate_injection() {
        // T1：占位符三条件仅门控 redact_request；占位符说明注入走独立门控
        // （placeholder_prompt_enabled + 体内含 token），脱敏关闭时仍注入。
        let config = test_config(&[("REDACTION_ENABLED", "0")]);
        assert!(!config.redaction_enabled);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(v["messages"][0]["role"], "system");
        // 无 token 体则不注入（占位符门控另一半）。
        let (scope, vault, detector) = fresh_arcs();
        let plain = br#"{"model":"m","messages":[{"role":"user","content":"hello"}]}"#;
        let out2 = request_rewrite(
            plain.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v2: serde_json::Value = serde_json::from_slice(&out2.body).expect("合法 JSON");
        assert_eq!(v2["messages"][0]["role"], "user");
    }

    #[tokio::test]
    async fn rewrite_placeholder_prompt_injected_when_tokens_present() {
        // T1：占位符三条件全满足 + 体内含 token → 注入说明（messages 首条 system）。
        let config = test_config(&[]);
        assert!(config.placeholder_prompt_enabled);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(v["messages"][0]["role"], "system");
    }

    #[tokio::test]
    async fn rewrite_placeholder_injection_declares_normalized_d1a() {
        // E3/D1 方案 A 锁定：占位符说明注入（紧凑重序列化）须置位 normalized_out。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(v["messages"][0]["role"], "system", "须已注入占位符说明");
        assert!(
            out.normalized_out,
            "D1 方案 A：注入分支须声明 normalized_out"
        );
    }

    #[tokio::test]
    async fn rewrite_pure_redaction_byte_replace_keeps_normalized_false_e13() {
        // E13/D2 锁定：纯脱敏字节替换（未重序列化）即使长度变化也不置位；
        // 关闭占位符注入以隔离纯替换分支。
        let config = test_config(&[("PII_PLACEHOLDER_PROMPT", "0")]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","messages":[{"role":"user","content":"call 13812345678"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert!(!out.normalized_out, "纯字节替换不得置位 normalized_out");
        assert_ne!(
            out.body.len(),
            raw.len(),
            "脱敏替换前后长度须不同（否则本用例无回归价值）"
        );
        assert!(
            String::from_utf8_lossy(&out.body).contains("__PII_"),
            "须已发生脱敏替换"
        );
    }

    #[tokio::test]
    async fn rewrite_empty_body_passthrough_without_network() {
        // T1：改写纯函数不触网——空体直接透传（签名无 client/upstream 参数即证明）。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let out = request_rewrite(vec![], Protocol::Chat, &config, scope, vault, detector).await;
        assert!(out.body.is_empty());
        assert!(!out.normalized_out);
        assert!(!out.stream_flag);
    }

    #[tokio::test]
    async fn rewrite_invalid_json_passthrough_byte_identical() {
        // T1：非法 JSON 原文字节透传，不触网、不抛错。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = b"not json at all {{{".to_vec();
        let out =
            request_rewrite(raw.clone(), Protocol::Chat, &config, scope, vault, detector).await;
        assert_eq!(out.body, raw);
        assert!(!out.normalized_out);
    }

    #[tokio::test]
    async fn rewrite_whitespace_flag_off_keeps_bytes() {
        // T1：空白归一开关关闭时带空格 JSON 字节等价（除 token 替换外）。
        let config = test_config(&[]);
        assert!(!config.normalize_json_whitespace);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{ "model" : "m" , "messages" : [ { "role" : "user" , "content" : "hello" } ] }"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert_eq!(out.body, raw);
        assert!(!out.normalized_out);
    }

    #[tokio::test]
    async fn rewrite_whitespace_flag_on_compacts_and_declares() {
        // T1：空白归一开关开启（仅 "1"）时压缩为空白无关紧凑 JSON 并声明。
        let config = test_config(&[("NORMALIZE_JSON_WHITESPACE", "1")]);
        assert!(config.normalize_json_whitespace);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{ "model" : "m" , "messages" : [ { "role" : "user" , "content" : "hello" } ] }"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert!(out.normalized_out);
        assert!(!out.body.contains(&b' '));
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(v["model"], "m");
    }

    #[tokio::test]
    async fn rewrite_nondialog_passthrough_without_stream_options() {
        // T1：NonDialog 路径不注入 stream_options（协议守门）。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","stream":true}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::NonDialog,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap_or_default();
        assert!(v.get("stream_options").is_none());
    }

    #[tokio::test]
    async fn rewrite_conv_id_extracted_for_block_reuse() {
        // T1：改写输出 init_conv 供阻断帧/截断帧复用（chat 取 id 字段）。
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"id":"chatcmpl-123","model":"m","messages":[]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert_eq!(out.init_conv.as_deref(), Some("chatcmpl-123"));
    }

    #[tokio::test]
    async fn rewrite_t3_chat_true_injection_integration() {
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("合法 JSON");
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn rewrite_t3_anthropic_true_injection_integration() {
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","system":"base","messages":[{"role":"user","content":"hi __VG_CRED_000001__"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Anthropic,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("合法 JSON");
        assert!(v["system"].as_str().unwrap().contains("base"));
        assert_ne!(v["system"].as_str().unwrap(), "base");
    }

    #[tokio::test]
    async fn rewrite_t3_responses_true_injection_integration() {
        let config = test_config(&[]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","input":"hi __PII_2_cd34ab12__"}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Responses,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("合法 JSON");
        assert!(v["input"].as_str().unwrap().contains("hi"));
        assert_ne!(v["input"].as_str().unwrap(), "hi __PII_2_cd34ab12__");
    }

    #[tokio::test]
    async fn rewrite_t3_disabled_switch_no_injection() {
        let config = test_config(&[("PII_PLACEHOLDER_PROMPT", "0")]);
        assert!(!config.placeholder_prompt_enabled);
        let (scope, vault, detector) = fresh_arcs();
        let raw =
            br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out.body).expect("合法 JSON");
        assert_eq!(v["messages"][0]["role"], "user");
    }
}
