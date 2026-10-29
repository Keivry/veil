use {
    super::{request_rewrite, request_rewrite_with_overrides},
    crate::{
        config::{HeaderValueSpec, ParamOverrides, ParamProtocol, UpstreamOverrides},
        handler::llm::test_support::test_config,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::Protocol,
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    std::{collections::BTreeMap, sync::Arc},
};

/// 构造单协议三段覆盖（测试用）。
fn params_for(
    protocol: ParamProtocol,
    default: &[(&str, serde_json::Value)],
    override_: &[(&str, serde_json::Value)],
    drop: &[&str],
) -> UpstreamOverrides {
    let rules = ParamOverrides {
        default: default
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect(),
        r#override: override_
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect(),
        drop: drop.iter().map(|key| (*key).to_string()).collect(),
    };
    UpstreamOverrides {
        headers: axum::http::HeaderMap::<HeaderValueSpec>::with_capacity(0),
        params: BTreeMap::from([(protocol, rules)]),
        override_existing: true,
        user_agent: None,
        drop_headers: Vec::new(),
    }
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
    // 用户自带 stream_options 其他键时按 key 合并，只补 include_usage。
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
    // 既有 include_usage=false 不得被覆盖为 true（按 key 合并）。
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
    // stream_options 非对象形态整体替换为 include_usage。
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
async fn rewrite_stream_options_null_preserved() {
    // 显式 null 不进注入分支，转发体保留 `"stream_options": null`。
    let config = test_config(&[]);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","stream":true,"stream_options":null,"messages":[]}"#;
    let out = request_rewrite(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
    )
    .await;
    let v: serde_json::Value = serde_json::from_slice(&out.body).expect("转发体须为合法 JSON");
    assert!(v["stream_options"].is_null(), "null 须保留: {v}");
    assert!(!out.normalized_out, "未注入不得置位 normalized");
}

#[tokio::test]
async fn rewrite_anthropic_never_injects_stream_options() {
    // Anthropic 协议永不注入 stream_options。
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
    // 占位符三条件仅门控 redact_request；占位符说明注入走独立门控
    // （placeholder_prompt_enabled + 体内含 token），脱敏关闭时仍注入。
    let config = test_config(&[("REDACTION_ENABLED", "0")]);
    assert!(!config.redaction_enabled);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
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
    // 占位符三条件全满足 + 体内含 token → 注入说明（messages 首条 system）。
    let config = test_config(&[]);
    assert!(config.placeholder_prompt_enabled);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
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
    // 方案 A 锁定：占位符说明注入（紧凑重序列化）须置位 normalized_out。
    let config = test_config(&[]);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
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
    assert!(out.normalized_out, "注入分支须声明 normalized_out");
}

#[tokio::test]
async fn rewrite_pure_redaction_byte_replace_keeps_normalized_false_e13() {
    // 锁定：非 JSON 纯文本的字节级替换（未重序列化）不置位；
    // 关闭占位符注入以隔离纯替换分支。
    let config = test_config(&[("PII_PLACEHOLDER_PROMPT", "0")]);
    let (scope, vault, detector) = fresh_arcs();
    let raw = b"call 13812345678 now".to_vec();
    let out = request_rewrite(raw.clone(), Protocol::Chat, &config, scope, vault, detector).await;
    assert!(
        !out.normalized_out,
        "非 JSON 字节替换不得置位 normalized_out"
    );
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
async fn request_json_redaction_declares_normalized() {
    // JSON 容器脱敏经 loads→walk→dumps 重序列化，须置位
    // `normalized_out`（handler 据此输出 `x-veil-normalized: json-whitespace`）。
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
    assert!(out.normalized_out, "JSON 脱敏重序列化须置位");
    let text = String::from_utf8_lossy(&out.body).into_owned();
    assert!(text.contains("__PII_"), "须已脱敏: {text}");
    assert!(
        text.find("\"model\"") < text.find("\"messages\""),
        "重序列化键序须保持: {text}"
    );
}

#[tokio::test]
async fn rewrite_empty_body_passthrough_without_network() {
    // 改写纯函数不触网——空体直接透传（签名无 client/upstream 参数即证明）。
    let config = test_config(&[]);
    let (scope, vault, detector) = fresh_arcs();
    let out = request_rewrite(vec![], Protocol::Chat, &config, scope, vault, detector).await;
    assert!(out.body.is_empty());
    assert!(!out.normalized_out);
    assert!(!out.stream_flag);
}

#[tokio::test]
async fn rewrite_invalid_json_passthrough_byte_identical() {
    // 非法 JSON 原文字节透传，不触网、不抛错。
    let config = test_config(&[]);
    let (scope, vault, detector) = fresh_arcs();
    let raw = b"not json at all {{{".to_vec();
    let out = request_rewrite(raw.clone(), Protocol::Chat, &config, scope, vault, detector).await;
    assert_eq!(out.body, raw);
    assert!(!out.normalized_out);
}

#[tokio::test]
async fn rewrite_whitespace_flag_off_keeps_bytes() {
    // 空白归一开关关闭时带空格 JSON 字节等价（除 token 替换外）。
    let config = test_config(&[]);
    assert!(!config.normalize_json_whitespace);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{ "model" : "m" , "messages" : [ { "role" : "user" , "content" : "hello" } ] }"#;
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
    // 空白归一开关开启（仅 "1"）时压缩为空白无关紧凑 JSON 并声明。
    let config = test_config(&[("PII_NORMALIZE_JSON_WHITESPACE", "1")]);
    assert!(config.normalize_json_whitespace);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{ "model" : "m" , "messages" : [ { "role" : "user" , "content" : "hello" } ] }"#;
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
    // NonDialog 路径不注入 stream_options（协议守门）。
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
    // 改写输出 init_conv 供阻断帧/截断帧复用（chat 取 id 字段）。
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
    let raw = br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
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
    let raw = br#"{"model":"m","system":"base","messages":[{"role":"user","content":"hi __CRED_000001__"}]}"#;
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
async fn rewrite_t3_responses_no_injection_bytes_preserved() {
    // Responses stream:true 不注入 stream_options，非脱敏路径字节等价。
    let config = test_config(&[]);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","stream":true,"input":"hi"}"#;
    let out = request_rewrite(
        raw.to_vec(),
        Protocol::Responses,
        &config,
        scope,
        vault,
        detector,
    )
    .await;
    assert!(out.stream_flag, "stream 意图仍须识别");
    assert_eq!(out.body, raw, "Responses 不得注入，字节须等价");
    assert!(!out.normalized_out, "未重序列化不得声明 normalized");
    let v: serde_json::Value = serde_json::from_slice(&out.body).expect("合法 JSON");
    assert!(
        v.get("stream_options").is_none(),
        "Responses 不得出现 stream_options"
    );
}

#[tokio::test]
async fn rewrite_t3_responses_user_stream_options_preserved() {
    // Responses 用户自带 stream_options 须逐字节保留，不合并/替换。
    let config = test_config(&[]);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","stream":true,"stream_options":{"include_obfuscation":false},"input":"hi"}"#;
    let out = request_rewrite(
        raw.to_vec(),
        Protocol::Responses,
        &config,
        scope,
        vault,
        detector,
    )
    .await;
    assert_eq!(
        out.body, raw,
        "用户自带 stream_options 须逐字节保留，不注入 include_usage"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.body).expect("合法 JSON");
    assert_eq!(v["stream_options"]["include_obfuscation"], false);
    assert!(v["stream_options"].get("include_usage").is_none());
    assert!(!out.normalized_out);
}

#[tokio::test]
async fn rewrite_t3_disabled_switch_no_injection() {
    let config = test_config(&[("PII_PLACEHOLDER_PROMPT", "0")]);
    assert!(!config.placeholder_prompt_enabled);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","messages":[{"role":"user","content":"hi __PII_1_ab12cd34__"}]}"#;
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

#[tokio::test]
async fn bom_prefixed_request_body_parses_like_non_bom() {
    // 带前导 BOM 的请求体经中央 `strip_bom`/`jloads` 正常解析——
    // stream 意图识别与 stream_options 注入与同字节无 BOM 体一致。
    let config = test_config(&[("REDACTION_ENABLED", "0"), ("PII_PLACEHOLDER_PROMPT", "0")]);
    let (scope, vault, detector) = fresh_arcs();
    let plain = br#"{"model":"m","stream":true,"messages":[]}"#.to_vec();
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(&plain);
    let out_plain = request_rewrite(plain, Protocol::Chat, &config, scope, vault, detector).await;
    let (scope, vault, detector) = fresh_arcs();
    let out_bom = request_rewrite(bom, Protocol::Chat, &config, scope, vault, detector).await;
    assert!(out_bom.stream_flag, "BOM 前缀体 stream 意图须识别");
    assert_eq!(
        out_bom.stream_flag, out_plain.stream_flag,
        "BOM 体与非 BOM 体 stream_flag 须一致"
    );
    let v: serde_json::Value = serde_json::from_slice(&out_bom.body).expect("注入后须合法 JSON");
    assert_eq!(v["stream_options"]["include_usage"], true);
    assert_eq!(
        out_bom.body, out_plain.body,
        "BOM 体解析结果须与无 BOM 体一致"
    );
}

#[tokio::test]
async fn bom_prefixed_request_body_redacts_and_parses() {
    // BOM 前缀请求体不再落 `body_value=None` 回退，脱敏与解析均正常。
    let config = test_config(&[("PII_PLACEHOLDER_PROMPT", "0")]);
    let (scope, vault, detector) = fresh_arcs();
    let mut raw = vec![0xEF, 0xBB, 0xBF];
    raw.extend_from_slice(
        br#"{"model":"m","messages":[{"role":"user","content":"call 13812345678"}]}"#,
    );
    let out = request_rewrite(raw, Protocol::Chat, &config, scope, vault, detector).await;
    assert!(out.normalized_out, "BOM 体 JSON 脱敏重序列化须置位");
    let text = String::from_utf8_lossy(&out.body).into_owned();
    assert!(text.contains("__PII_"), "BOM 体须已脱敏: {text}");
}

#[test]
fn redaction_fallback_never_emits_unredacted() {
    // 重解析失败时回退转发脱敏字节——含占位符、不含原文，
    // `x-veil-normalized` 不置位（未成功重序列化）。
    let original = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "secret-original-13812345678"}]
    });
    let redacted = r#"{"model":"m","messages":[{"role":"user","content":"__PII_1_ab12cd34__""#;
    let (bytes, normalized) =
        super::apply_stream_options_injection(redacted, true, Some(&original));
    let text = String::from_utf8(bytes).expect("回退字节须可读");
    assert!(text.contains("__PII_1_ab12cd34__"), "须含占位符: {text}");
    assert!(!text.contains("secret-original"), "不得外泄原文: {text}");
    assert!(!normalized, "未重序列化不得置位 normalized");
}

#[test]
fn redaction_fallback() {
    // 三场景：正常注入、重解析失败（original_valid）、original_valid=false。
    let v = serde_json::json!({"model": "m", "stream": true});
    let (bytes, normalized) =
        super::apply_stream_options_injection(r#"{"model":"m","stream":true}"#, true, Some(&v));
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("须合法 JSON");
    assert_eq!(parsed["stream_options"]["include_usage"], true);
    assert!(normalized, "成功重序列化须置位");
    let (bytes2, normalized2) = super::apply_stream_options_injection("{ broken", true, Some(&v));
    assert_eq!(bytes2, b"{ broken", "须回退脱敏字节");
    assert!(!normalized2, "重解析失败不得置位");
    let (bytes3, normalized3) = super::apply_stream_options_injection("{ broken", false, Some(&v));
    let parsed3: serde_json::Value = serde_json::from_slice(&bytes3).expect("须合法 JSON");
    assert_eq!(parsed3["model"], "m");
    assert!(!normalized3, "回退序列化不得置位");
}

#[tokio::test]
async fn param_injection_applies_three_sections_and_declares_normalized() {
    // task 4.1/4.2：default 缺则补 → override 恒写 → drop 删顶层键；
    // 实际改写须紧凑重序列化并置位 `normalized_out`（与 stream_options 同口径）。
    let config = test_config(&[("REDACTION_ENABLED", "0"), ("PII_PLACEHOLDER_PROMPT", "0")]);
    let overrides = params_for(
        ParamProtocol::Chat,
        &[
            ("top_p", serde_json::json!(0.9)),
            ("temperature", serde_json::json!(0.3)),
        ],
        &[
            ("temperature", serde_json::json!(0.7)),
            ("reasoning_effort", serde_json::json!("high")),
        ],
        &["service_tier"],
    );
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","temperature":0.1,"service_tier":"auto","messages":[]}"#;
    let out = request_rewrite_with_overrides(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
        Some(&overrides),
    )
    .await;
    assert!(out.normalized_out, "参数注入改写须置位 normalized_out");
    let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后须为合法 JSON");
    assert_eq!(
        v["temperature"],
        serde_json::json!(0.7),
        "override 须胜 default"
    );
    assert_eq!(v["top_p"], serde_json::json!(0.9), "default 须补齐缺失键");
    assert_eq!(v["reasoning_effort"], serde_json::json!("high"));
    assert!(v.get("service_tier").is_none(), "drop 须删除顶层键");
    assert_eq!(v["model"], "m", "未涉及键须保留");
}

#[tokio::test]
async fn param_injection_protocol_mismatch_keeps_bytes_and_flag() {
    // 仅声明 anthropic 而请求为 chat：协议不匹配不注入，字节与标志不变。
    let config = test_config(&[("REDACTION_ENABLED", "0"), ("PII_PLACEHOLDER_PROMPT", "0")]);
    let overrides = params_for(
        ParamProtocol::Anthropic,
        &[],
        &[("thinking", serde_json::json!({"type": "enabled"}))],
        &[],
    );
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","messages":[]}"#;
    let out = request_rewrite_with_overrides(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
        Some(&overrides),
    )
    .await;
    assert_eq!(out.body, raw, "协议不匹配须逐字节不变");
    assert!(!out.normalized_out, "未改写不得置位");
}

#[tokio::test]
async fn param_injection_non_object_bodies_skipped_without_reject() {
    // 非法 JSON / 数组 / 标量 / null：跳过注入、不拒绝请求、字节不变。
    let config = test_config(&[("REDACTION_ENABLED", "0"), ("PII_PLACEHOLDER_PROMPT", "0")]);
    let overrides = params_for(
        ParamProtocol::Chat,
        &[],
        &[("temperature", serde_json::json!(0.7))],
        &[],
    );
    for raw in [
        b"not json at all {{{".to_vec(),
        b"[1,2,3]".to_vec(),
        b"42".to_vec(),
        b"\"scalar\"".to_vec(),
        b"null".to_vec(),
        Vec::new(),
    ] {
        let (scope, vault, detector) = fresh_arcs();
        let expected = raw.clone();
        let out = request_rewrite_with_overrides(
            raw,
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
            Some(&overrides),
        )
        .await;
        assert_eq!(out.body, expected, "非对象体须逐字节不变: {expected:?}");
        assert!(!out.normalized_out, "跳过注入不得置位: {expected:?}");
    }
}

#[tokio::test]
async fn param_injection_noop_keeps_bytes_and_flag() {
    // default 键已存在且值相同：无实际变化 → 不重序列化、字节逐字不变。
    let config = test_config(&[("REDACTION_ENABLED", "0"), ("PII_PLACEHOLDER_PROMPT", "0")]);
    let overrides = params_for(
        ParamProtocol::Chat,
        &[("temperature", serde_json::json!(0.7))],
        &[],
        &[],
    );
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","temperature":0.7,"messages":[]}"#;
    let out = request_rewrite_with_overrides(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
        Some(&overrides),
    )
    .await;
    assert_eq!(out.body, raw, "无变化须保持原始字节");
    assert!(!out.normalized_out, "无变化不得置位");
}

#[tokio::test]
async fn param_injection_after_redaction_keeps_tokens_and_raw_config_values() {
    // task 4.2 组合：脱敏 + 占位符说明 + 参数注入——占位符 token 与说明保持，
    // 参数值为配置原文（含真实手机号，证明不参与脱敏）。
    let config = test_config(&[]);
    assert!(config.redaction_enabled && config.placeholder_prompt_enabled);
    let phone = "13812345678";
    let raw = format!(r#"{{"model":"m","messages":[{{"role":"user","content":"call {phone}"}}]}}"#);
    let overrides = params_for(
        ParamProtocol::Chat,
        &[("top_p", serde_json::json!(0.9))],
        &[("user_note", serde_json::json!(phone))],
        &[],
    );
    let (scope, vault, detector) = fresh_arcs();
    let out = request_rewrite_with_overrides(
        raw.into_bytes(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
        Some(&overrides),
    )
    .await;
    assert!(out.normalized_out, "注入改写须置位 normalized_out");
    let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后须为合法 JSON");
    assert_eq!(v["top_p"], serde_json::json!(0.9), "参数注入须生效");
    assert_eq!(
        v["user_note"],
        serde_json::json!(phone),
        "参数值为配置原文，不得参与脱敏"
    );
    assert_eq!(v["messages"][0]["role"], "system", "占位符说明须保持注入");
    let user_content = v["messages"][1]["content"]
        .as_str()
        .expect("用户消息须为字符串");
    assert!(
        user_content.contains("__PII_"),
        "消息内 PII 须已脱敏: {user_content}"
    );
    assert!(
        !user_content.contains(phone),
        "消息内不得残留明文: {user_content}"
    );
}

#[tokio::test]
async fn param_injection_merge_mode_preserves_client_value_bytes_unchanged() {
    // task 3.2：合并模式（override_existing = false）下客户端已有参数值恒保留——
    // 无实际变化时不重序列化、字节逐字不变、不置位 `normalized_out`。
    let config = test_config(&[("REDACTION_ENABLED", "0"), ("PII_PLACEHOLDER_PROMPT", "0")]);
    let mut overrides = params_for(
        ParamProtocol::Chat,
        &[],
        &[("temperature", serde_json::json!(0.9))],
        &[],
    );
    overrides.override_existing = false;
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","temperature":0.5,"messages":[]}"#;
    let out = request_rewrite_with_overrides(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
        Some(&overrides),
    )
    .await;
    assert_eq!(out.body, raw, "客户端值须逐字节保留");
    assert!(!out.normalized_out, "无实际变化不得置位 normalized_out");
    let v: serde_json::Value = serde_json::from_slice(&out.body).expect("转发体须为合法 JSON");
    assert_eq!(v["temperature"], serde_json::json!(0.5));
}

#[tokio::test]
async fn param_injection_merge_mode_adds_missing_key_and_declares_normalized() {
    // task 3.2：合并模式新增缺失键（并照常 drop）→ 紧凑重序列化 + 置位。
    let config = test_config(&[("REDACTION_ENABLED", "0"), ("PII_PLACEHOLDER_PROMPT", "0")]);
    let mut overrides = params_for(
        ParamProtocol::Chat,
        &[],
        &[("temperature", serde_json::json!(0.9))],
        &["service_tier"],
    );
    overrides.override_existing = false;
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","service_tier":"auto","messages":[]}"#;
    let out = request_rewrite_with_overrides(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
        Some(&overrides),
    )
    .await;
    assert!(out.normalized_out, "新增键改写须置位 normalized_out");
    let v: serde_json::Value = serde_json::from_slice(&out.body).expect("改写后须为合法 JSON");
    assert_eq!(v["temperature"], serde_json::json!(0.9), "缺失键须新增");
    assert!(
        v.get("service_tier").is_none(),
        "drop 不受开关影响，须照常删除"
    );
}
