//! NLP-3/NLP-4/APP-5 回归：逐出现点深度转义与还原 span 定位（自 `scope_tests.rs`
//! 外迁以免触文件行数红线）。

use {super::*, crate::service::pii::PiiDetector};

fn vault_with(secret: &str) -> (CredentialVault, String) {
    let vault = CredentialVault::new();
    let token = vault.register(secret).unwrap();
    (vault, token)
}

/// B3：经真实请求侧脱敏铸造凭据 token（响应侧仅授权本请求实际产出）。
async fn mint_cred(scope: &Scope, vault: &CredentialVault, secret: &str) {
    let _ = scope
        .redact_request(vault, &PiiDetector::new(), secret)
        .await;
}

#[tokio::test]
async fn same_plaintext_cross_depth_escape() {
    // NLP-4/D13：同明文跨深度逐点转义——浅层不得按深层 max 过度转义（内容损坏）。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let inner = serde_json::to_string(&serde_json::json!({ "k": token })).unwrap();
    let frame = serde_json::to_string(&serde_json::json!({ "a": token, "b": inner })).unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert_eq!(spans.len(), 2, "两个出现点各一 span: {spans:?}");
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("还原后外层须合法");
    assert_eq!(outer["a"], secret, "浅层出现点不得被过度转义: {restored}");
    let inner_parsed: serde_json::Value =
        serde_json::from_str(outer["b"].as_str().expect("b 为字符串")).expect("内层须可解析");
    assert_eq!(
        inner_parsed["k"], secret,
        "深层出现点须正确转义: {restored}"
    );
}

#[tokio::test]
async fn escape_per_occurrence() {
    // NLP-4/D13：各出现点按自身深度转义，互不聚合。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let lvl2 = serde_json::to_string(&serde_json::json!({ "k": token })).unwrap();
    let frame = serde_json::to_string(&serde_json::json!({ "a": token, "b": lvl2 })).unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("外层须合法");
    assert_eq!(outer["a"], secret);
    let inner_parsed: serde_json::Value =
        serde_json::from_str(outer["b"].as_str().unwrap()).expect("内层须合法");
    assert_eq!(inner_parsed["k"], secret);
    assert_eq!(spans.len(), 2);
}

#[tokio::test]
async fn key_depth_escape() {
    // NLP-3/D12 + NLP-4/D13：对象 key 位凭据深度须计入，键位还原按深度转义。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let mut inner_map = serde_json::Map::new();
    inner_map.insert(token.clone(), serde_json::json!("v"));
    let inner = serde_json::to_string(&serde_json::Value::Object(inner_map)).unwrap();
    let frame = serde_json::to_string(&serde_json::json!({ "b": inner })).unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert_eq!(spans.len(), 1, "键位出现点须有 span");
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("外层须合法");
    let inner_raw = outer["b"].as_str().expect("b 为字符串");
    let inner_parsed: serde_json::Value =
        serde_json::from_str(inner_raw).expect("键位还原后内层须可解析");
    assert_eq!(
        inner_parsed.get(secret).and_then(|v| v.as_str()),
        Some("v"),
        "键位凭据须按深度转义还原: {inner_raw}"
    );
}

#[tokio::test]
async fn restore_span_per_occurrence() {
    // APP-5/D19：还原 span 逐出现点定位；响应侧独立同值明文仍被掩码。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let token = scope
        .pii_scope()
        .register("13800138000", false)
        .expect("PII 注册恒成功");
    let frame = format!(r#"{{"a":"{token}","b":"13800138000"}}"#);
    let (restored, spans) = scope.restore_response_with_spans(&vault, &frame);
    assert!(restored.contains("13800138000"));
    assert_eq!(
        spans.len(),
        1,
        "仅 token 出现点落在 span（不得子串全量查找整段 skip）: {spans:?}"
    );
    let out = scope
        .redact_response_new_pii_with_skip(&vault, &detector, &restored, &spans)
        .await;
    assert!(
        out.contains(r#""a":"13800138000""#),
        "还原点须保持明文: {out}"
    );
    assert!(
        !out.contains(r#""b":"13800138000""#),
        "响应侧独立同值明文须被掩码: {out}"
    );
}

#[tokio::test]
async fn same_value_multiple_occurrences() {
    // APP-5/D19：同值多出现点各自独立处理，无过度 skip 导致漏掩码。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let token = scope
        .pii_scope()
        .register("13800138000", false)
        .expect("PII 注册恒成功");
    let frame = format!(r#"{{"a":"{token}","b":"13800138000","c":"13800138000"}}"#);
    let (restored, spans) = scope.restore_response_with_spans(&vault, &frame);
    assert_eq!(spans.len(), 1);
    let out = scope
        .redact_response_new_pii_with_skip(&vault, &detector, &restored, &spans)
        .await;
    assert!(out.contains(r#""a":"13800138000""#), "还原点保持: {out}");
    assert!(!out.contains(r#""b":"13800138000""#), "b 须掩码: {out}");
    assert!(!out.contains(r#""c":"13800138000""#), "c 须掩码: {out}");
    assert_eq!(
        out.matches("13800138000").count(),
        1,
        "仅还原点保留明文，两个独立出现点各被掩码: {out}"
    );
    assert!(
        out.matches("__PII_").count() >= 2,
        "两个独立出现点须各被掩码: {out}"
    );
}

#[tokio::test]
async fn fragment_depth_unclosed_json_plus_one() {
    // B4：载体（`input_json_delta`）中未闭合 JSON 片段的 token 按 depth+1 计——
    // 片段拼接后 token 明文落入内层 JSON，转义须多一层；载体外 `delta.text` 不加一。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
    mint_cred(&scope, &vault, secret).await;
    let frame = serde_json::to_string(&serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": { "type": "input_json_delta", "partial_json": format!("{{\"k\":\"{token}") }
    }))
    .unwrap();
    let (restored, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert_eq!(spans.len(), 1, "token 出现点须有 span: {restored}");
    let outer: serde_json::Value = serde_json::from_str(&restored).expect("外层须合法 JSON");
    let partial = outer["delta"]["partial_json"]
        .as_str()
        .expect("partial_json 为字符串");
    let inner: serde_json::Value = serde_json::from_str(&format!("{partial}\"}}"))
        .expect("片段拼接后内层须可解析（depth+1 转义）");
    assert_eq!(inner["k"], secret, "深层转义须严格互逆: {restored}");
    // 非载体：同形 text_delta 文本 SHALL NOT 加一（单层转义，片段拼接后内层非法）。
    let text_frame = serde_json::to_string(&serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": { "type": "text_delta", "text": format!("{{\"k\":\"{token}") }
    }))
    .unwrap();
    let (text_restored, text_spans) = scope.restore_response_with_spans_json(&vault, &text_frame);
    assert_eq!(text_spans.len(), 1);
    let text_outer: serde_json::Value =
        serde_json::from_str(&text_restored).expect("外层须合法 JSON");
    assert_eq!(
        text_outer["delta"]["text"].as_str().unwrap(),
        r#"{"k":"p@ss"q"#,
        "载体外字符串不得加一: {text_restored}"
    );
    // 完整可解析容器分支优先级不变：直接可解析且值与明文一致。
    let complete = serde_json::to_string(&serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {
            "type": "input_json_delta",
            "partial_json": serde_json::to_string(&serde_json::json!({ "k": token })).unwrap()
        }
    }))
    .unwrap();
    let (c_restored, _) = scope.restore_response_with_spans_json(&vault, &complete);
    let c_outer: serde_json::Value = serde_json::from_str(&c_restored).expect("外层须合法");
    let c_inner: serde_json::Value =
        serde_json::from_str(c_outer["delta"]["partial_json"].as_str().unwrap())
            .expect("完整容器须直接可解析");
    assert_eq!(c_inner["k"], secret, "完整容器分支不得回归: {c_restored}");
}

#[tokio::test]
async fn minted_set_records_only_produced_tokens() {
    // B3/C-1：白名单仅收本请求脱敏**实际产出**的 token；请求体自带的字面 token
    // 与他请求产出 token 均不入集，响应还原不得跨请求放行。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let scope = Scope::new();
    let produced = vault.register("produced-secret-001").unwrap();
    let literal = vault.register("literal-secret-002").unwrap();
    assert_ne!(produced, literal);
    let req = format!(r#"{{"a":"produced-secret-001","b":"{literal}"}}"#);
    let redacted = scope.redact_request(&vault, &detector, &req).await;
    assert!(
        redacted.contains(&produced),
        "真实明文须产出 token: {redacted}"
    );
    assert!(
        redacted.contains(&literal),
        "字面 token 须原样保护: {redacted}"
    );
    // 产出集合仅含 produced：literal 不还原、按未授权剥离；全局映射不变。
    let restored = scope.restore_response(&vault, &format!("a={produced} b={literal}"));
    assert!(restored.contains("produced-secret-001"), "{restored}");
    assert!(
        !restored.contains(&literal),
        "字面 token 不得还原: {restored}"
    );
    assert!(!restored.contains("literal-secret-002"), "{restored}");
    assert_eq!(
        vault.restore_one(&literal).as_deref(),
        Some("literal-secret-002"),
        "进程单例映射不变，授权收紧在请求级"
    );
    // 他请求（独立 Scope）产出的 token 在本请求无授权。
    let other = Scope::new();
    mint_cred(&other, &vault, "literal-secret-002").await;
    let crossed = scope.restore_response(&vault, &literal);
    assert!(
        !crossed.contains(&literal),
        "跨请求 token 不得还原: {crossed}"
    );
    assert!(!crossed.contains("literal-secret-002"), "{crossed}");
}

#[tokio::test]
async fn restore_unauthorized_token_stripped() {
    // B3/C-1：全局映射存在但非本请求产出的 token 不还原、按幻觉剥离（fail-closed）。
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let token = vault.register("leak-secret-001").unwrap();
    assert_eq!(
        vault.restore_one(&token).as_deref(),
        Some("leak-secret-001"),
        "全局映射须存在（泄漏链前提）"
    );
    let out = scope.restore_response(&vault, &format!("值 {token} 结束"));
    assert!(!out.contains(&token), "未授权 token 须剥离: {out}");
    assert!(!out.contains("leak-secret-001"), "不得还原明文: {out}");
    // 经本请求脱敏实际产出后方可还原。
    mint_cred(&scope, &vault, "leak-secret-001").await;
    let ok = scope.restore_response(&vault, &format!("值 {token} 结束"));
    assert_eq!(ok, "值 leak-secret-001 结束");
}

#[test]
fn scope_debug_redacts_conversation_context() {
    // FIX 2：`Scope` 手工 `Debug` 不得泄漏会话键 hex/租户指纹/密钥字节。
    let key = ConversationKey::for_test(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    );
    let tenant = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let secret: Arc<[u8]> = Arc::from(vec![0x5Au8; 32].into_boxed_slice());
    let scope = Scope::new().with_conversation(
        key.clone(),
        tenant.to_string(),
        secret.clone(),
        Arc::new(PreviousResponseMap::new(4)),
    );
    let debug = format!("{scope:?}");
    assert!(!debug.contains(key.as_str()), "不得泄漏会话键 hex: {debug}");
    assert!(!debug.contains(tenant), "不得泄漏租户指纹: {debug}");
    assert!(
        !debug.contains(&format!("{secret:?}")),
        "不得泄漏密钥字节: {debug}"
    );
    assert!(debug.contains("[redacted]"), "须显式标注已脱敏: {debug}");
}
