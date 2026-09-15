//! NLP-3/NLP-4/APP-5 回归：逐出现点深度转义与还原 span 定位（自 `scope_tests.rs`
//! 外迁以免触文件行数红线）。

use {super::*, crate::service::pii::PiiDetector};

fn vault_with(secret: &str) -> (CredentialVault, String) {
    let vault = CredentialVault::new();
    let token = vault.register(secret).unwrap();
    (vault, token)
}

#[test]
fn same_plaintext_cross_depth_escape() {
    // NLP-4/D13：同明文跨深度逐点转义——浅层不得按深层 max 过度转义（内容损坏）。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
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

#[test]
fn escape_per_occurrence() {
    // NLP-4/D13：各出现点按自身深度转义，互不聚合。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
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

#[test]
fn key_depth_escape() {
    // NLP-3/D12 + NLP-4/D13：对象 key 位凭据深度须计入，键位还原按深度转义。
    let secret = "p@ss\"q";
    let (vault, token) = vault_with(secret);
    let scope = Scope::new();
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
