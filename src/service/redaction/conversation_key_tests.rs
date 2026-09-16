//! 会话键分层推导/租户命名空间/响应 id 映射测试（sibling，`conversation_key.rs`）。

use {
    super::*,
    crate::{
        handler::llm::dispatch::strip_conversation_header,
        service::{json_walk, llm_gateway::Protocol},
    },
    axum::http::{HeaderMap, HeaderValue},
    serde_json::json,
};

const SECRET: &[u8] = b"conversation-test-secret";
const TENANT: &str = "tenant-fp";

fn prefix_body() -> serde_json::Value {
    json!({
        "tools": [{"type": "function", "function": {"name": "alpha"}}],
        "system": "you are helpful",
        "messages": [{"role": "user", "content": "hello"}],
    })
}

#[test]
fn conversation_key_layered_precedence() {
    let body = prefix_body();
    let stable = stable_prefix_key(SECRET, TENANT, &body).expect("三者齐备须产出稳定前缀键");
    let map = PreviousResponseMap::new(8);
    map.record(SECRET, TENANT, "resp_1", &stable);

    // ① 显式头胜出。
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        Some("conv-1"),
        Some("pck"),
        Some("resp_1"),
        Some(&body),
        Some(&map),
    )
    .unwrap();
    assert_eq!(k, scoped_key(SECRET, TENANT, "conv-1"));
    // ② prompt_cache_key 次之。
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        None,
        Some("pck"),
        Some("resp_1"),
        Some(&body),
        Some(&map),
    )
    .unwrap();
    assert_eq!(k, scoped_key(SECRET, TENANT, "pck"));
    // ③ previous_response_id 映射。
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        None,
        None,
        Some("resp_1"),
        Some(&body),
        Some(&map),
    )
    .unwrap();
    assert_eq!(k, stable);
    // ④ 稳定前缀。
    let k =
        derive_conversation_key(SECRET, TENANT, None, None, None, Some(&body), Some(&map)).unwrap();
    assert_eq!(k, stable);
    // ⑤ 全级不可用 → None。
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            None,
            None,
            None,
            Some(&json!({"model": "m"})),
            Some(&map)
        )
        .is_none()
    );
}

#[test]
fn conversation_key_never_uses_user_field() {
    let body = json!({"user": "alice", "model": "m"});
    assert!(derive_conversation_key(SECRET, TENANT, None, None, None, Some(&body), None).is_none());
    assert_ne!(
        derive_conversation_key(SECRET, TENANT, None, None, None, Some(&body), None),
        Some(scoped_key(SECRET, TENANT, "alice"))
    );
    let multi = json!({
        "user": "alice",
        "messages": [{"role": "user", "content": "hi"}],
    });
    assert!(
        derive_conversation_key(SECRET, TENANT, None, None, None, Some(&multi), None).is_none()
    );
}

#[test]
fn conversation_key_stable_prefix_deterministic() {
    let a = json!({
        "system": "s",
        "tools": [{"name": "beta"}, {"name": "alpha"}],
        "messages": [{"role": "user", "content": "u"}],
        "model": "m",
    });
    let b = json!({
        "model": "m",
        "messages": [{"role": "user", "content": "u"}],
        "tools": [{"name": "alpha"}, {"name": "beta"}],
        "system": "s",
    });
    let k1 = stable_prefix_key(SECRET, TENANT, &a).unwrap();
    let k2 = stable_prefix_key(SECRET, TENANT, &a).unwrap();
    let k3 = stable_prefix_key(SECRET, TENANT, &b).unwrap();
    assert_eq!(k1, k2, "同输入两次须同键");
    assert_eq!(k1, k3, "键序/工具序扰动后仍须同键");
}

#[test]
fn conversation_key_header_too_long_rejected() {
    let long = "a".repeat(EXPLICIT_HEADER_MAX_BYTES + 1);
    assert!(valid_explicit_header(&long).is_none());
    assert!(explicit_header(true, Some(&long)).is_none());
    // 含控制字符亦不命中。
    assert!(explicit_header(true, Some("bad\tvalue")).is_none());
    // 超长头不命中但按优先级继续到 prompt_cache_key；键非原始超长值的哈希。
    let k = derive_conversation_key(SECRET, TENANT, Some(&long), Some("pck"), None, None, None)
        .unwrap();
    assert_eq!(k, scoped_key(SECRET, TENANT, "pck"));
    assert_ne!(k, scoped_key(SECRET, TENANT, &long));
}

#[test]
fn conversation_key_plain_multiturn_falls_to_per_request() {
    let body = json!({
        "model": "m",
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u1"},
            {"role": "assistant", "content": "a1"},
            {"role": "user", "content": "u2"},
        ],
    });
    assert!(
        derive_conversation_key(SECRET, TENANT, None, None, None, Some(&body), None).is_none(),
        "无 tools 的纯多轮 messages 须落第 4 级"
    );
}

#[test]
fn conversation_key_tenant_namespace_isolates() {
    let fp_a = tenant_fingerprint(SECRET, "http://up:8878/v1", &[]);
    let fp_b = tenant_fingerprint(SECRET, "http://up:8879/v1", &[]);
    assert_ne!(
        scoped_key(SECRET, &fp_a, "conv"),
        scoped_key(SECRET, &fp_b, "conv"),
        "完整上游基址不同须隔离"
    );
    let fp_c = tenant_fingerprint(SECRET, "http://up/v1", &["Bearer a"]);
    let fp_d = tenant_fingerprint(SECRET, "http://up/v1", &["Bearer b"]);
    assert_ne!(
        scoped_key(SECRET, &fp_c, "conv"),
        scoped_key(SECRET, &fp_d, "conv"),
        "可区分凭据头须隔离"
    );
}

#[test]
fn conversation_key_hmac_not_raw() {
    let k = scoped_key(SECRET, TENANT, "conv-abc");
    assert_ne!(k.as_str(), "conv-abc");
    assert!(!k.as_str().contains("conv-abc"));
}

#[test]
fn conversation_key_tenant_fingerprint_defined_zero_credential() {
    let fp = tenant_fingerprint(SECRET, "http://up:1/v1", &[]);
    assert!(!fp.is_empty(), "零凭据指纹须非空且确定");
    assert_eq!(fp, tenant_fingerprint(SECRET, "http://up:1/v1", &[]));
    assert_eq!(
        fp,
        tenant_fingerprint(SECRET, "http://up:1/v1", &["", ""]),
        "空串分量须归一为固定空串（与零凭据同指纹）"
    );
}

#[test]
fn conversation_key_tenant_fingerprint_multi_credential_sorted() {
    let a = tenant_fingerprint(SECRET, "http://up/v1", &["b", "a", "a"]);
    let b = tenant_fingerprint(SECRET, "http://up/v1", &["a", "b"]);
    assert_eq!(a, b, "去重排序后同集合须恒同指纹");
}

#[test]
fn conversation_key_tenant_fingerprint_host_only_insufficient() {
    let base = tenant_fingerprint(SECRET, "http://up:8878/v1", &[]);
    assert_ne!(
        base,
        tenant_fingerprint(SECRET, "http://up:8878/v2", &[]),
        "同主机不同 path 须不同指纹"
    );
    assert_ne!(
        base,
        tenant_fingerprint(SECRET, "http://up:8879/v1", &[]),
        "同主机不同入口端口须不同指纹"
    );
    assert_ne!(
        tenant_fingerprint(SECRET, "http://up/v1", &[]),
        tenant_fingerprint(SECRET, "http://up/v1?x=1", &[]),
        "query 差异须体现在指纹"
    );
}

#[test]
fn previous_response_id_map_hit_and_miss() {
    let map = PreviousResponseMap::new(8);
    let key = scoped_key(SECRET, TENANT, "conv");
    map.record(SECRET, TENANT, "resp_1", &key);
    assert_eq!(map.resolve(SECRET, TENANT, "resp_1"), Some(key.clone()));
    assert_eq!(map.resolve(SECRET, TENANT, "resp_missing"), None);
    assert_eq!(
        derive_conversation_key(SECRET, TENANT, None, None, Some("resp_1"), None, Some(&map)),
        Some(key)
    );
    assert_eq!(
        derive_conversation_key(
            SECRET,
            TENANT,
            None,
            None,
            Some("resp_missing"),
            None,
            Some(&map)
        ),
        None,
        "未命中须继续下一级（此处无后续级即 None）"
    );
}

#[test]
fn previous_response_id_cross_tenant_not_resolved() {
    let fp_a = tenant_fingerprint(SECRET, "http://a/v1", &[]);
    let fp_b = tenant_fingerprint(SECRET, "http://b/v1", &[]);
    let map = PreviousResponseMap::new(8);
    let key = scoped_key(SECRET, &fp_a, "conv");
    map.record(SECRET, &fp_a, "resp_1", &key);
    assert_eq!(map.resolve(SECRET, &fp_a, "resp_1"), Some(key));
    assert_eq!(
        map.resolve(SECRET, &fp_b, "resp_1"),
        None,
        "租户 A 的响应 id 在租户 B 下不解析"
    );
}

#[test]
fn previous_response_id_resolves_via_faithful_response_id() {
    // 上游 response.id 值级不变：含 PII 帧经 loads→walk→dumps 重序列化后 id 仍不变。
    let original = r#"{"id":"resp_abc","output":[{"content":"call 13812345678"}]}"#;
    let mut leaf = |s: String| s.replace("13812345678", "__PII_9_deadbeef__");
    let rewritten = json_walk::process_text(original, &mut leaf, json_walk::DEPTH_LIMIT);
    let v: serde_json::Value = serde_json::from_str(&rewritten).expect("重序列化后仍为合法 JSON");
    assert_eq!(v["id"].as_str(), Some("resp_abc"), "id 值级须不变");
    assert!(rewritten.contains("__PII_9_deadbeef__"), "须已重序列化替换");
    let id = v["id"].as_str().unwrap();
    let map = PreviousResponseMap::new(8);
    let key = scoped_key(SECRET, TENANT, "conv");
    map.record(SECRET, TENANT, id, &key);
    assert_eq!(
        derive_conversation_key(SECRET, TENANT, None, None, Some(id), None, Some(&map)),
        Some(key)
    );
}

#[test]
fn previous_response_id_only_responses_writes_map() {
    let map = PreviousResponseMap::new(8);
    let key = scoped_key(SECRET, TENANT, "conv");
    assert!(!record_response_id(
        &map,
        SECRET,
        TENANT,
        Protocol::Chat,
        Some("chatcmpl-1"),
        &key
    ));
    assert!(!record_response_id(
        &map,
        SECRET,
        TENANT,
        Protocol::Anthropic,
        Some("msg_1"),
        &key
    ));
    assert!(map.is_empty(), "Chat/Anthropic 响应 id MUST NOT 进入映射");
    assert!(record_response_id(
        &map,
        SECRET,
        TENANT,
        Protocol::Responses,
        Some("resp_1"),
        &key
    ));
    assert_eq!(map.len(), 1);
    assert!(!record_response_id(
        &map,
        SECRET,
        TENANT,
        Protocol::Responses,
        None,
        &key
    ));
}

#[test]
fn conversation_key_header_ignored_when_mode_request() {
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-conversation-id", HeaderValue::from_static("conv-1"));
    let raw = headers
        .get("x-veil-conversation-id")
        .and_then(|v| v.to_str().ok());
    assert!(explicit_header(false, raw).is_none(), "request 模式不读头");
    assert_eq!(explicit_header(true, raw).as_deref(), Some("conv-1"));
}

#[test]
fn conversation_key_header_not_forwarded_upstream() {
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-conversation-id", HeaderValue::from_static("conv-1"));
    headers.insert("x-my-conv", HeaderValue::from_static("conv-2"));
    headers.insert("authorization", HeaderValue::from_static("Bearer x"));
    assert!(strip_conversation_header(
        &mut headers,
        "x-veil-conversation-id"
    ));
    assert!(
        strip_conversation_header(&mut headers, "X-My-Conv"),
        "自定义头名须大小写不敏感剔除"
    );
    assert!(headers.get("x-veil-conversation-id").is_none());
    assert!(headers.get("x-my-conv").is_none());
    assert!(headers.get("authorization").is_some(), "其他头不受影响");
}

#[test]
fn conversation_writeback_debug_redacts_secrets() {
    // FIX 2：`ConversationKey`/`ConversationWriteback`/`PreviousResponseMap` 的
    // `{:?}` 不得泄漏会话键 hex、租户指纹 hex 或 HMAC 密钥字节。
    let key = ConversationKey::for_test(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    let tenant = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabecafe";
    let secret: Arc<[u8]> = Arc::from(vec![0x11u8; 32].into_boxed_slice());
    assert!(
        !format!("{key:?}").contains(key.as_str()),
        "ConversationKey 不得泄漏键值"
    );

    let map = PreviousResponseMap::new(4);
    map.record(&secret, tenant, "resp_1", &key);
    let map_key = scoped_key(&secret, tenant, "resp_1");
    let map_debug = format!("{map:?}");
    assert!(
        !map_debug.contains(map_key.as_str()),
        "映射不得泄漏键: {map_debug}"
    );

    let wb = ConversationWriteback::new(
        key.clone(),
        tenant.to_string(),
        secret.clone(),
        Arc::new(PreviousResponseMap::new(4)),
    );
    let debug = format!("{wb:?}");
    assert!(!debug.contains(key.as_str()), "不得泄漏会话键 hex: {debug}");
    assert!(!debug.contains(tenant), "不得泄漏租户指纹: {debug}");
    assert!(
        !debug.contains(&format!("{secret:?}")),
        "不得泄漏密钥字节: {debug}"
    );
    assert!(debug.contains("[redacted]"), "须显式标注已脱敏: {debug}");
}
