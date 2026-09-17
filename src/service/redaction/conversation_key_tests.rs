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
        "messages": [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "hello"}
        ],
    })
}

#[test]
fn conversation_key_layered_precedence() {
    let body = prefix_body();
    let stable =
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &body).expect("三者齐备须产出稳定前缀键");
    let map = PreviousResponseMap::new(8);
    map.record(SECRET, TENANT, "resp_1", &stable);

    // ① 显式头胜出。
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        Protocol::Chat,
        Some("conv-1"),
        Some("pck"),
        Some("resp_1"),
        &body,
        &map,
    )
    .unwrap();
    assert_eq!(k, scoped_key(SECRET, TENANT, "conv-1"));
    // ② prompt_cache_key 次之（Chat 接受）。
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        Protocol::Chat,
        None,
        Some("pck"),
        Some("resp_1"),
        &body,
        &map,
    )
    .unwrap();
    assert_eq!(k, scoped_key(SECRET, TENANT, "pck"));
    // ③ previous_response_id 映射（Responses 接受）。
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        Protocol::Responses,
        None,
        None,
        Some("resp_1"),
        &json!({}),
        &map,
    )
    .unwrap();
    assert_eq!(k, stable);
    // ④ 稳定前缀。
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        Protocol::Chat,
        None,
        None,
        None,
        &body,
        &map,
    )
    .unwrap();
    assert_eq!(k, stable);
    // ⑤ 全级不可用 → None。
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            None,
            None,
            &json!({"model": "m"}),
            &map
        )
        .is_none()
    );
}

#[test]
fn conversation_key_native_keys_protocol_whitelist() {
    // R5-07/D1 正例：Chat/Responses 接受 `prompt_cache_key`。
    for protocol in [Protocol::Chat, Protocol::Responses] {
        let k = derive_conversation_key(
            SECRET,
            TENANT,
            protocol,
            None,
            Some("pck"),
            None,
            &json!({}),
            &PreviousResponseMap::new(1),
        )
        .unwrap();
        assert_eq!(k, scoped_key(SECRET, TENANT, "pck"), "{protocol:?}");
    }
    // 反例：Chat 体带 `previous_response_id` 不命中第 2 级。
    let map = PreviousResponseMap::new(4);
    let key = scoped_key(SECRET, TENANT, "conv-x");
    map.record(SECRET, TENANT, "resp_9", &key);
    let body = json!({"previous_response_id": "resp_9"});
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            None,
            Some("resp_9"),
            &body,
            &map
        )
        .is_none(),
        "Chat 的 previous_response_id MUST NOT 命中第 2 级"
    );
    assert_eq!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Responses,
            None,
            None,
            Some("resp_9"),
            &body,
            &map
        ),
        Some(key),
        "Responses 接受 previous_response_id"
    );
    // 反例：Anthropic 体带 `prompt_cache_key` 不命中第 2 级。
    let pck_body = json!({"prompt_cache_key": "pck"});
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Anthropic,
            None,
            Some("pck"),
            None,
            &pck_body,
            &map
        )
        .is_none(),
        "Anthropic 的 prompt_cache_key MUST NOT 命中第 2 级"
    );
    assert_eq!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            Some("pck"),
            None,
            &pck_body,
            &map
        ),
        Some(scoped_key(SECRET, TENANT, "pck"))
    );
}

#[test]
fn conversation_key_prefix_fields_protocol_whitelist() {
    // R5-07/D1 + R7-04：Chat 仅 messages；Anthropic 顶层 system 优先、否则 messages；
    // Responses 用 input/instructions。
    let chat_body = json!({
        "tools": [{"name": "t"}],
        "instructions": "be nice",
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
    });
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &chat_body).is_some(),
        "Chat 从 messages 取 system/first user，instructions 不参与"
    );
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Responses, &chat_body).is_none(),
        "Responses 的 messages MUST NOT 作首个 user turn（缺 input）"
    );
    // R7-04 正例：Anthropic 顶层 system 参与且优先于 messages 首条。
    let anth_top = json!({
        "tools": [{"name": "t"}],
        "system": "NATIVE",
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"}
        ],
    });
    let anth_key = stable_prefix_key(SECRET, TENANT, Protocol::Anthropic, &anth_top)
        .expect("Anthropic 顶层 system 须命中第 3 级");
    let anth_no_top = json!({
        "tools": [{"name": "t"}],
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"}
        ],
    });
    assert_ne!(
        anth_key,
        stable_prefix_key(SECRET, TENANT, Protocol::Anthropic, &anth_no_top).unwrap(),
        "Anthropic 顶层 system 须优先于 messages 首条"
    );
    let anth_other = json!({
        "tools": [{"name": "t"}],
        "system": "OTHER",
        "messages": [{"role": "user", "content": "u"}],
    });
    assert_ne!(
        anth_key,
        stable_prefix_key(SECRET, TENANT, Protocol::Anthropic, &anth_other).unwrap(),
        "Anthropic 顶层 system 内容参与稳定前缀"
    );
    // R7-04 反例：Chat 顶层 system 不参与第 3 级——与省略时同键。
    let chat_top = json!({
        "tools": [{"name": "t"}],
        "system": "TOP",
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"}
        ],
    });
    assert_eq!(
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &chat_top),
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &chat_body),
        "Chat 顶层 system MUST NOT 影响第 3 级结果"
    );
    let chat_only_user = json!({
        "tools": [{"name": "t"}],
        "system": "TOP",
        "messages": [{"role": "user", "content": "u"}],
    });
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &chat_only_user).is_none(),
        "Chat 顶层 system MUST NOT 作 system 来源"
    );
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            None,
            None,
            &chat_only_user,
            &PreviousResponseMap::new(1),
        )
        .is_none(),
        "Chat 顶层 system 不命中第 3 级须落第 4 级"
    );
}

#[test]
fn conversation_key_responses_scalar_input_falls_to_level4() {
    // R5-06/D1：Responses 标量 input 不参与第 3 级 → 落第 4 级（None）。
    let scalar = json!({
        "tools": [{"name": "t"}],
        "instructions": "be nice",
        "input": "当前轮全文，随轮次增长",
    });
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Responses, &scalar).is_none(),
        "标量 input 不作 turn 锚点"
    );
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Responses,
            None,
            None,
            None,
            &scalar,
            &PreviousResponseMap::new(1),
        )
        .is_none()
    );
    // 数组 input 正常命中第 3 级。
    let array = json!({
        "tools": [{"name": "t"}],
        "instructions": "be nice",
        "input": [{"role": "user", "content": "hello"}],
    });
    assert!(stable_prefix_key(SECRET, TENANT, Protocol::Responses, &array).is_some());
}

#[test]
fn conversation_key_never_uses_user_field() {
    let map = PreviousResponseMap::new(1);
    let body = json!({"user": "alice", "model": "m"});
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            None,
            None,
            &body,
            &map
        )
        .is_none()
    );
    assert_ne!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            None,
            None,
            &body,
            &map
        ),
        Some(scoped_key(SECRET, TENANT, "alice"))
    );
    let multi = json!({
        "user": "alice",
        "messages": [{"role": "user", "content": "hi"}],
    });
    assert!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            None,
            None,
            &multi,
            &map
        )
        .is_none()
    );
}

#[test]
fn conversation_key_stable_prefix_deterministic() {
    let a = json!({
        "system": "s",
        "tools": [{"name": "beta"}, {"name": "alpha"}],
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"}
        ],
        "model": "m",
    });
    let b = json!({
        "model": "m",
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"}
        ],
        "tools": [{"name": "alpha"}, {"name": "beta"}],
        "system": "s",
    });
    let k1 = stable_prefix_key(SECRET, TENANT, Protocol::Chat, &a).unwrap();
    let k2 = stable_prefix_key(SECRET, TENANT, Protocol::Chat, &a).unwrap();
    let k3 = stable_prefix_key(SECRET, TENANT, Protocol::Chat, &b).unwrap();
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
    let k = derive_conversation_key(
        SECRET,
        TENANT,
        Protocol::Chat,
        Some(&long),
        Some("pck"),
        None,
        &json!({}),
        &PreviousResponseMap::new(1),
    )
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
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Chat,
            None,
            None,
            None,
            &body,
            &PreviousResponseMap::new(1)
        )
        .is_none(),
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
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Responses,
            None,
            None,
            Some("resp_1"),
            &json!({}),
            &map
        ),
        Some(key)
    );
    assert_eq!(
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Responses,
            None,
            None,
            Some("resp_missing"),
            &json!({}),
            &map
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
        derive_conversation_key(
            SECRET,
            TENANT,
            Protocol::Responses,
            None,
            None,
            Some(id),
            &json!({}),
            &map
        ),
        Some(key)
    );
}

#[test]
fn previous_response_map_capacity_eviction_counted() {
    // R5-10/D10：达容量逐出最旧条目并计映射逐出计数；显式容量独立生效。
    let metrics = Arc::new(crate::service::llm_gateway::GatewayMetrics::default());
    let map = PreviousResponseMap::new(2).with_metrics(metrics.clone());
    assert_eq!(map.capacity(), 2);
    let key = scoped_key(SECRET, TENANT, "conv");
    map.record(SECRET, TENANT, "resp_1", &key);
    map.record(SECRET, TENANT, "resp_2", &key);
    assert_eq!(metrics.previous_response_eviction_count(), 0, "未满不逐出");
    map.record(SECRET, TENANT, "resp_3", &key);
    assert_eq!(map.len(), 2, "容量有界");
    assert_eq!(
        metrics.previous_response_eviction_count(),
        1,
        "逐出最旧须计一次"
    );
    assert_eq!(map.resolve(SECRET, TENANT, "resp_1"), None, "最旧须被逐出");
    assert!(map.resolve(SECRET, TENANT, "resp_3").is_some());
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
