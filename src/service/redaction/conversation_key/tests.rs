//! 会话键原语测试（sibling，`conversation_key.rs`）：租户命名空间、HMAC 派生、
//! 稳定前缀规范化与协议白名单。分层身份推导的覆盖已迁至
//! `service::session_identity::tests`（①–⑦ 优先级与别名优先），本文件只保留
//! 本模块仍拥有的纯函数契约。

use {super::*, crate::service::llm_gateway::Protocol, serde_json::json};

const SECRET: &[u8] = b"conversation-test-secret";
const TENANT: &str = "tenant-fp";

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
fn conversation_key_prefix_fields_protocol_whitelist() {
    // Chat 仅 messages；Anthropic 顶层 system 优先、否则 messages；
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
    // 正例：Anthropic 顶层 system 参与且优先于 messages 首条。
    let anth_top = json!({
        "tools": [{"name": "t"}],
        "system": "NATIVE",
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"}
        ],
    });
    let anth_key = stable_prefix_key(SECRET, TENANT, Protocol::Anthropic, &anth_top)
        .expect("Anthropic 顶层 system 须命中稳定前缀级");
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
    // 反例：Chat 顶层 system 不参与稳定前缀——与省略时同键。
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
        "Chat 顶层 system MUST NOT 影响稳定前缀结果"
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
}

#[test]
fn conversation_key_system_must_be_first_message() {
    // R7-04：Chat/Anthropic 仅 `messages` 首条 system/developer 参与；后续位置不得命中。
    let later_system = json!({
        "tools": [{"name": "t"}],
        "messages": [
            {"role": "user", "content": "u"},
            {"role": "system", "content": "s"},
        ],
    });
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &later_system).is_none(),
        "Chat 后续 system MUST NOT 参与稳定前缀"
    );
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Anthropic, &later_system).is_none(),
        "Anthropic 无顶层 system 时后续 system MUST NOT 参与"
    );
    let developer_first = json!({
        "tools": [{"name": "t"}],
        "messages": [
            {"role": "developer", "content": "s"},
            {"role": "user", "content": "u"},
        ],
    });
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &developer_first).is_some(),
        "首条 developer 须合法"
    );
}

#[test]
fn conversation_key_responses_scalar_input_falls_to_per_request() {
    // Responses 标量 input 不参与稳定前缀级 → 不可命中（调用方落逐请求）。
    let scalar = json!({
        "tools": [{"name": "t"}],
        "instructions": "be nice",
        "input": "当前轮全文，随轮次增长",
    });
    assert!(
        stable_prefix_key(SECRET, TENANT, Protocol::Responses, &scalar).is_none(),
        "标量 input 不作 turn 锚点"
    );
    // 数组 input 正常命中稳定前缀级。
    let array = json!({
        "tools": [{"name": "t"}],
        "instructions": "be nice",
        "input": [{"role": "user", "content": "hello"}],
    });
    assert!(stable_prefix_key(SECRET, TENANT, Protocol::Responses, &array).is_some());
}

#[test]
fn conversation_key_never_uses_user_field() {
    // `user`/`metadata.user_id` 一律不参与稳定前缀（不可作为会话键来源）。
    let body = json!({"user": "alice", "model": "m"});
    assert!(stable_prefix_key(SECRET, TENANT, Protocol::Chat, &body).is_none());
    assert_ne!(
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &body),
        Some(scoped_key(SECRET, TENANT, "alice"))
    );
    let multi = json!({
        "user": "alice",
        "messages": [{"role": "user", "content": "hi"}],
    });
    assert!(stable_prefix_key(SECRET, TENANT, Protocol::Chat, &multi).is_none());
}

#[test]
fn conversation_key_plain_multiturn_falls_to_per_request() {
    // 无 tools 的纯多轮 messages 缺稳定锚点 → 不可命中。
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
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &body).is_none(),
        "无 tools 的纯多轮 messages 须落逐请求"
    );
}

#[test]
fn conversation_key_same_indistinguishable_base_shares_namespace() {
    // 同完整上游基址且凭据头不可区分 → 同一命名空间（仅为层内保证）。
    let fp_1 = tenant_fingerprint(SECRET, "http://up:8878/v1", &[]);
    let fp_2 = tenant_fingerprint(SECRET, "http://up:8878/v1", &[]);
    assert_eq!(fp_1, fp_2);
    assert_eq!(
        scoped_key(SECRET, &fp_1, "shared"),
        scoped_key(SECRET, &fp_2, "shared"),
        "不可区分者共享命名空间（层内保证）"
    );
}

#[test]
fn conversation_key_credential_rotation_invalidates_old_keys() {
    let before = tenant_fingerprint(SECRET, "http://up/v1", &["Bearer old-key"]);
    let after = tenant_fingerprint(SECRET, "http://up/v1", &["Bearer new-key"]);
    assert_ne!(before, after, "凭据轮换须改变租户命名空间");
    assert_ne!(
        scoped_key(SECRET, &before, "conv-1"),
        scoped_key(SECRET, &after, "conv-1"),
        "轮换前铸造的会话键在轮换后不可解析（缓存失配，非错误）"
    );
}

#[test]
fn conversation_key_stable_prefix_frozen_boundary() {
    let base = json!({
        "tools": [{"name": "alpha"}],
        "messages": [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "hello"}
        ],
    });
    let key = stable_prefix_key(SECRET, TENANT, Protocol::Chat, &base).expect("基线须命中");
    for mutated in [
        json!({
            "tools": [{"name": "alpha"}],
            "messages": [
                {"role": "system", "content": "you are terse"},
                {"role": "user", "content": "hello"}
            ],
        }),
        json!({
            "tools": [{"name": "beta"}],
            "messages": [
                {"role": "system", "content": "you are helpful"},
                {"role": "user", "content": "hello"}
            ],
        }),
        json!({
            "tools": [{"name": "alpha"}],
            "messages": [
                {"role": "system", "content": "you are helpful"},
                {"role": "user", "content": "hello again"}
            ],
        }),
    ] {
        assert_ne!(
            stable_prefix_key(SECRET, TENANT, Protocol::Chat, &mutated),
            Some(key.clone()),
            "tools/system/首个 user turn 任一改写须改变会话键（已登记边界）: {mutated}"
        );
    }
    for missing in [
        json!({"messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]}),
        json!({"tools": [{"name": "alpha"}], "messages": [{"role": "user", "content": "u"}]}),
        json!({"tools": [{"name": "alpha"}], "messages": [{"role": "system", "content": "s"}]}),
    ] {
        assert!(
            stable_prefix_key(SECRET, TENANT, Protocol::Chat, &missing).is_none(),
            "三者缺一即不命中第 ⑤ 级: {missing}"
        );
    }
}

#[test]
fn conversation_key_debug_redacts() {
    // `ConversationKey` 的 `{:?}` 不得泄漏会话键 hex。
    let key = ConversationKey::for_test(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    let debug = format!("{key:?}");
    assert!(!debug.contains(key.as_str()), "不得泄漏键值: {debug}");
    assert!(debug.contains("[redacted]"), "须显式标注已脱敏: {debug}");
}
