//! 上游 prompt cache 保真与注入位置测试（sibling，`veil-pii-conversation-cache` 4.1–4.4）。
//!
//! 覆盖：`cache_control` 断点存活（不丢/不移/不改）、`prompt_cache_key`/`metadata` 原样
//! 转发、NonDialog 字节透传、占位符说明头部注入保持、同会话键跨轮注入前缀字节一致。

use {
    super::{
        conversation_key::scoped_key,
        conversation_store::ConversationScopeStore,
        scope::Scope,
    },
    crate::{
        handler::llm::serve_nondialog_passthrough,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol, inject_placeholder_prompt},
            pii::PiiDetector,
        },
    },
    axum::http::HeaderMap,
    serde_json::{Value, json},
    std::{collections::BTreeSet, sync::Arc, time::Duration},
};

/// 会话键派生测试用密钥/租户指纹常量（与生产键同形：HMAC 命名空间化）。
const SECRET: &[u8] = b"cache-fidelity-secret";
const TENANT: &str = "cache-fidelity-tenant";
/// 占位符说明文案（测试内固定，避免依赖内建默认文案）。
const PROMPT: &str = "PII 占位符说明";

/// 递归收集全部 `cache_control` 断点：返回 `(JSON 路径, 取值)` 列表。
/// 路径含对象键与数组下标，故可同时校验**数量、位置、取值**逐项存活。
fn collect_cache_control(value: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    walk_cache_control(value, String::new(), &mut out);
    out
}

fn walk_cache_control(value: &Value, path: String, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let child = format!("{path}/{k}");
                if k == "cache_control" {
                    out.push((child.clone(), v.clone()));
                }
                walk_cache_control(v, child, out);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk_cache_control(item, format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// 经脱敏改写链（`redact_request_with_report`）处理并返回改写后文本。
async fn redact(
    scope: &Scope,
    vault: &CredentialVault,
    detector: &PiiDetector,
    body: &Value,
) -> String {
    let text = serde_json::to_string(body).expect("测试体须可序列化");
    scope
        .redact_request_with_report(vault, detector, &text)
        .await
        .0
}

/// 脱敏 + 占位符说明注入（Chat），返回改写后文本；用于跨轮前缀字节比较。
async fn redact_and_inject(
    scope: &Scope,
    vault: &CredentialVault,
    detector: &PiiDetector,
    body: &Value,
) -> String {
    let redacted = redact(scope, vault, detector, body).await;
    inject_placeholder_prompt(&redacted, PROMPT, Protocol::Chat).unwrap_or(redacted)
}

/// 会话稳定前缀形态的请求体（tools+system+首个 user turn 齐备，含 PII 明文）。
fn talk_body() -> Value {
    json!({
        "model": "m",
        "tools": [{"type": "function", "function": {"name": "f"}}],
        "system": "you are helpful",
        "messages": [{"role": "user", "content": "call 13812345678"}],
    })
}

// ---------- 4.1 cache_control 断点存活 ----------

#[tokio::test]
async fn cache_control_breakpoints_survive_redaction() {
    // 脱敏 MUST NOT 丢弃/位移/改写断点；Chat 的 `tools`/`messages` 与
    // Anthropic 的 `tools`/`system`/`messages` 三处逐项对账。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let cases = [
        (
            Protocol::Chat,
            json!({
                "model": "m",
                "tools": [{
                    "type": "function",
                    "function": {"name": "f"},
                    "cache_control": {"type": "ephemeral", "ttl": "5m"}
                }],
                "messages": [
                    {"role": "system", "content": [
                        {"type": "text", "text": "sys"},
                        {"type": "text", "text": "cached", "cache_control": {"type": "ephemeral"}}
                    ]},
                    {
                        "role": "user",
                        "content": "call 13812345678",
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            }),
        ),
        (
            Protocol::Anthropic,
            json!({
                "model": "claude",
                "tools": [{"name": "f", "cache_control": {"type": "ephemeral"}}],
                "system": [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}],
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "call 13812345678", "cache_control": {"type": "ephemeral"}}
                    ]
                }]
            }),
        ),
    ];
    for (protocol, body) in cases {
        let before = collect_cache_control(&body);
        assert_eq!(before.len(), 3, "{protocol:?} 用例须含 3 处断点（自检）");
        let redacted = redact(&Scope::new(), &vault, &detector, &body).await;
        assert!(
            redacted.contains("__PII_"),
            "{protocol:?} 须实际脱敏（自检）"
        );
        let after_value: Value = serde_json::from_str(&redacted).expect("脱敏后仍为合法 JSON");
        let after = collect_cache_control(&after_value);
        assert_eq!(
            after, before,
            "{protocol:?} cache_control 断点数量/位置/取值须逐项存活"
        );
    }
}

#[tokio::test]
async fn cache_control_not_injected_when_absent() {
    // 无断点时系统 MUST NOT 自行注入（三协议各验一次）。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let bodies = [
        json!({"model": "m", "messages": [{"role": "user", "content": "call 13812345678"}]}),
        json!({"model": "claude", "system": "s",
            "messages": [{"role": "user", "content": "call 13812345678"}]}),
        json!({"model": "m", "input": "call 13812345678"}),
    ];
    for body in bodies {
        let redacted = redact(&Scope::new(), &vault, &detector, &body).await;
        assert!(
            !redacted.contains("cache_control"),
            "系统 MUST NOT 自行注入 cache_control：{redacted}"
        );
        let after: Value = serde_json::from_str(&redacted).expect("脱敏后仍为合法 JSON");
        assert!(collect_cache_control(&after).is_empty());
    }
}

// ---------- 4.2 prompt_cache_key / metadata 原样转发 ----------

#[tokio::test]
async fn prompt_cache_key_metadata_forwarded_untouched() {
    // 脱敏改写后保留原值，不新增/删除/改写（顶层键集合与两字段取值逐项对账）。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let cases = [
        json!({
            "model": "m",
            "prompt_cache_key": "pck-conv-12345",
            "metadata": {"user_id": "u-1", "tags": ["a", "b"], "nested": {"k": "v"}},
            "messages": [{"role": "user", "content": "call 13812345678"}]
        }),
        json!({
            "model": "m",
            "prompt_cache_key": "pck-conv-67890",
            "metadata": {"trace": "t-1"},
            "input": "call 13812345678"
        }),
    ];
    for body in cases {
        let before_keys: BTreeSet<String> = body
            .as_object()
            .expect("测试体须为对象")
            .keys()
            .cloned()
            .collect();
        let redacted = redact(&Scope::new(), &vault, &detector, &body).await;
        assert!(
            redacted.contains("__PII_"),
            "须实际脱敏（自检）: {redacted}"
        );
        let after: Value = serde_json::from_str(&redacted).expect("脱敏后仍为合法 JSON");
        let after_keys: BTreeSet<String> = after
            .as_object()
            .expect("脱敏后仍为对象")
            .keys()
            .cloned()
            .collect();
        assert_eq!(after_keys, before_keys, "顶层键集合须不增不减");
        assert_eq!(
            after["prompt_cache_key"], body["prompt_cache_key"],
            "prompt_cache_key 须原样转发"
        );
        assert_eq!(
            after["metadata"], body["metadata"],
            "metadata 须原样转发（不增删改）"
        );
    }
}

/// 回环 echo 服务：把收到的请求体原样回写为响应体，供字节透传对账。
async fn echo_request_body_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/models",
        listener.local_addr().expect("回环地址须可读")
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 4096];
            let header_end = loop {
                let n = match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => break None,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(pos + 4);
                }
            };
            let Some(header_end) = header_end else {
                continue;
            };
            let len: usize = header_value(&buf[..header_end], "content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            while buf.len() < header_end + len {
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let end = (header_end + len).min(buf.len());
            let body = buf[header_end..end].to_vec();
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

/// 从请求头字节中取指定头值（大小写不敏感）。
fn header_value(buf: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    text.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

#[tokio::test]
async fn nondialog_cache_fields_byte_passthrough() {
    // NonDialog 透传路径不变：请求体（含缓存字段与 PII 明文）逐字节转发上游，不做脱敏。
    let body = serde_json::to_vec(&json!({
        "model": "m",
        "prompt_cache_key": "pck-nondialog-1",
        "metadata": {"user_id": "u-1"},
        "cache_control": {"type": "ephemeral"},
        "messages": [{"role": "user", "content": "call 13812345678"}]
    }))
    .expect("测试体须可序列化");
    let (url, server) = echo_request_body_server().await;
    let client = reqwest::Client::new();
    let metrics = Arc::new(GatewayMetrics::default());
    let resp = serve_nondialog_passthrough(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        body.clone(),
        Protocol::NonDialog,
        &metrics,
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let out = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    assert_eq!(
        out.as_ref(),
        body.as_slice(),
        "NonDialog 透传须字节一致（含缓存字段与原样 PII）"
    );
    assert!(
        String::from_utf8_lossy(&out).contains("13812345678"),
        "NonDialog 不做脱敏"
    );
    assert_eq!(metrics.nondialog_passthrough_count(), 1, "透传须计数");
    server.abort();
}

// ---------- 4.3 占位符说明头部注入保持 ----------

#[test]
fn placeholder_injection_remains_head_position() {
    // Chat：messages[0] 头部插入 system，MUST NOT 尾部注入。
    let chat = json!({"messages": [{"role": "user", "content": "hi __PII_1_ab12cd34__"}]});
    let out = inject_placeholder_prompt(
        &serde_json::to_string(&chat).expect("测试体须可序列化"),
        PROMPT,
        Protocol::Chat,
    )
    .expect("Chat 须可注入");
    let v: Value = serde_json::from_str(&out).expect("注入后仍为合法 JSON");
    let msgs = v["messages"].as_array().expect("messages 须为数组");
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0]["role"], "system");
    assert_eq!(msgs[0]["content"], PROMPT);
    assert_eq!(msgs[msgs.len() - 1]["role"], "user", "MUST NOT 尾部注入");

    // Anthropic：system 头部字段合并，messages 不被追加。
    let anth = json!({"system": "base",
        "messages": [{"role": "user", "content": "hi __VG_CRED_000001__"}]});
    let out = inject_placeholder_prompt(
        &serde_json::to_string(&anth).expect("测试体须可序列化"),
        PROMPT,
        Protocol::Anthropic,
    )
    .expect("Anthropic 须可注入");
    let v: Value = serde_json::from_str(&out).expect("注入后仍为合法 JSON");
    let sys = v["system"].as_str().expect("system 须为字符串");
    assert!(sys.starts_with("base"), "system 原值须保留在头部: {sys}");
    assert!(sys.contains(PROMPT));
    assert_eq!(v["messages"][0]["role"], "user", "不得向 messages 尾部追加");

    // Responses：input 数组头部前插 system。
    let resp = json!({"input": [{"role": "user", "content": "hi __PII_1_ab12cd34__"}]});
    let out = inject_placeholder_prompt(
        &serde_json::to_string(&resp).expect("测试体须可序列化"),
        PROMPT,
        Protocol::Responses,
    )
    .expect("Responses 须可注入");
    let v: Value = serde_json::from_str(&out).expect("注入后仍为合法 JSON");
    let input = v["input"].as_array().expect("input 须为数组");
    assert_eq!(input[0]["role"], "system");
    assert_eq!(input[0]["content"], PROMPT);
    assert_eq!(input[1]["role"], "user");

    // 幂等守卫不变：二次注入返回 None（保留原字节）。
    let once = serde_json::to_string(&v).expect("已注入体须可序列化");
    assert!(
        inject_placeholder_prompt(&once, PROMPT, Protocol::Responses).is_none(),
        "幂等守卫须保持"
    );
}

// ---------- 4.4 会话内注入前缀字节一致 ----------

#[tokio::test]
async fn placeholder_prefix_byte_identical_across_turns() {
    // 同会话键两轮：共享 PiiScope → 同明文同 token → 注入前缀逐字节相等。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let store = ConversationScopeStore::new(8, Duration::from_secs(1800));
    let key = scoped_key(SECRET, TENANT, "conv-same");
    let body = talk_body();

    let scope1 = Scope::with_shared_pii(store.get_or_insert(&key), true, false);
    let out1 = redact_and_inject(&scope1, &vault, &detector, &body).await;
    let scope2 = Scope::with_shared_pii(store.get_or_insert(&key), true, false);
    let out2 = redact_and_inject(&scope2, &vault, &detector, &body).await;

    assert!(out1.contains("__PII_"), "须实际注入占位符说明（自检）");
    assert_eq!(out1, out2, "同会话键两轮改写体须逐字节相等");
    let v1: Value = serde_json::from_str(&out1).expect("改写后仍为合法 JSON");
    let v2: Value = serde_json::from_str(&out2).expect("改写后仍为合法 JSON");
    assert_eq!(v1["messages"][0]["role"], "system", "注入须在头部");
    assert_eq!(v1["messages"][0], v2["messages"][0], "注入前缀须逐字节相等");
}

#[tokio::test]
async fn placeholder_prefix_differs_across_conversations() {
    // 不同会话键不得误判相等：键不同、底层 PiiScope 不同、改写体不同。
    let vault = CredentialVault::new();
    let detector = PiiDetector::new();
    let store = ConversationScopeStore::new(8, Duration::from_secs(1800));
    let key_a = scoped_key(SECRET, TENANT, "conv-a");
    let key_b = scoped_key(SECRET, TENANT, "conv-b");
    assert_ne!(key_a, key_b, "不同会话键须不等");

    let pii_a = store.get_or_insert(&key_a);
    let pii_b = store.get_or_insert(&key_b);
    assert!(
        !Arc::ptr_eq(&pii_a, &pii_b),
        "不同会话键须映射不同 PiiScope"
    );

    let body = talk_body();
    let out_a = redact_and_inject(
        &Scope::with_shared_pii(pii_a, true, false),
        &vault,
        &detector,
        &body,
    )
    .await;
    let out_b = redact_and_inject(
        &Scope::with_shared_pii(pii_b, true, false),
        &vault,
        &detector,
        &body,
    )
    .await;
    assert_ne!(out_a, out_b, "不同会话键的注入前缀不得误判相等");
}
