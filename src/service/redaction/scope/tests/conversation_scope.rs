//! 会话作用域存储 + 授权域不对称测试（sibling，`scope.rs`）。

use {
    crate::{
        config::Config,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::GatewayMetrics,
            pii::{PII_MAX_ENTRIES, PiiDetector, PiiScope},
            redaction::{
                ConversationKey,
                ConversationScopeStore,
                Scope,
                scoped_key,
                tenant_fingerprint,
            },
        },
        state::{AppState, SqliteOutcome},
    },
    axum::http::HeaderMap,
    std::{
        path::PathBuf,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    },
};

const PHONE: &str = "13812345678";
const CRED: &str = "supersecretcredentialvalue123";

fn fake_clock() -> (
    crate::service::redaction::conversation_store::Clock,
    Arc<Mutex<Duration>>,
) {
    let base = Instant::now();
    let offset = Arc::new(Mutex::new(Duration::ZERO));
    let handle = offset.clone();
    let clock: crate::service::redaction::conversation_store::Clock =
        Arc::new(move || base + *handle.lock().unwrap());
    (clock, offset)
}

#[test]
fn conversation_store_capacity_lru_evicts() {
    let store = ConversationScopeStore::new(2, Duration::from_secs(60));
    let k1 = ConversationKey::for_test("k1");
    let k2 = ConversationKey::for_test("k2");
    let k3 = ConversationKey::for_test("k3");
    let a1 = store.get_or_insert(&k1);
    let a2 = store.get_or_insert(&k2);
    let _ = store.get_or_insert(&k1);
    let a3 = store.get_or_insert(&k3);
    assert_eq!(store.len(), 2, "超上限须淘汰至有界");
    let a2_again = store.get_or_insert(&k2);
    assert!(!Arc::ptr_eq(&a2, &a2_again), "k2 为最久未用者，须被淘汰");
    assert!(Arc::ptr_eq(&a3, &store.get_or_insert(&k3)), "k3 仍须在存");
    assert!(
        !Arc::ptr_eq(&a1, &store.get_or_insert(&k1)),
        "k1 随后为最久未用者，须被淘汰"
    );
}

#[test]
fn conversation_store_idle_ttl_evicts() {
    let (clock, offset) = fake_clock();
    let store = ConversationScopeStore::with_clock(4, Duration::from_secs(30), clock);
    let k1 = ConversationKey::for_test("k1");
    let a1 = store.get_or_insert(&k1);
    *offset.lock().unwrap() = Duration::from_secs(31);
    let a1_again = store.get_or_insert(&k1);
    assert!(
        !Arc::ptr_eq(&a1, &a1_again),
        "超空闲 TTL 后条目须消失并重建"
    );
    assert_eq!(store.len(), 1);
}

#[test]
fn conversation_store_aggregate_bound() {
    let store = ConversationScopeStore::new(3, Duration::from_secs(60));
    for i in 0..3 {
        let key = ConversationKey::for_test(&format!("k{i}"));
        let scope = store.get_or_insert(&key);
        for j in 0..(PII_MAX_ENTRIES + 5) {
            let _ = scope.register(&format!("value-{i}-{j}")).unwrap();
        }
    }
    assert!(store.len() <= 3);
    let mut total = 0usize;
    for i in 0..3 {
        let key = ConversationKey::for_test(&format!("k{i}"));
        let scope = store.get_or_insert(&key);
        let items = scope.table_sizes();
        assert!(
            items <= PII_MAX_ENTRIES,
            "单会话表须受 PII_MAX_ENTRIES 约束"
        );
        total += items;
    }
    let bound = 3 * PII_MAX_ENTRIES;
    assert!(
        total <= bound,
        "聚合上界须为 会话数×单会话条目: {total} <= {bound}"
    );
}

#[test]
fn conversation_store_concurrent_same_plaintext_one_token() {
    let store = Arc::new(ConversationScopeStore::new(8, Duration::from_secs(60)));
    let key = ConversationKey::for_test("k1");
    let scope = store.get_or_insert(&key);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let scope = scope.clone();
            std::thread::spawn(move || scope.register(PHONE).unwrap())
        })
        .collect();
    let tokens: std::collections::HashSet<String> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(tokens.len(), 1, "并发同明文须收敛到同一 token");
}

#[test]
fn conversation_store_get_or_insert_shared_arc() {
    let store = ConversationScopeStore::new(4, Duration::from_secs(60));
    let key = ConversationKey::for_test("k");
    let first = store.get_or_insert(&key);
    let second = store.get_or_insert(&key);
    assert!(
        Arc::ptr_eq(&first, &second),
        "重复取用须为同一 Arc（指针相等）"
    );
}

#[test]
fn conversation_store_poison_recovery() {
    let store = Arc::new(ConversationScopeStore::new(4, Duration::from_secs(60)));
    let poisoner = store.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poisoner.force_poison()));
    let key = ConversationKey::for_test("k");
    let scope = store.get_or_insert(&key);
    let token = scope.register(PHONE).unwrap();
    assert!(token.starts_with("__PII_"), "中毒恢复后须返回真实结果");
    assert_eq!(store.len(), 1);
}

#[test]
fn conversation_store_eviction_deterministic() {
    let store = ConversationScopeStore::new(2, Duration::from_secs(60));
    let a = ConversationKey::for_test("a");
    let b = ConversationKey::for_test("b");
    let c = ConversationKey::for_test("c");
    let a_first = store.get_or_insert(&a);
    let _ = store.get_or_insert(&b);
    let _ = store.get_or_insert(&c);
    let a_again = store.get_or_insert(&a);
    assert!(!Arc::ptr_eq(&a_first, &a_again), "最久未用者须被确定性淘汰");
    let b_first = store.get_or_insert(&b);
    assert!(Arc::ptr_eq(&b_first, &store.get_or_insert(&b)));
}

#[test]
fn conversation_store_evicted_remints_token() {
    let store = ConversationScopeStore::new(1, Duration::from_secs(60));
    let k1 = ConversationKey::for_test("k1");
    let k2 = ConversationKey::for_test("k2");
    let first = store.get_or_insert(&k1).register(PHONE).unwrap();
    let _ = store.get_or_insert(&k2);
    let second = store.get_or_insert(&k1).register(PHONE).unwrap();
    assert_ne!(first, second, "淘汰后同明文须重新铸造 token 且无错误");
}

fn unique_temp_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "veil-conv-scope-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_state(mode: Option<&str>) -> (AppState, PathBuf) {
    let dir = unique_temp_dir();
    let mut env = std::collections::HashMap::from([
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
        ("DATA_DIR".to_string(), dir.to_string_lossy().into_owned()),
    ]);
    if let Some(mode) = mode {
        env.insert("PII_SCOPE_MODE".to_string(), mode.to_string());
    }
    let config = Config::load_from(&env).expect("测试配置须合法");
    let outcome = SqliteOutcome {
        sqlite_ok: true,
        sqlite_error: None,
        db_path: dir.join("m.sqlite"),
    };
    let state = AppState::try_new(config, outcome).expect("AppState 装配须成功");
    (state, dir)
}

#[test]
fn app_state_carries_conversation_store() {
    let (state, dir) = test_state(Some("conversation"));
    let store = state
        .conversation_scope_store
        .as_ref()
        .expect("conversation 模式须构造存储");
    let cloned = state.clone();
    assert!(
        Arc::ptr_eq(store, cloned.conversation_scope_store.as_ref().unwrap()),
        "存储句柄须跨请求共享（Arc 指针相等）"
    );
    assert!(Arc::ptr_eq(
        &state.session_alias_map,
        &cloned.session_alias_map
    ));
    assert!(!state.conversation_secret.is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn app_state_request_mode_no_conversation_store_use() {
    let (state, dir) = test_state(None);
    assert!(
        state.conversation_scope_store.is_none(),
        "默认 request 模式 MUST NOT 构造会话存储"
    );
    let vault = CredentialVault::new();
    let first = Scope::with_opts(false);
    let token = first.pii_scope().register(PHONE).unwrap();
    let second = Scope::with_opts(false);
    let out = second.restore_response_with_spans(&vault, &token).0;
    assert!(
        out.contains(&token) && !out.contains(PHONE),
        "默认模式逐请求互不可见（未注册完整 token 原样透传、不还原）: {out:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn scope_conversation_shares_pii_only_not_minted() {
    let pii = Arc::new(PiiScope::new());
    let p_token = pii.register(PHONE).unwrap();
    let vault = CredentialVault::new();
    let cred_token = vault.register(CRED).unwrap();
    let detector = PiiDetector::new();
    let turn1 = Scope::with_shared_pii(pii.clone(), false);
    let (redacted, _) = turn1
        .redact_request_with_report(&vault, &detector, &format!("use {CRED} now"))
        .await;
    assert!(
        redacted.contains(&cred_token),
        "上轮须产出凭据 token: redacted={redacted:?} token={cred_token:?}"
    );
    let turn2 = Scope::with_shared_pii(pii.clone(), false);
    assert_eq!(
        turn2.restore_response_with_spans(&vault, &p_token).0,
        PHONE,
        "会话共享 PII 映射须跨轮可还原"
    );
    let out = turn2.restore_response_with_spans(&vault, &cred_token).0;
    assert!(
        out.contains(&cred_token) && !out.contains(CRED),
        "minted-set 各自独立：上轮凭据 token 原样透传（不还原）"
    );
}

#[tokio::test]
async fn conversation_mode_b3_request_level_unchanged() {
    let pii = Arc::new(PiiScope::new());
    let vault = CredentialVault::new();
    let cred_token = vault.register(CRED).unwrap();
    let detector = PiiDetector::new();
    let turn1 = Scope::with_shared_pii(pii.clone(), false);
    let (out1, _) = turn1
        .redact_request_with_report(&vault, &detector, &format!("k {CRED} end"))
        .await;
    assert!(
        out1.contains(&cred_token),
        "上轮脱敏须产出凭据 token: out1={out1:?} token={cred_token:?}"
    );
    let turn2 = Scope::with_shared_pii(pii.clone(), false);
    let stripped = turn2.restore_response_with_spans(&vault, &cred_token).0;
    assert!(
        stripped.contains(&cred_token) && !stripped.contains(CRED),
        "上轮凭据 token 在本轮响应原样透传（请求级授权不变）"
    );
    let (..) = turn2
        .redact_request_with_report(&vault, &detector, &format!("k {CRED}"))
        .await;
    assert_eq!(
        turn2.restore_response_with_spans(&vault, &cred_token).0,
        CRED,
        "仅本轮 minted 可还原"
    );
}

#[tokio::test]
async fn conversation_scope_never_holds_credentials() {
    let pii = Arc::new(PiiScope::new());
    let vault = CredentialVault::new();
    let cred_token = vault.register(CRED).unwrap();
    let detector = PiiDetector::new();
    let scope = Scope::with_shared_pii(pii.clone(), false);
    let _ = scope
        .redact_request_with_report(&vault, &detector, &format!("cred {CRED}"))
        .await;
    assert_eq!(
        pii.restore_with_fuzzy(&cred_token, false),
        cred_token,
        "会话 PII 作用域不得持有凭据映射"
    );
}

#[test]
fn pii_token_cross_conversation_not_restored() {
    let store = ConversationScopeStore::new(8, Duration::from_secs(60));
    let k1 = ConversationKey::for_test("k1");
    let k2 = ConversationKey::for_test("k2");
    let token = store.get_or_insert(&k1).register(PHONE).unwrap();
    let other = store.get_or_insert(&k2);
    // 会话 k2 非空，使未知 token 走宽松形态判定路径（空表提前返回）。
    let _ = other.register("11010519491231002X").unwrap();
    let text = format!("x {token} y");
    assert_eq!(
        other.restore_with_fuzzy(&text, false),
        text,
        "跨会话 PII token 不可还原"
    );
}

#[test]
fn pii_token_same_conversation_restored_next_turn() {
    let store = ConversationScopeStore::new(8, Duration::from_secs(60));
    let k1 = ConversationKey::for_test("k1");
    let turn1 = store.get_or_insert(&k1);
    let token = turn1.register(PHONE).unwrap();
    let turn2 = store.get_or_insert(&k1);
    assert!(Arc::ptr_eq(&turn1, &turn2), "同会话须复用同一作用域");
    assert_eq!(
        turn2.restore(&format!("x {token} y")),
        format!("x {PHONE} y")
    );
}

#[test]
fn conversation_restore_spans_json_depth_unchanged() {
    let pii = Arc::new(PiiScope::new());
    let token = pii.register(PHONE).unwrap();
    let scope = Scope::with_shared_pii(pii.clone(), false);
    let vault = CredentialVault::new();
    let frame = format!(r#"{{"a":"{token}"}}"#);
    let (out, spans) = scope.restore_response_with_spans_json(&vault, &frame);
    assert!(!spans.is_empty(), "须还原明文区间");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("还原后须仍可解析");
    assert_eq!(parsed["a"], PHONE);
    let nested = format!(r#"{{"a":"{{\"b\":\"{token}\"}}"}}"#);
    let (out2, spans2) = scope.restore_response_with_spans_json(&vault, &nested);
    assert!(!spans2.is_empty());
    let parsed2: serde_json::Value = serde_json::from_str(&out2).expect("嵌套还原后须仍可解析");
    let inner: serde_json::Value =
        serde_json::from_str(parsed2["a"].as_str().unwrap()).expect("内层须可解析");
    assert_eq!(inner["b"], PHONE, "跨轮还原的 JSON 转义深度语义不变");
}

#[test]
fn scope_default_mode_per_request_unchanged() {
    let vault = CredentialVault::new();
    let first = Scope::with_opts(false);
    let token = first.pii_scope().register(PHONE).unwrap();
    let second = Scope::with_opts(false);
    let out = second.restore_response_with_spans(&vault, &token).0;
    assert!(
        out.contains(&token) && !out.contains(PHONE),
        "默认模式跨请求互不可见（未注册完整 token 原样透传）: {out:?}"
    );
}

#[test]
fn pii_scope_counters_record_reuse_and_eviction() {
    // 复用命中记一次；LRU 容量淘汰与空闲 TTL 淘汰各记对应条数。
    let metrics = Arc::new(GatewayMetrics::default());
    let store =
        ConversationScopeStore::new(1, Duration::from_secs(60)).with_metrics(metrics.clone());
    let k1 = ConversationKey::for_test("k1");
    let k2 = ConversationKey::for_test("k2");
    assert_eq!(metrics.conversation_reuse_count(), 0);
    let _ = store.get_or_insert(&k1);
    assert_eq!(metrics.conversation_reuse_count(), 0, "首次插入非复用");
    let _ = store.get_or_insert(&k1);
    assert_eq!(metrics.conversation_reuse_count(), 1, "命中须记一次复用");
    assert_eq!(metrics.conversation_eviction_count(), 0, "未超限不淘汰");
    let _ = store.get_or_insert(&k2);
    assert_eq!(
        metrics.conversation_eviction_count(),
        1,
        "容量 LRU 淘汰须记一次"
    );

    let (clock, offset) = fake_clock();
    let ttl_metrics = Arc::new(GatewayMetrics::default());
    let ttl_store = ConversationScopeStore::with_clock(4, Duration::from_secs(30), clock)
        .with_metrics(ttl_metrics.clone());
    let kt = ConversationKey::for_test("kt");
    let _ = ttl_store.get_or_insert(&kt);
    *offset.lock().unwrap() = Duration::from_secs(31);
    let _ = ttl_store.get_or_insert(&kt);
    assert_eq!(
        ttl_metrics.conversation_eviction_count(),
        1,
        "空闲 TTL 淘汰须记一次"
    );
    assert_eq!(
        ttl_metrics.conversation_reuse_count(),
        0,
        "淘汰后重建不构成复用"
    );
}

#[test]
fn pii_scope_counters_zero_in_request_mode() {
    // 默认 request 模式不构造/不使用存储，三项计数恒 0（即使携带会话键头）。
    let (state, dir) = test_state(None);
    assert!(
        state.conversation_scope_store.is_none(),
        "request 模式 MUST NOT 构造会话存储"
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-conversation-id", "conv-abc".parse().unwrap());
    let body = serde_json::json!({"prompt_cache_key": "pck-1"});
    let _ = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers,
        crate::service::llm_gateway::Protocol::Chat,
        "https://up.example.com/v1",
        Some(&body),
    );
    let gm = &state.gateway_metrics;
    assert_eq!(gm.conversation_reuse_count(), 0);
    assert_eq!(gm.conversation_eviction_count(), 0);
    assert_eq!(
        gm.request_fallback_count(),
        0,
        "request 模式三项计数恒 0（不计回退）"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// 隔离边界回归：两请求只差 `x-session-affinity` 时 MUST NOT 落进同一 PII 作用域。
///
/// 该头是路由/亲和性提示（可能为常量或跨客户端共享），PII 链刻意不认它，
/// 故两次都退化为逐请求作用域（不同实例、不同键，无跨客户端明文串味）。
#[test]
fn differing_session_affinity_yields_distinct_pii_scopes() {
    let (state, dir) = test_state(Some("conversation"));
    let upstream = "https://up.example.com/v1";
    let body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    let mut client_a = HeaderMap::new();
    client_a.insert("x-session-affinity", "affinity-a".parse().unwrap());
    let mut client_b = HeaderMap::new();
    client_b.insert("x-session-affinity", "affinity-b".parse().unwrap());

    let scope_a = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &client_a,
        crate::service::llm_gateway::Protocol::Chat,
        upstream,
        Some(&body),
    );
    let scope_b = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &client_b,
        crate::service::llm_gateway::Protocol::Chat,
        upstream,
        Some(&body),
    );

    assert!(
        !std::ptr::eq(scope_a.pii_scope(), scope_b.pii_scope()),
        "仅差 x-session-affinity 的请求 MUST NOT 共享 PII 注册表"
    );
    assert!(
        !scope_a.has_writeback() && !scope_b.has_writeback(),
        "PII 链不认 affinity 头，两次均落逐请求"
    );
    assert_eq!(
        state
            .conversation_scope_store
            .as_ref()
            .expect("conversation 模式须构造存储")
            .len(),
        0,
        "affinity 头不得插入会话存储"
    );
    assert_eq!(
        state.gateway_metrics.request_fallback_count(),
        2,
        "两次均计逐请求回退"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 6.1 / spec「PII 作用域不认路由与通用头」：三者单独出现均不构成身份来源，
/// 无用户级来源时 PII 落逐请求、日志会话列取 `none`。
#[test]
fn untrusted_session_headers_are_not_identity_sources() {
    use crate::service::session_identity::{SessionScope, SessionSource};
    let (state, dir) = test_state(Some("conversation"));
    let upstream = "https://up.example.com/v1";
    let body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    for name in [
        "x-session-affinity",
        "x-session-id",
        "x-opencode-parent-session-id",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(name, "shared-constant".parse().unwrap());
        let scope = crate::handler::llm::dispatch::build_request_scope_for_tests(
            &state,
            &headers,
            crate::service::llm_gateway::Protocol::Responses,
            upstream,
            Some(&body),
        );
        assert!(!scope.has_writeback(), "{name} 不得产生 canonical");
        assert!(!scope.has_conversation_scope());

        let identity = crate::service::session_identity::resolve(
            &headers,
            Some(&body),
            crate::service::llm_gateway::Protocol::Responses,
            state.config.session_headers.as_slice(),
            &state.session_alias_map,
            state.conversation_secret.as_ref(),
            &crate::handler::llm::dispatch::request_tenant_fingerprint(&state, &headers, upstream),
        );
        assert_eq!(identity.source, SessionSource::None, "{name}");
        assert_eq!(identity.log_source, SessionSource::None, "{name}");
        assert_eq!(identity.log_scope, SessionScope::None, "{name}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// spec「共享头不得合并两个客户端」：同一 `x-session-affinity` 常量 + 各自不同的
/// 可信头 → 不同 canonical；一方注册的占位符在另一方响应中 MUST NOT 被还原。
#[test]
fn shared_affinity_constant_does_not_merge_two_clients() {
    const PLAINTEXT_A: &str = "13800000001";
    const PLAINTEXT_B: &str = "13800000002";
    let (state, dir) = test_state(Some("conversation"));
    let upstream = "https://up.example.com/v1";
    let body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});

    let mut client_a = HeaderMap::new();
    client_a.insert("x-session-affinity", "shared-constant".parse().unwrap());
    client_a.insert("x-veil-conversation-id", "client-A".parse().unwrap());
    let mut client_b = HeaderMap::new();
    client_b.insert("x-session-affinity", "shared-constant".parse().unwrap());
    client_b.insert("x-veil-conversation-id", "client-B".parse().unwrap());

    let scope_a = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &client_a,
        crate::service::llm_gateway::Protocol::Responses,
        upstream,
        Some(&body),
    );
    let scope_b = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &client_b,
        crate::service::llm_gateway::Protocol::Responses,
        upstream,
        Some(&body),
    );
    assert!(
        !std::ptr::eq(scope_a.pii_scope(), scope_b.pii_scope()),
        "共享 affinity 常量 + 不同的可信头 MUST NOT 合并两个客户端"
    );
    let token_a = scope_a
        .pii_scope()
        .register(PLAINTEXT_A)
        .expect("注册须成功");
    let token_b = scope_b
        .pii_scope()
        .register(PLAINTEXT_B)
        .expect("注册须成功");
    assert_eq!(
        scope_b.pii_scope().restore(&token_a),
        token_a,
        "A 的 token MUST NOT 在 B 的作用域内被还原"
    );
    assert_eq!(scope_a.pii_scope().restore(&token_b), token_b);
    assert_eq!(scope_a.pii_scope().restore(&token_a), PLAINTEXT_A);
    assert_eq!(scope_b.pii_scope().restore(&token_b), PLAINTEXT_B);
    std::fs::remove_dir_all(&dir).ok();
}

/// 对照：两请求只差 `x-opencode-session-id`（同一值）时须复用同一 PII 作用域。
#[test]
fn same_opencode_session_id_shares_one_pii_scope() {
    let (state, dir) = test_state(Some("conversation"));
    let upstream = "https://up.example.com/v1";
    let body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-opencode-session-id",
        "ses_shared_scope_1".parse().unwrap(),
    );
    let mut headers_again = HeaderMap::new();
    headers_again.insert(
        "x-opencode-session-id",
        "ses_shared_scope_1".parse().unwrap(),
    );

    let first = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers,
        crate::service::llm_gateway::Protocol::Chat,
        upstream,
        Some(&body),
    );
    let second = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers_again,
        crate::service::llm_gateway::Protocol::Chat,
        upstream,
        Some(&body),
    );

    assert!(
        std::ptr::eq(first.pii_scope(), second.pii_scope()),
        "同一 x-opencode-session-id 须复用同一 PII 注册表"
    );
    assert_eq!(
        state.gateway_metrics.conversation_reuse_count(),
        1,
        "第二次须记一次复用"
    );
    assert_eq!(
        state
            .conversation_scope_store
            .as_ref()
            .expect("conversation 模式须构造存储")
            .len(),
        1,
        "只应有一个会话条目"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 6.4：同租户 bearer id——客户端 B 携带 A 的 `previous_response_id` /
/// `conversation.id` 时路由到 A 的 canonical 并共享同一 `Arc<PiiScope>`；
/// 别名表只做路由，MUST NOT 新增条目或复制/迁移 PII 条目。
#[test]
fn same_tenant_bearer_id_routes_to_existing_scope_without_copying_pii() {
    const PLAINTEXT: &str = "13800138000";
    let (state, dir) = test_state(Some("conversation"));
    let upstream = "https://up.example.com/v1";

    // A 轮：头 `H-A` 确定 canonical K1。
    let mut headers_a = HeaderMap::new();
    headers_a.insert("x-veil-conversation-id", "H-A".parse().unwrap());
    let scope_a = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers_a,
        crate::service::llm_gateway::Protocol::Responses,
        upstream,
        Some(&serde_json::json!({"messages": []})),
    );
    assert!(scope_a.has_conversation_scope(), "前置：A 须落会话级作用域");
    let token = scope_a.pii_scope().register(PLAINTEXT).expect("注册须成功");
    let canonical = crate::service::redaction::scoped_key(
        state.conversation_secret.as_ref(),
        &crate::handler::llm::dispatch::request_tenant_fingerprint(
            &state,
            &HeaderMap::new(),
            upstream,
        ),
        "H-A",
    );

    // A 的上游 2xx 响应：按生产同路径绑定 `resp_A` 与 `conv_A`。
    let metrics = state.gateway_metrics.clone();
    let mut tracker = crate::service::redaction::CaptureTracker::default();
    tracker.observe(
        scope_a.as_ref(),
        crate::service::llm_gateway::Protocol::Responses,
        200,
        &serde_json::json!({"id": "resp_A", "conversation": {"id": "conv_A"}}),
        metrics.as_ref(),
    );
    let aliases_after_a = state.session_alias_map.len();
    assert_eq!(aliases_after_a, 2, "A 的响应须写两个别名条目");

    // B 同租户：分别只带 `previous_response_id` 与 `conversation.id`。
    for body in [
        serde_json::json!({"previous_response_id": "resp_A", "messages": []}),
        serde_json::json!({"conversation": "conv_A", "messages": []}),
    ] {
        let scope_b = crate::handler::llm::dispatch::build_request_scope_for_tests(
            &state,
            &HeaderMap::new(),
            crate::service::llm_gateway::Protocol::Responses,
            upstream,
            Some(&body),
        );
        assert!(
            std::ptr::eq(scope_a.pii_scope(), scope_b.pii_scope()),
            "同租户 bearer id 须路由到 A 的 PiiScope: {body}"
        );
        assert_eq!(
            scope_b.pii_scope().restore(&token),
            PLAINTEXT,
            "A 的既有 token 在 B 侧须可还原（同一注册表）"
        );
        let new_token = scope_b
            .pii_scope()
            .register("13900139000")
            .expect("注册须成功");
        assert_eq!(
            scope_a.pii_scope().restore(&new_token),
            "13900139000",
            "B 新注册的值须进入同一 canonical（A 侧可见），不另建条目"
        );
    }

    assert_eq!(
        state.session_alias_map.len(),
        aliases_after_a,
        "别名解析 MUST NOT 新增条目（只路由，不复制/迁移）"
    );
    assert_eq!(
        state
            .conversation_scope_store
            .as_ref()
            .expect("conversation 模式须构造存储")
            .len(),
        1,
        "同一 canonical 只有一个作用域"
    );
    assert!(
        state
            .session_alias_map
            .resolve(
                state.conversation_secret.as_ref(),
                &crate::handler::llm::dispatch::request_tenant_fingerprint(
                    &state,
                    &HeaderMap::new(),
                    upstream,
                ),
                "resp_A",
            )
            .is_some_and(|k| k == canonical),
        "A 的别名绑定须保持不变"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 6.4：跨租户（不同 `tenant_fingerprint`）不得解析他人 bearer id——
/// `conversation.id` 回退原生派生（新作用域），`previous_response_id` 未命中即回退逐请求。
#[test]
fn cross_tenant_bearer_id_does_not_resolve_and_falls_back() {
    const PLAINTEXT: &str = "13900139000";
    let (state, dir) = test_state(Some("conversation"));
    let upstream_a = "https://up.example.com/v1/a";
    let upstream_b = "https://up.example.com/v1/b";

    let mut headers_a = HeaderMap::new();
    headers_a.insert("x-veil-conversation-id", "H-X".parse().unwrap());
    let scope_a = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers_a,
        crate::service::llm_gateway::Protocol::Responses,
        upstream_a,
        Some(&serde_json::json!({"messages": []})),
    );
    let _token = scope_a.pii_scope().register(PLAINTEXT).expect("注册须成功");
    let metrics = state.gateway_metrics.clone();
    let mut tracker = crate::service::redaction::CaptureTracker::default();
    tracker.observe(
        scope_a.as_ref(),
        crate::service::llm_gateway::Protocol::Responses,
        200,
        &serde_json::json!({"id": "resp_X", "conversation": {"id": "conv_X"}}),
        metrics.as_ref(),
    );

    // 租户 B 携带 `conversation=conv_X`：因租户分域未命中，回退 `scoped_key(conv_X)`。
    let scope_b = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &HeaderMap::new(),
        crate::service::llm_gateway::Protocol::Responses,
        upstream_b,
        Some(&serde_json::json!({"conversation": "conv_X", "messages": []})),
    );
    assert!(
        !std::ptr::eq(scope_a.pii_scope(), scope_b.pii_scope()),
        "跨租户 MUST NOT 共享 PII 作用域"
    );
    assert!(
        scope_b.has_writeback(),
        "conversation 未命中仍须按原生派生得出 canonical"
    );

    // 租户 B 仅带 `previous_response_id=resp_X`：未命中即回退逐请求。
    let scope_prev = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &HeaderMap::new(),
        crate::service::llm_gateway::Protocol::Responses,
        upstream_b,
        Some(&serde_json::json!({"previous_response_id": "resp_X", "messages": []})),
    );
    assert!(
        !scope_prev.has_writeback(),
        "跨租户 previous_response_id 未命中须回退逐请求"
    );
    assert!(!scope_prev.has_conversation_scope());
    std::fs::remove_dir_all(&dir).ok();
}

/// 测试内最小 tracing 捕获订阅者：记录每条事件的级别与字段渲染文本。
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<String>>>);

struct FieldVisitor<'a>(&'a mut String);

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = event.metadata().level().to_string();
        event.record(&mut FieldVisitor(&mut line));
        self.0.lock().unwrap().push(line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn conversation_key_not_logged() {
    // 日志层：conversation 模式请求作用域路径（含 debug 级）不得出现头值/会话键/明文/token。
    let (state, dir) = test_state(Some("conversation"));
    let header_value = "conv-7f3a9c2e-secret";
    let plaintext = PHONE;
    let upstream = "https://up.example.com/v1";
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-conversation-id", header_value.parse().unwrap());
    let body = serde_json::json!({"messages": [{"role": "user", "content": plaintext}]});
    let capture = LogCapture::default();
    let sink = capture.0.clone();
    let (scope, token) = crate::test_support::with_capture_subscriber(capture, || {
        let scope = crate::handler::llm::dispatch::build_request_scope_for_tests(
            &state,
            &headers,
            crate::service::llm_gateway::Protocol::Responses,
            upstream,
            Some(&body),
        );
        let token = scope.pii_scope().register(plaintext).unwrap();
        tracing::debug!(canary = "capture-active", "日志捕获自检");
        (scope, token)
    });
    drop(scope);
    assert_eq!(
        state
            .conversation_scope_store
            .as_ref()
            .expect("conversation 模式须构造存储")
            .len(),
        1,
        "会话键推导与存储插入路径须确实执行"
    );
    assert_eq!(
        state.gateway_metrics.conversation_reuse_count(),
        0,
        "首轮插入不构成复用"
    );
    let secret = state.conversation_secret.as_ref();
    let fp = tenant_fingerprint(secret, upstream, &[]);
    let key = scoped_key(secret, &fp, header_value);
    let lines = sink.lock().unwrap().clone();
    assert!(
        lines.iter().any(|l| l.contains("capture-active")),
        "捕获机制须生效（否则断言空洞）: {lines:?}"
    );
    for line in &lines {
        assert!(!line.contains(header_value), "日志不得含头值: {line}");
        assert!(!line.contains(plaintext), "日志不得含明文: {line}");
        assert!(!line.contains(&token), "日志不得含 token: {line}");
        assert!(!line.contains(key.as_str()), "日志不得含会话键: {line}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn responses_scalar_input_falls_to_per_request_counted() {
    // Responses 标量 input 落第 4 级逐请求并计 `request_fallback`；
    // 数组 input 正常命中第 3 级、不产生回退。
    let (state, dir) = test_state(Some("conversation"));
    let headers = HeaderMap::new();
    let upstream = "https://up.example.com/v1";
    let scalar = serde_json::json!({
        "tools": [{"name": "t"}],
        "instructions": "be nice",
        "input": "当前轮全文，随轮次增长",
    });
    let _ = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers,
        crate::service::llm_gateway::Protocol::Responses,
        upstream,
        Some(&scalar),
    );
    assert_eq!(
        state.gateway_metrics.request_fallback_count(),
        1,
        "标量 input 须计回退"
    );
    assert_eq!(
        state
            .conversation_scope_store
            .as_ref()
            .expect("conversation 模式须构造存储")
            .len(),
        0,
        "落第 4 级不得插入会话存储"
    );
    let array = serde_json::json!({
        "tools": [{"name": "t"}],
        "instructions": "be nice",
        "input": [{"role": "user", "content": "hello"}],
    });
    let _ = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers,
        crate::service::llm_gateway::Protocol::Responses,
        upstream,
        Some(&array),
    );
    assert_eq!(
        state.gateway_metrics.request_fallback_count(),
        1,
        "数组 input 不得回退"
    );
    assert_eq!(
        state
            .conversation_scope_store
            .as_ref()
            .expect("conversation 模式须构造存储")
            .len(),
        1,
        "数组 input 须命中第 3 级并插入会话"
    );
    std::fs::remove_dir_all(&dir).ok();
}
