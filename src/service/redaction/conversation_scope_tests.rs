//! 会话作用域存储 + 授权域不对称测试（sibling，`conversation_store.rs`）。

use {
    super::ConversationScopeStore,
    crate::{
        config::Config,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::GatewayMetrics,
            pii::{PII_MAX_ENTRIES, PiiDetector, PiiScope},
            redaction::{ConversationKey, Scope, derive_conversation_key, tenant_fingerprint},
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
            let _ = scope.register(&format!("value-{i}-{j}"), false).unwrap();
        }
    }
    assert!(store.len() <= 3);
    let mut total = 0usize;
    for i in 0..3 {
        let key = ConversationKey::for_test(&format!("k{i}"));
        let scope = store.get_or_insert(&key);
        let (request, response) = scope.table_sizes();
        assert!(
            request <= PII_MAX_ENTRIES,
            "单请求表须受 PII_MAX_ENTRIES 约束"
        );
        assert!(
            response <= PII_MAX_ENTRIES,
            "单响应表须受 PII_MAX_ENTRIES 约束"
        );
        total += request + response;
    }
    let bound = 3 * PII_MAX_ENTRIES * 2;
    assert!(
        total <= bound,
        "聚合上界须为 会话数×单会话条目×2: {total} <= {bound}"
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
            std::thread::spawn(move || scope.register(PHONE, false).unwrap())
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
    let token = scope.register(PHONE, false).unwrap();
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
    let first = store.get_or_insert(&k1).register(PHONE, false).unwrap();
    let _ = store.get_or_insert(&k2);
    let second = store.get_or_insert(&k1).register(PHONE, false).unwrap();
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
        &state.previous_response_map,
        &cloned.previous_response_map
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
    let first = Scope::with_opts(true, false);
    let token = first.pii_scope().register(PHONE, false).unwrap();
    let second = Scope::with_opts(true, false);
    assert_eq!(
        second.restore_response_with_spans(&vault, &token).0,
        token,
        "默认模式逐请求、跨请求互不可见（零行为变化）"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn scope_conversation_shares_pii_only_not_minted() {
    let pii = Arc::new(PiiScope::new());
    let p_token = pii.register(PHONE, false).unwrap();
    let vault = CredentialVault::new();
    let cred_token = vault.register(CRED).unwrap();
    let detector = PiiDetector::new();
    let turn1 = Scope::with_shared_pii(pii.clone(), true, false);
    let (redacted, _) = turn1
        .redact_request_with_report(&vault, &detector, &format!("use {CRED} now"))
        .await;
    assert!(
        redacted.contains(&cred_token),
        "上轮须产出凭据 token: redacted={redacted:?} token={cred_token:?}"
    );
    let turn2 = Scope::with_shared_pii(pii.clone(), true, false);
    assert_eq!(
        turn2.restore_response_with_spans(&vault, &p_token).0,
        PHONE,
        "会话共享 PII 映射须跨轮可还原"
    );
    let out = turn2.restore_response_with_spans(&vault, &cred_token).0;
    assert!(
        !out.contains(&cred_token) && !out.contains(CRED),
        "minted-set 各自独立：上轮凭据 token 须被剥离"
    );
}

#[tokio::test]
async fn conversation_mode_b3_request_level_unchanged() {
    let pii = Arc::new(PiiScope::new());
    let vault = CredentialVault::new();
    let cred_token = vault.register(CRED).unwrap();
    let detector = PiiDetector::new();
    let turn1 = Scope::with_shared_pii(pii.clone(), true, false);
    let (out1, _) = turn1
        .redact_request_with_report(&vault, &detector, &format!("k {CRED} end"))
        .await;
    assert!(
        out1.contains(&cred_token),
        "上轮脱敏须产出凭据 token: out1={out1:?} token={cred_token:?}"
    );
    let turn2 = Scope::with_shared_pii(pii.clone(), true, false);
    let stripped = turn2.restore_response_with_spans(&vault, &cred_token).0;
    assert!(
        !stripped.contains(&cred_token) && !stripped.contains(CRED),
        "上轮凭据 token 在本轮响应被剥离（B3 请求级授权不变）"
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
    let scope = Scope::with_shared_pii(pii.clone(), true, false);
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
    let token = store.get_or_insert(&k1).register(PHONE, false).unwrap();
    let other = store.get_or_insert(&k2);
    // 会话 k2 非空，使未知 token 走审计计数路径（空表提前返回不计数）。
    let _ = other.register("11010519491231002X", false).unwrap();
    let text = format!("x {token} y");
    assert_eq!(
        other.restore_with_fuzzy(&text, false),
        text,
        "跨会话 PII token 不可还原"
    );
    assert!(
        other.audit_count("unregistered") >= 1,
        "跨会话还原失败须记审计计数"
    );
}

#[test]
fn pii_token_same_conversation_restored_next_turn() {
    let store = ConversationScopeStore::new(8, Duration::from_secs(60));
    let k1 = ConversationKey::for_test("k1");
    let turn1 = store.get_or_insert(&k1);
    let token = turn1.register(PHONE, false).unwrap();
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
    let token = pii.register(PHONE, false).unwrap();
    let scope = Scope::with_shared_pii(pii.clone(), true, false);
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
    let first = Scope::with_opts(true, false);
    let token = first.pii_scope().register(PHONE, false).unwrap();
    let second = Scope::with_opts(true, false);
    assert_eq!(
        second.restore_response_with_spans(&vault, &token).0,
        token,
        "默认模式跨请求互不可见"
    );
}

#[test]
fn pii_scope_counters_record_reuse_and_eviction() {
    // D12：复用命中记一次；LRU 容量淘汰与空闲 TTL 淘汰各记对应条数。
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
    // D12：默认 request 模式不构造/不使用存储，三项计数恒 0（即使携带会话键头）。
    let (state, dir) = test_state(None);
    assert!(
        state.conversation_scope_store.is_none(),
        "request 模式 MUST NOT 构造会话存储"
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-conversation-id", "conv-abc".parse().unwrap());
    let body = serde_json::json!({"prompt_cache_key": "pck-1"});
    let _ = crate::handler::llm::dispatch::build_request_scope(
        &state,
        &headers,
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
    // D12 日志层：conversation 模式请求作用域路径（含 debug 级）不得出现头值/会话键/明文/token。
    let (state, dir) = test_state(Some("conversation"));
    let header_value = "conv-7f3a9c2e-secret";
    let plaintext = PHONE;
    let upstream = "https://up.example.com/v1";
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-conversation-id", header_value.parse().unwrap());
    let body = serde_json::json!({"messages": [{"role": "user", "content": plaintext}]});
    let capture = LogCapture::default();
    let sink = capture.0.clone();
    let (scope, token) = tracing::subscriber::with_default(capture, || {
        let scope = crate::handler::llm::dispatch::build_request_scope(
            &state,
            &headers,
            upstream,
            Some(&body),
        );
        let token = scope.pii_scope().register(plaintext, false).unwrap();
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
    let key = derive_conversation_key(secret, &fp, Some(header_value), None, None, None, None)
        .expect("显式头须可推导会话键");
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
