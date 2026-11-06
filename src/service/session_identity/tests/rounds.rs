//! 关键跨轮序列（tasks 6.2）：真实 `SessionAliasMap` + `ConversationScopeStore` +
//! `PiiScope` 下，头 → `conversation` → `previous_response_id` 必须收敛到**同一**
//! canonical 与同一共享 `PiiScope`，且第 2 轮能还原第 1 轮铸造的 PII token。
//!
//! 另一组覆盖 `prompt_cache_key` 与稳定前缀作为首轮来源、`conversation` 作为次轮
//! 来源时同样收敛；以及别名逐出后的未命中回退。

use {
    super::*,
    crate::service::{
        llm_gateway::GatewayMetrics,
        pii::PiiScope,
        redaction::{
            ConversationScopeStore,
            Scope,
            writeback::{CaptureTracker, ConversationWriteback},
        },
        request_log::session_digest,
    },
    std::{sync::Arc, time::Duration},
};

const DIGEST_KEY: &[u8] = b"rounds-digest-key";
const PLAINTEXT: &str = "13800001111";

/// 跨轮夹具：别名表 + 共享作用域存储 + 度量（整段会话共用同一实例）。
struct Rounds {
    alias: Arc<SessionAliasMap>,
    store: ConversationScopeStore,
    metrics: Arc<GatewayMetrics>,
}

impl Rounds {
    fn new(alias_capacity: usize) -> Self {
        let metrics = Arc::new(GatewayMetrics::default());
        Self {
            alias: Arc::new(
                SessionAliasMap::new(alias_capacity).with_metrics(Arc::clone(&metrics)),
            ),
            store: ConversationScopeStore::new(8, Duration::from_secs(3600)),
            metrics,
        }
    }

    fn resolve(&self, headers: &HeaderMap, body: &serde_json::Value) -> SessionIdentity {
        resolve_with(headers, Some(body), Protocol::Responses, &self.alias)
    }

    /// 打开一轮请求的作用域：共享 `PiiScope`（来自存储）+ 会话写回。
    fn open(&self, identity: &SessionIdentity) -> (Arc<PiiScope>, Arc<Scope>) {
        let canonical = identity.canonical.as_ref().expect("本用例须有 canonical");
        let pii = self.store.get_or_insert(canonical);
        let writeback = ConversationWriteback::new(
            identity.clone(),
            Arc::<[u8]>::from(SECRET),
            Arc::clone(&self.alias),
        );
        let scope =
            Scope::with_shared_pii(Arc::clone(&pii), false).with_conversation(writeback, true);
        (pii, Arc::new(scope))
    }

    /// 模拟上游 2xx 响应：绑定 `response.id` 与响应新出现的 `conversation.id`。
    fn respond(&self, scope: &Scope, response_id: &str, conversation_id: &str) {
        let mut tracker = CaptureTracker::default();
        let captured = tracker.observe(
            scope,
            Protocol::Responses,
            200,
            &json!({
                "id": response_id,
                "conversation": {"id": conversation_id},
            }),
            &self.metrics,
        );
        assert_eq!(captured.response_id.as_deref(), Some(response_id));
        assert_eq!(captured.conversation_id.as_deref(), Some(conversation_id));
        assert_eq!(self.metrics.conversation_writeback_miss_count(), 0);
        assert_eq!(self.metrics.session_bind_miss_count(), 0);
    }
}

/// Responses 形态的稳定前缀体：`tools` + `instructions` + 数组形 `input`。
fn responses_prefix_body() -> serde_json::Value {
    json!({
        "tools": [{"type": "function", "name": "alpha"}],
        "instructions": "you are helpful",
        "input": [{"role": "user", "content": "hello"}],
    })
}

fn digest(identity: &SessionIdentity) -> Option<String> {
    session_digest(
        DIGEST_KEY,
        Protocol::Responses.wire_name(),
        identity.canonical.as_ref()?.as_str(),
    )
}

#[test]
fn header_then_conversation_shares_one_scope_and_restores_first_round_token() {
    let rounds = Rounds::new(8);

    // 第 1 轮：头 `H` → canonical K1，响应绑定 `resp_1` 与 `conv_1`。
    let id1 = rounds.resolve(
        &headers(&[("x-veil-conversation-id", "H")]),
        &json!({"messages": []}),
    );
    let k1 = id1.canonical.clone().expect("头命中须有 canonical");
    assert_eq!(id1.source, SessionSource::Header);
    let (pii1, scope1) = rounds.open(&id1);
    let token = pii1.register(PLAINTEXT).expect("注册须成功");
    assert_ne!(token, PLAINTEXT, "须为占位符而非明文");
    rounds.respond(scope1.as_ref(), "resp_1", "conv_1");
    assert_eq!(
        rounds.alias.resolve(SECRET, TENANT, "resp_1"),
        Some(k1.clone())
    );
    assert_eq!(
        rounds.alias.resolve(SECRET, TENANT, "conv_1"),
        Some(k1.clone())
    );

    // 第 2 轮：仅 `conversation=conv_1` → 别名命中 K1，不另建键。
    let id2 = rounds.resolve(&HeaderMap::new(), &json!({"conversation": "conv_1"}));
    assert_eq!(
        id2.canonical,
        Some(k1.clone()),
        "conversation 须经别名命中 K1（MUST NOT 以 conv_1 原生派生）"
    );
    assert_eq!(id2.source, SessionSource::Conversation);
    let (pii2, _scope2) = rounds.open(&id2);
    assert!(
        Arc::ptr_eq(&pii1, &pii2),
        "同一 canonical 必须复用同一 PiiScope（MUST NOT 分裂成两个）"
    );
    assert_eq!(rounds.store.len(), 1, "同一逻辑会话只有一个作用域条目");
    // 第 1 轮 token 在第 2 轮可还原，同值再注册复用同一 token。
    assert_eq!(pii2.register(PLAINTEXT).expect("注册须成功"), token);
    assert_eq!(pii2.restore(&token), PLAINTEXT);
    assert_eq!(digest(&id1), digest(&id2), "同一 canonical 摘要须相同");
}

#[test]
fn header_conversation_previous_response_three_rounds_converge() {
    let rounds = Rounds::new(8);

    let id_header = rounds.resolve(
        &headers(&[("x-veil-conversation-id", "H3")]),
        &json!({"messages": []}),
    );
    let k1 = id_header.canonical.clone().expect("头命中须有 canonical");
    let (_pii, scope) = rounds.open(&id_header);
    rounds.respond(scope.as_ref(), "resp_1", "conv_1");

    let id_conv = rounds.resolve(&HeaderMap::new(), &json!({"conversation": "conv_1"}));
    let id_prev = rounds.resolve(
        &HeaderMap::new(),
        &json!({"previous_response_id": "resp_1"}),
    );

    for id in [&id_conv, &id_prev] {
        assert_eq!(id.canonical, Some(k1.clone()));
    }
    assert_eq!(id_conv.source, SessionSource::Conversation);
    assert_eq!(id_prev.source, SessionSource::PrevResponse);
    assert_eq!(id_conv.log_source, SessionSource::Conversation);
    assert_eq!(id_prev.log_source, SessionSource::PrevResponse);

    let header_digest = digest(&id_header).expect("须有摘要");
    assert_eq!(digest(&id_conv).as_deref(), Some(header_digest.as_str()));
    assert_eq!(digest(&id_prev).as_deref(), Some(header_digest.as_str()));
    assert_eq!(
        session_digest(DIGEST_KEY, Protocol::Responses.wire_name(), k1.as_str()).as_deref(),
        Some(header_digest.as_str()),
        "摘要须对 canonical 而非原始锚点计算"
    );
}

#[test]
fn prompt_cache_key_then_conversation_converges() {
    let rounds = Rounds::new(8);

    let round1 = rounds.resolve(
        &HeaderMap::new(),
        &json!({"prompt_cache_key": "pck-1", "messages": []}),
    );
    assert_eq!(round1.source, SessionSource::CacheKey);
    let canonical = round1.canonical.clone().expect("④ 须产出 canonical");
    let (_pii, scope) = rounds.open(&round1);
    rounds.respond(scope.as_ref(), "resp_pck", "conv_pck");

    let round2 = rounds.resolve(&HeaderMap::new(), &json!({"conversation": "conv_pck"}));
    assert_eq!(round2.canonical, Some(canonical));
    assert_eq!(rounds.store.len(), 1);
}

#[test]
fn stable_prefix_then_conversation_converges() {
    let rounds = Rounds::new(8);

    let round1 = rounds.resolve(&HeaderMap::new(), &responses_prefix_body());
    let canonical = round1.canonical.clone().expect("稳定前缀须产出 canonical");
    assert_eq!(round1.source, SessionSource::None, "⑤ 不产生日志来源");
    let (_pii, scope) = rounds.open(&round1);
    rounds.respond(scope.as_ref(), "resp_prefix", "conv_prefix");

    let round2 = rounds.resolve(&HeaderMap::new(), &json!({"conversation": "conv_prefix"}));
    assert_eq!(
        round2.canonical,
        Some(canonical),
        "稳定前缀首轮 + conversation 次轮须收敛"
    );
    assert_eq!(round2.source, SessionSource::Conversation);
    assert_eq!(rounds.store.len(), 1, "MUST NOT 分裂成两个作用域");
}

#[test]
fn evicted_alias_falls_back_to_native_derivation() {
    // 容量 1：后续绑定逐出最旧条目；被逐出的标识解析未命中 → 回退原生派生。
    let rounds = Rounds::new(1);

    let round1 = rounds.resolve(
        &headers(&[("x-veil-conversation-id", "H-evict")]),
        &json!({"messages": []}),
    );
    let k1 = round1.canonical.clone().expect("头命中须有 canonical");
    let (_pii, scope) = rounds.open(&round1);
    rounds.respond(scope.as_ref(), "resp_old", "conv_old");
    rounds.respond(scope.as_ref(), "resp_new", "conv_new");
    assert!(
        rounds.metrics.session_alias_evict_count() >= 1,
        "容量 1 下写入须逐出"
    );
    assert!(rounds.alias.resolve(SECRET, TENANT, "conv_old").is_none());
    assert!(rounds.alias.len() <= 1, "容量恒有界");

    let fallback = rounds.resolve(&HeaderMap::new(), &json!({"conversation": "conv_old"}));
    assert_eq!(fallback.source, SessionSource::Conversation);
    assert_eq!(
        fallback.canonical,
        Some(scoped_key(SECRET, TENANT, "conv_old")),
        "逐出后须回退原生派生，MUST NOT 报错"
    );
    assert_ne!(fallback.canonical, Some(k1), "逐出后键可变化（已登记边界）");
    assert_eq!(rounds.metrics.conversation_writeback_miss_count(), 0);
    assert_eq!(rounds.metrics.session_bind_miss_count(), 0);
}

#[test]
fn alias_miss_changes_derived_digest_but_stays_consistent() {
    // 第 1 轮头 `H` → K1；别名表为空时第 2 轮 `conversation=C` 未命中 →
    // `scoped_key(C)` 新 canonical，日志摘要随之变化且不告警（spec 已登记边界）。
    let rounds = Rounds::new(8);
    let header_round = rounds.resolve(
        &headers(&[("x-veil-conversation-id", "H-miss")]),
        &json!({"messages": []}),
    );
    let miss_round = rounds.resolve(&HeaderMap::new(), &json!({"conversation": "C-miss"}));

    assert_eq!(
        miss_round.source,
        SessionSource::Conversation,
        "来源仍为 conversation"
    );
    assert_ne!(
        miss_round.canonical, header_round.canonical,
        "别名未命中须按 scoped_key(C) 派生新 canonical"
    );
    let header_digest = digest(&header_round).expect("须有摘要");
    let miss_digest = digest(&miss_round).expect("须有摘要");
    assert_ne!(
        header_digest, miss_digest,
        "日志 session_id 须随 canonical 变化"
    );

    // 同一输入再解析（仍是未命中）结果稳定，不得两次不同。
    let again = rounds.resolve(&HeaderMap::new(), &json!({"conversation": "C-miss"}));
    assert_eq!(again.canonical, miss_round.canonical);
    assert_eq!(digest(&again).as_deref(), Some(miss_digest.as_str()));
}
