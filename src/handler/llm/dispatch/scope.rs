//! 请求作用域装配：租户指纹 + 身份解析后的 `PiiScope` 选择与会话写回挂载。
//!
//! 从 `dispatch.rs` 拆出（生产文件行数红线）：只做纯装配、无网络 I/O，调用点是
//! `dispatch::serve_inner` 的身份解析之后。

use {
    super::session_identity,
    crate::{
        service::{
            redaction::{Scope, tenant_fingerprint, writeback::ConversationWriteback},
            session_identity::{SessionIdentity, first_rejected_header},
        },
        state::AppState,
    },
    axum::http::HeaderMap,
    std::sync::Arc,
};

/// 租户指纹可区分凭据头（可选次判别项）：Authorization / api-key。
const CREDENTIAL_HEADER_NAMES: [&str; 3] = ["authorization", "x-api-key", "api-key"];

/// 计算本次请求的租户指纹：`HMAC(secret, 完整上游基址 || 凭据头归一化)`。
///
/// 每次请求**只调用一次**（解析身份前），结果同时供身份解析、别名绑定与出站标识
/// 复用，响应阶段 MUST NOT 重新推导。
///
/// 隔离边界：上游 key 由 `[llm.targets].headers` 注入时客户端不发凭据头，
/// `tenant_fingerprint` 对所有客户端相同；路由/通用头（`x-session-affinity` 常为固定
/// 常量、`x-session-id` 常被代理复用）一旦纳入键，两个逻辑客户端会共用一个
/// `PiiScope` 注册表，一方的明文可被还原进另一方响应——它们现由启动期校验拒出
/// `[session].headers`。
pub(crate) fn request_tenant_fingerprint(
    state: &AppState,
    headers: &HeaderMap,
    upstream_base: &str,
) -> String {
    let credentials: Vec<&str> = CREDENTIAL_HEADER_NAMES
        .iter()
        .filter_map(|name| {
            headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
        })
        .collect();
    tenant_fingerprint(
        state.conversation_secret.as_ref(),
        upstream_base,
        &credentials,
    )
}

/// 作用域选择：`request` 逐请求 `PiiScope`；`conversation` 用已解析的
/// `identity.canonical` 从共享存储取 `Arc<PiiScope>`，键不可推导时回退逐请求。
/// `conversation` 模式下的逐请求回退计入 `request_fallback`（`request` 模式不计）。
///
/// 两种模式在 canonical 存在时都会挂载 [`ConversationWriteback`]——`request` 模式
/// 仅跳过 `ConversationScopeStore` 创建，别名绑定/解析照常（spec「身份解析与模式正交」）。
///
/// 可判定降级事件：仅三类记内部计数 + `warn!`（不含键/头值/明文/token）——
/// ① 身份无 canonical 落逐请求；② `ConversationScopeStore` 缺失回退；③ 会话头
/// 存在但非法被丢弃（仅当头链未命中且确有非法候选时）。
///
/// 非目标：键推导不做网络 I/O、不保留「上次命中级别/上次键」状态，故「同一会话在
/// 非首轮静默换键或级别变化」不可观测；本函数不提供该信号，亦不新增下游可观测响应头。
pub(crate) fn build_request_scope(
    state: &AppState,
    identity: &SessionIdentity,
    headers: &HeaderMap,
) -> Arc<Scope> {
    let fuzzy_restore = state.config.pii_fuzzy_restore;
    let conversation_mode = state.config.pii_scope_mode.is_conversation();
    let per_request = || Arc::new(Scope::with_opts(fuzzy_restore));
    // 可判定事件 ③：会话头存在但非法（超长/控制字符/非 ASCII/非 UTF-8）被丢弃。
    // 仅当本次身份**未**由头链命中且头链确有非法候选时告警——告警只曝头名，
    // 绝不曝头值（与指标面同强度）。
    if conversation_mode
        && identity.source != session_identity::SessionSource::Header
        && let Some(rejected) =
            first_rejected_header(headers, state.config.session_headers.as_slice())
    {
        state.gateway_metrics.record_conversation_header_invalid();
        tracing::warn!(
            header = %rejected,
            "会话头存在但非法，已丢弃且不参与身份解析"
        );
    }
    let Some(canonical) = identity.canonical.as_ref() else {
        // 无 canonical：落逐请求，不挂写回。`conversation` 模式下计回退 + warn；
        // `request` 模式不递增 `request_fallback`（保持既有指标语义）。
        if conversation_mode {
            state.gateway_metrics.record_request_fallback();
            tracing::warn!("会话身份无 canonical 键，回退逐请求作用域（缓存失配属预期降级）");
        }
        return per_request();
    };
    // 两种模式在 canonical 存在时都构造写回——`request` 模式仅跳过
    // `ConversationScopeStore`，别名绑定/解析照常（spec「身份解析与模式正交」）。
    let new_writeback = || {
        ConversationWriteback::new(
            identity.clone(),
            state.conversation_secret.clone(),
            state.session_alias_map.clone(),
        )
    };
    if !conversation_mode {
        return Arc::new(Scope::with_opts(fuzzy_restore).with_conversation(new_writeback(), false));
    }
    let Some(store) = state.conversation_scope_store.as_ref() else {
        // `conversation` 模式但存储缺失——回退逐请求并计数；canonical 存在时
        // 仍挂载写回（与 request 模式同义：仅跳过共享 `PiiScope`），避免别名
        // 绑定丢失、并把 `session_bind_miss` 误计为「无 canonical」。
        state.gateway_metrics.record_request_fallback();
        state.gateway_metrics.record_conversation_store_missing();
        tracing::warn!("conversation 模式会话存储缺失，回退逐请求作用域（缓存失配属预期降级）");
        return Arc::new(Scope::with_opts(fuzzy_restore).with_conversation(new_writeback(), false));
    };
    let pii = store.get_or_insert(canonical);
    Arc::new(Scope::with_shared_pii(pii, fuzzy_restore).with_conversation(new_writeback(), true))
}
