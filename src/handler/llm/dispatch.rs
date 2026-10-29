//! LLM 网关入口分发（自 `mod.rs` 拆出）：`llm_proxy_handler` 入口 +
//! `gateway_serve` 协议分发（对话改写/流泵 vs 非对话透传）。

use {
    super::{
        ExpandCtx,
        NondialogCtx,
        NonstreamCtx,
        NonstreamOutcome,
        RequestCtx,
        StreamPumpCtx,
        build_sse_response,
        forward_headers,
        is_event_stream,
        serve_detailed,
        serve_nondialog_detailed,
        spawn_stream_pump,
        trace::{
            NonstreamDetail,
            Outcome,
            RequestTrace,
            StreamLog,
            record_row,
            upstream_authority as trace_authority,
        },
    },
    crate::{
        error::VeilError,
        router::{RequestId, generated_request_id},
        service::{
            json_walk,
            llm_gateway::{self, Protocol, resolve_protocol, resolve_target},
            metrics::SampleBinding,
            redaction::{
                Scope,
                derive_conversation_key,
                explicit_header,
                leaf::{
                    NORMALIZED_HEADER_NAME,
                    NORMALIZED_HEADER_VALUE,
                    PROTOCOL_HEADER_NAME,
                    RedactionTally,
                },
                tenant_fingerprint,
            },
            request_log::{
                pii_scope_header_name,
                pii_scope_header_present,
                resolve_pii_scope_header,
            },
        },
        state::AppState,
    },
    axum::{
        Json,
        body::Body,
        extract::{Request, State},
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::json,
    std::{sync::Arc, time::Instant},
};

/// 通用 ingress 超限响应：413 + 错误码 `E_PAYLOAD_TOO_LARGE`。
fn payload_too_large(limit: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({"error":{"code":"E_PAYLOAD_TOO_LARGE","message":format!("请求体超过上限 {limit} 字节")}})),
    )
        .into_response()
}

/// 生产请求体 JSON 解析统一经中央 `json_walk::{strip_bom, jloads}`——
/// 先剥前导 BOM 再解析，使 BOM 前缀体与非 BOM 体解析结果一致（不再落解析失败回退）。
fn parse_request_json(bytes: &[u8]) -> Option<serde_json::Value> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| json_walk::jloads(json_walk::strip_bom(s)).ok())
}

/// 脱敏链 fail-closed 守门——`Scope` 报告 rand8 熵源/内部故障时，以
/// `502 + E_PII_UNAVAILABLE`（`VeilError::into_response` 集中装配错误体）收敛，
/// MUST NOT 转发未脱敏/部分脱敏正文。返回 `None` 表示脱敏链健康、可继续。
fn pii_fail_closed(scope: &Scope) -> Option<Response> {
    scope
        .pii_unavailable()
        .then(|| VeilError::PiiUnavailable.into_response())
}

/// spawn 包裹 + 立即 await 的语义容器：
/// 1) panic 兜底：spawn 任务内 panic 被隔离为 `JoinError`，统一转 500 （不穿透为下游连接中断）；
/// 2) 断连续跑：任务所有权脱离 handler future，客户端断连致 handler 被 `drop`
///    时任务仍续跑至完成（审计/用量落库完整）。
///
/// 正常路径与直接 await 等价，无并发收益。
async fn spawn_contained<F>(fut: F) -> Response
where
    F: std::future::Future<Output = Response> + Send + 'static,
{
    match crate::logging::spawn_in_request_span(fut).await {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":{"code":"E_INTERNAL","message":"内部错误"}})),
        )
            .into_response(),
    }
}

pub async fn llm_proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    spawn_contained(async move {
        // 通用 ingress JSON 检查点 10MB：
        // 超限返回 413，MUST NOT 以 `unwrap_or_default` 静默为空体继续处理。
        let body_bytes = match axum::body::to_bytes(body, super::GATEWAY_BODY_LIMIT_BYTES).await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => return payload_too_large(super::GATEWAY_BODY_LIMIT_BYTES),
        };
        gateway_serve(&state, &mut parts, &path, body_bytes).await
    })
    .await
}

/// 入站 query 保序拼接上游 URL。`path` 取 `uri.path()`，query 取
/// `Uri::query()` 原始切片（不重排、不重编码、不丢空值参数），无 query 时
/// SHALL NOT 追加 `?`；上游基址自带 query（`?x=y`）时把入站 query 以 `&`
/// 合并到基址 query 之后，避免双 `?`（边界）。
fn build_upstream_url(base: &str, path: &str, inbound_query: Option<&str>) -> String {
    let (raw_path, base_query) = match base.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (base, None),
    };
    let base_path = raw_path.trim_end_matches('/');
    let mut url = format!("{base_path}{path}");
    let query = match (base_query, inbound_query) {
        (Some(b), Some(i)) => Some(format!("{b}&{i}")),
        (Some(b), None) => Some(b.to_string()),
        (None, Some(i)) => Some(i.to_string()),
        (None, None) => None,
    };
    if let Some(q) = query {
        url.push('?');
        url.push_str(&q);
    }
    url
}

/// 采样 `upstream` 兜底：`Host` 缺失/非法时回退缺省入口端口字符串
/// （单一监听端口见 `lib.rs`），避免空串或不透明占位。
const DEFAULT_INGRESS_PORT: &str = "8877";

/// 入口宿主机端口解析：`]` 存在时按方括号 IPv6 取 `]:` 后段端口
/// （如 `[::1]:8878` → `8878`）；无方括号且冒号恰一时取尾段（`host:port`）；
/// 裸 IPv6（多冒号无方括号，如 `::1`）与缺失/非法一律回退 `None`（缺省上游），不猜测。
fn parse_ingress_port(host: &str) -> Option<u16> {
    if let Some(end) = host.rfind(']') {
        return host[end + 1..]
            .strip_prefix(':')?
            .trim()
            .parse::<u16>()
            .ok();
    }
    if host.chars().filter(|c| *c == ':').count() != 1 {
        return None;
    }
    host.rsplit(':').next()?.trim().parse::<u16>().ok()
}

/// 生效入口端口：专用监听的承载端口（仅当该端口已被声明为 LLM 入口）恒胜
/// `Host` 头派生的端口；专用监听未承载（主监听）或无声明时回退 `Host` 派生值，
/// 两者皆无则为 `None`（缺省上游）。
///
/// 旧部署（宿主机 8878/8879 映射到容器 8877）的请求落在主监听上、无专用端口，
/// 只能靠 `Host` 区分，故回退分支不要求端口已声明。
pub fn resolve_ingress_port(
    config: &crate::config::Config,
    dedicated_listener_port: Option<u16>,
    host_port: Option<u16>,
) -> Option<u16> {
    match dedicated_listener_port {
        Some(port) if config.declares_port(port) => Some(port),
        _ => host_port,
    }
}

/// 租户指纹可区分凭据头（可选次判别项）：Authorization / api-key。
const CREDENTIAL_HEADER_NAMES: [&str; 3] = ["authorization", "x-api-key", "api-key"];

/// 作用域选择：`request` 逐请求 `PiiScope`；`conversation` 按四级推导
/// 会话键并从共享存储取 `Arc<PiiScope>`，键不可推导时回退逐请求（缓存失配、不报错）。
/// `conversation` 模式下的逐请求回退计入 `request_fallback`（`request` 模式不计）。
/// `protocol` 传入键推导，原生键按协议白名单收窄（Anthropic 忽略
/// `prompt_cache_key`/`previous_response_id`；Chat 忽略 `previous_response_id`）。
///
/// 可判定降级事件：仅三类记内部计数 + `warn!`（不含键/头值/明文/token）——
/// ① 键推导返 `None` 落第 4 级；② `ConversationScopeStore` 缺失回退；③ 显式会话键头
/// 存在但非法被丢弃。
///
/// 非目标：键推导为**逐请求无状态纯函数**，网关不保留「上次命中级别/
/// 上次键」状态，故「同一会话在非首轮静默换键或级别变化」**不可观测**；本函数不提供
/// 该信号（须新增每租户/会话状态面并另行交付），亦不新增下游可观测响应头。
pub(crate) fn build_request_scope(
    state: &AppState,
    headers: &HeaderMap,
    protocol: Protocol,
    upstream_base: &str,
    body: Option<&serde_json::Value>,
) -> Arc<Scope> {
    let fuzzy_restore = state.config.pii_fuzzy_restore;
    let per_request = || Arc::new(Scope::with_opts(fuzzy_restore));
    if !state.config.pii_scope_mode.is_conversation() {
        return per_request();
    }
    let Some(store) = state.conversation_scope_store.as_ref() else {
        // `conversation` 模式但存储缺失——回退逐请求。
        state.gateway_metrics.record_request_fallback();
        state.gateway_metrics.record_conversation_store_missing();
        tracing::warn!("conversation 模式会话存储缺失，回退逐请求作用域（缓存失配属预期降级）");
        return per_request();
    };
    let secret = state.conversation_secret.as_ref();
    // PII 隔离口径：配置头优先，其后**只**接受 opencode 明确表达「本会话」的两个头
    // （`x-opencode-session` / `x-opencode-session-id`），刻意窄于遥测链
    // [`resolve_session_header`]（后者还认 parent-session/affinity/中间代理常用头）。
    //
    // 隔离边界只剩会话键值本身：上游 key 由 `[llm.targets].headers` 注入时客户端不发
    // 凭据头，`tenant_fingerprint` 对所有客户端相同。因此路由/通用头（`x-session-affinity`
    // 常为固定常量、`x-session-id` 常被代理复用）一旦纳入键，两个逻辑客户端会共用一个
    // `PiiScope` 注册表，一方的明文可被还原进另一方响应。
    //
    // 已知取舍：只发 `x-session-affinity` 的客户端仍有日志 `session_id`，但此处键推导
    // 落空→逐请求作用域（按既有第 4 级降级计数）。丢失跨轮 token 稳定性优于跨客户端串味。
    let explicit_raw =
        resolve_pii_scope_header(headers, state.config.pii_scope_key_header.as_str());
    let explicit = explicit_header(true, explicit_raw);
    // 显式会话键头存在但非法（超长/控制字符/非 UTF-8）
    // 被静默丢弃——记内部计数 + warn（头名可现，头值/明文/token MUST NOT 出现）。
    // 告警指名**实际被拒的头**：配置头缺席时值来自回退头，只打配置头名会误导排查。
    if explicit.is_none()
        && pii_scope_header_present(headers, state.config.pii_scope_key_header.as_str())
    {
        let rejected = pii_scope_header_name(headers, state.config.pii_scope_key_header.as_str())
            .unwrap_or(state.config.pii_scope_key_header.as_str());
        state.gateway_metrics.record_conversation_header_invalid();
        tracing::warn!(
            header = %rejected,
            "显式会话键头存在但非法，已丢弃且不参与键推导"
        );
    }
    let prompt_cache_key = body
        .and_then(|v| v.get("prompt_cache_key"))
        .and_then(serde_json::Value::as_str);
    let previous_response_id = body
        .and_then(|v| v.get("previous_response_id"))
        .and_then(serde_json::Value::as_str);
    let credentials: Vec<&str> = CREDENTIAL_HEADER_NAMES
        .iter()
        .filter_map(|name| headers.get(*name).and_then(|v| v.to_str().ok()))
        .collect();
    let tenant_fp = tenant_fingerprint(secret, upstream_base, &credentials);
    // 请求体非 JSON 时以 `Null` 参与推导（稳定前缀不可得），显式头仍可命中第 1 级
    // （保持既有语义：显式头键不依赖请求体）。
    let null_body = serde_json::Value::Null;
    let body_value = body.unwrap_or(&null_body);
    let Some(key) = derive_conversation_key(
        secret,
        &tenant_fp,
        protocol,
        explicit.as_deref(),
        prompt_cache_key,
        previous_response_id,
        body_value,
        &state.previous_response_map,
    ) else {
        // 键推导失败（纯多轮 messages、Responses 标量
        // `input` 等）回退逐请求，不伪造键；记回退计数 + warn（不含键/头值/明文/token）。
        state.gateway_metrics.record_request_fallback();
        tracing::warn!("会话键推导失败，回退逐请求作用域（缓存失配属预期降级）");
        return per_request();
    };
    let pii = store.get_or_insert(&key);
    Arc::new(
        Scope::with_shared_pii(pii, fuzzy_restore).with_conversation(
            key,
            tenant_fp,
            state.conversation_secret.clone(),
            state.previous_response_map.clone(),
        ),
    )
}

/// 非流落行参数：响应 + 终态详情（`gateway_serve` 在此之外唯一落行）。
struct NonStreamServed {
    resp: Response,
    detail: NonstreamDetail,
}

/// 分发结果：流式行已由 `StreamGuard` 承接（终态在泵内落），非流待外层落行。
enum Served {
    NonStream(NonStreamServed),
    Streamed(Response),
}

pub(crate) async fn gateway_serve(
    state: &AppState,
    parts: &mut axum::http::request::Parts,
    path: &str,
    body_bytes: Vec<u8>,
) -> Response {
    let req_start = Instant::now();
    let ct = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // dispatcher 仅保留 protocol/url 分发。
    let protocol = resolve_protocol(path, ct.as_deref(), Some(&state.gateway_metrics));
    // `count_tokens` 的 redact-only 语义由等价 sibling 判定产出（不新增
    // `Protocol` 变体），在下方 RequestCtx 单一装配点写入；`is_passthrough` 仍只认
    // `NonDialog`，故此处置位后 `count_tokens` 走对话臂（请求侧脱敏、跳过四类后处理）。
    // 入口端口（entry-transport）：专用监听的承载端口恒胜 `Host` 派生端口
    //（方括号 IPv6/裸 IPv6/非法一律有定义，缺失/非法回退 None，不猜测）；
    // 主监听无该扩展，按 `Host` 选路以保持旧部署兼容。
    let host_port: Option<u16> = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_ingress_port);
    let dedicated_port = parts
        .extensions
        .get::<crate::router::IngressPort>()
        .map(|port| port.0);
    let ingress_port = resolve_ingress_port(&state.config, dedicated_port, host_port);
    // 请求日志追踪点（design §1.1）：`req_start` 之后、`resolve_target` 与 NonDialog
    // 分支之前创建，保证后续所有早退都被记录；读取请求体前中断/`payload_too_large`
    // 不进入本函数，故不产生行（与 spec 一致）。
    let request_id = parts
        .extensions
        .get::<RequestId>()
        .map(|id| id.0.clone())
        .unwrap_or_else(generated_request_id);
    let mut trace = RequestTrace::new(
        request_id,
        protocol,
        ingress_port,
        state.config.redaction_enabled,
        req_start,
    );
    let served = serve_inner(state, parts, path, body_bytes, &mut trace).await;
    match served {
        Served::Streamed(resp) => resp,
        Served::NonStream(served) => {
            let outcome = served.detail.outcome.clone().unwrap_or(Outcome::NoUpstream);
            record_row(&state.request_log, trace.finish(&outcome, &served.detail));
            served.resp
        }
    }
}

/// 分发主体（不含落行）：流式把追踪快照交 `StreamGuard`，非流把终态详情交回外层。
async fn serve_inner(
    state: &AppState,
    parts: &mut axum::http::request::Parts,
    path: &str,
    body_bytes: Vec<u8>,
    trace: &mut RequestTrace,
) -> Served {
    let protocol = trace.protocol();
    let ingress_port = trace.ingress_port();
    let is_chat = trace.is_chat();
    let redact_only = llm_gateway::redact_only_protocol(path).is_some();
    if redact_only {
        // `count_tokens` 复用 Anthropic 协议线走对话臂（请求侧脱敏），但它不是
        // 对话请求——落行判别位须显式置 `false`，不随协议默认值。
        trace.set_is_chat(false);
    }
    let req_start = trace.req_start();
    // 单次目标解析（design D3）：URL 与覆盖同源取得，三路径共用同一结果，
    // 不存在第二条覆盖查询路径。
    let target = match resolve_target(&state.config, ingress_port) {
        Some(target) => target,
        None => {
            return Served::NonStream(NonStreamServed {
                resp: (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游未配置"}})),
                )
                    .into_response(),
                detail: NonstreamDetail {
                    outcome: Some(Outcome::NoUpstream),
                    ..NonstreamDetail::default()
                },
            });
        }
    };
    trace.set_upstream(trace_authority(target.base_url));
    let url = build_upstream_url(target.base_url, path, parts.uri.query());
    // 动态头值展开上下文（design D3）：原始入站头 + 会话键头生效名。
    // 原始 `parts.headers` 不受下游出站装配剔除（协议必要头/hop 头/`drop_headers`）影响。
    let expand = ExpandCtx {
        inbound: &parts.headers,
        conversation_key_header: &state.config.pii_scope_key_header,
    };
    let client: &reqwest::Client = &state.http_client;
    // 流式（SSE）分支用无总超时的独立 client，长流不被 `HTTP_TIMEOUT_SECS` 截断；
    // 非流与 NonDialog 透传保持既有总超时 client。
    let stream_client: &reqwest::Client = &state.http_stream_client;
    // 全局单例快照（credential-vault-singleton）：网关只读复用进程级
    // vault/detector，不得每请求新建空映射致还原断链。
    let vault = state.vault.clone();
    let detector = state.detector.clone();
    let sqlite_precise = state.sqlite_ok();
    let hold_max = state.config.audit_hold_max_bytes.max(1) as usize;
    // 审计 hold 缓冲帧数上限（配置文件 `[audit].hold_max_frames`，默认 65536）：
    // 单次大 tool 调用的参数按 token 分片可达数千帧，帧数维度须独立于字节维度。
    let hold_max_frames = state.config.audit_hold_max_frames.max(1) as usize;
    // SSE 硬上限运行时值（env/TOML `SSE_FRAME_HARD_BYTES`），经 `StreamPumpCtx`
    // 注入解析器；默认值 8MiB 在配置层给出，此处零二次判定。
    let sse_frame_hard_bytes = state.config.sse_frame_hard_bytes;
    let audit_mode = state.config.audit_mode;
    let audit_policy = state.audit_policy.clone();
    let approval_whitelist = state.config.approval_whitelist.clone();

    // 出站头基线：客户端入站头原样透传，仅剔除协议必要头与 `x-veil-*` 内部命名空间
    // （由 `forward_headers` 统一装配）。会话键头/回退链头不再被隐式剔除——需剔除时
    // 由目标 `drop_headers` 显式声明。键推导（`build_request_scope`）读原始
    // `parts.headers`，故此处克隆体仅供下游装配，不改入站语义。
    let fwd_headers = parts.headers.clone();

    if !is_chat {
        // NonDialog 走专用透传入口（返回 `Response`，无 `Stream` 死臂）；
        // 上游意外回 SSE 亦按字节透传，类型即契约。传客户端入站头的克隆体。
        let upstream_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        // 非对话请求体不做脱敏，故摘要恒 `NULL`（design §6）；会话标识仍按显式头派生。
        trace.attach_identity(None, &parts.headers, &state.config);
        let (resp, detail) = serve_nondialog_detailed(
            client,
            upstream_method,
            &url,
            fwd_headers,
            body_bytes,
            NondialogCtx {
                protocol,
                metrics: &state.gateway_metrics,
                overrides: target.overrides,
                expand,
            },
        )
        .await;
        return Served::NonStream(NonStreamServed { resp, detail });
    }

    let req_value = parse_request_json(&body_bytes);
    // 请求侧 `model` 快照，流式响应帧缺失有效 model 时回退分桶。
    let req_model = req_value
        .as_ref()
        .and_then(|v| v.get("model"))
        .and_then(|m| m.as_str())
        .filter(|m| !m.is_empty())
        .unwrap_or("")
        .to_string();
    trace.attach_identity(req_value.as_ref(), &parts.headers, &state.config);
    // 作用域选择：`request` 逐请求、
    // `conversation` 取存储共享的 `Arc<PiiScope>`；脱敏前 `req_value` 供键推导。
    let scope = build_request_scope(
        state,
        &parts.headers,
        protocol,
        target.base_url,
        req_value.as_ref(),
    );
    // 采样绑定单一装配点——`is_chat` 即 `is_chat_tail`（`NonDialog` 为唯一非对话，
    // 与 `is_chat_tail` 返回值等价且不重复计入宽容命中）；`upstream` 取入口端口字符串。
    scope.configure_sampling(SampleBinding {
        sampler: Some(state.admin.sampler.clone()),
        is_chat_tail: is_chat,
        upstream: ingress_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| DEFAULT_INGRESS_PORT.to_string()),
    });
    // redact-only（count_tokens）SHALL NOT 注入 params：以 `None` 收窄改写入口的
    // 覆盖（headers 注入走 `forward_headers`，不受此限）；命中 params 声明时按
    // 豁免语义记单次 warn（去重，避免逐请求刷屏）。
    let rewrite_overrides = if redact_only {
        llm_gateway::warn_redact_only_params_ignored_once(target.overrides);
        None
    } else {
        target.overrides
    };
    let rw = super::request_rewrite_with_overrides(
        body_bytes,
        protocol,
        &state.config,
        scope.clone(),
        vault.clone(),
        detector.clone(),
        rewrite_overrides,
    )
    .await;
    // 请求侧脱敏链熵源/内部故障 fail-closed——MUST NOT 转发未脱敏正文上游。
    if let Some(resp) = pii_fail_closed(scope.as_ref()) {
        return Served::NonStream(NonStreamServed {
            resp,
            detail: NonstreamDetail {
                outcome: Some(Outcome::PiiUnavailable),
                ..NonstreamDetail::default()
            },
        });
    }
    // 摘要取自请求侧**已脱敏**正文（design §6）：`rw.body` 是脱敏后的最终字节，
    // 失败回退为 `None`（宁可无摘要也不落原文）。
    let redacted_value = parse_request_json(&rw.body);
    trace.attach_summary(redacted_value.as_ref());
    trace.mark_stream(rw.stream_flag && !redact_only);
    let dialog_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);
    // 单一装配点构造共享请求上下文，流式/非流路径复用。
    let req = RequestCtx {
        protocol,
        scope: scope.clone(),
        vault: vault.clone(),
        detector: detector.clone(),
        audit_mode,
        audit_policy: audit_policy.clone(),
        approval_whitelist: approval_whitelist.clone(),
        audit_sink: state.audit_sink.clone(),
        gateway_metrics: state.gateway_metrics.clone(),
        admin_metrics: state.admin.metrics.clone(),
        sqlite_precise,
        req_start,
        pending: state.pending.clone(),
        normalized_out: rw.normalized_out,
        redact_only,
        // redact_only 与 NonDialog 非计数端点，请求侧报告清零（响应侧亦不产出）。
        redaction_tally: if redact_only {
            RedactionTally::default()
        } else {
            rw.tally
        },
    };
    let pump_ctx = || StreamPumpCtx {
        req: req.clone(),
        hold_max,
        hold_max_frames,
        sse_frame_hard_bytes,
        init_conv: rw.init_conv.clone(),
        req_model: req_model.clone(),
        stream_log: None,
    };
    // redact-only 变体（count_tokens）恒走非流有界读路径（受
    // `NONSTREAM_MAX_BYTES` 约束），不因请求体 stream 意图误入 SSE 泵。
    if rw.stream_flag && !redact_only {
        let fwd_headers = forward_headers(
            &fwd_headers,
            &state.gateway_metrics,
            target.overrides,
            &expand,
        );
        match llm_gateway::fetch_upstream_with_retry(
            stream_client,
            dialog_method,
            &url,
            fwd_headers,
            rw.body,
        )
        .await
        {
            Ok(up) => {
                let status_u16 = up.status().as_u16();
                // 透传上游 2xx 原状态（StatusCode 为 Copy，入泵前快照）。
                let upstream_status = up.status();
                let resp_ct = up
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                // 仅 `status<400` 且上游正文为 `text/event-stream` 才转 SSE 泵；
                // 上游错误状态（4xx/5xx）或 2xx 非 SSE 正文按非流口径保状态保正文透传，
                // 不得改写为 200 SSE 假流（客户端会误判为流式成功）。谓词与
                // `should_pump_stream` 共用同一实现（`;` 前段 + trim + 大小写不敏感）。
                if status_u16 >= 400 || !is_event_stream(&resp_ct) {
                    let resp = stream_upstream_passthrough(
                        up,
                        rw.normalized_out,
                        protocol,
                        state.config.nonstream_max_bytes,
                        &state.gateway_metrics,
                    )
                    .await;
                    return Served::NonStream(NonStreamServed {
                        detail: NonstreamDetail {
                            outcome: Some(Outcome::Passthrough {
                                status: resp.status().as_u16(),
                                is_chat: true,
                            }),
                            ..NonstreamDetail::default()
                        },
                        resp,
                    });
                }
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                // 不 detach 泵任务——JoinHandle 交响应体持有，客户端断开
                // 时由响应体 drop 触发 abort 回收（避免上游连接与任务泄漏）。
                let mut pctx = pump_ctx();
                pctx.stream_log = Some(StreamLog {
                    guard: state.request_log.stream_guard(trace.into_row()),
                    request_log: state.request_log.clone(),
                    upstream_status: status_u16,
                });
                let pump = spawn_stream_pump(up, tx, pctx);
                return Served::Streamed(build_sse_response(
                    rx,
                    rw.normalized_out,
                    pump,
                    upstream_status,
                ));
            }
            Err(_) => {
                return Served::NonStream(NonStreamServed {
                    resp: super::empty_body_response(protocol),
                    detail: NonstreamDetail {
                        outcome: Some(Outcome::NoUpstream),
                        ..NonstreamDetail::default()
                    },
                });
            }
        }
    }
    let nctx = NonstreamCtx {
        req: req.clone(),
        stream_flag: false,
        nonstream_max_bytes: state.config.nonstream_max_bytes,
        overrides: target.overrides,
        expand,
    };
    let (outcome, detail) =
        serve_detailed(client, dialog_method, &url, fwd_headers, rw.body, nctx).await;
    match outcome {
        NonstreamOutcome::Responded(resp) => Served::NonStream(NonStreamServed { resp, detail }),
        // 客户端未要求流但上游回 SSE 时，转字节泵保证终止闭合。
        // 泵 conv 首选透传的请求会话（与 `rw.init_conv` 同源），
        // 缺失才用改写输出的会话。
        NonstreamOutcome::Stream(up, req_conv) => {
            let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
            let mut pctx = pump_ctx();
            if req_conv.is_some() {
                pctx.init_conv = req_conv;
            }
            // 客户端未要求流但上游回 SSE，实际按流式收尾——行须标 `stream`。
            trace.mark_stream(true);
            let upstream_status = up.status();
            pctx.stream_log = Some(StreamLog {
                guard: state.request_log.stream_guard(trace.into_row()),
                request_log: state.request_log.clone(),
                upstream_status: upstream_status.as_u16(),
            });
            let pump = spawn_stream_pump(up, tx, pctx);
            Served::Streamed(build_sse_response(
                rx,
                rw.normalized_out,
                pump,
                upstream_status,
            ))
        }
    }
}

/// 流式请求命中上游错误状态（`status>=400`）或非 `text/event-stream` 正文时，
/// 读取正文字节并按原状态返回（受 `NONSTREAM_MAX_BYTES` 约束），hop 头过滤后附
/// `x-veil-protocol`，对齐非流错误/非 JSON 透传口径；不进入 SSE 泵。
/// 非错误状态严格超限走 502 `response_too_large`（与非流一致），4xx/5xx 错误体
/// 不因体大改写。
pub(super) async fn stream_upstream_passthrough(
    up: reqwest::Response,
    normalized_out: bool,
    protocol: Protocol,
    max_bytes: usize,
    metrics: &llm_gateway::GatewayMetrics,
) -> Response {
    // 上游状态码经受约束类型承载；非法值按现状回退 `502`。
    let upstream_status = llm_gateway::UpstreamStatus::new(up.status().as_u16());
    let is_error = upstream_status.is_none_or(|s| s.is_error());
    let mut resp_headers = HeaderMap::new();
    for (k, v) in up.headers().iter() {
        if let (Ok(n), Ok(val)) = (
            k.to_string().parse::<axum::http::HeaderName>(),
            axum::http::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            // `append` 而非 `insert`——同名多值上游头（如多条
            // `warning`/`set-cookie`）逐值保留，不得被折叠为末值。
            resp_headers.append(n, val);
        }
    }
    // 剔除上游 `x-veil-*` 内部头（大小写不敏感），网关自置头在剔除后写入，
    // 上游同名声不得覆盖或泄漏。
    llm_gateway::strip_veil_internal_headers(&mut resp_headers);
    let decode_enabled = llm_gateway::downstream_decode_enabled(up.headers());
    // 先判 `content-length`（仅非错误状态），超限即 502 且不读 body。
    if !is_error
        && up
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
    {
        return super::nonstream::oversize_response(protocol);
    }
    llm_gateway::filter_hop_headers_counted(
        &mut resp_headers,
        "downstream",
        decode_enabled,
        Some(metrics),
    );
    let status = upstream_status
        .and_then(|s| StatusCode::from_u16(s.as_u16()).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }
    if normalized_out {
        builder = builder.header(NORMALIZED_HEADER_NAME, NORMALIZED_HEADER_VALUE);
    }
    let builder = builder.header(PROTOCOL_HEADER_NAME, super::protocol_header_value(protocol));
    // `status >= 400` 错误体按透传语义保状态保字节，流式转发仅为内存安全，
    // 不改写为 502、不缓冲放大。
    if is_error {
        return builder
            .body(Body::from_stream(up.bytes_stream()))
            .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response());
    }
    // 非错误状态有界读（至多 `max_bytes + 1`），严格超限 fail-closed 502。
    let bytes = match super::nonstream::read_bounded_body(up, max_bytes, metrics).await {
        super::nonstream::BoundedBody::Complete(b) => b,
        super::nonstream::BoundedBody::Oversize => {
            return super::nonstream::oversize_response(protocol);
        }
    };
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
}

/// `build_request_scope` 降级计数、fail-closed 守门与
/// BOM 前缀解析等单测见 `dispatch/tests.rs` 与 `dispatch/tests/` 子模块。
#[cfg(test)]
mod tests;
