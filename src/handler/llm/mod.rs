//! LLM 网关入口三单元装配：`rewrite`（请求改写）+ `nonstream`（一发一收）+
//! `pump`（流式字节泵）+ `dispatch`（入口分发）；本模块留守限值常量与共享小谓词，
//! 对外 `handler::*` 路径不变。

use {
    crate::{
        config::{
            HeaderReplaceRule,
            HeaderValueSegment,
            HeaderValueSpec,
            UpstreamOverrides,
            targets::REQUEST_ID_HEADER,
        },
        service::{
            llm_gateway::{self, GatewayMetrics, Protocol},
            redaction::leaf::PROTOCOL_HEADER_NAME,
            session_identity::OutboundId,
        },
    },
    axum::{
        Json,
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::json,
};

pub mod dispatch;
pub mod nonstream;
pub mod pump;
pub mod rewrite;
pub mod trace;

#[cfg(test)]
mod tests;

/// 限值常量归属 `config.rs`，此处原位转发防外部引用断裂。
pub use crate::config::{AUDIT_SUBLIMIT_CEILING_BYTES, GATEWAY_BODY_LIMIT_BYTES};

/// 审计/扫描类体长归属判定（8MB 上限的回归锚点，不接请求路径）。
#[cfg(test)]
pub(crate) fn audit_scan_body_over_limit(len: usize) -> bool { len > AUDIT_SUBLIMIT_CEILING_BYTES }

/// 头值插值展开的只读上下文（design D5）：原始入站头 + 预计算的出站标识 + 请求模型。
///
/// `$header(名)` / `$request-id` 从 `inbound` 读取——原始 `parts.headers` 不受出站
/// 装配剔除（协议必要头/hop 头/`drop_headers`）影响；`$header(名)` 来源限入站请求
/// 自身，与透传同信任边界。
///
/// `outbound_id` 在 `SessionIdentity` 解析完成后由
/// `session_identity::outbound_id(&identity, secret)` 预计算并 owned 持有——避免
/// 借用随后会被 move 的 identity，也避免在展开时重新解析身份。`model` 同理由
/// dispatch 写入（对话路径 `Some`，NonDialog `None`）。
#[derive(Clone)]
pub struct ExpandCtx<'a> {
    /// 原始入站请求头（`parts.headers`）。
    pub inbound: &'a HeaderMap,
    /// `$conversation` 的预计算出站标识（`None` = 无锚点，按来源缺失跳过）。
    pub outbound_id: Option<OutboundId>,
    /// 本次请求的 `model`（`$model` 类展开使用；NonDialog 为 `None`）。
    pub model: Option<String>,
}

/// 上游转发头：透传客户端入站头——仅剔除协议必要项（`host`/`content-length`/
/// `content-encoding` 与下游 `accept-encoding`，reqwest 仅在其请求头缺席时注入网关
/// 支持集 `gzip/br/deflate`，从而保证上游只回可解码编码）与 `x-veil-*` 内部命名空间，
/// 再做 hop 头过滤并计数；随后按目标 `drop_headers` 显式剔除，最后注入目标配置头
/// （design D3/D4）。
///
/// 会话类头（`[session].headers` 链与历史回退名）不再被隐式剔除：客户端动态
/// 身份头按 D1 原样上游，需剔除时由操作者显式声明 `drop_headers`。
///
/// 配置头注入两态策略：
/// - `override_existing == true`（缺省）：`insert` 恒胜客户端同名头（`HeaderName`
///   大小写不敏感），保证供应商契约不被客户端破坏；
/// - `override_existing == false`（合并模式）：仅当客户端未发送同名头时 `insert`，
///   客户端同名头（含多值条目的全部值）原样保留。
///
/// 配置头值：`Static` 走原路径零变化；`Template` 在注入时按 [`ExpandCtx`] 展开，
/// 任一来源缺失（或展开结果防御性校验失败）时该条目跳过不注入（不写/不改/删，
/// 等同未声明；design D4），同表其余条目不受影响。
///
/// 配置 `user_agent`（`Some` 时）在配置头注入完成之后写入出站 `User-Agent`：
/// 恒胜、单值，与 `override_existing` 两态及客户端是否发送均无关（design D3）；
/// `None` 时 UA 装配零变化。
///
/// 配置头与 `drop_headers` 已过加载期校验（同名互斥、`x-veil-*` 拒绝等），故此处
/// 不再二次过滤。
///
/// `header_replace` 在 `drop_headers` 删除之后、配置 `headers` 注入之前逐值应用
/// （design D3）：按 `HeaderMap` 每个值条目精确匹配 `from`（大小写敏感）后改为字面
/// `to`（不做 `$` 插值），未匹配值及其顺序保留；头缺失即 no-op，绝不注入。同一
/// 头名的全部命中改动一次性写回，故规则顺序无关、不级联。`models` 门控读取
/// [`ExpandCtx::model`]（dispatch 在脱敏/重写前快照的客户端原始模型）。
pub fn forward_headers(
    incoming: &HeaderMap,
    metrics: &GatewayMetrics,
    overrides: Option<&UpstreamOverrides>,
    expand: &ExpandCtx<'_>,
) -> HeaderMap {
    let mut fwd = incoming.clone();
    fwd.remove(header::HOST);
    fwd.remove(header::CONTENT_LENGTH);
    fwd.remove(header::CONTENT_ENCODING);
    fwd.remove(header::ACCEPT_ENCODING);
    // 请求方向同样剔除下游 `x-veil-*` 内部头（大小写不敏感），防内部头外传上游。
    llm_gateway::strip_veil_internal_headers(&mut fwd);
    llm_gateway::filter_hop_headers_counted(
        &mut fwd,
        "upstream",
        llm_gateway::DECODE_ENABLED,
        Some(metrics),
    );
    if let Some(overrides) = overrides {
        // 显式剔除先于配置头注入：`drop_headers` 命中的客户端头（含全部值）在此移除，
        // 随后两态注入照常生效（故「剔除 UA + 声明 user_agent」最终为配置值）。
        for name in &overrides.drop_headers {
            fwd.remove(name);
        }
        apply_header_replace(&mut fwd, &overrides.header_replace, expand.model.as_deref());
        let config_wins = overrides.override_existing;
        for (name, value) in overrides.headers.iter() {
            // 恒胜模式直接覆盖；合并模式仅当客户端未发送同名头时新增。
            if config_wins || !fwd.contains_key(name) {
                let Some(resolved) = resolve_header_value(value, expand, metrics) else {
                    continue;
                };
                fwd.insert(name.clone(), resolved);
            }
        }
        if let Some(ua) = &overrides.user_agent {
            fwd.insert(header::USER_AGENT, ua.clone());
        }
    }
    fwd
}

/// 出站头条件替换：按头名分组，逐**值条目**精确匹配 `from` 后改写为字面 `to`。
///
/// 每个头名先取 `get_all` 快照（应用前客户端值），随后一次性重建该头名条目——
/// 未匹配值原样保序保留，故规则顺序无关、不级联；不拆分逗号拼接的单值。头名
/// 缺失即整个头名跳过（不注入）。运行期非法规则名/值按跳过处理（加载期已校验）。
fn apply_header_replace(fwd: &mut HeaderMap, rules: &[HeaderReplaceRule], model: Option<&str>) {
    let mut names: Vec<header::HeaderName> = Vec::new();
    for rule in rules {
        let Ok(name) = header::HeaderName::from_bytes(rule.name.as_bytes()) else {
            continue;
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for name in names {
        let values: Vec<header::HeaderValue> = fwd.get_all(&name).iter().cloned().collect();
        if values.is_empty() {
            continue;
        }
        let mut rebuilt: Vec<header::HeaderValue> = Vec::with_capacity(values.len());
        let mut changed = false;
        for value in values {
            let hit = rules.iter().find(|rule| {
                rule.name.eq_ignore_ascii_case(name.as_str())
                    && llm_gateway::models_gate_matches(rule.models.as_deref(), model)
                    && rule.from.as_bytes() == value.as_bytes()
            });
            match hit.and_then(|rule| header::HeaderValue::from_str(&rule.to).ok()) {
                Some(to) => {
                    rebuilt.push(to);
                    changed = true;
                }
                None => rebuilt.push(value),
            }
        }
        if changed {
            fwd.remove(&name);
            for value in rebuilt {
                fwd.append(&name, value);
            }
        }
    }
}

/// 单条配置值求值：`Static` 原样；`Template` 展开（来源缺失或展开结果防御性
/// 校验失败返回 `None`，调用方按「跳过该条目」处理）。
fn resolve_header_value(
    value: &HeaderValueSpec,
    ctx: &ExpandCtx<'_>,
    metrics: &GatewayMetrics,
) -> Option<header::HeaderValue> {
    match value {
        HeaderValueSpec::Static(value) => Some(value.clone()),
        HeaderValueSpec::Template(segments) => expand_template(segments, ctx, metrics),
    }
}

/// 模板段展开：字面拼接 + 三种来源取入站首值；任一来源缺失即整条 `None`。
/// 展开结果由「合法来源 + 启动期校验字面 + `$$` 转义」结构性保证可解析，
/// 防御性构造失败（理论不可达）记 warn 后按跳过处理（design D5）。
///
/// `session_outbound_hmac` 计数点（design D5）：一个 header 值内每个**成功建出整条
/// 头值**的 `Conversation` 服务端 HMAC 段各计一次；客户端原值、无锚点跳过、构造失败
/// 均不计数，故计数在 `from_str` 成功之后按累计段数一次性递增。
fn expand_template(
    segments: &[HeaderValueSegment],
    ctx: &ExpandCtx<'_>,
    metrics: &GatewayMetrics,
) -> Option<header::HeaderValue> {
    let mut out = String::new();
    let mut server_hmac_segments: u32 = 0;
    for segment in segments {
        match segment {
            HeaderValueSegment::Literal(text) => out.push_str(text),
            HeaderValueSegment::Conversation => {
                let outbound = ctx.outbound_id.as_ref()?;
                out.push_str(outbound.as_str());
                if outbound.is_server_hmac() {
                    server_hmac_segments = server_hmac_segments.saturating_add(1);
                }
            }
            HeaderValueSegment::RequestId => {
                out.push_str(inbound_first_value(ctx.inbound, REQUEST_ID_HEADER)?);
            }
            HeaderValueSegment::Mirror(name) => {
                out.push_str(inbound_first_value(ctx.inbound, name.as_str())?);
            }
        }
    }
    match header::HeaderValue::from_str(&out) {
        Ok(value) => {
            for _ in 0..server_hmac_segments {
                metrics.record_session_outbound_hmac();
            }
            Some(value)
        }
        Err(_) => {
            tracing::warn!("动态头值展开结果不符合 http 头值语义，跳过该条目（理论不可达）");
            None
        }
    }
}

/// 入站头首个值（缺失或非 UTF-8/含不可见字节时 `None`，按来源缺失处理）。
fn inbound_first_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

pub(crate) fn protocol_header_value(protocol: Protocol) -> &'static str { protocol.wire_name() }

/// 非流对话路径 + 流式错误透传路径由网关生成的响应置
/// `x-veil-protocol`（与成功的非流分支/阻断分支口径一致）；SSE 成功路径（`build_sse_response`）与
/// NonDialog 透传不置该头。
pub(crate) fn with_protocol_header(mut resp: Response, protocol: Protocol) -> Response {
    resp.headers_mut().insert(
        PROTOCOL_HEADER_NAME,
        header::HeaderValue::from_static(protocol_header_value(protocol)),
    );
    resp
}

pub(crate) fn empty_body_response(protocol: Protocol) -> Response {
    with_protocol_header(
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
        )
            .into_response(),
        protocol,
    )
}

/// `Content-Type` 是否为 `text/event-stream`——仅取 `;` 前段、trim 后
/// 大小写不敏感比较，供 pump 路由与非流分类共用，消除第二决策站点。
pub(crate) fn is_event_stream(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// 流泵路由判定（定稿：客户端 `stream` 意图优先）：上游 `Content-Type`
/// 为 `event-stream` 或请求 `stream==true` 即转流泵；`stream:true` 配
/// `application/json` 组合亦走流泵，由泵内残余分类保证不丢帧。
pub fn should_pump_stream(resp_content_type: &str, stream_flag: bool) -> bool {
    is_event_stream(resp_content_type) || stream_flag
}

pub use {
    dispatch::llm_proxy_handler,
    nonstream::{
        NondialogCtx,
        NonstreamCtx,
        NonstreamOutcome,
        serve_detailed,
        serve_nondialog_detailed,
        serve_nondialog_passthrough,
        serve_nonstream,
    },
    pump::{PumpOutcome, RequestCtx, StreamPumpCtx, build_sse_response, spawn_stream_pump},
    rewrite::{RewriteOutput, request_rewrite, request_rewrite_with_overrides},
    trace::{NonstreamDetail, Outcome, RequestTrace, StreamLog},
};

/// 网关集成单测共享夹具：`tests` 各用例组 / `nonstream::tests` / `rewrite::tests`
/// 经 `crate::handler::llm::test_support` 复用，消除逐字复制。
#[cfg(test)]
pub(crate) mod test_support {
    use {
        super::ExpandCtx,
        crate::config::Config,
        axum::http::HeaderMap,
        std::collections::HashMap,
    };

    /// 最小合法配置环境（四必填项）。
    pub(crate) fn base_env() -> HashMap<String, String> {
        HashMap::from([
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
        ])
    }

    /// 以 `base_env` 为底叠加 `extra` 后加载配置。
    pub(crate) fn test_config(extra: &[(&str, &str)]) -> Config {
        let mut env = base_env();
        for (k, v) in extra {
            env.insert((*k).to_string(), (*v).to_string());
        }
        Config::load_from(&env).expect("测试配置须合法")
    }

    /// 零来源展开上下文（空头表 + 无出站标识），静态条目测试用。
    pub(crate) fn no_expand() -> ExpandCtx<'static> {
        static EMPTY: std::sync::OnceLock<HeaderMap> = std::sync::OnceLock::new();
        ExpandCtx {
            inbound: EMPTY.get_or_init(HeaderMap::new),
            outbound_id: None,
            model: None,
        }
    }

    /// 以给定入站头为来源、无出站标识的展开上下文（`$header`/`$request-id` 测试用）。
    pub(crate) fn expand_ctx(inbound: &HeaderMap) -> ExpandCtx<'_> {
        ExpandCtx {
            inbound,
            outbound_id: None,
            model: None,
        }
    }

    /// 以给定入站头与预计算出站标识构造的展开上下文（`$conversation` 测试用）。
    pub(crate) fn expand_ctx_with(
        inbound: &HeaderMap,
        outbound_id: Option<crate::service::session_identity::OutboundId>,
    ) -> ExpandCtx<'_> {
        ExpandCtx {
            inbound,
            outbound_id,
            model: None,
        }
    }
}
