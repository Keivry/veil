//! LLM 网关入口三单元装配：`rewrite`（请求改写）+ `nonstream`（一发一收）+
//! `pump`（流式字节泵）+ `dispatch`（入口分发）；本模块留守限值常量与共享小谓词，
//! 对外 `handler::*` 路径不变。

use {
    crate::{
        config::{
            HeaderValueSegment,
            HeaderValueSpec,
            UpstreamOverrides,
            targets::REQUEST_ID_HEADER,
        },
        service::{
            llm_gateway::{self, GatewayMetrics, Protocol},
            redaction::leaf::PROTOCOL_HEADER_NAME,
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

/// 头值插值展开的只读上下文（design D3）：原始入站头 + 会话键头生效名。
///
/// `$conversation` / `$header(名)` / `$request-id` 三种来源均从 `inbound` 读取——
/// 原始 `parts.headers` 不受出站装配剔除（协议必要头/hop 头/`drop_headers`）影响；
/// `$header(名)` 来源限入站请求自身，与透传同信任边界。
pub struct ExpandCtx<'a> {
    /// 原始入站请求头（`parts.headers`）。
    pub inbound: &'a HeaderMap,
    /// 会话键头生效名（`PII_SCOPE_KEY_HEADER`），`$conversation` 读取用。
    pub conversation_key_header: &'a str,
}

/// 上游转发头：透传客户端入站头——仅剔除协议必要项（`host`/`content-length`/
/// `content-encoding` 与下游 `accept-encoding`，reqwest 仅在其请求头缺席时注入网关
/// 支持集 `gzip/br/deflate`，从而保证上游只回可解码编码）与 `x-veil-*` 内部命名空间，
/// 再做 hop 头过滤并计数；随后按目标 `drop_headers` 显式剔除，最后注入目标配置头
/// （design D3/D4）。
///
/// 会话键头（含 `SESSION_HEADER_FALLBACKS` 五名回退链）不再被隐式剔除：客户端动态
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
        let config_wins = overrides.override_existing;
        for (name, value) in overrides.headers.iter() {
            // 恒胜模式直接覆盖；合并模式仅当客户端未发送同名头时新增。
            if config_wins || !fwd.contains_key(name) {
                let Some(resolved) = resolve_header_value(value, expand) else {
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

/// 单条配置值求值：`Static` 原样；`Template` 展开（来源缺失或展开结果防御性
/// 校验失败返回 `None`，调用方按「跳过该条目」处理）。
fn resolve_header_value(
    value: &HeaderValueSpec,
    ctx: &ExpandCtx<'_>,
) -> Option<header::HeaderValue> {
    match value {
        HeaderValueSpec::Static(value) => Some(value.clone()),
        HeaderValueSpec::Template(segments) => expand_template(segments, ctx),
    }
}

/// 模板段展开：字面拼接 + 三种来源取入站首值；任一来源缺失即整条 `None`。
/// 展开结果由「合法来源 + 启动期校验字面 + `$$` 转义」结构性保证可解析，
/// 防御性构造失败（理论不可达）记 warn 后按跳过处理（design D5）。
fn expand_template(
    segments: &[HeaderValueSegment],
    ctx: &ExpandCtx<'_>,
) -> Option<header::HeaderValue> {
    let mut out = String::new();
    for segment in segments {
        match segment {
            HeaderValueSegment::Literal(text) => out.push_str(text),
            HeaderValueSegment::Conversation => {
                out.push_str(inbound_first_value(
                    ctx.inbound,
                    ctx.conversation_key_header,
                )?);
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
        Ok(value) => Some(value),
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
        crate::config::{Config, env_parse::pii_scope::PII_SCOPE_KEY_HEADER_DEFAULT},
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

    /// 零来源展开上下文（空头表 + 默认会话键头名），静态条目测试用。
    pub(crate) fn no_expand() -> ExpandCtx<'static> {
        static EMPTY: std::sync::OnceLock<HeaderMap> = std::sync::OnceLock::new();
        ExpandCtx {
            inbound: EMPTY.get_or_init(HeaderMap::new),
            conversation_key_header: PII_SCOPE_KEY_HEADER_DEFAULT,
        }
    }

    /// 以给定入站头为来源的展开上下文（会话键头取默认名），动态条目测试用。
    pub(crate) fn expand_ctx(inbound: &HeaderMap) -> ExpandCtx<'_> {
        ExpandCtx {
            inbound,
            conversation_key_header: PII_SCOPE_KEY_HEADER_DEFAULT,
        }
    }
}
