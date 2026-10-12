//! LLM 网关协议管线（按协议拆模块）：`protocol`（协议识别/流判定）+ `usage`
//! （用量提取/合并）+ `hop`（逐跳头过滤）+ `placeholder`（占位符说明注入）+ `tool`
//! （工具调用/会话归档）；本模块留守网关度量、空体分类、重试/选路/上游抓取与重导出，
//! 对外 `llm_gateway::*` 路径不变。

use {
    crate::config::{Config, TargetKey, UpstreamOverrides},
    axum::http::HeaderMap,
    std::time::Duration,
};

pub mod hop;
pub mod metrics;
pub mod overrides;
pub mod placeholder;
pub mod protocol;
pub mod tool;
pub mod tool_responses;
pub mod usage;

pub use metrics::GatewayMetrics;

/// 剔除 `HeaderMap` 中全部 `x-veil-*` 内部头——`HeaderName`
/// 大小写不敏感且规范化为小写，`starts_with` 即大小写不敏感匹配；请求方向防内部
/// 头外传上游，响应方向防上游同名头覆盖网关自置头（网关自置头在剔除后写入）。
pub fn strip_veil_internal_headers(headers: &mut HeaderMap) {
    let veil_keys: Vec<_> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-veil-"))
        .cloned()
        .collect();
    for k in veil_keys {
        headers.remove(&k);
    }
}

/// 上游重试退避三档（毫秒）：500/1000/2000，总等待 3.5s，远小于
/// `HTTP_TIMEOUT_SECS`（默认 30s）转发超时；硬编码理由：重试预算须锁定在
/// 超时预算一个数量级以下，固定档位防雪崩放大，不开放配置（调大任一档都可能
/// 拖过整体超时，改值须同步复核 `retry_delay` 单测与超时预算）。
pub const RETRY_DELAYS_MS: [u64; 3] = [500, 1000, 2000];
/// 最多重试 3 次（`0..=3` 含初次共 4 次请求）；硬编码理由同上，与退避档位
/// 一一对应，超限下标回退末档 2000ms（见 `retry_delay`）。
pub const MAX_RETRY_ATTEMPTS: usize = 3;

/// 上游状态码受约束类型——仅接受 `100..=599` 的合法 HTTP 状态，
/// 服务层不再以裸 `u16` 无约束传递；非法值在构造处即被拒（返回 `None`），
/// 调用方按既有回退（`502`）处理，不 panic、不改写对外语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamStatus(u16);

impl UpstreamStatus {
    pub const fn new(code: u16) -> Option<Self> {
        if code >= 100 && code <= 599 {
            Some(Self(code))
        } else {
            None
        }
    }

    pub const fn as_u16(self) -> u16 { self.0 }

    pub const fn is_error(self) -> bool { self.0 >= 400 }

    pub const fn is_success(self) -> bool { self.0 < 400 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyAction {
    NonStreamTo502,
    PassthroughErrorStatus,
    NonDialogExempt,
    PassthroughOk,
}

/// 空体分类（非流路径唯一入口）。流式空流策略唯一归
/// `should_synthesize_empty_stream`（`handler::llm::pump`），两策略不得并存。
pub fn classify_empty(
    is_chat: bool,
    body_len: usize,
    is_json: bool,
    upstream_status: u16,
) -> EmptyAction {
    if !is_chat {
        return EmptyAction::NonDialogExempt;
    }
    if upstream_status >= 400 {
        // `status>=400` 恒豁免合成 502（JSON 走调用方完整后处理链，
        // 非 JSON 含空体原样透传状态码与正文字节，不再吞错转 `E_EMPTY_BODY`）。
        return EmptyAction::PassthroughErrorStatus;
    }
    // 「空体/非 JSON→502」门控 SHALL 仅对 `upstream_status == 200` 生效。
    // 其余非错误状态（201/204/304 等，均可能合法携带空体）按原状态码与正文字节
    // 透传，不合成 502；`status>=400` 错误体由上方分支透传，不受本门控影响。
    if upstream_status != 200 {
        return EmptyAction::PassthroughOk;
    }
    if body_len == 0 || !is_json {
        return EmptyAction::NonStreamTo502;
    }
    EmptyAction::PassthroughOk
}

pub fn retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(RETRY_DELAYS_MS.get(attempt).copied().unwrap_or(2000))
}

// 缺省回退告警每进程至多一次（热路径去噪；取端口升序选择语义仍每次确定性计算）。
static DEFAULT_FALLBACK_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 选路与覆盖同源解析结果（design D3）：单次解析同时给出上游基址与命中的目标
/// 覆盖；`overrides` 为 `None` 表示该上游未声明 `[llm.targets]` 覆盖。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolvedTarget<'a> {
    pub base_url: &'a str,
    pub overrides: Option<&'a UpstreamOverrides>,
}

/// 目标解析唯一入口：复用既有 `resolve_upstream` 选路语义
/// （`LLM_<port>` > `LLM_UPSTREAM` > 端口升序首个），并按选定分支命中同源覆盖——
/// 端口专用上游命中 `[llm.targets."<port>"]`，缺省上游命中
/// `[llm.targets.default]`，缺省回退（无端口专用、无缺省上游）不命中覆盖。
/// 单请求单次调用即得 `{URL, 覆盖}`，杜绝对同一请求二次查询（错配）。
pub fn resolve_target(config: &Config, local_port: Option<u16>) -> Option<ResolvedTarget<'_>> {
    if let Some(port) = local_port
        && let Some(base_url) = config.llm_upstreams.get(&port)
    {
        return Some(ResolvedTarget {
            base_url,
            overrides: config.llm_targets.get(&TargetKey::Port(port)),
        });
    }
    if let Some(base_url) = config.llm_default_upstream.as_deref() {
        return Some(ResolvedTarget {
            base_url,
            overrides: config.llm_targets.get(&TargetKey::Default),
        });
    }
    // 缺省回退按端口升序取首个（确定性，不依赖 HashMap 迭代序），并 warn 提示。
    let mut ports: Vec<u16> = config.llm_upstreams.keys().copied().collect();
    ports.sort_unstable();
    let chosen = ports.first().and_then(|p| config.llm_upstreams.get(p))?;
    if !DEFAULT_FALLBACK_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(upstream = %chosen, "未配置缺省上游，按端口升序回退首个 LLM_<port>（本进程仅提示一次）");
    }
    Some(ResolvedTarget {
        base_url: chosen,
        overrides: None,
    })
}

/// 上游基址选路（兼容入口）：委托 [`resolve_target`] 并只取 URL，
/// 选路与告警语义逐项不变；需要覆盖的调用方 SHALL 改用 [`resolve_target`]。
pub fn resolve_upstream(config: &Config, local_port: Option<u16>) -> Option<String> {
    resolve_target(config, local_port).map(|target| target.base_url.to_string())
}

pub async fn fetch_upstream_with_retry(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> anyhow::Result<reqwest::Response> {
    // 请求体转共享 `Bytes`，重试时按引用计数克隆（零字节拷贝），
    // 不再对 `Vec<u8>` 逐次深拷贝；拿头前重试分类/退避语义不变。
    // 6.5：直接用 `bytes::Bytes`（直依赖），service 生产不再引用 axum 通配路径。
    let body = bytes::Bytes::from(body);
    let mut last_err: Option<reqwest::Error> = None;
    for attempt in 0..=MAX_RETRY_ATTEMPTS {
        let mut req = client.request(method.clone(), url);
        for (k, v) in headers.iter() {
            if let Ok(val) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
                req = req.header(k.clone(), val);
            }
        }
        if !body.is_empty() {
            req = req.body(body.clone());
        }
        match req.send().await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                if e.is_connect() || e.is_timeout() || e.is_request() {
                    last_err = Some(e);
                    if attempt < MAX_RETRY_ATTEMPTS {
                        tokio::time::sleep(retry_delay(attempt)).await;
                        continue;
                    }
                    break;
                }
                return Err(anyhow::anyhow!(e));
            }
        }
    }
    Err(anyhow::anyhow!(
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "上游拿头前连续失败".to_string())
    ))
}

pub use {
    hop::{DECODE_ENABLED, HOP_HEADERS, downstream_decode_enabled, filter_hop_headers_counted},
    overrides::{
        apply_param_overrides,
        matched_params,
        param_protocol,
        warn_redact_only_params_ignored_once,
    },
    placeholder::{
        has_placeholder_tokens,
        inject_placeholder_prompt,
        placeholder_inject_obj,
        placeholder_schema_ok,
        should_inject_placeholders,
    },
    protocol::{
        Protocol,
        inject_stream_options,
        is_chat_tail,
        is_passthrough,
        is_stream_body,
        redact_only_protocol,
        resolve_protocol,
        should_inject_stream_options,
    },
    tool::{
        ToolCall,
        anthropic_bucket_index,
        archive_unknown_id,
        chat_bucket,
        extract_conv_id,
        extract_tool_calls,
        normalize_tool_args,
        resolve_conv_id,
        retrieval_args,
        retrieval_tool_name,
    },
    usage::{Usage, accumulate_usage, extract_usage_nonstream, extract_usage_stream},
};

#[cfg(test)]
mod tests;
