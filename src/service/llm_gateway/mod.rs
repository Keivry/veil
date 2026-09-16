//! LLM 网关协议管线（D1 按协议拆模块）：`protocol`（协议识别/流判定）+ `usage`
//! （用量提取/合并）+ `hop`（逐跳头过滤）+ `placeholder`（占位符说明注入）+ `tool`
//! （工具调用/会话归档）；本模块留守网关度量、空体分类、重试/选路/上游抓取与重导出，
//! 对外 `llm_gateway::*` 路径不变。

use {crate::config::Config, axum::http::HeaderMap, std::time::Duration};

pub mod hop;
pub mod metrics;
pub mod placeholder;
pub mod protocol;
pub mod tool;
pub mod usage;

pub use metrics::GatewayMetrics;

/// T2/D2 + TRN-4（F-2）：剔除 `HeaderMap` 中全部 `x-veil-*` 内部头——`HeaderName`
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

/// ARH-10（7.7）：上游状态码受约束类型——仅接受 `100..=599` 的合法 HTTP 状态，
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
        // N2/D6：`status>=400` 恒豁免合成 502（JSON 走调用方完整后处理链，
        // 非 JSON 含空体原样透传状态码与正文字节，不再吞错转 `E_EMPTY_BODY`）。
        return EmptyAction::PassthroughErrorStatus;
    }
    // NLP-6/D：「空体/非 JSON→502」门控 SHALL 仅对 `upstream_status == 200` 生效
    // （对齐 Python `_llm.py:3009-3013` 的 `upstream_resp.status == 200` 守卫）。
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

pub fn resolve_upstream(config: &Config, local_port: Option<u16>) -> Option<String> {
    if let Some(port) = local_port
        && let Some(u) = config.llm_upstreams.get(&port)
    {
        return Some(u.clone());
    }
    if let Some(u) = config.llm_default_upstream.clone() {
        return Some(u);
    }
    // 缺省回退按端口升序取首个（确定性，不依赖 HashMap 迭代序），并 warn 便于迁移。
    let mut ports: Vec<u16> = config.llm_upstreams.keys().copied().collect();
    ports.sort_unstable();
    let chosen = ports
        .first()
        .and_then(|p| config.llm_upstreams.get(p))
        .cloned();
    if let Some(ref u) = chosen
        && !DEFAULT_FALLBACK_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        tracing::warn!(upstream = %u, "未配置缺省上游，按端口升序回退首个 LLM_<port>（本进程仅提示一次）");
    }
    chosen
}

pub async fn fetch_upstream_with_retry(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> anyhow::Result<reqwest::Response> {
    // ARH-7（7.4）：请求体转共享 `Bytes`，重试时按引用计数克隆（零字节拷贝），
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
mod retry_tests;

#[cfg(test)]
mod tests {
    use super::{
        metrics::{CONV_MISSING_KEYS, HOP_DIR_KEYS, LENIENT_TAIL_KEYS, TRUNCATED_MODE_KEYS},
        *,
    };

    #[test]
    fn empty_body_502_three_branches() {
        // D3：is_stream 分支已删；流式空流唯一策略见 should_synthesize_empty_stream。
        assert_eq!(
            classify_empty(true, 0, false, 200),
            EmptyAction::NonStreamTo502
        );
        assert_eq!(
            classify_empty(true, 10, false, 200),
            EmptyAction::NonStreamTo502
        );
        assert_eq!(
            classify_empty(true, 10, true, 502),
            EmptyAction::PassthroughErrorStatus
        );
        assert_eq!(
            classify_empty(true, 5, true, 401),
            EmptyAction::PassthroughErrorStatus
        );
        assert_eq!(
            classify_empty(false, 0, false, 200),
            EmptyAction::NonDialogExempt
        );
        assert_eq!(
            classify_empty(true, 10, true, 200),
            EmptyAction::PassthroughOk
        );
    }

    #[test]
    fn upstream_port_mapping_resolves() {
        use std::collections::HashMap;
        let env = HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://m.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
            (
                "LLM_8877".to_string(),
                "https://up-a.example.com".to_string(),
            ),
            (
                "LLM_8878".to_string(),
                "https://up-b.example.com".to_string(),
            ),
        ]);
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            resolve_upstream(&cfg, Some(8877)).as_deref(),
            Some("https://up-a.example.com")
        );
        assert_eq!(
            resolve_upstream(&cfg, Some(8878)).as_deref(),
            Some("https://up-b.example.com")
        );
        assert!(resolve_upstream(&cfg, Some(9999)).is_some());
    }

    #[test]
    fn resolve_upstream_default_fallback_picks_lowest_port_deterministically() {
        use std::collections::HashMap;
        let env = HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://m.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
            (
                "LLM_8879".to_string(),
                "https://up-high.example.com".to_string(),
            ),
            (
                "LLM_8878".to_string(),
                "https://up-low.example.com".to_string(),
            ),
        ]);
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            resolve_upstream(&cfg, None).as_deref(),
            Some("https://up-low.example.com"),
            "双端口缺省须取最小端口"
        );
        for _ in 0..10 {
            assert_eq!(
                resolve_upstream(&cfg, None).as_deref(),
                Some("https://up-low.example.com"),
                "重复运行须一致（端口升序最小，不依赖 HashMap 迭代序）"
            );
        }
    }

    #[test]
    fn retry_backoff_curve() {
        assert_eq!(retry_delay(0), Duration::from_millis(500));
        assert_eq!(retry_delay(1), Duration::from_millis(1000));
        assert_eq!(retry_delay(2), Duration::from_millis(2000));
    }

    #[tokio::test]
    async fn disconnect_retries_capped_then_fails() {
        use axum::http::HeaderMap;
        assert_eq!(retry_delay(3), Duration::from_millis(2000));
        assert_eq!(retry_delay(99), Duration::from_millis(2000));
        assert_eq!(MAX_RETRY_ATTEMPTS, 3);
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let err = fetch_upstream_with_retry(
            &client,
            reqwest::Method::POST,
            "http://127.0.0.1:9/v1/chat/completions",
            HeaderMap::new(),
            b"{}".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(
            start.elapsed() >= Duration::from_millis(3000),
            "三次退避(500+1000+2000)须走完，实测 {:?}",
            start.elapsed()
        );
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn first_refused_then_retry_succeeds() {
        use axum::http::HeaderMap;
        // 预留端口后释放：首连 ECONNREFUSED（可重试类），600ms 后起真服务；
        // 两次退避（500+1000）后第三次命中，验证首连失败仍能恢复。
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("预留端口须成功")
            .local_addr()
            .expect("回环地址须可读")
            .port();
        let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
                .await
                .expect("延迟服务须监听成功");
            let (mut sock, _) = listener.accept().await.expect("须收到重试连接");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
        });
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let resp = fetch_upstream_with_retry(
            &client,
            reqwest::Method::POST,
            &url,
            HeaderMap::new(),
            b"{}".to_vec(),
        )
        .await
        .expect("退避后服务就绪须成功");
        assert_eq!(resp.status().as_u16(), 200);
        assert!(
            start.elapsed() >= Duration::from_millis(1200),
            "须走完两次退避才成功，实测 {:?}",
            start.elapsed()
        );
        server.abort();
    }

    #[test]
    fn fix4_lenient_count_and_models_zero_stats() {
        let m = GatewayMetrics::default();
        for p in [
            "/v1/models",
            "/v1/models/",
            "/v1/models/extra",
            "/v1/fake-chat/completions-extra",
        ] {
            let (hit, _) = is_chat_tail(p, Some(&m));
            assert!(!hit, "{p}");
        }
        assert_eq!(m.lenient_count("chat/completions"), 0);
        assert_eq!(m.lenient_count("v1/messages"), 0);
        assert_eq!(m.lenient_count("v1/responses"), 0);
        let (hit, _) = is_chat_tail("/v1/chat/completions/", Some(&m));
        assert!(hit);
        assert_eq!(m.lenient_count("chat/completions"), 1);
    }

    #[tokio::test]
    async fn business_500_returns_without_retry() {
        use axum::http::HeaderMap;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock 须监听成功");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("须收到连接");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let body = br#"{"error":"synthetic"}"#;
            let head = format!(
                "HTTP/1.1 500 Internal Server Error\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
        });
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let resp = fetch_upstream_with_retry(
            &client,
            reqwest::Method::POST,
            &format!("http://127.0.0.1:{port}/v1/chat/completions"),
            HeaderMap::new(),
            b"{}".to_vec(),
        )
        .await
        .expect("业务 500 是合法响应体，不得转为 Err");
        assert_eq!(resp.status().as_u16(), 500);
        assert!(
            start.elapsed() < Duration::from_millis(3000),
            "业务错误不得走退避重试，实测 {:?}",
            start.elapsed()
        );
        server.abort();
    }

    #[test]
    fn truncated_tool_dropped_counter_accumulates() {
        // P0-3.1：截断丢弃计数可查询（泵内截断路径经此计数）。
        let m = GatewayMetrics::default();
        assert_eq!(m.truncated_tool_dropped_count(), 0);
        m.record_truncated_tool_dropped(2);
        m.record_truncated_tool_dropped(1);
        assert_eq!(m.truncated_tool_dropped_count(), 3);
    }

    #[test]
    fn nondialog_passthrough_counter_accumulates() {
        // P0-4.2：NonDialog 透传计数可查询（非流臂经此计数）。
        let m = GatewayMetrics::default();
        assert_eq!(m.nondialog_passthrough_count(), 0);
        m.record_nondialog_passthrough();
        assert_eq!(m.nondialog_passthrough_count(), 1);
    }

    #[test]
    fn sse_and_hop_counters_queryable_and_count_on_strip() {
        let m = GatewayMetrics::default();
        assert_eq!(m.sse_event_total(), 0);
        m.add_sse_event();
        m.add_sse_event();
        assert_eq!(m.sse_event_total(), 2);
        assert_eq!(m.hop_filtered_count("upstream"), 0);
        m.record_hop_filtered("upstream", 0);
        assert_eq!(m.hop_filtered_count("upstream"), 0, "零剥离不计数");
        m.record_hop_filtered("upstream", 3);
        assert_eq!(m.hop_filtered_count("upstream"), 3);
        assert_eq!(m.hop_filtered_count("downstream"), 0, "方向隔离");
    }

    #[test]
    fn gateway_metrics_atomic_keys() {
        let m = GatewayMetrics::default();
        for key in LENIENT_TAIL_KEYS {
            assert_eq!(m.lenient_count(key), 0);
            m.record_lenient(key);
            assert_eq!(m.lenient_count(key), 1, "{key}");
        }
        for key in TRUNCATED_MODE_KEYS {
            m.record_truncated(key);
            assert_eq!(m.truncated_count(key), 1, "{key}");
        }
        for key in HOP_DIR_KEYS {
            m.record_hop_filtered(key, 2);
            assert_eq!(m.hop_filtered_count(key), 2, "{key}");
        }
        for key in CONV_MISSING_KEYS {
            m.record_conv_missing(key);
            assert_eq!(m.conv_missing_count(key), 1, "{key}");
        }
    }

    #[test]
    fn gateway_metrics_unknown_key_other() {
        let m = GatewayMetrics::default();
        m.record_lenient("unknown-tail");
        m.record_lenient("unknown-tail");
        assert_eq!(
            m.lenient_count("chat/completions"),
            0,
            "未知键不影响已知键读数"
        );
        assert_eq!(m.lenient_count("another-unknown"), 2, "未知键共享 other 桶");
        m.record_lenient("chat/completions");
        assert_eq!(m.lenient_count("chat/completions"), 1);
    }

    #[test]
    fn admin_metrics_keys_unchanged() {
        let m = GatewayMetrics::default();
        for k in ["chat/completions", "v1/messages", "v1/responses"] {
            m.record_lenient(k);
        }
        for k in ["chat/completions", "v1/messages", "v1/responses"] {
            assert_eq!(m.lenient_count(k), 1, "{k}");
        }
        assert_eq!(m.sse_event_total(), 0);
        m.add_sse_event();
        assert_eq!(m.sse_event_total(), 1);
        for k in TRUNCATED_MODE_KEYS {
            m.record_truncated(k);
            assert_eq!(m.truncated_count(k), 1, "{k}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gateway_metrics_concurrent_count() {
        use std::sync::Arc;
        let m = Arc::new(GatewayMetrics::default());
        const TASKS: u64 = 8;
        const PER_TASK: u64 = 1_000;
        let mut handles = Vec::new();
        for _ in 0..TASKS {
            let m = m.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..PER_TASK {
                    m.record_lenient("chat/completions");
                    m.record_truncated("open_ended");
                    m.record_hop_filtered("upstream", 1);
                    m.record_conv_missing("failed");
                }
            }));
        }
        for h in handles {
            h.await.expect("并发任务须完成");
        }
        assert_eq!(m.lenient_count("chat/completions"), TASKS * PER_TASK);
        assert_eq!(m.truncated_count("open_ended"), TASKS * PER_TASK);
        assert_eq!(m.hop_filtered_count("upstream"), TASKS * PER_TASK);
        assert_eq!(m.conv_missing_count("failed"), TASKS * PER_TASK);
        assert_eq!(m.hop_filtered_count("downstream"), 0, "方向隔离");
        assert_eq!(m.truncated_count("synthesized_failed"), 0, "模式隔离");
    }

    #[test]
    fn admin_rate_evicted_counter_accumulates() {
        let m = GatewayMetrics::default();
        assert_eq!(m.admin_rate_evicted_count(), 0);
        m.record_admin_rate_evicted(3);
        m.record_admin_rate_evicted(1);
        assert_eq!(m.admin_rate_evicted_count(), 4);
        m.record_admin_rate_evicted(0);
        assert_eq!(m.admin_rate_evicted_count(), 4, "零驱逐不递增");
    }

    #[test]
    fn upstream_read_error_counter_accumulates() {
        let m = GatewayMetrics::default();
        assert_eq!(m.upstream_read_error_count(), 0);
        m.record_upstream_read_error();
        assert_eq!(m.upstream_read_error_count(), 1, "一次失败递增 1");
        m.record_nondialog_passthrough();
        m.add_sse_event();
        assert_eq!(m.upstream_read_error_count(), 1, "成功路径不递增");
        m.record_upstream_read_error();
        assert_eq!(m.upstream_read_error_count(), 2);
    }

    #[test]
    fn upstream_status_constrained() {
        // ARH-10（7.7）：状态码经受约束类型——合法区间接受，非法值拒绝（不 panic）。
        assert_eq!(
            UpstreamStatus::new(200).map(UpstreamStatus::as_u16),
            Some(200)
        );
        assert_eq!(
            UpstreamStatus::new(599).map(UpstreamStatus::as_u16),
            Some(599)
        );
        assert!(UpstreamStatus::new(99).is_none(), "低于 100 非法");
        assert!(UpstreamStatus::new(600).is_none(), "高于 599 非法");
        assert!(!UpstreamStatus::new(200).expect("合法").is_error());
        assert!(UpstreamStatus::new(200).expect("合法").is_success());
        assert!(UpstreamStatus::new(500).expect("合法").is_error());
        assert!(!UpstreamStatus::new(500).expect("合法").is_success());
    }

    #[test]
    fn strip_veil_internal_headers_case_insensitive_and_selective() {
        // F-2（9.3）：单一定义——全部 `x-veil-*`（大小写归一）剔除，他头保留。
        let mut headers = HeaderMap::new();
        headers.insert("x-veil-protocol", "chat".parse().expect("合法头值"));
        headers.insert("X-Veil-Normalized", "1".parse().expect("合法头值"));
        headers.insert(
            "content-type",
            "text/event-stream".parse().expect("合法头值"),
        );
        assert_eq!(headers.len(), 3, "归一后 `x-veil-*` 两项 + 他头一项");
        strip_veil_internal_headers(&mut headers);
        assert!(headers.get("x-veil-protocol").is_none());
        assert!(headers.get("x-veil-normalized").is_none());
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(headers.len(), 1, "仅非 x-veil-* 头保留");
    }
}
