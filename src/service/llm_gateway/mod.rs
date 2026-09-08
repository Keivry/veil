//! LLM 网关协议管线（D1 按协议拆模块）：`protocol`（协议识别/流判定）+ `usage`
//! （用量提取/合并）+ `hop`（逐跳头过滤）+ `placeholder`（占位符说明注入）+ `tool`
//! （工具调用/会话归档）；本模块留守网关度量、空体分类、重试/选路/上游抓取与重导出，
//! 对外 `llm_gateway::*` 路径不变。

use {
    crate::config::Config,
    axum::http::HeaderMap,
    std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    },
};

pub mod hop;
pub mod placeholder;
pub mod protocol;
pub mod tool;
pub mod usage;

pub const RETRY_DELAYS_MS: [u64; 3] = [500, 1000, 2000];
pub const MAX_RETRY_ATTEMPTS: usize = 3;

#[derive(Debug, Default)]
pub struct GatewayMetrics {
    lenient: Mutex<HashMap<String, u64>>,
    truncated: Mutex<HashMap<String, u64>>,
    hop_filtered: Mutex<HashMap<String, u64>>,
    conv_missing: Mutex<HashMap<String, u64>>,
    sse_events: AtomicU64,
}

impl GatewayMetrics {
    pub fn record_lenient(&self, tail: &str) {
        if let Ok(mut g) = self.lenient.lock() {
            *g.entry(tail.to_string()).or_insert(0) += 1;
        }
    }

    pub fn lenient_count(&self, tail: &str) -> u64 {
        self.lenient
            .lock()
            .map(|g| g.get(tail).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    pub fn record_truncated(&self, mode: &str) {
        if let Ok(mut g) = self.truncated.lock() {
            *g.entry(mode.to_string()).or_insert(0) += 1;
        }
    }

    pub fn truncated_count(&self, mode: &str) -> u64 {
        self.truncated
            .lock()
            .map(|g| g.get(mode).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    pub fn add_sse_event(&self) { self.sse_events.fetch_add(1, Ordering::Relaxed); }

    pub fn sse_event_total(&self) -> u64 { self.sse_events.load(Ordering::Relaxed) }

    pub fn record_hop_filtered(&self, dir: &str, count: u64) {
        if count == 0 {
            return;
        }
        if let Ok(mut g) = self.hop_filtered.lock() {
            *g.entry(dir.to_string()).or_insert(0) += count;
        }
    }

    pub fn hop_filtered_count(&self, dir: &str) -> u64 {
        self.hop_filtered
            .lock()
            .map(|g| g.get(dir).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    pub fn record_conv_missing(&self, reason: &str) {
        if let Ok(mut g) = self.conv_missing.lock() {
            *g.entry(reason.to_string()).or_insert(0) += 1;
        }
    }

    pub fn conv_missing_count(&self, reason: &str) -> u64 {
        self.conv_missing
            .lock()
            .map(|g| g.get(reason).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyAction {
    StreamInjectThen502,
    NonStreamTo502,
    Passthrough502_401,
    NonDialogExempt,
    PassthroughOk,
}

pub fn classify_empty(
    is_chat: bool,
    is_stream: bool,
    body_len: usize,
    is_json: bool,
    upstream_status: u16,
) -> EmptyAction {
    if !is_chat {
        return EmptyAction::NonDialogExempt;
    }
    if upstream_status == 502 || upstream_status == 401 {
        return EmptyAction::Passthrough502_401;
    }
    if is_stream {
        if body_len == 0 {
            return EmptyAction::StreamInjectThen502;
        }
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

pub fn resolve_upstream(config: &Config, local_port: Option<u16>) -> Option<String> {
    if let Some(port) = local_port
        && let Some(u) = config.llm_upstreams.get(&port)
    {
        return Some(u.clone());
    }
    if let Some(u) = config.llm_default_upstream.clone() {
        return Some(u);
    }
    config.llm_upstreams.values().next().cloned()
}

pub async fn fetch_upstream_with_retry(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> anyhow::Result<reqwest::Response> {
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
                if e.is_connect() || e.is_timeout() {
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
    hop::{DECODE_ENABLED, HOP_HEADERS, filter_hop_headers, filter_hop_headers_counted},
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
        is_stream_body,
        resolve_protocol,
        should_inject_stream_options,
    },
    tool::{
        ToolCall,
        archive_unknown_id,
        extract_conv_id,
        extract_tool_calls,
        normalize_tool_args,
        resolve_conv_id,
    },
    usage::{Usage, accumulate_usage, extract_usage_nonstream, extract_usage_stream},
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 空体502四分支() {
        assert_eq!(
            classify_empty(true, true, 0, false, 200),
            EmptyAction::StreamInjectThen502
        );
        assert_eq!(
            classify_empty(true, false, 0, false, 200),
            EmptyAction::NonStreamTo502
        );
        assert_eq!(
            classify_empty(true, false, 10, false, 200),
            EmptyAction::NonStreamTo502
        );
        assert_eq!(
            classify_empty(true, false, 10, true, 502),
            EmptyAction::Passthrough502_401
        );
        assert_eq!(
            classify_empty(true, true, 5, true, 401),
            EmptyAction::Passthrough502_401
        );
        assert_eq!(
            classify_empty(false, false, 0, false, 200),
            EmptyAction::NonDialogExempt
        );
    }

    #[test]
    fn 上游端口映射解析() {
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
    fn 重试退避曲线() {
        assert_eq!(retry_delay(0), Duration::from_millis(500));
        assert_eq!(retry_delay(1), Duration::from_millis(1000));
        assert_eq!(retry_delay(2), Duration::from_millis(2000));
    }

    #[tokio::test]
    async fn 断开重试退避封顶且最终失败() {
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
    async fn 首连拒收重试后成功() {
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
    fn fix4宽容计数加models零统计() {
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
    async fn 业务500体不重试直接返回() {
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
    fn sse与hop计数器可查且剥离即计数() {
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
}
