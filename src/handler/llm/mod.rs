//! LLM 网关入口三单元装配（D1 拆分）：`rewrite`（请求改写）+ `nonstream`（一发一收）+
//! `pump`（流式字节泵）；本模块留守入口（`llm_proxy_handler`）、分发（`gateway_serve`）、
//! 限值常量与共享小谓词，对外 `handler::*` 路径不变。

use {
    crate::{
        config::resolve_upstream_with_ingress,
        service::{
            llm_gateway::{self, GatewayMetrics, Protocol, resolve_protocol},
            redaction::Scope,
        },
        state::AppState,
    },
    axum::{
        Json,
        extract::{Request, State},
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::{Value, json},
    std::{sync::Arc, time::Instant},
};

pub mod nonstream;
pub mod pump;
pub mod rewrite;

/// 限值常量归属 `config.rs`（D1 下沉），此处原位转发防外部引用断裂。
pub use crate::config::{AUDIT_SUBLIMIT_CEILING_BYTES, GATEWAY_BODY_LIMIT_BYTES};
#[cfg(test)]
use crate::{
    approval::PendingApprovals,
    config::{AuditMode, Config},
    service::{credential_vault::CredentialVault, metrics::MetricsStore, pii::PiiDetector},
};

/// 审计/扫描类体长归属判定（spec 8MB 上限的回归锚点，不接请求路径）。
pub fn audit_scan_body_over_limit(len: usize) -> bool { len > AUDIT_SUBLIMIT_CEILING_BYTES }

/// 通用 ingress 超限响应：413 + 错误码 `E_PAYLOAD_TOO_LARGE`（spec 锁定）。
fn payload_too_large(limit: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({"error":{"code":"E_PAYLOAD_TOO_LARGE","message":format!("请求体超过上限 {limit} 字节")}})),
    )
        .into_response()
}

pub async fn llm_proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let outcome = tokio::spawn(async move {
        // 通用 ingress JSON 检查点 10MB（spec `admin-ratelimit-contract` + design D4）：
        // 超限返回 413，MUST NOT 以 `unwrap_or_default` 静默为空体继续处理。
        let body_bytes = match axum::body::to_bytes(body, GATEWAY_BODY_LIMIT_BYTES).await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => return payload_too_large(GATEWAY_BODY_LIMIT_BYTES),
        };
        gateway_serve(&state, &mut parts, &path, body_bytes).await
    })
    .await;
    match outcome {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":{"code":"E_INTERNAL","message":"内部错误"}})),
        )
            .into_response(),
    }
}

/// 上游转发头：剥 `host`/`content-length`/`content-encoding` 后做 hop 头过滤并计数。
pub fn forward_headers(incoming: &HeaderMap, metrics: &GatewayMetrics) -> HeaderMap {
    let mut fwd = incoming.clone();
    fwd.remove(header::HOST);
    fwd.remove(header::CONTENT_LENGTH);
    fwd.remove(header::CONTENT_ENCODING);
    llm_gateway::filter_hop_headers_counted(
        &mut fwd,
        "upstream",
        llm_gateway::DECODE_ENABLED,
        Some(metrics),
    );
    fwd
}

pub(crate) fn protocol_header_value(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Chat => "chat",
        Protocol::Anthropic => "anthropic",
        Protocol::Responses => "responses",
        Protocol::NonDialog => "passthrough",
    }
}

pub(crate) fn empty_body_response() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
    )
        .into_response()
}

/// 流泵路由判定（D5 定稿：客户端 `stream` 意图优先）：上游 `Content-Type`
/// 为 `event-stream` 或请求 `stream==true` 即转流泵；`stream:true` 配
/// `application/json` 组合亦走流泵，由泵内残余分类保证不丢帧。
pub fn should_pump_stream(resp_content_type: &str, stream_flag: bool) -> bool {
    resp_content_type.contains("text/event-stream") || stream_flag
}

async fn gateway_serve(
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
    let is_chat = protocol != Protocol::NonDialog;
    // 入口宿主机端口（entry-transport）：`Host: ip:port` 尾段解析，
    // 缺失/非法回退 None（缺省上游），不猜测。
    let ingress_port: Option<u16> = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|host| {
            host.rsplit(':').next().and_then(|tail| {
                if host.contains(':') {
                    tail.trim().parse::<u16>().ok()
                } else {
                    None
                }
            })
        });
    let upstream_base = match resolve_upstream_with_ingress(&state.config, ingress_port) {
        Some(u) => u,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游未配置"}})),
            )
                .into_response();
        }
    };
    let url = format!("{}{}", upstream_base.trim_end_matches('/'), path);
    let client: &reqwest::Client = &state.http_client;
    let scope = Arc::new(Scope::with_opts(
        state.config.pii_response_side,
        state.config.pii_fuzzy_restore,
    ));
    // 全局单例快照（credential-vault-singleton）：网关只读复用进程级
    // vault/detector，不得每请求新建空映射致还原断链。
    let vault = state.vault.clone();
    let detector = state.detector.clone();
    let sqlite_precise = state.sqlite_ok();
    let hold_max = state.config.audit_hold_max_bytes.max(1) as usize;
    let audit_mode = state.config.audit_mode;
    let audit_policy_file = state.config.audit_policy_file.clone();
    let approval_whitelist = state.config.approval_whitelist.clone();
    let pii_boundary_chars = if state.config.pii_response_side {
        state.config.pii_hold_max.max(1) as usize
    } else {
        0
    };

    if !is_chat {
        // D6：NonDialog 请求体快照：上游意外回 SSE 转泵时 conv 归档与对话路径
        // 同源（同一 `resolve_conv_id`，未知体归档不断链）；仅 Stream 臂使用。
        let nondialog_body: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
        let upstream_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let nctx = NonstreamCtx {
            protocol,
            normalized_out: false,
            stream_flag: false,
            scope: scope.clone(),
            vault: vault.clone(),
            detector: detector.clone(),
            gateway_metrics: state.gateway_metrics.clone(),
            admin_metrics: state.admin.metrics.clone(),
            sqlite_precise,
            req_start,
            audit_mode,
            audit_policy_file: audit_policy_file.clone(),
        };
        return match serve_nonstream(
            client,
            upstream_method,
            &url,
            parts.headers.clone(),
            body_bytes,
            nctx,
        )
        .await
        {
            NonstreamOutcome::Responded(resp) => resp,
            // 非对话本不应回 SSE；上游意外回流时仍按字节泵闭合。
            NonstreamOutcome::Stream(up) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let pctx = StreamPumpCtx {
                    protocol,
                    scope,
                    vault,
                    detector,
                    audit_mode: state.config.audit_mode,
                    audit_policy_file: state.config.audit_policy_file.clone(),
                    approval_whitelist: state.config.approval_whitelist.clone(),
                    hold_max,
                    pii_boundary_chars: if state.config.pii_response_side {
                        state.config.pii_hold_max.max(1) as usize
                    } else {
                        0
                    },
                    gateway_metrics: state.gateway_metrics.clone(),
                    admin_metrics: state.admin.metrics.clone(),
                    sqlite_precise,
                    req_start,
                    pending: state.pending.clone(),
                    // D6：转泵 conv 经同一 `resolve_conv_id` 归档，阻断帧 id 与对话路径同源。
                    init_conv: Some(
                        llm_gateway::resolve_conv_id(
                            None,
                            &nondialog_body,
                            Some(&state.gateway_metrics),
                            "nondialog-stream",
                        )
                        .0,
                    ),
                    normalized_out: false,
                };
                let _pump = spawn_stream_pump(up, tx, pctx);
                build_sse_response(rx, false)
            }
        };
    }

    let rw = request_rewrite(
        body_bytes,
        protocol,
        &state.config,
        scope.clone(),
        vault.clone(),
        detector.clone(),
    )
    .await;
    let dialog_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);
    let pump_ctx = || StreamPumpCtx {
        protocol,
        scope: scope.clone(),
        vault: vault.clone(),
        detector: detector.clone(),
        audit_mode,
        audit_policy_file: audit_policy_file.clone(),
        approval_whitelist: approval_whitelist.clone(),
        hold_max,
        pii_boundary_chars,
        gateway_metrics: state.gateway_metrics.clone(),
        admin_metrics: state.admin.metrics.clone(),
        sqlite_precise,
        req_start,
        pending: state.pending.clone(),
        init_conv: rw.init_conv.clone(),
        normalized_out: rw.normalized_out,
    };
    if rw.stream_flag {
        let fwd_headers = forward_headers(&parts.headers, &state.gateway_metrics);
        match llm_gateway::fetch_upstream_with_retry(
            client,
            dialog_method,
            &url,
            fwd_headers,
            rw.body,
        )
        .await
        {
            Ok(up) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let _pump = spawn_stream_pump(up, tx, pump_ctx());
                build_sse_response(rx, rw.normalized_out)
            }
            Err(_) => empty_body_response(),
        }
    } else {
        let nctx = NonstreamCtx {
            protocol,
            normalized_out: rw.normalized_out,
            stream_flag: false,
            scope: scope.clone(),
            vault: vault.clone(),
            detector: detector.clone(),
            gateway_metrics: state.gateway_metrics.clone(),
            admin_metrics: state.admin.metrics.clone(),
            sqlite_precise,
            req_start,
            audit_mode,
            audit_policy_file: audit_policy_file.clone(),
        };
        match serve_nonstream(
            client,
            dialog_method,
            &url,
            parts.headers.clone(),
            rw.body,
            nctx,
        )
        .await
        {
            NonstreamOutcome::Responded(resp) => resp,
            // 客户端未要求流但上游回 SSE 时，转字节泵保证终止闭合。
            NonstreamOutcome::Stream(up) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let _pump = spawn_stream_pump(up, tx, pump_ctx());
                build_sse_response(rx, rw.normalized_out)
            }
        }
    }
}

pub use {
    nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
    pump::{PumpOutcome, StreamPumpCtx, build_sse_response, spawn_stream_pump},
    rewrite::{RewriteOutput, request_rewrite},
};

#[cfg(test)]
mod gateway_units_tests {
    use {
        super::{pump::should_synthesize_empty_stream, *},
        std::collections::HashMap,
    };

    fn base_env() -> HashMap<String, String> {
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

    fn test_config(extra: &[(&str, &str)]) -> Config {
        let mut env = base_env();
        for (k, v) in extra {
            env.insert((*k).to_string(), (*v).to_string());
        }
        Config::load_from(&env).expect("测试配置须合法")
    }

    fn fresh_arcs() -> (Arc<Scope>, Arc<CredentialVault>, Arc<PiiDetector>) {
        (
            Arc::new(Scope::new()),
            Arc::new(CredentialVault::new()),
            Arc::new(PiiDetector::new()),
        )
    }

    fn nonstream_ctx(
        protocol: Protocol,
        scope: Arc<Scope>,
        vault: Arc<CredentialVault>,
        detector: Arc<PiiDetector>,
    ) -> NonstreamCtx {
        NonstreamCtx {
            protocol,
            normalized_out: false,
            stream_flag: false,
            scope,
            vault,
            detector,
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            audit_mode: AuditMode::Off,
            audit_policy_file: None,
        }
    }

    fn pump_ctx(
        protocol: Protocol,
        scope: Arc<Scope>,
        vault: Arc<CredentialVault>,
        detector: Arc<PiiDetector>,
    ) -> StreamPumpCtx {
        StreamPumpCtx {
            protocol,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Off,
            audit_policy_file: None,
            approval_whitelist: Vec::new(),
            hold_max: 1_048_576,
            pii_boundary_chars: 64,
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            pending: Arc::new(PendingApprovals::default()),
            init_conv: None,
            normalized_out: false,
        }
    }

    /// 回环上游：固定状态码/内容类型/体，供非流与流泵回放单测（无外网依赖）。
    async fn loopback_server(
        status: u16,
        content_type: &str,
        body: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("回环监听须成功");
        let url = format!(
            "http://{}/v1/chat/completions",
            listener.local_addr().expect("回环地址须可读")
        );
        let reason = match status {
            200 => "OK",
            401 => "Unauthorized",
            502 => "Bad Gateway",
            _ => "OK",
        };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 65536];
                let _ = sock.read(&mut buf).await;
                if sock.write_all(head.as_bytes()).await.is_err() {
                    continue;
                }
                if sock.write_all(&body).await.is_err() {
                    continue;
                }
                let _ = sock.shutdown().await;
            }
        });
        (url, handle)
    }

    /// 预留端口后立即释放，后续连接恒被拒绝（超时/不可达映射单测用）。
    async fn refused_url() -> String {
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("回环监听须成功")
            .local_addr()
            .expect("回环地址须可读")
            .port();
        format!("http://127.0.0.1:{port}/v1/chat/completions")
    }

    #[tokio::test]
    async fn 改写默认字节等价且无网络() {
        let config = test_config(&[]);
        assert!(!config.normalize_json_whitespace);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","messages":[{"role":"user","content":"hello"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert_eq!(out.body, raw, "默认关闭空白压缩时除 token 替换外须字节等价");
        assert!(!out.normalized_out);
        assert!(!out.stream_flag);
        assert!(out.init_conv.is_none());
    }

    #[tokio::test]
    async fn 脱敏关闭显式零值请求原文透传() {
        let config = test_config(&[("REDACTION_ENABLED", "0")]);
        assert!(!config.redaction_enabled);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","messages":[{"role":"user","content":"call 13812345678"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert_eq!(
            out.body, raw,
            "显式关闭脱敏时含 PII 请求须原文透传，防旧 compose 静默变严"
        );
    }

    #[tokio::test]
    async fn 改写注入stream选项并声明归一化() {
        let config = test_config(&[("NORMALIZE_JSON_WHITESPACE", "1")]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","stream":true,"messages":[]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert!(out.stream_flag);
        assert!(out.normalized_out);
        let v: Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(
            v.get("stream_options")
                .and_then(|o| o.get("include_usage"))
                .and_then(|b| b.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn 非流转发成功原样返回() {
        let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
        let (url, server) = loopback_server(200, "application/json", up_body).await;
        let client = reqwest::Client::new();
        let (scope, vault, detector) = fresh_arcs();
        let admin = Arc::new(MetricsStore::new(std::path::PathBuf::from(
            "/tmp/veil-gateway-units-test.sqlite",
        )));
        let mut ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
        ctx.admin_metrics = admin.clone();
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            ctx,
        )
        .await;
        let resp = match outcome {
            NonstreamOutcome::Responded(r) => r,
            NonstreamOutcome::Stream(_) => panic!("JSON 上游不得转流泵"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-veil-protocol")
                .and_then(|v| v.to_str().ok()),
            Some("chat")
        );
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("响应体须可读");
        assert!(
            body.windows(2).any(|w| w == b"hi"),
            "响应体须原样返回上游内容"
        );
        assert_eq!(admin.ring_len(), 1, "非流成功须记一条 record_chat 快照");
        server.abort();
    }

    #[tokio::test]
    async fn 非流上游不可达映射502而非挂起() {
        let url = refused_url().await;
        let client = reqwest::Client::new();
        let (scope, vault, detector) = fresh_arcs();
        let ctx = nonstream_ctx(Protocol::NonDialog, scope, vault, detector);
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::GET,
            &url,
            HeaderMap::new(),
            Vec::new(),
            ctx,
        )
        .await;
        let resp = match outcome {
            NonstreamOutcome::Responded(r) => r,
            NonstreamOutcome::Stream(_) => panic!("不可达上游不得转流泵"),
        };
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("响应体须可读");
        assert!(
            body.windows(12).any(|w| w == b"E_EMPTY_BODY"),
            "网关级错误码须为 E_EMPTY_BODY"
        );
    }

    async fn collect_pump(
        upstream: reqwest::Response,
        ctx: StreamPumpCtx,
    ) -> (PumpOutcome, Vec<String>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
        let handle = spawn_stream_pump(upstream, tx, ctx);
        let outcome = handle.await.expect("流泵任务不得崩");
        let mut frames = Vec::new();
        while let Some(f) = rx.recv().await {
            frames.push(f);
        }
        (outcome, frames)
    }

    #[tokio::test]
    async fn 流泵正常收尾恰一个终止帧() {
        let sse =
            b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) =
            collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
        assert!(!outcome.block_injected);
        let joined = frames.join("");
        assert!(joined.contains("hi"), "录制流内容须泵到下游");
        let done_count = frames.iter().filter(|f| f.contains("data: [DONE]")).count();
        assert_eq!(done_count, 1, "正常收尾恰一个终止帧，不追加多余终止");
        assert!(
            frames.last().is_some_and(|f| f.contains("data: [DONE]")),
            "下游须以终止帧收尾"
        );
        server.abort();
    }

    #[tokio::test]
    async fn 跨帧切分手机号边界hold掩码() {
        let sse = b"data: {\"choices\":[{\"delta\":{\"content\":\"call 138\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"12345678 ok\"}}]}\n\ndata: [DONE]\n\n"
            .to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (cscope, cvault, cdetector) = (scope.clone(), vault.clone(), detector.clone());
        let (outcome, frames) =
            collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
        assert!(!outcome.block_injected);
        let mut decoded = String::new();
        for f in &frames {
            for line in f.lines() {
                let Some(payload) = line.strip_prefix("data: ") else {
                    continue;
                };
                if payload.trim() == "[DONE]" {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload)
                    && let Some(c) = v
                        .pointer("/choices/0/delta/content")
                        .and_then(|x| x.as_str())
                {
                    decoded.push_str(c);
                }
            }
        }
        assert!(
            !decoded.contains("13812345678"),
            "解码拼接后不得复原完整手机号: {decoded}"
        );
        assert!(decoded.contains("call "), "非敏感前缀须保留: {decoded}");
        assert!(decoded.contains("ok"), "非敏感后缀须保留: {decoded}");
        // 对照：逐帧脱敏（无边界 hold）对切分残片漏检，拼接可复原原文。
        let f1 = cscope
            .redact_response_new_pii(&cvault, &cdetector, "call 138")
            .await;
        let f2 = cscope
            .redact_response_new_pii(&cvault, &cdetector, "12345678 ok")
            .await;
        assert!(
            format!("{f1}{f2}").contains("13812345678"),
            "对照组须复现漏检，否则本用例无回归价值"
        );
        server.abort();
    }

    #[tokio::test]
    async fn 保真字段原样透传不改写() {
        let sse = b"data: {\"id\":\"chatcmpl-xyz\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"m-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chatcmpl-xyz\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"m-test\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
            .to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) =
            collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
        assert!(!outcome.block_injected);
        let joined = frames.join("");
        for key in [
            "\"chatcmpl-xyz\"",
            "\"chat.completion.chunk\"",
            "1700000000",
            "\"m-test\"",
            "\"stop\"",
        ] {
            assert!(
                joined.contains(key),
                "保真字段须原样透传，缺 {key}: {joined}"
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn 流泵残余已发不再合成二次空流帧() {
        // 无尾空行半帧：事件循环无分发（`forwarded==0`），残余路径直发下游。
        // 旧守门（`forwarded==0`）误触发二次空流合成；新守门以状态位为准跳过。
        let half = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}".to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", half).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) =
            collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
        let joined = frames.join("");
        assert!(joined.contains("hi"), "残余半帧须送达下游");
        assert!(!outcome.block_injected, "残余已发不得再合成空流阻断帧");
        assert!(!joined.contains("empty-stream"), "全流不得出现二次空流合成");
        server.abort();
    }

    #[test]
    fn 空流合成守门真值表() {
        assert!(should_synthesize_empty_stream(false, false, false));
        assert!(!should_synthesize_empty_stream(false, true, false));
        assert!(!should_synthesize_empty_stream(true, false, false));
        assert!(!should_synthesize_empty_stream(false, false, true));
        assert!(!should_synthesize_empty_stream(true, true, true));
    }

    #[tokio::test]
    async fn 非流上游400原样透出不吞错() {
        // D5 回归：`truncation:disabled` 类上游 400 错误体须原样透出（状态码与正文），
        // 不得吞错转 502/空体。
        let up_body = br#"{"error":{"message":"truncation with disabled is not supported","type":"invalid_request_error"}}"#.to_vec();
        let (url, server) = loopback_server(400, "application/json", up_body).await;
        let client = reqwest::Client::new();
        let (scope, vault, detector) = fresh_arcs();
        let ctx = nonstream_ctx(Protocol::Responses, scope, vault, detector);
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            HeaderMap::new(),
            br#"{"model":"m","truncation":"disabled"}"#.to_vec(),
            ctx,
        )
        .await;
        let resp = match outcome {
            NonstreamOutcome::Responded(r) => r,
            NonstreamOutcome::Stream(_) => panic!("400 错误体不得转流泵"),
        };
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("响应体须可读");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("truncation"), "错误正文须透出: {text}");
        assert!(
            text.contains("invalid_request_error"),
            "错误类型须透出: {text}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn thinking与signature不透明透传值一致() {
        // D5 回归：thinking/signature/redacted_thinking 为次要事件，不进 hold 不审计；
        // 网关 JSON 归一化仅调序，敏感字节值须原样透出。
        let sse = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm...\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig-bytes-123\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"redacted_thinking\",\"redacted_data\":\"eHh4\"}\n\n".to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) = collect_pump(
            upstream,
            pump_ctx(Protocol::Anthropic, scope, vault, detector),
        )
        .await;
        assert!(!outcome.block_injected, "次要事件不得触发阻断");
        assert_eq!(frames.len(), 3, "三帧须逐帧透出不丢弃");
        let mut values = Vec::new();
        for f in &frames {
            for line in f.lines() {
                if let Some(payload) = line.strip_prefix("data: ") {
                    let v: Value = serde_json::from_str(payload).expect("下游帧须为合法 JSON");
                    if let Some(t) = v
                        .get("delta")
                        .and_then(|d| d.get("thinking"))
                        .and_then(|x| x.as_str())
                    {
                        values.push(t.to_string());
                    }
                    if let Some(s) = v
                        .get("delta")
                        .and_then(|d| d.get("signature"))
                        .and_then(|x| x.as_str())
                    {
                        values.push(s.to_string());
                    }
                    if let Some(r) = v.get("redacted_data").and_then(|x| x.as_str()) {
                        values.push(r.to_string());
                    }
                }
            }
        }
        assert_eq!(
            values,
            vec![
                "hmm...".to_string(),
                "sig-bytes-123".to_string(),
                "eHh4".to_string()
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn 流泵空流注入阻断并标记终止() {
        let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) =
            collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
        assert!(outcome.block_injected, "空流须注入阻断帧");
        assert!(
            outcome.terminal_injected,
            "阻断注入后 terminal_injected 须为真"
        );
        let joined = frames.join("");
        assert!(joined.contains("empty-stream"), "下游须收到阻断事件");
        assert!(
            frames.iter().any(|f| f.contains("data: [DONE]")),
            "阻断事件后恒有终止帧"
        );
        server.abort();
    }

    #[tokio::test]
    async fn responses_incomplete与error合成单个failed() {
        let sse = b"data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r9\",\"status\":\"incomplete\"}}\n\ndata: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) = collect_pump(
            upstream,
            pump_ctx(Protocol::Responses, scope, vault, detector),
        )
        .await;
        let joined = frames.join("");
        assert!(
            joined.contains("response.failed"),
            "incomplete/error 须映射为 failed"
        );
        assert!(
            !joined.contains("response.incomplete"),
            "原始 incomplete 不得透出"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|f| f.contains("response.failed"))
                .count(),
            1,
            "恒恰一个 failed 终止帧"
        );
        assert!(outcome.terminal_injected, "映射后 terminal 须落位");
        server.abort();
    }

    #[test]
    fn sse响应构建头合规() {
        let (_tx, rx) = tokio::sync::mpsc::channel::<String>(64);
        let resp = build_sse_response(rx, true);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(
            resp.headers()
                .get("x-veil-normalized")
                .and_then(|v| v.to_str().ok()),
            Some("json-whitespace")
        );
    }
}

#[cfg(test)]
mod entry_tests {
    use super::*;

    #[test]
    fn stream真加json组合走流泵() {
        assert!(should_pump_stream("text/event-stream", false));
        assert!(should_pump_stream("text/event-stream", true));
        assert!(should_pump_stream("application/json", true));
        assert!(!should_pump_stream("application/json", false));
        assert!(!should_pump_stream("", false));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn 体上限分级取值与spec一致() {
        assert_eq!(GATEWAY_BODY_LIMIT_BYTES, 10 * 1024 * 1024);
        assert_eq!(AUDIT_SUBLIMIT_CEILING_BYTES, 8 * 1024 * 1024);
        assert!(GATEWAY_BODY_LIMIT_BYTES > AUDIT_SUBLIMIT_CEILING_BYTES);
        assert!(!audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES));
        assert!(audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES + 1));
    }

    #[tokio::test]
    async fn 体超限响应413携带错误码() {
        let resp = payload_too_large(GATEWAY_BODY_LIMIT_BYTES);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "E_PAYLOAD_TOO_LARGE");
    }

    #[tokio::test]
    async fn 超限体被to_bytes拒绝而非静默空体() {
        let over = vec![b'x'; 64];
        let err = axum::body::to_bytes(axum::body::Body::from(over), 16).await;
        assert!(err.is_err());
        let ok = axum::body::to_bytes(axum::body::Body::from(vec![b'x'; 16]), 16).await;
        assert!(ok.is_ok());
    }
}
