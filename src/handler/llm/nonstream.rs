//! 非流单元（2.2）：一发一收，超时/不可达映射为网关级错误而非挂起。

use {
    super::{
        empty_body_response,
        forward_headers,
        protocol_header_value,
        pump::now_secs,
        should_pump_stream,
    },
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        service::{
            audit::AuditPolicy,
            block_inject,
            credential_vault::CredentialVault,
            llm_gateway::{
                self,
                EmptyAction,
                GatewayMetrics,
                Protocol,
                classify_empty,
                extract_usage_nonstream,
            },
            metrics::{ChatRecord, MetricsStore},
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    axum::{
        Json,
        body::Body,
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::Value,
    std::{path::PathBuf, sync::Arc, time::Instant},
};

/// 2.2 `nonstream` 一发一收的上下文：显式传入的请求级依赖快照。
/// `req_start`/`sqlite_precise` 以快照值传入，保持 `record_chat` 快照语义。
pub struct NonstreamCtx {
    pub protocol: Protocol,
    pub normalized_out: bool,
    pub stream_flag: bool,
    pub scope: Arc<Scope>,
    pub vault: Arc<CredentialVault>,
    pub detector: Arc<PiiDetector>,
    pub gateway_metrics: Arc<GatewayMetrics>,
    pub admin_metrics: Arc<MetricsStore>,
    pub sqlite_precise: bool,
    pub req_start: Instant,
    pub audit_mode: AuditMode,
    pub audit_policy_file: Option<PathBuf>,
    /// 非流 approve 建单表（P0-1.4：`NeedApproval` 记 pending，不断链）。
    pub pending: Arc<PendingApprovals>,
}

/// `serve_nonstream` 的结果：完整响应，或上游意外回 SSE 时把未消费的
/// `reqwest::Response` 交回调用方转流泵（原 `looks_sse` 语义）。
pub enum NonstreamOutcome {
    Responded(Response),
    Stream(reqwest::Response),
}

/// 2.2 `nonstream` 一发一收：接收改写后请求，返回完整上游响应；
/// 上游超时/不可达映射为网关级错误状态码而非挂起。
/// `client` 为只读引用（单例由 1.x 负责），本单元内不新建 Client。
pub async fn serve_nonstream(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
    ctx: NonstreamCtx,
) -> NonstreamOutcome {
    let fwd_headers = forward_headers(&headers, &ctx.gateway_metrics);
    let up = match llm_gateway::fetch_upstream_with_retry(client, method, url, fwd_headers, body)
        .await
    {
        Ok(up) => up,
        Err(_) => return NonstreamOutcome::Responded(empty_body_response()),
    };
    if ctx.protocol == Protocol::NonDialog {
        // P0-4.2/F1：非对话臂保持字节透传（与 Python 直通语义一致：无用量/
        // 审计/还原），记 `nondialog_passthrough` 供流量验证；若需补还原另立任务。
        ctx.gateway_metrics.record_nondialog_passthrough();
        let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        let mut resp_headers = HeaderMap::new();
        for (k, v) in up.headers().iter() {
            if let (Ok(n), Ok(val)) = (
                k.to_string().parse::<axum::http::HeaderName>(),
                axum::http::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                resp_headers.insert(n, val);
            }
        }
        llm_gateway::filter_hop_headers_counted(
            &mut resp_headers,
            "downstream",
            llm_gateway::DECODE_ENABLED,
            Some(&ctx.gateway_metrics),
        );
        for (k, v) in resp_headers.iter() {
            builder = builder.header(k, v);
        }
        return NonstreamOutcome::Responded(
            builder
                .body(Body::from_stream(up.bytes_stream()))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response()),
        );
    }
    // P0-1.1：502/401 不再早返原始字节，走完整后处理链（用量记录 +
    // 审计判定 + 凭据/PII 还原，还原失败回退原文）；非 JSON 错误体按下文
    // 显式豁免透传（无 JSON 可提取用量/工具调用，见尾部 `is_error_status` 分支）。
    let status_u16 = up.status().as_u16();
    let is_error_status = status_u16 == 502 || status_u16 == 401;
    let resp_ct = up
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let looks_sse = should_pump_stream(&resp_ct, ctx.stream_flag);
    if looks_sse {
        return NonstreamOutcome::Stream(up);
    }
    let bytes = up.bytes().await.unwrap_or_default();
    let is_json = serde_json::from_slice::<Value>(&bytes).is_ok();
    if classify_empty(true, false, bytes.len(), is_json, status_u16) == EmptyAction::NonStreamTo502
    {
        return NonstreamOutcome::Responded(empty_body_response());
    }
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        let usage = extract_usage_nonstream(ctx.protocol, &v);
        // C13：模型分桶取上游回显值（缺失归 `unknown_model`）。
        let upstream_model = v.get("model").and_then(|m| m.as_str()).unwrap_or("");
        ctx.admin_metrics.record_chat(ChatRecord {
            protocol: ctx.protocol,
            model: upstream_model,
            latency_ms: ctx.req_start.elapsed().as_millis() as u64,
            usage: usage.as_ref(),
            truncated_mode: None,
            is_precise: ctx.sqlite_precise,
            ts_secs: now_secs(),
        });
        // 非流 tool 提取 + 审计（§2.3）：阻断时返回协议正确的 block 体代替上游响应。
        let audit_policy = match ctx.audit_policy_file.clone() {
            Some(path) => match AuditPolicy::load_from_file(Some(path.as_path())) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!("审计策略文件加载失败，使用默认策略: {err}");
                    AuditPolicy::default_policy()
                }
            },
            None => AuditPolicy::default_policy(),
        };
        let conv_id = llm_gateway::extract_conv_id(&v).unwrap_or_else(|| {
            llm_gateway::resolve_conv_id(None, &v, Some(&ctx.gateway_metrics), "nonstream-block").0
        });
        if let Some(block_body) = block_inject::evaluate_nonstream(
            ctx.protocol,
            &v,
            ctx.audit_mode,
            &audit_policy,
            &conv_id,
            &ctx.pending,
        ) {
            ctx.admin_metrics
                .record_aux_counts(ctx.protocol, now_secs(), 0, 0, 1);
            let mut resp = (
                StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
                Json(block_body),
            )
                .into_response();
            if ctx.normalized_out {
                resp.headers_mut().insert(
                    "x-veil-normalized",
                    header::HeaderValue::from_static("json-whitespace"),
                );
            }
            resp.headers_mut().insert(
                "x-veil-protocol",
                header::HeaderValue::from_static(protocol_header_value(ctx.protocol)),
            );
            return NonstreamOutcome::Responded(resp);
        }
        ctx.admin_metrics
            .record_aux_counts(ctx.protocol, now_secs(), 0, 0, 0);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let (restored, spans) = ctx.scope.restore_response_with_spans(&ctx.vault, &text);
        let mut restored = ctx
            .scope
            .redact_response_new_pii_with_skip(&ctx.vault, &ctx.detector, &restored, &spans)
            .await;
        // P0-1.2：还原后双 `_jloads` 校验（对标 Python `_nonstream_build`）：
        // 还原/脱敏可能把未转义明文写回 JSON 串内致破裂，失败回退上游原文并 warn。
        if serde_json::from_str::<Value>(&restored).is_err() {
            let preview: String = restored.chars().take(4000).collect();
            tracing::warn!("非流还原后 JSON 校验失败，已回退上游原文: {preview}");
            restored = text;
        }
        // P0-1.3：出口显式残缺剥离（凭据 `__VG_CRED_` + PII `__PII_` 半截形态）。
        // 还原/脱敏路径内已带剥离，此处幂等兜底响应侧关闭等旁路。
        let restored = crate::service::redaction::strip_partials(&restored);
        let mut resp = (
            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
            restored,
        )
            .into_response();
        if ctx.normalized_out {
            resp.headers_mut().insert(
                "x-veil-normalized",
                header::HeaderValue::from_static("json-whitespace"),
            );
        }
        resp.headers_mut().insert(
            "x-veil-protocol",
            header::HeaderValue::from_static(protocol_header_value(ctx.protocol)),
        );
        return NonstreamOutcome::Responded(resp);
    }
    // P0-1.1 显式豁免：非 JSON 的 502/401 错误体无用量/工具调用可提取，
    // 按设计备选路径原样透传（状态码保留），不吞错转空体。
    if is_error_status {
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
        return NonstreamOutcome::Responded((status, bytes.to_vec()).into_response());
    }
    NonstreamOutcome::Responded(empty_body_response())
}

#[cfg(test)]
mod nonstream_empty_tests {
    use {
        super::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        crate::{
            approval::PendingApprovals,
            config::{AuditMode, Config},
            service::{
                credential_vault::CredentialVault,
                llm_gateway::{self, EmptyAction, Protocol, classify_empty},
                metrics::MetricsStore,
                pii::PiiDetector,
                redaction::{self, Scope},
            },
        },
        std::{collections::HashMap, sync::Arc, time::Instant},
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

    fn test_config() -> Config { Config::load_from(&base_env()).expect("测试配置须合法") }

    fn test_ctx(protocol: Protocol) -> NonstreamCtx {
        let _ = test_config();
        NonstreamCtx {
            protocol,
            normalized_out: false,
            stream_flag: false,
            scope: Arc::new(Scope::new()),
            vault: Arc::new(CredentialVault::new()),
            detector: Arc::new(PiiDetector::new()),
            gateway_metrics: Arc::new(llm_gateway::GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-nonstream-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            audit_mode: AuditMode::Off,
            audit_policy_file: None,
            pending: Arc::new(PendingApprovals::default()),
        }
    }

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

    #[test]
    fn llm_empty_1_empty_body_maps_to_502() {
        // T2-1：空体（len 0）非流转 502；空体响应体为 E_EMPTY_BODY/502。
        assert_eq!(
            classify_empty(true, false, 0, false, 200),
            EmptyAction::NonStreamTo502
        );
        assert_eq!(
            classify_empty(true, false, 0, true, 200),
            EmptyAction::NonStreamTo502,
            "JSON 与否不影响空体转 502"
        );
    }

    #[test]
    fn llm_empty_2_hallucinated_cred_stripped_to_blank_is_502() {
        // T2-2：仅幻觉凭据 token 经 strip 后空白 → 502（PII 完整形态保留不计入）。
        let vault = CredentialVault::new();
        let cleaned = redaction::strip_token_forms(&vault, "__VG_CRED_000007__");
        assert!(
            cleaned.trim().is_empty(),
            "幻觉凭据剥离后须空白，实际 {cleaned:?}"
        );
        assert_eq!(
            classify_empty(true, false, cleaned.len(), false, 200),
            EmptyAction::NonStreamTo502
        );
    }

    #[test]
    fn llm_empty_3_complete_pii_token_kept_after_strip() {
        // T2-3：完整 PII token（响应期新 token）在出口保留，不触发 502。
        let vault = CredentialVault::new();
        let kept = redaction::strip_token_forms(&vault, "__PII_7_ab12cd34__");
        assert!(
            kept.contains("__PII_7_ab12cd34__"),
            "完整 PII token 须保留，实际 {kept:?}"
        );
    }

    #[test]
    fn llm_empty_4_normal_text_not_502() {
        // T2-4：正常 JSON 文本 strip 后非空 → PassthroughOk，不转 502。
        let vault = CredentialVault::new();
        let body = r#"{"content":"hello world 正常响应"}"#;
        let out = redaction::strip_token_forms(&vault, body);
        assert!(out.contains("hello world"));
        assert_eq!(
            classify_empty(true, false, out.len(), true, 200),
            EmptyAction::PassthroughOk
        );
        // 非 JSON 载荷非流恒转 502（无 JSON 可提取用量/工具调用）。
        assert_eq!(
            classify_empty(true, false, out.len(), false, 200),
            EmptyAction::NonStreamTo502
        );
    }

    #[test]
    fn llm_empty_5_error_status_never_maps_to_502() {
        // T2-5：502/401 豁免 502 映射（原样透传）；429 空体仍转 502（无体可透传）。
        for status in [502u16, 401] {
            assert_eq!(
                classify_empty(true, false, 0, false, status),
                EmptyAction::Passthrough502_401,
                "status={status} 不应转 NonStreamTo502"
            );
        }
        assert_eq!(
            classify_empty(true, false, 0, false, 429),
            EmptyAction::NonStreamTo502,
            "429 空体无透传物，仍转 502"
        );
        assert_eq!(
            classify_empty(true, true, 0, false, 502),
            EmptyAction::Passthrough502_401
        );
    }

    #[test]
    fn llm_empty_6_stream_zero_frames_still_synthesizes() {
        // T2-6：流式零帧发出（含 hold 缓冲吞帧）仍合成空流兜底。
        assert!(super::super::pump::should_synthesize_empty_stream(
            false, false, false
        ));
        assert!(!super::super::pump::should_synthesize_empty_stream(
            false, true, false
        ));
        assert!(!super::super::pump::should_synthesize_empty_stream(
            true, false, false
        ));
        assert!(!super::super::pump::should_synthesize_empty_stream(
            false, false, true
        ));
    }

    #[test]
    fn llm_empty_7_nondialog_exempt_from_empty_mapping() {
        // T2-7：非对话路径豁免空体映射（字节透传）。
        assert_eq!(
            classify_empty(false, false, 0, false, 200),
            EmptyAction::NonDialogExempt
        );
    }

    #[tokio::test]
    async fn llm_empty_e2e_upstream_empty_body_returns_502() {
        // T2-E2E：上游空体经 serve_nonstream 返回 502（回环，无外网）。
        let client = reqwest::Client::new();
        let (url, server) = loopback_server(200, "application/json", vec![]).await;
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            axum::http::HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            test_ctx(Protocol::Chat),
        )
        .await;
        server.abort();
        let NonstreamOutcome::Responded(resp) = outcome else {
            panic!("空体上游须直接响应而非转流");
        };
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn llm_empty_e2e_error_status_passthrough_not_502_shape() {
        // T2-E2E：上游 401 非 JSON 体原样透传 401（不吞错转 502 空体）。
        let client = reqwest::Client::new();
        let (url, server) = loopback_server(401, "text/plain", b"unauthorized".to_vec()).await;
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            axum::http::HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            test_ctx(Protocol::Chat),
        )
        .await;
        server.abort();
        let NonstreamOutcome::Responded(resp) = outcome else {
            panic!("401 上游须直接响应");
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
