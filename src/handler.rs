use {
    crate::{
        error::{Result, VeilError},
        service::{self, AuthBlock, CredentialBody, CredentialHeaders},
        state::AppState,
    },
    axum::{
        Json,
        body::Body,
        extract::{Request, State},
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
};

pub async fn health_handler(State(state): State<AppState>) -> Json<Value> {
    let health = service::health_status(&state);
    Json(json!({
        "ok": true,
        "sqlite_ok": health.sqlite_ok,
        "sqlite_error": health.sqlite_error,
    }))
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn credential_headers(headers: &HeaderMap) -> CredentialHeaders {
    CredentialHeaders::new(
        header_str(headers, "x-get-binary-hash"),
        header_str(headers, "x-get-binary-secret"),
    )
}

pub async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CredentialBody>,
) -> Result<Json<Value>> {
    let payload = service::handle_credential(&state, &credential_headers(&headers), &body).await?;
    Ok(Json(json!({ "ok": true, "credential": payload })))
}

pub async fn registrations_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let views = service::list_registrations(
        &state,
        header_str(&headers, "x-admin-token").as_deref(),
        header_str(&headers, "x-get-binary-secret").as_deref(),
    )
    .await?;
    Ok(Json(json!({ "ok": true, "registrations": views })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterBody {
    #[serde(default)]
    pub caller_path: String,
    #[serde(default)]
    pub caller_hash: String,
    #[serde(default)]
    pub source: Option<String>,
}

pub async fn register_caller_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Result<Json<Value>> {
    let source = body
        .source
        .clone()
        .or_else(|| header_str(&headers, "x-source").or_else(|| Some("unknown".to_string())));
    let view = service::register_caller(
        &state,
        &body.caller_path,
        &body.caller_hash,
        source.as_deref().unwrap_or("unknown"),
    )
    .await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeBody {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub caller_hash: Option<String>,
}

fn revoke_key(body: &RevokeBody) -> Result<String> {
    body.key
        .clone()
        .or_else(|| body.caller_path.clone())
        .or_else(|| body.caller_hash.clone())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| VeilError::BadRequest {
            message: "key/caller_path/caller_hash 三选一必填".to_string(),
        })
}

pub async fn revoke_handler(
    State(state): State<AppState>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<Value>> {
    let view = service::revoke_caller(&state, &revoke_key(&body)?).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmergencyRevokeBody {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub caller_hash: Option<String>,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub file_present: bool,
}

pub async fn emergency_revoke_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EmergencyRevokeBody>,
) -> Result<Json<Value>> {
    let key = revoke_key(&RevokeBody {
        key: body.key.clone(),
        caller_path: body.caller_path.clone(),
        caller_hash: body.caller_hash.clone(),
    })?;
    let admin_token = body
        .admin_token
        .clone()
        .or_else(|| header_str(&headers, "x-admin-token"));
    let view = service::emergency_revoke(
        &state,
        &key,
        admin_token.as_deref(),
        body.source.as_deref(),
        body.file_present,
    )
    .await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproveHashChangeBody {
    #[serde(default)]
    pub caller_path: String,
    #[serde(default)]
    pub new_hash: String,
}

pub async fn approve_hash_change_handler(
    State(state): State<AppState>,
    Json(body): Json<ApproveHashChangeBody>,
) -> Result<Json<Value>> {
    let view = service::approve_hash_change(&state, &body.caller_path, &body.new_hash).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialRequestBody {
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthBlock>,
}

pub async fn llm_proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let outcome = tokio::spawn(async move {
        let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
            .await
            .unwrap_or_default()
            .to_vec();
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

async fn gateway_serve(
    state: &AppState,
    parts: &mut axum::http::request::Parts,
    path: &str,
    mut body_bytes: Vec<u8>,
) -> Response {
    use {
        crate::{
            approval::PendingRecord,
            config::AuditMode,
            service::{
                audit::{self, AuditPolicy},
                audit_hold::AuditHold,
                block_inject,
                llm_gateway::{
                    self,
                    Protocol,
                    classify_empty,
                    extract_usage_nonstream,
                    is_stream_body,
                    resolve_protocol,
                    resolve_upstream,
                },
                redaction::Scope,
                sse::{Speed, SseParser, StreamMeta, set_truncated},
            },
        },
        bytes::Bytes,
    };
    let req_start = std::time::Instant::now();

    let ct = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let protocol = resolve_protocol(path, ct.as_deref(), Some(&state.gateway_metrics));
    let is_chat = protocol != Protocol::NonDialog;
    let upstream_base = match resolve_upstream(&state.config, None) {
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
    let client = reqwest::Client::builder()
        .gzip(llm_gateway::DECODE_ENABLED)
        .brotli(llm_gateway::DECODE_ENABLED)
        .deflate(llm_gateway::DECODE_ENABLED)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let scope = Scope::new();
    let upstream_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    if !is_chat {
        let mut fwd_headers = parts.headers.clone();
        fwd_headers.remove(header::HOST);
        fwd_headers.remove(header::CONTENT_LENGTH);
        fwd_headers.remove(header::CONTENT_ENCODING);
        llm_gateway::filter_hop_headers(&mut fwd_headers);
        match llm_gateway::fetch_upstream_with_retry(
            &client,
            upstream_method,
            &url,
            fwd_headers,
            body_bytes,
        )
        .await
        {
            Ok(up) => {
                let status =
                    StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
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
                llm_gateway::filter_hop_headers(&mut resp_headers);
                for (k, v) in resp_headers.iter() {
                    builder = builder.header(k, v);
                }
                builder
                    .body(Body::from_stream(up.bytes_stream()))
                    .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
            }
            Err(_) => (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
            )
                .into_response(),
        }
    } else {
        let original_valid = std::str::from_utf8(&body_bytes).is_ok();
        let original_text = String::from_utf8_lossy(&body_bytes).into_owned();
        let mut body_value: Option<Value> = serde_json::from_slice(&body_bytes).ok();
        let stream_flag = body_value.as_ref().is_some_and(is_stream_body);
        let mut normalized_out = false;
        let mut redacted_text = original_text.clone();
        if llm_gateway::should_inject_placeholders(
            true,
            state.config.redaction_enabled,
            !body_bytes.is_empty(),
        ) {
            let vault = crate::service::credential_vault::CredentialVault::new();
            let detector = crate::service::pii::PiiDetector::new();
            redacted_text = scope
                .redact_request(&vault, &detector, &original_text)
                .await;
        }
        let need_inject = body_value
            .as_ref()
            .is_some_and(|v| llm_gateway::should_inject_stream_options(protocol, v));
        if need_inject {
            normalized_out = state.config.normalize_json_whitespace;
            if let Ok(mut v) = serde_json::from_str::<Value>(&redacted_text) {
                llm_gateway::inject_stream_options(&mut v);
                body_value = Some(v);
                body_bytes = serde_json::to_vec(body_value.as_ref().expect("刚注入的请求体"))
                    .unwrap_or_default();
            } else if let Some(v) = body_value.as_ref() {
                body_bytes = serde_json::to_vec(v).unwrap_or_default();
            }
        } else if redacted_text != original_text && original_valid {
            body_bytes = redacted_text.into_bytes();
        } else if state.config.normalize_json_whitespace
            && let Some(v) = body_value.as_ref()
        {
            body_bytes = serde_json::to_vec(v).unwrap_or_default();
            normalized_out = true;
        }
        let mut fwd_headers = parts.headers.clone();
        fwd_headers.remove(header::HOST);
        fwd_headers.remove(header::CONTENT_LENGTH);
        fwd_headers.remove(header::CONTENT_ENCODING);
        let dialog_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::POST);
        let up = match llm_gateway::fetch_upstream_with_retry(
            &client,
            dialog_method,
            &url,
            fwd_headers,
            body_bytes,
        )
        .await
        {
            Ok(up) => up,
            Err(_) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
                )
                    .into_response();
            }
        };
        let status_u16 = up.status().as_u16();
        if status_u16 == 502 || status_u16 == 401 {
            let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
            let bytes = up.bytes().await.unwrap_or_default();
            return (status, bytes.to_vec()).into_response();
        }
        let resp_ct = up
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let looks_sse = resp_ct.contains("text/event-stream") || stream_flag;
        if !looks_sse {
            let bytes = up.bytes().await.unwrap_or_default();
            let is_json = serde_json::from_slice::<Value>(&bytes).is_ok();
            if classify_empty(true, false, bytes.len(), is_json, status_u16)
                == crate::service::llm_gateway::EmptyAction::NonStreamTo502
            {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
                )
                    .into_response();
            }
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                let usage = extract_usage_nonstream(protocol, &v);
                state.admin.metrics.record_chat(
                    protocol,
                    req_start.elapsed().as_millis() as u64,
                    usage.as_ref(),
                    None,
                    state.sqlite_ok(),
                    now_secs(),
                );
                let text = String::from_utf8_lossy(&bytes).into_owned();
                let vault = crate::service::credential_vault::CredentialVault::new();
                let restored = scope.restore_response(&vault, &text);
                let mut resp = (
                    StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
                    restored,
                )
                    .into_response();
                if normalized_out {
                    resp.headers_mut().insert(
                        "x-veil-normalized",
                        header::HeaderValue::from_static("json-whitespace"),
                    );
                }
                resp.headers_mut().insert(
                    "x-veil-protocol",
                    header::HeaderValue::from_static(match protocol {
                        Protocol::Chat => "chat",
                        Protocol::Anthropic => "anthropic",
                        Protocol::Responses => "responses",
                        Protocol::NonDialog => "passthrough",
                    }),
                );
                return resp;
            }
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
            )
                .into_response();
        }
        let speed = if resp_ct.contains("fast") {
            Speed::Fast
        } else {
            Speed::Slow
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
        let keepalive = crate::service::audit_hold::RequestKeepalive::spawn(tx.clone());
        let metrics = state.gateway_metrics.clone();
        let admin_metrics = state.admin.metrics.clone();
        let sqlite_precise = state.sqlite_ok();
        let hold_max = state.config.audit_hold_max_bytes.max(1) as usize;
        let audit_mode = state.config.audit_mode;
        let audit_pending = state.pending.clone();
        let audit_policy = match state.config.audit_policy_file.clone() {
            Some(path) => match AuditPolicy::load_from_file(Some(path.as_path())) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!("审计策略文件加载失败，使用默认策略: {err}");
                    AuditPolicy::default_policy()
                }
            },
            None => AuditPolicy::default_policy(),
        };
        let mut upstream = up;
        let pump_tx = tx.clone();
        tokio::spawn(async move {
            let _keep = keepalive;
            let mut parser = SseParser::new();
            let mut hold = AuditHold::new(hold_max);
            let mut meta = StreamMeta::default();
            let mut forwarded: usize = 0;
            let mut agg = String::new();
            let mut terminated = false;
            let mut rejected_sticky = false;
            let mut block_injected = false;
            while let Ok(chunk) = upstream.chunk().await {
                let bytes = match chunk {
                    Some(b) => b,
                    None => break,
                };
                if bytes.is_empty() {
                    continue;
                }
                for ev in parser.push_bytes(&bytes) {
                    if ev.is_comment_only {
                        let _ = pump_tx
                            .send(format!(":{}\n\n", ev.comments.join("\n:")))
                            .await;
                        continue;
                    }
                    if rejected_sticky {
                        let trimmed = ev.data.trim();
                        if trimmed == "[DONE]" {
                            continue;
                        }
                        if !ev.data.is_empty() {
                            let terminal = match protocol {
                                Protocol::Anthropic => {
                                    ev.data.contains("content_block_stop")
                                        || ev.data.contains("message_delta")
                                        || ev.data.contains("message_stop")
                                }
                                Protocol::Responses => ev.data.contains("response.completed"),
                                _ => false,
                            };
                            if terminal {
                                continue;
                            }
                        }
                        if !ev.data.is_empty()
                            && ev.data.trim() != "[DONE]"
                            && let Ok(v) = serde_json::from_str::<Value>(&ev.data)
                            && (!extract_tool_fragments(protocol, &v).is_empty()
                                || AuditHold::is_complete_event(&v))
                        {
                            continue;
                        }
                    }
                    if !ev.data.is_empty() && ev.data.trim() != "[DONE]" {
                        if let Ok(v) = serde_json::from_str::<Value>(&ev.data) {
                            let frags = extract_tool_fragments(protocol, &v);
                            let is_tool_event = !frags.is_empty();
                            if rejected_sticky && is_tool_event {
                                continue;
                            }
                            let mut reject_reason: Option<String> = None;
                            for frag in frags {
                                if hold.push_fragment(
                                    frag.0,
                                    frag.1.as_deref(),
                                    frag.2.as_deref(),
                                    &frag.3,
                                ) == crate::service::audit_hold::HoldVerdict::Rejected
                                {
                                    reject_reason = Some("audit-hold-overflow".to_string());
                                    break;
                                }
                            }
                            let mut approve_held = false;
                            if reject_reason.is_none()
                                && !hold.is_rejected()
                                && AuditHold::is_complete_event(&v)
                                && !matches!(audit_mode, AuditMode::Off)
                            {
                                for (idx, name, args) in hold.tool_triples() {
                                    match audit::evaluate(audit_mode, &name, &args, &audit_policy) {
                                        audit::AuditVerdict::Block { .. } => {
                                            hold.mark_rejected();
                                            reject_reason = Some("audit-policy-block".to_string());
                                            break;
                                        }
                                        audit::AuditVerdict::NeedApproval { reason, summary } => {
                                            audit_pending.insert(PendingRecord::new(
                                                &format!("audit-hold-{idx}-{name}"),
                                                &format!("{reason}: {summary}"),
                                            ));
                                            approve_held = true;
                                        }
                                        audit::AuditVerdict::Allow => {}
                                    }
                                }
                            }
                            if let Some(reason) = reject_reason {
                                rejected_sticky = true;
                                agg.clear();
                                if !block_injected {
                                    block_injected = true;
                                    for f in block_inject::ensure_event_lines(match protocol {
                                        Protocol::Chat => block_inject::chat_block_frames(&reason),
                                        Protocol::Anthropic => {
                                            block_inject::anthropic_block_frames(&reason)
                                        }
                                        Protocol::Responses => {
                                            block_inject::responses_block_frames("r-block")
                                        }
                                        Protocol::NonDialog => vec![],
                                    }) {
                                        let _ = pump_tx.send(f).await;
                                    }
                                    block_inject::mark_terminal(&mut meta);
                                }
                                if is_tool_event || AuditHold::is_complete_event(&v) {
                                    continue;
                                }
                            } else if AuditHold::is_complete_event(&v) && !approve_held {
                                hold.mark_completed();
                            }
                            let restored_data =
                                crate::service::sse::json_aware_line(&ev.data, |s| s);
                            let prefix = ev
                                .event_type
                                .as_ref()
                                .map(|t| format!("event: {t}\n"))
                                .unwrap_or_default();
                            agg.push_str(&prefix);
                            agg.push_str(&format!("data: {restored_data}\n\n"));
                            if hold.held() && !restored_data.is_empty() {
                                continue;
                            }
                        } else {
                            let prefix = ev
                                .event_type
                                .as_ref()
                                .map(|t| format!("event: {t}\n"))
                                .unwrap_or_default();
                            agg.push_str(&prefix);
                            agg.push_str(&format!("data: {}\n\n", ev.data));
                        }
                    } else {
                        let prefix = ev
                            .event_type
                            .as_ref()
                            .map(|t| format!("event: {t}\n"))
                            .unwrap_or_default();
                        if ev.data.trim() == "[DONE]" {
                            agg.push_str(&format!("{prefix}data: [DONE]\n\n"));
                        } else {
                            agg.push_str(&format!("{prefix}data: {}\n\n", ev.data));
                        }
                    }
                    if let Some(out) = crate::service::sse::select_emit(&mut agg, speed) {
                        metrics.add_sse_event();
                        forwarded += 1;
                        if pump_tx.send(out).await.is_err() {
                            break;
                        }
                    }
                }
                if terminated {
                    break;
                }
            }
            if !agg.is_empty() {
                metrics.add_sse_event();
                let _ = pump_tx.send(std::mem::take(&mut agg)).await;
                forwarded += 1;
            }
            let residual = parser.residual_json_aware();
            if !residual.is_empty() {
                let _ = pump_tx.send(format!("data: {residual}\n\n")).await;
            }
            if forwarded == 0 && !block_injected {
                for f in block_inject::ensure_event_lines(match protocol {
                    Protocol::Chat => block_inject::chat_block_frames("empty-stream"),
                    Protocol::Anthropic => block_inject::anthropic_block_frames("empty-stream"),
                    Protocol::Responses => block_inject::responses_truncated_frames("r-empty"),
                    Protocol::NonDialog => vec![],
                }) {
                    let _ = pump_tx.send(f).await;
                }
                if protocol == Protocol::Chat {
                    let _ = pump_tx.send("data: [DONE]\n\n".to_string()).await;
                }
                let _ = set_truncated(
                    &mut meta,
                    protocol,
                    if protocol == Protocol::Responses {
                        crate::service::sse::TruncatedMode::SynthesizedFailed
                    } else {
                        crate::service::sse::TruncatedMode::OpenEnded
                    },
                    Some(&metrics),
                );
                block_inject::mark_terminal(&mut meta);
                terminated = true;
            }
            let _ = terminated;
            admin_metrics.record_chat(
                protocol,
                req_start.elapsed().as_millis() as u64,
                None,
                meta.truncated_mode.as_ref().map(|m| m.as_str()),
                sqlite_precise,
                now_secs(),
            );
        });
        let stream = async_stream::stream! {
            let mut rx = rx;
            while let Some(msg) = rx.recv().await {
                yield Ok::<_, anyhow::Error>(Bytes::from(msg));
            }
        };
        let mut stream_builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache");
        if normalized_out {
            stream_builder = stream_builder.header("x-veil-normalized", "json-whitespace");
        }
        stream_builder
            .header("X-Accel-Buffering", "no")
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "stream").into_response())
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn extract_tool_fragments(
    protocol: crate::service::llm_gateway::Protocol,
    v: &Value,
) -> Vec<(u32, Option<String>, Option<String>, String)> {
    use crate::service::llm_gateway::Protocol as P;
    let mut out = Vec::new();
    match protocol {
        P::Chat => {
            if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
                for ch in choices {
                    if let Some(delta) = ch.get("delta").or_else(|| ch.get("message"))
                        && let Some(calls) = delta.get("tool_calls").and_then(|c| c.as_array())
                    {
                        for (i, call) in calls.iter().enumerate() {
                            let idx = call
                                .get("index")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(i as u64) as u32;
                            let id = call
                                .get("id")
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string());
                            let name = call
                                .get("function")
                                .and_then(|f| f.get("name"))
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string());
                            let args = call
                                .get("function")
                                .and_then(|f| f.get("arguments"))
                                .map(|a| {
                                    if let Some(s) = a.as_str() {
                                        s.to_string()
                                    } else {
                                        a.to_string()
                                    }
                                })
                                .unwrap_or_default();
                            out.push((idx, id, name, args));
                        }
                    }
                }
            }
        }
        P::Anthropic => {
            if let Some(block) = v.get("content_block").or_else(|| v.get("delta")) {
                let name = block
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let id = block
                    .get("id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let args = block
                    .get("partial_json")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                if name.is_some() || !args.is_empty() {
                    out.push((0, id, name, args));
                }
            }
        }
        P::Responses => {
            let ev_type = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            if ev_type.contains("function_call_arguments") {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let id = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                let name = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                if ev_type.ends_with(".delta") {
                    let delta = v
                        .get("delta")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !delta.is_empty() || name.is_some() {
                        out.push((idx, id, name, delta));
                    }
                } else if ev_type.ends_with(".done") {
                    let args = v
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    if !args.is_empty() || name.is_some() {
                        out.push((idx, id, name, args));
                    }
                }
                return out;
            }
            if ev_type.contains("output_text") {
                return out;
            }
            if ev_type == "response.output_item.done"
                && let Some(item) = v.get("item")
                && item.get("type").and_then(|x| x.as_str()) == Some("function_call")
            {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let args = item
                    .get("arguments")
                    .map(|a| {
                        if let Some(s) = a.as_str() {
                            s.to_string()
                        } else {
                            a.to_string()
                        }
                    })
                    .unwrap_or_default();
                let name = item
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let id = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                if !args.is_empty() || name.is_some() {
                    out.push((idx, id, name, args));
                }
                return out;
            }
            if v.get("item").is_some() {
                return out;
            }
            if let Some(output) = v.get("output").and_then(|o| o.as_array()) {
                for (i, item) in output.iter().enumerate() {
                    let args = item
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    let name = item
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let id = item
                        .get("id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    if !args.is_empty() || name.is_some() {
                        out.push((i as u32, id, name, args));
                    }
                }
            }
        }
        P::NonDialog => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{config::Config, state::SqliteOutcome},
        std::{collections::HashMap, path::PathBuf},
    };

    #[tokio::test]
    async fn 健康处理器透出服务层状态() {
        let env = HashMap::from([
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
        ]);
        let state = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: false,
            },
        );
        let Json(body) = health_handler(State(state)).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["sqlite_ok"], true);
    }
}
