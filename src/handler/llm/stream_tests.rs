//! 流泵集成单测（D2 自 `mod.rs` 拆出；`#[cfg(test)]` 门控，见 `mod.rs` 声明）。
//!
//! 触 800 行上限后按仓库测试外迁模板拆分子模块（`tool_fragments_tests`/
//! `transport_tests`/`terminal_tests`/`vacuum_tests`/`passthrough_tests`）；
//! 共享辅助（`fresh_arcs`/`pump_ctx`/回环服务器/`collect_pump`）仍留本文件，
//! 供兄弟模块复用，测试名与断言不变。

use {
    super::pump::{PumpOutcome, RequestCtx, StreamPumpCtx, spawn_stream_pump},
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    std::{sync::Arc, time::Instant},
};

mod passthrough_tests;
mod terminal_tests;
mod tool_fragments_tests;
mod transport_tests;
mod vacuum_tests;

pub(super) fn fresh_arcs() -> (Arc<Scope>, Arc<CredentialVault>, Arc<PiiDetector>) {
    (
        Arc::new(Scope::new()),
        Arc::new(CredentialVault::new()),
        Arc::new(PiiDetector::new()),
    )
}

pub(super) fn pump_ctx(
    protocol: Protocol,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
) -> StreamPumpCtx {
    StreamPumpCtx {
        req: RequestCtx {
            protocol,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Off,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: crate::service::audit::AuditSink::test_arc(),
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            pending: Arc::new(PendingApprovals::default()),
            normalized_out: false,
            redact_only: false,
        },
        hold_max: 1_048_576,
        pii_boundary_chars: 64,
        init_conv: None,
        req_model: String::new(),
    }
}

/// 回环上游：固定状态码/内容类型/体，供流泵回放单测（无外网依赖）。
pub(super) async fn loopback_server(
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

/// 中途传输错误上游：声明 `content-length` 大于实际写入体后关闭连接，
/// 触发 reqwest `chunk()` 返回 `Err`（S5/D5 观测回归用）。
pub(super) async fn broken_body_server(
    content_type: &str,
    declared_len: usize,
    body: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {declared_len}\r\nconnection: close\r\n\r\n"
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
            let _ = sock.write_all(&body).await;
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

/// R8-06 回归上游：以 chunked 编码发送一次体后**保持连接不关闭**（不发送终止
/// chunk），模拟「上游发终端帧后不 EOF」；调用方 SHALL 以超时保护等待泵闭合。
pub(super) async fn loopback_server_hold_open(
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
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
    );
    let chunk_head = format!("{:x}\r\n", body.len());
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            if sock.write_all(head.as_bytes()).await.is_err()
                || sock.write_all(chunk_head.as_bytes()).await.is_err()
                || sock.write_all(&body).await.is_err()
                || sock.write_all(b"\r\n").await.is_err()
                || sock.flush().await.is_err()
            {
                continue;
            }
            // 不发送终止 chunk：保持连接打开，模拟上游不 EOF。
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
    (url, handle)
}

pub(super) async fn collect_pump(
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
