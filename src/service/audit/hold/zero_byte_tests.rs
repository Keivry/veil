//! 同 index 零字节分片洪泛的 pending 记账测试（触 800 红线后按 `keepalive_tests`
//! 模板独立成子模块；实现体仍留 `hold.rs`，用例语义不变）。

use super::*;

#[tokio::test]
async fn pending_tool_frames_same_index_zero_byte_flood_bounded() {
    use crate::handler::llm::pump::{RequestCtx, StreamPumpCtx, spawn_stream_pump};
    // C-3/D1（5.4）+ 11.4：上游对**同一 index** 持续发零字节 tool 分片洪泛——
    // `pending_tool_frames` 条目与字节双维度须独立有界，超限走
    // `reject_reason="audit-hold-overflow"` fail-closed 阻断臂（不静默丢弃）。
    // (1) 条目维度独立计数：零字节不增聚合条目/字节，聚合维度恒放行，独立计数器仍受
    // `AUDIT_HOLD_MAX_ENTRIES` 约束。
    let key = AuditHold::responses_key(Some("call-0"), 0);
    let mut entries = AuditHold::new(1 << 30);
    for seq in 0..AUDIT_HOLD_MAX_ENTRIES as u64 {
        assert_eq!(
            entries.push_responses_fragment(&key, 0, Some(seq), Some("call-0"), Some("run"), ""),
            HoldVerdict::Approved,
            "同槽零字节分片不增聚合条目，聚合维度不得先行拒绝"
        );
        assert_eq!(
            entries.account_pending_frame(0),
            HoldVerdict::Approved,
            "未达条目上限不得拒绝"
        );
    }
    assert_eq!(entries.pending_accounting(), (AUDIT_HOLD_MAX_ENTRIES, 0));
    assert_eq!(
        entries.account_pending_frame(0),
        HoldVerdict::Rejected,
        "条目超限须 fail-closed（第 {} 帧）",
        AUDIT_HOLD_MAX_ENTRIES + 1
    );
    assert!(entries.is_rejected());
    assert_eq!(entries.pending_accounting(), (0, 0), "清仓须归零双维度");
    // (2) 字节维度独立计数：恰达上限放行、超限拒绝；出账归还后长流不误判。
    let mut bytes = AuditHold::new(64);
    assert_eq!(bytes.account_pending_frame(64), HoldVerdict::Approved);
    assert_eq!(bytes.account_pending_frame(1), HoldVerdict::Rejected);
    let mut reclaim = AuditHold::new(64);
    for _ in 0..100 {
        assert_eq!(reclaim.account_pending_frame(64), HoldVerdict::Approved);
        reclaim.release_pending_frames(1, 64);
    }
    assert!(!reclaim.is_rejected(), "出账归还后长流不得误判溢出");
    // (3) e2e 判别力：真实泵路径（push 前记账缺失则无阻断、无粘滞抑制）。
    let flood = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-0\",\"type\":\"function\",\"function\":{\"name\":\"run\",\"arguments\":\"\"}}]}}]}\n\n";
    let sse = flood.repeat(64).into_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        sse.len()
    );
    let server = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&sse).await;
            let _ = sock.shutdown().await;
        }
    });
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let ctx = StreamPumpCtx {
        req: RequestCtx {
            protocol: crate::service::llm_gateway::Protocol::Chat,
            scope: Arc::new(crate::service::redaction::Scope::new()),
            vault: Arc::new(crate::service::credential_vault::CredentialVault::new()),
            detector: Arc::new(crate::service::pii::PiiDetector::new()),
            audit_mode: crate::config::AuditMode::Block,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: crate::service::audit::AuditSink::test_arc(),
            gateway_metrics: Arc::new(crate::service::llm_gateway::GatewayMetrics::default()),
            admin_metrics: Arc::new(crate::service::metrics::MetricsStore::new(
                std::path::PathBuf::from("/tmp/veil-hold-flood.sqlite"),
            )),
            sqlite_precise: false,
            req_start: std::time::Instant::now(),
            pending: Arc::new(crate::approval::PendingApprovals::default()),
            normalized_out: false,
        },
        hold_max: 512,
        pii_boundary_chars: 0,
        init_conv: None,
        req_model: String::new(),
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let outcome = spawn_stream_pump(upstream, tx, ctx)
        .await
        .expect("流泵任务不得崩");
    server.abort();
    let mut frames = Vec::new();
    while let Some(f) = rx.recv().await {
        frames.push(f);
    }
    let joined = frames.join("");
    assert!(
        outcome.block_injected,
        "同 index 零字节洪泛超限须 fail-closed 阻断: {joined}"
    );
    assert!(
        joined.contains("audit-hold-overflow"),
        "阻断原因须为 audit-hold-overflow: {joined}"
    );
    assert_eq!(
        joined.matches("[blocked:").count(),
        1,
        "阻断帧恰一: {joined}"
    );
}
