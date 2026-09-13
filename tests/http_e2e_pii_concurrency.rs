//! T-M3 PII 100 并发 e2e（`veil-review-followup-test-gap` T3.1）：
//! 对标原仓 `pii_concurrency` + `stream_restore_lock`。100 路并发非流
//! chat 请求经网关到回声上游（上游原样回显收到的脱敏体），各路断言
//! 还原本路号码且全矩阵无串扰（下标无冲突）。
//!
//! flaky 隔离策略：失败即加 `#[ignore]` 并在 tasks 登记，不阻塞门禁；
//! 超时预算 120s，mock 回声零外部依赖。

use common::{serve, test_app_router};

mod common;

const CONCURRENCY: usize = 100;

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

fn phone(i: usize) -> String { format!("138{:08}", 1000 + i) }

/// 回声上游：把收到的请求体原文嵌入 chat completion 的 `content` 回显。
async fn mock_upstream_echo() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|body: bytes::Bytes| async move {
            let echoed = String::from_utf8_lossy(&body).into_owned();
            let resp = serde_json::json!({
                "id": "chatcmpl-echo",
                "object": "chat.completion",
                "model": "echo-m",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": echoed},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            });
            (axum::http::StatusCode::OK, axum::Json(resp))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn t3_1_pii_100_concurrent_restore_isolated_no_crosstalk() {
    let (upstream, uhandle) = mock_upstream_echo().await;
    let (base, handle) = serve(test_app_router(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();

    let mut tasks = Vec::with_capacity(CONCURRENCY);
    for i in 0..CONCURRENCY {
        let client = client.clone();
        let base = base.clone();
        let mine = phone(i);
        tasks.push(tokio::spawn(async move {
            let req_body = serde_json::json!({
                "model": "echo-m",
                "messages": [{"role": "user", "content": format!("我的电话是{mine}请记住")}]
            });
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                client
                    .post(format!("{base}/v1/chat/completions"))
                    .header("Content-Type", "application/json")
                    .json(&req_body)
                    .send(),
            )
            .await
            .expect("单路须在 120s 内返回")
            .unwrap();
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap();
            (i, status, text)
        }));
    }
    let mut bodies = vec![String::new(); CONCURRENCY];
    let mut statuses = [0u16; CONCURRENCY];
    for t in tasks {
        let (i, status, text) = t.await.expect("并发任务须成功");
        bodies[i] = text;
        statuses[i] = status;
    }

    // 请求级断言（每路 3 条，共 3×CONCURRENCY）：状态码 200、本路号码已还原、
    // 本路占位符形态已全部还原为号码（合法 `__PII_<seq>_<8hex>__` token 归零；
    // 说明提示中的字面 `__PII_*__` 不属合法形态，不误伤）。
    let pii_token = regex::Regex::new(r"__PII_\d+_[0-9a-fA-F]{8}__").expect("正则恒合法");
    let mut request_assertions = 0usize;
    for (i, body) in bodies.iter().enumerate() {
        assert_eq!(statuses[i], 200, "第 {i} 路须 200");
        request_assertions += 1;
        assert!(
            body.contains(&phone(i)),
            "第 {i} 路须还原本路号码 {}: {body}",
            phone(i)
        );
        request_assertions += 1;
        assert!(
            !pii_token.is_match(body),
            "第 {i} 路占位符须全部还原: {body}"
        );
        request_assertions += 1;
    }
    assert_eq!(
        request_assertions,
        3 * CONCURRENCY,
        "请求级断言数须 ≥3×CONCURRENCY=300"
    );

    // 全对串扰矩阵（100×99 显式计数）：任一路不得含他路号码，自环跳过。
    let mut pair_checks = 0usize;
    for (i, body) in bodies.iter().enumerate() {
        for j in 0..CONCURRENCY {
            if i == j {
                continue;
            }
            pair_checks += 1;
            assert!(
                !body.contains(&phone(j)),
                "第 {i} 路串扰他路号码 {}: {body}",
                phone(j)
            );
        }
    }
    assert_eq!(
        pair_checks,
        CONCURRENCY * (CONCURRENCY - 1),
        "串扰矩阵须覆盖 100×99 全对"
    );

    // 用量计数：100 路并发全部计入，一进一出无遗漏。
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status().as_u16(), 200);
    let metrics_body: serde_json::Value = metrics.json().await.unwrap();
    assert_eq!(
        metrics_body["requests"], 100,
        "100 路并发须全部记录用量: {metrics_body}"
    );

    uhandle.abort();
    handle.abort();
}
