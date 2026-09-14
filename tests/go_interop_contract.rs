//! Go 互操作网关侧契约（`veil-test-coverage-fill` GO/D5）：镜像存量 Go `get`
//! 的请求形状（`FetchCredential` 纯 body、无三因子头），锁定网关侧行为。
//! **真机 Go 闭环仍由 `veil-hardening` 5.1（存量直连全链路）/5.2（三因子
//! 齐全与缺失）/5.3（阻断流终止）承接**；本文件只锁网关侧契约，不冒充该
//! 闭环，且不修改 `veil-hardening` 任何文件。

use {
    common::{serve, test_app, test_app_router},
    std::time::Duration,
};

mod common;

const GET_HASH: &str = "gethash1";
const GET_SECRET: &str = "s3cr3t";

/// POST /credential：可选头 + 纯 JSON body，返回 (状态码, JSON 体)。
async fn cred_post(
    client: &reqwest::Client,
    base: &str,
    headers: &[(&str, &str)],
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let mut req = client
        .post(format!("{base}/credential"))
        .header("Content-Type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = tokio::time::timeout(Duration::from_secs(15), req.json(&body).send())
        .await
        .expect("凭据请求不得挂起")
        .unwrap();
    let status = resp.status().as_u16();
    let value: serde_json::Value = resp.json().await.unwrap();
    (status, value)
}

fn auth_body(caller_hash: &str, caller_path: &str) -> serde_json::Value {
    serde_json::json!({
        "auth": {"caller_hash": caller_hash, "caller_path": caller_path},
        "entry": "网易", "field": "授权码"
    })
}

#[tokio::test]
async fn go_shaped_credential_body_only_rejected() {
    // GO/D5-1（对应 `veil-hardening` 5.1/5.2）：Go `FetchCredential` 纯 body、
    // 不发三因子头 → 403 且错误体为 `{"error":{"code","message"}}` **对象**
    //（`error` 非 string），锁定「Go 不可直接解析」根因契约；
    // 同时锁定 `body.auth.get_binary_hash`/`get_binary_secret` 与 `body.secret`
    // 被采纳为等价头（`auth.rs::effective_*`）的行为。
    let (app, state) = test_app(&[]);
    let (base, handle) = serve(app).await;
    common::enroll_allow(&state, "/srv/go2.sh", "go-h2").await;
    common::enroll_allow(&state, "/srv/go3.sh", "go-h3").await;
    let client = reqwest::Client::new();

    let (status, body) = cred_post(&client, &base, &[], auth_body("go-h1", "/srv/go1.sh")).await;
    assert_eq!(status, 403, "纯 body 无因子须 403: {body}");
    assert!(body["error"].is_object(), "error 须为对象非 string: {body}");
    assert!(!body["error"].is_string(), "error 不得为 string: {body}");
    assert_eq!(body["error"]["code"], "E_AUTH", "{body}");
    assert!(
        body["error"]["message"].is_string(),
        "error.message 须为 string: {body}"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("get_binary_hash"),
        "诊断须指向缺失的三因子字段: {body}"
    );

    // body.auth.* 等价头被采纳：get_binary_hash + get_binary_secret → 放行。
    let (status, body) = cred_post(
        &client,
        &base,
        &[],
        serde_json::json!({
            "auth": {
                "caller_hash": "go-h2",
                "caller_path": "/srv/go2.sh",
                "get_binary_hash": GET_HASH,
                "get_binary_secret": GET_SECRET
            },
            "entry": "网易", "field": "授权码"
        }),
    )
    .await;
    assert_eq!(status, 200, "body.auth 等价头须被采纳: {body}");
    assert_eq!(body["ok"], true, "{body}");

    // body.secret 兼容 + body.auth.get_binary_hash：兼容路径同样放行。
    let (status, body) = cred_post(
        &client,
        &base,
        &[],
        serde_json::json!({
            "secret": GET_SECRET,
            "auth": {
                "caller_hash": "go-h3",
                "caller_path": "/srv/go3.sh",
                "get_binary_hash": GET_HASH
            },
            "entry": "网易", "field": "授权码"
        }),
    )
    .await;
    assert_eq!(status, 200, "body.secret 兼容须被采纳: {body}");
    assert_eq!(body["ok"], true, "{body}");

    handle.abort();
}

#[tokio::test]
async fn go_three_factor_matrix() {
    // GO/D5-2（对应 `veil-hardening` 5.2）：齐全（头体一致）→ 放行；
    // 缺哈希头 / 缺密钥头 / 缺 `body.auth.*` / 冒用 caller_hash==GET_BINARY_HASH
    // 各 → 403 明确诊断；冒用为 `token:false` 原始取用的拒止口径。
    let (app, state) = test_app(&[]);
    let (base, handle) = serve(app).await;
    common::enroll_allow(&state, "/srv/go-m1.sh", "go-m1").await;
    let client = reqwest::Client::new();

    // 齐全（头体一致）→ 放行。
    let (status, body) = cred_post(
        &client,
        &base,
        &[
            ("X-Get-Binary-Hash", GET_HASH),
            ("X-Get-Binary-Secret", GET_SECRET),
        ],
        auth_body("go-m1", "/srv/go-m1.sh"),
    )
    .await;
    assert_eq!(status, 200, "三因子齐全须放行: {body}");
    assert_eq!(body["ok"], true, "{body}");

    // 缺哈希头（仅密钥头 + body.auth）→ 403。
    let (status, body) = cred_post(
        &client,
        &base,
        &[("X-Get-Binary-Secret", GET_SECRET)],
        auth_body("go-m2", "/srv/go-m2.sh"),
    )
    .await;
    assert_eq!(status, 403, "缺哈希头须 403: {body}");
    assert_eq!(body["error"]["code"], "E_AUTH", "{body}");

    // 缺密钥头（仅哈希头 + body.auth）→ 403。
    let (status, body) = cred_post(
        &client,
        &base,
        &[("X-Get-Binary-Hash", GET_HASH)],
        auth_body("go-m3", "/srv/go-m3.sh"),
    )
    .await;
    assert_eq!(status, 403, "缺密钥头须 403: {body}");
    assert_eq!(body["error"]["code"], "E_AUTH", "{body}");

    // 缺 `body.auth.*`（头齐全）→ 403。
    let (status, body) = cred_post(
        &client,
        &base,
        &[
            ("X-Get-Binary-Hash", GET_HASH),
            ("X-Get-Binary-Secret", GET_SECRET),
        ],
        serde_json::json!({"entry": "网易", "field": "授权码"}),
    )
    .await;
    assert_eq!(status, 403, "缺 body.auth.* 须 403: {body}");
    assert_eq!(body["error"]["code"], "E_AUTH", "{body}");

    // 冒用：caller_hash == GET_BINARY_HASH（终端直调/原始取用）→ 403。
    let (status, body) = cred_post(
        &client,
        &base,
        &[
            ("X-Get-Binary-Hash", GET_HASH),
            ("X-Get-Binary-Secret", GET_SECRET),
        ],
        serde_json::json!({
            "auth": {"caller_hash": GET_HASH, "caller_path": "/srv/go-term.sh"},
            "entry": "网易", "field": "授权码", "token": false
        }),
    )
    .await;
    assert_eq!(status, 403, "冒用 get 哈希须 403: {body}");
    assert_eq!(body["error"]["code"], "E_AUTH", "{body}");

    handle.abort();
}

/// 阻断相 mock 上游：chat/anthropic 发危险 tool 流（首分片超小 hold 上限即拒），
/// responses 空流走截断合成 `response.failed`。
async fn mock_upstream_block() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|uri: axum::http::Uri| async move {
            let path = uri.path().to_string();
            if path.ends_with("/chat/completions") {
                let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"exec\",\"arguments\":\"{\\\"command\\\":\\\"rm -rf / --no-preserve-root /tmp/veil-danger\\\"}\"}}]}}]}\n\n\
                            data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"}\"}}]}}]}\n\n\
                            data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
                            data: [DONE]\n\n";
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
            } else if path.ends_with("/v1/messages") {
                let body = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"m\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n\
                            event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"exec\",\"input\":{}}}\n\n\
                            event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"rm -rf / --no-preserve-root\\\"}\"}}\n\n\
                            event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
                            event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":2}}\n\n\
                            event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
            } else if path.ends_with("/v1/responses") {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    "",
                )
            } else {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    "",
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

async fn post_stream(base: &str, path: &str, body: &str) -> String {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}{path}"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{path} 阻断流仍须 200");
    tokio::time::timeout(Duration::from_secs(15), resp.text())
        .await
        .unwrap_or_else(|_| panic!("{path} 阻断流须即时闭合，不得挂起"))
        .unwrap()
}

#[tokio::test]
async fn go_blocked_stream_terminates() {
    // GO/D5-3（对应 `veil-hardening` 5.3）：`AUDIT_MODE=block` + 极小 hold 上限，
    // 三协议阻断/截断均以终止帧即时闭合：chat 恰一 `[DONE]` + `[blocked:`、
    // anthropic `message_stop` + `content_block_stop`、responses `response.failed`；
    // 危险参数零泄漏、无重试/挂起。
    let (upstream, uhandle) = mock_upstream_block().await;
    let (base, handle) = serve(test_app_router(&[
        ("LLM_UPSTREAM", upstream.as_str()),
        ("AUDIT_MODE", "block"),
        ("AUDIT_HOLD_MAX_BYTES", "16"),
    ]))
    .await;

    let chat = post_stream(
        &base,
        "/v1/chat/completions",
        "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"run\"}],\"stream\":true}",
    )
    .await;
    assert!(
        chat.contains("[blocked:"),
        "chat 阻断帧须含 [blocked:: {chat}"
    );
    assert_eq!(
        chat.matches("data: [DONE]").count(),
        1,
        "chat 阻断须恰一 [DONE]: {chat}"
    );
    assert!(!chat.contains("rm -rf"), "chat 危险参数不得泄漏: {chat}");
    assert!(
        !chat.contains("call_1") && !chat.contains("exec"),
        "chat 工具名/调用 id 不得泄漏: {chat}"
    );

    let anth = post_stream(
        &base,
        "/v1/messages",
        "{\"model\":\"m\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"run\"}],\"stream\":true}",
    )
    .await;
    assert_eq!(
        anth.matches("\"type\":\"message_stop\"").count(),
        1,
        "anthropic 阻断须恰一 message_stop: {anth}"
    );
    assert!(
        anth.contains("content_block_stop"),
        "anthropic 阻断须含 content_block_stop: {anth}"
    );
    assert!(
        !anth.contains("rm -rf"),
        "anthropic 危险参数不得泄漏: {anth}"
    );

    let resp = post_stream(
        &base,
        "/v1/responses",
        "{\"model\":\"m\",\"input\":\"run\",\"stream\":true}",
    )
    .await;
    assert_eq!(
        resp.matches("\"type\":\"response.failed\"").count(),
        1,
        "responses 截断须恰一 failed: {resp}"
    );
    assert!(
        !resp.contains("response.completed"),
        "responses 不得伪造完成: {resp}"
    );

    uhandle.abort();
    handle.abort();
}
