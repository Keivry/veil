//! T2/T10 测试：非流上游响应头透传（逐跳过滤 + `x-veil-*` 覆盖）与
//! 网关生成响应统一 `x-veil-protocol`。归属拆分：`nonstream/tests.rs` 触
//! 800 红线后按测试外迁模板独立成子模块。

use {
    super::test_ctx,
    crate::{
        handler::llm::nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        service::llm_gateway::Protocol,
    },
    axum::http::StatusCode,
};

/// 原始 TCP 上游：可按需附带任意响应头；带 `transfer-encoding` 时按 chunked
/// 帧投递（不写 `content-length`），其余按 `content-length` 定长投递。
async fn loopback_raw(
    status: u16,
    headers: &[(&str, &str)],
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
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    };
    let chunked = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    if !chunked {
        head.push_str(&format!("content-length: {}\r\n", body.len()));
    }
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let mut wire = head.into_bytes();
    if chunked {
        wire.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        wire.extend_from_slice(&body);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
    } else {
        wire.extend_from_slice(&body);
    }
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            if sock.write_all(&wire).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

fn ctx_with_cap(protocol: Protocol, cap: usize) -> NonstreamCtx {
    NonstreamCtx {
        nonstream_max_bytes: cap,
        ..test_ctx(protocol)
    }
}

fn header_of(resp: &axum::http::Response<axum::body::Body>, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[tokio::test]
async fn nonstream_upstream_headers_forwarded() {
    // T2.1：200 `application/json` 的 content-type 保留；429 透传
    // `retry-after: 30` 与 `x-request-id`，不再被框架默认类型覆盖。
    let client = reqwest::Client::new();
    let json_body = br#"{"id":"x","model":"m","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_raw(
        200,
        &[
            ("content-type", "application/json"),
            ("x-request-id", "req-200"),
        ],
        json_body,
    )
    .await;
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
        panic!("JSON 上游须直接响应");
    };
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header_of(&resp, "content-type").as_deref(),
        Some("application/json"),
        "上游 content-type 须保留（不得被强制 text/plain）"
    );
    assert_eq!(
        header_of(&resp, "x-request-id").as_deref(),
        Some("req-200"),
        "上游诊断头须转发"
    );

    let (url, server) = loopback_raw(
        429,
        &[
            ("content-type", "text/plain"),
            ("retry-after", "30"),
            ("x-request-id", "req-429"),
        ],
        b"slow down".to_vec(),
    )
    .await;
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
        panic!("非 JSON 错误体须直接响应");
    };
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        header_of(&resp, "content-type").as_deref(),
        Some("text/plain"),
        "上游 text/plain 须保留（不得被改写 octet-stream）"
    );
    assert_eq!(
        header_of(&resp, "retry-after").as_deref(),
        Some("30"),
        "retry-after 须透传"
    );
    assert_eq!(
        header_of(&resp, "x-request-id").as_deref(),
        Some("req-429"),
        "x-request-id 须透传"
    );
}

#[tokio::test]
async fn nonstream_hop_filtered_and_veil_override() {
    // T2.2：上游 `connection`/`transfer-encoding` 不入下游；上游自带
    // `x-veil-protocol` 不得覆盖网关派生值。
    let client = reqwest::Client::new();
    let body = br#"{"id":"x","model":"m","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_raw(
        200,
        &[
            ("content-type", "application/json"),
            ("connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("x-veil-protocol", "hijack"),
        ],
        body,
    )
    .await;
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
        panic!("JSON 上游须直接响应");
    };
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        header_of(&resp, "connection").is_none(),
        "逐跳头 connection 不得转发"
    );
    assert!(
        header_of(&resp, "transfer-encoding").is_none(),
        "逐跳头 transfer-encoding 不得转发"
    );
    assert_eq!(
        header_of(&resp, "x-veil-protocol").as_deref(),
        Some("chat"),
        "网关派生 x-veil-protocol 须覆盖上游同名头"
    );
}

#[tokio::test]
async fn nonstream_error_response_has_protocol_header() {
    // T10：429 透传响应含对应协议头。
    let client = reqwest::Client::new();
    let (url, server) = loopback_raw(
        429,
        &[("content-type", "text/plain")],
        b"rate limited".to_vec(),
    )
    .await;
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
        panic!("非 JSON 错误体须直接响应");
    };
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        header_of(&resp, "x-veil-protocol").as_deref(),
        Some("chat"),
        "429 透传须携带协议头"
    );
}

#[tokio::test]
async fn nonstream_502_responses_have_protocol_header() {
    // T10：超限 502 与空体 502 均含对应协议头。
    let client = reqwest::Client::new();
    let big = vec![b'y'; 64];
    let (url, server) = loopback_raw(200, &[("content-type", "application/json")], big).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx_with_cap(Protocol::Chat, 1),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("超限须直接响应");
    };
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        header_of(&resp, "x-veil-protocol").as_deref(),
        Some("chat"),
        "超限 502 须携带协议头"
    );

    let (url, server) =
        loopback_raw(200, &[("content-type", "application/json")], Vec::new()).await;
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
        panic!("空体须直接响应");
    };
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        header_of(&resp, "x-veil-protocol").as_deref(),
        Some("chat"),
        "空体 502 须携带协议头"
    );
}

#[tokio::test]
async fn protocol_header_matrix_nonstream() {
    // T10：Chat/Anthropic/Responses 的错误与超限响应各自携带正确协议值，不互串。
    let client = reqwest::Client::new();
    let cases = [
        (Protocol::Chat, "chat"),
        (Protocol::Anthropic, "anthropic"),
        (Protocol::Responses, "responses"),
    ];
    for (protocol, want) in cases {
        let (url, server) = loopback_raw(
            429,
            &[("content-type", "text/plain")],
            b"rate limited".to_vec(),
        )
        .await;
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            axum::http::HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            test_ctx(protocol),
        )
        .await;
        server.abort();
        let NonstreamOutcome::Responded(resp) = outcome else {
            panic!("{protocol:?} 错误体须直接响应");
        };
        assert_eq!(
            header_of(&resp, "x-veil-protocol").as_deref(),
            Some(want),
            "{protocol:?} 错误响应协议头须为 {want}"
        );

        let (url, server) =
            loopback_raw(200, &[("content-type", "text/plain")], vec![b'z'; 64]).await;
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            axum::http::HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            ctx_with_cap(protocol, 1),
        )
        .await;
        server.abort();
        let NonstreamOutcome::Responded(resp) = outcome else {
            panic!("{protocol:?} 超限须直接响应");
        };
        assert_eq!(
            header_of(&resp, "x-veil-protocol").as_deref(),
            Some(want),
            "{protocol:?} 超限响应协议头须为 {want}"
        );
    }
}
