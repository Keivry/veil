//! NLP-6 空体/非 JSON 502 门控边界测试：门控仅对上游 `status == 200` 生效
//! （对齐 Python `_llm.py:3009-3013`），非 200 非错误状态（201/204/304）按原状态码
//! 与正文字节透传，错误状态（`>=400`）走错误体透传。归属拆分：`nonstream/tests.rs`
//! 触 800 红线后按测试外迁模板独立成子模块。

use {
    super::{loopback_server, test_ctx},
    crate::{
        handler::llm::nonstream::{NonstreamOutcome, serve_nonstream},
        service::llm_gateway::{EmptyAction, Protocol, classify_empty},
    },
};

#[tokio::test]
async fn empty_body_gate_boundary() {
    assert_eq!(
        classify_empty(true, 0, false, 200),
        EmptyAction::NonStreamTo502
    );
    for s in [201u16, 204, 304, 400] {
        let expect = if s >= 400 {
            EmptyAction::PassthroughErrorStatus
        } else {
            EmptyAction::PassthroughOk
        };
        assert_eq!(classify_empty(true, 0, false, s), expect, "status={s}");
    }

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
        panic!("200 空体须直接响应而非转流");
    };
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_GATEWAY,
        "200+empty 须 502"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("502 体须可读");
    assert!(String::from_utf8_lossy(&bytes).contains("E_EMPTY_BODY"));

    for status in [201u16, 204, 304] {
        let (url, server) = loopback_server(status, "application/json", vec![]).await;
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
            panic!("{status} 空体须直接响应而非转流");
        };
        assert_eq!(
            resp.status().as_u16(),
            status,
            "{status}+empty 须保留原状态而非 502"
        );
    }

    let (url, server) = loopback_server(400, "application/json", vec![]).await;
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
        panic!("400 空体须直接响应而非转流");
    };
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "400+empty 须错误体透传，不合成 502"
    );
}
