//! 管理面鉴权全矩阵（B1）：优先级 header > Cookie > query（仅 SSE）、
//! 非 SSE 带 query 恒 401、token 环境独立性、OBSERVABILITY_DISABLE=1 全 404。
//! 每个用例独立建 app（sqlite 隔离 + 限流器隔离），经真 HTTP 回环，无外网依赖。

use {
    common::{TestOpts, serve, test_app_router},
    std::{path::PathBuf, sync::atomic::AtomicU64},
};

mod common;

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

// B1.1：三凭证齐全且 header 有效时按 header 放行（SSE 面，query 仅 SSE 生效）。
#[tokio::test]
async fn b1_header_beats_cookie_and_query_on_sse() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{base}/_admin/events/stream?access_token={ADMIN_TOKEN}"
        ))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .header("Cookie", format!("__Host-admin_token={ADMIN_TOKEN}"))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("text/event-stream")
    );
    handle.abort();
}

// B1.1：header 有效时低优先级无效凭证被忽略（Cookie/Query 错值不影响放行）。
#[tokio::test]
async fn b1_valid_header_ignores_invalid_cookie_and_query() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/metrics?access_token=wrong-query"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .header("Cookie", "__Host-admin_token=wrong-cookie")
        .send()
        .await
        .unwrap();
    // 非 SSE 带 query 恒 401：即使 header 有效，query 在位即拒绝。
    assert_eq!(resp.status().as_u16(), 401);
    // SSE 面 header 有效 + query 错值：按 header 放行。
    let sse = client
        .get(format!(
            "{base}/_admin/events/stream?access_token=wrong-query"
        ))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .header("Cookie", "__Host-admin_token=wrong-cookie")
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(sse.status().as_u16(), 200);
    handle.abort();
}

// B1.1：仅 Cookie 有效且无 header 时按 Cookie 放行（含 http 兼容名）。
#[tokio::test]
async fn b1_cookie_only_without_header_ok() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    for cookie in [
        format!("__Host-admin_token={ADMIN_TOKEN}"),
        format!("admin_token={ADMIN_TOKEN}"),
    ] {
        let resp = client
            .get(format!("{base}/_admin/metrics"))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }
    handle.abort();
}

// B1.1：仅 query 有效时非 SSE 恒 401 而 SSE 放行。
#[tokio::test]
async fn b1_query_only_sse_ok_non_sse_401() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let non_sse = client
        .get(format!("{base}/_admin/metrics?access_token={ADMIN_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(non_sse.status().as_u16(), 401);
    let sse = client
        .get(format!(
            "{base}/_admin/events/stream?access_token={ADMIN_TOKEN}"
        ))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(sse.status().as_u16(), 200);
    handle.abort();
}

// B1.1 边缘：header 在位但无效 + Cookie 有效 → 仍 401（fail-closed，不降级）。
// 对应单测锁定的 `auth_priority_header_cookie_query_and_401`（头无效直接 401）。
#[tokio::test]
async fn b1_header_present_invalid_blocks_cookie_downgrade_401() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", "wrong-header")
        .header("Cookie", format!("__Host-admin_token={ADMIN_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    // 无凭证全失败同样 401。
    let anon = client
        .get(format!("{base}/_admin/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status().as_u16(), 401);
    handle.abort();
}

// B1.2：非 SSE 带 query 恒 401，与 token 值正确性无关。
#[tokio::test]
async fn b1_non_sse_query_401_regardless_of_token_value() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    for token in [ADMIN_TOKEN, "wrong-token", ""] {
        let resp = client
            .get(format!("{base}/_admin/series?access_token={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401, "token={token:?}");
    }
    handle.abort();
}

// B1.2：环境变量 token 各 app 独立生效，无串扰。
#[tokio::test]
async fn b1_env_token_isolation_no_crosstalk() {
    let (base_a, handle_a) = serve(test_app_router(TestOpts::default().set(
        "OBSERVABILITY_ADMIN_TOKEN",
        "env-token-aaaa-0123456789abcdef",
    )))
    .await;
    let (base_b, handle_b) = serve(test_app_router(TestOpts::default().set(
        "OBSERVABILITY_ADMIN_TOKEN",
        "env-token-bbbb-0123456789abcdef",
    )))
    .await;
    let client = reqwest::Client::new();
    let ok_a = client
        .get(format!("{base_a}/_admin/metrics"))
        .header("X-Admin-Token", "env-token-aaaa-0123456789abcdef")
        .send()
        .await
        .unwrap();
    assert_eq!(ok_a.status().as_u16(), 200);
    let cross = client
        .get(format!("{base_a}/_admin/metrics"))
        .header("X-Admin-Token", "env-token-bbbb-0123456789abcdef")
        .send()
        .await
        .unwrap();
    assert_eq!(cross.status().as_u16(), 401);
    let ok_b = client
        .get(format!("{base_b}/_admin/metrics"))
        .header("X-Admin-Token", "env-token-bbbb-0123456789abcdef")
        .send()
        .await
        .unwrap();
    assert_eq!(ok_b.status().as_u16(), 200);
    handle_a.abort();
    handle_b.abort();
}

fn temp_data_dir(tag: &str) -> PathBuf {
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("veil-admin-matrix-{tag}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// B1.2：文件缺席 / 空文件均不影响环境变量 token 独立生效。
#[tokio::test]
async fn b1_env_token_independent_of_admin_token_file() {
    let client = reqwest::Client::new();
    // 缺文件：DATA_DIR 下无 admin_token。
    let dir_missing = temp_data_dir("nofile");
    assert!(!dir_missing.join("admin_token").exists());
    let (base, handle) = serve(test_app_router(&[(
        "DATA_DIR",
        dir_missing.to_str().unwrap(),
    )]))
    .await;
    let ok = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200);
    handle.abort();
    // 空文件：admin_token 存在但为空，环境变量仍独立生效（文件不覆写环境）。
    let dir_empty = temp_data_dir("emptyfile");
    std::fs::write(dir_empty.join("admin_token"), "").unwrap();
    let (base2, handle2) = serve(test_app_router(&[(
        "DATA_DIR",
        dir_empty.to_str().unwrap(),
    )]))
    .await;
    let ok2 = client
        .get(format!("{base2}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(ok2.status().as_u16(), 200);
    handle2.abort();
    std::fs::remove_dir_all(&dir_missing).ok();
    std::fs::remove_dir_all(&dir_empty).ok();
}

// B1.3：OBSERVABILITY_DISABLE=1 时管理面全 404，与 token 有效性无关。
// E-3（8.3）：门控 404 复用 `with_security_headers`，authed/anon 均须含
// `cache-control: no-store`。
#[tokio::test]
async fn b1_disable_all_admin_404_regardless_of_token() {
    let (base, handle) = serve(test_app_router(&[("OBSERVABILITY_DISABLE", "1")])).await;
    let client = reqwest::Client::new();
    for path in ["/_admin/metrics", "/_admin/events/stream", "/_admin/health"] {
        let authed = client
            .get(format!("{base}{path}"))
            .header("X-Admin-Token", ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(authed.status().as_u16(), 404, "{path}");
        assert!(
            authed
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("no-store")),
            "{path} authed 404 须含 cache-control: no-store"
        );
        let anon = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(anon.status().as_u16(), 404, "{path}");
        assert!(
            anon.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("no-store")),
            "{path} anon 404 须含 cache-control: no-store"
        );
    }
    // 非管理面不受影响。
    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 200);
    assert!(
        !health.headers().contains_key("x-frame-options"),
        "非管理面不得被加管理安全头"
    );
    handle.abort();
}

// E-3（8.3）：OBSERVABILITY_DISABLE=1 的门控 404 五项安全头齐全，
// 非 `/_admin` 路径不受该分支影响。
#[tokio::test]
async fn admin_gate_404_security_headers() {
    let (base, handle) = serve(test_app_router(&[("OBSERVABILITY_DISABLE", "1")])).await;
    let client = reqwest::Client::new();
    for path in ["/_admin/metrics", "/_admin/events/stream", "/_admin/health"] {
        for authed in [true, false] {
            let mut req = client.get(format!("{base}{path}"));
            if authed {
                req = req.header("X-Admin-Token", ADMIN_TOKEN);
            }
            let resp = req.send().await.unwrap();
            assert_eq!(resp.status().as_u16(), 404, "{path} authed={authed}");
            let h = resp.headers();
            for name in [
                "pragma",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
            ] {
                assert!(h.contains_key(name), "{path} authed={authed} 缺 {name}");
            }
            assert_eq!(
                h.get("x-content-type-options")
                    .and_then(|v| v.to_str().ok()),
                Some("nosniff"),
                "{path} authed={authed}"
            );
        }
    }
    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 200);
    assert!(!health.headers().contains_key("x-frame-options"));
    handle.abort();
}

// B1.3：取消置位后恢复正常鉴权；值非 1 时不触发全 404。
#[tokio::test]
async fn b1_disable_off_recovers_and_non_one_no_effect() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let ok = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200);
    handle.abort();
    for value in ["true", "yes", "0", "2"] {
        let (base_v, handle_v) = serve(test_app_router(&[("OBSERVABILITY_DISABLE", value)])).await;
        let resp = client
            .get(format!("{base_v}/_admin/metrics"))
            .header("X-Admin-Token", ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "value={value}");
        handle_v.abort();
    }
}

// G4/P11：未鉴权 /_admin/metrics 恒 401，响应体不得泄漏 pii_value_samples 采样桶。
#[tokio::test]
async fn pii_value_sample_401_no_leak() {
    let (base, handle) = serve(test_app_router(&[("PII_VALUE_SAMPLE_ENABLED", "1")])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("pii_value_samples"),
        "401 响应体不得泄漏采样桶: {body}"
    );
    assert!(
        body.contains("E_UNAUTHORIZED"),
        "须为标准未鉴权错误体: {body}"
    );
    handle.abort();
}
