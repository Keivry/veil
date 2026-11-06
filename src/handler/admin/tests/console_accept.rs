//! 控制台 `Accept` 词法协商单测（从 `console.rs` 拆出以守住 1200 行预算）。

use {
    crate::handler::admin::console::wants_html,
    axum::http::{HeaderMap, HeaderValue, header},
};

/// 仅携带 `Accept` 的请求头。
fn accept(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::ACCEPT, value.parse().unwrap());
    h
}

#[test]
fn wants_html_accepts_exact_html_media_types() {
    for value in [
        "text/html",
        "application/xhtml+xml",
        "TEXT/HTML",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ] {
        assert!(wants_html(&accept(value)), "Accept={value:?} 须命中 HTML");
    }
}

#[test]
fn wants_html_rejects_missing_wildcard_json_and_zero_q() {
    for value in [
        "*/*",
        "text/*",
        "application/json",
        "text/html;q=0",
        "text/html;Q=0.0",
        "text/html;q=0, */*;q=0.8",
    ] {
        assert!(
            !wants_html(&accept(value)),
            "Accept={value:?} 不得命中 HTML"
        );
    }
    assert!(!wants_html(&HeaderMap::new()), "缺 Accept 头不得命中");
    // 非 UTF-8 头值：`HeaderMap::get(...).to_str()` 失败 → 不命中。
    let mut non_utf8 = HeaderMap::new();
    non_utf8.insert(
        header::ACCEPT,
        HeaderValue::from_bytes(b"text/html;profile=\xff").unwrap(),
    );
    assert!(!wants_html(&non_utf8), "非 UTF-8 Accept 不得命中");
}
