//! 管理控制台静态壳：`/_admin/` 入口按 `Accept` 协商分发。
//!
//! 壳内不含任何运维数据，故免鉴权；安全头与 `Vary` 由本模块与 `admin_index` 统一注入。

use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

/// 控制台静态壳（三段 `include_str!` 编译期拼接进二进制，无运行时文件依赖，Dockerfile 零改动）：
/// `console.head.html`（doctype/head/style/markup + 起始 `<script>`）、`console.app.js`（脚本正文）
/// 与 `console.tail.html`（`</script>` 与收尾 markup）依次拼接。拼接结果与拆分前单文件逐字节一致，
/// 仍是一次响应、一个 URL、零外部 URL 的 `&'static str` 常量（编译期拼接，无运行时构造）。
pub const CONSOLE_HTML: &str = concat!(
    include_str!("console.head.html"),
    include_str!("console.app.js"),
    include_str!("console.tail.html")
);

/// 词法级 `Accept` 协商：仅精确 `text/html` / `application/xhtml+xml` 命中
/// （不匹配 `text/*`、`*/*` 等通配）；条目参数 `q=`（键名大小写不敏感）解析值
/// `<= 0.0` 时该条目视为不可接受；缺头或非 UTF-8 一律不命中。
pub fn wants_html(headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    raw.split(',').any(|item| {
        let mut params = item.split(';');
        let media = params.next().unwrap_or("").trim().to_ascii_lowercase();
        if media != "text/html" && media != "application/xhtml+xml" {
            return false;
        }
        !params.any(|param| {
            let Some((key, value)) = param.split_once('=') else {
                return false;
            };
            key.trim().eq_ignore_ascii_case("q")
                && value.trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
        })
    })
}

/// 控制台壳响应：`200` + `Content-Type: text/html; charset=utf-8` + `Vary: Accept`，
/// 并统一套用管理面安全头（免鉴权分支专用，下发前不经过 `authorize`）。
pub fn console_response() -> Response {
    let mut response = (StatusCode::OK, CONSOLE_HTML).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::VARY, axum::http::HeaderValue::from_static("Accept"));
    super::with_security_headers(response)
}
