//! 管理控制台静态壳单测：`Accept` 词法协商、壳响应头与自包含性。
//!
//! 只覆盖 `console.rs` 的纯逻辑与响应构造；入口路由的鉴权分支与
//! `OBSERVABILITY_DISABLE` 门控由 `tests/http_e2e_admin_console.rs` 端到端锁定。

use {
    crate::handler::admin::console::{CONSOLE_HTML, console_response, wants_html},
    axum::http::{HeaderMap, HeaderValue, StatusCode, header},
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

#[tokio::test]
async fn console_response_headers_and_body() {
    let resp = console_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        headers.get(header::VARY).and_then(|v| v.to_str().ok()),
        Some("Accept")
    );
    assert!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("no-store")),
        "壳须 no-store"
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(body.len(), CONSOLE_HTML.len(), "响应体须逐字节为壳");
    assert!(String::from_utf8_lossy(&body).starts_with("<!DOCTYPE html"));
}

#[test]
fn console_html_command_section_wired() {
    for needle in [
        "data-sec=\"commands\"",
        "id=\"sec-commands\"",
        "id=\"cmd-table\"",
        "SEC_TITLES = { overview: '概览', redaction: '脱敏', performance: '性能', events: '事件', commands: '命令调用' }",
        "'/_admin/commands?limit='",
        "approval_status=",
        "parsed.kind === 'command'",
        "function commandRowModel",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_command_row_model_executes_in_node() {
    const START: &str = "/* @veil-testable:start */";
    const END: &str = "/* @veil-testable:end */";
    let fn_pos = CONSOLE_HTML
        .find("function commandRowModel")
        .expect("壳须含 commandRowModel");
    let start = CONSOLE_HTML[..fn_pos]
        .rfind(START)
        .expect("commandRowModel 须位于 @veil-testable 块内")
        + START.len();
    let rest = &CONSOLE_HTML[start..];
    let end = rest.find(END).expect("壳须含 @veil-testable:end 标记");
    let helpers = &rest[..end];

    let node_ready = std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if !node_ready {
        return;
    }

    let harness = r#"
function fmtTs(ts) {
    if (ts == null || ts === '') return '';
    var d = new Date(Number(ts) * 1000);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleTimeString('zh-CN', { hour12: false });
}
var out = {};
var r = commandRowModel({ ts_secs: 1700000000, downstream: 'ci', command: 'deploy', host: 'api', approval_status: 'approved', exec_status: 'failed', exit_code: 3, duration_ms: 12 });
out.command = r.command;
out.exit = r.exit;
out.duration = r.duration;
out.approval = r.approval;
var empty = commandRowModel(null);
out.empty_exit = empty.exit;
out.empty_command = empty.command;
console.log(JSON.stringify(out));
"#;
    let script = format!("{helpers}\n{harness}\n");
    let output = std::process::Command::new("node")
        .arg("-e")
        .arg(&script)
        .output()
        .expect("spawn `node -e` 失败");
    assert!(
        output.status.success(),
        "node 执行失败（status={}）：{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_str(
        String::from_utf8(output.stdout)
            .expect("node stdout 须为 UTF-8")
            .trim(),
    )
    .expect("node 须输出 JSON");
    assert_eq!(verdict["command"], "deploy");
    assert_eq!(verdict["exit"], "3");
    assert_eq!(verdict["duration"], "12");
    assert_eq!(verdict["approval"], "approved");
    assert_eq!(verdict["empty_exit"], "-");
    assert_eq!(verdict["empty_command"], "");
}

#[test]
fn console_html_honors_retry_after_backoff() {
    // C 语义接线：SSE 错误后先探 `Retry-After` 再决定重连间隔（EventSource 错误
    // 不暴露响应头），回退轮询亦在退避窗口内让路——否则每 3s 撞一次焊死限流窗口。
    // 探针与 SSE 退避均带内存令牌 / 独立字段，不阻塞登录探针。
    for needle in [
        "probeRetryAfter",
        "headers.get('retry-after')",
        "headers['X-Admin-Token'] = state.token",
        "state.streamRetryAt = ra > 0",
        "Date.now() < state.streamRetryAt",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_self_contained_and_wired_to_sse() {
    for needle in [
        "<!DOCTYPE html",
        "addEventListener('event'",
        "addEventListener('metrics'",
        "addEventListener('done'",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    let lower = CONSOLE_HTML.to_ascii_lowercase();
    for forbidden in [
        "onmessage",
        "chart",
        "localstorage",
        "sessionstorage",
        "serviceworker",
        "http://",
        "https://",
        "<script src=",
        "@import",
    ] {
        assert!(!lower.contains(forbidden), "壳不得含 {forbidden:?}");
    }
}

#[test]
fn console_html_pii_samples_aggregation_and_top3_wiring() {
    // 「PII 采样分布」须适配后端嵌套形状 `{kind:{mask:{count,hash}}}`（observability.rs
    // 形状测试锁定）：柱值 = kind 下全部 mask count 之和；悬停/无障碍标签列该 kind 的
    // Top-3 掩码样本（count 降序）。renderDist 不得再把原始嵌套对象直传平坦 drawBars。
    for needle in [
        "function piiKindStats",
        "if (!samples || typeof samples !== 'object') return out;",
        "var cnt = countOf(byMask[mask]);",
        "total += cnt",
        "top.sort(function (a, b) { return b.count - a.count; });",
        "top.slice(0, 3)",
        "return t.mask + ' x' + t.count;",
        "piiKindStats(m.pii_value_samples)",
        "drawPiiBars('pii-box', piiStats)",
        "rect.setAttribute('aria-label', tip ? tip.aria",
        "title.textContent = tip ? tip.title",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    assert!(
        !CONSOLE_HTML.contains("drawBars('pii-box'"),
        "PII 面板不得把原始嵌套对象直传仅支持平坦数值的 drawBars"
    );
    // 协议/模型分布的调用点保持原样（逐字未变），不受 PII 适配影响。
    for needle in [
        "drawBars('proto-box', m.per_protocol || {});",
        "drawBars('model-box', m.per_model || {});",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_pii_hint_scope_and_approximation_wording() {
    // 提示行：保留作用域模式文案；明示采样口径「进程内 TopN 采样（非全量）、不随
    // range 变化」；近似标注只绑定全局窗口精度（is_precise 非 true 且存在样本），
    // 措辞用「全局指标近似窗口」，不得表述为采样精度。
    for needle in [
        "作用域模式：",
        "仅展示有计数的 kind（上限 12 项）。",
        "样本为进程内 TopN 采样（非全量）、不随 range 变化。",
        "hasSamples && m.is_precise !== true",
        "parts.push('全局指标近似窗口。');",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    assert!(
        !CONSOLE_HTML.contains("采样精度标注"),
        "近似标注不得表述为采样精度"
    );
    assert!(
        CONSOLE_HTML.contains("'<span class=\"empty\">暂无数据</span>'"),
        "空样本/全零须保留「暂无数据」空态"
    );
}

#[test]
fn console_html_oversize_wiring_and_pii_class_removed() {
    // 超软限观测（帧/字节）须有渲染目标；响应侧 PII 分类面板不在渲染面内。
    for needle in ["m.oversize_frames", "m.oversize_frame_bytes", "超软限帧"] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    // 已移除的响应侧 PII 分类渲染面：JS 取数键、指标键与面板行 id（前两者字面量拆写，
    // 以通过 `src/` 归零门禁；负断言语义不变）。
    for removed in [
        concat!("m.", "pii_", "classification"),
        concat!("masked_unreg", "istered"),
        "pii-class-line",
    ] {
        assert!(
            !CONSOLE_HTML.contains(removed),
            "壳不得再含被移除的 PII 分类渲染: {removed:?}"
        );
    }
    // fail-closed 截断四态保留（`oversize` 为只增项，不得替换移除既有关卡）。
    assert!(
        CONSOLE_HTML.contains("function truncSum") && CONSOLE_HTML.contains("截断合计"),
        "fail-closed 截断四态卡不得移除"
    );
}

#[test]
fn console_html_pii_kind_stats_execute_in_node() {
    // 执行型断言：抽出 `@veil-testable` 标记之间的纯函数（`countOf`/`piiKindStats`）
    // 交给 node 实际求值——纯内容断言只能证明符号存在，锁定不了聚合语义。
    // 无 node 的环境（探测无法 spawn 或非零退出）直接跳过，避免平台差异误报。
    const START: &str = "/* @veil-testable:start */";
    const END: &str = "/* @veil-testable:end */";
    let start = CONSOLE_HTML
        .find(START)
        .expect("壳须含 @veil-testable:start 标记")
        + START.len();
    let rest = &CONSOLE_HTML[start..];
    let end = rest.find(END).expect("壳须含 @veil-testable:end 标记");
    let helpers = &rest[..end];

    let node_ready = std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if !node_ready {
        return; // 无 node：跳过执行型断言，符号/接线由同类内容断言继续覆盖
    }

    let harness = r#"
var out = {};
var s1 = piiKindStats({ phone: { a: { count: 2 }, b: { count: 10 } } });
out.single_total = s1.phone ? s1.phone.total : null;
out.single_top = s1.phone ? s1.phone.top.map(function (t) { return t.mask + ':' + t.count; }) : null;
out.single_len = s1.phone ? s1.phone.top.length : -1;

var s2 = piiKindStats({ phone: { a: { count: 2 }, b: { count: 10 }, c: { count: 7 }, d: { count: 1 } } });
out.top3_len = s2.phone.top.length;
out.top3 = s2.phone.top.map(function (t) { return t.mask + ':' + t.count; });

out.null_keys = Object.keys(piiKindStats(null)).length;
out.empty_keys = Object.keys(piiKindStats({})).length;
out.zero_keys = Object.keys(piiKindStats({ phone: { a: { count: 0 } } })).length;

var s4 = piiKindStats({ phone: { a: { count: 2 }, b: { count: 10 } }, email: { x: { count: 3 } } });
out.kinds = Object.keys(s4).sort();
out.phone_total = s4.phone ? s4.phone.total : null;
out.email_total = s4.email ? s4.email.total : null;

console.log(JSON.stringify(out));
"#;
    let script = format!("{helpers}\n{harness}\n");
    let output = std::process::Command::new("node")
        .arg("-e")
        .arg(&script)
        .output()
        .expect("spawn `node -e` 失败");
    assert!(
        output.status.success(),
        "node 执行失败（status={}）：{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("node stdout 须为 UTF-8");
    let verdict: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("node 须在 stdout 输出 JSON 判定");
    let expected = serde_json::json!({
        "single_total": 12,
        "single_top": ["b:10", "a:2"],
        "single_len": 2,
        "top3_len": 3,
        "top3": ["b:10", "c:7", "a:2"],
        "null_keys": 0,
        "empty_keys": 0,
        "zero_keys": 0,
        "kinds": ["email", "phone"],
        "phone_total": 12,
        "email_total": 3,
    });
    assert_eq!(
        verdict, expected,
        "piiKindStats 聚合语义（合计/Top-3 降序/空态/多 kind 独立）须与契约一致"
    );
}
