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
        "SEC_TITLES = { overview: '概览', redaction: '脱敏', performance: '性能', events: '事件', commands: '命令调用', requests: 'LLM 请求' }",
        "'/_admin/commands?range='",
        "approval_status=",
        "parsed.kind === 'command'",
        "function commandRowModel",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_request_section_wired() {
    // 五处触点：nav / 分区 / SEC_TITLES（上条逐字锁定）/ showSection 分支 / state.requests。
    for needle in [
        "data-sec=\"requests\"",
        "id=\"sec-requests\"",
        "id=\"req-table\"",
        "if (sec === 'requests') {",
        "reloadRequests();",
        "requests: { limit: 50, offset: 0, total: 0,",
        "function renderRequests(d)",
        "function reloadRequests(force)",
        "function requestRowModel(item)",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_request_table_columns_and_filters() {
    // 12 列顺序固定：时间/模型/协议/上游/会话/状态/输入·输出/命中率/耗时/TTFT/TPS/摘要。
    assert!(
        CONSOLE_HTML.contains(
            "<th>时间</th><th>模型</th><th>协议</th><th>上游</th><th>会话</th><th>状态</th>\n                <th class=\"num\">输入·输出</th><th class=\"num\">命中率</th><th class=\"num\">耗时</th><th class=\"num\">TTFT</th><th class=\"num\">TPS</th><th>摘要</th>"
        ),
        "请求表头须为 12 列且顺序固定"
    );
    // 过滤器取值：protocol 有 chat/responses/messages（`other` 随服务端 llm=1 过滤下线），
    // status 有 2xx/4xx/5xx/error，session 前缀 ≥4 字符提示，scope 有 会话/用户，
    // limit 有 50/100/200。
    for needle in [
        "id=\"req-model\"",
        "id=\"req-protocol\"",
        "<option value=\"chat\">chat</option>",
        "<option value=\"responses\">responses</option>",
        "<option value=\"anthropic\">messages</option>",
        "id=\"req-status\"",
        "<option value=\"2xx\">2xx</option>",
        "<option value=\"4xx\">4xx</option>",
        "<option value=\"5xx\">5xx</option>",
        "<option value=\"error\">error</option>",
        "id=\"req-session\"",
        "会话前缀至少 4 个字符才生效",
        "id=\"req-scope\"",
        "<option value=\"session\">会话</option>",
        "<option value=\"user\">用户</option>",
        "id=\"req-limit\"",
        "<option value=\"50\">每页 50</option>",
        "<option value=\"100\">每页 100</option>",
        "<option value=\"200\">每页 200</option>",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    // 会话前缀不足 4 字符不生效（源码级：只在 ≥4 时拼进查询）。
    assert!(
        CONSOLE_HTML.contains("if (r.session.length >= 4) q += '&session='"),
        "会话前缀须在 ≥4 字符时才作为查询参数发送"
    );
    // 负向：协议过滤器只留服务端 llm=1 口径下的三种取值，`other`/`passthrough`
    // 已随「只列真实 LLM 请求」下线，重新加回会让筛选结果为空。断言限定在该
    // `<select>` 自身，避免命中注释/CSS 里的同名词。
    let proto_start = CONSOLE_HTML
        .find("id=\"req-protocol\"")
        .expect("壳须含 req-protocol 过滤器");
    let proto_rest = &CONSOLE_HTML[proto_start..];
    let proto_end = proto_rest
        .find("</select>")
        .expect("req-protocol 须以 </select> 收尾");
    let proto_select = &proto_rest[..proto_end];
    for absent in ["other", "passthrough"] {
        let option = format!("<option value=\"{absent}\">");
        assert!(
            !proto_select.contains(&option),
            "请求协议过滤器不得再含已下线的 {option:?}: {proto_select}"
        );
    }
}

#[test]
fn console_html_request_states_pagination_and_range() {
    // 三态文案互不相同：记录关闭 / 范围内无请求 / partial 覆盖提示。
    for needle in [
        "逐请求记录已关闭（[storage].request_log_enabled = false）",
        "当前范围内无请求",
        "记录覆盖不足：实际覆盖 ",
        "if (d.partial === true) {",
        "id=\"req-partial\"",
        "id=\"req-prev\"",
        "id=\"req-next\"",
        "info.textContent = '共 ' + r.total + ' 条';",
        "prev.disabled = r.offset <= 0;",
        "next.disabled = rowCount === 0 || r.offset + rowCount >= r.total;",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    // 全局范围恒随查询发送；SSE 与回退轮询的分区刷新沿用同一端点。
    assert!(
        CONSOLE_HTML.contains("'/_admin/requests?range=' + encodeURIComponent(state.range)"),
        "请求分区查询须恒带 range"
    );
    assert!(
        CONSOLE_HTML.contains("if (!$('sec-requests').hidden) {\n        reloadRequests();"),
        "断线回退时请求分区须以 /_admin/requests 为单端点"
    );
}

#[test]
fn console_html_all_data_requests_carry_range() {
    // 范围切换须落到每一次取数：SSE 建连、指标/时序回退，以及事件/命令/请求三个
    // 分页端点全部携带当前 `range`（否则切换后仍展示旧窗口数据）。
    for needle in [
        "return '/_admin/events/stream?range=' + encodeURIComponent(state.range);",
        "api('/_admin/metrics?range=' + encodeURIComponent(state.range))",
        "var q = '/_admin/events?range=' + encodeURIComponent(state.range) +\n      '&limit=' + EVENT_LIMIT;",
        "var q = '/_admin/commands?range=' + encodeURIComponent(state.range) +\n      '&limit=' + state.cmdLimit + '&offset=' + state.cmdOffset;",
        "var q = '/_admin/requests?range=' + encodeURIComponent(state.range) +",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    assert_eq!(
        CONSOLE_HTML.matches("/_admin/events?range=").count(),
        1,
        "`/_admin/events` 的取数点须唯一且带 range"
    );
    assert_eq!(
        CONSOLE_HTML.matches("/_admin/commands?range=").count(),
        1,
        "`/_admin/commands` 的取数点须唯一且带 range"
    );
}

#[test]
fn console_html_range_change_refetches_visible_section() {
    // 范围切换后：overview 仅靠 SSE 快照（不额外取数），事件/命令/请求各按当前分区
    // 重取一页，且分页偏移归零避免旧窗口的越界页。
    for needle in [
        "} else if (!$('sec-events').hidden) {\n          reloadEventsOnce();",
        "} else if (!$('sec-commands').hidden) {\n          state.cmdOffset = 0;\n          reloadCommands(true);",
        "restartStream();\n        if (!$('sec-requests').hidden) {\n          state.requests.offset = 0;\n          reloadRequests(true);",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_distribution_coverage_and_partial_hint() {
    // 模型分布：`per_model_partial` 为真时标注环内样本（非范围全量），
    // `coverage_secs` 存在时展示覆盖时长；PII 采样面板的既有文案保持不变。
    for needle in [
        "id=\"model-hint\"",
        "if (m.per_model_partial === true) mparts.push('模型分布为环内样本，非范围全量。');",
        "if (m.coverage_secs != null) mparts.push('分布样本覆盖 ' + fmtCoverage(m.coverage_secs) + '。');",
        "mh.hidden = mparts.length === 0;",
        "样本为进程内 TopN 采样（非全量）、不随 range 变化。",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_requests_next_page_respects_offset_cap_and_surfaces_errors() {
    // offset > 10000 服务端 400：按钮先禁用，点击处再兜底提示，请求失败给非阻塞横幅。
    for needle in [
        "var REQ_MAX_OFFSET = 10000;",
        "if (next && r.offset + r.limit > REQ_MAX_OFFSET) next.disabled = true;",
        "if (r.offset + r.limit > REQ_MAX_OFFSET) {\n        setBanner(REQ_NEXT_LIMIT);\n        return;\n      }",
        "setBanner('请求列表加载失败：' + (err && err.message ? err.message : '未知错误'));",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_request_cells_use_escaping_helper() {
    // 每个单元格都经 esc()：模型/摘要/会话等均为不可信输入，不拼接原始值。
    for needle in [
        "'<td>' + esc(x.ts) + '</td>'",
        "'<td>' + esc(x.model) + '</td>'",
        "'<td>' + esc(x.protocol) + '</td>'",
        "'<td>' + esc(x.session) +",
        "'<td>' + esc(x.status) + '</td>'",
        "'<td class=\"num\">' + esc(x.io) + '</td>'",
        "'<td class=\"num\" title=\"' + esc(x.hitTitle) + '\">' + esc(x.hit) + '</td>'",
        "'<td class=\"num\">' + esc(x.latency) + '</td>'",
        "'<td class=\"sum\" title=\"' + esc(x.summary) + '\">' + esc(x.summary) + '</td>'",
        "'<span class=\"badge\" title=\"' + esc(x.source) + '\">' + esc(x.scope) + '</span>'",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    assert!(
        !CONSOLE_HTML.contains("+ x.summary +") && !CONSOLE_HTML.contains("+ x.model +"),
        "摘要与模型不得以原始值拼接进 HTML"
    );
    // 该端点的取数点唯一：全部集中在 reloadRequests 内，分区外不得另立请求。
    assert_eq!(
        CONSOLE_HTML.matches("'/_admin/requests?range='").count(),
        1,
        "`/_admin/requests` 的取数点须唯一"
    );
    assert!(
        CONSOLE_HTML.contains("function reqEmptyRow(text) {\n    return '<tr><td colspan=\"' + REQ_EMPTY_COLS + '\"><div class=\"empty\">' + esc(text) + '</div></td></tr>';"),
        "请求表空态文案也须经 esc()"
    );
}

#[test]
fn console_html_req_empty_cols_equals_header_column_count() {
    // 空态行的 colspan 由 `REQ_EMPTY_COLS` 渲染，必须与 `#req-table` 表头列数
    // 逐一相等：单改任一侧都会让空态行错位（左对齐到 9 列即漏掉后 3 列）。
    const NEEDLE: &str = "var REQ_EMPTY_COLS = ";
    let start = CONSOLE_HTML
        .find(NEEDLE)
        .expect("壳须含 REQ_EMPTY_COLS 字面量")
        + NEEDLE.len();
    let rest = &CONSOLE_HTML[start..];
    let end = rest.find(';').expect("REQ_EMPTY_COLS 须以 ; 收尾");
    let parsed: usize = rest[..end]
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("REQ_EMPTY_COLS 取值非法 {:?}: {e}", &rest[..end]));

    let table_start = CONSOLE_HTML
        .find("<table id=\"req-table\">")
        .expect("壳须含 #req-table");
    let table_rest = &CONSOLE_HTML[table_start..];
    let head_start = table_rest.find("<thead>").expect("请求表须有 thead");
    let head_rest = &table_rest[head_start..];
    let head_end = head_rest.find("</thead>").expect("请求表 thead 须闭合");
    let row_start = head_rest.find("<tr>").expect("请求表头须有行");
    let th_count = head_rest[row_start..head_end].matches("<th").count();

    assert_eq!(
        parsed, th_count,
        "REQ_EMPTY_COLS 须等于 #req-table 表头列数（否则空态行 colspan 与表头错位）"
    );
    assert_eq!(th_count, 12, "请求表头须为 12 列: {th_count}");
}

#[test]
fn console_html_sync_poll_clears_timer_when_section_hidden_or_toggle_off() {
    // `syncPoll` 是切分区/切 Live 时唯一启停轮询定时器的入口：want 为假时必须
    // 走 clearInterval 分支，否则切走后定时器继续在后台取数。
    let start = CONSOLE_HTML
        .find("function syncPoll() {")
        .expect("壳须含 syncPoll");
    let rest = &CONSOLE_HTML[start..];
    let end = rest.find("\n  }\n").expect("syncPoll 须以标准缩进收尾");
    let body = &rest[..end];

    for needle in [
        "$('sec-requests').hidden && state.reqLive",
        "$('sec-commands').hidden && state.cmdLive",
        "if (state.pollTimer === null) state.pollTimer = setInterval(pollTick, POLL_MS);",
        "clearInterval(state.pollTimer);",
        "state.pollTimer = null;",
    ] {
        assert!(body.contains(needle), "syncPoll 须含 {needle:?}: {body}");
    }
    // 清除分支必须挂在 else 上：want 为真时不得顺手清掉刚建好的定时器。
    assert!(
        body.contains(
            "} else if (state.pollTimer !== null) {\n      clearInterval(state.pollTimer);"
        ),
        "syncPoll 的 clearInterval 须仅在不该轮询时执行: {body}"
    );
}

#[test]
fn console_request_row_model_executes_in_node() {
    const START: &str = "/* @veil-testable:start */";
    const END: &str = "/* @veil-testable:end */";
    let fn_pos = CONSOLE_HTML
        .find("function requestRowModel")
        .expect("壳须含 requestRowModel");
    let start = CONSOLE_HTML[..fn_pos]
        .rfind(START)
        .expect("requestRowModel 须位于 @veil-testable 块内")
        + START.len();
    let rest = &CONSOLE_HTML[start..];
    let end = rest.find(END).expect("壳须含 @veil-testable:end 标记");
    let helpers = &rest[..end];
    // `esc` 位于该测试块之外：按函数头切出源码，配合最小 DOM 垫片在 node 中求值，
    // 锁定「先 textContent 再由 innerHTML 读出」的转义语义（而不是只断言符号存在）。
    let esc_pos = CONSOLE_HTML
        .find("function esc(s) {")
        .expect("壳须含 esc 转义助手");
    let esc_rest = &CONSOLE_HTML[esc_pos..];
    let esc_end = esc_rest.find("\n  }\n").expect("esc 函数须以标准缩进收尾") + "\n  }\n".len();
    let esc_src = &esc_rest[..esc_end];
    // `fmtMs` 同在该块之外：抽出真身而非在垫片里重写，否则格式化口径被改写也测不出来。
    let ms_pos = CONSOLE_HTML
        .find("function fmtMs(v) {")
        .expect("壳须含 fmtMs 助手");
    let ms_rest = &CONSOLE_HTML[ms_pos..];
    let ms_end = ms_rest.find("\n  }\n").expect("fmtMs 须以标准缩进收尾") + "\n  }\n".len();
    let ms_src = &ms_rest[..ms_end];

    let node_ready = std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if !node_ready {
        return;
    }

    let harness = format!(
        r#"
function makeDoc() {{
    return {{
        createElement: function () {{
            var el = {{}}, text = '';
            Object.defineProperty(el, 'textContent', {{
                set: function (v) {{ text = v == null ? '' : String(v); }},
                get: function () {{ return text; }}
            }});
            Object.defineProperty(el, 'innerHTML', {{
                get: function () {{
                    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                }}
            }});
            return el;
        }}
    }};
}}
var document = makeDoc();
{esc_src}
{ms_src}
function fmtNum(n) {{
    if (n == null || n === '') return '—';
    var x = Number(n);
    if (!isFinite(x)) return '—';
    return String(x);
}}
function fmtFullTs(ts) {{
    if (ts == null || ts === '') return '';
    var d = new Date(Number(ts) * 1000);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString('zh-CN', {{ hour12: false }});
}}
var out = {{}};
var r = requestRowModel({{ ts_secs: 1700000000, model: '<img src=x onerror=alert(1)>', protocol: 'chat',
  prompt_tokens: 1024, completion_tokens: 256, cache_hit_rate: 0.75, cache_write_rate: 0.125,
  latency_ms: 812, session_id: '9f2c8a1b4d5e6f70', session_source: 'cache_key', session_scope: 'session',
  upstream: 'api.example.ai:443', ttft_ms: 812, tps: 25.4,
  summary: '<script>x</script>' }});
out.model = r.model;
out.session = r.session;
out.scope = r.scope;
out.source = r.source;
out.io = r.io;
out.hit = r.hit;
out.hitTitle = r.hitTitle;
out.latency = r.latency;
out.upstream = r.upstream;
out.upstreamShort = r.upstreamShort;
out.ttft = r.ttft;
out.tps = r.tps;
out.summary = r.summary;
var longUp = requestRowModel({{ upstream: 'upstream.internal.example.corp:11434' }});
out.long_upstream = longUp.upstream;
out.long_upstream_short = longUp.upstreamShort;
var nul = requestRowModel({{ ts_secs: 1, cache_hit_rate: null, status: null, error_kind: 'upstream_unreachable',
  prompt_tokens: 0, completion_tokens: 0, latency_ms: 0, session_id: null, session_scope: 'none',
  upstream: null, ttft_ms: null, tps: null }});
out.null_hit = nul.hit;
out.null_status = nul.status;
out.null_session = nul.session;
out.null_scope = nul.scope;
out.null_upstream = nul.upstream;
out.null_upstream_short = nul.upstreamShort;
out.null_ttft = nul.ttft;
out.null_tps = nul.tps;
var escModel = esc('<img src=x onerror=alert(1)>');
out.esc_model = escModel;
out.esc_has_img = escModel.indexOf('<img') >= 0;
out.esc_has_script = esc('<' + 'script>x</' + 'script>').indexOf('<script') >= 0;
out.esc_quotes = esc('a"b\'c');
console.log(JSON.stringify(out));
"#
    );
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
    assert_eq!(verdict["model"], "<img src=x onerror=alert(1)>");
    assert_eq!(verdict["session"], "9f2c8a1b4d5e");
    assert_eq!(verdict["scope"], "会话");
    assert_eq!(verdict["source"], "cache_key");
    assert_eq!(verdict["io"], "1,024 · 256");
    assert_eq!(verdict["hit"], "75.0%");
    assert_eq!(verdict["hitTitle"], "缓存写比率 12.5%");
    assert_eq!(verdict["latency"], "812 ms");
    assert_eq!(verdict["upstream"], "api.example.ai:443");
    assert_eq!(
        verdict["upstreamShort"], "api.example.ai:443",
        "不超 18 字符的上游 authority 须原样展示"
    );
    assert_eq!(
        verdict["long_upstream"], "upstream.internal.example.corp:11434",
        "title 用的完整上游值不得被截断"
    );
    assert_eq!(
        verdict["long_upstream_short"], "upstream.…rp:11434",
        "超 18 字符的上游须中段省略为 truncMiddle(upstream, 18)"
    );
    assert_eq!(verdict["ttft"], "812 ms", "TTFT 须走 fmtMs 口径");
    assert_eq!(verdict["tps"], "25.4 tok/s", "TPS 须保留一位小数");
    assert_eq!(verdict["summary"], "<script>x</script>");
    assert_eq!(verdict["null_hit"], "—");
    assert_eq!(verdict["null_status"], "upstream_unreachable");
    assert_eq!(verdict["null_session"], "");
    assert_eq!(verdict["null_scope"], "");
    assert_eq!(verdict["null_upstream"], "", "上游缺失须为空串入口径");
    assert_eq!(verdict["null_upstream_short"], "");
    assert_eq!(verdict["null_ttft"], "—", "TTFT 不可测须为占位符而非空串/0");
    assert_eq!(verdict["null_tps"], "—", "TPS 不可测须为占位符而非空串/0");
    // XSS：模型原文可流出模型层，但经 esc() 后不得再含可执行的标签起始。
    assert_eq!(verdict["esc_has_img"], false, "esc 输出不得含 <img");
    assert_eq!(verdict["esc_has_script"], false, "esc 输出不得含 <script");
    assert_eq!(
        verdict["esc_model"], "&lt;img src=x onerror=alert(1)&gt;",
        "esc 须把标签起始/结束转为实体"
    );
    assert_eq!(
        verdict["esc_quotes"], "a&quot;b&#39;c",
        "esc 须同时转义双引号与单引号（属性位安全）"
    );
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
fn console_html_poll_budget_guards() {
    // 管理面通用桶 10 次/分钟：轮询取数间隔须为 30 秒（单分区稳态 2 次/分钟），
    // 后台标签页不取数；同分区上一轮未落地时不得叠加第二个同源请求；
    // 429 无 Retry-After 时仍至少退避一个轮询间隔，否则下一拍立刻重撞。
    for needle in [
        "var POLL_MS = 5000;",
        "var POLL_MIN_GAP_MS = 30000;",
        "if (document.visibilityState !== 'visible') return;",
        "reqBusy: false, cmdBusy: false,",
        "if (state.reqBusy) return;",
        "if (state.cmdBusy) return;",
        "state.reqBusy = false;",
        "state.cmdBusy = false;",
        "var ra = (err.retryAfter > 0) ? err.retryAfter * 1000 : POLL_MIN_GAP_MS;",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    // 手动路径不得被飞行中的上一轮静默丢弃：排队一次重跑（轮询路径仍无 force）。
    for needle in [
        "function reloadRequests(force) {",
        "if (state.reqBusy) { r.pending = true; return; }",
        "if (r.pending) { r.pending = false; reloadRequests(true); }",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    // SSE 回退轮询的指标 429 分支同样按 POLL_MIN_GAP_MS 兜底退避。
    assert_eq!(
        CONSOLE_HTML
            .matches("var ra = (err.retryAfter > 0) ? err.retryAfter * 1000 : POLL_MIN_GAP_MS;")
            .count(),
        3,
        "请求/命令/回退指标三个 429 分支须共用同一兜底退避"
    );
}

#[test]
fn console_html_polling_keeps_single_request_endpoints() {
    // 轮询不得另立取数点：两个端点字面量各自唯一，且仍走 reloadRequests/reloadCommands。
    assert_eq!(
        CONSOLE_HTML.matches("'/_admin/requests?range='").count(),
        1,
        "`/_admin/requests` 的取数点须唯一"
    );
    assert_eq!(
        CONSOLE_HTML.matches("/_admin/commands?range=").count(),
        1,
        "`/_admin/commands` 的取数点须唯一"
    );
    for needle in [
        ">= POLL_MIN_GAP_MS) reloadRequests();",
        ">= POLL_MIN_GAP_MS) reloadCommands();",
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
    // 协议/模型分布改走统一的横向条入口（形态与 PII 面板一致），调用点逐字锁定。
    for needle in [
        "drawDistBars('proto-box', m.per_protocol || {});",
        "drawDistBars('model-box', m.per_model || {});",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_layout_toolbar_grouping_and_pager_baseline() {
    // 工具栏改为「筛选组 + 分页组」语义分组：折行只发生在组边界，分页信息不再复用
    // 带 margin-top 的 .hintline（否则基线比相邻按钮低 13px）。
    for needle in [
        ".tb-group { display: flex; gap: 8px; align-items: center; flex-wrap: nowrap; }",
        ".tb-pager { display: flex; gap: 8px; align-items: center; flex-wrap: nowrap; margin-left: auto; }",
        ".pager-info { font-size: 11px; color: var(--faint); margin-top: 0;",
        "font-variant-numeric: tabular-nums; }",
        "class=\"tb-group\"",
        "class=\"tb-group tb-pager\"",
        "<span class=\"pager-info\" id=\"req-page-info\">—</span>",
        "<span class=\"pager-info\" id=\"cmd-page-info\">—</span>",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    // .toolbar 外层仍须保留折行能力：#range-bar 也复用该类，不能被改成 nowrap。
    assert!(
        CONSOLE_HTML
            .contains(".toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center;"),
        "外层 .toolbar 须保留 flex-wrap:wrap"
    );
}

#[test]
fn console_html_layout_narrow_viewport_fallback() {
    // 1024px 下筛选组宽度远超工具栏内宽：不放开组内折行必横向溢出。
    for needle in [
        "@media (max-width: 1100px) {",
        ".tb-group { flex-wrap: wrap; }",
        ".tb-pager { flex-wrap: nowrap; flex-basis: 100%; }",
        ".tb-group, .tb-pager { flex-wrap: wrap; }",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_layout_request_filter_group_nowrap_above_1100() {
    // 规范「在 >1100px 时组内控件 SHALL NOT 折行」：筛选组须靠收窄控件自身宽度在
    // 1280px（面板内宽 ≈938px）下容身，MUST NOT 用媒体查询放开组内折行。
    for needle in [
        "#sec-requests .tb-group:not(.tb-pager) input,",
        "#sec-requests .tb-group:not(.tb-pager) select { min-width: 0; }",
        "#sec-requests .tb-group:not(.tb-pager) input { width: 110px; }",
        "#sec-requests .tb-group:not(.tb-pager) select { width: 120px; }",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    assert!(
        !CONSOLE_HTML.contains("max-width: 1440px)"),
        "不得保留任何在 >1100px 放开组内折行的媒体查询"
    );
    // 动作控件移入分页组：`#req-apply` / `#req-live` 须位于 `.tb-group.tb-pager` 之内，
    // 筛选组只剩 6 个过滤控件（组内 min-content 不再含按钮宽度）。
    let pager = CONSOLE_HTML
        .find("id=\"req-apply\"")
        .and_then(|pos| CONSOLE_HTML[..pos].rfind("<div class=\"tb-group tb-pager\">"))
        .expect("`#req-apply` 须位于请求分页组内");
    let pager_block = &CONSOLE_HTML[pager..];
    let pager_end = pager_block
        .find("</div>\n          </div>")
        .expect("分页组须以闭合标签收尾");
    let pager_html = &pager_block[..pager_end];
    for needle in [
        "id=\"req-apply\"",
        "id=\"req-live\"",
        "id=\"req-prev\"",
        "id=\"req-next\"",
        "id=\"req-page-info\"",
    ] {
        assert!(
            pager_html.contains(needle),
            "请求分页组须含 {needle:?}: {pager_html}"
        );
    }
}

#[test]
fn console_html_bucket_bounds_match_metrics_latency_bounds() {
    // 漂移守卫：控制台延迟桶上界字面量与 `metrics::aggregate::LATENCY_BOUNDS_MS` 必须
    // 逐元素相等，任一侧单改即 `cargo test` 失败（否则图表桶标签与服务端桶口径错位）。
    const NEEDLE: &str = "var BUCKET_BOUNDS = [";
    let start = CONSOLE_HTML
        .find(NEEDLE)
        .expect("壳须含 BUCKET_BOUNDS 字面量")
        + NEEDLE.len();
    let rest = &CONSOLE_HTML[start..];
    let end = rest.find(']').expect("BUCKET_BOUNDS 须以 ] 收尾");
    let console_bounds: Vec<u64> = rest[..end]
        .split(',')
        .map(|part| {
            part.trim()
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("BUCKET_BOUNDS 元素非法 {part:?}: {e}"))
        })
        .collect();
    assert_eq!(
        console_bounds,
        crate::service::metrics::aggregate::LATENCY_BOUNDS_MS.to_vec(),
        "控制台 BUCKET_BOUNDS 须与服务端 LATENCY_BOUNDS_MS 逐元素一致"
    );
}

#[test]
fn console_html_layout_dist_panel_equal_height() {
    // 同排面板等高：.grid2 由 start 改 stretch，分布面板内部为纵向弹性布局。
    for needle in [
        ".grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; align-items: stretch; }",
        ".dist-panel { display: flex; flex-direction: column; }",
        ".dist-panel .dist-body { flex: 1; display: flex; flex-direction: column; }",
        ".dist-panel .dist-body > .empty { flex: 1; }",
        ".dist-panel #model-box { flex: 1; }",
        "class=\"panel dist-panel\"",
        "class=\"dist-body\" id=\"pii-box\"",
        "class=\"dist-body\" id=\"proto-box\"",
        "class=\"dist-body\" id=\"model-box\"",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_layout_summary_column_is_elastic() {
    // 摘要列上限随视口弹性收缩；定长 + white-space:nowrap 的组合是上限生效的前提。
    // 12 列表头后上限收到 8vw（≤240px），保证 1280px 下不横向溢出。
    assert!(
        CONSOLE_HTML.contains("td.sum { max-width: clamp(96px, 8vw, 240px);"),
        "摘要列须为 clamp 弹性上限"
    );
    assert!(
        !CONSOLE_HTML.contains("td.sum { max-width: 420px;"),
        "固定 420px 上限会让表格在 1280px 下超出容器"
    );
    assert!(
        CONSOLE_HTML.contains("overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }"),
        "摘要列的省略号截断与 nowrap 须保留"
    );
}

#[test]
fn console_html_layout_command_status_is_enum_select() {
    // 命令页审批状态由自由文本改为枚举下拉，消除 placeholder 截断与非法取值。
    for needle in [
        "<select id=\"cmd-status\" aria-label=\"审批状态过滤\">",
        "<option value=\"\">审批状态：全部</option>",
        "<option value=\"approved\">approved</option>",
        "<option value=\"denied\">denied</option>",
        "<option value=\"timeout\">timeout</option>",
        "<option value=\"not_required\">not_required</option>",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    assert!(
        !CONSOLE_HTML.contains("<input id=\"cmd-status\""),
        "审批状态过滤器不得再为自由文本输入"
    );
    // 空值（全部）不拼参数：守卫与读取点均不变。
    for needle in [
        "state.cmdStatus = $('cmd-status').value.trim();",
        "if (state.cmdStatus) q += '&approval_status=' + encodeURIComponent(state.cmdStatus);",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_layout_dist_bars_unified_horizontal() {
    // 三张分布图统一走横向条入口；drawPiiBars 保留为薄封装（测试锚点）。
    for needle in [
        "function drawDistBars(boxId, data, tips) {",
        "function drawPiiBars(boxId, stats) {",
        "drawPiiBars('pii-box', piiStats);",
        "drawDistBars(boxId, data, tips);",
        "drawBarsH(box, pairs, tips, SVGNS, max, 'barg-' + boxId, null, distLabelW || null);",
        // 三图标签列宽须共享同一取值，逐图按自身 maxLab 计算会导致左边界不对齐。
        "function sharedDistLabelW(piiStats, protoData, modelData) {",
        "distLabelW = sharedDistLabelW(piiStats, m.per_protocol, m.per_model);",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
}

#[test]
fn console_html_layout_resize_redraw_visible_only() {
    // 无 viewBox 的横向条在窗口变窄后只被裁切：须 300ms 去抖重绘，且只重绘可见分区
    // （隐性分区 clientWidth 为 0，会算出兜底宽度）。
    for needle in [
        "var resizeTimer = 0;",
        "window.addEventListener('resize', function () {",
        "if (resizeTimer) clearTimeout(resizeTimer);",
        "resizeTimer = setTimeout(function () {",
        "}, 300);",
        "if (!$('sec-redaction').hidden && state.metrics) renderDist(state.metrics);",
        "if (!$('sec-overview').hidden && state.series) renderTrend(state.series);",
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
