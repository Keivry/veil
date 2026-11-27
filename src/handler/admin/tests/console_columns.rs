//! 记录表列宽引擎单测：固定布局/手柄锚点、列宽解析与钳制、会话 title 隐私边界。
//! 从 `console.rs` 拆出以守住 1200 行测试预算；DOM 行为由浏览器验收覆盖。

use crate::handler::admin::console::CONSOLE_HTML;

const START: &str = "/* @veil-testable:start */";
const END: &str = "/* @veil-testable:end */";

#[test]
fn console_html_record_tables_have_fixed_layout_and_resizers() {
    for needle in [
        "#ev-table, #cmd-table, #req-table { table-layout: fixed; width: 100%; }",
        ".col-resizer {",
        "setAttribute('role', 'separator')",
        "setAttribute('aria-orientation', 'vertical')",
        "var COLUMN_DEFAULTS = {",
        "window.VEIL_COLUMNS = { init: initTableColumns };",
        "function initTableColumns(tableId)",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    assert!(
        !CONSOLE_HTML.contains("td:nth-child(2) { max-width"),
        "模型列不得再由列位固定 max-width 约束"
    );
    assert!(
        CONSOLE_HTML.contains("function sessionTitle(session, sourceTitle)"),
        "会话 title 须由可测纯函数组合"
    );
    assert!(
        CONSOLE_HTML.contains("if (sec === 'events')")
            && CONSOLE_HTML.contains("window.VEIL_COLUMNS.init('ev')"),
        "事件分区须接入列宽引擎"
    );
    assert!(
        CONSOLE_HTML.contains("'<td class=\"sum\">' + esc(e.summary || '') + '</td>'"),
        "事件表摘要不得叠加逐单元格 title"
    );
    assert!(
        CONSOLE_HTML.contains("var map = mergeColWidths(loadColWidths(), fixed);"),
        "保存列宽前须合并 Cookie 中其他表的旧值"
    );
}

#[test]
fn console_column_engine_executes_in_node() {
    let anchor = CONSOLE_HTML
        .find("function parseColWidths")
        .expect("壳须含 parseColWidths");
    let start = CONSOLE_HTML[..anchor]
        .rfind(START)
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
        return;
    }

    let harness = r#"
var out = {};
out.clamp_3000 = clampColWidth(3000, 44);
out.clamp_10 = clampColWidth(10, 44);
out.clamp_44 = clampColWidth(44, 44);
out.clamp_100 = clampColWidth(100, 44);
out.clamp_nan = clampColWidth(NaN, 44);
out.floor_44 = columnFloor(44);
out.floor_60 = columnFloor(60);
var valid = 'v1.req:8-11-6-10-10-6-10-6-6-6-6-10';
var p = parseColWidths(valid, { req: 12, cmd: 8, ev: 5 });
out.req = p.req || null;
out.ev_missing = !p.ev;
out.bad_prefix = Object.keys(parseColWidths('v2.req:8-11-6-10-10-6-10-6-6-6-6-10', { req: 12 })).length;
out.bad_count = Object.keys(parseColWidths('v1.req:8-11', { req: 12 })).length;
out.bad_value = Object.keys(parseColWidths('v1.req:8-11-6-10-10-6-10-6-6-6-6-12abc', { req: 12 })).length;
out.bad_big = Object.keys(parseColWidths('v1.req:8-11-6-10-10-6-10-6-6-6-6-3000', { req: 12 })).length;
out.bad_neg = Object.keys(parseColWidths('v1.req:8-11-6-10-10-6-10-6-6-6-6--5', { req: 12 })).length;
out.bad_sci = Object.keys(parseColWidths('v1.req:8-11-6-10-10-6-10-6-6-6-6-1e3', { req: 12 })).length;
out.bad_hex = Object.keys(parseColWidths('v1.req:8-11-6-10-10-6-10-6-6-6-6-0x38', { req: 12 })).length;
out.bad_float = Object.keys(parseColWidths('v1.req:8-11-6-10-10-6-10-6-6-6-6-56.5', { req: 12 })).length;
var mixed = parseColWidths(
  'v1.ev:12-14-20-14-40~req:8-11-6-10-10-6-10-6-6-6-6-3000~cmd:9-11-17-17-12-12-8-14',
  { ev: 5, cmd: 8, req: 12 }
);
out.mixed_ev = mixed.ev || null;
out.mixed_cmd = mixed.cmd || null;
out.mixed_req_missing = !mixed.req;
out.encoded = encodeColWidths({
  req: [8, 11, 6, 10, 10, 6, 10, 6, 6, 6, 6, 10],
  ev: [12, 14, 20, 14, 40]
});
var merged = mergeColWidths(
  { cmd: [9, 11, 17, 17, 12, 12, 8, 14], ev: [12, 14, 20, 14, 40] },
  { req: [8, 11, 6, 10, 10, 6, 10, 6, 6, 6, 6, 10] }
);
out.merge_cmd = merged.cmd || null;
out.merge_req = merged.req || null;
out.merge_encoded = encodeColWidths(merged);
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
        "clamp_3000": 2000,
        "clamp_10": 44,
        "clamp_44": 44,
        "clamp_100": 100,
        "clamp_nan": 44,
        "floor_44": 44,
        "floor_60": 56,
        "req": [8, 11, 6, 10, 10, 6, 10, 6, 6, 6, 6, 10],
        "ev_missing": true,
        "bad_prefix": 0,
        "bad_count": 0,
        "bad_value": 0,
        "bad_big": 0,
        "bad_neg": 0,
        "bad_sci": 0,
        "bad_hex": 0,
        "bad_float": 0,
        "mixed_ev": [12, 14, 20, 14, 40],
        "mixed_cmd": [9, 11, 17, 17, 12, 12, 8, 14],
        "mixed_req_missing": true,
        "encoded": "v1.ev:12-14-20-14-40~req:8-11-6-10-10-6-10-6-6-6-6-10",
        "merge_cmd": [9, 11, 17, 17, 12, 12, 8, 14],
        "merge_req": [8, 11, 6, 10, 10, 6, 10, 6, 6, 6, 6, 10],
        "merge_encoded": "v1.ev:12-14-20-14-40~cmd:9-11-17-17-12-12-8-14~req:8-11-6-10-10-6-10-6-6-6-6-10"
    });
    assert_eq!(verdict, expected, "列宽解析/钳制/编码须与契约一致");
}

#[test]
fn console_session_title_executes_in_node() {
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

    let node_ready = std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if !node_ready {
        return;
    }

    let harness = r#"
var out = {};
out.full = sessionTitle('9f2c8a1b4d5e', '来源：Responses 会话对象');
out.no_source = sessionTitle('9f2c8a1b4d5e', '');
out.source_only = sessionTitle('', '来源：用户标识');
out.empty = sessionTitle('', '');
out.sixteen = sessionTitle('0123456789abcdef', '');
out.sixteen_leaks = out.sixteen.indexOf('0123456789abcdef') !== -1;
out.sixty4 = sessionTitle('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', '');
out.sixty4_leaks = out.sixty4.indexOf('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') !== -1;
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
        "full": "会话摘要：9f2c8a1b4d5e\n来源：Responses 会话对象",
        "no_source": "会话摘要：9f2c8a1b4d5e",
        "source_only": "来源：用户标识",
        "empty": "",
        "sixteen": "会话摘要：0123456789ab",
        "sixteen_leaks": false,
        "sixty4": "会话摘要：0123456789ab",
        "sixty4_leaks": false
    });
    assert_eq!(verdict, expected, "会话 title 只含 12 位摘要与来源说明");
}
