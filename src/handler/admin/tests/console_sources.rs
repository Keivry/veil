//! 控制台「会话」列来源/作用域文案单测（从 `console.rs` 拆出以守住 1200 行预算）。
//!
//! 锁定 5.2 的 8 类来源人类可读映射、旧库 `prev_message` 兼容 fallback、
//! request 模式 PII 逐请求提示，以及链概念已移除。

use crate::handler::admin::console::CONSOLE_HTML;

#[test]
fn console_html_request_source_labels_and_hint_wired() {
    for needle in [
        "var REQUEST_SOURCE_LABELS = {",
        "header: '显式会话头',",
        "conversation: 'Responses 会话对象',",
        "prev_response: '前驱响应',",
        "cache_key: 'prompt_cache_key',",
        "user_id: '用户标识',",
        "safety_identifier: '安全标识',",
        "user: '用户',",
        "none: '无来源'",
        "var REQUEST_SOURCE_LEGACY = { prev_message: '历史来源' };",
        "function requestSourceLabel(raw) {",
        "function requestSourceTitle(raw, piiMode) {",
        "title += '（旧版本数据）';",
        "title += '（request 模式：PII 逐请求）';",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    // 现行映射对象内不得混入 `prev_message`：它只能出现在兼容回退对象里。
    let labels_start = CONSOLE_HTML
        .find("var REQUEST_SOURCE_LABELS = {")
        .expect("壳须含 REQUEST_SOURCE_LABELS");
    let labels_end = labels_start
        + CONSOLE_HTML[labels_start..]
            .find("};")
            .expect("REQUEST_SOURCE_LABELS 须以 }; 收尾");
    let labels_block = &CONSOLE_HTML[labels_start..labels_end];
    assert!(
        !labels_block.contains("prev_message"),
        "现行来源映射不得包含 prev_message: {labels_block}"
    );
    assert!(
        CONSOLE_HTML.contains("var scope = it.session_scope === 'session' ? '会话' :\n      (it.session_scope === 'user' ? '用户' : '');"),
        "作用域徽标须仅为「会话」/「用户」，其余为空"
    );
    for needle in [
        "id=\"req-source-hint\"",
        "request 模式下 PII 按逐请求隔离，不跨请求共享。",
        "conversation 模式下 PII 在同一会话内共享。",
        "var piiMode = (state.metrics && state.metrics.pii_scope && state.metrics.pii_scope.mode) || '';",
    ] {
        assert!(CONSOLE_HTML.contains(needle), "壳须含 {needle:?}");
    }
    let chain_badge = concat!("链", "徽标");
    for absent in [chain_badge, "wide-chain", "chain-badge", "is_chain"] {
        assert!(
            !CONSOLE_HTML.contains(absent),
            "壳不得再含已移除的链概念: {absent:?}"
        );
    }
}
