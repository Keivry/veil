//! `[session]` 配置测试：默认链、全部拒绝分支、迁移建议数组边界与 Debug 脱敏。

use super::{
    SESSION_ALIAS_MAX_ENTRIES_DEFAULT,
    SESSION_HEADER_DEFAULTS,
    SessionFileConfig,
    SessionParts,
    alias_migration_suggestion,
    headers_migration_suggestion,
    load,
};

fn file(headers: Option<Vec<&str>>, alias_max_entries: Option<usize>) -> SessionFileConfig {
    SessionFileConfig {
        headers: headers.map(|list| list.into_iter().map(str::to_string).collect()),
        alias_max_entries,
    }
}

#[test]
fn default_parts_follow_design_d6_order() {
    let parts = SessionParts::default();
    assert_eq!(
        parts.headers,
        vec![
            "x-veil-conversation-id".to_string(),
            "x-opencode-session".to_string(),
            "x-opencode-session-id".to_string(),
        ],
        "默认链顺序须与 design D6 一致"
    );
    assert_eq!(
        parts.headers,
        SESSION_HEADER_DEFAULTS
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(parts.alias_max_entries, 1024);
    assert_eq!(parts.alias_max_entries, SESSION_ALIAS_MAX_ENTRIES_DEFAULT);
}

#[test]
fn absent_section_falls_back_to_defaults() {
    assert_eq!(load(None).expect("缺省须合法"), SessionParts::default());
    assert_eq!(
        load(Some(SessionFileConfig::default())).expect("空分节须合法"),
        SessionParts::default()
    );
}

#[test]
fn debug_does_not_leak_header_names() {
    let parts = SessionParts::default();
    let debug = format!("{parts:?}");
    for name in SESSION_HEADER_DEFAULTS {
        assert!(!debug.contains(name), "Debug 不得输出头名 {name}: {debug}");
    }
    assert!(
        debug.contains("[redacted]"),
        "Debug 须显式标注已脱敏: {debug}"
    );

    let file_cfg = file(Some(vec!["x-client-session"]), Some(8));
    let debug = format!("{file_cfg:?}");
    assert!(
        !debug.contains("x-client-session"),
        "Debug 不得输出头名: {debug}"
    );

    let headers = super::SessionHeaders::new(vec!["x-client-session".to_string()]);
    let debug = format!("{headers:?}");
    assert!(
        !debug.contains("x-client-session"),
        "Debug 不得输出头名: {debug}"
    );
    assert_eq!(headers.primary(), "x-client-session");
    assert_eq!(headers.len(), 1);
    assert!(!headers.is_empty());
}

#[test]
fn legal_custom_header_loads() {
    let parts = load(Some(file(
        Some(vec!["x-client-session", "x-client-tenant"]),
        Some(2048),
    )))
    .expect("合法自定义头须可加载");
    assert_eq!(
        parts.headers,
        vec![
            "x-client-session".to_string(),
            "x-client-tenant".to_string()
        ]
    );
    assert_eq!(parts.alias_max_entries, 2048);
}

#[test]
fn empty_array_rejected_naming_key() {
    let err = load(Some(file(Some(Vec::new()), None))).expect_err("空数组须拒");
    let message = err.to_string();
    assert!(
        message.contains("[session].headers") && message.contains("空"),
        "须指名该键与空数组原因: {message}"
    );
}

#[test]
fn invalid_header_name_rejected_naming_entry() {
    for bad in ["bad header", "x-bad\r\n", "", "x-session:1"] {
        let err =
            load(Some(file(Some(vec![bad]), None))).expect_err(&format!("非法头名 {bad:?} 须拒"));
        let message = err.to_string();
        assert!(
            message.contains("[session].headers") && message.contains("第 1 项"),
            "须指名字段与条目序号: {message}"
        );
    }
}

#[test]
fn case_insensitive_duplicate_rejected() {
    let err = load(Some(file(Some(vec!["X-Session", "x-session"]), None))).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("[session].headers") && message.contains("重复"),
        "须指名重复并说明大小写归一: {message}"
    );
    // 归一后不重复的不同头名须放行。
    assert!(
        load(Some(file(Some(vec!["X-Client-A", "x-client-b"]), None))).is_ok(),
        "仅大小写不同才是重复"
    );
}

#[test]
fn reserved_and_untrusted_headers_rejected() {
    for reserved in [
        "authorization",
        "X-Api-Key",
        "api-key",
        "host",
        "content-length",
        "content-encoding",
        "accept-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    ] {
        let err = load(Some(file(Some(vec![reserved]), None)))
            .expect_err(&format!("保留头名 {reserved:?} 须拒"));
        let message = err.to_string();
        assert!(
            message.contains(reserved) && message.contains("[session].headers"),
            "错误须指名被拒头名 {reserved}: {message}"
        );
    }
    let err = load(Some(file(Some(vec!["cookie"]), None))).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("cookie") && message.contains("保留鉴权/传输头名"),
        "cookie 须按保留头名拒绝: {message}"
    );
}

#[test]
fn untrusted_session_identifiers_rejected() {
    for untrusted in [
        "x-opencode-parent-session-id",
        "X-Session-Affinity",
        "x-session-id",
    ] {
        let err = load(Some(file(Some(vec![untrusted]), None)))
            .expect_err(&format!("不可信头名 {untrusted:?} 须拒"));
        let message = err.to_string();
        assert!(
            message.contains("不可信"),
            "错误须说明不可信理由（{untrusted}）: {message}"
        );
    }
}

#[test]
fn alias_zero_rejected_naming_key() {
    let err = load(Some(file(None, Some(0)))).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("[session].alias_max_entries") && message.contains("≥ 1"),
        "须指名该键与合法下界: {message}"
    );
    // 1 是合法下界。
    assert_eq!(
        load(Some(file(None, Some(1))))
            .expect("1 须合法")
            .alias_max_entries,
        1
    );
}

#[test]
fn whitespace_padded_header_name_rejected() {
    // 静默 trim 会掩盖 CRLF 注入形态，故两端空白按非法头名处理。
    let err = load(Some(file(Some(vec!["  x-client-session  "]), None)))
        .expect_err("两端空白须按非法头名拒绝");
    assert!(err.to_string().contains("[session].headers"), "{err}");
}

/// 迁移建议：五类边界（空 / 自定义 / 等于回退头 / 命中三个不可信名 / 命中 cookie）。
#[test]
fn headers_migration_suggestion_covers_boundaries() {
    // ① 旧 key_header 为空 → 默认链原样。
    let empty = headers_migration_suggestion(Some(""));
    assert!(
        empty.contains(
            "headers = [\"x-veil-conversation-id\", \"x-opencode-session\", \"x-opencode-session-id\"]"
        ),
        "空旧值须给出默认完整数组: {empty}"
    );
    assert!(empty.contains("可直接省略"), "空旧值须说明可省略: {empty}");

    // ② 自定义 → 首项 + 默认回退两项。
    let custom = headers_migration_suggestion(Some("x-client-session"));
    assert!(
        custom.contains(
            "headers = [\"x-client-session\", \"x-opencode-session\", \"x-opencode-session-id\"]"
        ),
        "自定义旧值须给出完整建议数组: {custom}"
    );

    // ③ 等于回退头 → 去重后仍三项，不重复。
    let fallback = headers_migration_suggestion(Some("X-OpenCode-Session"));
    assert!(
        fallback.contains("headers = [\"X-OpenCode-Session\", \"x-opencode-session-id\"]"),
        "回退头须按大小写归一后去重: {fallback}"
    );

    // ④ 命中三个不可信名 → 明确告知无法等价迁移。
    for untrusted in [
        "x-opencode-parent-session-id",
        "x-session-affinity",
        "x-session-id",
    ] {
        let text = headers_migration_suggestion(Some(untrusted));
        assert!(
            text.contains("无法等价迁移") && text.contains(untrusted),
            "{untrusted} 须告知无法等价迁移: {text}"
        );
    }

    // ⑤ 命中 cookie → 同样无法等价迁移。
    let cookie = headers_migration_suggestion(Some("cookie"));
    assert!(
        cookie.contains("无法等价迁移") && cookie.contains("cookie"),
        "cookie 须告知无法等价迁移: {cookie}"
    );

    // 保留名（如 authorization）亦不可等价迁移。
    let auth = headers_migration_suggestion(Some("authorization"));
    assert!(auth.contains("无法等价迁移"), "保留名须告知: {auth}");
}

#[test]
fn headers_migration_suggestion_rejects_invalid_header_name() {
    for bad in ["bad header", "x-session:1", "x bad"] {
        let text = headers_migration_suggestion(Some(bad));
        assert!(
            text.contains("无法等价迁移"),
            "非法头名 {bad:?} 须告知无法等价迁移: {text}"
        );
        assert!(
            !text.contains("headers = ["),
            "非法头名 {bad:?} 不得产出不可加载的建议数组: {text}"
        );
    }
}

#[test]
fn alias_migration_suggestion_mentions_entry_semantics() {
    let explicit = alias_migration_suggestion(Some(64));
    assert!(explicit.contains("alias_max_entries = 64"), "{explicit}");
    assert!(
        explicit.contains("按别名条目计") && explicit.contains("两条"),
        "须说明条目计口径: {explicit}"
    );
    let absent = alias_migration_suggestion(None);
    assert!(absent.contains("[session].alias_max_entries"), "{absent}");
    assert!(absent.contains("1024"), "须写明新缺省: {absent}");
}

/// 建议数组本身须是可加载的合法头链（除「无法等价迁移」分支外）。
#[test]
fn suggested_arrays_are_loadable() {
    for old in [None, Some(""), Some("x-client-session"), Some("X-Session")] {
        let text = headers_migration_suggestion(old);
        let list = text
            .split("headers = [")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("建议文本须含数组");
        let names: Vec<&str> = list
            .split(',')
            .map(|item| item.trim().trim_matches('"'))
            .collect();
        let parts = load(Some(file(Some(names), None)))
            .unwrap_or_else(|e| panic!("建议数组须可加载（{old:?}）: {e}"));
        assert!(!parts.headers.is_empty());
    }
}
