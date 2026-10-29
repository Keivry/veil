//! `[llm.targets]` schema 与校验单测（tasks 1.1–1.3 与 1.5 的纯校验面）。
//!
//! schema 层（未知键 / 类型 / 协议键集合）经 `toml::from_str::<FileConfig>` 断言；
//! 字段级（目标键 / 头 / 保留键 / 孤儿目标）经 `validate_targets` 与
//! `validate_target_upstreams` 断言，错误消息须指名完整键路径。

use {
    super::*,
    crate::config::{
        Config,
        FileConfig,
        apply_config_file,
        env_parse::test_support::base_env,
        file_layer::BOOTSTRAP_VAR,
    },
    serde_json::json,
    std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU32, Ordering},
    },
};

/// 解析 TOML 为文件 schema（含 `[llm.targets]`），schema 非法即 panic。
fn parse_file(text: &str) -> FileConfig { toml::from_str(text).expect("schema 须可解析") }

/// 取原始目标表（样例须已声明 `[llm.targets]`）。
fn raw_targets(text: &str) -> RawTargets {
    parse_file(text)
        .llm
        .and_then(|section| section.targets)
        .expect("样例须含 [llm.targets]")
}

/// 原始 schema → 强类型目标表的校验结果。
fn validated(text: &str) -> Result<LlmTargets> { validate_targets(Some(&raw_targets(text))) }

/// 校验失败的错误消息（用例须为 fail-closed）。
fn err_msg(text: &str) -> String { validated(text).expect_err("须拒绝启动").to_string() }

/// TOML schema 层（未知键 / 类型）失败的错误消息。
fn parse_err_msg(text: &str) -> String {
    toml::from_str::<FileConfig>(text)
        .expect_err("schema 须拒解析")
        .to_string()
}

/// 取 `HeaderValueSpec` 的静态值文本（模板或不可见字符返回 `None`）。
fn static_text(spec: &HeaderValueSpec) -> Option<&str> {
    match spec {
        HeaderValueSpec::Static(value) => value.to_str().ok(),
        HeaderValueSpec::Template(_) => None,
    }
}

const VALID_TOML: &str = r#"
[llm.targets."8878"]
user_agent = "opencode/1.18.33"

[llm.targets."8878".headers]
anthropic-version = "2023-06-01"
x-custom = "1"

[llm.targets."8878".params.anthropic]
default = { thinking = { type = "enabled", budget_tokens = 1024 } }
override = { temperature = 0.2 }
drop = ["metadata", "top_k"]

[llm.targets."8878".params.chat]
default = { temperature = 0.7 }

[llm.targets."8878".params.responses]
override = { reasoning = { effort = "high" } }

[llm.targets.default.headers]
x-custom = "1"
"#;

#[test]
fn valid_sample_with_port_default_and_three_protocols_validates() {
    let targets = validated(VALID_TOML).expect("合法样例须通过校验");
    assert_eq!(targets.len(), 2, "端口目标与 default 目标各一");

    let port = targets
        .get(&TargetKey::Port(8878))
        .expect("端口目标须在结果中");
    assert_eq!(
        port.user_agent
            .as_ref()
            .and_then(|value| value.to_str().ok()),
        Some("opencode/1.18.33"),
        "user_agent 须随合法样例进入强类型载荷"
    );
    assert_eq!(
        port.headers.get("anthropic-version").and_then(static_text),
        Some("2023-06-01")
    );
    assert_eq!(
        port.headers.get("x-custom").and_then(static_text),
        Some("1")
    );
    assert_eq!(port.params.len(), 3, "三协议子表须逐项进入");

    let anthropic = port
        .params
        .get(&ParamProtocol::Anthropic)
        .expect("anthropic 子表须在");
    assert_eq!(
        anthropic.default.get("thinking"),
        Some(&json!({"type": "enabled", "budget_tokens": 1024}))
    );
    assert_eq!(anthropic.r#override.get("temperature"), Some(&json!(0.2)));
    assert_eq!(
        anthropic.drop,
        vec!["metadata".to_string(), "top_k".to_string()]
    );

    let chat = port
        .params
        .get(&ParamProtocol::Chat)
        .expect("chat 子表须在");
    assert_eq!(chat.default.get("temperature"), Some(&json!(0.7)));
    assert!(chat.r#override.is_empty());
    assert!(chat.drop.is_empty());

    let responses = port
        .params
        .get(&ParamProtocol::Responses)
        .expect("responses 子表须在");
    assert_eq!(
        responses.r#override.get("reasoning"),
        Some(&json!({"effort": "high"}))
    );

    let default = targets
        .get(&TargetKey::Default)
        .expect("保留键 default 目标须在");
    assert_eq!(
        default.headers.get("x-custom").and_then(static_text),
        Some("1")
    );
    assert!(default.params.is_empty());
}

#[test]
fn absent_or_empty_targets_yield_empty_typed_table() {
    assert_eq!(
        validate_targets(None).expect("缺省须合法"),
        LlmTargets::new()
    );
    let targets = validated("[llm.targets]\n").expect("空分节须合法");
    assert!(targets.is_empty());
}

#[test]
fn invalid_target_keys_rejected_naming_legal_forms() {
    for raw in ["abc", "0x22b6", "70000", "-1", "", " 8878"] {
        let text = format!("[llm.targets.{raw:?}.headers]\nx-custom = \"1\"\n");
        let msg = err_msg(&text);
        assert!(
            msg.contains("目标键") && msg.contains("default"),
            "键 {raw:?} 须指名合法目标键：{msg}"
        );
        assert!(msg.contains(raw), "错误须回显非法键 {raw:?}：{msg}");
    }
}

#[test]
fn normalized_duplicate_target_keys_rejected() {
    // "0078" 与 "78" 均为合法 u16 写法，归一后同指端口 78。
    let text = "[llm.targets.\"0078\".headers]\nx = \"1\"\n\
                [llm.targets.\"78\".headers]\ny = \"2\"\n";
    let msg = err_msg(text);
    assert!(
        msg.contains("0078") && msg.contains("78") && msg.contains("归一后重复"),
        "归一重复目标键须拒启动并指名：{msg}"
    );
}

#[test]
fn unknown_keys_rejected_by_schema_with_key_name() {
    for (text, needle, extra) in [
        ("[llm.targets.\"8878\"]\nfoo = 1\n", "foo", Some("headers")),
        (
            "[llm.targets.\"8878\".params]\ngemini = { default = { temperature = 1 } }\n",
            "gemini",
            Some("chat"),
        ),
        (
            "[llm.targets.\"8878\".params.chat]\nfoo = 1\n",
            "foo",
            Some("default"),
        ),
        (
            "[llm.targets.\"8878\".headers.extra.sub]\nx = \"1\"\n",
            "extra",
            None,
        ),
    ] {
        let msg = parse_err_msg(text);
        assert!(msg.contains(needle), "未知键 {needle} 须被指名：{msg}");
        if let Some(extra) = extra {
            assert!(
                msg.contains(extra),
                "未知键错误须列出合法键集合（含 {extra}）：{msg}"
            );
        }
    }
}

#[test]
fn type_violations_rejected_by_schema_with_key_name() {
    for (text, needle) in [
        ("[llm.targets.\"8878\".headers]\nx-num = 123\n", "x-num"),
        ("[llm.targets.\"8878\"]\nheaders = \"x\"\n", "headers"),
        ("[llm.targets.\"8878\"]\nparams = \"x\"\n", "params"),
        (
            "[llm.targets.\"8878\".params.chat]\ndefault = \"x\"\n",
            "default",
        ),
        (
            "[llm.targets.\"8878\".params.chat]\noverride = 1\n",
            "override",
        ),
        (
            "[llm.targets.\"8878\".params.chat]\ndrop = \"model\"\n",
            "drop",
        ),
        (
            "[llm.targets.\"8878\".params.chat]\ndrop = [1, 2]\n",
            "drop",
        ),
    ] {
        let msg = parse_err_msg(text);
        assert!(msg.contains(needle), "类型错误 {needle} 须被指名：{msg}");
    }
}

/// 构造仅含单条头声明的 TOML。
fn header_toml(name: &str, value_literal: &str) -> String {
    format!("[llm.targets.\"8878\".headers]\n{name:?} = {value_literal}\n")
}

#[test]
fn user_agent_string_parses_into_typed_payload() {
    // task 1.1：`user_agent` 为字符串键，合法声明进入强类型载荷且值保真。
    let targets = validated("[llm.targets.\"8878\"]\nuser_agent = \"opencode/1.18.33\"\n")
        .expect("合法 user_agent 须加载通过");
    assert_eq!(
        targets
            .get(&TargetKey::Port(8878))
            .expect("端口目标须在")
            .user_agent
            .as_ref()
            .and_then(|value| value.to_str().ok()),
        Some("opencode/1.18.33")
    );
}

#[test]
fn user_agent_non_string_rejected_by_schema_with_key_name() {
    // task 1.1 / NIT-1：`user_agent` 非字符串由 TOML 反序列化层拒绝并回显键值对（不静默忽略）。
    // serde/toml 层类型错误以「源码片段 +
    // 值」定位（无结构化完整键路径），故断言键值回显与类型措辞。
    let msg = parse_err_msg("[llm.targets.\"8878\"]\nuser_agent = 123\n");
    assert!(
        msg.contains("user_agent = 123") && msg.contains("expected a string"),
        "类型错误须回显键值对与期望类型：{msg}"
    );
}

#[test]
fn user_agent_empty_or_whitespace_rejected_naming_full_path() {
    // task 1.2：空串/全空白拒启动，错误指名完整键路径。
    for literal in ["\"\"", "\"   \"", "\"\\t\""] {
        let text = format!("[llm.targets.\"8878\"]\nuser_agent = {literal}\n");
        let msg = err_msg(&text);
        assert!(
            msg.contains("llm.targets.\"8878\".user_agent") && msg.contains("拒绝启动"),
            "空/全空白 user_agent {literal} 须拒启动并指名完整键路径：{msg}"
        );
    }
}

#[test]
fn user_agent_padded_whitespace_rejected_naming_full_path() {
    // NIT-2：含首尾空白拒启动（不静默修剪），错误指名完整键路径。
    for literal in [
        "\" opencode/1.0\"",
        "\"opencode/1.0 \"",
        "\"\\topencode/1.0\\t\"",
    ] {
        let text = format!("[llm.targets.\"8878\"]\nuser_agent = {literal}\n");
        let msg = err_msg(&text);
        assert!(
            msg.contains("llm.targets.\"8878\".user_agent") && msg.contains("首尾空白"),
            "含首尾空白 user_agent {literal} 须拒启动并指名完整键路径：{msg}"
        );
    }
}

#[test]
fn user_agent_crlf_rejected_naming_full_path() {
    // task 1.2：含 CR/LF 等非法字节拒启动，错误指名完整键路径。
    for literal in ["\"a\\r\\nb\"", "\"a\\nb\"", "\"a\\rb\""] {
        let text = format!("[llm.targets.\"8878\"]\nuser_agent = {literal}\n");
        let msg = err_msg(&text);
        assert!(
            msg.contains("llm.targets.\"8878\".user_agent") && msg.contains("CR/LF"),
            "含 CR/LF user_agent {literal} 须拒启动并指名：{msg}"
        );
    }
}

#[test]
fn user_agent_conflicting_with_headers_channel_rejected() {
    // task 1.2：`user_agent` 与 `headers` 归一后 `user-agent`（含大小写变体）互斥，
    // 错误指名两条 UA 通道。
    for header_name in ["user-agent", "User-Agent", "USER-AGENT"] {
        let text = format!(
            "[llm.targets.\"8878\"]\nuser_agent = \"opencode/1.18.33\"\n\
             [llm.targets.\"8878\".headers]\n{header_name:?} = \"x\"\n"
        );
        let msg = err_msg(&text);
        assert!(
            msg.contains("llm.targets.\"8878\".user_agent")
                && msg.contains("user-agent")
                && msg.contains("两条 User-Agent 覆盖通道"),
            "user_agent 与 {header_name} 并存须拒启动并指名两条通道：{msg}"
        );
    }
}

#[test]
fn user_agent_legal_value_enters_config_without_startup_error() {
    // task 1.2：合法值加载通过（含与其它键共存的形态）。
    let targets = validated(
        "[llm.targets.\"8878\"]\nuser_agent = \"opencode/1.18.33\"\noverride_existing = false\n\
         [llm.targets.\"8878\".headers]\nx-custom = \"1\"\n",
    )
    .expect("合法值须加载通过");
    assert_eq!(
        targets
            .get(&TargetKey::Port(8878))
            .expect("端口目标须在")
            .user_agent
            .as_ref()
            .and_then(|value| value.to_str().ok()),
        Some("opencode/1.18.33")
    );
}

#[test]
fn target_override_switch_parses_bool_and_defaults_true() {
    // override_existing = false / true / 未声明三种写法均加载通过，载荷分别为
    // false / true / true（缺省恒胜，向后兼容）。
    let targets = validated(
        "[llm.targets.\"8878\"]\noverride_existing = false\n\
         [llm.targets.\"8879\"]\noverride_existing = true\n\
         [llm.targets.default]\nheaders = { x-custom = \"1\" }\n",
    )
    .expect("三种写法均须加载通过");
    assert!(
        !targets
            .get(&TargetKey::Port(8878))
            .expect("端口 8878 目标须在")
            .override_existing,
        "override = false 须进合并模式"
    );
    assert!(
        targets
            .get(&TargetKey::Port(8879))
            .expect("端口 8879 目标须在")
            .override_existing,
        "override = true 须为恒胜"
    );
    assert!(
        targets
            .get(&TargetKey::Default)
            .expect("default 目标须在")
            .override_existing,
        "未声明 override 须缺省恒胜"
    );
}

#[test]
fn target_override_non_bool_rejected_with_key_name() {
    // override_existing 非布尔由 TOML 反序列化层拒绝并回显键名（不静默忽略）。
    let msg = parse_err_msg("[llm.targets.\"8878\"]\noverride_existing = \"x\"\n");
    assert!(
        msg.contains("override_existing"),
        "类型错误须回显键名 override_existing：{msg}"
    );
}

#[test]
fn hard_deny_reserved_headers_rejected_with_reason() {
    for name in [
        "host",
        "content-length",
        "content-encoding",
        "accept-encoding",
        "transfer-encoding",
    ] {
        let msg = err_msg(&header_toml(name, "\"1\""));
        assert!(
            msg.contains(name) && msg.contains("硬拒清单") && msg.contains("保留/长度与编码头"),
            "保留类头 {name} 须拒启动并指名理由：{msg}"
        );
    }
    // 配置重注入 `accept-encoding` 会破坏「reqwest 仅声明支持集、上游只回可解码编码」
    // 不变量（装配期已剔除该头），须以硬拒清单拒启动。
    let msg = err_msg(&header_toml("accept-encoding", "\"zstd\""));
    assert!(
        msg.contains("accept-encoding")
            && msg.contains("硬拒清单")
            && msg.contains("保留/长度与编码头"),
        "accept-encoding 配置重注入须拒启动并指名硬拒清单：{msg}"
    );
}

#[test]
fn hard_deny_hop_by_hop_headers_rejected_with_reason() {
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    ] {
        let msg = err_msg(&header_toml(name, "\"1\""));
        assert!(
            msg.contains(name) && msg.contains("硬拒清单") && msg.contains("逐跳头"),
            "逐跳头 {name} 须拒启动并指名理由：{msg}"
        );
    }
}

#[test]
fn hard_deny_veil_internal_headers_rejected_with_reason() {
    for name in ["x-veil-conversation-id", "X-Veil-Normalized", "x-VEIL-foo"] {
        let msg = err_msg(&header_toml(name, "\"1\""));
        assert!(
            msg.contains("x-veil") && msg.contains("硬拒清单") && msg.contains("内部头"),
            "x-veil-* 头 {name} 须拒启动并指名理由：{msg}"
        );
    }
}

#[test]
fn hard_deny_auth_headers_rejected_with_reason() {
    for name in [
        "authorization",
        "Authorization",
        "x-api-key",
        "api-key",
        "cookie",
    ] {
        let msg = err_msg(&header_toml(name, "\"1\""));
        assert!(
            msg.contains("硬拒清单") && msg.contains("鉴权/身份类头"),
            "鉴权/身份类头 {name} 须拒启动并指名理由：{msg}"
        );
    }
}

#[test]
fn invalid_header_name_rejected_with_reason() {
    for name in ["bad name", "x-foo()", "头名"] {
        let msg = err_msg(&header_toml(name, "\"1\""));
        assert!(
            msg.contains(name) && msg.contains("头名非法"),
            "非法头名 {name:?} 须拒启动并指名：{msg}"
        );
    }
}

#[test]
fn header_value_crlf_rejected_with_reason() {
    for literal in ["\"a\\r\\nb\"", "\"a\\nb\"", "\"a\\rb\""] {
        let msg = err_msg(&header_toml("x-note", literal));
        assert!(
            msg.contains("x-note") && msg.contains("CR/LF"),
            "含 CR/LF 头值 {literal} 须拒启动并指名：{msg}"
        );
    }
}

#[test]
fn header_value_invalid_bytes_rejected_with_reason() {
    let msg = err_msg(&header_toml("x-note", "\"\\u0001\""));
    assert!(
        msg.contains("x-note") && msg.contains("头值非法"),
        "非法头值字节须拒启动并指名：{msg}"
    );
}

#[test]
fn case_normalized_duplicate_headers_rejected() {
    let text = "[llm.targets.\"8878\".headers]\nX-Api-Version = \"1\"\nx-api-version = \"2\"\n";
    let msg = err_msg(text);
    assert!(
        msg.contains("X-Api-Version")
            && msg.contains("x-api-version")
            && msg.contains("归一后重复"),
        "大小写归一重复头须拒启动并指名两侧：{msg}"
    );
}

/// 单条头值的解析探针（键路径与头名固定，便于断言完整路径）。
fn parse_spec(value: &str) -> Result<HeaderValueSpec> {
    parse_header_value_spec(TargetKey::Port(8878), "x-dyn", value)
}

#[test]
fn header_value_spec_static_fast_path_and_template_segment_order() {
    // task 1.1：无 `$` 走静态快路径；三种插值、`$$` 转义与多片段混排段序正确。
    assert_eq!(
        parse_spec("cli").expect("静态值须解析"),
        HeaderValueSpec::Static(HeaderValue::from_static("cli"))
    );
    assert_eq!(
        parse_spec("$request-id").expect("请求 ID 模板须解析"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::RequestId])
    );
    assert_eq!(
        parse_spec("$header(x-session-id)").expect("镜像模板须解析"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Mirror(HeaderName::from_static(
            "x-session-id"
        ))])
    );
    // HeaderName 归一：大写镜像名解析后存小写。
    assert_eq!(
        parse_spec("$header(X-Session-Id)").expect("大写镜像名须解析"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Mirror(HeaderName::from_static(
            "x-session-id"
        ))])
    );
    assert_eq!(
        parse_spec("sid-$conversation-$$v1").expect("混排模板须解析"),
        HeaderValueSpec::Template(vec![
            HeaderValueSegment::Literal("sid-".to_string()),
            HeaderValueSegment::Conversation,
            HeaderValueSegment::Literal("-$v1".to_string()),
        ])
    );
    assert_eq!(
        parse_spec("$$").expect("纯转义须解析"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Literal("$".to_string())])
    );
}

#[test]
fn header_value_spec_variable_names_are_case_sensitive() {
    // task 1.1：变量名匹配大小写敏感——`$Conversation` 不匹配小写关键字，按未知形态拒启动。
    let msg = parse_spec("$Conversation")
        .expect_err("大写变量须拒启动")
        .to_string();
    assert!(
        msg.contains("未知插值形态")
            && msg.contains("Conversation")
            && msg.contains("$conversation"),
        "大小写不符须按未知形态拒启动并列出合法形态：{msg}"
    );
}

#[test]
fn header_value_spec_illegal_forms_rejected_naming_full_path() {
    // task 1.2：未知变量、结尾孤立 `$`、未闭合/嵌套 `$header(`、空/非法头名、
    // x-veil-* 命名空间镜像均 fail-closed，错误指名完整键路径与非法形态。
    let path = "llm.targets.\"8878\".headers.x-dyn";
    for (value, needle) in [
        ("$foo", "未知插值形态"),
        ("$conversationx", "未知插值形态"),
        ("$Request-Id", "未知插值形态"),
        ("abc$", "结尾孤立"),
        ("$header(x", "未闭合"),
        ("$header($header(x))", "嵌套"),
        ("$header()", "头名为空"),
        ("$header(a b)", "头名非法"),
        ("$header(x-veil-foo)", "x-veil-*"),
        ("$header($conversation)", "镜像名含"),
        ("$conversation_", "未知插值形态"),
    ] {
        let msg = parse_spec(value).expect_err("非法形态须拒启动").to_string();
        assert!(
            msg.contains(path),
            "非法形态 {value:?} 须指名完整键路径 {path}：{msg}"
        );
        assert!(
            msg.contains(needle) && msg.contains("拒绝启动"),
            "非法形态 {value:?} 须含描述 {needle:?}：{msg}"
        );
    }
}

#[test]
fn interpolation_forms_load_end_to_end() {
    // task 1.2：三种来源 + `$$` 混排经加载期校验通过，解析为强类型模板段。
    let targets = validated(
        "[llm.targets.\"8878\".headers]\n\
         x-opencode-session = \"$conversation\"\n\
         x-opencode-request = \"$request-id\"\n\
         x-mirror = \"$header(x-session-id)\"\n\
         x-mixed = \"sid-$conversation-$$v1\"\n",
    )
    .expect("合法插值形态须加载通过");
    let headers = &targets
        .get(&TargetKey::Port(8878))
        .expect("端口目标须在")
        .headers;
    assert_eq!(
        headers.get("x-opencode-session"),
        Some(&HeaderValueSpec::Template(vec![
            HeaderValueSegment::Conversation
        ]))
    );
    assert_eq!(
        headers.get("x-opencode-request"),
        Some(&HeaderValueSpec::Template(vec![
            HeaderValueSegment::RequestId
        ]))
    );
    assert_eq!(
        headers.get("x-mirror"),
        Some(&HeaderValueSpec::Template(vec![
            HeaderValueSegment::Mirror(HeaderName::from_static("x-session-id"))
        ]))
    );
    assert_eq!(
        headers.get("x-mixed"),
        Some(&HeaderValueSpec::Template(vec![
            HeaderValueSegment::Literal("sid-".to_string()),
            HeaderValueSegment::Conversation,
            HeaderValueSegment::Literal("-$v1".to_string()),
        ]))
    );
}

#[test]
fn interpolation_illegal_forms_rejected_at_load_naming_path() {
    // task 1.2：非法插值经加载期（validate_targets）拒启动并指名完整键路径。
    for (value_literal, needle) in [
        ("\"$foo\"", "未知插值形态"),
        ("\"$header(x\"", "未闭合"),
        ("\"$header(x-veil-foo)\"", "x-veil-*"),
        ("\"$header($conversation)\"", "镜像名含"),
        ("\"$conversation_\"", "未知插值形态"),
    ] {
        let msg = err_msg(&header_toml("x-dyn", value_literal));
        assert!(
            msg.contains("llm.targets.\"8878\".headers.x-dyn") && msg.contains(needle),
            "非法插值 {value_literal} 须经加载期拒启动并指名：{msg}"
        );
    }
}

#[test]
fn reserved_key_matrix_rejected_across_protocols_and_segments() {
    for protocol in ["chat", "anthropic", "responses"] {
        for segment in ["default", "override", "drop"] {
            for reserved in RESERVED_PARAM_KEYS {
                let line = match segment {
                    "default" => format!("default = {{ {reserved} = 1 }}"),
                    "override" => format!("override = {{ {reserved} = 1 }}"),
                    _ => format!("drop = [{reserved:?}]"),
                };
                let text = format!("[llm.targets.\"8878\".params.{protocol}]\n{line}\n");
                let msg = err_msg(&text);
                assert!(
                    msg.contains(reserved) && msg.contains("保留键"),
                    "保留键 {reserved} 在 {protocol}.{segment} 须拒启动并指名：{msg}"
                );
            }
        }
    }
}

#[test]
fn reserved_key_in_mixed_segment_still_rejected() {
    let text = "[llm.targets.\"8878\".params.chat]\n\
                override = { temperature = 0.2, model = \"m\" }\n";
    let msg = err_msg(text);
    assert!(
        msg.contains("model") && msg.contains("保留键") && msg.contains("chat.override"),
        "同段混排的保留键须拒启动并指名键路径：{msg}"
    );
}

#[test]
fn orphan_port_target_rejected_naming_port() {
    let targets = validated("[llm.targets.\"9000\".headers]\nx = \"1\"\n").expect("校验通过");
    let upstreams: HashMap<u16, String> = HashMap::new();
    let msg = validate_target_upstreams(&targets, &upstreams, Some("http://default:1"))
        .expect_err("孤儿目标须拒启动")
        .to_string();
    assert!(
        msg.contains("llm.targets.\"9000\"") && msg.contains("孤儿目标"),
        "须指名孤儿端口：{msg}"
    );

    let mut upstreams: HashMap<u16, String> = HashMap::new();
    upstreams.insert(8878, "http://other:1".to_string());
    let msg = validate_target_upstreams(&targets, &upstreams, None)
        .expect_err("非对应端口不得视为上游")
        .to_string();
    assert!(msg.contains("9000"), "须指名孤儿端口：{msg}");
}

#[test]
fn default_target_without_default_upstream_rejected() {
    let targets = validated("[llm.targets.default.headers]\nx = \"1\"\n").expect("校验通过");
    let mut upstreams: HashMap<u16, String> = HashMap::new();
    upstreams.insert(8878, "http://port:1".to_string());
    let msg = validate_target_upstreams(&targets, &upstreams, None)
        .expect_err("缺省上游未定义须拒启动")
        .to_string();
    assert!(
        msg.contains("llm.targets.default")
            && msg.contains("[llm].default_upstream")
            && msg.contains("已不再从进程 env 读取"),
        "须指名 default 目标缺缺省上游且为文件口径：{msg}"
    );
}

#[test]
fn linked_targets_pass_orphan_validation() {
    let targets = validated(VALID_TOML).expect("校验通过");
    let mut upstreams: HashMap<u16, String> = HashMap::new();
    upstreams.insert(8878, "http://port:1".to_string());
    validate_target_upstreams(&targets, &upstreams, Some("http://default:1"))
        .expect("端口目标有上游且 default 已定义须通过");

    // 仅端口目标时缺省上游可缺（不触发 default 依赖）。
    let port_only = validated("[llm.targets.\"8878\".headers]\nx = \"1\"\n").expect("校验通过");
    validate_target_upstreams(&port_only, &upstreams, None).expect("端口目标不要求缺省上游");
}

#[test]
fn default_only_target_passes_with_default_upstream() {
    let targets = validated("[llm.targets.default.headers]\nx = \"1\"\n").expect("校验通过");
    let empty: BTreeMap<u16, String> = BTreeMap::new();
    let upstreams: HashMap<u16, String> = empty.into_iter().collect();
    validate_target_upstreams(&targets, &upstreams, Some("http://default:1"))
        .expect("default 目标有缺省上游须通过");
}

/// 临时配置文件：每实例独立目录，`Drop` 整目录清理（并发用例互不干扰）。
struct TempConfigFile {
    dir: PathBuf,
    path: PathBuf,
}

impl TempConfigFile {
    fn new(name: &str, content: &str) -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "veil-config-targets-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("建临时目录");
        let path = dir.join(name);
        fs::write(&path, content).expect("写临时文件");
        Self { dir, path }
    }

    fn path(&self) -> &Path { &self.path }
}

impl Drop for TempConfigFile {
    fn drop(&mut self) { fs::remove_dir_all(&self.dir).ok(); }
}

/// 基础 env + 引导变量指向临时文件。
fn env_with_file(file: &TempConfigFile) -> HashMap<String, String> {
    let mut env = base_env();
    env.insert(
        BOOTSTRAP_VAR.to_string(),
        file.path().to_string_lossy().into_owned(),
    );
    env
}

#[test]
fn file_declared_targets_enter_config_with_file_upstream() {
    // `LLM_UPSTREAM` / `LLM_<port>` 只认文件键，进程 env 置位不生效。
    let file = TempConfigFile::new(
        "llm-targets.toml",
        &format!(
            "[llm]\ndefault_upstream = \"http://file-default:1\"\n\
             [llm.upstreams]\n\"8878\" = \"http://file-8878:1\"\n{VALID_TOML}"
        ),
    );
    let mut env = env_with_file(&file);
    let targets = apply_config_file(&mut env)
        .expect("文件层应用须成功")
        .llm_targets;
    let cfg = Config::load_from_with_targets(&env, targets).expect("文件上游可满足覆盖依赖");
    assert_eq!(
        cfg.llm_upstreams.get(&8878).map(String::as_str),
        Some("http://file-8878:1"),
        "端口上游须取自文件"
    );
    assert_eq!(
        cfg.llm_default_upstream.as_deref(),
        Some("http://file-default:1"),
        "缺省上游须取自文件"
    );

    let port = cfg
        .llm_targets
        .get(&TargetKey::Port(8878))
        .expect("端口覆盖须进入 Config 字段");
    assert_eq!(
        port.user_agent
            .as_ref()
            .and_then(|value| value.to_str().ok()),
        Some("opencode/1.18.33"),
        "user_agent 须随文件层进入 Config 字段"
    );
    assert_eq!(
        port.headers.get("anthropic-version").and_then(static_text),
        Some("2023-06-01")
    );
    let anthropic = port
        .params
        .get(&ParamProtocol::Anthropic)
        .expect("anthropic 子表须进入 Config 字段");
    assert_eq!(
        anthropic.default.get("thinking"),
        Some(&json!({"type": "enabled", "budget_tokens": 1024}))
    );
    assert_eq!(anthropic.r#override.get("temperature"), Some(&json!(0.2)));
    assert_eq!(
        anthropic.drop,
        vec!["metadata".to_string(), "top_k".to_string()]
    );

    let default = cfg
        .llm_targets
        .get(&TargetKey::Default)
        .expect("default 覆盖须进入 Config 字段");
    assert_eq!(
        default.headers.get("x-custom").and_then(static_text),
        Some("1")
    );
    assert!(default.params.is_empty());
}

#[test]
fn orphan_port_target_from_file_rejected_after_merge() {
    let file = TempConfigFile::new(
        "llm-targets-orphan.toml",
        "[llm.targets.\"9000\".headers]\nx = \"1\"\n",
    );
    let mut env = env_with_file(&file);
    let targets = apply_config_file(&mut env)
        .expect("字段校验先通过")
        .llm_targets;
    let err = Config::load_from_with_targets(&env, targets).expect_err("孤儿目标须拒启动");
    let msg = err.to_string();
    assert!(
        msg.contains("llm.targets.\"9000\"") && msg.contains("孤儿目标"),
        "须指名孤儿端口与理由: {msg}"
    );
}

#[test]
fn default_target_from_file_without_upstream_rejected() {
    let file = TempConfigFile::new(
        "llm-targets-default.toml",
        "[llm.targets.default.headers]\nx = \"1\"\n",
    );
    let mut env = env_with_file(&file);
    let targets = apply_config_file(&mut env)
        .expect("字段校验先通过")
        .llm_targets;
    let err = Config::load_from_with_targets(&env, targets).expect_err("缺省上游未定义须拒启动");
    let msg = err.to_string();
    assert!(
        msg.contains("llm.targets.default")
            && msg.contains("[llm].default_upstream")
            && msg.contains("已不再从进程 env 读取"),
        "须指名 default 目标缺缺省上游: {msg}"
    );
}

#[test]
fn file_default_upstream_and_file_port_upstreams_satisfy_targets() {
    let file = TempConfigFile::new(
        "llm-targets-file-upstreams.toml",
        "[llm]\ndefault_upstream = \"http://file-default:1\"\n\
         [llm.upstreams]\n\"8878\" = \"http://file-8878:1\"\n\
         [llm.targets.\"8878\".headers]\nx = \"1\"\n\
         [llm.targets.default.headers]\ny = \"2\"\n",
    );
    let mut env = env_with_file(&file);
    let targets = apply_config_file(&mut env)
        .expect("文件层应用须成功")
        .llm_targets;
    let cfg = Config::load_from_with_targets(&env, targets).expect("文件上游可满足覆盖依赖");
    assert_eq!(
        cfg.llm_upstreams.get(&8878).map(String::as_str),
        Some("http://file-8878:1")
    );
    assert_eq!(
        cfg.llm_default_upstream.as_deref(),
        Some("http://file-default:1")
    );
    assert_eq!(cfg.llm_targets.len(), 2);
}

/// 从 `deny_unknown_fields` 错误消息的 `expected` 段提取字段集（反引号成对）。
fn expected_fields_from_message(message: &str) -> BTreeSet<String> {
    message
        .rsplit_once("expected")
        .map(|(_, tail)| {
            tail.split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 以未知字段探针读取 `T` 的 `deny_unknown_fields` 期望字段集。
fn expected_fields<T: serde::de::DeserializeOwned>(toml_text: &str) -> BTreeSet<String> {
    let error = toml::from_str::<T>(toml_text)
        .err()
        .expect("探针须因未知字段被拒");
    expected_fields_from_message(&error.to_string())
}

#[test]
fn structural_key_set_matches_schema_field_sets() {
    // task 6.3：schema 侧结构性键闭集须与结构体实际接受字段逐组相等——任一字段
    // 新增/改名/删除而未同步 `TARGETS_STRUCTURAL_KEYS` 即失败；端口号/头名/参数名
    // 等用户自定义键不参与（探针只看固定字段集）。
    let probed = [
        expected_fields::<TargetSection>("bogus = 1\n"),
        expected_fields::<TargetParams>("bogus = 1\n"),
        expected_fields::<ParamSegments>("bogus = 1\n"),
    ];
    assert_eq!(
        probed.len(),
        TARGETS_STRUCTURAL_KEYS.len(),
        "探针层级数须与闭集分组数一致"
    );
    assert_eq!(
        probed.iter().map(BTreeSet::len).collect::<Vec<_>>(),
        vec![4, 3, 3],
        "结构性键分组规模须为 4/3/3（目标内 / params 内 / 协议段内）"
    );
    for (group, (layer, closed)) in TARGETS_STRUCTURAL_KEYS.iter().enumerate() {
        let want: BTreeSet<String> = closed.iter().map(|key| (*key).to_string()).collect();
        assert_eq!(
            probed[group], want,
            "「{layer}」结构性键集须与 schema 字段集逐项相等（增删改须同步闭集）"
        );
    }
}
