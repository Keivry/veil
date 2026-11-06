//! 条件替换规则（replace / header_replace）的 schema 与校验单测。

use super::*;

fn body_replace_toml(protocol: &str, rule_body: &str) -> String {
    format!("[[llm.targets.\"8878\".params.{protocol}.replace]]\n{rule_body}\n")
}

/// 构造单条 header 规则声明的 TOML。
fn header_replace_toml(rule_body: &str) -> String {
    format!("[[llm.targets.\"8878\".header_replace]]\n{rule_body}\n")
}

#[test]
fn replace_rules_deserialize_from_array_of_tables_preserving_json_scalar_types() {
    // task 1.1：`[[...params.<proto>.replace]]` 反序列化为规则数组，`from`/`to` 保留
    // 字符串/数字/布尔类型；未声明时为空 Vec。
    let targets = validated(
        "[llm.targets.\"8878\".params.chat]\n\
         default = { temperature = 0.7 }\n\
         [[llm.targets.\"8878\".params.chat.replace]]\n\
         field = \"reasoningEffort\"\n\
         from = \"none\"\n\
         to = \"off\"\n\
         models = [\"deepseek-chat\"]\n\
         [[llm.targets.\"8878\".params.chat.replace]]\n\
         field = \"max_tokens\"\n\
         from = 0\n\
         to = true\n\
         [[llm.targets.\"8878\".header_replace]]\n\
         name = \"x-reasoning-effort\"\n\
         from = \"none\"\n\
         to = \"off\"\n",
    )
    .expect("合法规则须加载通过");
    let chat = targets
        .get(&TargetKey::Port(8878))
        .expect("端口目标须在")
        .params
        .get(&ParamProtocol::Chat)
        .expect("chat 子表须在");
    assert_eq!(
        chat.replace,
        vec![
            ReplaceRule {
                field: "reasoningEffort".to_string(),
                from: json!("none"),
                to: json!("off"),
                models: Some(vec!["deepseek-chat".to_string()]),
            },
            ReplaceRule {
                field: "max_tokens".to_string(),
                from: json!(0),
                to: json!(true),
                models: None,
            },
        ],
        "规则数组须按书写序保留且 JSON 标量类型不丢失"
    );
    let header_rules = &targets
        .get(&TargetKey::Port(8878))
        .expect("端口目标须在")
        .header_replace;
    assert_eq!(
        header_rules,
        &vec![HeaderReplaceRule {
            name: "x-reasoning-effort".to_string(),
            from: "none".to_string(),
            to: "off".to_string(),
            models: None,
        }]
    );
}

#[test]
fn absent_replace_rules_default_to_empty_vec() {
    // task 1.1：未声明时为空 Vec，既有三段载荷逐项不变。
    let targets =
        validated("[llm.targets.\"8878\".params.chat]\ndefault = { temperature = 0.7 }\n")
            .expect("无规则须加载通过");
    let target = targets.get(&TargetKey::Port(8878)).expect("端口目标须在");
    assert!(target.header_replace.is_empty());
    assert!(
        target
            .params
            .get(&ParamProtocol::Chat)
            .expect("chat 子表须在")
            .replace
            .is_empty()
    );
}

#[test]
fn replace_unknown_keys_and_wrong_nesting_rejected_by_schema() {
    // task 1.2：规则层未知键与错误嵌套仍 fail-closed，错误列出合法键集。
    for (text, needle, extra) in [
        (
            "[[llm.targets.\"8878\".params.chat.replace]]\nfield = \"x\"\nfrom = 1\nto = 2\nbogus = 1\n",
            "bogus",
            Some("field"),
        ),
        (
            "[[llm.targets.\"8878\".header_replace]]\nname = \"x\"\nfrom = 1\nto = 2\nbogus = 1\n",
            "bogus",
            Some("name"),
        ),
        (
            // `replace` 写在目标级（错误嵌套层级）。
            "[llm.targets.\"8878\"]\nreplace = []\n",
            "replace",
            Some("header_replace"),
        ),
        (
            // `header_replace` 写在协议子表内（错误嵌套层级）。
            "[llm.targets.\"8878\".params.chat]\nheader_replace = []\n",
            "header_replace",
            Some("replace"),
        ),
    ] {
        let msg = parse_err_msg(text);
        assert!(msg.contains(needle), "未知/错层键 {needle} 须被指名：{msg}");
        if let Some(extra) = extra {
            assert!(
                msg.contains(extra),
                "错误须列出合法键集合（含 {extra}）：{msg}"
            );
        }
    }
}

#[test]
fn replace_rule_type_violations_rejected_by_schema() {
    // task 1.2 / spec：`replace`/`header_replace` 非数组表、字段类型错误由 serde 拒绝。
    for (text, needle) in [
        (
            "[llm.targets.\"8878\".params.chat]\nreplace = 1\n",
            "replace",
        ),
        (
            "[[llm.targets.\"8878\".params.chat.replace]]\nfield = 1\nfrom = \"a\"\nto = \"b\"\n",
            "field",
        ),
        (
            "[[llm.targets.\"8878\".params.chat.replace]]\nfield = \"x\"\nto = \"b\"\n",
            "from",
        ),
        (
            "[[llm.targets.\"8878\".params.chat.replace]]\nfield = \"x\"\nfrom = \"a\"\nto = \"b\"\nmodels = \"m\"\n",
            "models",
        ),
        (
            "[llm.targets.\"8878\"]\nheader_replace = \"x\"\n",
            "header_replace",
        ),
        (
            "[[llm.targets.\"8878\".header_replace]]\nname = \"x\"\nfrom = \"a\"\nto = \"b\"\nmodels = [1]\n",
            "models",
        ),
    ] {
        let msg = parse_err_msg(text);
        assert!(msg.contains(needle), "类型错误 {needle} 须被指名：{msg}");
    }
}

#[test]
fn legal_body_replace_rule_loads() {
    // task 1.3：`reasoningEffort: none → off` 合法示例可加载。
    let targets = validated(
        "[[llm.targets.\"8878\".params.chat.replace]]\n\
         field = \"reasoningEffort\"\nfrom = \"none\"\nto = \"off\"\n",
    )
    .expect("合法 body 规则须加载通过");
    assert_eq!(
        targets
            .get(&TargetKey::Port(8878))
            .expect("端口目标须在")
            .params
            .get(&ParamProtocol::Chat)
            .expect("chat 子表须在")
            .replace
            .len(),
        1
    );
}

#[test]
fn existing_drop_tools_still_loads_without_replace_rules() {
    // task 1.3：`replace` 扩展保留清单不施加于 `default`/`override`/`drop`。
    let targets = validated("[llm.targets.\"8878\".params.chat]\ndrop = [\"tools\"]\n")
        .expect("既有 drop=[tools] 配置须仍可加载");
    assert_eq!(
        targets
            .get(&TargetKey::Port(8878))
            .expect("端口目标须在")
            .params
            .get(&ParamProtocol::Chat)
            .expect("chat 子表须在")
            .drop,
        vec!["tools".to_string()]
    );
}

#[test]
fn replace_field_rejects_empty_dotted_and_reserved_names() {
    // task 1.3：`field` 为空 / 含 `.` / 命中基线或扩展保留键即拒启动并指名字段。
    for (field, needle) in [
        ("", "为空"),
        ("a.b", "含 `.`"),
        ("model", "保留键"),
        ("messages", "保留键"),
        ("tools", "保留键"),
        ("previous_response_id", "保留键"),
        ("conversation", "保留键"),
        ("prompt_cache_key", "保留键"),
        ("metadata", "保留键"),
        ("user", "保留键"),
        ("safety_identifier", "保留键"),
    ] {
        let text = body_replace_toml(
            "chat",
            &format!("field = {field:?}\nfrom = \"a\"\nto = \"b\"\n"),
        );
        let msg = err_msg(&text);
        assert!(
            msg.contains("llm.targets.\"8878\".params.chat.replace")
                && msg.contains(needle)
                && msg.contains("第 1 条规则"),
            "非法 field {field:?} 须拒启动并指名规则与理由 {needle}：{msg}"
        );
        if !field.is_empty() {
            assert!(msg.contains(field), "错误须回显字段名 {field:?}：{msg}");
        }
    }
}

#[test]
fn replace_field_colliding_with_segments_rejected() {
    // task 1.3：与同协议子表 `default`/`override`/`drop` 键重名即拒启动。
    for (segment_line, field) in [
        ("default = { temperature = 0.7 }", "temperature"),
        ("override = { top_p = 0.9 }", "top_p"),
        ("drop = [\"service_tier\"]", "service_tier"),
    ] {
        let text = format!(
            "[llm.targets.\"8878\".params.chat]\n{segment_line}\n\
             [[llm.targets.\"8878\".params.chat.replace]]\n\
             field = {field:?}\nfrom = \"a\"\nto = \"b\"\n"
        );
        let msg = err_msg(&text);
        assert!(
            msg.contains(field) && msg.contains("冲突") && msg.contains("同字段歧义"),
            "同字段歧义 {field:?} 须拒启动并指名：{msg}"
        );
    }
}

#[test]
fn replace_scalar_shape_violations_rejected() {
    // task 1.3：`from`/`to` 非标量（对象/数组/null）或相等即拒启动。
    for (from, to, needle) in [
        ("{ a = 1 }", "\"b\"", "非标量"),
        ("[1]", "\"b\"", "非标量"),
        ("\"same\"", "\"same\"", "相等"),
        ("1", "1", "相等"),
        ("true", "true", "相等"),
    ] {
        let text = body_replace_toml(
            "chat",
            &format!("field = \"x\"\nfrom = {from}\nto = {to}\n"),
        );
        let msg = err_msg(&text);
        assert!(
            msg.contains("llm.targets.\"8878\".params.chat.replace") && msg.contains(needle),
            "非法标量 from={from} to={to} 须拒启动并指名 {needle}：{msg}"
        );
    }
    // TOML 无法表达 null，故直接对校验函数断言。
    let msg = validate_replace_scalar(
        &RuleSite {
            path: "llm.targets.\"8878\".params.chat.replace",
            ordinal: 1,
            label: "x",
        },
        "from",
        &serde_json::Value::Null,
    )
    .expect_err("null 须拒启动")
    .to_string();
    assert!(
        msg.contains("null") && msg.contains("第 1 条规则"),
        "null 标量须拒启动并指名：{msg}"
    );
}

#[test]
fn replace_duplicate_field_from_rejected_within_protocol() {
    // task 1.3：同一协议子表内 `(field, from)` 重复即拒启动；大小写不同视为不同规则。
    let duplicate = "[llm.targets.\"8878\".params.chat]\n\
                     [[llm.targets.\"8878\".params.chat.replace]]\n\
                     field = \"x\"\nfrom = \"none\"\nto = \"off\"\n\
                     [[llm.targets.\"8878\".params.chat.replace]]\n\
                     field = \"x\"\nfrom = \"none\"\nto = \"other\"\n";
    let msg = err_msg(duplicate);
    assert!(
        msg.contains("(field, from)") && msg.contains("重复"),
        "重复规则须拒启动并指名：{msg}"
    );

    let case_distinct = "[llm.targets.\"8878\".params.chat]\n\
                         [[llm.targets.\"8878\".params.chat.replace]]\n\
                         field = \"x\"\nfrom = \"none\"\nto = \"off\"\n\
                         [[llm.targets.\"8878\".params.chat.replace]]\n\
                         field = \"x\"\nfrom = \"None\"\nto = \"other\"\n";
    validated(case_distinct).expect("大小写不同的 from 须视为不同规则");

    let type_distinct = "[llm.targets.\"8878\".params.chat]\n\
                         [[llm.targets.\"8878\".params.chat.replace]]\n\
                         field = \"x\"\nfrom = \"1\"\nto = \"off\"\n\
                         [[llm.targets.\"8878\".params.chat.replace]]\n\
                         field = \"x\"\nfrom = 1\nto = \"other\"\n";
    validated(type_distinct).expect("字符串 1 与数字 1 须视为不同 from");
}

#[test]
fn replace_models_shape_violations_rejected() {
    // task 1.3：`models` 声明但为空数组或含空串即拒启动；省略合法。
    for literal in ["[]", "[\"\"]", "[\"m\", \"\"]"] {
        let text = body_replace_toml(
            "chat",
            &format!("field = \"x\"\nfrom = \"a\"\nto = \"b\"\nmodels = {literal}\n"),
        );
        let msg = err_msg(&text);
        assert!(
            msg.contains("models") && (msg.contains("空数组") || msg.contains("空字符串")),
            "非法 models {literal} 须拒启动并指名：{msg}"
        );
    }
    validated(&body_replace_toml(
        "chat",
        "field = \"x\"\nfrom = \"a\"\nto = \"b\"\n",
    ))
    .expect("省略 models 须合法");
}

#[test]
fn replace_scalar_values_rejecting_actual_pii_token_shapes_only() {
    // task 1.3：实际 PII 占位符形态（`__PII_*__` / 凭据私有前缀）拒启动；泛化 `*__` 不误伤。
    for value in ["__PII_1_ab12cd34__", "__PII_token__", "__CRED_000001__"] {
        let text = body_replace_toml(
            "chat",
            &format!("field = \"x\"\nfrom = {value:?}\nto = \"b\"\n"),
        );
        let msg = err_msg(&text);
        assert!(
            msg.contains("PII 占位符形态") && msg.contains(value),
            "PII 形态 {value:?} 须拒启动并指名：{msg}"
        );
    }
    for value in ["v1__", "__foo__", "v1__trailing"] {
        let text = body_replace_toml(
            "chat",
            &format!("field = \"x\"\nfrom = {value:?}\nto = \"b\"\n"),
        );
        validated(&text)
            .unwrap_or_else(|error| panic!("普通值 {value:?} 不得被误判为占位符形态：{error}"));
    }
}

#[test]
fn legal_header_replace_rule_loads() {
    // task 1.4：`x-reasoning-effort: none → off` 合法示例可加载。
    let targets = validated(&header_replace_toml(
        "name = \"x-reasoning-effort\"\nfrom = \"none\"\nto = \"off\"\n",
    ))
    .expect("合法 header 规则须加载通过");
    assert_eq!(
        targets
            .get(&TargetKey::Port(8878))
            .expect("端口目标须在")
            .header_replace
            .len(),
        1
    );
}

#[test]
fn header_replace_rejects_invalid_hard_denied_and_overlapping_names() {
    // task 1.4：非法头名 / 硬拒头（含 cookie 与全部 HOP 头）/ 与 headers 或 drop_headers
    // 重叠即拒启动，错误指名头名与规则序号。
    for (name, needle) in [
        ("bad name", "头名非法"),
        ("host", "硬拒清单"),
        ("content-length", "硬拒清单"),
        ("content-encoding", "硬拒清单"),
        ("accept-encoding", "硬拒清单"),
        ("transfer-encoding", "硬拒清单"),
        ("connection", "硬拒清单"),
        ("keep-alive", "硬拒清单"),
        ("proxy-authenticate", "硬拒清单"),
        ("proxy-authorization", "硬拒清单"),
        ("te", "硬拒清单"),
        ("trailer", "硬拒清单"),
        ("upgrade", "硬拒清单"),
        ("authorization", "硬拒清单"),
        ("x-api-key", "硬拒清单"),
        ("api-key", "硬拒清单"),
        ("cookie", "硬拒清单"),
        ("x-veil-conversation-id", "硬拒清单"),
        ("X-Veil-Anything", "硬拒清单"),
    ] {
        let msg = err_msg(&header_replace_toml(&format!(
            "name = {name:?}\nfrom = \"a\"\nto = \"b\"\n"
        )));
        assert!(
            msg.contains("llm.targets.\"8878\".header_replace")
                && msg.contains(name)
                && msg.contains(needle)
                && msg.contains("第 1 条规则"),
            "非法/硬拒头 {name:?} 须拒启动并指名：{msg}"
        );
    }
}

#[test]
fn header_replace_overlap_with_headers_or_drop_headers_rejected() {
    // task 1.4：与同目标 `headers` / `drop_headers` 归一后重叠即拒启动。
    let overlap_headers = "[llm.targets.\"8878\"]\n\
                           [llm.targets.\"8878\".headers]\nX-Provider-Version = \"v1\"\n\
                           [[llm.targets.\"8878\".header_replace]]\n\
                           name = \"x-provider-version\"\nfrom = \"a\"\nto = \"b\"\n";
    let msg = err_msg(overlap_headers);
    assert!(
        msg.contains("x-provider-version") && msg.contains("headers") && msg.contains("同名"),
        "与 headers 重叠须拒启动并指名：{msg}"
    );

    let overlap_drop = "[llm.targets.\"8878\"]\ndrop_headers = [\"X-Provider-Version\"]\n\
                        [[llm.targets.\"8878\".header_replace]]\n\
                        name = \"x-provider-version\"\nfrom = \"a\"\nto = \"b\"\n";
    let msg = err_msg(overlap_drop);
    assert!(
        msg.contains("x-provider-version") && msg.contains("drop_headers") && msg.contains("同名"),
        "与 drop_headers 重叠须拒启动并指名：{msg}"
    );
}

#[test]
fn header_replace_user_agent_conflict_rejected_only_when_field_declared() {
    // task 1.4：目标声明 `user_agent` 时归一后为 `user-agent` 的规则拒启动（死配置）；
    // 未声明时该规则合法。
    let conflicting = "[llm.targets.\"8878\"]\nuser_agent = \"opencode/1.18.33\"\n\
                       [[llm.targets.\"8878\".header_replace]]\n\
                       name = \"User-Agent\"\nfrom = \"a\"\nto = \"b\"\n";
    let msg = err_msg(conflicting);
    assert!(
        msg.contains("User-Agent") && msg.contains("user_agent") && msg.contains("死配置"),
        "user_agent 同头冲突须拒启动并指名：{msg}"
    );

    let legal_without_field =
        header_replace_toml("name = \"User-Agent\"\nfrom = \"a\"\nto = \"b\"\n");
    let targets = validated(&legal_without_field).expect("未声明 user_agent 时规则须合法");
    assert_eq!(
        targets
            .get(&TargetKey::Port(8878))
            .expect("端口目标须在")
            .header_replace[0]
            .name,
        "user-agent",
        "头名须归一为小写"
    );
}

#[test]
fn header_replace_value_shape_violations_rejected() {
    // task 1.4：`from`/`to` 含 CR/LF 或非法字节、相等即拒启动。
    for (from, to, needle) in [
        ("\"a\\r\\nb\"", "\"b\"", "CR/LF"),
        ("\"a\"", "\"b\\nc\"", "CR/LF"),
        ("\"\\u0001\"", "\"b\"", "值非法"),
        ("\"same\"", "\"same\"", "相等"),
    ] {
        let msg = err_msg(&header_replace_toml(&format!(
            "name = \"x-note\"\nfrom = {from}\nto = {to}\n"
        )));
        assert!(
            msg.contains("x-note") && msg.contains(needle),
            "非法规则值 from={from} to={to} 须拒启动并指名 {needle}：{msg}"
        );
    }
}

#[test]
fn header_replace_duplicate_name_from_rejected() {
    // task 1.4：同目标内 `(name, from)` 重复即拒启动（大小写归一后比较头名）。
    let text = "[llm.targets.\"8878\"]\n\
                [[llm.targets.\"8878\".header_replace]]\n\
                name = \"x-note\"\nfrom = \"none\"\nto = \"off\"\n\
                [[llm.targets.\"8878\".header_replace]]\n\
                name = \"X-Note\"\nfrom = \"none\"\nto = \"other\"\n";
    let msg = err_msg(text);
    assert!(
        msg.contains("(name, from)") && msg.contains("重复"),
        "重复 header 规则须拒启动并指名：{msg}"
    );
}

#[test]
fn header_replace_models_and_pii_shape_rules_match_body() {
    // task 1.4：`models` 与 PII 形态规则同 body。
    for literal in ["[]", "[\"\"]"] {
        let msg = err_msg(&header_replace_toml(&format!(
            "name = \"x-note\"\nfrom = \"a\"\nto = \"b\"\nmodels = {literal}\n"
        )));
        assert!(
            msg.contains("models"),
            "非法 models {literal} 须指名：{msg}"
        );
    }
    let msg = err_msg(&header_replace_toml(
        "name = \"x-note\"\nfrom = \"__PII_1_ab12cd34__\"\nto = \"b\"\n",
    ));
    assert!(
        msg.contains("PII 占位符形态"),
        "header 规则 PII 形态须拒启动：{msg}"
    );
    validated(&header_replace_toml(
        "name = \"x-note\"\nfrom = \"v1__\"\nto = \"b\"\n",
    ))
    .expect("泛化 `*__` 值不得被误判为占位符形态");
}

#[test]
fn merge_mode_with_any_rule_rejected_naming_override_existing() {
    // task 1.5：`override_existing = false` + 任一非空 replace/header_replace 拒启动，
    // 错误指名 `override_existing` 与规则位置。
    let body = "[llm.targets.\"8878\"]\noverride_existing = false\n\
                [[llm.targets.\"8878\".params.chat.replace]]\n\
                field = \"x\"\nfrom = \"a\"\nto = \"b\"\n";
    let msg = err_msg(body);
    assert!(
        msg.contains("override_existing")
            && msg.contains("llm.targets.\"8878\".params.chat.replace")
            && msg.contains("合并模式"),
        "合并模式 + body 规则须拒启动并指名：{msg}"
    );

    let header = "[llm.targets.\"8878\"]\noverride_existing = false\n\
                  [[llm.targets.\"8878\".header_replace]]\n\
                  name = \"x-note\"\nfrom = \"a\"\nto = \"b\"\n";
    let msg = err_msg(header);
    assert!(
        msg.contains("override_existing")
            && msg.contains("llm.targets.\"8878\".header_replace")
            && msg.contains("合并模式"),
        "合并模式 + header 规则须拒启动并指名：{msg}"
    );
}

#[test]
fn merge_mode_without_rules_and_override_true_with_rules_stay_legal() {
    // task 1.5：`override_existing = false` 无规则合法；`true`/缺省 + 规则合法。
    validated(
        "[llm.targets.\"8878\"]\noverride_existing = false\n\
               [llm.targets.\"8878\".headers]\nx-a = \"1\"\n",
    )
    .expect("合并模式无规则须合法");

    for prefix in [
        "[llm.targets.\"8878\"]\noverride_existing = true\n",
        "[llm.targets.\"8878\"]\n",
    ] {
        let text = format!(
            "{prefix}[[llm.targets.\"8878\".params.chat.replace]]\n\
             field = \"x\"\nfrom = \"a\"\nto = \"b\"\n\
             [[llm.targets.\"8878\".header_replace]]\n\
             name = \"x-note\"\nfrom = \"a\"\nto = \"b\"\n"
        );
        validated(&text).expect("恒胜/缺省 + 规则须合法");
    }
}
