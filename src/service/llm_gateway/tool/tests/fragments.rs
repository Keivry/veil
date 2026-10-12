//! 流式分片（`emit_warn=false`）提取用例——原 `handler/llm/pump/fragments/tests.rs`
//! 迁入：薄适配层删除后直接对共享核心 `extract_tool_calls_with` 断言，
//! 并锁定与非流 `extract_tool_calls` 的逐字段等价。

use super::super::extract_tool_calls_with;

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split(
        "tool/tests/fragments.rs",
        include_str!("fragments.rs"),
    );
}

#[test]
fn chat_fragments_multi_choice_same_index_isolated() {
    // 流侧：`n=2` 同 `index:0` 分桶隔离、参数不串扰，与非流同键。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let v = serde_json::json!({"choices":[
        {"delta":{"tool_calls":[{"index":0,"id":"c0a","function":{"name":"a","arguments":"{\"x\":1}"}}]}},
        {"delta":{"tool_calls":[{"index":0,"id":"c0b","function":{"name":"b","arguments":"{\"y\":2}"}}]}}
    ]});
    let frags = extract_tool_calls_with(false, P::Chat, &v);
    assert_eq!(frags.len(), 2);
    assert_ne!(frags[0].index, frags[1].index, "跨 choice 同 index 须分桶");
    assert!(frags[0].args.contains("\"x\":1") && !frags[0].args.contains("\"y\""));
    assert!(frags[1].args.contains("\"y\":2") && !frags[1].args.contains("\"x\""));
    let calls = extract_tool_calls(P::Chat, &v);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].index, frags[0].index, "流/非流同槽");
    assert_eq!(calls[1].index, frags[1].index, "流/非流同槽");
}

#[test]
fn streaming_legacy_function_call_matches_nonstream() {
    use crate::service::llm_gateway::Protocol as P;
    let stream_delta = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
    let frags = extract_tool_calls_with(false, P::Chat, &stream_delta);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].index, 0);
    assert_eq!(frags[0].id, "call_stable_0");
    assert_eq!(frags[0].name.as_deref(), Some("old"));
    assert_eq!(frags[0].args, "{\"x\":1}");
    let non_stream = serde_json::json!({"choices":[{"message":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
    let frags2 = extract_tool_calls_with(false, P::Chat, &non_stream);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].name.as_deref(), Some("old"));
    assert_eq!(frags2[0].id, "call_stable_0");
    let legacy_arr = serde_json::json!({"choices":[{"delta":{"function_call":[{"name":"a","arguments":"{}"}]}}]});
    let frags3 = extract_tool_calls_with(false, P::Chat, &legacy_arr);
    assert_eq!(
        frags3.len(),
        1,
        "legacy function_call 数组须提取恰一: {frags3:?}"
    );
    assert_eq!(frags3[0].name.as_deref(), Some("a"));
}

#[test]
fn dual_tool_calls_accumulate_independently_by_index() {
    use crate::service::llm_gateway::Protocol as P;
    let two = serde_json::json!({"choices":[{"delta":{"tool_calls":[
        {"index":0,"id":"call_a","type":"function","function":{"name":"exec_a","arguments":"{\"x\":1}"}},
        {"index":1,"id":"call_b","type":"function","function":{"name":"exec_b","arguments":"{\"y\":2}"}}
    ]}}]});
    let frags = extract_tool_calls_with(false, P::Chat, &two);
    assert_eq!(frags.len(), 2, "双路须各一条: {frags:?}");
    assert_eq!(frags[0].index, 0);
    assert_eq!(frags[1].index, 1);
    assert_eq!(frags[0].name.as_deref(), Some("exec_a"));
    assert_eq!(frags[1].name.as_deref(), Some("exec_b"));
    assert!(frags[0].args.contains("\"x\":1") && !frags[0].args.contains("\"y\""));
    assert!(frags[1].args.contains("\"y\":2") && !frags[1].args.contains("\"x\""));
}

#[test]
fn anthropic_array_content_aligns_with_gateway() {
    use crate::service::llm_gateway::Protocol as P;
    let content_arr = serde_json::json!({"content":[{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}]});
    let frags = extract_tool_calls_with(false, P::Anthropic, &content_arr);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].id, "a1");
    assert_eq!(frags[0].name.as_deref(), Some("bash"));
    assert_eq!(frags[0].args, r#"{"cmd":"ls"}"#);
    let msg_content = serde_json::json!({"message":{"content":[{"type":"tool_use","id":"m1","name":"run","input":{"p":2}}]}});
    let frags2 = extract_tool_calls_with(false, P::Anthropic, &msg_content);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].id, "m1");
    let delta =
        serde_json::json!({"delta":{"type":"tool_use","name":"t","partial_json":"{\"a\":"}});
    let frags3 = extract_tool_calls_with(false, P::Anthropic, &delta);
    assert_eq!(frags3.len(), 1);
    assert_eq!(frags3[0].id, "call_stable_0");
    let text_only = serde_json::json!({"delta":{"type":"text","text":"hi"}});
    assert!(extract_tool_calls_with(false, P::Anthropic, &text_only).is_empty());
}

#[test]
fn anthropic_buckets_by_event_index_not_position() {
    use crate::service::llm_gateway::Protocol as P;
    let first = serde_json::json!({"content_block":{"type":"tool_use","index":4,"id":"a4","name":"t","input":{}}});
    let frags = extract_tool_calls_with(false, P::Anthropic, &first);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].index, 4);
    let second =
        serde_json::json!({"delta":{"type":"input_json_delta","index":4,"partial_json":"{}"}});
    let frags2 = extract_tool_calls_with(false, P::Anthropic, &second);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].index, 4);
    assert_eq!(frags2[0].args, "{}");
}

#[test]
fn responses_added_builds_slot_so_truncation_stays_auditable() {
    // 起始截断漏审回归：仅 `added` 到达（`.done` 前截断）时槽须已建，
    // 名/id 保留至审计三元组；非 tool 起始不建槽。
    use crate::service::llm_gateway::Protocol as P;
    let added = serde_json::json!({"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","id":"call-9","name":"run"}});
    let frags = extract_tool_calls_with(false, P::Responses, &added);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].index, 2);
    assert_eq!(frags[0].id, "call-9");
    assert_eq!(frags[0].name.as_deref(), Some("run"));
    assert!(frags[0].args.is_empty());
    // 复用既有按槽缓冲建槽：空参分片入槽后，即使零参数到达完成点，
    // 审计仍可见起始名（截断前可审计，不断链漏审）。
    let mut hold = crate::service::audit::AuditHold::new(1_048_576);
    for frag in &frags {
        let key =
            crate::service::audit::AuditHold::responses_key(Some(frag.id.as_str()), frag.index);
        hold.push_responses_fragment(
            &key,
            frag.index,
            None,
            Some(frag.id.as_str()),
            frag.name.as_deref(),
            &frag.args,
        );
        hold.mark_responses_done(&key, None);
    }
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1);
    assert_eq!(triples[0].0, 2);
    assert_eq!(triples[0].1, "run");
    let msg = serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","content":[]}});
    assert!(extract_tool_calls_with(false, P::Responses, &msg).is_empty());
}

#[test]
fn responses_custom_tool_call_stream_matches_nonstream() {
    // 流式 custom 覆盖：同调用在流/非流须同结论（名/参/id 一致）。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let nested = serde_json::json!({"output":[{"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}]});
    let frags = extract_tool_calls_with(false, P::Responses, &nested);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].name.as_deref(), Some("ct"));
    assert_eq!(frags[0].args, "{}");
    let calls = extract_tool_calls(P::Responses, &nested);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name.as_deref(), frags[0].name.as_deref());
    assert_eq!(calls[0].args, frags[0].args);
    // 裸回退形态（`tool_name`+`input` 别名）双向同解。
    let bare = serde_json::json!({"output":[{"type":"tool","tool_name":"grep","input":{"p":1}}]});
    let frags2 = extract_tool_calls_with(false, P::Responses, &bare);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].name.as_deref(), Some("grep"));
    assert_eq!(frags2[0].args, r#"{"p":1}"#);
    let calls2 = extract_tool_calls(P::Responses, &bare);
    assert_eq!(calls2.len(), 1);
    assert_eq!(calls2[0].name.as_deref(), Some("grep"));
    assert_eq!(calls2[0].args, r#"{"p":1}"#);
    // 纯消息项双向皆不建槽。
    let msg = serde_json::json!({"output":[{"type":"message","id":"m1","content":[]}]});
    assert!(extract_tool_calls_with(false, P::Responses, &msg).is_empty());
    assert!(extract_tool_calls(P::Responses, &msg).is_empty());
}

#[test]
fn stream_interleaved_outer_index_matches_nonstream_slot() {
    // 回归：流式分桶与非流同槽（外层 0/1 胜过内层 3/5）。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let start0 = serde_json::json!({"index":0,"content_block":{"type":"tool_use","index":3,"id":"a0","name":"run","input":{}}});
    let frags = extract_tool_calls_with(false, P::Anthropic, &start0);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].index, 0, "流式外层 0 须胜过内层 3");
    let calls = extract_tool_calls(P::Anthropic, &start0);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].index, frags[0].index, "流/非流同槽");
    let d1 = serde_json::json!({"index":1,"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"y\":"}});
    let frags1 = extract_tool_calls_with(false, P::Anthropic, &d1);
    assert_eq!(frags1.len(), 1);
    assert_eq!(frags1[0].index, 1, "流式外层 1 须胜过内层 5");
    let calls1 = extract_tool_calls(P::Anthropic, &d1);
    assert_eq!(calls1.len(), 1);
    assert_eq!(calls1[0].index, frags1[0].index, "流/非流同槽");
}

#[test]
fn tool_extract_parity() {
    // 同一输入（缺参/缺 id/`output_index` 缺省）两入口字段值与桶号一致。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let cases = [
        (
            P::Chat,
            serde_json::json!({"choices":[{"delta":{"tool_calls":[{"index":0}]}}]}),
        ),
        (
            P::Responses,
            serde_json::json!({"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","name":"run"}}),
        ),
        (
            P::Responses,
            serde_json::json!({"output":[{"type":"function_call","name":"x","arguments":"{}"}]}),
        ),
        (
            P::Anthropic,
            serde_json::json!({"delta":{"type":"tool_use","partial_json":"{\"a\":"}}),
        ),
        (
            P::Responses,
            serde_json::json!({"output":[{"type":"web_search_call","action":{"type":"search","query":"veil audit"}}]}),
        ),
    ];
    for (proto, v) in cases {
        let frags = extract_tool_calls_with(false, proto, &v);
        let calls = extract_tool_calls(proto, &v);
        assert_eq!(frags.len(), calls.len(), "{proto:?} 条目数一致: {v}");
        for (f, c) in frags.iter().zip(calls.iter()) {
            assert_eq!(f.index, c.index, "{proto:?} 桶号一致: {v}");
            assert_eq!(f.id, c.id, "{proto:?} id 一致: {v}");
            assert_eq!(f.name, c.name, "{proto:?} name 一致: {v}");
            assert_eq!(f.args, c.args, "{proto:?} args 一致: {v}");
        }
    }
}

#[test]
fn fragment_nonstream_parity() {
    // 三组锁定：Chat 多 choice、Responses `output_index`、缺参缺 id。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let chat = serde_json::json!({"choices":[
        {"delta":{"tool_calls":[{"index":0,"id":"c0","function":{"name":"a","arguments":"{\"x\":1}"}}]}},
        {"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"b","arguments":"{\"y\":2}"}}]}}
    ]});
    let frags = extract_tool_calls_with(false, P::Chat, &chat);
    let calls = extract_tool_calls(P::Chat, &chat);
    assert_eq!(frags.len(), 2);
    for (f, c) in frags.iter().zip(calls.iter()) {
        assert_eq!(f.index, c.index);
        assert_eq!(f.id, c.id);
        assert_eq!(f.name, c.name);
        assert_eq!(f.args, c.args);
    }
    assert_ne!(
        frags[0].index, frags[1].index,
        "多 choice 同 index 分桶隔离"
    );
    let resp = serde_json::json!({"output":[
        {"type":"function_call","output_index":5,"id":"f5","name":"run","arguments":"{\"a\":1}"},
        {"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}
    ]});
    let frags_r = extract_tool_calls_with(false, P::Responses, &resp);
    let calls_r = extract_tool_calls(P::Responses, &resp);
    assert_eq!(frags_r.len(), calls_r.len());
    for (f, c) in frags_r.iter().zip(calls_r.iter()) {
        assert_eq!(f.index, c.index, "Responses 桶号一致");
        assert_eq!(f.id, c.id);
        assert_eq!(f.name, c.name);
        assert_eq!(f.args, c.args);
    }
    assert_eq!(frags_r[0].index, 5, "显式 output_index 锁定");
    let missing = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"index":0}]}}]});
    let f = extract_tool_calls_with(false, P::Chat, &missing);
    let c = extract_tool_calls(P::Chat, &missing);
    assert_eq!(f[0].id, c[0].id);
    assert_eq!(f[0].id, "call_stable_0");
    assert_eq!(f[0].args, c[0].args);
}

#[test]
fn tool_bucket_parity() {
    // Responses `output[]` 流式分片与非流提取桶号同键
    //（`output_index` 存在同值、缺失均回退枚举下标）。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let with_index = serde_json::json!({"output":[
        {"type":"function_call","output_index":3,"id":"f3","name":"run","arguments":"{}"},
        {"type":"function_call","id":"f0","name":"run2","arguments":"{}"}
    ]});
    let frags = extract_tool_calls_with(false, P::Responses, &with_index);
    let calls = extract_tool_calls(P::Responses, &with_index);
    assert_eq!(frags.len(), 2);
    assert_eq!(calls.len(), 2);
    assert_eq!(frags[0].index, 3, "显式 output_index 优先");
    assert_eq!(frags[1].index, 1, "缺失回退枚举下标");
    assert_eq!(frags[0].index, calls[0].index, "流/非流同键（显式）");
    assert_eq!(frags[1].index, calls[1].index, "流/非流同键（回退）");
    let no_index = serde_json::json!({"output":[
        {"type":"function_call","id":"a","name":"x","arguments":"{}"},
        {"type":"function_call","id":"b","name":"y","arguments":"{}"}
    ]});
    let frags2 = extract_tool_calls_with(false, P::Responses, &no_index);
    let calls2 = extract_tool_calls(P::Responses, &no_index);
    assert_eq!(frags2.len(), 2);
    assert_eq!(calls2.len(), 2);
    for (f, c) in frags2.iter().zip(calls2.iter()) {
        assert_eq!(f.index, c.index, "全缺失场景须同键");
    }
    assert_eq!(frags2[0].index, 0);
    assert_eq!(frags2[1].index, 1);
}

#[test]
fn web_search_action_audit_both_paths() {
    // 官方 `action` 查询经流式分片与非流 `extract_tool_calls`
    // 均进入审计参数（不漏审）。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let nonstream = serde_json::json!({"output":[{"type":"web_search_call","id":"ws1",
        "action":{"type":"search","query":"veil audit"}}]});
    let calls = extract_tool_calls(P::Responses, &nonstream);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name.as_deref(), Some("web_search"));
    assert!(calls[0].args.contains("veil audit"), "{:?}", calls[0]);
    let stream = serde_json::json!({"type":"response.output_item.done","output_index":0,
        "item":{"type":"web_search_call","id":"ws1",
            "action":{"type":"search","query":"veil audit"}}});
    let frags = extract_tool_calls_with(false, P::Responses, &stream);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].name.as_deref(), Some("web_search"));
    assert!(frags[0].args.contains("veil audit"), "{:?}", frags[0]);
}

#[test]
fn anthropic_empty_input_no_arg_pollution() {
    // `content_block_start` 的 `input:{}` 占位不进累积，`partial_json`
    // 拼接后无 `{}{` 前缀污染。
    use crate::service::llm_gateway::Protocol as P;
    let start = serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"run","input":{}}});
    let frags = extract_tool_calls_with(false, P::Anthropic, &start);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].args, "", "空占位 input 不得序列化为 {{}}");
    let delta = serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\"}"}});
    let frags2 = extract_tool_calls_with(false, P::Anthropic, &delta);
    let mut hold = crate::service::audit::AuditHold::new(1_048_576);
    for frag in frags.iter().chain(frags2.iter()) {
        hold.push_fragment(
            frag.index,
            Some(frag.id.as_str()),
            frag.name.as_deref(),
            &frag.args,
        );
    }
    let triples = hold.tool_triples();
    assert_eq!(triples[0].2, "{\"cmd\":\"ls\"}", "参数须为纯增量拼接");
    assert!(!triples[0].2.starts_with("{}{"), "不得有花括号前缀污染");
}

#[test]
fn anthropic_nonempty_input_seed() {
    // 非空完整 `input` 仍可一次性种子（非流形态），不被占位规则吞掉。
    use crate::service::llm_gateway::Protocol as P;
    let start = serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"run","input":{"cmd":"ls"}}});
    let frags = extract_tool_calls_with(false, P::Anthropic, &start);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].args, "{\"cmd\":\"ls\"}", "非空 input 须保留");
}

#[test]
fn responses_four_delta_kinds_accumulate() {
    // code_interpreter/shell/mcp/custom_tool 四类 Responses 工具 delta
    // 均建槽累积参数分片，`.done` 后 `tool_triples` 可见。
    use crate::service::{audit::AuditHold, llm_gateway::Protocol as P};
    let cases = [
        (
            "response.code_interpreter_call_code",
            "code_interpreter",
            "{\"code\":\"print(1)\"}",
        ),
        (
            "response.shell_call_command",
            "shell",
            "{\"command\":\"rm -rf /\"}",
        ),
        (
            "response.mcp_call_arguments",
            "mcp",
            "{\"query\":\"rm -rf /\"}",
        ),
        (
            "response.custom_tool_call_input",
            "custom_tool",
            "{\"input\":\"rm -rf /\"}",
        ),
    ];
    for (i, (base, want_name, delta)) in cases.iter().enumerate() {
        let v = serde_json::json!({
            "type": format!("{base}.delta"),
            "item_id": format!("call-{i}"),
            "output_index": i,
            "delta": delta,
        });
        let frags = extract_tool_calls_with(false, P::Responses, &v);
        assert_eq!(frags.len(), 1, "{base}.delta 须产分片");
        assert_eq!(frags[0].index, i as u32, "{base} 槽号按 output_index");
        assert_eq!(
            frags[0].name.as_deref(),
            Some(*want_name),
            "{base} 派生工具名"
        );
        assert_eq!(frags[0].args, *delta, "{base} delta 入参");
        let mut hold = AuditHold::new(1024);
        let key = AuditHold::responses_key(Some(frags[0].id.as_str()), frags[0].index);
        hold.push_responses_fragment(
            &key,
            frags[0].index,
            Some(0),
            Some(frags[0].id.as_str()),
            frags[0].name.as_deref(),
            &frags[0].args,
        );
        let done = serde_json::json!({
            "type": format!("{base}.done"),
            "item_id": format!("call-{i}"),
            "output_index": i,
        });
        assert!(
            AuditHold::is_responses_slot_complete_event(&done),
            "{base}.done 须为槽级完成"
        );
        hold.mark_responses_done(&key, None);
        let triples = hold.tool_triples();
        assert_eq!(triples.len(), 1, "{base} 分片须 tool_triples 可见");
        assert_eq!(triples[0].2, *delta);
    }
}

#[test]
fn chat_bucket_declared_index() {
    // `choices[].index` 乱序/跳号时，各 choice 分片按声明 index 归入各自槽。
    use crate::service::llm_gateway::{Protocol as P, chat_bucket};
    let v = serde_json::json!({"choices":[
        {"index":2,"delta":{"tool_calls":[{"index":0,"id":"c2","function":{"name":"a","arguments":"{\"x\":2}"}}]}},
        {"index":0,"delta":{"tool_calls":[{"index":0,"id":"c0","function":{"name":"b","arguments":"{\"x\":0}"}}]}},
        {"index":5,"delta":{"tool_calls":[{"index":0,"id":"c5","function":{"name":"c","arguments":"{\"x\":5}"}}]}}
    ]});
    let frags = extract_tool_calls_with(false, P::Chat, &v);
    assert_eq!(frags.len(), 3);
    assert_eq!(frags[0].index, chat_bucket(2, 0), "声明 index 2 槽");
    assert_eq!(frags[1].index, chat_bucket(0, 0), "声明 index 0 槽");
    assert_eq!(frags[2].index, chat_bucket(5, 0), "声明 index 5 槽");
    assert_ne!(frags[0].index, frags[2].index);
}

#[test]
fn chat_bucket_single_choice_unchanged() {
    // 回归：单 choice（index=0，位置 0）分桶键与旧实现等值。
    use crate::service::llm_gateway::{Protocol as P, chat_bucket};
    assert_eq!(chat_bucket(0, 0), 0, "单 choice index 0 键值不变");
    let v = serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c0","function":{"name":"a","arguments":"{\"x\":1}"}}]}}]});
    let frags = extract_tool_calls_with(false, P::Chat, &v);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].index, chat_bucket(0, 0));
    assert_eq!(frags[0].args, "{\"x\":1}");
}
