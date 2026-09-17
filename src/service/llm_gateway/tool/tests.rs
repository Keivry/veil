#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("tool.rs", include_str!("../tool.rs"));
    crate::test_support::file_len_under_800_or_split("tool/tests.rs", include_str!("tests.rs"));
}

use super::*;

#[test]
fn responses_output_bucket_explicit_and_fallback() {
    // P9/X2：`output_index` 优先，缺失回退枚举下标（流/非流共用唯一实现）。
    let explicit = serde_json::json!({"output_index": 3});
    assert_eq!(responses_output_bucket(&explicit, 0), 3);
    let fallback = serde_json::json!({"type": "function_call"});
    assert_eq!(responses_output_bucket(&fallback, 2), 2);
    assert_eq!(responses_output_bucket(&fallback, 0), 0);
}

#[test]
fn chat_multi_choice_same_index_isolated_by_ci() {
    // F-P1b：`n=2` 同 `index:0` 须分桶隔离，参数不串扰。
    let v = serde_json::json!({"choices":[
        {"delta":{"tool_calls":[{"index":0,"id":"c0a","function":{"name":"a","arguments":"{\"x\":1}"}}]}},
        {"delta":{"tool_calls":[{"index":0,"id":"c0b","function":{"name":"b","arguments":"{\"y\":2}"}}]}}
    ]});
    let calls = extract_tool_calls(Protocol::Chat, &v);
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].index, calls[1].index, "跨 choice 同 index 须分桶");
    assert_eq!(calls[0].id, "c0a");
    assert_eq!(calls[1].id, "c0b");
    assert!(!calls[0].id_synth && !calls[1].id_synth);
    assert!(calls[0].args.contains("\"x\":1") && !calls[0].args.contains("\"y\""));
    assert!(calls[1].args.contains("\"y\":2") && !calls[1].args.contains("\"x\""));
    // 缺 id 时合成名同步混入 ci，跨 choice 不重名。
    let no_id = serde_json::json!({"choices":[
        {"delta":{"tool_calls":[{"index":0,"function":{"name":"a","arguments":"{}"}}]}},
        {"delta":{"tool_calls":[{"index":0,"function":{"name":"b","arguments":"{}"}}]}}
    ]});
    let synth = extract_tool_calls(Protocol::Chat, &no_id);
    assert_eq!(synth.len(), 2);
    assert_ne!(synth[0].id, synth[1].id);
    assert!(synth[0].id_synth && synth[1].id_synth);
    // custom 方言同步混入 ci。
    let custom = serde_json::json!({"choices":[
        {"delta":{"custom_tool_call":{"id":"k0","name":"t","input":{"p":0}}}},
        {"delta":{"custom_tool_call":{"id":"k1","name":"t","input":{"p":1}}}}
    ]});
    let cc = extract_tool_calls(Protocol::Chat, &custom);
    assert_eq!(cc.len(), 2);
    assert_ne!(cc[0].index, cc[1].index);
    // legacy 与新形态口径一致：同 choice 同槽基址。
    let legacy = serde_json::json!({"choices":[
        {"delta":{"function_call":{"name":"old","arguments":"{}"}}}
    ]});
    let lc = extract_tool_calls(Protocol::Chat, &legacy);
    assert_eq!(lc.len(), 1);
    assert_eq!(lc[0].index, chat_bucket(0, 0));
}

#[test]
fn item_done_type_coverage() {
    // RSP-6/2.30 + A/M-1：`output_item.done` 与非流 `output[]` 全量体均覆盖非
    // function_call 工具 item 类型，两路径派生同名且携带非空参数（同结论）。
    let cases = [
        (
            serde_json::json!({"type":"function_call","id":"i1","name":"run","arguments":"{\"x\":1}"}),
            "run",
        ),
        (
            serde_json::json!({"type":"custom_tool_call","id":"i2","input":"{\"y\":2}"}),
            "custom_tool",
        ),
        (
            serde_json::json!({"type":"code_interpreter_call","id":"i3","code":"print(1)"}),
            "code_interpreter",
        ),
        (
            serde_json::json!({"type":"shell_call","id":"i4","action":{"command":"ls"}}),
            "shell",
        ),
        (
            serde_json::json!({"type":"mcp_call","id":"i5","arguments":"{\"p\":1}"}),
            "mcp",
        ),
        (
            serde_json::json!({"type":"file_search_call","id":"i6","queries":["q"]}),
            "file_search",
        ),
        (
            serde_json::json!({"type":"web_search_call","id":"i7","action":{"query":"q"}}),
            "web_search",
        ),
    ];
    for (item, expect_name) in cases {
        let ty = item["type"].as_str().expect("item type").to_string();
        let payload = serde_json::json!(
            {"type":"response.output_item.done","output_index":3,"item":item.clone()}
        );
        let calls = extract_tool_calls(Protocol::Responses, &payload);
        assert_eq!(calls.len(), 1, "{ty} 须进 item-done 审计: {calls:?}");
        assert_eq!(calls[0].index, 3, "{ty} 桶号");
        assert_eq!(
            calls[0].name.as_deref(),
            Some(expect_name),
            "{ty} 派生名须一致"
        );
        assert!(!calls[0].args.is_empty(), "{ty} 参非空: {calls:?}");

        // 1.3：非流 `output[]` 全量体同条目须同结论。
        let mut body_item = item;
        body_item["output_index"] = serde_json::json!(3);
        let body = serde_json::json!({"output": [body_item]});
        let body_calls = extract_tool_calls(Protocol::Responses, &body);
        assert_eq!(
            body_calls.len(),
            1,
            "{ty} 须进非流 output[] 审计: {body_calls:?}"
        );
        assert_eq!(body_calls[0].index, 3, "{ty} 非流桶号");
        assert_eq!(
            body_calls[0].name.as_deref(),
            Some(expect_name),
            "{ty} 非流 output[] 派生名须一致"
        );
        assert!(
            !body_calls[0].args.is_empty(),
            "{ty} 非流参非空: {body_calls:?}"
        );
    }
}

#[test]
fn responses_output_builtin_tools_audited() {
    // A/M-1：非流 Responses `output[]` 内置工具经派生名路径审计——各条目派生名
    // 非空且 args 非空（真实条目：`code_interpreter_call` 携带 `code`、
    // `shell_call`/`computer_call` 携带 `action`）。
    let cases = [
        (
            serde_json::json!({"type":"function_call","id":"b1","name":"run","arguments":"{\"x\":1}"}),
            "run",
        ),
        (
            serde_json::json!({"type":"custom_tool_call","id":"b2","input":"{\"y\":2}"}),
            "custom_tool",
        ),
        (
            serde_json::json!({"type":"code_interpreter_call","id":"b3","code":"print(1)"}),
            "code_interpreter",
        ),
        (
            serde_json::json!({"type":"shell_call","id":"b4","action":{"command":"ls"}}),
            "shell",
        ),
        (
            serde_json::json!({"type":"mcp_call","id":"b5","arguments":"{\"p\":1}"}),
            "mcp",
        ),
        (
            serde_json::json!({"type":"file_search_call","id":"b6","queries":["q"]}),
            "file_search",
        ),
        (
            serde_json::json!({"type":"web_search_call","id":"b7","action":{"query":"q"}}),
            "web_search",
        ),
        (
            serde_json::json!({"type":"computer_call","id":"b8","action":{"type":"click","x":1}}),
            "computer",
        ),
    ];
    for (item, expect_name) in cases {
        let ty = item["type"].as_str().expect("item type").to_string();
        let body = serde_json::json!({"output": [item]});
        let calls = extract_tool_calls(Protocol::Responses, &body);
        assert_eq!(calls.len(), 1, "{ty} 须进非流 output[] 审计: {calls:?}");
        assert_eq!(
            calls[0].name.as_deref(),
            Some(expect_name),
            "{ty} 派生名须非空且一致"
        );
        assert!(
            calls[0].name.as_deref().is_some_and(|n| !n.is_empty()),
            "{ty} 派生名非空"
        );
        assert!(!calls[0].args.is_empty(), "{ty} args 非空: {calls:?}");
    }
}

#[test]
fn responses_output_stream_nonstream_parity() {
    // A/G/6.2：同一工具条目经 `response.output_item.done`（流）与非流 `output[]`
    // 两路径提取，`(name, args, bucket)` 须逐一致（冲突即失败）。
    let items = [
        serde_json::json!({"type":"function_call","id":"p1","name":"run","arguments":"{\"x\":1}"}),
        serde_json::json!({"type":"custom_tool_call","id":"p2","input":"{\"y\":2}"}),
        serde_json::json!({"type":"code_interpreter_call","id":"p3","code":"print(1)"}),
        serde_json::json!({"type":"shell_call","id":"p4","action":{"command":"ls"}}),
        serde_json::json!({"type":"mcp_call","id":"p5","arguments":"{\"p\":1}"}),
        serde_json::json!({"type":"file_search_call","id":"p6","queries":["q"]}),
        serde_json::json!({"type":"web_search_call","id":"p7","action":{"query":"q"}}),
        serde_json::json!({"type":"computer_call","id":"p8","action":{"type":"click","x":1}}),
    ];
    for item in items {
        let ty = item["type"].as_str().expect("item type").to_string();
        let done_payload = serde_json::json!(
            {"type":"response.output_item.done","output_index":3,"item":item.clone()}
        );
        let mut body_item = item;
        body_item["output_index"] = serde_json::json!(3);
        let stream = extract_tool_calls(Protocol::Responses, &done_payload);
        let nonstream = extract_tool_calls(
            Protocol::Responses,
            &serde_json::json!({"output": [body_item]}),
        );
        assert_eq!(stream.len(), 1, "{ty} item-done 须建恰一条目");
        assert_eq!(nonstream.len(), 1, "{ty} output[] 须建恰一条目");
        assert_eq!(
            (
                stream[0].name.as_deref(),
                stream[0].args.as_str(),
                stream[0].index
            ),
            (
                nonstream[0].name.as_deref(),
                nonstream[0].args.as_str(),
                nonstream[0].index
            ),
            "{ty} 流/非流 (name, args, bucket) 须逐一致"
        );
    }
}

#[test]
fn responses_computer_call_audited() {
    // B/2.1：`computer_call` 经 `contains("computer")` 分支派生名 `"computer"`，
    // 流式 `response.output_item.done` 与非流 `output[]` 两路径同结论；参数取
    // item 的 `action` 字段（serde 序列化）。`computer_use_preview`/
    // `computer_call_output` 型 item 由同一 `contains("computer")` 分支覆盖。
    let cases = [
        (
            serde_json::json!({"type":"computer_call","id":"c1","action":{"type":"click","x":1,"y":2}}),
            "computer_call",
        ),
        (
            serde_json::json!({"type":"computer_use_preview","id":"c2","action":{"type":"screenshot"}}),
            "computer_use_preview",
        ),
        (
            serde_json::json!({"type":"computer_call_output","id":"c3","action":{"type":"keypress","keys":["a"]}}),
            "computer_call_output",
        ),
    ];
    for (item, ty) in cases {
        let action = item["action"].clone();
        let expect_args = serde_json::to_string(&action).expect("action 序列化");

        // 流式路径：`response.output_item.done`。
        let done_payload = serde_json::json!(
            {"type":"response.output_item.done","output_index":3,"item":item.clone()}
        );
        let stream = extract_tool_calls(Protocol::Responses, &done_payload);
        assert_eq!(stream.len(), 1, "{ty} item-done 须建恰一条目: {stream:?}");
        assert_eq!(
            stream[0].name.as_deref(),
            Some("computer"),
            "{ty} item-done 派生名须恰为 computer"
        );
        assert!(!stream[0].args.is_empty(), "{ty} item-done args 非空");
        assert_eq!(
            stream[0].args, expect_args,
            "{ty} item-done args 须来自 action 序列化"
        );

        // 非流路径：`output[]` 全量体。
        let mut body_item = item;
        body_item["output_index"] = serde_json::json!(3);
        let body = serde_json::json!({"output": [body_item]});
        let nonstream = extract_tool_calls(Protocol::Responses, &body);
        assert_eq!(
            nonstream.len(),
            1,
            "{ty} output[] 须建恰一条目: {nonstream:?}"
        );
        assert_eq!(
            nonstream[0].name.as_deref(),
            Some("computer"),
            "{ty} output[] 派生名须恰为 computer"
        );
        assert!(!nonstream[0].args.is_empty(), "{ty} output[] args 非空");
        assert_eq!(
            nonstream[0].args, expect_args,
            "{ty} output[] args 须来自 action 序列化"
        );

        // 两路径 (name, args, bucket) 逐一致。
        assert_eq!(
            (
                stream[0].name.as_deref(),
                stream[0].args.as_str(),
                stream[0].index
            ),
            (
                nonstream[0].name.as_deref(),
                nonstream[0].args.as_str(),
                nonstream[0].index
            ),
            "{ty} 流/非流 (name, args, bucket) 须逐一致"
        );
    }
}

#[test]
fn chat_bucket_no_collision() {
    // CHC-6/2.25：声明域内 (ci, idx) 单射无碰撞；覆盖旧 64 步长碰撞点。
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for ci in 0..8usize {
        for idx in 0..256u32 {
            assert!(
                seen.insert(chat_bucket(ci, idx)),
                "分桶碰撞: ci={ci} idx={idx}"
            );
        }
    }
    assert_ne!(
        chat_bucket(0, 64),
        chat_bucket(1, 0),
        "64 步长旧碰撞点须消除"
    );
    assert_ne!(chat_bucket(0, 4096), chat_bucket(64, 0));
    assert_eq!(chat_bucket(0, 0), 0, "单 choice 键值不变");
}

#[test]
fn chat_bucket_bitfield_ci0_equivalence() {
    // B2 回归锁定：位域公式 `(ci << 16) | (idx & 0xFFFF)` 在 `ci = 0` 时与历史
    // `ci * 64 + idx` 等值（单 choice 桶键不变）；非零 choice 消除 64 步长饱和。
    for idx in [0u32, 1, 63, 64, 255, 4095, 65535] {
        assert_eq!(chat_bucket(0, idx), idx, "ci=0 须与历史公式等值: idx={idx}");
    }
    assert_eq!(chat_bucket(2, 5), (2 << 16) | 5);
    assert_ne!(
        chat_bucket(0, 4096),
        chat_bucket(64, 0),
        "旧 64 步长公式在该点碰撞，位域须分离"
    );
}

#[test]
fn r5_16_out_of_range_index_no_legal_collision() {
    // R5-16/D12：越界索引经 `u32::try_from` 检测后有界哈希溢出，不得静默截断
    // 与合法索引碰撞。
    assert_ne!(chat_bucket_raw(0, 65536), chat_bucket_raw(0, 0));
    assert_ne!(chat_bucket_raw(0, u32::MAX as u64), chat_bucket_raw(0, 0));
    let legal = serde_json::json!({"type":"response.output_item.done","output_index":0,
        "item":{"type":"function_call","id":"a","name":"run","arguments":"{}"}});
    let over = serde_json::json!({"type":"response.output_item.done","output_index":u64::MAX,
        "item":{"type":"function_call","id":"b","name":"run","arguments":"{}"}});
    let lc = extract_tool_calls(Protocol::Responses, &legal);
    let oc = extract_tool_calls(Protocol::Responses, &over);
    assert_eq!((lc.len(), oc.len()), (1, 1));
    assert_ne!(
        oc[0].index, lc[0].index,
        "u64::MAX 越界索引不得与合法 0 碰撞"
    );
}

#[test]
fn r5_16_legacy_function_call_multi_entries_distinct_buckets() {
    // 旧式 `function_call` 多条目须按枚举下标分桶，不得恒用固定桶 0 互相覆盖。
    let v = serde_json::json!({"choices":[{"delta":{"function_call":[
        {"name":"a","arguments":"{\"x\":1}"},
        {"name":"b","arguments":"{\"y\":2}"}
    ]}}]});
    let calls = extract_tool_calls(Protocol::Chat, &v);
    assert_eq!(calls.len(), 2);
    assert_ne!(
        calls[0].index, calls[1].index,
        "同 choice 多 function_call 须分桶不互相覆盖"
    );
    assert_eq!(calls[0].name.as_deref(), Some("a"));
    assert_eq!(calls[1].name.as_deref(), Some("b"));
    assert!(calls[0].args.contains("\"x\":1") && calls[1].args.contains("\"y\":2"));
    // 单条目仍与历史桶 0 等值（单 choice 快照不变）。
    let one = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{}"}}}]});
    let c1 = extract_tool_calls(Protocol::Chat, &one);
    assert_eq!(c1[0].index, chat_bucket(0, 0));
}

#[test]
fn empty_placeholder_covers_empty_array() {
    // STP-9/2.21：`content_block_start` 空数组占位 `input:[]` 不计入参数累积，
    // 不与后续 `partial_json` 拼成 `[]...` 前缀污染。
    let start = serde_json::json!({"type":"content_block_start","index":0,
        "content_block":{"type":"tool_use","id":"t1","name":"run","input":[]}});
    let calls = extract_tool_calls(Protocol::Anthropic, &start);
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].args.is_empty(),
        "空数组占位不得计为参数: {:?}",
        calls[0].args
    );
    let partial = serde_json::json!({"type":"content_block_delta","index":0,
        "delta":{"type":"input_json_delta","partial_json":"{\"x\":1}"}});
    let rest = extract_tool_calls(Protocol::Anthropic, &partial);
    assert_eq!(rest[0].args, "{\"x\":1}");
}

#[test]
fn t5_null_tool_fragment_skipped_without_entry() {
    let v = serde_json::json!({"choices":[{"delta":{"tool_calls":[null]}}]});
    let calls = extract_tool_calls(Protocol::Chat, &v);
    assert_eq!(calls.len(), 1);
    assert!(calls[0].name.is_none(), "空增量无名");
    assert!(calls[0].args.is_empty(), "空增量无参");
    let empty_custom = serde_json::json!({"choices":[{"message":{"custom_tool_call":{}}}]});
    assert!(extract_tool_calls(Protocol::Chat, &empty_custom).is_empty());
    let null_items = serde_json::json!({"choices":[{"message":{"custom_tool_call":[null, 42]}}]});
    assert!(extract_tool_calls(Protocol::Chat, &null_items).is_empty());
}

#[test]
fn t5_missing_index_falls_back_without_panic() {
    let v =
        serde_json::json!({"content_block":{"type":"tool_use","id":"a1","name":"bash","input":{}}});
    assert_eq!(anthropic_bucket_index(None, &v["content_block"], 7), 7);
    assert_eq!(
        anthropic_bucket_index(None, &serde_json::json!({"index": 4}), 7),
        4
    );
    assert_eq!(
        anthropic_bucket_index(Some(3), &serde_json::json!({"index": 9}), 7),
        3,
        "外层 index 优先"
    );
    let chat =
        serde_json::json!({"choices":[{"delta":{"tool_calls":[{"function":{"name":"run"}}]}}]});
    let calls = extract_tool_calls(Protocol::Chat, &chat);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].index, 0);
}

#[test]
fn t5_multi_index_grouping_keeps_slots_separate() {
    let v = serde_json::json!({"choices":[{"delta":{"tool_calls":[
        {"index":0,"id":"c0","function":{"name":"a","arguments":"{}"}},
        {"index":2,"id":"c2","function":{"name":"b","arguments":"{}"}}
    ]}}]});
    let calls = extract_tool_calls(Protocol::Chat, &v);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].index, 0);
    assert_eq!(calls[1].index, 2);
    assert_eq!(calls[0].name.as_deref(), Some("a"));
    assert_eq!(calls[1].name.as_deref(), Some("b"));
}

#[test]
fn fix3_missing_id_synthesizes_call_stable_id() {
    let v = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"index":2,"function":{"name":"run","arguments":"{}"}}]}}]});
    let calls = extract_tool_calls(Protocol::Chat, &v);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, "call_stable_2");
    assert!(calls[0].id_synth);
    assert_eq!(calls[0].name.as_deref(), Some("run"));
}

#[test]
fn fix3_preserved_id_normalizes_non_string_args() {
    let v = serde_json::json!({"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"q","arguments":{"a":1}}}]}}]});
    let calls = extract_tool_calls(Protocol::Chat, &v);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, "c1");
    assert!(!calls[0].id_synth);
    assert_eq!(calls[0].args, r#"{"a":1}"#);
    let v2 = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"id":"c2","function":{"name":"q"}}]}}]});
    let calls2 = extract_tool_calls(Protocol::Chat, &v2);
    assert_eq!(calls2[0].args, "");
}

#[test]
fn fix3_supports_legacy_and_custom_dialects() {
    let legacy = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
    let calls = extract_tool_calls(Protocol::Chat, &legacy);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name.as_deref(), Some("old"));
    assert!(calls[0].id_synth);
    let custom = serde_json::json!({"choices":[{"message":{"custom_tool_call":{"id":"k1","name":"t","input":{"p":2}}}}]});
    let calls2 = extract_tool_calls(Protocol::Chat, &custom);
    assert_eq!(calls2.len(), 1);
    assert_eq!(calls2[0].id, "k1");
    assert_eq!(calls2[0].args, r#"{"p":2}"#);
    let anth = serde_json::json!({"content_block":{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}});
    let calls3 = extract_tool_calls(Protocol::Anthropic, &anth);
    assert_eq!(calls3.len(), 1);
    assert_eq!(calls3[0].args, r#"{"cmd":"ls"}"#);
    let resp = serde_json::json!({"output":[{"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}]});
    let calls4 = extract_tool_calls(Protocol::Responses, &resp);
    assert_eq!(calls4.len(), 1);
    assert!(calls4[0].id_synth);
}

#[test]
fn responses_delta_extracted_by_three_level_key_ignoring_text() {
    let d1 = serde_json::json!({"type":"response.function_call_arguments.delta","output_index":1,"item_id":"item-7","sequence_number":0,"delta":"{\"x\":"});
    let calls = extract_tool_calls(Protocol::Responses, &d1);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].index, 1);
    assert_eq!(calls[0].id, "item-7");
    assert!(!calls[0].id_synth);
    assert_eq!(calls[0].args, "{\"x\":");
    let done = serde_json::json!({"type":"response.function_call_arguments.done","output_index":1,"item_id":"item-7","sequence_number":2,"name":"run","arguments":"{\"x\":1}"});
    let calls2 = extract_tool_calls(Protocol::Responses, &done);
    assert_eq!(calls2.len(), 1);
    assert_eq!(calls2[0].name.as_deref(), Some("run"));
    assert_eq!(calls2[0].args, "{\"x\":1}");
    let text =
        serde_json::json!({"type":"response.output_text.delta","output_index":0,"delta":"hi"});
    assert!(extract_tool_calls(Protocol::Responses, &text).is_empty());
    let item_done = serde_json::json!({"type":"response.output_item.done","output_index":2,"item":{"type":"function_call","id":"c9","name":"q","arguments":"{}"}});
    let calls3 = extract_tool_calls(Protocol::Responses, &item_done);
    assert_eq!(calls3.len(), 1);
    assert_eq!((calls3[0].index, calls3[0].id.as_str()), (2, "c9"));
}

#[test]
fn anthropic_interleaved_indices_bucketed_by_event_index() {
    let b0 = serde_json::json!({"content_block":{"type":"tool_use","index":3,"id":"a3","name":"t3","input":{}}});
    let calls = extract_tool_calls(Protocol::Anthropic, &b0);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].index, 3);
    let d1 =
        serde_json::json!({"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"a\":"}});
    let calls2 = extract_tool_calls(Protocol::Anthropic, &d1);
    assert_eq!(calls2.len(), 1);
    assert_eq!(calls2[0].index, 5);
    assert_eq!(calls2[0].args, "{\"a\":");
    assert!(calls2[0].id_synth);
}

#[test]
fn anthropic_outer_index_interleaving_keeps_buckets_separate() {
    let start0 = serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a0","name":"run"}});
    let start1 = serde_json::json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"a1","name":"run"}});
    let d0 = serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"x\":"}});
    let d1 = serde_json::json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"y\":"}});
    let c0 = extract_tool_calls(Protocol::Anthropic, &start0);
    assert_eq!((c0.len(), c0[0].index), (1, 0));
    assert_eq!(c0[0].id, "a0");
    let c1 = extract_tool_calls(Protocol::Anthropic, &start1);
    assert_eq!((c1.len(), c1[0].index), (1, 1));
    let p0 = extract_tool_calls(Protocol::Anthropic, &d0);
    assert_eq!((p0.len(), p0[0].index), (1, 0));
    assert_eq!(p0[0].args, "{\"x\":");
    let p1 = extract_tool_calls(Protocol::Anthropic, &d1);
    assert_eq!((p1.len(), p1[0].index), (1, 1));
    assert_eq!(p1[0].args, "{\"y\":");
    let inner = serde_json::json!({"content":[{"type":"tool_use","index":7,"id":"z","name":"q","input":{}}]});
    let ci = extract_tool_calls(Protocol::Anthropic, &inner);
    assert_eq!(ci[0].index, 7);
}

#[test]
fn anthropic_outer_index_wins_over_conflicting_inner() {
    // P0-2.3 回归：外层 0/1 + 内层 3/5 交错时以外层分桶（与流式同槽）。
    let start0 = serde_json::json!({"index":0,"content_block":{"type":"tool_use","index":3,"id":"a0","name":"run","input":{}}});
    let c0 = extract_tool_calls(Protocol::Anthropic, &start0);
    assert_eq!(c0.len(), 1);
    assert_eq!(c0[0].index, 0, "外层 0 须胜过内层 3");
    let d1 = serde_json::json!({"index":1,"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"y\":"}});
    let c1 = extract_tool_calls(Protocol::Anthropic, &d1);
    assert_eq!(c1.len(), 1);
    assert_eq!(c1[0].index, 1, "外层 1 须胜过内层 5");
    assert_eq!(c1[0].args, "{\"y\":");
    // 共享分桶函数直断言：三级回退（外层 > 内层 > 下标）。
    let blk = serde_json::json!({"index":3});
    assert_eq!(anthropic_bucket_index(Some(0), &blk, 9), 0);
    assert_eq!(anthropic_bucket_index(None, &blk, 9), 3);
    assert_eq!(anthropic_bucket_index(None, &serde_json::json!({}), 9), 9);
}

#[test]
fn responses_added_creates_slot_preserving_name_id() {
    // C9 起始事件建槽：`added` 无 arguments 仍须产出空参调用保留名/id。
    let added = serde_json::json!({"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","id":"call-9","name":"run"}});
    let calls = extract_tool_calls(Protocol::Responses, &added);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].index, 2);
    assert_eq!(calls[0].id, "call-9");
    assert!(!calls[0].id_synth);
    assert_eq!(calls[0].name.as_deref(), Some("run"));
    assert!(calls[0].args.is_empty());
    // 非 tool 形态 `added`（纯消息项）仍直返，不建槽。
    let msg = serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","content":[]}});
    assert!(extract_tool_calls(Protocol::Responses, &msg).is_empty());
    // 无名无 id 的裸 `added` 合成稳定 id，不断链。
    let bare = serde_json::json!({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call"}});
    let bare_calls = extract_tool_calls(Protocol::Responses, &bare);
    assert_eq!(bare_calls.len(), 1);
    assert!(bare_calls[0].id_synth);
}

#[test]
fn empty_custom_heartbeat_builds_no_entry() {
    // L16：空心跳（无 id/name/args）只 warn 不建条目；对照组非空仍建槽。
    let empty = serde_json::json!({"choices": [{"delta": {"custom_tool_call": {}}}]});
    assert!(
        extract_tool_calls(Protocol::Chat, &empty).is_empty(),
        "空 custom_tool_call 不得建条目"
    );
    let named = serde_json::json!({"choices": [{"delta": {"custom_tool_call": {"name": "run"}}}]});
    let calls = extract_tool_calls(Protocol::Chat, &named);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name.as_deref(), Some("run"));
}

#[test]
fn fix6_single_double_layer_fallback_with_missing_archive() {
    let m = GatewayMetrics::default();
    let single = serde_json::json!({"type":"response.failed","id":"r1"});
    assert_eq!(extract_conv_id(&single).as_deref(), Some("r1"));
    let dbl = serde_json::json!({"type":"response.incomplete","response":{"id":"r2"}});
    assert_eq!(extract_conv_id(&dbl).as_deref(), Some("r2"));
    let nested = serde_json::json!({"type":"error","data":{"response":{"id":"r3"}}});
    assert_eq!(extract_conv_id(&nested).as_deref(), Some("r3"));
    let err_obj = serde_json::json!({"type":"error","error":{"id":"e1"}});
    assert_eq!(extract_conv_id(&err_obj).as_deref(), Some("e1"));
    let empty = serde_json::json!({"type":"response.failed"});
    assert!(extract_conv_id(&empty).is_none());
    let (archived, exempt) = resolve_conv_id(None, &empty, Some(&m), "failed");
    assert!(archived.starts_with("unknown_") && archived.len() == 8 + 8);
    assert!(!exempt);
    assert_eq!(m.conv_missing_count("failed"), 1);
    let (hid, hexempt) = resolve_conv_id(
        Some("h1"),
        &serde_json::json!({"id":"b1"}),
        Some(&m),
        "failed",
    );
    assert_eq!(hid, "h1");
    assert!(hexempt);
    assert_eq!(m.conv_missing_count("failed"), 1);
}

#[test]
fn retrieval_args_action_query() {
    // T11/D10：官方 action 形态提取（query 字符串 / queries 数组序列化）。
    let single = serde_json::json!({"type":"web_search_call","action":{"type":"search","query":"veil audit"}});
    assert_eq!(retrieval_args(single.as_object().unwrap()), "veil audit");
    let multi = serde_json::json!({"type":"file_search_call","action":{"type":"search","queries":["a","b"]}});
    assert_eq!(retrieval_args(multi.as_object().unwrap()), r#"["a","b"]"#);
    let prefer_action = serde_json::json!({"action":{"query":"from-action"},"query":"from-top"});
    assert_eq!(
        retrieval_args(prefer_action.as_object().unwrap()),
        "from-action",
        "action 优先于顶层回退"
    );
    let null_action = serde_json::json!({"action":{"query":null,"queries":["q1"]}});
    assert_eq!(
        retrieval_args(null_action.as_object().unwrap()),
        r#"["q1"]"#
    );
}

#[test]
fn retrieval_args_legacy_fallback() {
    // T11/D10：legacy 顶层 query/queries 提取不因新增 action 分支回退。
    let q = serde_json::json!({"type":"web_search_call","query":"legacy"});
    assert_eq!(retrieval_args(q.as_object().unwrap()), "legacy");
    let qs = serde_json::json!({"type":"file_search_call","queries":["legacy","x"]});
    assert_eq!(retrieval_args(qs.as_object().unwrap()), r#"["legacy","x"]"#);
    let args_first = serde_json::json!({"arguments":"{\"a\":1}","action":{"query":"ignore"}});
    assert_eq!(
        retrieval_args(args_first.as_object().unwrap()),
        r#"{"a":1}"#,
        "arguments 优先于 action"
    );
    // `results` 仍排除（体量风险，只看查询）。
    let with_results = serde_json::json!({"action":{"query":"q"},"results":[{"big":"body"}]});
    assert_eq!(retrieval_args(with_results.as_object().unwrap()), "q");
}

#[test]
fn extract_conv_id_variants() {
    let cases: [(&serde_json::Value, Option<&str>); 7] = [
        (&serde_json::json!({"id":"top"}), Some("top")),
        (&serde_json::json!({"response":{"id":"r1"}}), Some("r1")),
        (&serde_json::json!({"data":{"id":"d1"}}), Some("d1")),
        (
            &serde_json::json!({"data":{"response":{"id":"r2"}}}),
            Some("r2"),
        ),
        (&serde_json::json!({"error":{"id":"e1"}}), Some("e1")),
        (&serde_json::json!({"error":"estr"}), Some("estr")),
        (&serde_json::json!({"type":"response.failed"}), None),
    ];
    for (v, want) in cases {
        assert_eq!(extract_conv_id(v).as_deref(), want, "变体不得回退: {v}");
    }
}

#[test]
fn anthropic_message_start_conv_id() {
    let v =
        serde_json::json!({"type":"message_start","message":{"id":"msg_abc","model":"claude-x"}});
    assert_eq!(extract_conv_id(&v).as_deref(), Some("msg_abc"));
    let empty = serde_json::json!({"type":"message_start","message":{"id":"","model":"claude-x"}});
    assert!(extract_conv_id(&empty).is_none(), "空 id 不得命中");
}
