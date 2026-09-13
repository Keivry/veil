#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../tool.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "tool.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "tool/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
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
