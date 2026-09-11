#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../fragments.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "fragments.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "fragments/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
}

use {
    super::{super::event::is_minor_event, *},
    crate::service::audit::AuditHold,
};

#[test]
fn chat_fragments_multi_choice_same_index_isolated() {
    // F-P1b 流侧：`n=2` 同 `index:0` 分桶隔离、参数不串扰，与非流同键。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let v = serde_json::json!({"choices":[
        {"delta":{"tool_calls":[{"index":0,"id":"c0a","function":{"name":"a","arguments":"{\"x\":1}"}}]}},
        {"delta":{"tool_calls":[{"index":0,"id":"c0b","function":{"name":"b","arguments":"{\"y\":2}"}}]}}
    ]});
    let frags = extract_tool_fragments(P::Chat, &v);
    assert_eq!(frags.len(), 2);
    assert_ne!(frags[0].0, frags[1].0, "跨 choice 同 index 须分桶");
    assert!(frags[0].3.contains("\"x\":1") && !frags[0].3.contains("\"y\""));
    assert!(frags[1].3.contains("\"y\":2") && !frags[1].3.contains("\"x\""));
    let calls = extract_tool_calls(P::Chat, &v);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].index, frags[0].0, "流/非流同槽");
    assert_eq!(calls[1].index, frags[1].0, "流/非流同槽");
}

#[test]
fn streaming_legacy_function_call_matches_nonstream() {
    use crate::service::llm_gateway::Protocol as P;
    let stream_delta = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
    let frags = extract_tool_fragments(P::Chat, &stream_delta);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].0, 0);
    assert_eq!(frags[0].1.as_deref(), Some("call_stable_0"));
    assert_eq!(frags[0].2.as_deref(), Some("old"));
    assert_eq!(frags[0].3, "{\"x\":1}");
    let non_stream = serde_json::json!({"choices":[{"message":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
    let frags2 = extract_tool_fragments(P::Chat, &non_stream);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].2.as_deref(), Some("old"));
    assert_eq!(frags2[0].1.as_deref(), Some("call_stable_0"));
    let legacy_arr = serde_json::json!({"choices":[{"delta":{"function_call":[{"name":"a","arguments":"{}"}]}}]});
    let frags3 = extract_tool_fragments(P::Chat, &legacy_arr);
    assert!(frags3.is_empty() || frags3.len() == 1);
}

#[test]
fn dual_tool_calls_accumulate_independently_by_index() {
    use crate::service::llm_gateway::Protocol as P;
    let two = serde_json::json!({"choices":[{"delta":{"tool_calls":[
        {"index":0,"id":"call_a","type":"function","function":{"name":"exec_a","arguments":"{\"x\":1}"}},
        {"index":1,"id":"call_b","type":"function","function":{"name":"exec_b","arguments":"{\"y\":2}"}}
    ]}}]});
    let frags = extract_tool_fragments(P::Chat, &two);
    assert_eq!(frags.len(), 2, "双路须各一条: {frags:?}");
    assert_eq!(frags[0].0, 0);
    assert_eq!(frags[1].0, 1);
    assert_eq!(frags[0].2.as_deref(), Some("exec_a"));
    assert_eq!(frags[1].2.as_deref(), Some("exec_b"));
    assert!(frags[0].3.contains("\"x\":1") && !frags[0].3.contains("\"y\""));
    assert!(frags[1].3.contains("\"y\":2") && !frags[1].3.contains("\"x\""));
}

#[test]
fn anthropic_array_content_aligns_with_gateway() {
    use crate::service::llm_gateway::Protocol as P;
    let content_arr = serde_json::json!({"content":[{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}]});
    let frags = extract_tool_fragments(P::Anthropic, &content_arr);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].1.as_deref(), Some("a1"));
    assert_eq!(frags[0].2.as_deref(), Some("bash"));
    assert_eq!(frags[0].3, r#"{"cmd":"ls"}"#);
    let msg_content = serde_json::json!({"message":{"content":[{"type":"tool_use","id":"m1","name":"run","input":{"p":2}}]}});
    let frags2 = extract_tool_fragments(P::Anthropic, &msg_content);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].1.as_deref(), Some("m1"));
    let delta =
        serde_json::json!({"delta":{"type":"tool_use","name":"t","partial_json":"{\"a\":"}});
    let frags3 = extract_tool_fragments(P::Anthropic, &delta);
    assert_eq!(frags3.len(), 1);
    assert_eq!(frags3[0].1.as_deref(), Some("call_stable_0"));
    let text_only = serde_json::json!({"delta":{"type":"text","text":"hi"}});
    assert!(extract_tool_fragments(P::Anthropic, &text_only).is_empty());
}

#[test]
fn anthropic_buckets_by_event_index_not_position() {
    use crate::service::llm_gateway::Protocol as P;
    let first = serde_json::json!({"content_block":{"type":"tool_use","index":4,"id":"a4","name":"t","input":{}}});
    let frags = extract_tool_fragments(P::Anthropic, &first);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].0, 4);
    let second =
        serde_json::json!({"delta":{"type":"input_json_delta","index":4,"partial_json":"{}"}});
    let frags2 = extract_tool_fragments(P::Anthropic, &second);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].0, 4);
    assert_eq!(frags2[0].3, "{}");
}

#[test]
fn responses_delta_carries_sequence_and_done_is_full() {
    use crate::service::llm_gateway::Protocol as P;
    let delta = serde_json::json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"it1","sequence_number":3,"delta":"{\"a\":"});
    let frags = extract_tool_fragments(P::Responses, &delta);
    assert_eq!(frags.len(), 1);
    assert_eq!(super::super::event::extract_responses_seq(&delta), Some(3));
    assert!(!AuditHold::is_complete_event(&delta));
    let done = serde_json::json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"it1","sequence_number":4,"name":"run","arguments":"{\"a\":1}"});
    let frags2 = extract_tool_fragments(P::Responses, &done);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].2.as_deref(), Some("run"));
    assert!(AuditHold::is_complete_event(&done));
}

#[test]
fn mixed_thinking_tool_fragments_win_hold() {
    // E7-P0 混帧回归：`content_block_delta` 同含 `thinking_delta` 与
    // `partial_json` 时工具片段优先，非空走 tool 通道进 hold 审计，
    // 剩余 thinking 部分才走 minor 透传；纯 thinking 帧仍为 minor。
    use crate::service::llm_gateway::Protocol as P;
    let mixed = serde_json::json!({
        "type": "content_block_delta",
        "index": 1,
        "delta": {"type": "thinking_delta", "thinking": "让我想想", "partial_json": "{\"x\":"}
    });
    let frags = extract_tool_fragments(P::Anthropic, &mixed);
    assert!(!frags.is_empty(), "混帧工具增量不得漏提: {mixed}");
    let is_tool_event = !frags.is_empty();
    let minor = !is_tool_event && is_minor_event(P::Anthropic, &mixed);
    assert!(!minor, "混帧不得整帧标 minor");
    // 主循环同形：tool 通道进 hold，审计三元组可见。
    let mut hold = AuditHold::new(1_048_576);
    for (idx, id, name, args) in &frags {
        hold.push_fragment(*idx, id.as_deref(), name.as_deref(), args);
    }
    assert!(
        !hold.tool_triples().is_empty(),
        "混帧工具增量须进 hold 审计"
    );
    assert!(hold.tool_triples()[0].2.contains("\"x\":"));
    // 纯 thinking 帧：仍为 minor，工具片段为空即 hold 无新增。
    let pure = serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "thinking_delta", "thinking": "纯思考"}
    });
    assert!(extract_tool_fragments(P::Anthropic, &pure).is_empty());
    assert!(is_minor_event(P::Anthropic, &pure));
    let hold2 = AuditHold::new(1_048_576);
    assert!(hold2.tool_triples().is_empty(), "纯 thinking 不得进 hold");
}

#[test]
fn responses_added_builds_slot_so_truncation_stays_auditable() {
    // C9 起始截断漏审回归：仅 `added` 到达（`.done` 前截断）时槽须已建，
    // 名/id 保留至审计三元组；非 tool 起始不建槽。
    use crate::service::llm_gateway::Protocol as P;
    let added = serde_json::json!({"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","id":"call-9","name":"run"}});
    let frags = extract_tool_fragments(P::Responses, &added);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].0, 2);
    assert_eq!(frags[0].1.as_deref(), Some("call-9"));
    assert_eq!(frags[0].2.as_deref(), Some("run"));
    assert!(frags[0].3.is_empty());
    // 复用既有按槽缓冲建槽：空参分片入槽后，即使零参数到达完成点，
    // 审计仍可见起始名（截断前可审计，不断链漏审）。
    let mut hold = AuditHold::new(1_048_576);
    for (idx, id, name, args) in &frags {
        let key = AuditHold::responses_key(id.as_deref(), *idx);
        hold.push_responses_fragment(&key, *idx, None, id.as_deref(), name.as_deref(), args);
        hold.mark_responses_done(&key, None);
    }
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1);
    assert_eq!(triples[0].0, 2);
    assert_eq!(triples[0].1, "run");
    let msg = serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","content":[]}});
    assert!(extract_tool_fragments(P::Responses, &msg).is_empty());
}

#[test]
fn responses_custom_tool_call_stream_matches_nonstream() {
    // C9 流式 custom 覆盖：同调用在流/非流须同结论（名/参/id 一致）。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let nested = serde_json::json!({"output":[{"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}]});
    let frags = extract_tool_fragments(P::Responses, &nested);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].2.as_deref(), Some("ct"));
    assert_eq!(frags[0].3, "{}");
    let calls = extract_tool_calls(P::Responses, &nested);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name.as_deref(), frags[0].2.as_deref());
    assert_eq!(calls[0].args, frags[0].3);
    // 裸回退形态（`tool_name`+`input` 别名）双向同解。
    let bare = serde_json::json!({"output":[{"type":"tool","tool_name":"grep","input":{"p":1}}]});
    let frags2 = extract_tool_fragments(P::Responses, &bare);
    assert_eq!(frags2.len(), 1);
    assert_eq!(frags2[0].2.as_deref(), Some("grep"));
    assert_eq!(frags2[0].3, r#"{"p":1}"#);
    let calls2 = extract_tool_calls(P::Responses, &bare);
    assert_eq!(calls2.len(), 1);
    assert_eq!(calls2[0].name.as_deref(), Some("grep"));
    assert_eq!(calls2[0].args, r#"{"p":1}"#);
    // 纯消息项双向皆不建槽。
    let msg = serde_json::json!({"output":[{"type":"message","id":"m1","content":[]}]});
    assert!(extract_tool_fragments(P::Responses, &msg).is_empty());
    assert!(extract_tool_calls(P::Responses, &msg).is_empty());
}

#[test]
fn retrieval_calls_reach_identical_verdicts_across_modes() {
    // C10 同调用同结论：同一检索调用经流/非流须得同一审计结论。
    use crate::{
        config::AuditMode,
        service::{
            audit::{AuditPolicy, evaluate_with_whitelist, test_whitelist},
            llm_gateway::{Protocol as P, extract_tool_calls},
        },
    };
    let policy = AuditPolicy::default_policy();
    let nonstream = serde_json::json!({"output":[{"type":"file_search_call","id":"fs1","queries":["rm -rf /"]}]});
    let calls = extract_tool_calls(P::Responses, &nonstream);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name.as_deref(), Some("file_search"));
    assert!(calls[0].args.contains("rm -rf /"));
    let stream = serde_json::json!({"type":"response.file_search_call.completed","output_index":0,"item_id":"fs1","queries":["rm -rf /"]});
    let frags = extract_tool_fragments(P::Responses, &stream);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].2.as_deref(), Some("file_search"));
    assert!(frags[0].3.contains("rm -rf /"));
    assert!(
        !is_minor_event(P::Responses, &stream),
        "检索事件不再列为次要"
    );
    let v_stream = evaluate_with_whitelist(
        AuditMode::Block,
        frags[0].2.as_deref().unwrap_or(""),
        &frags[0].3,
        &policy,
        test_whitelist(),
    );
    let v_nonstream = evaluate_with_whitelist(
        AuditMode::Block,
        calls[0].name.as_deref().unwrap_or(""),
        &calls[0].args,
        &policy,
        test_whitelist(),
    );
    assert!(
        matches!(v_stream, crate::service::audit::AuditVerdict::Block { .. }),
        "流式危险检索须阻断"
    );
    assert!(
        matches!(
            v_nonstream,
            crate::service::audit::AuditVerdict::Block { .. }
        ),
        "非流危险检索须阻断"
    );
    // 良性检索双向同放行；检索外围仍透传不审计。
    let benign_ns =
        serde_json::json!({"output":[{"type":"web_search_call","id":"w1","queries":["hello"]}]});
    let benign_calls = extract_tool_calls(P::Responses, &benign_ns);
    assert_eq!(benign_calls[0].name.as_deref(), Some("web_search"));
    let benign_s = serde_json::json!({"type":"response.web_search_call.completed","output_index":0,"item_id":"w1","queries":["hello"]});
    let benign_frags = extract_tool_fragments(P::Responses, &benign_s);
    assert_eq!(benign_frags[0].2.as_deref(), Some("web_search"));
    assert!(matches!(
        evaluate_with_whitelist(
            AuditMode::Block,
            "web_search",
            &benign_frags[0].3,
            &policy,
            test_whitelist()
        ),
        crate::service::audit::AuditVerdict::Allow
    ));
    assert!(is_minor_event(
        P::Responses,
        &serde_json::json!({"type":"response.reasoning.delta"})
    ));
}

#[test]
fn stream_interleaved_outer_index_matches_nonstream_slot() {
    // P0-2.3 回归：流式分桶与非流同槽（外层 0/1 胜过内层 3/5）。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let start0 = serde_json::json!({"index":0,"content_block":{"type":"tool_use","index":3,"id":"a0","name":"run","input":{}}});
    let frags = extract_tool_fragments(P::Anthropic, &start0);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].0, 0, "流式外层 0 须胜过内层 3");
    let calls = extract_tool_calls(P::Anthropic, &start0);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].index, frags[0].0, "流/非流同槽");
    let d1 = serde_json::json!({"index":1,"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"y\":"}});
    let frags1 = extract_tool_fragments(P::Anthropic, &d1);
    assert_eq!(frags1.len(), 1);
    assert_eq!(frags1[0].0, 1, "流式外层 1 须胜过内层 5");
    let calls1 = extract_tool_calls(P::Anthropic, &d1);
    assert_eq!(calls1.len(), 1);
    assert_eq!(calls1[0].index, frags1[0].0, "流/非流同槽");
}

#[test]
fn tool_extract_parity() {
    // X2/D8 9.1：同一输入（缺参/缺 id/`output_index` 缺省）两入口字段值与桶号一致。
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
    ];
    for (proto, v) in cases {
        let frags = extract_tool_fragments(proto, &v);
        let calls = extract_tool_calls(proto, &v);
        assert_eq!(frags.len(), calls.len(), "{proto:?} 条目数一致: {v}");
        for (f, c) in frags.iter().zip(calls.iter()) {
            assert_eq!(f.0, c.index, "{proto:?} 桶号一致: {v}");
            assert_eq!(
                f.1.as_deref(),
                Some(c.id.as_str()),
                "{proto:?} id 一致: {v}"
            );
            assert_eq!(f.2, c.name, "{proto:?} name 一致: {v}");
            assert_eq!(f.3, c.args, "{proto:?} args 一致: {v}");
        }
    }
}

#[test]
fn fragment_nonstream_parity() {
    // X2/D8 9.2 三组锁定：Chat 多 choice、Responses `output_index`、缺参缺 id。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let chat = serde_json::json!({"choices":[
        {"delta":{"tool_calls":[{"index":0,"id":"c0","function":{"name":"a","arguments":"{\"x\":1}"}}]}},
        {"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"b","arguments":"{\"y\":2}"}}]}}
    ]});
    let frags = extract_tool_fragments(P::Chat, &chat);
    let calls = extract_tool_calls(P::Chat, &chat);
    assert_eq!(frags.len(), 2);
    for (f, c) in frags.iter().zip(calls.iter()) {
        assert_eq!(f.0, c.index);
        assert_eq!(f.1.as_deref(), Some(c.id.as_str()));
        assert_eq!(f.2, c.name);
        assert_eq!(f.3, c.args);
    }
    assert_ne!(frags[0].0, frags[1].0, "多 choice 同 index 分桶隔离");
    let resp = serde_json::json!({"output":[
        {"type":"function_call","output_index":5,"id":"f5","name":"run","arguments":"{\"a\":1}"},
        {"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}
    ]});
    let frags_r = extract_tool_fragments(P::Responses, &resp);
    let calls_r = extract_tool_calls(P::Responses, &resp);
    assert_eq!(frags_r.len(), calls_r.len());
    for (f, c) in frags_r.iter().zip(calls_r.iter()) {
        assert_eq!(f.0, c.index, "Responses 桶号一致");
        assert_eq!(f.1.as_deref(), Some(c.id.as_str()));
        assert_eq!(f.2, c.name);
        assert_eq!(f.3, c.args);
    }
    assert_eq!(frags_r[0].0, 5, "显式 output_index 锁定");
    let missing = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"index":0}]}}]});
    let f = extract_tool_fragments(P::Chat, &missing);
    let c = extract_tool_calls(P::Chat, &missing);
    assert_eq!(f[0].1.as_deref(), Some(c[0].id.as_str()));
    assert_eq!(f[0].1.as_deref(), Some("call_stable_0"));
    assert_eq!(f[0].3, c[0].args);
}

#[test]
fn tool_bucket_parity() {
    // P9：Responses `output[]` 流式分片与非流提取桶号同键
    //（`output_index` 存在同值、缺失均回退枚举下标）。
    use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
    let with_index = serde_json::json!({"output":[
        {"type":"function_call","output_index":3,"id":"f3","name":"run","arguments":"{}"},
        {"type":"function_call","id":"f0","name":"run2","arguments":"{}"}
    ]});
    let frags = extract_tool_fragments(P::Responses, &with_index);
    let calls = extract_tool_calls(P::Responses, &with_index);
    assert_eq!(frags.len(), 2);
    assert_eq!(calls.len(), 2);
    assert_eq!(frags[0].0, 3, "显式 output_index 优先");
    assert_eq!(frags[1].0, 1, "缺失回退枚举下标");
    assert_eq!(frags[0].0, calls[0].index, "流/非流同键（显式）");
    assert_eq!(frags[1].0, calls[1].index, "流/非流同键（回退）");
    let no_index = serde_json::json!({"output":[
        {"type":"function_call","id":"a","name":"x","arguments":"{}"},
        {"type":"function_call","id":"b","name":"y","arguments":"{}"}
    ]});
    let frags2 = extract_tool_fragments(P::Responses, &no_index);
    let calls2 = extract_tool_calls(P::Responses, &no_index);
    assert_eq!(frags2.len(), 2);
    assert_eq!(calls2.len(), 2);
    for (f, c) in frags2.iter().zip(calls2.iter()) {
        assert_eq!(f.0, c.index, "全缺失场景须同键");
    }
    assert_eq!(frags2[0].0, 0);
    assert_eq!(frags2[1].0, 1);
}
