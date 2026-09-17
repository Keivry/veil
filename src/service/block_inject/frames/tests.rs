//! 帧/体合成单测（自 `frames.rs` 外迁兄弟文件，避免 800 行红线；纯搬移不改断言）。

use {
    super::*,
    crate::service::block_inject::{count_done, ensure_event_lines},
};

#[test]
fn frame_files_under_800_lines() {
    crate::test_support::file_len_under_800_or_split("frames.rs", include_str!("../frames.rs"));
    crate::test_support::file_len_under_800_or_split("frames/tests.rs", include_str!("tests.rs"));
}

/// 抽取帧内所有 `data:` 行的合法 JSON 载荷（`[DONE]` 跳过）。
fn data_payloads(frame: &str) -> Vec<Value> {
    frame
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter(|p| p.trim() != "[DONE]")
        .filter_map(|p| serde_json::from_str::<Value>(p).ok())
        .collect()
}

#[test]
fn synth_chat_frame_fields_complete() {
    // CHC-3/D8：合成 chat 流帧补齐 id/object/created/model 四字段且类型正确。
    let frames = chat_block_frames("policy");
    assert_eq!(frames.len(), 3);
    for (i, expected_content) in [(0usize, true), (1, false)] {
        let payload = data_payloads(&frames[i]).remove(0);
        assert!(
            payload["id"].as_str().is_some_and(|s| !s.is_empty()),
            "id 非空: {payload}"
        );
        assert_eq!(payload["object"], "chat.completion.chunk");
        assert!(payload["created"].is_u64(), "created 为整数: {payload}");
        assert!(
            payload["model"].as_str().is_some_and(|s| !s.is_empty()),
            "model 非空: {payload}"
        );
        assert_eq!(payload["choices"][0]["index"], 0);
        if expected_content {
            assert!(payload["choices"][0]["delta"]["content"].is_string());
        } else {
            assert_eq!(payload["choices"][0]["finish_reason"], "stop");
        }
    }
}

#[test]
fn no_synthetic_event_message() {
    // RSP-7/2.31：缺 `event:` 的 data 帧保持原形态，不注入 `event: message`。
    let raw = vec!["data: {\"a\":1}\n\n".to_string()];
    let out = ensure_event_lines(raw.clone());
    assert_eq!(out, raw, "不得注入 event: 行");
    assert!(!out[0].contains("event:"), "{}", out[0]);
    let with_event = vec!["event: x\ndata: {\"a\":1}\n\n".to_string()];
    assert_eq!(ensure_event_lines(with_event.clone()), with_event);
}

#[test]
fn block_frame_choice_coverage() {
    // CHC-6/2.25：合成 Chat 阻断帧的声明覆盖范围为单 choice index 0，锁定之。
    let frames = ensure_event_lines(chat_block_frames("policy"));
    let mut choice_indices = Vec::new();
    for f in &frames {
        for payload in data_payloads(f) {
            let choices = payload["choices"].as_array().expect("choices 须为数组");
            assert_eq!(choices.len(), 1, "声明覆盖单 choice: {payload}");
            choice_indices.push(choices[0]["index"].as_u64().expect("index 须为整数"));
        }
    }
    assert_eq!(choice_indices.len(), 2, "两数据帧各一个 choice");
    assert!(
        choice_indices.iter().all(|i| *i == 0),
        "声明覆盖 choices[].index == 0: {choice_indices:?}"
    );
}

#[test]
fn synth_chat_frame_sdk_parse() {
    // CHC-3/D8（SDK 等价）：规范流式增量为 `choices[].delta`，恰一裸 `[DONE]`。
    let frames = ensure_event_lines(chat_block_frames("policy"));
    assert_eq!(count_done(&frames), 1, "恰一 [DONE]");
    assert!(
        frames.iter().all(|f| !f.contains("event:")),
        "Chat 帧恒为纯 data: 形态"
    );
    let head = data_payloads(&frames[0]).remove(0);
    assert_eq!(head["object"], "chat.completion.chunk");
    assert_eq!(head["choices"][0]["delta"]["role"], "assistant");
    assert!(
        head["choices"][0]["delta"]["content"]
            .as_str()
            .unwrap()
            .contains("[blocked: policy]")
    );
    assert!(head["created"].is_u64() && head["model"].as_str().is_some());
    let tail = data_payloads(&frames[1]).remove(0);
    assert_eq!(tail["choices"][0]["finish_reason"], "stop");
    assert_eq!(tail["object"], "chat.completion.chunk");
}

#[test]
fn synth_frames_sequence_number_monotonic() {
    // RSP-3/D8：阻断与真空流全序列均自 0 单调递增、无缺口。
    for frames in [
        ensure_event_lines(responses_block_frames("r1")),
        ensure_event_lines(responses_truncated_frames("r1")),
    ] {
        let seqs: Vec<u64> = frames
            .iter()
            .flat_map(|f| data_payloads(f))
            .filter_map(|p| p["sequence_number"].as_u64())
            .collect();
        assert_eq!(seqs.len(), 7, "7 帧均须带序号: {seqs:?}");
        assert_eq!(
            seqs,
            (0..7u64).collect::<Vec<u64>>(),
            "须自 0 单调无缺口: {seqs:?}"
        );
    }
}

#[test]
fn synth_frames_sequence_number_required() {
    // RSP-3/D8：每帧结构断言含 `sequence_number`，不得省略。
    let frames = ensure_event_lines(responses_block_frames("r1"));
    assert_eq!(frames.len(), 7);
    for f in &frames {
        let payload = data_payloads(f).remove(0);
        assert!(
            payload.get("sequence_number").is_some(),
            "缺 sequence_number: {f}"
        );
    }
}

#[test]
fn synth_response_required_fields() {
    // RSP-4/D9：合成 `response` 对象含 `output`/`status`，
    // `output_text` 语义可达（`output` 为数组且含 output_text part）。
    let frames = ensure_event_lines(responses_block_frames("r1"));
    let completed = frames
        .iter()
        .find(|f| f.contains("response.completed"))
        .expect("须含 response.completed");
    let payload = data_payloads(completed).remove(0);
    let response = &payload["response"];
    assert_eq!(response["object"], "response");
    assert_eq!(response["status"], "completed");
    assert!(response["created_at"].is_number());
    assert!(response["model"].as_str().is_some_and(|s| !s.is_empty()));
    let output = response["output"].as_array().expect("output 须为数组");
    assert_eq!(output[0]["type"], "message");
    assert_eq!(output[0]["content"][0]["type"], "output_text");
    assert!(
        output[0]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("[blocked:")
    );
    let failed = ensure_event_lines(responses_truncated_frames("r1"));
    let payload = data_payloads(failed.last().unwrap()).remove(0);
    assert_eq!(payload["response"]["status"], "failed");
    assert!(payload["response"]["output"].is_array());
}

#[test]
fn synth_frames_sequence_number_after_block() {
    // A-2/F-02：合成注入起始基准 = cursor.map_or(0, |c| c + 1)——流内阻断
    // 接续已见最大序号（严格大于上游已发），真空流仍自 0（0..6 不变）。
    let blocked = ensure_event_lines(responses_block_frames_at("r1", 7));
    let seqs: Vec<u64> = blocked
        .iter()
        .flat_map(|f| data_payloads(f))
        .filter_map(|p| p["sequence_number"].as_u64())
        .collect();
    assert_eq!(
        seqs,
        (7..14u64).collect::<Vec<u64>>(),
        "阻断序列须接续 base: {seqs:?}"
    );

    let dispatched = ensure_event_lines(protocol_block_frames(
        GatewayProtocol::Responses,
        "audit",
        Some("r1"),
        0,
        None,
        Some(5),
    ));
    assert_eq!(dispatched.len(), 7);
    let first = data_payloads(&dispatched[0]).remove(0);
    assert_eq!(first["sequence_number"], 6, "游标 5 → base 6: {first}");

    let trunc = synthesize_truncation(GatewayProtocol::Responses, "r1", Some(5));
    assert_eq!(trunc.len(), 1);
    let tf = data_payloads(&trunc[0]).remove(0);
    assert_eq!(tf["sequence_number"], 6, "截断单帧须接续 base: {tf}");

    let vacuum = empty_stream_frames("responses", "r1");
    let vseqs: Vec<u64> = vacuum
        .iter()
        .flat_map(|f| data_payloads(f))
        .filter_map(|p| p["sequence_number"].as_u64())
        .collect();
    assert_eq!(vseqs, (0..7u64).collect::<Vec<u64>>(), "真空流 0..6 不变");
    let zero = synthesize_truncation(GatewayProtocol::Responses, "r1", None);
    assert_eq!(
        data_payloads(&zero[0]).remove(0)["sequence_number"],
        0,
        "无游标 base=0"
    );
}

#[test]
fn anthropic_block_frames_message_start_first() {
    // A-3/F-04：阻断五件套——首帧 `message_start` 恰一（空 content、null
    // stop_reason、usage 全 0、id 取会话标识），原四帧内容/顺序不动。
    let frames = ensure_event_lines(anthropic_block_frames_full("policy", 2, Some("conv-9")));
    assert_eq!(frames.len(), 5, "五件套: {frames:?}");
    let first = data_payloads(&frames[0]).remove(0);
    assert_eq!(first["type"], "message_start");
    assert_eq!(first["message"]["id"], "conv-9");
    assert_eq!(first["message"]["model"], "unknown_model");
    assert_eq!(first["message"]["content"], serde_json::json!([]));
    assert!(first["message"]["stop_reason"].is_null());
    assert_eq!(first["message"]["usage"]["input_tokens"], 0);
    assert_eq!(first["message"]["usage"]["output_tokens"], 0);
    let tail: Vec<String> = frames[1..]
        .iter()
        .filter_map(|f| {
            data_payloads(f).remove(0)["type"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert_eq!(
        tail,
        vec![
            "content_block_start",
            "content_block_stop",
            "message_delta",
            "message_stop"
        ],
        "原四帧顺序不动"
    );
    assert_eq!(
        data_payloads(&frames[1]).remove(0)["index"],
        2,
        "真实 index 保留"
    );
    let legacy = anthropic_block_frames("policy", 0);
    assert_eq!(legacy.len(), 5);
    assert_eq!(
        data_payloads(&legacy[0]).remove(0)["message"]["id"],
        "blocked-0",
        "旧 2 参入口 id 回退"
    );
    let vacuum = empty_stream_frames("anthropic", "v1");
    let vs = data_payloads(&vacuum[0]).remove(0);
    assert_eq!(vs["type"], "message_start");
    assert_eq!(vs["message"]["id"], "v1");
    assert_eq!(vs["message"]["model"], "unknown_model");
}

#[test]
fn nonstream_responses_block_body_required_fields() {
    // A-1/F-01：非流 Responses 阻断体与流式 failed 帧同形——字段集齐全、
    // `output` 恒空数组、`status` 恒 failed、`error` 仅 message。
    let body = nonstream_block_body(GatewayProtocol::Responses, "policy", "r1", None);
    assert_eq!(body["object"], "response");
    assert_eq!(body["status"], "failed");
    assert!(body["created_at"].is_u64(), "created_at 须为整数: {body}");
    assert_eq!(body["model"], "unknown_model");
    assert_eq!(body["id"], "r1");
    let output = body["output"].as_array().expect("output 须为数组");
    assert!(output.is_empty(), "output 恒空数组: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("[blocked: policy]")),
        "error.message 须携带阻断文案: {body}"
    );
    let err_keys: Vec<&String> = body["error"].as_object().unwrap().keys().collect();
    assert_eq!(
        err_keys,
        vec!["message"],
        "error 仅保留 message（不合成 code/param）"
    );
    let mut keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "created_at",
            "error",
            "id",
            "model",
            "object",
            "output",
            "status"
        ],
        "字段集须与流式 failed 帧同形"
    );
}

#[test]
fn nonstream_responses_block_body_upstream_echo() {
    // A-1：上游三级回退——`id`/`model`/`created_at` 优先回显上游，缺失才回退
    // `conv_id`/`unknown_model`/now；空上游与空 conv 的降级路径不 panic。
    let upstream = serde_json::json!({
        "id": "resp_up", "model": "gpt-5.1", "created_at": 1700000123
    });
    let echo = nonstream_block_body(
        GatewayProtocol::Responses,
        "policy",
        "conv-x",
        Some(&upstream),
    );
    assert_eq!(echo["id"], "resp_up", "优先回显上游 id");
    assert_eq!(echo["model"], "gpt-5.1", "优先回显上游归一 model");
    assert_eq!(echo["created_at"], 1700000123, "优先回显上游 created_at");
    assert_eq!(echo["status"], "failed");
    assert!(echo["output"].as_array().is_some_and(|o| o.is_empty()));

    let empty = serde_json::json!({});
    let degraded =
        nonstream_block_body(GatewayProtocol::Responses, "policy", "conv-x", Some(&empty));
    assert_eq!(degraded["id"], "conv-x", "无上游 id 回退 conv_id");
    assert_eq!(degraded["model"], "unknown_model", "无上游 model 回退默认");
    assert!(
        degraded["created_at"]
            .as_u64()
            .is_some_and(|t| t > 1_600_000_000),
        "无上游 created_at 回退 now: {degraded}"
    );
    let no_conv = nonstream_block_body(GatewayProtocol::Responses, "policy", "", None);
    assert_eq!(no_conv["id"], "blocked-0", "空 conv 回退合成 id");
    assert_eq!(no_conv["model"], "unknown_model");
    assert!(no_conv["output"].as_array().is_some_and(|o| o.is_empty()));
}

#[test]
fn streaming_block_frames_echo_id_model_match_nonstream() {
    // R5-03/R5-39：三协议流式阻断帧的 id/model 回显须与非流 `nonstream_block_body`
    // 同口径（上游 id/model 已知时不得硬编码 blocked-0/unknown_model）。
    let chat_upstream = serde_json::json!({"id": "conv-1", "model": "gpt-4o"});
    let chat = ensure_event_lines(chat_block_frames_full("audit", Some("conv-1"), "gpt-4o"));
    let head = data_payloads(&chat[0]).remove(0);
    let ns = nonstream_block_body(
        GatewayProtocol::Chat,
        "audit",
        "conv-1",
        Some(&chat_upstream),
    );
    assert_eq!(head["id"], ns["id"], "Chat 阻断帧 id 须与非流一致");
    assert_eq!(head["model"], ns["model"], "Chat 阻断帧 model 须与非流一致");
    assert_eq!(head["model"], "gpt-4o");

    let anth = ensure_event_lines(anthropic_block_frames_modeled(
        "audit",
        0,
        Some("msg-1"),
        "claude-3",
    ));
    let anth_start = data_payloads(&anth[0]).remove(0);
    let anth_ns = nonstream_block_body(
        GatewayProtocol::Anthropic,
        "audit",
        "msg-1",
        Some(&serde_json::json!({"model": "claude-3"})),
    );
    assert_eq!(anth_start["message"]["id"], anth_ns["id"]);
    assert_eq!(anth_start["message"]["model"], anth_ns["model"]);
    assert_eq!(anth_start["message"]["model"], "claude-3");

    let resp = ensure_event_lines(responses_block_frames_at_modeled("resp-1", 0, "gpt-5.1"));
    let completed = resp
        .iter()
        .find(|f| f.contains("response.completed"))
        .expect("须含 response.completed");
    let terminal = data_payloads(completed).remove(0);
    let resp_ns = nonstream_block_body(
        GatewayProtocol::Responses,
        "audit",
        "resp-1",
        Some(&serde_json::json!({"id": "resp-1", "model": "gpt-5.1"})),
    );
    assert_eq!(terminal["response"]["id"], resp_ns["id"]);
    assert_eq!(terminal["response"]["model"], resp_ns["model"]);
    assert_eq!(terminal["response"]["model"], "gpt-5.1");

    // 缺失回退口径：conv 缺失归 blocked-0，model 缺失归 unknown_model。
    let fallback = ensure_event_lines(chat_block_frames_full("audit", None, ""));
    let fb = data_payloads(&fallback[0]).remove(0);
    assert_eq!(fb["id"], "blocked-0");
    assert_eq!(fb["model"], "unknown_model");
    let anth_fb = ensure_event_lines(anthropic_block_frames_modeled("audit", 0, None, ""));
    assert_eq!(
        data_payloads(&anth_fb[0]).remove(0)["message"]["model"],
        "unknown_model"
    );
}

#[test]
fn responses_failed_frame_echoes_model() {
    // R5-39：`responses_failed_frame_modeled` 回显模型；旧入口维持 unknown_model。
    let modeled = responses_failed_frame_modeled("r1", None, None, "gpt-5.1");
    assert!(modeled.contains("\"model\":\"gpt-5.1\""), "{modeled}");
    let legacy = responses_failed_frame("r1", None, None);
    assert!(legacy.contains("\"model\":\"unknown_model\""), "{legacy}");
    let trunc = synthesize_truncation_modeled(GatewayProtocol::Responses, "r1", None, "gpt-5.1");
    assert!(trunc[0].contains("\"model\":\"gpt-5.1\""), "{}", trunc[0]);
}
