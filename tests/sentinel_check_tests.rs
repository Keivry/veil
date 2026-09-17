//! 8.1 sentinel 录制回放：对 `tests/fixtures/sentinel_*.jsonl` 做 `--check` 对齐校验，
//! 并经 `veil::service::sse::SseParser::push_bytes` 回放断言三协议终止语义。
//!
//! 对齐原仓 `scripts/sentinel_record.py --check` 语义：
//! 每行合法 JSON；`kind=sse` 行含 `line` 字段；chat/anthropic/responses 含 `: keepalive`。

use {std::collections::HashMap, veil::service::sse::SseParser};

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn load_fixture(name: &str) -> (Vec<serde_json::Value>, Vec<String>, Vec<serde_json::Value>) {
    let text = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("缺少 fixture {name}: {e}"));
    let mut requests = Vec::new();
    let mut sse_lines = Vec::new();
    let mut audits = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let obj: serde_json::Value = serde_json::from_str(raw)
            .unwrap_or_else(|e| panic!("{name}:{} JSON 解析失败: {e}", i + 1));
        match obj.get("kind").and_then(|k| k.as_str()) {
            Some("request") => requests.push(obj),
            Some("sse") => {
                let line = obj
                    .get("line")
                    .and_then(|l| l.as_str())
                    .unwrap_or_else(|| panic!("{name}:{} sse 行缺 line 字段", i + 1));
                sse_lines.push(line.to_string());
            }
            Some("audit") => audits.push(obj),
            other => panic!("{name}:{} 未知 kind: {other:?}", i + 1),
        }
    }
    assert!(!requests.is_empty(), "{name} 缺少 request 行");
    assert!(!sse_lines.is_empty(), "{name} 缺少 sse 行");
    assert!(!audits.is_empty(), "{name} 缺少 audit 行");
    (requests, sse_lines, audits)
}

fn replay(sse_lines: &[String]) -> Vec<veil::service::sse::SseEvent> {
    let mut parser = SseParser::new();
    let mut events = Vec::new();
    for line in sse_lines {
        events.extend(parser.push_bytes(line.as_bytes()));
    }
    events
}

fn data_events(events: &[veil::service::sse::SseEvent]) -> Vec<&veil::service::sse::SseEvent> {
    events.iter().filter(|e| !e.data.is_empty()).collect()
}

fn count_done(data: &[&veil::service::sse::SseEvent]) -> usize {
    data.iter()
        .filter(|e| {
            e.data
                .lines()
                .any(|l| l.trim() == "[DONE]" || e.data.trim() == "[DONE]")
        })
        .count()
}

#[test]
fn sentinel_check_semantics_aligned_all_fixtures_parseable_with_keepalive() {
    let mut seen_keepalive: HashMap<&str, bool> = HashMap::new();
    for name in [
        "sentinel_chat.jsonl",
        "sentinel_anthropic.jsonl",
        "sentinel_responses.jsonl",
        "sentinel_v1_models.jsonl",
    ] {
        let text = std::fs::read_to_string(fixture_path(name)).expect("fixture 可读");
        for (i, raw) in text.lines().enumerate() {
            serde_json::from_str::<serde_json::Value>(raw)
                .unwrap_or_else(|e| panic!("{name}:{} loads 失败: {e}", i + 1));
        }
        let has_keepalive = text.contains(": keepalive");
        seen_keepalive.insert(name, has_keepalive);
    }
    for name in [
        "sentinel_chat.jsonl",
        "sentinel_anthropic.jsonl",
        "sentinel_responses.jsonl",
    ] {
        assert!(
            seen_keepalive[name],
            "{name} 缺少 keepalive 注释（--check 语义）"
        );
    }
}

#[test]
fn chat_replay_terminates_with_exactly_one_done() {
    let (_req, sse_lines, _audit) = load_fixture("sentinel_chat.jsonl");
    let events = replay(&sse_lines);
    let data = data_events(&events);
    assert!(!data.is_empty(), "chat 应有 data 事件");
    assert_eq!(count_done(&data), 1, "chat [DONE] 必须恰 1 个");
    for ev in &data {
        if ev.data.trim() == "[DONE]" {
            continue;
        }
        serde_json::from_str::<serde_json::Value>(&ev.data)
            .unwrap_or_else(|e| panic!("chat data 非 JSON: {e}: {}", ev.data));
    }
    let comment_only = events.iter().filter(|e| e.is_comment_only).count();
    assert!(comment_only >= 1, "chat 应透传 keepalive 注释");
}

#[test]
fn anthropic_replay_contains_stop_triad() {
    let (_req, sse_lines, _audit) = load_fixture("sentinel_anthropic.jsonl");
    let events = replay(&sse_lines);
    let data = data_events(&events);
    assert!(!data.is_empty(), "anthropic 应有 data 事件");
    let joined: String = data
        .iter()
        .map(|e| e.data.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("content_block_stop"),
        "anthropic 缺 content_block_stop"
    );
    assert!(joined.contains("message_stop"), "anthropic 缺 message_stop");
    let with_event = events.iter().filter(|e| e.event_type.is_some()).count();
    assert!(with_event >= 2, "anthropic 事件应带 event: 行");
    for ev in &data {
        serde_json::from_str::<serde_json::Value>(&ev.data)
            .unwrap_or_else(|e| panic!("anthropic data 非 JSON: {e}: {}", ev.data));
    }
}

#[test]
fn responses_replay_contains_completed_terminator() {
    let (_req, sse_lines, _audit) = load_fixture("sentinel_responses.jsonl");
    let events = replay(&sse_lines);
    let data = data_events(&events);
    assert!(!data.is_empty(), "responses 应有 data 事件");
    let joined: String = data
        .iter()
        .map(|e| e.data.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("response.completed"),
        "responses 缺 response.completed"
    );
    for ev in &data {
        serde_json::from_str::<serde_json::Value>(&ev.data)
            .unwrap_or_else(|e| panic!("responses data 非 JSON: {e}: {}", ev.data));
    }
}

#[test]
fn v1_models_replay_passthrough_single_packet() {
    let (_req, sse_lines, _audit) = load_fixture("sentinel_v1_models.jsonl");
    let events = replay(&sse_lines);
    let data = data_events(&events);
    assert_eq!(data.len(), 1, "v1/models 应为单个 data 包透传");
    let v: serde_json::Value = serde_json::from_str(&data[0].data).expect("v1/models data 可解析");
    assert_eq!(v.get("object").and_then(|o| o.as_str()), Some("list"));
}

#[test]
fn empty_stream_yields_zero_events_without_breaking_chain() {
    let mut parser = SseParser::new();
    let events = parser.push_bytes(b"");
    assert!(events.is_empty(), "空输入应零事件");
    let tail = parser.residual_json_aware();
    assert!(tail.is_empty(), "空流残余应为空");
    // R7-07：`dedupe_terminal_frames`/`count_done` 已随仅测试引用收编为
    // `#[cfg(test)]`（集成测试以非 cfg(test) 链接本库、不可见），chat 空流
    // 恰一 `[DONE]` 归一语义改由生产入口 `empty_stream_frames_modeled` 断言。
    let norm = veil::service::block_inject::empty_stream_frames_modeled("chat", "empty-stream", "");
    assert_eq!(norm, vec!["data: [DONE]\n\n".to_string()]);
}

#[test]
fn malformed_json_parser_survives_and_passes_through() {
    let mut parser = SseParser::new();
    let events = parser.push_bytes(b"data: {not-json\n\n");
    assert_eq!(events.len(), 1, "坏 JSON 行仍应产出事件");
    assert_eq!(events[0].data, "{not-json");
    let next = parser.push_bytes(b"data: [DONE]\n\n");
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].data, "[DONE]");
}

#[test]
fn truncated_half_frame_buffered_residual_visible() {
    let mut parser = SseParser::new();
    let events = parser.push_bytes(b"data: {\"a\": 1");
    assert!(events.is_empty(), "半帧不应提前产出事件");
    let rest = parser.push_bytes(b"}\n\n");
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].data, "{\"a\": 1}");
    let mut cut = SseParser::new();
    assert!(cut.push_bytes(b"data: {\"a\": 1").is_empty());
    let residual = cut.residual_json_aware();
    assert!(residual.contains("\"a\""), "断连残余应保留已收字节");
}

#[test]
fn split_utf8_half_char_reassembled_bytewise() {
    let mut parser = SseParser::new();
    let raw = "data: 中文\n\n".as_bytes();
    let mut events = Vec::new();
    for byte in raw {
        events.extend(parser.push_bytes(std::slice::from_ref(byte)));
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "中文");
}
