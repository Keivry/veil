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
fn sentinel_check语义对齐_四份全行可loads且keepalive可见() {
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
fn chat回放_终止恰1个done() {
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
fn anthropic回放_含stop三件套() {
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
fn responses回放_含completed终止() {
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
fn v1models回放_非对话透传单包() {
    let (_req, sse_lines, _audit) = load_fixture("sentinel_v1_models.jsonl");
    let events = replay(&sse_lines);
    let data = data_events(&events);
    assert_eq!(data.len(), 1, "v1/models 应为单个 data 包透传");
    let v: serde_json::Value = serde_json::from_str(&data[0].data).expect("v1/models data 可解析");
    assert_eq!(v.get("object").and_then(|o| o.as_str()), Some("list"));
}

#[test]
fn 空流_零事件不断链() {
    let mut parser = SseParser::new();
    let events = parser.push_bytes(b"");
    assert!(events.is_empty(), "空输入应零事件");
    let tail = parser.residual_json_aware();
    assert!(tail.is_empty(), "空流残余应为空");
    let norm = veil::service::block_inject::dedupe_terminal_frames(vec![], "chat");
    assert_eq!(veil::service::block_inject::count_done(&norm), 1);
}

#[test]
fn 坏json_解析器不崩且原样透出() {
    let mut parser = SseParser::new();
    let events = parser.push_bytes(b"data: {not-json\n\n");
    assert_eq!(events.len(), 1, "坏 JSON 行仍应产出事件");
    assert_eq!(events[0].data, "{not-json");
    let next = parser.push_bytes(b"data: [DONE]\n\n");
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].data, "[DONE]");
}

#[test]
fn 断连_半帧缓冲不断链残余可见() {
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
fn 跨分片utf8半字符按字节缓冲组装() {
    let mut parser = SseParser::new();
    let raw = "data: 中文\n\n".as_bytes();
    let mut events = Vec::new();
    for byte in raw {
        events.extend(parser.push_bytes(std::slice::from_ref(byte)));
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "中文");
}
