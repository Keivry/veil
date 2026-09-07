use super::sse::StreamMeta;

pub fn chat_block_frames(reason: &str) -> Vec<String> {
    vec![
        format!(
            "event: message\ndata: {{\"choices\":[{{\"finish_reason\":\"stop\",\"message\":{{\"role\":\"assistant\",\"content\":\"[blocked: {reason}]\"}}}}]}}\n\n"
        ),
        "data: [DONE]\n\n".to_string(),
    ]
}

pub fn anthropic_block_frames(reason: &str) -> Vec<String> {
    vec![
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_string(),
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n".to_string(),
        format!("event: message_stop\ndata: {{\"type\":\"message_stop\",\"reason\":\"{reason}\"}}\n\n"),
    ]
}

pub fn responses_block_frames(response_id: &str) -> Vec<String> {
    vec![format!(
        "event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"{response_id}\",\"status\":\"completed\"}}}}\n\n"
    )]
}

pub fn responses_truncated_frames(response_id: &str) -> Vec<String> {
    vec![format!(
        "event: response.failed\ndata: {{\"type\":\"response.failed\",\"response\":{{\"id\":\"{response_id}\",\"status\":\"failed\"}}}}\n\n"
    )]
}

pub fn ensure_event_lines(frames: Vec<String>) -> Vec<String> {
    frames
        .into_iter()
        .map(|f| {
            if f.lines().any(|l| l.starts_with("event:")) {
                f
            } else if let Some(pos) = f.find("data:") {
                format!("event: message\n{}", &f[pos..])
            } else {
                f
            }
        })
        .collect()
}

pub fn mark_terminal(meta: &mut StreamMeta) { meta.terminal_injected = true; }

pub fn chat_done_frame() -> String { "event: message\ndata: [DONE]\n\n".to_string() }

pub fn is_done_frame(frame: &str) -> bool {
    frame.lines().any(|l| {
        let t = l.trim();
        t == "data: [DONE]" || t == "data:[DONE]"
    })
}

pub fn has_chat_terminal(frames: &[String]) -> bool { frames.iter().any(|f| is_done_frame(f)) }

pub fn normalize_chat_done(frames: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = frames.into_iter().filter(|f| !is_done_frame(f)).collect();
    kept = ensure_event_lines(kept);
    kept.push(chat_done_frame());
    kept
}

pub fn dedupe_terminal_frames(frames: Vec<String>, protocol: &str) -> Vec<String> {
    match protocol {
        "chat" => normalize_chat_done(frames),
        "anthropic" => {
            let mut seen_stop = false;
            let mut out = Vec::new();
            for f in ensure_event_lines(frames) {
                let is_stop = f.contains("message_stop");
                if is_stop {
                    if seen_stop {
                        continue;
                    }
                    seen_stop = true;
                }
                out.push(f);
            }
            out
        }
        _ => {
            let mut seen_term = false;
            let mut out = Vec::new();
            for f in ensure_event_lines(frames) {
                let is_term = f.contains("response.completed") || f.contains("response.failed");
                if is_term {
                    if seen_term {
                        continue;
                    }
                    seen_term = true;
                }
                out.push(f);
            }
            out
        }
    }
}

pub fn should_discard_after_terminal(terminated: bool) -> bool { terminated }

pub fn count_done(frames: &[String]) -> usize {
    frames
        .iter()
        .filter(|f| f.contains("data: [DONE]") || f.contains("data:[DONE]"))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat阻断恒以done恰1个收尾() {
        let frames = ensure_event_lines(chat_block_frames("policy"));
        assert_eq!(count_done(&frames), 1);
        assert!(
            frames
                .iter()
                .all(|f| f.lines().any(|l| l.starts_with("event:")))
        );
    }

    #[test]
    fn anthropic三件套终止() {
        let frames = ensure_event_lines(anthropic_block_frames("policy"));
        let joined = frames.join("");
        assert!(joined.contains("content_block_stop"));
        assert!(joined.contains("message_delta"));
        assert!(joined.contains("message_stop"));
        assert!(
            frames
                .iter()
                .all(|f| f.lines().any(|l| l.starts_with("event:")))
        );
    }

    #[test]
    fn responses阻断与截断区分() {
        let done = ensure_event_lines(responses_block_frames("r1"));
        let failed = ensure_event_lines(responses_truncated_frames("r1"));
        assert!(done.join("").contains("response.completed"));
        assert!(!done.join("").contains("response.failed"));
        assert!(failed.join("").contains("response.failed"));
        assert!(!failed.join("").contains("response.completed"));
        assert!(
            done.iter()
                .chain(failed.iter())
                .all(|f| f.lines().any(|l| l.starts_with("event:")))
        );
    }

    #[test]
    fn 缺event行阻断载荷补全() {
        let raw = vec!["data: {\"a\":1}\n\n".to_string()];
        let fixed = ensure_event_lines(raw);
        assert!(fixed[0].lines().any(|l| l.starts_with("event:")));
        assert!(fixed[0].contains("data:"));
    }

    #[test]
    fn 终止标记落meta() {
        let mut meta = StreamMeta::default();
        mark_terminal(&mut meta);
        assert!(meta.terminal_injected);
    }

    #[test]
    fn chat空流与重复done恒恰1个且去重不重复计费() {
        let dup = vec![
            "event: message\ndata: {\"a\":1}\n\n".to_string(),
            "data: [DONE]\n\n".to_string(),
            "data:[DONE]\n\n".to_string(),
            chat_done_frame(),
        ];
        let norm = dedupe_terminal_frames(dup, "chat");
        assert_eq!(count_done(&norm), 1);
        assert!(norm.last().is_some_and(|f| is_done_frame(f)));
        assert!(
            norm.iter()
                .all(|f| f.lines().any(|l| l.starts_with("event:")))
        );
        assert!(has_chat_terminal(&norm));
        let empty_norm = dedupe_terminal_frames(vec![], "chat");
        assert_eq!(count_done(&empty_norm), 1);
    }

    #[test]
    fn anthropic三件套去重保留首个stop() {
        let frames = vec![
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\"}\n\n".to_string(),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
        ];
        let out = dedupe_terminal_frames(frames, "anthropic");
        assert_eq!(out.iter().filter(|f| f.contains("message_stop")).count(), 1);
        assert!(out.join("").contains("content_block_stop"));
    }

    #[test]
    fn responses完成失败形态区分且去重() {
        let frames = vec![
            "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n".to_string(),
            "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n".to_string(),
        ];
        let out = dedupe_terminal_frames(frames, "responses");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("response.completed"));
        assert!(!out[0].contains("response.failed"));
        assert!(should_discard_after_terminal(true));
        assert!(!should_discard_after_terminal(false));
    }
}
