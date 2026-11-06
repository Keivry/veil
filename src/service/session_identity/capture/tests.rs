//! 响应标识捕获测试（sibling，`session_identity/capture.rs`）。

use {super::*, crate::service::llm_gateway::Protocol, serde_json::json};

#[test]
fn nonstream_body_captures_top_level_id_and_conversation_object() {
    let body = json!({"id": "resp_1", "conversation": {"id": "conv_1"}});
    assert_eq!(
        capture_response_ids(&body, 200, Protocol::Responses, ResponseShape::Complete),
        CapturedIds {
            response_id: Some("resp_1".to_string()),
            conversation_id: Some("conv_1".to_string()),
        }
    );
}

#[test]
fn nonstream_body_captures_conversation_string() {
    let body = json!({"id": "resp_1", "conversation": "conv_1"});
    assert_eq!(
        capture_response_ids(&body, 200, Protocol::Responses, ResponseShape::Complete),
        CapturedIds {
            response_id: Some("resp_1".to_string()),
            conversation_id: Some("conv_1".to_string()),
        }
    );
}

#[test]
fn empty_or_missing_fields_yield_exact_none() {
    let cases = [
        (json!({}), None, None),
        (json!({"id": ""}), None, None),
        (json!({"id": "resp_1"}), Some("resp_1"), None),
        (
            json!({"id": "resp_1", "conversation": {}}),
            Some("resp_1"),
            None,
        ),
        (
            json!({"id": "resp_1", "conversation": ""}),
            Some("resp_1"),
            None,
        ),
        (
            json!({"conversation": {"id": "conv_1"}}),
            None,
            Some("conv_1"),
        ),
    ];
    for (body, response_id, conversation_id) in cases {
        let captured =
            capture_response_ids(&body, 200, Protocol::Responses, ResponseShape::Complete);
        assert_eq!(captured.response_id.as_deref(), response_id, "{body}");
        assert_eq!(
            captured.conversation_id.as_deref(),
            conversation_id,
            "{body}"
        );
    }
}

#[test]
fn streaming_event_reads_nested_response_object() {
    // `response.created` 首帧：完整 response 对象在 `response` 下。
    let event = json!({
        "type": "response.created",
        "response": {
            "id": "resp_1",
            "conversation": {"id": "conv_1"},
        },
    });
    assert_eq!(
        capture_response_ids(&event, 200, Protocol::Responses, ResponseShape::StreamEvent),
        CapturedIds {
            response_id: Some("resp_1".to_string()),
            conversation_id: Some("conv_1".to_string()),
        }
    );
}

#[test]
fn stream_event_without_response_object_never_reads_top_level_id() {
    // 流式事件缺失 `response` 对象时，事件自身的顶层 `id`/`conversation` 不是
    // `response.id`/`response.conversation`，MUST NOT 被捕获。
    for event in [
        json!({"type": "response.output_item.added", "id": "item_1"}),
        json!({"type": "error", "id": "err_1"}),
        json!({"id": "resp_1", "conversation": "conv_1"}),
    ] {
        assert!(
            capture_response_ids(&event, 200, Protocol::Responses, ResponseShape::StreamEvent)
                .is_empty(),
            "{event} 不得按非流形态捕获"
        );
    }
}

#[test]
fn error_status_returns_empty_even_with_ids() {
    for status in [400u16, 404, 429, 500, 503] {
        for body in [
            json!({"error": {"id": "err_1"}}),
            json!({"id": "resp_1", "conversation": {"id": "conv_1"}}),
            json!({"message": {"id": "m_1"}, "data": {"id": "d_1"}}),
        ] {
            let captured =
                capture_response_ids(&body, status, Protocol::Responses, ResponseShape::Complete);
            assert!(captured.is_empty(), "{status} {body} 须不返回任何 id");
        }
    }
}

#[test]
fn non_responses_protocol_returns_empty() {
    let body = json!({"id": "resp_1", "conversation": {"id": "conv_1"}});
    for protocol in [Protocol::Chat, Protocol::Anthropic, Protocol::NonDialog] {
        assert!(
            capture_response_ids(&body, 200, protocol, ResponseShape::Complete).is_empty(),
            "{protocol:?} MUST NOT 捕获"
        );
    }
}

#[test]
fn never_falls_back_to_error_or_message_or_data_id() {
    for body in [
        json!({"error": {"id": "err_1"}, "conversation": {"id": "conv_1"}}),
        json!({"message": {"id": "m_1"}}),
        json!({"data": {"id": "d_1"}}),
    ] {
        let captured =
            capture_response_ids(&body, 200, Protocol::Responses, ResponseShape::Complete);
        assert!(
            captured.response_id.is_none(),
            "{body} 的 response.id 不得回退"
        );
    }
}

#[test]
fn stream_flag_with_json_body_parses_nonstream_shape() {
    // `stream: true` 但上游返回 2xx JSON（透传路径）——按非流形态解析。
    let body = json!({"stream": true, "id": "resp_1", "conversation": "conv_1"});
    assert_eq!(
        capture_response_ids(&body, 200, Protocol::Responses, ResponseShape::Complete),
        CapturedIds {
            response_id: Some("resp_1".to_string()),
            conversation_id: Some("conv_1".to_string()),
        }
    );
}

#[test]
fn debug_redacts_captured_ids() {
    let captured = capture_response_ids(
        &json!({"id": "resp_secret", "conversation": {"id": "conv_secret"}}),
        200,
        Protocol::Responses,
        ResponseShape::Complete,
    );
    let debug = format!("{captured:?}");
    assert!(!debug.contains("resp_secret"), "{debug}");
    assert!(!debug.contains("conv_secret"), "{debug}");
    assert!(debug.contains("[redacted]"));
}
