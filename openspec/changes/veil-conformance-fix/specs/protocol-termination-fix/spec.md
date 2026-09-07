## Purpose

Restore strict wire compatibility for the three LLM streaming protocols so downstream clients never see polluted terminators, missing blocks, or miscounted usage.

## ADDED Requirements

### Requirement: Chat terminator is bare DONE exactly once

The system SHALL terminate Chat `text/event-stream` flows with exactly one bare `data: [DONE]` frame (no `event:` line) and SHALL deduplicate repeated DONE frames to one.

#### Scenario: Block injection ends with bare DONE

- **WHEN** a Chat stream is blocked by audit
- **THEN** the last frame is exactly `data: [DONE]` with no `event:` prefix and `count_done == 1`

#### Scenario: Upstream duplicate DONE collapses

- **WHEN** upstream sends two DONE frames
- **THEN** downstream receives exactly one bare DONE as the final frame

### Requirement: Anthropic block carries start and stop set

Anthropic audit-block injection SHALL emit `content_block_start` followed by `content_block_stop`, `message_delta(end_turn)`, and a single `message_stop`, preserving event ordering.

#### Scenario: Blocked tool stream is reassemblable

- **WHEN** an Anthropic tool stream is blocked
- **THEN** downstream sees one start, one stop set, and one `message_stop` with no dangling `tool_use` block

### Requirement: Responses incomplete and error close the stream

`response.incomplete` and `response.failed`/`error` events SHALL close a Responses stream with a single terminal `response.failed` frame; usage from `response.usage` single layer takes precedence over the double layer.

#### Scenario: Incomplete maps to failed

- **WHEN** upstream ends with `response.incomplete`
- **THEN** downstream receives `response.failed` once and the stream closes without hanging

### Requirement: Streaming usage accumulates monotonically

Anthropic streaming usage SHALL accumulate by monotonic max per field (`input_tokens` from `message_start`, `output_tokens` from `message_delta`) rather than naive summation, and the stream fast-path SHALL also match bare `input_tokens`/`output_tokens` keys.

#### Scenario: Start plus delta does not double count

- **WHEN** `message_start` reports input 5 and `message_delta` reports output 20 with cumulative output semantics
- **THEN** the recorded totals are input 5 and output 20, not doubled
