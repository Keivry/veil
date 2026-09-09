# stream-protocol-parity Specification

## Purpose
Close remaining streaming-protocol edge semantics and restore observability columns so truncation never escapes audit and dashboards regain model/cache dimensions.

## Requirements

### Requirement: Empty streams stay open-ended for chat/anthropic

Chat/Anthropic streams with zero residual bytes SHALL stay open-ended (no fabricated success termination); Responses SHALL still synthesize a failed terminal.

#### Scenario: Vacuum stream does not fabricate stop

- **WHEN** a chat stream ends with zero bytes written and no residue
- **THEN** downstream sees no synthetic `delta+stop+[DONE]` and Hermes stub protection still applies

### Requirement: Responses start events create audit slots

`response.output_item.added` carrying function_call name/id SHALL create an audit slot so truncation before `.done` is still auditable.

#### Scenario: Truncation after added is audited

- **WHEN** only `output_item.added` arrives before truncation
- **THEN** an audit record exists for the pending function call

### Requirement: Tool verdicts agree across stream modes

The same `file_search/web_search` invocation SHALL yield the same audit verdict in streaming and non-streaming modes.

#### Scenario: Same call same verdict

- **WHEN** a `file_search_call` arrives via stream vs non-stream
- **THEN** both paths reach identical audit conclusions

### Requirement: Overlong lines are marked not silently dropped

SSE lines over 16KB SHALL be truncated with a `truncated_line_dropped_bytes` counter and remain visible to audit.

#### Scenario: Long tool fragment is counted

- **WHEN** a 20KB tool fragment arrives
- **THEN** it is truncated with counter increment, never silently cleared

### Requirement: Inline BOM is stripped before parsing

`\uFEFFdata:` frames SHALL be BOM-stripped before DONE/JSON evaluation.

#### Scenario: BOM frame parses

- **WHEN** upstream sends a BOM-prefixed data frame
- **THEN** it parses exactly like the non-BOM equivalent

### Requirement: Model and cache columns restored

`record_chat` SHALL bucket by model (truncated 128, control chars removed) and usage SHALL expose `cached_read/cached_write`.

#### Scenario: Block body echoes upstream model

- **WHEN** a block body is synthesized
- **THEN** its model field echoes the upstream value, never the literal `blocked`
