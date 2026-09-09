## Purpose

Ensure every non-streaming response path has defined usage/audit/restore semantics, tool-call bucketing is single-sourced, truncated fragments never reach downstream, and pump misconfiguration can never cause undefined behavior.

## ADDED Requirements

### Requirement: Error statuses traverse post-processing

Non-streaming 502/401 responses SHALL traverse usage recording, audit evaluation, and credential/PII restore (falling back to upstream bytes on restore failure) instead of returning raw bytes.

#### Scenario: 502 error body is scrubbed

- **WHEN** upstream returns 502 with a body containing a credential token
- **THEN** downstream receives the body with the token stripped, usage recorded, and audit evaluated

### Requirement: Single index priority for tool bucketing

Stream and non-stream tool-call accumulation SHALL use outer-index priority from a single shared bucketing function.

#### Scenario: Interleaved indexes land in the same slot

- **WHEN** fragments carry outer 0/1 with inner 3/5
- **THEN** stream and non-stream bucket identically and `clear_index` clears the correct slot

### Requirement: Truncated tool fragments are dropped

Tool-call fragments that never reach `done` SHALL be dropped on truncation and never forwarded downstream (TSS-03).

#### Scenario: Mid-call truncation drops pending call

- **WHEN** a chat stream truncates mid tool-call arguments
- **THEN** downstream receives no partial tool call and a `truncated_tool_dropped` counter increments

### Requirement: Pump entry clamps limits

`hold_max == 0` SHALL fall back to 1MB with warn; values above `AUDIT_SUBLIMIT_CEILING` SHALL be clamped with warn. `pii_boundary_chars == 0` is a disable-signal for response-side passthrough (retained without clamping, per `StreamPumpCtx` caller contract) and SHALL NOT fall back to 64.

#### Scenario: Zero hold_max is clamped

- **WHEN** `hold_max` is 0
- **THEN** the pump uses 1MB, logs a warning, and never exhibits undefined behavior

#### Scenario: Zero pii_boundary_chars disables response-side hold

- **WHEN** `pii_boundary_chars` is 0
- **THEN** response-side boundary hold is disabled (passthrough) with no fallback and no warning

### Requirement: Non-stream restore falls back on broken JSON

Restored non-stream bodies that fail JSON re-parse SHALL fall back to upstream bytes with a warning.

#### Scenario: Corrupted restore falls back

- **WHEN** post-restore bytes fail `_jloads`
- **THEN** downstream receives the original upstream bytes and a warning is logged

### Requirement: Non-stream approval aligns with streaming B-case

Non-stream `NeedApproval` SHALL record pending and pass through upstream (only `deny` blocks), consistent with streaming README 6.4.

#### Scenario: Approve does not block non-stream

- **WHEN** audit returns `NeedApproval` for a non-stream call
- **THEN** downstream receives the upstream response and a pending record exists
