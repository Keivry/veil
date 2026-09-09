## Purpose

Close high/medium-risk test gaps so regressions in rewrite, non-stream, placeholder, streaming core, audit, credential, vault, perf, observability, IPv6, and concurrency are all caught.

## ADDED Requirements

### Requirement: Zero-coverage files reach parity

`rewrite.rs` and `nonstream.rs` SHALL have unit tests covering empty-body-to-502, post-strip emptiness, and normal-text passthrough.

#### Scenario: Empty body maps to 502

- **WHEN** upstream returns an empty body
- **THEN** a unit test asserts the 502 mapping (no manual verification needed)

### Requirement: Placeholder injection matrix restored

The placeholder suite SHALL cover multi-system strings/arrays, image blocks, truncated JSON passthrough, and all three protocols.

#### Scenario: Image block is untouched

- **WHEN** a request contains image blocks
- **THEN** a test asserts injection skips them without corruption

### Requirement: Streaming holds locked

Dual-hold, token affix holds, and fast/slow path splits SHALL have regression tests.

#### Scenario: Dual hold equivalence

- **WHEN** PII hold and audit hold coincide
- **THEN** a test asserts single-frame equivalence with sequential holds

### Requirement: Audit edge cases locked

Null bodies, missing indexes, dotdot normalization, and pipe priority SHALL be tested.

#### Scenario: Null tool call is skipped

- **WHEN** a null tool fragment arrives
- **THEN** a test asserts it is skipped without audit entry

### Requirement: Credential E2E exists

Three-factor auth, health, rate limit, and raw terminal rejection SHALL have E2E coverage.

#### Scenario: Raw terminal call rejected

- **WHEN** `caller_hash == GET_BINARY_HASH`
- **THEN** E2E asserts 403

### Requirement: Vault scale locked

Hole-skipping, CSPRNG uniqueness, and 100-way concurrent registration SHALL be tested.

#### Scenario: 100 concurrent registers conflict-free

- **WHEN** 100 tasks register concurrently
- **THEN** no index conflict occurs

### Requirement: Perf budgets enforced

1MB<500ms, 100KB<100ms, 1KB<2ms budgets SHALL gate CI.

#### Scenario: 1MB audit under budget

- **WHEN** a 1MB body is audited in CI
- **THEN** it completes under 500ms or CI fails

### Requirement: Observability and network parity

Model/upstream linkage, series buckets, and IPv6 edge cases SHALL be tested item by item.

#### Scenario: Series buckets exact

- **WHEN** querying 1h/24h/7d/30d series
- **THEN** bucket counts match spec exactly with zero-filled empty buckets
