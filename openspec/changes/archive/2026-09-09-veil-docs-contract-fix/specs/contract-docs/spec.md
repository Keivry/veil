## Purpose

Make documentation references verifiable and record legacy parity decisions so future changes cannot silently drift.

## ADDED Requirements

### Requirement: Doc paths are verified

Every `src/...rs` reference in README and proposals SHALL resolve to an existing file (CI script enforced).

#### Scenario: Stale path fails CI

- **WHEN** a doc references `src/service/llm_gateway.rs`<!-- doc-paths-ignore -->
- **THEN** CI fails with the missing path listed

### Requirement: Env table is complete

Every binary-read env var SHALL have a row in the README env table; unwired configs SHALL be removed or documented.

#### Scenario: Hidden config is caught

- **WHEN** `CREDENTIAL_BLOCK_WAIT` exists in code without a table row
- **THEN** either the code is removed or the row is added (no third state)

### Requirement: Legacy decisions recorded

NonDialog passthrough, debug-dir absence, Go open items, and entry-mode semantics SHALL be recorded in README §8 and locked by this spec.

#### Scenario: NonDialog stays declared

- **WHEN** NonDialog passthrough counter exists
- **THEN** README declares passthrough semantics with the counter name

#### Scenario: Debug-dir absence stays declared

- **WHEN** request dump-to-disk is absent
- **THEN** README §8 declares the absence with log-plus-audit-file alternative and new-change requirement for restoration

#### Scenario: Go open items stay tracked

- **WHEN** Go client verification items are unverified
- **THEN** README §8 lists them with `veil-hardening` section 5 as owner

#### Scenario: Entry-mode semantics stay declared

- **WHEN** entry-mode or approval semantics change
- **THEN** README §8 declares the three entry modes, approve-to-block degrade, `_ask`-None rejection, and `AUTO_APPROVE` tristate without silent drift

### Requirement: Transport declarations stay declared

`x-veil-normalized` set-conditions, usage max migration mapping, and `file_search` verdict parity SHALL stay declared in README §6-§7.

#### Scenario: Normalization header stays declared

- **WHEN** request renormalization conditions change
- **THEN** README declares the exact set-conditions with the header value

#### Scenario: Usage migration stays declared

- **WHEN** usage aggregation changes
- **THEN** README keeps the old-dashboard对照 with max-wins-migration note
