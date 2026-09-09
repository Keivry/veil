## Purpose

Remove cyclic dependencies, split oversized files, eliminate dead code and duplicated implementations while keeping all public paths compatible.

## ADDED Requirements

### Requirement: Dependencies are acyclic

`state` SHALL NOT depend on `service` business logic; `service` SHALL access state via trait injection.

#### Scenario: No cycle compiles

- **WHEN** running `cargo build`
- **THEN** no `state -> service -> state` dependency edge exists

### Requirement: Files stay splittable

No business file SHALL exceed 800 lines; splits SHALL re-export legacy paths.

#### Scenario: Legacy path still compiles

- **WHEN** downstream uses `crate::service::X` legacy path
- **THEN** it compiles via `mod.rs` re-export

### Requirement: No dead code or duplication

Unwired configs, test-only pub functions, duplicate BOM/constants, and dual desensitization paths SHALL be removed or unified.

#### Scenario: Single BOM source

- **WHEN** grepping `strip_sse_bom`
- **THEN** zero definitions remain; all callers use `json_walk::strip_bom`

#### Scenario: Single scan limit

- **WHEN** grepping `pub const SCAN_INPUT_LIMIT`
- **THEN** exactly one definition exists in `json_walk.rs`
