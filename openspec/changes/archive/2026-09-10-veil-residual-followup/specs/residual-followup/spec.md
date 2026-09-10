# residual-followup Specification

## Purpose

锁定 Oracle 终审三项低危遗留的收敛行为：性能用例并行确定性、缺省回退告警去重。

## ADDED Requirements

### Requirement: Perf budget case deterministic under parallel load

`t8_100kb_scan_under_800ms` SHALL assert on the minimum of 3 wall-clock measurements so the case is deterministic under parallel test load while keeping the 800ms upper bound and hit-count assertion unchanged.

#### Scenario: Parallel load does not flake

- **WHEN** the full `cargo test` suite runs with default parallelism
- **THEN** the case passes with the minimum measurement below 800ms

#### Scenario: Real regression still caught

- **WHEN** scan time regresses far beyond the bound
- **THEN** all three measurements exceed 800ms and the case fails

### Requirement: Default fallback warns once per process

`resolve_upstream` default fallback SHALL emit at most one warning per process while keeping deterministic lowest-port selection.

#### Scenario: Repeated resolutions warn once

- **WHEN** multiple requests resolve upstream without a default configured
- **THEN** only the first resolution emits the warning and all resolutions return the same lowest-port upstream
