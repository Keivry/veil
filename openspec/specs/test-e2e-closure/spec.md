# test-e2e-closure Specification

## Purpose
堵住 E2E 真空与弱断言放水，新增 `truncation`、`audit_approve`、`sse_loop` 三个 HTTP E2E，并补齐空流 hold 矩阵、并发隔离、观测 DB 持久、ReDoS、性能锚点与帧级断言，使回归测试能捕获流式、审计、截断与性能退化。

## Requirements

### Requirement: 三个 HTTP E2E

系统 SHALL 新增 `tests/http_e2e_truncation.rs`（mock 上游中途断流，断言已透传保留、无伪造 stop/[DONE]、无合成）、`tests/http_e2e_audit_approve.rs`（批准放行/拒绝-过期注入 `BLOCK_MESSAGE` 且无 tool_calls）、`tests/http_e2e_sse_loop.rs`（跨行数组/字符串/`[DONE]`/快慢 WHATWG 对齐 + CR-only/空行 drop/多 data）。

#### Scenario: 截断开环不断链

- **WHEN** 上游中途断流
- **THEN** 下游 200，已透传分片保留，无伪造终止

### Requirement: 边缘矩阵与弱断言收紧

空流 hold 四分支矩阵、并发 Scope/audit_hold 隔离、并发解锁单 ask、观测 DB 持久（按日 UPSERT/7 天滚动/0600 含 wal-shm/persist=0 不建表/401 不泄漏）SHALL 补齐；ReDoS（真超时记账 + `<200ms`）、性能锚点（5000 字典/1MB/增量秒级）、`is_precise` 双条件、p95 三态、帧级 `event:` 序列断言、`[DONE]` 精确单帧计数 + 子串负例、嵌套 `p@ss"quote/\u/BOM` 强断言、采样全矩阵 SHALL 收紧。

#### Scenario: 性能退化被捕获

- **WHEN** 5000 字典扫描超过 500ms
- **THEN** 测试失败告警
