# test-coverage-closure Specification

## Purpose
以断言级用例锁定本次修复的全部行为，防止回归：补齐 P0 的 IPv6/审计审批流/查询语义/truncation/扫描性能用例，以及 P1 的误报守卫、流语义与并发弱覆盖，使 approvals、IPv6、series、truncation、perf 各域闭环。

## Requirements

### Requirement: P0 补测必过

系统 SHALL 新增并通过：`pii_ipv6_time` 16 项（时间戳 vs IPv6）、`audit_approve_stream` 13 项流级（批准/拒绝/过期注入、`anthropic_precheck`、溢出 fail-closed 流验证、`abort_mid_toolcall`、超时与断连竞态、早断清理）、`series/model/upstream/pii_value` 查询语义、`truncation` TSS01-04 与真实数据、扫描性能锚点（5000 名单与增量扫描耗时）。

#### Scenario: 回归被锁

- **WHEN** 运行新增 P0 用例
- **THEN** 全部通过且覆盖 approvals/IPv6/series/truncation/perf 五域

### Requirement: P1 弱覆盖补齐

系统 SHALL 新增并通过：四误报守卫（订单号/URL 参数/base64/连续数字）、句末标点与 `+86`/`sk-proj`/62-13 位卡、flush 去抖、N2 不广播与还原保真与多行透传与断开重试 e2e、refusal 与三分片单 flush 与 flush 失败不双还原、并发单 ask 与 unlock 超时与审批文案三段、`room_send` 异常仍回 id、malformed 审计与容量分表。

#### Scenario: 弱覆盖清零

- **WHEN** 运行新增 P1 用例
- **THEN** 误报、流语义、并发三类弱覆盖闭环
