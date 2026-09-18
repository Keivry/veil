# Spec Delta

## MODIFIED Requirements

### Requirement: Responses 审计字节去重

系统 SHALL 按槽/调用维度对 Responses 审计持有字节去重，同一调用的 `.done` 参数 SHALL NOT 在 `total_bytes` 中重复计入；长流多工具 SHALL NOT 因重复计数提前触发溢出 fail-closed，真实超限 SHALL 仍拒绝并清仓。去重 SHALL 覆盖官方双投递形态（`R8-01`）：`response.function_call_arguments.done` 与 `response.output_item.done` 先后携带**同一完整参数**时，第二次 `.done` SHALL NOT 再次累加字节（记旧值 SHALL 取该槽 `held_bytes()`（分片与已存 `done_args` 之和），或对相同 `done_args` 幂等早退）；槽释放 SHALL 按同源口径恰好归还一次，使任意时刻「`total_bytes` == `args_by_index` 各值长度之和 + `responses_slots` 各 `held_bytes()` 之和」的守恒不变量成立（`pending_bytes` 为独立维度、不计入）。

#### Scenario: 双计场景 total_bytes 正确

- **WHEN** 同一 Responses 调用的分片与 `.done` 参数先后到达（`seq` 缺失场景）
- **THEN** `total_bytes` 只计该调用参数一次，不超过实际上限

#### Scenario: 重复 .done 不二次累加

- **WHEN** 官方流对同一调用先后投递 `response.function_call_arguments.done` 与 `response.output_item.done`（同一完整参数）
- **THEN** `total_bytes` 不重复累加，槽释放后字节归还恰一次，无残留

#### Scenario: 字节守恒

- **WHEN** 多工具长流中任意时刻检查 `total_bytes` 与「`args_by_index` 值长度之和 + `responses_slots` `held_bytes()` 之和」
- **THEN** 两者相等（饱和口径下不出现只增不归的泄漏）

#### Scenario: 真实超限仍 fail-closed

- **WHEN** 去重后单调用活跃分片累计仍超过 `AUDIT_HOLD_MAX_BYTES`
- **THEN** 审计拒绝并清仓，不透出参数

## ADDED Requirements

### Requirement: 工具分桶单射与越界 index 归属

系统 SHALL 保证审计工具分桶对「同一事件内多外层块」与「越界索引」均为单射（`R8-05`/`R8-15`）：Anthropic `custom_tool_call`（及同型数组承载）的数组项 SHALL 以「块键 + 块内位置」复合桶键 `anthropic_item_bucket(block_bucket, item_index)` 编码（`block_bucket` 为既有 `anthropic_bucket_index(outer_index, block, fallback)` 已算出的块身份编码；`item_index == 0` 且块键在合法域（`< ANTHROPIC_BLOCK_MAX`）时退化为纯块键、与对象分支等价；合法域位域单射、越界（含块键 `>= ANTHROPIC_BLOCK_MAX`）经有界哈希溢出桶），SHALL NOT 使用裸数组下标致不同块或同块多项串扰。协议声明的 `index`/`output_index` 取值超出既有桶位域时，系统 SHALL 将其路由至保留带溢出桶或视为缺失（`None`），SHALL NOT 以 `u64 as u32` 静默截断后操作错误槽。

#### Scenario: Anthropic 数组项跨块不串扰

- **WHEN** 同一 Anthropic 事件的多个 `content_block` 各携带 `custom_tool_call` 数组项（`outer_index` 缺失，非流消息解析常态）
- **THEN** 各 (块键, 块内位置) 归入互异槽，审计参数不合并、不串扰

#### Scenario: 越界 index 不静默截断

- **WHEN** 上游 `index`/`output_index` ≥ 2^32
- **THEN** 系统不以截断值操作槽（路由至溢出桶或按缺失处理），不误清/误审其他槽

#### Scenario: 常规分桶不回归

- **WHEN** 既有 Chat/Anthropic/Responses 常规流（index 在带内）
- **THEN** 分桶键与既有行为等值，审计结果不回归
