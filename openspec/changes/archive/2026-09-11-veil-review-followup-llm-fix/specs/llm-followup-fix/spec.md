## Purpose

锁定 4 项 LLM 后续修复的可验证行为：Responses 用量顶层优先、多 choice 桶隔离、占位字面不误触发、用量快路径零分配。

## ADDED Requirements

### Requirement: F-P1a Responses 用量顶层优先三级回退

系统 SHALL 对 Responses 用量按顶层 `usage` 优先、其次 `response.usage`、最后 `response.response.usage` 取数，缓存列 SHALL 同口径。

#### Scenario: 标准顶层体命中

- **WHEN** 非流体为 `{"output":[...],"usage":{"input_tokens":12,"output_tokens":45}}`
- **THEN** 提取 prompt 12 / completion 45，缓存列按 `input_tokens_details.cached_tokens`

#### Scenario: 定制双层体回退不断链

- **WHEN** 体仅含 `response.usage` 或 `response.response.usage`
- **THEN** 回退命中且不断链

### Requirement: F-P1b 多 choice 桶隔离

系统 SHALL 对 Chat tool 桶键混入 choice 序号，跨 choice 同 `index` SHALL 落不同槽。

#### Scenario: n=2 同 index 不串扰

- **WHEN** `choices[0].delta.tool_calls[0].index=0` 与 `choices[1].delta.tool_calls[0].index=0` 先后到达
- **THEN** 分属不同桶，参数拼接互不串扰

#### Scenario: legacy 与新形态一致

- **WHEN** `function_call` 与 `tool_calls` 混用
- **THEN** 桶键口径一致，审计快照可复现

### Requirement: F-P2a 占位精确形态与幂等

系统 SHALL 仅将全形态 `__PII_<seq>_<hex8>__` 与 `__VG_CRED_<digits>__` 判为 token，`__PII_*__` 字面 SHALL 不触发；已含说明 SHALL 不再重复前插。

#### Scenario: 字面不注入

- **WHEN** 体仅含 `__PII_*__` 说明字面无真实 token
- **THEN** 不注入说明，字节等价透传

#### Scenario: 重复请求不膨胀

- **WHEN** 体首条 system 已含说明指纹
- **THEN** 不再前插第二条说明

### Requirement: F-P2b 用量快路径零分配

系统 SHALL 对无用量心跳分片零分配跳过，有用量分片 SHALL 走全量归一且结论不变。

#### Scenario: 心跳跳过

- **WHEN** 分片无 `usage`/token 键
- **THEN** 返回 None 且无堆分配（单测以行为等价断言，不做 bench 门禁）

#### Scenario: 有用量仍命中

- **WHEN** 分片含 `usage`
- **THEN** 提取结论与改前一致
