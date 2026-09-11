# llm-critical-compliance Specification

## Purpose
锁定 6 项 LLM 关键合规修复的可验证行为：混帧工具优先、终止精确判定、conv 优先流内、false 语义声明、双字段独立回退、阻断状态码对称。

## Requirements

### Requirement: E7 thinking 混帧工具优先进审

系统 SHALL 对同时含 thinking 增量与工具 `partial_json` 增量的帧优先提取工具片段，非空时 SHALL 走 tool 通道进 hold 审计，仅剩余 thinking 部分 SHALL 走 minor 透传。

#### Scenario: 混帧工具增量不漏审

- **WHEN** Anthropic `content_block_delta` 同时含 `thinking_delta` 与 `partial_json`
- **THEN** 工具片段进 hold 审计，thinking 部分透传不审计

#### Scenario: 纯 thinking 仍为次要事件

- **WHEN** 帧只含 `thinking_delta` 无工具片段
- **THEN** 整帧标 minor 透传且不进 hold

### Requirement: E8 Responses 终止按 type 精确判定

系统 SHALL 对 Responses 终止判定经 `serde_json` 解析后按 `type` 字段精确匹配（`response.completed/response.failed/response.incomplete/error`），SHALL 不再依赖 `contains` 字符串匹配。

#### Scenario: 空格变体不漏判

- **WHEN** 错误帧为 `{"type": "error"}`（冒号后带空格）
- **THEN** 判定为终结并合成截断帧

#### Scenario: 正文含关键词不误判

- **WHEN** 文本内容含 `response.completed` 字符串但 `type` 非终结类型
- **THEN** 不触发终结，流继续转发

### Requirement: E9 incomplete 合成优先流内 conv_id

系统 SHALL 在合成 `incomplete/error` 截断帧时优先采用流内首见 `id`，仅缺失时 SHALL 回退 `resolve_conv_id` 归档值。

#### Scenario: 流内 id 优先

- **WHEN** 流内已见 `response.created` 带 `id=resp_123` 后出现 `incomplete`
- **THEN** 合成截断帧用 `resp_123`，下游可关联

#### Scenario: 缺失才归档

- **WHEN** 流内从未出现可用 `id`
- **THEN** 回退归档值并记 `conv_missing` 计数

### Requirement: E1 显式 false 用量语义文档化

系统 SHALL 在 `README §7.2` 声明“`stream_options.include_usage` 显式 false 即用户放弃流式用量”，且 SHALL 说明 metrics 空 usage 桶为预期告警而非异常。

#### Scenario: false 保留可预期

- **WHEN** 请求自带 `stream_options={"include_usage":false}`
- **THEN** 转发体保留 false，文档解释无流式 usage 帧

#### Scenario: 空 usage 桶不误报

- **WHEN** metrics 观测到某模型空 usage 桶
- **THEN** 按文档先查请求是否显式 false，再判异常

### Requirement: E2 Responses 双字段独立注入独立回退

系统 SHALL 对 Responses `input` 与 `instructions` 按字段独立注入占位说明，各字段独立校验独立回退，一字段非法 SHALL 不丢弃另一合法字段的改动。

#### Scenario: 部分非法不连坐

- **WHEN** `input` 为合法 string 且 `instructions` 为非法 number
- **THEN** `input` 注入保留，`instructions` 保持原值

#### Scenario: 双非法整体回退

- **WHEN** `input` 与 `instructions` 均非法
- **THEN** 整体回退不注入，返回原体

### Requirement: E4 非流与流式阻断状态码对称

系统 SHALL 使非流阻断与流式阻断状态码对称：统一恒 200，或文档声明差异为有意，二选一 SHALL 由单测锁定。

#### Scenario: 对称恒 200

- **WHEN** 非流命中阻断且上游状态为 502
- **THEN** 若选统一方案，下游收 200 加阻断体

#### Scenario: 差异声明锁定

- **WHEN** 选择文档声明方案
- **THEN** 文档写明非流保留上游码而流式恒 200 的原因，单测断言该差异
