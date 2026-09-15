## ADDED Requirements

### Requirement: 下游内部请求头隔离

系统 SHALL 在向 LLM 上游转发请求前，从下游请求头中剔除所有 `x-veil-*` 内部头（大小写不敏感），SHALL NOT 让下游自带的 `x-veil-*` 头泄漏到上游；网关自置的内部头 SHALL 在剔除后由网关写入，SHALL NOT 与下游同名头混淆。

#### Scenario: 下游内部头不转发

- **WHEN** 下游请求含 `x-veil-debug: leak`
- **THEN** 转发到上游的请求头不含任何 `x-veil-*`

#### Scenario: 大小写不敏感剔除

- **WHEN** 下游以不同大小写形态（如 `X-Veil-Debug`）携带内部头
- **THEN** 该头同样被剔除，不泄漏到上游

## MODIFIED Requirements

### Requirement: Anthropic 阻断帧真实 index 与参数累积清洁

系统 SHALL 在 Anthropic 阻断帧合成时使用触发本次阻断的真实 content block index；仅在无法获知真实 index 时才回退 `0`。系统 SHALL 在 Anthropic 流式参数累积中排除 `content_block_start` 的空占位 `input`（如 `{}`/空串），使 `content_block_delta.partial_json` 不与其拼接；审计参数 SHALL NOT 出现 `"{}{...}"` 前缀污染。空占位检测 SHALL 同时覆盖空数组形态 `input: []`（与 `{}`/空串/null 同处理）；终端最终审计（terminal audit）合成 Anthropic 阻断帧时 SHALL 使用真实 content block index，SHALL NOT 硬编码 `0`（仅无法获知真实 index 时回退 `0`）。

#### Scenario: 阻断帧使用真实 index

- **WHEN** 上游在 `index: 2` 的 tool_use 块命中阻断
- **THEN** 下游阻断帧的 `content_block_start`/`content_block_stop` 的 `index` 为 `2`；仅当真实 index 未知时回退 `0`

#### Scenario: 空 input 不污染参数

- **WHEN** 上游发 `content_block_start`（`content_block.input={}`、`index:0`）后发 `content_block_delta`（`partial_json="{\"cmd\":\"ls\"}"`）
- **THEN** 审计累积参数为 `{"cmd":"ls"}`，无 `{}{` 前缀

#### Scenario: 空数组 input 不污染参数

- **WHEN** 上游发 `content_block_start` 且其 `content_block.input=[]`
- **THEN** 空数组不计入参数累积，审计参数无前缀污染

#### Scenario: 终端审计阻断帧使用真实 index

- **WHEN** 终端最终审计在 `index: 2` 的 content block 命中阻断
- **THEN** 合成阻断帧的 `index` 为真实值 `2`，不硬编码 `0`
