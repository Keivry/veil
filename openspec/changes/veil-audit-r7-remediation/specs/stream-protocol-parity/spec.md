# Spec Delta

## MODIFIED Requirements

### Requirement: Model and cache columns restored

`record_chat` SHALL bucket by model (truncated 128, control chars removed) and usage SHALL expose `cached_read/cached_write`. 流式模型提取 SHALL 按顶层 `model` → Anthropic 嵌套 `message.model` → Responses 嵌套 `response.model` 三级回退（与 `response.id` 会话标识回退对称），使 Responses `response.completed` 携带的 `response.model` 被读取用于分桶；SHALL NOT 仅查顶层 `model` 与 `message.model` 而令 Responses 流式恒回退请求模型、与非流上游回显口径分裂。

Anthropic 缓存列 SHALL 精确取自顶层 `cache_read_input_tokens` 与 `cache_creation_input_tokens`（实现指针 `src/service/llm_gateway/usage.rs::cached_columns`）；README §7.2 SHALL 使用该精确字段名登记，SHALL NOT 使用 `cache_read/cache_creation_input_tokens` 之截断简写（`R7-09`）。Responses 取 `input_tokens_details.cached_tokens`、Chat 取 `prompt_tokens_details.cached_tokens` 的既有口径不变。

#### Scenario: Block body echoes upstream model

- **WHEN** a block body is synthesized
- **THEN** its model field echoes the upstream value, never the literal `blocked`

#### Scenario: Responses 流式读取嵌套 response.model

- **WHEN** Responses 流式事件（如 `response.completed`）的模型名位于嵌套 `response.model` 而顶层无 `model`
- **THEN** 流式模型提取返回该值用于分桶，与非流路径的上游回显口径一致，不再回退请求模型

#### Scenario: README §7.2 缓存字段名与实现精确一致

- **WHEN** 核查 README §7.2 的 Anthropic 缓存列字段名与 `src/service/llm_gateway/usage.rs::cached_columns`
- **THEN** 文档为 `cache_read_input_tokens`/`cache_creation_input_tokens` 全名，零命中 `cache_read/cache_creation_input_tokens` 简写
