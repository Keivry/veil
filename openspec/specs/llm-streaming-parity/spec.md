# llm-streaming-parity Specification

## Purpose
使三种 LLM API 的流式增量、占位符注入、残缺处理、终止与审计语义与官方规范一致，且不破坏原结构与工具调用。

## Requirements

### Requirement: 路径与流标志

系统 SHALL 以请求尾缀判定协议（`chat/completions|v1/messages|v1/responses`，宽容一层后缀并计数），`Content-Type` 仅日志参考；`stream:true` 布尔为真才走流泵；`stream_options.include_usage` 仅对 Chat/Responses 缺失时注入。

#### Scenario: 非对话透传

- **WHEN** 请求 `v1/models`
- **THEN** 系统透传不计统计、不注入占位符与 usage 选项

### Requirement: 占位符注入形态

Chat SHALL 向 `messages` 首条 system 追加/前插；Anthropic SHALL 向 `system` 字段追加；Responses 数组 `input` SHALL 向首条前插；Responses 字符串 `input` 与 Anthropic 非法 `system` 形态 SHALL 按显式策略处理（不注入且 warn）；注入后 SHALL 做 schema 校验，失败回退不注入。

#### Scenario: 数组与字符串分流

- **WHEN** Responses `input` 为字符串
- **THEN** 系统不注入、打 warn 且转发原体

### Requirement: 流式工具累积与审计

Chat SHALL 按 `tool_calls[].index` 拼接 `arguments` 片段；Anthropic SHALL 按块 `index` 字段分桶累积 `partial_json` 并在 `content_block_stop` 处一次性解析；Responses SHALL 按 `item_id/output_index+sequence_number` 保序拼接 `function_call_arguments.delta` 并以 `done` 全量校验后执行审计；缺 id SHALL 合成 `call_stable_<index>` 不断链；`thinking/signature/citations/refusal/reasoning/mcp/file_search/web_search` 等次要事件 SHALL 按策略透传且审计口径显式（审计或声明放行）。

#### Scenario: 跨包拼接

- **WHEN** 某工具参数分三个增量到达
- **THEN** 系统拼接完整 JSON 后才审计执行，不对片段误报

#### Scenario: 增量期不放行危险调用

- **WHEN** Responses 危险参数尚未收齐 `done`
- **THEN** 系统暂缓放行，收齐并审计通过后才转发

### Requirement: 还原与终止

请求/响应体 SHALL 经 JSON-aware 叶级脱敏还原（含嵌套 stringified JSON 与 BOM），失败回退原串；残缺与幻觉 token SHALL 在出口剥离；Chat SHALL 以唯一裸 `data: [DONE]` 收尾，Anthropic 以 `message_stop` 三件套有序收尾，Responses 以 `completed/failed` 收尾；空流 SHALL 按协议注入最小可解析帧，`502/401` 透传；审计阻断 SHALL 按协议形态注入且不泄漏参数明文。

#### Scenario: 终止唯一

- **WHEN** 流正常结束或被审计阻断
- **THEN** 下游恰收到一个协议正确的终止帧且可正常结束，不重试不挂起
