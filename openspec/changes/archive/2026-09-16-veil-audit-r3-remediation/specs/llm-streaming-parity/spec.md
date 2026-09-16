## MODIFIED Requirements

### Requirement: 还原与终止

请求/响应体 SHALL 经 JSON-aware 叶级脱敏还原（含嵌套 stringified JSON 与 BOM），失败回退原串；残缺与幻觉 token SHALL 在出口剥离；Chat SHALL 以唯一裸 `data: [DONE]` 收尾，Anthropic SHALL 以五件套有序收尾（`message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`），Responses 以 `completed/failed` 收尾；空流 SHALL 按协议注入最小可解析帧，`502/401` 透传；审计阻断 SHALL 按协议形态注入且不泄漏参数明文。

#### Scenario: 终止唯一

- **WHEN** 流正常结束或被审计阻断
- **THEN** 下游恰收到一个协议正确的终止帧且可正常结束，不重试不挂起

#### Scenario: Anthropic 五件套有序收尾

- **WHEN** Anthropic 流正常结束或被审计阻断
- **THEN** 下游依序收到 `message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`，首帧为 `message_start`，不缺帧、不乱序
