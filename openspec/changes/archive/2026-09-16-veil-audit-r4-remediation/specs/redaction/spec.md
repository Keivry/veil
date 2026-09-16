## MODIFIED Requirements

### Requirement: 残余帧 JSON 转义还原

系统 SHALL 对残余帧（流末未被正常路径处理、但载荷为完整 JSON 的半帧）使用 JSON-aware 的按深度转义还原（`restore_response_with_spans_json`），与正常帧同一口径；SHALL NOT 使用逐字插入变体（`restore_response_with_spans`）。当还原明文含 `"`、`\` 或控制字符时，输出 SHALL 仍为合法 JSON。

系统 SHALL 使残余帧还原与正常帧还原**共用单一发送 helper** `emit_restored_json_frame`（handler 层，含 metrics/warn）：该 helper SHALL 恒执行 `guard_restored_frame_parsed`（还原后 JSON 可解析 + 内层 `inner_json_intact`），守卫**失败时 SHALL 回退占位符帧**（SHALL NOT 落非法 JSON、SHALL NOT 直接 `feed_output_frame`）；仅守卫成功才输出还原帧。残余路径（`terminal.rs`）与正常帧路径（`event_loop.rs` 的 opaque 臂与普通臂）SHALL 均经该 helper，SHALL NOT 各自内联直通。`service::redaction::restore_guard` SHALL 保持零 axum 依赖边界。

#### Scenario: 明文含引号仍为合法 JSON

- **WHEN** 残余帧为完整 JSON 且还原出的明文含双引号或反斜杠
- **THEN** 明文按 JSON 深度转义写入，残余帧解析后仍为合法 JSON

#### Scenario: 控制字符不破坏结构

- **WHEN** 还原明文含换行等控制字符
- **THEN** 按深度转义输出，JSON 结构保持完整可解析

#### Scenario: 残余帧守卫失败回退占位符帧

- **WHEN** 残余帧还原后 JSON 校验失败（外层破损或内层 stringified JSON 破损）
- **THEN** 输出回退为占位符帧并记录 metrics/warn，不输出非法 JSON，与正常帧守卫失败语义一致

#### Scenario: 残余与正常帧共用 helper

- **WHEN** 检查残余帧路径与正常帧路径的还原发送点
- **THEN** 两者均调用 `emit_restored_json_frame`，无内联直通 `feed_output_frame`，守卫与回退口径一致
