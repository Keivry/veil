# Spec Delta

## MODIFIED Requirements

### Requirement: 残余帧 JSON 转义还原

系统 SHALL 对残余帧（流末未被正常路径处理、但载荷为完整 JSON 的半帧）使用 JSON-aware 的按深度转义还原（`restore_response_with_spans_json`），与正常帧同一口径；SHALL NOT 使用逐字插入变体（`restore_response_with_spans`）。当还原明文含 `"`、`\` 或控制字符时，输出 SHALL 仍为合法 JSON。

系统 SHALL 使残余帧还原与正常帧还原**共用单一发送 helper** `emit_restored_json_frame`（handler 层，含 metrics/warn）：该 helper SHALL 恒执行 `guard_restored_frame_parsed`（还原后 JSON 可解析 + 内层 `inner_json_intact`）。守卫失败时 SHALL 按阶梯回退（`R8-03`/`R8-18`）：① 回退**已应用响应侧新 PII 掩码**的占位符帧；② 掩码回退仍失败时**丢弃该帧**（不 `feed`、不下发）。系统 SHALL NOT 落非法 JSON、SHALL NOT 直接 `feed_output_frame`、SHALL NOT 回退未掩码正文。仅守卫成功才输出还原帧。残余路径（`terminal.rs`）与正常帧路径（`event_loop.rs` 的 opaque 臂与普通臂）SHALL 均经该 helper，SHALL NOT 各自内联直通；其中 opaque 臂按 `gateway-fidelity`「Opaque 字段原字节透传」以无掩码回退保字节恒等（该字节恒等豁免仅限签名/密文载体帧；纯 `thinking_delta` 走普通帧路径，残余臂与本条其余帧 `mask_fallback:true`，不享豁免）。

`inner_json_intact` 的容器比较 SHALL 在对象键被还原改写时仍正确判定（`R8-18`）：对象分支 SHALL 要求两侧条目数相等、同名键逐键递归比较，且**仅当占位符侧键为完整 token 形态**（`__VG_CRED_<≥6 位>__` 或 `__PII_<seq>_<8 hex>__`）时，方可将该键与还原侧新增键作一一配对（配对 SHALL 为双射且与同名键集互补）；容器类型 SHALL 同类（Object↔Object、Array↔Array）。SHALL NOT 接受条目数不等、含非 token 形态新增键或容器类型漂移的结构；SHALL NOT 扩大既有 `_ => true` 兜底的适用范围。`service::redaction::restore_guard` SHALL 保持零 axum 依赖边界。

#### Scenario: 明文含引号仍为合法 JSON

- **WHEN** 残余帧为完整 JSON 且还原出的明文含双引号或反斜杠
- **THEN** 明文按 JSON 深度转义写入，残余帧解析后仍为合法 JSON

#### Scenario: 控制字符不破坏结构

- **WHEN** 还原明文含换行等控制字符
- **THEN** 按深度转义输出，JSON 结构保持完整可解析

#### Scenario: 残余帧守卫失败回退占位符帧

- **WHEN** 残余帧还原后 JSON 校验失败（外层破损或内层 stringified JSON 破损）
- **THEN** 输出回退为**已应用响应侧新 PII 掩码**的占位符帧并记录 metrics/warn；无新检出 PII 明文、无非法 JSON

#### Scenario: 掩码回退仍失败则丢帧

- **WHEN** 掩码回退本身失败（如 PII 注册不可用）
- **THEN** 该帧被丢弃、不下发，SHALL NOT 输出未掩码正文

#### Scenario: 残余与正常帧共用 helper

- **WHEN** 检查残余帧路径与正常帧路径的还原发送点
- **THEN** 两者均调用 `emit_restored_json_frame`，无内联直通 `feed_output_frame`，守卫与回退口径一致

#### Scenario: 对象键 token 还原被守卫接受

- **WHEN** 占位符侧对象键为完整 token 形态、还原后被改写为明文键，且值的结构完好、条目数相等、容器同类
- **THEN** `inner_json_intact` 判定为完整（不触发 `restore_fallback`），输出还原帧

#### Scenario: 结构破损仍被守卫拒绝

- **WHEN** 内层 stringified JSON 破损，或键位变更伴随条目数不等、新增非 token 形态键、容器类型漂移
- **THEN** 守卫拒绝并按上述阶梯回退，不因键名放宽而接受破损结构

## ADDED Requirements

### Requirement: 请求侧零替换字节保真

系统 SHALL 在请求侧脱敏「零替换」时保持转发字节原样（`R8-17`）：当请求侧脱敏未发生任何 PII/凭据替换且自定义规则快照为空时，SHALL NOT 执行 `strip_partials`（`strip_cred_partials`/`strip_pii_partials`）等残缺剥离，SHALL NOT 因客户端正文中合法的 `__VG_`/`__PII_` 片段而静默改写转发字节。发生替换时既有残缺清理语义 SHALL 保持不变。该约束 SHALL 服务于上游 prompt cache 前缀保真（与 `llm-gateway`「上游 prompt cache 前缀保真」同向）。

#### Scenario: 零替换请求字节不变

- **WHEN** 请求体无任何 PII/凭据命中且自定义规则快照为空，正文含形似前缀的普通片段
- **THEN** 转发体与客户端输入逐字节一致，SHALL NOT 删除任何字符

#### Scenario: 有替换时清理语义不变

- **WHEN** 请求发生 PII/凭据替换
- **THEN** 既有残缺清理语义不变（确证残缺仍被剥离）
