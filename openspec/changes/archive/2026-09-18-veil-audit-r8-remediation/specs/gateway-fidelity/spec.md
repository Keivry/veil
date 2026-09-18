# Spec Delta

## MODIFIED Requirements

### Requirement: 流式还原 JSON 破帧防护

系统 SHALL 保证响应流式路径（`Scope::restore_response_with_spans` → `Scope::redact_response_new_pii_with_skip` → `json_aware_line`）在还原帧「还原前可解析」的前提下，「还原后仍可解析」。系统 SHALL 在向 JSON 字符串上下文写入还原明文时按 RFC 8259 字符串转义规则处理（`"` → `\"`、`\` → `\\`、控制字符转义）。当转义后仍无法通过 JSON 校验时，系统 SHALL 按阶梯回退（`R8-03`）：① 主产物为 `mask(restore(frame))`；② 守卫失败时回退**已应用响应侧新 PII 掩码**的占位符帧（`mask(placeholder)`——掩码为 ASCII 替换、不破 JSON）；③ 上述仍失败时 SHALL 丢弃该帧（不 `feed`、不下发），SHALL NOT 下发破损帧或未掩码正文。系统 SHALL NOT 将未转义明文写回、SHALL NOT 使下游收到 `JSONDecodeError` 破损帧、SHALL NOT 回退未掩码的上游原文或未掩码占位符帧。守卫失败 SHALL 记 warn 与 `record_restore_fallback` 指标（恰一次）。上述「SHALL NOT 回退未掩码正文」SHALL NOT 适用于「Opaque 字段原字节透传」所界定的 opaque 签名/密文载体帧：此类帧本就跳过响应侧新 PII 掩码，其守卫失败 SHALL 按字节恒等回退至上游原始帧，并记 warn 与 `record_restore_fallback` 恰一次；该豁免为唯一例外，仅限签名/密文载体，纯 `thinking_delta` 不适用。非流路径既有 `retry_stripped` 回退语义 SHALL 作为流式实现的对齐参照（其回退目标见 `llm-edge-gateway`「非流还原回退前残缺重试」）。

#### Scenario: 明文含双引号流式还原不破帧

- **WHEN** 已注册凭据明文含 `"`，上游响应 JSON 帧（如 `{"text":"... __VG_CRED_000001__ ..."}`）经流式还原写回
- **THEN** 下游收到的帧为合法 JSON，且解析后字符串值逐字符等于原始明文

#### Scenario: 明文含反斜杠与换行控制字符

- **WHEN** 已注册凭据明文含 `\` 或换行等控制字符，流式帧还原写回
- **THEN** 帧内对应位置为 JSON 转义形态（`\\`/`\n`），下游可解析且语义等价；不得出现裸控制字符

#### Scenario: 还原后仍破损则回退占位符帧

- **WHEN** 流式帧还原后 `jloads` 校验失败（病态输入），无法转义挽回
- **THEN** 下游收到**已应用响应侧新 PII 掩码**的占位符帧（token 形态保留、不破帧、无新检出 PII 明文），warn 日志与 `restore_fallback` 计数各 +1

#### Scenario: 掩码回退仍失败则丢帧

- **WHEN** 掩码回退本身失败（如 PII 注册熵源故障）
- **THEN** 该帧被丢弃、不下发，下游 SHALL NOT 收到未掩码正文或破损帧

#### Scenario: 非 JSON 帧不受影响

- **WHEN** 流式帧本身非 JSON（plain 文本残留）
- **THEN** 走既有 plain 路径，字节级还原不做 JSON 转义，行为与修复前一致

### Requirement: Opaque 字段原字节透传

系统 SHALL 对 Anthropic 签名/密文载体帧——`signature_delta`、`redacted_thinking`、携 `signature`/`redacted_data` 的 `thinking` 与 `content_block_start`——跳过响应侧新 PII 扫描（`redact_response_new_pii*`）与 `json_aware_line` 的 JSON 重序列化，按字节级透传；已注册凭据 token 的精确还原 MAY 以字节级替换执行，但 SHALL NOT 触发全帧重排或掩码。系统 SHALL NOT 对这些字段产生新的 `__PII_` 占位符。

纯 `thinking_delta`（不携 `signature`/`redacted_data`）SHALL NOT 视为 opaque 载体：其文本 SHALL 经 `TokenCarry` 参与跨帧缝合，并按普通帧路径进入响应侧新 PII 掩码（`redact_response_new_pii_with_skip`）；其余帧字节保真口径不变。

上述签名/密文载体帧 SHALL NOT 进入 `PrefixHold`/`BoundaryHold` 的跨缝合掩码路径（`R8-08`）：系统 SHALL 为其提供无掩码直通通路（或以等价方式排除其字节区间），使 `signature` 与密文载荷不因跨缝命中而被 `mask_span_bytes` 改写；该直通 SHALL NOT 影响其他帧（含纯 `thinking_delta`）的跨缝检测口径。

签名/密文载体帧的还原守卫 SHALL 以字节恒等为最高优先：守卫失败时 SHALL 回退至掩码前占位符（上游原始帧）字节，SHALL NOT 施加响应侧新 PII 掩码、SHALL NOT 丢帧；失败 SHALL 记 warn 与 `record_restore_fallback` 恰一次。该豁免与「流式还原 JSON 破帧防护」显式互引且 MUST NOT 漂移。

#### Scenario: signature_delta 字节不变

- **WHEN** 上游流式发 `signature_delta` 事件
- **THEN** 下游该帧字节与上游逐字节一致（除已注册 token 的字节级精确还原外无任何改写）

#### Scenario: redacted_thinking 密文不被掩码

- **WHEN** `redacted_thinking.data` 含形似 PII（如数字串）的密文片段
- **THEN** 下游原样透传，无 `__PII_` 注入、无字节改写

#### Scenario: thinking 内 token 精确还原不重排

- **WHEN** `thinking_delta` 文本含已注册凭据 token
- **THEN** token 被字节级还原为明文，帧其余字节与上游一致，不触发 JSON 键序/数字变化

#### Scenario: opaque 帧不经跨缝掩码

- **WHEN** 前一帧尾与 opaque 帧首在跨缝窗口内拼出 PII/自定义 hint 命中
- **THEN** opaque 帧的签名/密文字节 SHALL NOT 被掩码改写（无跨缝掩码注入），其余帧的跨缝检测口径不变

#### Scenario: thinking_delta 仍参与跨帧掩码

- **WHEN** 相邻两帧的纯 `thinking_delta` 文本拼接后命中 PII/自定义 hint
- **THEN** 该跨缝命中 SHALL 被响应侧新 PII 掩码处理，且两帧仍经 `TokenCarry` 缝合（不被 opaque 直通旁路）
