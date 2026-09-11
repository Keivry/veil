# gateway-fidelity Specification

## Purpose
锁定 LLM 网关在传输保真面的修复后契约：流式还原遇特殊字符不破帧（转义或回退）、响应 JSON 帧零替换时逐字节透传且重序列化保持键序、请求 JSON 脱敏重序列化时诚实声明 `x-veil-normalized`、content-encoding 解码与剥头配对、Responses `response.failed` 保留上游 error 诊断字段、Anthropic opaque 字段原字节透传、残缺剥离不误删合法正文、Go 存量客户端网关侧兼容收敛。

## Requirements

### Requirement: 流式还原 JSON 破帧防护

系统 SHALL 保证响应流式路径（`Scope::restore_response_with_spans` → `Scope::redact_response_new_pii_with_skip` → `json_aware_line`）在还原帧「还原前可解析」的前提下，「还原后仍可解析」。系统 SHALL 在向 JSON 字符串上下文写入还原明文时按 RFC 8259 字符串转义规则处理（`"` → `\"`、`\` → `\\`、控制字符转义）。当转义后仍无法通过 JSON 校验时，系统 SHALL 回退为**还原前占位符帧字节**（fail-closed，占位符保留）并记录 warn 与 `record_restore_fallback` 指标；系统 SHALL NOT 将未转义明文写回、SHALL NOT 使下游收到 `JSONDecodeError` 破损帧。非流路径既有 `retry_stripped` 回退语义 SHALL 作为流式实现的对齐参照。

#### Scenario: 明文含双引号流式还原不破帧

- **WHEN** 已注册凭据明文含 `"`，上游响应 JSON 帧（如 `{"text":"... __VG_CRED_000001__ ..."}`）经流式还原写回
- **THEN** 下游收到的帧为合法 JSON，且解析后字符串值逐字符等于原始明文

#### Scenario: 明文含反斜杠与换行控制字符

- **WHEN** 已注册凭据明文含 `\` 或换行等控制字符，流式帧还原写回
- **THEN** 帧内对应位置为 JSON 转义形态（`\\`/`\n`），下游可解析且语义等价；不得出现裸控制字符

#### Scenario: 还原后仍破损则回退占位符帧

- **WHEN** 流式帧还原后 `jloads` 校验失败（病态输入），无法转义挽回
- **THEN** 下游收到还原前占位符帧（token 形态保留、不破帧），warn 日志与 `restore_fallback` 计数各 +1

#### Scenario: 非 JSON 帧不受影响

- **WHEN** 流式帧本身非 JSON（plain 文本残留）
- **THEN** 走既有 plain 路径，字节级还原不做 JSON 转义，行为与修复前一致

### Requirement: 响应 JSON 帧字节保真

系统 SHALL 在响应侧新 PII 检出为空且无叶替换时逐字节透传响应帧，SHALL NOT 执行无条件 `loads→walk→dumps` 重序列化。系统 SHALL 在必须重序列化时保持对象键序（启用 `serde_json` `preserve_order`）并使对象键按原始顺序输出。系统 SHALL 消除 `json_aware_line` 对已处理帧的二次重序列化（仅做解析校验或按输入返回）。无法在重序列化路径消除的数字表示与空白改写（如 `1e3` → `1000.0`）SHALL 在 README/design 显式声明为已知偏离；零替换路径 SHALL NOT 产生该偏离。

#### Scenario: 零替换响应帧逐字节透传

- **WHEN** 上游响应帧为 `{"b":2,"a":1}` 且响应侧未检出任何新 PII、无 token 还原
- **THEN** 下游字节与上游逐字节一致（键序仍为 `b,a`，无空白/数字变化）

#### Scenario: 新 PII 掩码时键序保持

- **WHEN** 响应帧 `{"b":"8.8.8.8","a":1}` 检出 IP 需掩码、必须重序列化
- **THEN** 输出对象键序仍为 `b,a`（非字典序 `a,b`），仅命中叶被替换为 `__PII_...__`

#### Scenario: 幂等帧不再二次重排

- **WHEN** 帧已经过作用域处理且不含任何待处理项，进入 `json_aware_line`
- **THEN** 输出与输入帧字节一致（不再触发第二次 `dumps`）

#### Scenario: 数字表示零替换不重写

- **WHEN** 响应帧含 `1e3` 且无任何替换
- **THEN** 下游仍收到 `1e3`，不得改写为 `1000.0`

### Requirement: 请求归一化声明诚实

系统 SHALL 在请求体因脱敏发生 `loads→walk→dumps` 重序列化时置位 `normalized_out`，并由 handler 输出 `x-veil-normalized: json-whitespace`；仅非 JSON 文本的字节级子串替换与原文透传 SHALL NOT 置位。`Scope::redact_request` SHALL 向调用方报告「是否经重序列化」（而非仅文本差异），使声明与实际字节变换一致。README §7.7 SHALL 与实现同字修订：删除「纯脱敏子串替换（字节级，未重序列化）」在不成立场景下的前提，明确 JSON 请求脱敏重序列化即置位（若 apply 改为 span 级字节替换方案，则按新事实恢复「字节级不置位」口径并同步 README）。

#### Scenario: JSON 脱敏重序列化置位

- **WHEN** 请求体为合法 JSON，PII/凭据替换经 json_walk 重序列化输出
- **THEN** 下游响应头含 `x-veil-normalized: json-whitespace`

#### Scenario: 非 JSON 字节替换不置位

- **WHEN** 请求体为非 JSON 纯文本，仅做 token 字节级替换（未解析 JSON）
- **THEN** 下游响应无 `x-veil-normalized` 头

#### Scenario: 无替换不置位

- **WHEN** 请求体无任何 PII/凭据命中且未触发空白归一/注入分支
- **THEN** 下游响应无 `x-veil-normalized` 头，转发体字节与原文一致

#### Scenario: 注入分支声明不回退

- **WHEN** `stream_options` 注入或占位符说明注入成功重序列化
- **THEN** 置位逻辑与既有声明口径一致，且不得因本修复回退既有置位条件

### Requirement: 内容编码解码配对

系统 SHALL 保证「剥除 `content-encoding`/`content-length`」与「reqwest 实际完成解压」严格配对。转发上游前系统 SHALL 剥离或重写下游 `accept-encoding` 为网关实际支持集（gzip/br/deflate，或按 design D4 决策显式启用 zstd feature 后含 zstd），SHALL NOT 把客户端声明的全部编码原样透传。网关不支持解码的编码（如未启用 feature 的 zstd）、多值编码与别名（`x-gzip`）SHALL NOT 被无声明地剥头透传；要么先解压后剥头，要么保留编码头原样透传使下游可自解。

#### Scenario: 未支持编码不剥头透传压缩字节

- **WHEN** 客户端发 `accept-encoding: zstd` 且上游返回 `content-encoding: zstd`，网关未启用 zstd 解码
- **THEN** 下游要么收到解压后正文且无 `content-encoding` 头，要么收到保留 `content-encoding: zstd` 的原始压缩字节；不得出现「无编码头 + 压缩字节」

#### Scenario: 支持集内编码解码剥头

- **WHEN** 客户端发 `accept-encoding: gzip, br` 且上游返回 gzip 响应
- **THEN** 转发上游的请求头中 `accept-encoding` 已被剥离或重写为支持集；下游正文已解压且无 `content-encoding`/`content-length` 头

#### Scenario: 别名编码配对一致

- **WHEN** 上游返回 `content-encoding: x-gzip`（gzip 别名）
- **THEN** 与 `gzip` 同口径处理（解码成功后剥头或保头透传），不得混用

### Requirement: Responses 失败帧诊断保真

系统 SHALL 在响应流 `type:"error"` 合成 `response.failed` 时，将上游 error 对象中存在的 `code`/`type`/`param`/`message` 字段映射进合成帧的 `response.error`（message 缺失时回退既有形态）。系统 SHALL NOT 仅保留 `message` 而静默丢弃其余诊断字段。确实无法保真的字段范围 SHALL 在 README §7.2 显式声明（lossy 边界），不得留作未声明行为。

#### Scenario: 诊断字段保留

- **WHEN** 上游 error 为 `{"type":"error","code":"rate_limit_exceeded","param":"model","message":"slow down"}`
- **THEN** 合成 `response.failed` 的 `response.error` 含 `code=="rate_limit_exceeded"`、`param=="model"`、`message=="slow down"`（type 按对象形态保留或声明不保留）

#### Scenario: 仅 message 时无空字段噪声

- **WHEN** 上游 error 仅含 `message`
- **THEN** 合成帧保留 message，且不输出 `code`/`param` 的 null 或空串噪声

#### Scenario: 无 message 不崩空

- **WHEN** 上游 error 对象无 `message`（或 error 为非对象）
- **THEN** 合成帧回退既有 `{"id","status"}` 形态，无 panic、无空体

### Requirement: Opaque 字段原字节透传

系统 SHALL 对 Anthropic `signature_delta`、`redacted_thinking`、`thinking`（含 `thinking_delta`）及其他签名/加密载体帧跳过响应侧新 PII 扫描（`redact_response_new_pii*`）与 `json_aware_line` 的 JSON 重序列化，按字节级透传；已注册凭据 token 的精确还原 MAY 以字节级替换执行，但 SHALL NOT 触发全帧重排或掩码。系统 SHALL NOT 对这些字段产生新的 `__PII_` 占位符。

#### Scenario: signature_delta 字节不变

- **WHEN** 上游流式发 `signature_delta` 事件
- **THEN** 下游该帧字节与上游逐字节一致（除已注册 token 的字节级精确还原外无任何改写）

#### Scenario: redacted_thinking 密文不被掩码

- **WHEN** `redacted_thinking.data` 含形似 PII（如数字串）的密文片段
- **THEN** 下游原样透传，无 `__PII_` 注入、无字节改写

#### Scenario: thinking 内 token 精确还原不重排

- **WHEN** `thinking_delta` 文本含已注册凭据 token
- **THEN** token 被字节级还原为明文，帧其余字节与上游一致，不触发 JSON 键序/数字变化

### Requirement: 残缺剥离边界收敛

系统 SHALL 将 `strip_cred_partials` 与 `strip_pii_partials` 的剥离范围收敛到可确证为占位符残缺的形态。系统 SHALL NOT 删除正文中形似前缀但后续为合法单词字符的普通文本（如 `__VG_CREDENTIALS`、`__PIXEL`、`__PII_DATA`）。真残缺形态（流分片切断的 `__VG_CRED_000`、`__PII_3_ab`）的清理保护 SHALL NOT 退化；完整凭据 token 在还原先行后仍按既有口径清理。

#### Scenario: 合法正文前缀不误删

- **WHEN** 正文含 `__VG_CREDENTIALS`、`__PIXEL`、`__PII_DATA` 等非占位符续段
- **THEN** 输出与输入逐字节一致，不得删除任何字符

#### Scenario: 真残缺仍被清理

- **WHEN** 流分片输出确证残缺 `__VG_CRED_000` 或 `__PII_3_ab`
- **THEN** 残缺片段被剥离，不泄漏半截占位符（既有保护不退化）

#### Scenario: 边界差分锁定

- **WHEN** 输入为前缀本身（`__VG_`、`__PI`）或前缀 + 下划线变体
- **THEN** 行为与 design D7 裁定的差分用例表一致，且单测锁定该表

### Requirement: Go 网关侧兼容收敛

系统 SHALL 在 `POST /credential` 三因子核验中，当头缺失时回退读取 `body.auth.get_binary_hash` / `body.auth.get_binary_secret`（Go 存量 `CredentialBody` 字段），使 Go 形态请求能按三因子语义放行/转审/403，而非恒 403。系统 SHALL 使 `GET /health` 与 `POST /register-caller` 响应在不删除既有字段的前提下提供 Go 可解析的加性超集字段。错误体形态决策 SHALL 明确写入 README（对象契约保持 + Go 侧解析容忍由 `veil-hardening` 5.2 承接，交叉引用不改该 change 文件）。SSE 终止帧对无 SSE 消费代码的 Go 客户端 SHALL 保持透明（流恒以终止帧闭合，客户端不重试不挂起）。

#### Scenario: body.auth 因子回退

- **WHEN** 请求仅带 `body.auth.get_binary_hash` 与 `body.secret`（无对应头）
- **THEN** 三因子核验读取体字段，返回放行/202 `E_PENDING`/403 之一，不得因「头缺失」直接判 Secret 失败

#### Scenario: health 超集不破坏旧新客户端

- **WHEN** `GET /health` 被 `get status` 与既有探针同时调用
- **THEN** 响应同时含 `ok`/`sqlite_ok` 与 `status`/`unlocked`（及 design 裁定的加性字段），任何一方解析均不失败

#### Scenario: register 形态加性兼容

- **WHEN** `POST /register-caller` 以 Go 形态（`name/script_path/script_hash/entries/allow_mode`）或既有形态提交
- **THEN** 响应在不删除既有字段的前提下提供兼容超集，且幂等/重名 409 语义不变

#### Scenario: SSE 终止对 Go 透明

- **WHEN** 流式响应被审计阻断或上游截断
- **THEN** 流以终止帧闭合（Chat `[DONE]`、Anthropic `message_stop`、Responses 终端恰一），Go 客户端视为正常结束，不重试不挂起
