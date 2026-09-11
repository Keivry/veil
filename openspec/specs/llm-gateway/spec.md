# llm-gateway Specification

## Purpose
LLM 网关兼容多协议转发（OpenAI chat / Anthropic / Responses 系）：通配路由、对话尾判定、占位符注入、流式缓冲与终止语义统一收敛，非对话流量透传不干扰计费与审计口径。本 spec 的截断、终止、尾判定口径与 protocol-compliance-fix spec（FIX-2 / FIX-4）同字，FIX 定义以 protocol-compliance-fix 为准；字节契约与 redaction spec json-aware 定义同字，语义细节以 redaction spec 为准，本 spec 只做网关侧落点。

## Requirements

### Requirement: /{tail} 通配路由与 is_chat_tail 唯一判定

网关 SHALL 以 `/{tail}` 通配承接全部上游路径；`is_chat_tail` SHALL 为全协议唯一尾判定函数，仅在三类对话尾部返回真：`/chat/completions`、`/messages`、`/responses`；其余尾 SHALL 判定为假。任何业务分支 MUST NOT 内联 `endswith` 做尾判定（B1 审计旁路），一律调用 `is_chat_tail`。

#### Scenario: 对话尾命中
- **WHEN** 请求路径尾为 `/chat/completions`、`/messages`、`/responses` 之一
- **THEN** `is_chat_tail` 返回真，走对话处理分支

#### Scenario: 非对话尾透传分支
- **WHEN** 请求路径尾为上述三者之外（如模型列表、用量查询）
- **THEN** `is_chat_tail` 返回假，走透传分支

#### Scenario: 内联 endswith 禁止
- **WHEN** 代码审计扫描业务分支
- **THEN** 不存在内联 `endswith` 尾判定，全部经 `is_chat_tail`（违例即 B1 审计旁路缺陷）

### Requirement: is_chat_tail 一层后缀宽容与可观测

`is_chat_tail` SHALL 保留一层后缀宽容（仅容忍一层合法后缀如斜杠或标点变体）；每次宽容命中 SHALL 记 `chat_tail_lenient_total{tail}` 计数并写 debug 日志（含 path 与 tail 标签）；严格命中与宽容命中 SHALL 在日志中可区分。

#### Scenario: 宽容命中计数与日志
- **WHEN** 请求路径以对话尾加一层容忍后缀到达
- **THEN** 判定为真，`chat_tail_lenient_total{tail}` 加一并记 debug 日志

#### Scenario: 非对话请求不污染
- **WHEN** 请求为 `v1/models` 等非对话路径
- **THEN** 判定为假，不计入宽容计数，不走对话分支

### Requirement: 非对话透传不计费不审计 PII

非对话尾请求 SHALL 原样透传上游，不注入占位符，不计入对话用量，不触发 PII 审计。

#### Scenario: 非对话请求透传
- **WHEN** 客户端请求非对话尾路径
- **THEN** 网关原样转发，不做注入与审计计数

### Requirement: stream_options 仅 chat / responses 注入

`stream_options` 参数 SHALL 仅对 `chat` 与 `responses` 系请求注入；Anthropic `messages` 系 SHALL NOT 注入。

#### Scenario: chat 系注入 stream_options
- **WHEN** chat 或 responses 请求开启流式但未带 `stream_options`
- **THEN** 网关注入默认 `stream_options`

#### Scenario: Anthropic 系不注入
- **WHEN** 请求为 Anthropic `messages` 系
- **THEN** 网关不注入 `stream_options`，原样转发

### Requirement: 占位符注入三条件

占位符注入 SHALL 同时满足三条件才执行：`is_chat_tail` 为真、启用脱敏、请求体含需替换值；任一不满足 SHALL NOT 注入。

#### Scenario: 三条件齐备注入
- **WHEN** 对话尾请求、脱敏启用、正文含已注册凭据或 PII
- **THEN** 网关将明文替换为占位符后转发上游

#### Scenario: 条件缺失不注入
- **WHEN** 任一条件不满足（如脱敏未启用）
- **THEN** 网关原样转发，不注入占位符

### Requirement: WHATWG 缓冲与 slow / fast 双速

流式转发 SHALL 使用 WHATWG 缓冲语义；网关 SHALL 支持 `slow` / `fast` 双速转发档：`slow` 逐分片即时转发（低延迟），`fast` 按标点边界聚合后转发（利于脱敏完整性）。

#### Scenario: slow 档低延迟
- **WHEN** 配置为 `slow` 档
- **THEN** 分片到达即转发，延迟最低

#### Scenario: fast 档聚合转发
- **WHEN** 配置为 `fast` 档
- **THEN** 分片按标点边界聚合后转发，截断形态完整

### Requirement: 审计 hold 与空流 502

审计未决（hold）期间 SHALL 暂存尾部分片不向客户端放行；上游返回空流（零有效分片）SHALL 按 FIX-2 终止闭合处理（chat 恒补 `data:[DONE]`），空流整体仍转为 502 错误语义并记审计。

#### Scenario: 审计 hold 暂存
- **WHEN** 审计判定未决
- **THEN** 网关暂存尾部分片，待审计结论后再放行或拒绝

#### Scenario: 空流转 502 且补 DONE
- **WHEN** 上游返回零有效分片
- **THEN** 网关按 FIX-2 补足终止块后向客户端返回 502 口径

### Requirement: 三协议终止闭合（引用 FIX-2）

本 Requirement 口径与 protocol-compliance-fix spec FIX-2 同字：chat 阻断/空流恒以 `data:[DONE]` 恰 1 个收尾；Anthropic 补 `content_block_stop` + `message_delta` + `message_stop`；responses 阻断补 `response.completed`、截断补 `response.failed`；合成块必须带 `event:` 行。重复终止标记 SHALL 被去重，不得重复计费。

#### Scenario: chat 阻断补 DONE 恰 1 个
- **WHEN** chat 流被审计阻断或上游空流
- **THEN** 网关注入阻断块后恒以 `data:[DONE]` 恰 1 个收尾

#### Scenario: Anthropic 三件套终止
- **WHEN** Anthropic 流被阻断或正常结束
- **THEN** 网关补 `content_block_stop` + `message_delta`（含 `stop_reason`）+ `message_stop`，合成块带 `event:` 行

#### Scenario: responses completed 与 failed 区分
- **WHEN** responses 流被阻断
- **THEN** 网关补 `response.completed`；截断场景补 `response.failed`，两者不得互换，合成块带 `event:` 行

### Requirement: 截断三态（唯一值）

流截断状态 SHALL 仅为三态之一：`silent_discard` / `open_ended` / `synthesized_failed`（`synthesized_failed` 仅 responses 可用）；网关 SHALL 在 `stream_meta.truncated_mode` 记录该值并落 metrics（截断计数按 mode 分标签）。本 spec 不得使用 `complete` / `truncated` / `aborted` 旧三态命名。

#### Scenario: silent_discard 静默丢弃
- **WHEN** 超限尾部命中静默丢弃策略
- **THEN** `stream_meta.truncated_mode=silent_discard` 并记 metrics

#### Scenario: open_ended 保持开放
- **WHEN** 流保持开放等待后续
- **THEN** `stream_meta.truncated_mode=open_ended` 并记 metrics

#### Scenario: synthesized_failed 仅 responses
- **WHEN** responses 流需合成失败终止
- **THEN** `stream_meta.truncated_mode=synthesized_failed` 并记 metrics；chat 与 Anthropic 不得取该值

### Requirement: 请求改写字节契约（引用 redaction）

网关 SHALL 遵循与 redaction spec json-aware 定义同字的字节契约：默认仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`。语义细节以 redaction spec 为准。

#### Scenario: 默认子串替换不重排
- **WHEN** `normalize_json_whitespace` 未开启
- **THEN** 网关仅做 token 子串替换，不重排 JSON，不带 `x-veil-normalized` 头

#### Scenario: 开启才允许 dumps 重写
- **WHEN** `normalize_json_whitespace=1`
- **THEN** 网关允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`

### Requirement: 非流式 usage 与流式同口径捕获

非流式响应 SHALL 与流式口径一致捕获用量：responses 系 SHALL 捕获单层 `response.usage`，Anthropic 系 SHALL 捕获 `message.usage`；用量缺失 SHALL 记缺失计数不断链。

#### Scenario: responses 单层 usage 捕获
- **WHEN** 非流式 responses 响应含单层 `response.usage`
- **THEN** 网关按流式同口径捕获并计入用量

#### Scenario: Anthropic message.usage 捕获
- **WHEN** 非流式 Anthropic 响应含 `message.usage`
- **THEN** 网关按流式同口径捕获并计入用量

### Requirement: 审批 keepalive 句柄 per-request 隔离与 slow / fast 对齐

审批 keepalive 句柄 SHALL 由 per-request 持有，MUST NOT 跨请求共享字段；首包到达前即挂起（首包即挂起）SHALL 同样保活；slow 与 fast 双路径 keepalive SHALL 对齐：每 10s 下发一次冒号注释行，注释行 SHALL NOT 计入 `sse_event`。

#### Scenario: keepalive 句柄不跨请求共享
- **WHEN** 多请求并发挂起审批
- **THEN** 各请求持独立 keepalive 句柄，无共享字段串扰

#### Scenario: 首包即挂起亦保活
- **WHEN** 审计在首个上游分片到达前即挂起请求
- **THEN** 网关仍按 10s 节奏下发 keepalive 注释保活连接

#### Scenario: slow 与 fast 注释对齐且不计事件
- **WHEN** slow 或 fast 任一路径下发 keepalive 注释
- **THEN** 节奏均为 10s，且注释行不计入 `sse_event` 计数

### Requirement: 上游重试边界（仅拿头前 3 次，中段 fail-closed 不重试）

上游重试 SHALL 仅在拿头前（响应头/首字节到达前）执行，最多 3 次（指数退避 0.5s→1s→2s）；中段断连（已开始向客户端放行后）SHALL 走 fail-closed 丢弃注入，不重试。

#### Scenario: 拿头前瞬断重试
- **WHEN** 上游在响应头到达前瞬断
- **THEN** 网关按 0.5s→1s→2s 退避重试，最多 3 次

#### Scenario: 中段断连不重试走 fail-closed
- **WHEN** 上游在已放行分片后断连
- **THEN** 网关不重试，按 fail-closed 丢弃注入并闭合终止

### Requirement: tail 与 Content-Type 冲突时 tail 优先

协议分发 SHALL 以 `is_chat_tail(tail)` 为准；`Content-Type` 仅作日志与透传参考，MUST NOT 作为分发依据；两者冲突时 SHALL 以 tail 判定优先。

#### Scenario: 冲突时 tail 优先
- **WHEN** 路径尾判定与 `Content-Type` 暗示的协议分支不一致
- **THEN** 网关按 `is_chat_tail(tail)` 分发，`Content-Type` 仅记录日志并透传

### Requirement: 空体 502 四分支一致性

空响应与错误透传 SHALL 按四分支执行：流式空流（零有效分片）SHALL 按 FIX-2 注入终止后转 502；非流式空体/非 JSON SHALL 转 502；上游 `502`/`401` SHALL 原样透传不改写；非对话尾 SHALL 豁免（原样透传不转 502）。

#### Scenario: 流式空流注入转 502
- **WHEN** 上游返回零有效分片的流
- **THEN** 网关按 FIX-2 补足终止块后按 502 口径处理并记审计

#### Scenario: 非流式空体非 JSON 转 502
- **WHEN** 非流式上游返回空体或非 JSON
- **THEN** 网关转为 502，不透传空体

#### Scenario: 502 与 401 透传
- **WHEN** 上游返回 `502`/`401`
- **THEN** 网关原样透传状态码与包体，不改写

#### Scenario: 非对话豁免
- **WHEN** 空响应来自非对话尾路径
- **THEN** 网关原样透传，不转 502，不计对话用量
