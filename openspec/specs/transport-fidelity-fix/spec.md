# transport-fidelity-fix Specification

## Purpose
锁定 LLM 网关传输保真契约：入站 query 保序保编码转发、非流上游响应头逐跳过滤后透传、流式独立无总超时 client、非流响应体有界读取、协议尾判定排除官方子资源、非流还原 JSON 转义、Anthropic usage total 跨事件口径、还原区间跳过后的嵌套重检、网关生成错误响应统一 `x-veil-protocol`、检索调用官方 `action` 审计、拿头前瞬断重试分类、非流超限/空体判序声明。

## Requirements

### Requirement: 入站 query 保序转发

系统 SHALL 将入站请求的原始 query string 保序追加到上游 URL：`GET`/`POST` 等任意方法、对话（`Protocol::Chat`/`Anthropic`/`Responses`）与 `Protocol::NonDialog` 透传路径 SHALL 同源适用。query SHALL 按 `Uri::query()` 原样转发（不重排、不重编码、不丢弃空值参数与重复键，保留 `%` 编码与 `+` 形态）；无 query 时 SHALL NOT 追加 `?` 后缀。上游基址自带 query 的形态 SHALL NOT 发生二次拼接歧义（基址尾斜杠与 path/query 拼接规则确定）。

#### Scenario: NonDialog 带 query 透传

- **WHEN** 客户端请求 `GET /v1/models?limit=10&after=abc`
- **THEN** 上游收到 `limit=10&after=abc` 同序同编码 query，响应按 NonDialog 字节透传

#### Scenario: 对话路径带 query 转发

- **WHEN** 客户端请求 `POST /v1/chat/completions?trace=1&x=a%2Bb`
- **THEN** 上游收到 `trace=1&x=a%2Bb` 原样 query，协议仍判 `Chat`

#### Scenario: 无 query 不追加问号

- **WHEN** 入站请求无 query string
- **THEN** 上游 URL 不含 `?` 后缀，与修复前路径保持逐字节一致

#### Scenario: 空值参数保留

- **WHEN** 入站请求 `GET /v1/models?limit=`（空值参数）
- **THEN** 上游收到 `limit=`，不被规范化丢弃

### Requirement: 非流上游响应头透传

系统 SHALL 在非流对话响应路径（含 `status>=400` 非 JSON 错误体透传分支与 JSON 后处理分支）消费上游 body 前快照上游响应头，按逐跳（HOP）过滤规则过滤后转发；SHALL 保留上游 `content-type`（如 `application/json`、`text/plain`）与 `retry-after`、`x-request-id`、rate-limit 类头；SHALL NOT 由框架默认值（`text/plain; charset=utf-8`、`application/octet-stream`）覆盖上游声明。网关自有 `x-veil-*` 头 SHALL 在过滤后追加，SHALL NOT 从上游透传同名头。上游无 `content-type` 时，JSON 后处理分支 SHALL 回退 `application/json`。

#### Scenario: 200 JSON content-type 保留

- **WHEN** 上游 200 返回 `content-type: application/json` 的对话响应
- **THEN** 下游响应 `content-type` 为 `application/json`，不再被强制为 `text/plain; charset=utf-8`

#### Scenario: 429 Retry-After 透传

- **WHEN** 上游 429 返回 `retry-after: 30` 与 `text/plain` 体
- **THEN** 下游收到 429、`retry-after: 30` 与同字节正文

#### Scenario: 逐跳头过滤

- **WHEN** 上游响应携带 `connection`、`transfer-encoding` 等逐跳头
- **THEN** 下游不出现这些逐跳头，且 `hop_filtered_total` 计数递增

#### Scenario: x-veil 头不被上游覆盖

- **WHEN** 上游响应自带 `x-veil-protocol` 头
- **THEN** 下游该头为网关派生值，上游值不生效

### Requirement: 流式转发独立超时策略

系统 SHALL 对流式（SSE）上游转发使用独立 client：MUST NOT 施加覆盖整个响应体读取的总超时（避免长流被 `HTTP_TIMEOUT_SECS` 截断）；MAY 配置读空闲超时用于失活连接回收。非流与 NonDialog 透传 SHALL 保持既有总超时口径（`HTTP_TIMEOUT_SECS`，默认 `30`s）。两类 client SHALL 在启动期构造并经共享态注入，MUST NOT 在请求路径构造新 `reqwest::Client`。流式 client 的读空闲超时与失效口径（无 / 取值）SHALL 在 design 与 README 显式声明。

#### Scenario: 长流不因总超时中断

- **WHEN** 以较小 `HTTP_TIMEOUT_SECS`（如 `1`）配置启动，上游流式持续产出超过该时长且事件间隔小于读空闲阈值
- **THEN** 下游流持续收到事件、不被网关以超时中断

#### Scenario: 非流保持总超时

- **WHEN** 非流上游响应头到达后长时间不返回 body
- **THEN** 网关按 `HTTP_TIMEOUT_SECS` 超时映射为网关错误，行为与修复前一致

#### Scenario: 启动期构造共享注入

- **WHEN** 审查转发路径实现
- **THEN** 请求处理函数内不存在 `Client::new`/`Client::builder` 调用，两类 client 均于启动期构造并经共享态注入

### Requirement: 非流响应体有界读取

系统 SHALL 在非流对话路径对上游响应体执行有界读取：`content-length` 声明严格大于 `NONSTREAM_MAX_BYTES` 且 `status < 400` 时 SHALL 直接返回 502 `response_too_large`，SHALL NOT 先全量读入内存；无 `content-length` 或分块传输时 SHALL 以累计字节有界读取并在超过上限时停止读取并返回 502。`status >= 400` 的错误体 SHALL 维持既有语义（按状态与字节透传，不受超限改写）。边界 `len == cap` SHALL 放行。

错误状态响应体的读取 SHALL 同样受有界约束、SHALL NOT 无界全量缓冲：`status >= 400` 时系统 SHALL NOT 以一次性缓冲整个错误体的方式（无界读取）读取上游正文；SHALL 采用累计字节有界读取，并在累计超过上限时按 design 既定策略截断或转为流式转发，保证内存占用不随错误体体积线性增长。有界读取仅为内存安全手段，SHALL NOT 改变错误臂的可观测语义——下行状态码 SHALL 保持上游原值、正文 SHALL NOT 被改写为 502 `response_too_large`（与「错误状态不受超限改写」一致）；截断或流式转发的具体选择 SHALL 在 design 固定并以回归测试锁定。

#### Scenario: content-length 预检

- **WHEN** 上游 200 响应 `content-length` 严格大于 `NONSTREAM_MAX_BYTES`
- **THEN** 网关立即返回 502 `response_too_large`，不读取响应体

#### Scenario: 分块超限停止读取

- **WHEN** 上游以 `transfer-encoding: chunked` 持续输出超过 `NONSTREAM_MAX_BYTES` 的 200 响应体
- **THEN** 网关在累计超限处停止读取并返回 502，内存占用不随响应体线性增长

#### Scenario: 错误状态不受超限改写

- **WHEN** 上游 `status >= 400` 且响应体超过 `NONSTREAM_MAX_BYTES`
- **THEN** 网关按状态码与正文字节透传，不改写为 502 `response_too_large`

#### Scenario: 错误大体积有界读不改语义

- **WHEN** 上游 `status >= 400` 返回超大错误体（超过 `NONSTREAM_MAX_BYTES`）
- **THEN** 网关读取过程内存有界（不一次性全量缓冲），下行保持上游状态码、不合成 502

### Requirement: 协议尾判定排除官方子资源

系统 SHALL 仅将对话尾本身（`/chat/completions`、`/v1/messages`、`/v1/responses`）与既有尾斜杠/一层标点宽容命中判为对话协议；对尾后缀额外路径段的官方子资源 SHALL 判 `Protocol::NonDialog` 字节透传，SHALL NOT 触发请求改写、占位符注入、用量记录或审计判定：至少包含 Anthropic `v1/messages/count_tokens`、`v1/messages/batches`，以及 Responses `v1/responses/{任意单段}`（响应对象检索）。`v1/responses/{id}/cancel`、`v1/responses/{id}/input_items` 等更深子资源 SHALL 同样为 `NonDialog`。

#### Scenario: count_tokens 判 NonDialog

- **WHEN** 请求 `POST /v1/messages/count_tokens`
- **THEN** 协议为 `NonDialog`，请求体与响应体字节透传，不注入占位符、不记对话用量

#### Scenario: 响应对象检索判 NonDialog

- **WHEN** 请求 `GET /v1/responses/{id}`
- **THEN** 协议为 `NonDialog`，响应原字节透传，不合成阻断体、不触发审计后处理

#### Scenario: 子资源取消/输入项判 NonDialog

- **WHEN** 请求 `POST /v1/responses/{id}/cancel` 或 `GET /v1/responses/{id}/input_items`
- **THEN** 协议为 `NonDialog`，字节透传

#### Scenario: batches 判 NonDialog

- **WHEN** 请求 `GET /v1/messages/batches`
- **THEN** 协议为 `NonDialog`，字节透传

#### Scenario: 既有宽容语义保持

- **WHEN** 请求 `/v1/chat/completions/extra`（非官方子资源的一层宽容形态）
- **THEN** 仍判 `Chat` 并记宽容计数，既有 `llm-gateway` 一层宽容契约不回退

### Requirement: 非流 JSON 还原按转义变体

系统 SHALL 对非流对话 JSON 响应体的还原使用 JSON 转义变体（与流式 `restore_response_with_spans_json` 同语义：写回明文按 RFC 8259 转义 `"`/`\`/控制字符）；SHALL NOT 使用字节级直写还原。明文含 `"` 或 `\` 时，还原后响应体 SHALL 仍为可解析 JSON，且 SHALL NOT 因写破 JSON 而回退为未还原上游原文（下游不得看到占位符）。

#### Scenario: 明文含引号正确还原

- **WHEN** vault 明文含 `"` 且上游响应体占用位符 token
- **THEN** 下游 JSON 解析成功，字段值为完整明文，无 `__VG_CRED_`/`__PII_` 残留

#### Scenario: 明文含反斜杠正确还原

- **WHEN** vault 明文含 `\` 或控制字符
- **THEN** 还原后 JSON 可解析且明文完整，不触发 `restore_fallback`

### Requirement: Anthropic 流式 usage total 跨事件口径

系统 SHALL 使 Anthropic 流式 `total_tokens` 跨事件正确：当事件携带显式 `total_tokens`（或 `total`）时取各事件显式值的 `max`；当所有事件均未携带显式 total 时，SHALL 以合并后的 `max(prompt_tokens)+max(completion_tokens)` 归一，SHALL NOT 对各事件按单事件 `prompt+completion` 派生的 total 取 `max` 作为最终值（避免 `message_start` 部分 output 与 `message_delta` 增量错配低估）。

#### Scenario: start 与 delta 跨事件求和

- **WHEN** 流式收到 `message_start` usage `{input_tokens:100, output_tokens:1}` 与 `message_delta` usage `{output_tokens:50}`
- **THEN** 记录 `prompt_tokens=100`、`completion_tokens=50`、`total_tokens=150`

#### Scenario: 显式 total 优先

- **WHEN** 某事件显式携带 `total_tokens` 且与 prompt/completion 之和不一致
- **THEN** 记录取显式 total 的 `max`

### Requirement: 还原区间跳过后的嵌套重检

系统 SHALL 在按还原区间切段后，对非跳过段重新执行 JSON-aware 新 PII 检测（包含嵌套 stringified JSON 的递归解析）；跳过段 SHALL 保持字节级原样（刚还原的请求明文不二次掩码）。工具调用参数等嵌套 JSON 字符串内出现的新 PII SHALL NOT 因分段切分而漏检。

#### Scenario: 混合场景双重处理

- **WHEN** 同一响应既含 vault 凭据占位符（需还原）又含工具参数内新 PII（需掩码）
- **THEN** 凭据区段还原为明文、工具参数内新 PII 被掩码，二者互不影响

#### Scenario: 纯跳过不误伤

- **WHEN** 响应仅含还原区间且新 PII 检测关闭
- **THEN** 输出与输入逐字节一致

### Requirement: 网关生成非流错误响应统一协议头

系统 SHALL 对非流对话路径由网关生成的响应统一置 `x-veil-protocol` 头（取值为请求协议派生 `chat`/`anthropic`/`responses`），至少覆盖：`status>=400` 非 JSON 错误体透传、超限 502 `response_too_large`、空体/非 JSON 502 `E_EMPTY_BODY`；与成功分支、阻断分支口径一致。上游响应头转发时该头 SHALL 以网关派生值覆盖同名上游头。

#### Scenario: 429 透传含协议头

- **WHEN** 上游 429 非 JSON 错误体经网关透传
- **THEN** 下游响应含 `x-veil-protocol: chat`（随请求协议）

#### Scenario: 502 超限含协议头

- **WHEN** 非流对话响应超限返回 502 `response_too_large`
- **THEN** 下游响应含对应协议的 `x-veil-protocol`

#### Scenario: 空体 502 含协议头

- **WHEN** 非流对话上游返回空体/非 JSON 触发 `E_EMPTY_BODY`
- **THEN** 下游响应含对应协议的 `x-veil-protocol`

### Requirement: web_search_call 官方 action 审计

系统 SHALL 使 Responses 检索调用（`web_search_call`/`file_search_call`）的审计参数提取覆盖官方条目形态 `action` 对象：`action.query` 为字符串时 SHALL 作为审计参数（`action.queries` 为数组时 SHALL 序列化）；legacy 顶层 `queries`/`query` 形态 SHALL 保留为回退。检索查询 SHALL NOT 因官方 `action` 形态而漏进审计 hold；检索结果（`results`）SHALL 继续不进审计。

#### Scenario: action.query 进审计

- **WHEN** Responses 输出条目 `{"type":"web_search_call","action":{"type":"search","query":"veil audit"}}`
- **THEN** 审计参数含 `veil audit`，hold 判定与 legacy 形态同通道

#### Scenario: legacy 顶层 query 保持

- **WHEN** 条目带顶层 `query`/`queries`
- **THEN** 审计参数按既有回退顺序提取，不因新增 action 分支回退

### Requirement: 拿头前瞬断重试分类

系统 SHALL 在拿头前（`send()` 返回 `Ok` 之前）对瞬断类错误统一执行退避重试：至少覆盖 connect/timeout 及请求/请求体发送类错误（reqwest `is_connect`/`is_timeout`/`is_request` 等），按 0.5s→1s→2s 退避、最多 3 次；一旦 `send()` 返回响应（拿到响应头）SHALL NOT 重试（中段断连走既有 fail-closed 终止）。重试边界 SHALL 以「请求尚未向客户端产生任何输出、幂等安全」为准。

#### Scenario: RST 瞬断退避后成功

- **WHEN** mock 上游第一次连接被 RST、随后恢复正常
- **THEN** 网关退避后重试并成功拿到响应，下游无错误

#### Scenario: 拿头后不重试

- **WHEN** 已拿到响应头后上游断连
- **THEN** 不发起重试，按 fail-closed 终止闭合

#### Scenario: 重试次数有界

- **WHEN** mock 上游持续 RST 超过 3 次
- **THEN** 网关最多退避重试 3 次后按网关错误返回，无无限重试

### Requirement: 非流超限与空体判序声明

系统 SHALL 保持 canonical `runtime-parity-limits` 的「非流对话响应体上限」口径：`status < 400` 且响应体长度严格大于 `NONSTREAM_MAX_BYTES` 时返回 502 `response_too_large`，`len == cap` 放行，`status >= 400` 不改写；超限判定 SHALL 先于空体/非 JSON 502 动作生效。与 Python 原仓在超限分支的日志与指标差异（Python 记 `metrics_ctx['status']=502` 与 warning、判定无状态门；本仓不设独立超限指标）SHALL 在 design 与 README 记录，SHALL NOT 以静默差异处理。

#### Scenario: 非 JSON 200 超限命中

- **WHEN** 上游 200 返回非 JSON 体且长度大于 `NONSTREAM_MAX_BYTES`
- **THEN** 网关返回 502 且 `error.type=response_too_large`，不走空体 502

#### Scenario: 错误状态超限透传

- **WHEN** 上游 429 非 JSON 体长度大于 `NONSTREAM_MAX_BYTES`
- **THEN** 网关按 429 与正文字节透传，不改写为超限 502

#### Scenario: 观测差异记录

- **WHEN** 查阅 design 与 README §4/§7.2
- **THEN** 超限分支在本仓无独立指标/日志、与 Python `metrics_ctx['status']`+warning 的差异有显式记录
