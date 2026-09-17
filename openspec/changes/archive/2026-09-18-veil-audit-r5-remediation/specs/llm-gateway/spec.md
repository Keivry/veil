# Spec Delta

## RENAMED Requirements

- FROM: `### Requirement: stream_options 仅 chat / responses 注入`
- TO: `### Requirement: stream_options 仅 Chat 注入`

## MODIFIED Requirements

### Requirement: stream_options 仅 Chat 注入

`stream_options` 参数 SHALL 仅对 `chat` 系请求注入；`responses` 系与 Anthropic `messages` 系 SHALL NOT 注入。注入判定的唯一来源 SHALL 为 `src/service/llm_gateway/protocol.rs::should_inject_stream_options`，其对非 Chat 协议 SHALL 直接返回假。Responses 官方 `stream_options` 仅接受 `include_obfuscation`、无 `include_usage`，其流式用量 SHALL 经 `response.completed.response.usage` 三级回退捕获（见「非流式 usage 与流式同口径捕获」），不依赖请求注入（与 README §7.2 同字）。Chat 已带 `stream_options` 对象时 SHALL 按 key 合并（仅 `include_usage` 缺失才注入）、已含 `include_usage`（含 `false`）SHALL 原样保留、显式 `null` SHALL 原样保留；用户自带的 `responses` 系 `stream_options` SHALL 逐字节原样转发（MUST NOT 注入、合并或删除）。

#### Scenario: chat 系注入 stream_options
- **WHEN** Chat 请求开启流式（`stream:true`）但未带 `stream_options`（或对象缺 `include_usage`）
- **THEN** 网关注入默认 `stream_options.include_usage=true` 并重序列化转发体（`x-veil-normalized: json-whitespace`）

#### Scenario: Anthropic 系不注入
- **WHEN** 请求为 Anthropic `messages` 系或 Responses 系
- **THEN** 网关 SHALL NOT 注入 `stream_options`，原样转发（Responses 用户自带键逐字节保留）

### Requirement: 占位符注入三条件

占位符注入 SHALL 同时满足三条件才执行：`is_chat_tail` 为真、启用脱敏、请求体含需替换值；任一不满足 SHALL NOT 注入。**容器缺失三协议不对称（已声明，`R5-37`/D11）**：Anthropic 缺 `system` 时 SHALL 新建 `system` 容器并注入说明；Chat SHALL 要求 `messages` 为数组（缺失或非数组 → SHALL NOT 注入）；Responses SHALL 要求 `input`/`instructions` 至少其一存在且形态合法（双缺或非法 → warn 后 SHALL NOT 注入）。系统 SHALL NOT 为 Chat 新建 `messages`、为 Responses 新建 `input`（不臆造上游 schema；该不对称为有意声明，唯一来源为 `src/service/llm_gateway/placeholder.rs::placeholder_schema_ok` 与 `placeholder_inject_obj`）。

#### Scenario: 三条件齐备注入
- **WHEN** 对话尾请求、脱敏启用、正文含已注册凭据或 PII
- **THEN** 网关将明文替换为占位符后转发上游

#### Scenario: 条件缺失不注入
- **WHEN** 任一条件不满足（如脱敏未启用）
- **THEN** 网关原样转发，不注入占位符

#### Scenario: 容器缺失三协议不对称
- **WHEN** 请求体含 token 但目标容器缺失（Anthropic 缺 `system` / Chat 缺或非数组 `messages` / Responses 双缺 `input` 与 `instructions`）
- **THEN** Anthropic 新建 `system` 容器并注入；Chat 不注入；Responses warn 后不注入；系统 SHALL NOT 新建 `messages`/`input` 容器

### Requirement: WHATWG 缓冲与 slow / fast 双速

流式转发 SHALL 使用 WHATWG 缓冲语义；网关 SHALL 提供两种下游发送语义（`src/service/sse/emit.rs::select_emit`）：`Speed::Slow` 见文即吐（聚合缓冲非空即整段返回），`Speed::Fast` 攒至标点边界（`is_punct_boundary`）或 `FAST_EMIT_THRESHOLD_BYTES`（4096 字节）阈值再返回。二者 SHALL 由 `audit_mode` 派生（`src/handler/llm/pump/spawn/setup.rs`：`AuditMode::Off` → `Speed::Fast`，其余 → `Speed::Slow`），MUST NOT 作为独立配置项暴露。SHALL NOT 声称 `Fast` 服务脱敏完整性——`Fast` 用于审计关闭（无 hold 需求）的低帧数路径，`Slow` 为审计开启时的即时转发路径。

#### Scenario: slow 档低延迟
- **WHEN** `audit_mode` 非 Off（审计开启）
- **THEN** 派生 `Speed::Slow`，聚合缓冲非空即转发（见文即吐），延迟最低

#### Scenario: fast 档聚合转发
- **WHEN** `audit_mode` 为 Off（审计关闭）
- **THEN** 派生 `Speed::Fast`，攒至标点边界或 4096 字节阈值再转发

### Requirement: 审计 hold 与空流 502

审计未决（hold）期间 SHALL 暂存尾部分片不向客户端放行；上游返回空流（零有效分片）SHALL 补最小可解析终止（chat 恒补恰一 `data:[DONE]`；Anthropic 补 `message_start`+`message_stop`；Responses 补恰一 `response.failed` 全序列），SHALL NOT 因空流转 502——502 仅适用于非流式空体或非 JSON 响应（见 README §7.2/§8.6）。空流 SHALL 记审计并落 `truncated_mode` 观测（Chat/Anthropic 记 `open_ended`，Responses 记 `synthesized_failed`）；实现见 `src/service/block_inject/frames.rs::empty_stream_frames_modeled`。

#### Scenario: 审计 hold 暂存
- **WHEN** 审计判定未决
- **THEN** 网关暂存尾部分片，待审计结论后再放行或拒绝

#### Scenario: 空流转 502 且补 DONE
- **WHEN** 上游返回零有效分片
- **THEN** 网关按协议补足最小可解析终止块（chat 恰一 `data:[DONE]`）后按正常流闭合，SHALL NOT 转 502（历史场景名保留为工具锚点；其字面「转 502」已被本 change 废止，正文为准）

### Requirement: 三协议终止闭合（引用 FIX-2）

本 Requirement 口径与本 change 同步修订后的 protocol-compliance-fix spec FIX-2（Anthropic 阻断/真空流/正常结束三态区分）同字：chat 阻断/空流恒以 `data:[DONE]` 恰 1 个收尾；Anthropic **阻断**恒依五件套顺序补 `message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`；Anthropic **真空流**（零有效分片）补最小二帧 `message_start` + `message_stop`（空 content、null `stop_reason`、usage 全 0，不含 `content_block_*`）；Anthropic **正常上游结束** SHALL NOT 合成任何终止帧；responses 阻断补 `response.completed`、截断补 `response.failed`；合成块必须带 `event:` 行。终止后到达的滞后分片 SHALL 被丢弃；重复终止标记 SHALL 去重，不得重复计费。实现落点：`src/service/block_inject/frames.rs::anthropic_block_frames_modeled`（阻断五件套）、`empty_stream_frames_modeled`（真空最小二帧）。

#### Scenario: chat 阻断补 DONE 恰 1 个

- **WHEN** chat 流被审计阻断或上游空流
- **THEN** 网关注入阻断块后恒以 `data:[DONE]` 恰 1 个收尾

#### Scenario: Anthropic 三件套终止

- **WHEN** Anthropic 流被审计阻断或正常结束（二者均非真空流）
- **THEN** 网关 SHALL NOT 注入真空流最小二帧（`message_start`+`message_stop`）：审计阻断路径 SHALL 依五件套恰一收尾，正常结束路径 SHALL 透传原始终端、不合成任何帧；两路径下游均恰收到一个协议正确终止帧，不重试、不挂起

#### Scenario: Anthropic 五件套终止

- **WHEN** Anthropic 流被审计阻断
- **THEN** 网关依五件套顺序补 `message_start` → `content_block_start` → `content_block_stop` → `message_delta`（含 `stop_reason`）→ `message_stop`，首帧为 `message_start`（空 `content`、null `stop_reason`、usage 全 0），合成块带 `event:` 行

#### Scenario: Anthropic 真空流最小二帧

- **WHEN** Anthropic 上游返回零有效分片（真空流）
- **THEN** 网关仅补 `message_start` + `message_stop` 两帧（空 content、null `stop_reason`、usage 全 0，不含 `content_block_*`），SHALL NOT 合成五件套

#### Scenario: Anthropic 正常结束不合成

- **WHEN** Anthropic 上游正常结束（已发 `message_stop` 等终端）
- **THEN** 网关 SHALL NOT 合成任何终止帧，透传原始终端

#### Scenario: responses completed 与 failed 区分

- **WHEN** responses 流被阻断
- **THEN** 网关补 `response.completed`；截断场景补 `response.failed`，两者不得互换，合成块带 `event:` 行

### Requirement: 非流式 usage 与流式同口径捕获

非流式响应 SHALL 与流式口径一致捕获用量：responses 系 SHALL 按三级回退捕获——顶层 `usage` → `response.usage` → `response.response.usage`（流式含 `response.completed` 事件，与 `src/service/llm_gateway/usage.rs::extract_usage_nonstream`/`extract_usage_stream` 共用 `usage_from_paths` 同口径）；Anthropic 系 SHALL 捕获 `message.usage`；用量缺失 SHALL 记缺失计数不断链。

#### Scenario: responses 单层 usage 捕获
- **WHEN** 非流式 responses 响应含 `response.usage`
- **THEN** 网关按流式同口径捕获并计入用量

#### Scenario: responses 顶层与双层回退
- **WHEN** 非流式 responses 响应仅含顶层 `usage` 或双层 `response.response.usage`
- **THEN** 网关按三级回退（顶层 → `response.usage` → `response.response.usage`）命中并计入用量，不因缺单层 `response.usage` 断链

#### Scenario: Anthropic message.usage 捕获
- **WHEN** 非流式 Anthropic 响应含 `message.usage`
- **THEN** 网关按流式同口径捕获并计入用量

### Requirement: 审批 keepalive 句柄 per-request 隔离与 slow / fast 对齐

审批 keepalive 句柄（`src/service/audit/hold.rs::RequestKeepalive`）SHALL 由 per-request 持有，MUST NOT 跨请求共享字段；首包到达前即挂起（首包即挂起）SHALL 同样保活；保活 SHALL 每 10s（`KEEPALIVE_INTERVAL`）下发一次冒号注释行，注释行 SHALL NOT 计入 `sse_event`；该节奏与下游发送语义（`Speed`，由 `audit_mode` 派生，见「WHATWG 缓冲与 slow / fast 双速」）无关，两条发送语义下均一致，SHALL NOT 描述为「双路径 keepalive」。

#### Scenario: keepalive 句柄不跨请求共享
- **WHEN** 多请求并发挂起审批
- **THEN** 各请求持独立 keepalive 句柄，无共享字段串扰

#### Scenario: 首包即挂起亦保活
- **WHEN** 审计在首个上游分片到达前即挂起请求
- **THEN** 网关仍按 10s 节奏下发 keepalive 注释保活连接

#### Scenario: slow 与 fast 注释对齐且不计事件
- **WHEN** `Speed::Slow` 或 `Speed::Fast` 任一下游发送语义下下发 keepalive 注释
- **THEN** 节奏均为 10s，且注释行不计入 `sse_event` 计数

### Requirement: 占位符说明头部注入跨轮字节恒定

占位符说明注入 SHALL 保持头部位置（Chat `messages[0]` / Anthropic `system` / Responses `input|instructions`），MUST NOT 改为尾部注入（尾部注入会改变提示语义并削弱指令遵循）。当 `PII_SCOPE_MODE=conversation` 且会话键稳定时，同一会话两轮的注入前缀 SHALL 字节一致（依赖 token 跨轮稳定 + 注入位置稳定）。**已声明边界（`R5-11`）**：注入仅在脱敏后请求体仍含占位符 token 时发生（`src/handler/llm/rewrite.rs` 经 `src/service/llm_gateway/placeholder.rs::has_placeholder_tokens` 判定），故「同一会话两轮前缀字节一致」仅对**两轮均含 token**成立；token 首次出现的那一轮 SHALL 允许头部新增说明、其前缀字节较前一轮增长（属合法增长，非缓存失稳缺陷）。既有幂等守卫（已含说明不重复前插，返回原字节）SHALL 不变。

#### Scenario: 头部注入位置不变

- **WHEN** 占位符说明被注入
- **THEN** 位置为头部（`messages[0]`/`system`/`input|instructions`），非尾部

#### Scenario: 会话内注入前缀字节一致

- **WHEN** 同一会话键的两轮请求均含需注入的 token
- **THEN** 两轮注入前缀字节一致（逐字节相等）

#### Scenario: token 首次出现那轮允许前缀增长

- **WHEN** 同一会话键的前一轮请求无 token、后一轮首次出现 token
- **THEN** 后一轮头部新增说明文案，其前缀字节较前一轮增长（已声明边界，不视为缓存失稳缺陷）

#### Scenario: 幂等不重复前插

- **WHEN** 目标位置已含说明
- **THEN** 不再重复前插，返回原字节（既有幂等语义不变）

### Requirement: 空体 502 四分支一致性

空响应与错误透传 SHALL 按四分支执行：流式空流（零有效分片）SHALL 补最小可解析终止帧后按正常流闭合，SHALL NOT 转 502；非流式空体/非 JSON SHALL 转 502；上游 `502`/`401` SHALL 原样透传不改写；非对话尾 SHALL 豁免（原样透传不转 502）。流式空流的终止帧 SHALL 为 Chat 恰一 `data: [DONE]`、Anthropic `message_start`+`message_stop`、Responses 恰一 `response.failed`（实现见 `src/service/block_inject/frames.rs::empty_stream_frames_modeled` 与 README §8.6）；502 SHALL 仅适用于非流式空体/非 JSON（唯一入口 `src/service/llm_gateway/mod.rs::classify_empty` 的 `NonStreamTo502`），流式空流 SHALL NOT 转 502。

#### Scenario: 流式空流注入转 502
- **WHEN** 上游返回零有效分片的流
- **THEN** 网关按协议补最小可解析终止块（Chat 恰一 `data: [DONE]`、Anthropic `message_start`+`message_stop`、Responses 恰一 `response.failed`）后按正常流闭合并记审计，SHALL NOT 转 502（历史场景名保留为工具锚点；其字面「转 502」已被本 change 废止，正文为准）

#### Scenario: 非流式空体非 JSON 转 502
- **WHEN** 非流式上游返回空体或非 JSON
- **THEN** 网关转为 502，不透传空体

#### Scenario: 502 与 401 透传
- **WHEN** 上游返回 `502`/`401`
- **THEN** 网关原样透传状态码与包体，不改写

#### Scenario: 非对话豁免
- **WHEN** 空响应来自非对话尾路径
- **THEN** 网关原样透传，不转 502，不计对话用量

### Requirement: 截断三态（唯一值）

流截断/终止状态 SHALL 仅为以下四态之一：`silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error`。其中 `synthesized_failed` 仅 responses 可用（协议适用范围口径不变）；`upstream_error` 用于「上游错误载荷帧即终端」的观测（带顶层 `error` 且无 `choices` 的帧）。网关 SHALL 在 `stream_meta.truncated_mode` 记录该值并落 metrics（截断计数按 mode 分标签）。四态之外的值 SHALL NOT 落该指标。本 spec 不得使用 `complete` / `truncated` / `aborted` 旧三态命名。

命名残余声明（名称与正文口径不一致的显式接受）：本 requirement 名中的「三态」为历史命名锚点，canonical `openspec/specs/docs-test-parity/spec.md` 与 docs-test-parity delta 均按该名互引，故本 change SHALL NOT 将其重命名为「四态」；正文白名单实为四态，口径一律以正文四态为准，名称与正文的差异属已接受命名残余（不改名以维持跨 spec 互引稳定）。

「唯一值」口径 SHALL 端到端一致：四态白名单 SHALL 在所有落点全量齐备，SHALL NOT 任一落点仅覆盖其中三态而把 `upstream_error` 归入 `other`/丢弃桶。至少以下四类落点 SHALL 四态齐备（`N`，`veil-audit-r4-remediation`）：

1. **进程内固定键计数**：`src/service/llm_gateway/metrics.rs::TRUNCATED_MODE_KEYS` SHALL 为长度 4 的键数组，派生 `KeyedCounters` 容量同步为 4；`upstream_error` 调用 SHALL 命中具名键递增，SHALL NOT 落 `other` 桶，SHALL NOT 触发未知键 warn（`src/service/llm_gateway/metrics.rs::KeyedCounters` 的未知键路径）。
2. **落盘合法性白名单与聚合**：`src/service/metrics/aggregate.rs::TRUNCATED_MODES` SHALL 为长度 4；`src/service/metrics/store.rs::MetricsStore::record_chat_extended` SHALL NOT 对 `upstream_error` 走「非法值不落指标」分支或记该 warn；`WindowAgg` 截断列与聚合落标签分支（`src/service/metrics/aggregate.rs::WindowAgg`、`src/service/metrics/store.rs` 聚合落标签分支）SHALL 各含 `upstream_error` 独立槽。
3. **持久化与快照/时序**：`src/service/metrics/aggregate.rs::MetricsSnapshot` 与 `src/service/metrics/aggregate.rs::SeriesPoint` 的截断字段、`src/service/metrics/aggregate.rs::snapshot` 环标签分支、`src/service/metrics/store.rs` 的 SQL 表列/UPSERT 与 `src/service/metrics/aggregate.rs` 的读取/回填与派生 SQL 的稳定列序。持久化 SHALL 采用加列式（见 canonical `observability-admin`「truncated_mode 三态落 metrics 分标签计数」）。每个状态 SHALL 只递增自身列/标签，SHALL NOT 借其他状态的列承载。
4. **管理面导出**：`/_admin/metrics` 的 `truncated` 对象（`src/handler/admin.rs` 的 `truncated` 对象）SHALL 含四态标签，SHALL NOT 仅导出三态而令 `upstream_error` 不可见。

每个状态 SHALL 使「自身标签计数」递增（进程内计数与持久化列各自独立），SHALL NOT 计入其他状态的标签。

#### Scenario: silent_discard 静默丢弃

- **WHEN** 超限尾部命中静默丢弃策略
- **THEN** `stream_meta.truncated_mode=silent_discard` 并记 metrics

#### Scenario: open_ended 保持开放

- **WHEN** 流保持开放等待后续
- **THEN** `stream_meta.truncated_mode=open_ended` 并记 metrics

#### Scenario: synthesized_failed 仅 responses

- **WHEN** responses 流需合成失败终止
- **THEN** `stream_meta.truncated_mode=synthesized_failed` 并记 metrics；chat 与 Anthropic 不得取该值

#### Scenario: upstream_error 上游错误终端

- **WHEN** 带顶层 `error` 且无 `choices` 的 Chat 错误载荷帧被判定为终端
- **THEN** `stream_meta.truncated_mode=upstream_error` 并记 metrics，区别于 `open_ended`

#### Scenario: 四态白名单唯一

- **WHEN** 检查 `stream_meta.truncated_mode` 的合法取值集
- **THEN** 仅 `silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error` 四态；四态之外的值 SHALL NOT 落该指标

#### Scenario: upstream_error 命中具名键不落 other

- **WHEN** 以 `upstream_error` 调用进程内截断计数（`record_truncated("upstream_error")`）
- **THEN** `upstream_error` 具名键计数递增为 1，`other` 桶保持 0，未知键 warn 不触发（`upstream_error` 已在 `TRUNCATED_MODE_KEYS` 白名单内）

#### Scenario: upstream_error 落盘与导出各标签独立

- **WHEN** 一次 `upstream_error` 截断经 `record_chat_extended` 记录并刷盘、快照与 `/_admin/series` 查询
- **THEN** 持久化 `upstream_error` 独立列、快照 `truncated.upstream_error`（`/_admin/metrics`）与 series 对应字段各自递增 1；`silent_discard`/`open_ended`/`synthesized_failed` 三者不受影响；不产生「truncated_mode 非法值不落指标」warn

#### Scenario: 四态各自独立计数

- **WHEN** 依次以四种 mode 各记录一次截断
- **THEN** 四枚标签各自为 1、互不串计；四态之外的值四枚标签均不递增并记告警
