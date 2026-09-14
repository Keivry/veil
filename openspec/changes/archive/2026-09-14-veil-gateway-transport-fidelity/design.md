## Context

独立六维审查（2026-09-14，C3 LLM 网关传输面）确认 7 项传输保真偏差（见 proposal Why 与覆盖表）。现状真相源：

- SSE 出口仅重放 `event:`，丢 `id`/`retry`：解析侧已捕获（`src/service/sse/parser.rs:248-255`），出口 `src/handler/llm/pump/spawn.rs:559-563`（JSON 分支）与 `:607-611`（非 JSON 分支）只拼 `event: {type}`；`event:`/`data:` 分块时解析块分发按块独立，配对丢失（`parser.rs:227-265 dispatch_block`）。Python 对照 `_llm.py:5285-5318` 暂存 `event`/`id` 与 `data` 同块写出、`retry` 直通。
- Anthropic 会话/模型缺失：`extract_conv_id`（`src/service/llm_gateway/tool.rs:580-620`）分支仅覆盖顶层 `id`、`response.id`、`data.id`、`error.id`，无 `message.id`；流泵模型仅读顶层 `v.get("model")`（`src/handler/llm/pump/spawn.rs:198-202`）。Python `_llm.py:350-368` 提取 `data['message']['id']`。
- Responses error 形态：`responses_error_object`（`src/handler/llm/pump/event.rs:138-161`）仅读嵌套 `error` 对象；官方 `ResponseErrorEvent` 字段在顶层（`openai/types/responses/response_error_event.py`：`code`/`message`/`param`/`sequence_number`/`type`）。
- 透传无界读与头泄漏：`src/handler/llm/dispatch.rs:328` `up.bytes().await` 全量读，超限判定 `:329`；`:318-326` 拷贝全部上游头，`:332-337` hop 过滤不含 `x-veil-*`。
- `stream_options` 三态：`should_inject_stream_options`（`src/service/llm_gateway/protocol.rs:149-156`）非对象返回 `true`；`inject_stream_options`（`:159-178`）整体替换非对象。
- Anthropic 阻断帧与参数污染：`anthropic_block_frames`（`src/service/block_inject/frames.rs:40-48`）硬编码 `index:0`；fragments `input` 分支（`src/handler/llm/pump/fragments.rs:155-174`）+ `normalize_tool_args_with`（`src/service/llm_gateway/tool.rs:21-38`）把 `input:{}` 序列化为 `"{}"` 再与 `partial_json` 拼接。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 README；不新增依赖；不碰协议终端语义与审计 verdict。

## Goals / Non-Goals

**Goals：**

- 给出 `TRN-1`–`TRN-7` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「SSE 出口信封保真」「Anthropic 会话/模型提取」「Responses error 双形态」「透传有界读与内部头隔离」「`stream_options` 三态」「阻断帧真实 index 与参数清洁」收敛为 spec 契约，README §7.2 与行为同批同步。
- 固化 `TRN-2` 的形态支持口径与 `TRN-3` 的超限行为、`TRN-5` 的三态语义，消除静默改写与内存放大面。

**Non-Goals：**

- 不改协议终端语义与 `truncated_mode` 口径（属既有 `veil-stream-fidelity-fix`）、不改 usage `max` 口径、不改审计 verdict 与脱敏 recognizer。
- 不把透传改造为 `Body::from_stream` 全流式转发（见 D4 备选）。
- 不改 hop 头集与解码配对语义（README §7.1），仅新增 `x-veil-*` 出口剔除。
- 不改 `src/` 实现与 README（本 change 只交付规划）；不提交 commit。

## Decisions

### D1：SSE 出口信封三要素保真（`TRN-1`）

**决策**：出口信封在保留既有 `event:` 重放基础上，补齐两项——① 从 `SseEvent.id`/`SseEvent.retry` 透出 `id:`/`retry:` 行（`retry` 仅在合法整数值透出，与解析侧口径一致）；② 跨块配对：当块分发产生「有 `event` 无 `data`」的事件时，将 `event` 压入 FIFO 暂存、将 `id` 记为最近值（WHATWG last-event-id 语义），下一含 `data` 的块在出口重建为「`event:`+`id:`（最近值）+`data:`」同块；`retry` 随其所在块透出。上游正常同块事件不受影响。**计数保真**：暂存只在出口块重建，不额外产生或吞并事件——`SseEvent` 计数（`src/service/sse/parser.rs:263 sse_event_count`）与出口转发帧计数（`src/handler/llm/pump/spawn.rs:647 metrics.add_sse_event()` 与 `forwarded`）对分块信封流须与同内容非分块流逐一致（审计与 metrics 语义不变）。

**理由**：解析侧已保留字段而出口丢字段属实现缺口（非设计取舍）；`id` 的 WHATWG 语义是「最近一次出现的 id 对后续事件持续有效」，故为最近值而非 FIFO；`event` 是块级字段，跨块暂存须 FIFO 配对（对齐 Python `slow_event_pending` 与 `_llm.py:5285-5318`）。若让 `event:` 成为孤立块，下游严格 SSE/JSON 解析按块读取会产生空 data 或 JSONDecodeError（Python 注释明确此动机）。

**备选**：仅透出 `id`/`retry`、不处理跨块 event——`event:` 孤立块缺陷保留，不采用；把 `event` 也按最近值持久化——与 WHATWG 块级语义不符且可能错配，不采用。

### D2：Anthropic `message_start` 会话与模型提取（`TRN-7`）

**决策**：`extract_conv_id` 在既有分支之后新增 `data["message"]["id"]`（非空字符串）分支；流泵（`spawn.rs:198-202`）模型提取扩展为 `v.get("model")` 优先、回退 `v["message"]["model"]`。提取值注入既有 `conv_id`/`stream_first_id` 与审计/metrics 分桶路径，不新增旁路。

**理由**：Anthropic `message_start` 的唯一 id/model 位于 `message` 嵌套对象（`{"type":"message_start","message":{"id":"msg_...","model":"claude-...",...}}`），顶层恒无；缺失导致会话关联丢失与 `unknown_model` 分桶。Python 已按 `message.id` 提取，属 parity 缺口。回退而非替换保证 Responses/Chat 现有顶层形态不回退。

**备选**：只改 `extract_conv_id` 不改模型提取——`unknown_model` 缺陷保留，不采用；把 `message.model` 提取放到 metrics 层——审计关联与分桶两处需同源，集中在流泵提取更一致，不采用。

### D3：Responses error 双形态与 `sequence_number`（`TRN-2`）

**决策**：`responses_error_object` 改为「合并来源」：先取嵌套 `error` 对象内 `type`/`code`/`param`/`message`（既有形态），再取顶层 `code`/`param`/`message`（缺失才补，顶层优先用于官方形态），并复用既有 `extract_responses_seq`（`event.rs`）读取顶层 `sequence_number`（整数）作为返回值的一部分。签名由 `Option<Value>` 扩展为可同时返回 `sequence_number`（如 `Option<(Value, Option<u64>)>` 或等价结构）；合成 `response.failed` 时把 `sequence_number` 置于事件载荷顶层（与官方 `ResponseErrorEvent` 对齐）。无 `message` 时维持既有回退形态；顶层/嵌套均无有效字段时不产生空噪声。

**理由**：官方 SDK 将 `code`/`message`/`param`/`sequence_number` 定义在顶层，既有实现只认嵌套，官方形态下 code/param 丢失；`sequence_number` 对下游断序诊断有信息价值（README §7.2 已有断序容忍条款）。合并而非互斥保证两形态都不断链。此前 README §7.2 的「`type/code/param/message` 四字段 lossy 边界」需随本 change 扩展为「含官方顶层形态 + `sequence_number`」。

**备选**：只支持官方顶层、弃嵌套——既有上游/测试回退风险，不采用；`sequence_number` 仅入日志不进合成帧——下游诊断缺失，不采用。

### D4：透传有界读与超限行为（`TRN-3`）

**决策**：`stream_upstream_passthrough` 读取改为两段，且**超限 502 仅作用于非错误状态**——① 若 `status < 400` 且上游带 `content-length` 值 `> NONSTREAM_MAX_BYTES`，直接返回 502 `response_too_large`，不读 body；② 否则以 `up.chunk()` 循环读取至多 `NONSTREAM_MAX_BYTES + 1` 字节并**按状态分流**：`status < 400` 累计严格超 `NONSTREAM_MAX_BYTES` 即 502 `response_too_large`；`status >= 400`（4xx/5xx 错误体）**不进入 502 分支**，按错误体透传语义保持上游状态码与正文字节（有界读/计数仅为内存安全，不改写状态或正文），与 README §4「错误体按透传语义不改写」及非流 `oversize_response`（仅 `status < 400` 严格超限）口径一致。上限内行为与现状一致（保状态、保正文字节、hop 过滤 + 自置 `x-veil-*`）。

**理由**：无界 `bytes()` 对错误体/异常大体可致内存放大；先判 `content-length` 是零拷贝短路，`+1` 读取用于精确判定「严格超限」（`len == cap` 放行，与非流 `oversize_response` 口径一致）。但 `status>=400` 的错误体在 README §4 已声明「按透传语义不改写」，把它改写成 502 会同时违反 README §4 与非流口径，故超限 502 严格限定在非错误状态——保留现状 `dispatch.rs:329` 的 `status_u16 < 400` 门，只把门内的无界 `bytes()` 换成有界读。

**备选**：`Body::from_stream` 全流式转发（不缓冲）——内存最优但需改函数返回类型与下游流式错误处理，超出本 change 最小面，另立 change；错误状态超限一律 502——与 README §4 透传声明冲突且与非流口径分裂，不采用。

### D5：内部响应头隔离（`TRN-4`）

**决策**：在 `stream_upstream_passthrough` 拷贝上游头时（`dispatch.rs:318-326`）剔除名称以 `x-veil-` 开头（ASCII 大小写不敏感）的头；网关自置的 `x-veil-protocol`/`x-veil-normalized` 在剔除后写入，不被上游同名覆盖。

**理由**：`x-veil-*` 是网关内部命名空间（协议标注/归一化标注），上游不可信；原样透传会让上游伪造内部语义或注入调试信息。hop 过滤只管逐跳头，不管内部命名空间，需独立剔除。**现状核对**：非流对话路径已剔除——`src/handler/llm/nonstream.rs:405-409 snapshot_downstream_headers` 已剥 `x-veil-*`，随后由 `build_downstream_response` 覆盖写入网关自置头；故本 finding 仅存于流式透传路径（`src/handler/llm/dispatch.rs`）与 NonDialog 透传臂（`serve_nondialog_passthrough`/`passthrough_upstream_response`，`nonstream.rs:321-343` 仅做 hop 过滤、**未**剥 `x-veil-*`）。本 change 范围锁定流式透传路径（finding 证据面），NonDialog 臂如需一致另立任务。

**备选**：加入 hop 头集统一过滤——hop 语义是 RFC 逐跳头，混入内部头会污染定义与既有计数指标，不采用。

### D6：`stream_options` 三态保留（`TRN-5`）

**决策**：`should_inject_stream_options` 区分三态：键缺失（`None`）→ `true`；`null` → `false`（不注入）；对象缺 `include_usage` → `true`；对象含 `include_usage` → `false`。`inject_stream_options` 相应：仅当键缺失或对象形态合并时写入，`null` 保留 `null` 不动；非对象非 `null`（畸形）维持既有 warn + 整体替换。

**理由**：`null` 是用户显式传入的第三态（非「缺失」），整体替换为非最小改写且改变语义；对齐 Python `setdefault` 仅处理缺失/对象合并、不覆写显式值。畸形值（字符串/数组）无合法语义，保留 fail-safe 整体替换 + warn（不静默丢键）。

**备选**：`null` 按畸形整体替换（现状）——非最小改写，不采用；`null` 视为缺失注入——同样改变显式三态语义，不采用。

### D7：Anthropic 阻断帧真实 index 与参数累积清洁（`TRN-6`）

**决策**：① `anthropic_block_frames` 增 `index` 入参（真实 content block index），`content_block_start`/`content_block_stop` 使用该 index；调用点从触发阻断的事件解析 index（复用 `event.rs` 既有 `outer_event_index`：Anthropic `v["index"]`），无法解析才回退 `0`。② fragments 的 Anthropic 参数累积：`content_block_start` 的空占位 `input`（空对象/空串/null）不作为 args_delta 累积；非空完整 `input`（非流式形态）仍可作为一次性种子；`partial_json` 正常累积。

**理由**：`index:0` 硬编码使多块流中阻断帧指向错误块，严格 SDK 按 index 拼接会错位；`input:{}` 是流式块开始的占位符，把它当增量会使审计参数前缀污染为 `"{}{...}"`（`normalize_tool_args_with` 把空对象序列化为 `"{}"`），污染审计判定输入。

**备选**：阻断帧 index 保持 0——多块流错位缺陷保留，不采用；参数侧改为整帧替换而非累积——破坏流式增量语义，不采用。

## Risks / Trade-offs

- [`TRN-1` 跨块暂存延迟/错配] → 仅暂存 `event`/`id` 元数据（有界、无内容），FIFO 与最近值语义明确；流末未配对 `event` 按既有残余处理不外泄内容。回归覆盖分块顺序。
- [`TRN-7` 提取分支扩展] → 仅在既有分支后追加，顶层形态优先不回退；补 Chat/Responses 既有用例防回归。
- [`TRN-2` 签名变化] → `responses_error_object` 返回值扩展需同步其调用点（`spawn.rs` 合成路径）与既有测试；`sequence_number` 缺失时不写，不断链。
- [`TRN-3` 有界读] → 超限 502 仅限非错误状态（`status < 400`），与现状 `dispatch.rs:329` 门及非流 `oversize_response` 一致，无对外语义变化；`status >= 400` 错误体保持透传不改写（README §4），本次仅消除无界缓冲内存放大。
- [`TRN-4` 头剔除] → 仅剔 `x-veil-*`，不影响普通业务头；补注入用例锁定。
- [`TRN-5` `null` 保留] → 下游若不识别 `null` 可能回退默认，但这是用户显式传值，保留即尊重原义；README §7.2/§7.7 同步。
- [`TRN-6` index 传递] → 调用点解析失败回退 `0` 与现状一致；参数清洁只影响空占位，非空 `input` 行为不变。

## Migration Plan

1. 按 tasks 顺序落地：先出口/提取（`TRN-1`/`TRN-7`），再 Responses 形态（`TRN-2`），再透传内存与头（`TRN-3`/`TRN-4`），再 `stream_options`（`TRN-5`），最后阻断帧/参数（`TRN-6`）。
2. 每组独立 `cargo test`；README §7.2 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；下游可感知的行为变化（`id`/`retry`/跨块 `event` 保真、Responses error 字段更全、`x-veil-*` 不再泄漏、`stream_options:null` 保留；透传路径**仅非错误（`status<400`）超限**走 502 `response_too_large`，`status>=400` 错误体仍透传不改写）由 README §7.2 声明。

## Open Questions

- 无。`TRN-1`–`TRN-7` 均已裁定。若 apply 阶段实测某上游 `content-length` 缺失且 chunk 持续流式超限，以 spec「流式上游错误透传有界读」Scenario 为准（读满 `max+1` 即 502）；若严格 SDK 对 Anthropic 阻断帧序列的 index 有额外约束，回到本 design 记录差异并补帧。
