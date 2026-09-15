## Why

独立六维审查（2026-09-14，C3 LLM 网关传输面）确认 7 项传输保真偏差（TRN-1–TRN-7），其中 3 项 P1、4 项 P2，违反既有 spec/README 声明或官方流式契约：

- **`TRN-1`（P1）SSE 出口丢 `id:`/`retry:` 与跨块 `event:` 配对**：解析侧已捕获 `id`/`retry`（`src/service/sse/parser.rs:248-255`），但出口信封重建时仅重放 `event: {type}`，丢弃 `id`/`retry`（`src/handler/llm/pump/spawn/event_loop.rs:50-62`，非 JSON 分支 `:607-611` 同）；`event:` 与 `data:` 被上游分块/空行隔开时配对丢失。Python 对照 `_llm.py:5285-5318` 将 `event`/`id` FIFO 暂存后与 `data` 同块写出、`retry` 直通。
- **`TRN-7`（P1）Anthropic 流式 `message.id`/`message.model` 未提取**：`extract_conv_id` 不识别 `message.id` 嵌套形态（`src/service/llm_gateway/tool.rs:580-620`），模型仅读顶层 `model`（`src/handler/llm/pump/event.rs:175-181`）；`message_start`（`{"message":{"id","model",...}}`）下会话关联缺失、model 分桶恒 `unknown_model`。Python 对照 `_llm.py:350-368` 提取 `data['message']['id']`。
- **`TRN-2`（P1）Responses `type:"error"` 合成帧丢 `code`/`param`（且缺 `sequence_number`）**：`responses_error_object` 仅读嵌套 `error` 对象（`src/handler/llm/pump/event.rs:138-161`）；官方 `ResponseErrorEvent`（`openai/types/responses/response_error_event.py`）的 `code`/`message`/`param`/`sequence_number` 均在**顶层**，故官方形态下 code/param 丢失、sequence_number 从未透出。
- **`TRN-3`（P2）`stream_upstream_passthrough` 无界读**：`up.bytes().await` 先全量读 body 再判超限（`src/handler/llm/dispatch.rs:328`，判定 `:329`），错误体/异常大体可致内存放大。
- **`TRN-4`（P2）透传未剔上游 `x-veil-*` 响应头**：`src/handler/llm/dispatch.rs:318-349` 原样拷贝全部上游响应头并仅做 hop 过滤，上游注入的 `x-veil-*` 会泄漏到下游。
- **`TRN-5`（P2）`stream_options:null` 被替换**：`should_inject_stream_options` 对非对象（含 `null`）返回 `true`（`src/service/llm_gateway/protocol.rs:149-156`），`inject_stream_options` 将非对象整体替换为 `{"include_usage":true}`（`:159-178`），非最小改写且改变三态语义。
- **`TRN-6`（P2）Anthropic 阻断帧 `index:0` 硬编码 + `content_block_start.input:{}` 污染审计参数**：阻断帧恒 `index:0`（`src/service/block_inject/frames.rs:40-48`）；fragments 将 `content_block_start` 的 `input:{}` 当作 args_delta（`src/service/llm_gateway/tool.rs:390-404`），经 `normalize_tool_args_with` 序列化为 `"{}"`（`src/service/llm_gateway/tool.rs:21-38`），与后续 `partial_json` 拼接成 `"{}{...}"` 污染审计参数。

真相源为上述 `src/` 文件、`README.md` §7.1/§7.2 与官方 SDK 契约。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 README；实现与文档同步留待 apply 阶段。

引用规范：WHATWG SSE（`event`/`data`/`id`/`retry` 字段语义与 last-event-id 持久化）；OpenAI Responses 流式 `error` 事件（`ResponseErrorEvent` 顶层 `code`/`message`/`param`/`sequence_number`）；Anthropic Messages 流式（`message_start.message.id`/`message_start.message.model`）；OpenAI Chat Completions `stream_options`（`include_usage` 合并语义）。

## What Changes

- **`TRN-1` SSE 出口信封保真**：解析保留的 `id`/`retry` 在出口同块重放；跨块 `event:`/`id:` 按 WHATWG 与 Python 口径暂存——`event` FIFO 配对后续 `data`、`id` 取最近值持久化、`retry` 随所在块透传；暂存仅在出口块重建，**不改变既有事件/帧计数语义**（`sse_event_count` 与出口转发帧计数，审计与 metrics）；补 `id:`/`retry:` 直通、`event:`/`data:` 跨块配对与分块流计数不变回归。
- **`TRN-7` Anthropic 会话/模型提取**：`extract_conv_id` 增 `message.id` 嵌套分支；流泵提取 `message_start.message.model` 供审计与 model 分桶；补 `message_start` 后 conv/model 正确落审计/分桶回归。
- **`TRN-2` Responses error 双形态兼容**：`responses_error_object` 同时接受官方顶层形态与既有嵌套形态，合并 `code`/`message`/`param`，并在可得时把 `sequence_number` 带出到合成 `response.failed`；补官方形态 error 帧 code/param/sequence_number 保留回归。
- **`TRN-3` 透传有界读**：`stream_upstream_passthrough` 先判 `content-length`、再按 `max_bytes + 1` 有界读，不再全量缓冲；超限 502 `response_too_large` **仅适用于非错误状态（`status < 400`）**，错误状态（`status >= 400`）保持错误体透传语义——有界读仅为内存安全，**不改写上游状态/正文为 502**（与 README §4「错误体按透传语义不改写」同字）；补超大 body 受上限约束不 OOM 回归与 4xx/5xx 超限仍透传回归。
- **`TRN-4` 内部响应头剥离**：透传前剔除/覆盖上游 `x-veil-*` 内部头（大小写不敏感），网关自置的 `x-veil-protocol`/`x-veil-normalized` 不被上游覆盖；补上游注入 `x-veil-*` 不泄漏回归。
- **`TRN-5` `stream_options` 三态保留**：缺失→注入、`null`→原样保留不注入、对象→仅缺 `include_usage` 时按 key 合并注入、含 `include_usage`→保留；补三态矩阵回归。
- **`TRN-6` Anthropic 阻断帧 index 与参数清洁**：阻断帧使用真实 block index（未知才回退 0）；`content_block_start` 的空 `input:{}` 占位不得进入参数累积，消除 `"{}{..."`；补多 index 阻断与审计参数无前缀回归。
- **文档同步**：README §7.2（SSE 信封声明、Responses error 形态与 `sequence_number`、透传有界读与内部头剥离、`stream_options` 三态）与修复后行为同批更新。

## Capabilities

### New Capabilities

- `gateway-transport-fidelity`：LLM 网关传输面保真契约——SSE 出口信封（`id`/`retry`/跨块 `event`）、Anthropic `message_start` 会话与模型提取、Responses `error` 双形态与 `sequence_number`、流式上游错误透传有界读与内部头剥离、`stream_options` 三态、Anthropic 阻断帧真实 index 与参数累积清洁。

### Modified Capabilities

- 无。本 change 新增 capability；既有 `openspec/specs/stream-protocol-parity/spec.md`、`openspec/specs/transport-fidelity-fix/spec.md`、`openspec/specs/llm-streaming-parity/spec.md` 等契约中与本 spec 冲突的旧口径（Responses 失败帧诊断字段 lossy 边界、透传无界读、`stream_options` 非对象替换）在 apply 阶段按 `openspec/changes/veil-gateway-transport-fidelity/specs/gateway-transport-fidelity/spec.md` 为准同步并在归档时随 canonical 修订，不作为本 change 的 MODIFIED delta。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `TRN-1` | P1 | 出口同块重放 `id`/`retry`；跨块 `event`/`id` 暂存配对（`event` FIFO、`id` 最近值持久化）；分块暂存不改事件/帧计数（审计+metrics）；`id:`/`retry:` 直通与跨块配对回归 | 1.1、1.2、1.3、1.4 |
| `TRN-7` | P1 | `extract_conv_id` 增 `message.id`；流泵提取 `message.message.model` 注入审计/分桶；`message_start` 后 conv/model 回归 | 2.1、2.2 |
| `TRN-2` | P1 | `responses_error_object` 兼容顶层与嵌套、合并 `code`/`message`/`param`、透出 `sequence_number`；官方形态回归 | 3.1、3.2 |
| `TRN-3` | P2 | 先判 `content-length` 再按 `max_bytes + 1` 有界读；仅非错误（`status<400`）超限 502 `response_too_large`，`status>=400` 超限仍透传不改写；大 body 不 OOM 与 4xx/5xx 超限透传回归 | 4.1、4.2 |
| `TRN-4` | P2 | 透传前剔上游 `x-veil-*`（大小写不敏感），网关自置头不被覆盖；注入不泄漏回归 | 5.1、5.2 |
| `TRN-5` | P2 | `stream_options` 三态：缺失注入 / `null` 保留 / 对象合并 / 含 `include_usage` 保留；三态矩阵回归 | 6.1、6.2 |
| `TRN-6` | P2 | 阻断帧用真实 block index；`content_block_start.input:{}` 不进参数累积；多 index 与 `{}{` 前缀回归 | 7.1、7.2、7.3 |
| — | 文档 | README §7.2 同步 SSE 信封、error 形态、透传有界读与内部头、`stream_options` 三态 | 8.1、8.2 |

## Non-Goals（显式）

- **不迁移/不改协议语义**：不新增协议、不改 Chat/Anthropic/Responses 的终端语义与 `truncated_mode` 口径（属既有 `veil-stream-fidelity-fix`）、不改 usage `max` 口径、不改审计 verdict 与脱敏 recognizer。
- **不重构透传为全流式转发**：`TRN-3` 采「先判长度 + 有界读」的最小方案，不引入 `Body::from_stream` 全流式改造（若后续需真流式另立 change）。
- **不改 `TRN-4` 之外的头策略**：hop 头集与解码配对语义（README §7.1）不变，仅新增内部 `x-veil-*` 出口剔除。
- **不改 `src/`、`tests/` 与 README**：本 change 只交付规划 artifacts，实现与文档改动留待 apply 阶段；不改 `openspec/changes/` 内既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-gateway-transport-fidelity/proposal.md`、`design.md`、`specs/gateway-transport-fidelity/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`src/service/sse/parser.rs`、`src/handler/llm/pump/spawn.rs`、`src/service/llm_gateway/tool.rs`、`src/handler/llm/pump/event.rs`、`src/handler/llm/dispatch.rs`、`src/service/llm_gateway/protocol.rs`、`src/service/block_inject/frames.rs`、`src/handler/llm/pump/fragments.rs`、对应单测与 e2e、`README.md` §7.2。
- **影响系统**：SSE 出口字节保真、Anthropic 会话关联与 model 分桶、Responses 错误诊断字段、流式错误透传内存边界、下游内部头隔离、Chat 请求最小改写。
- **依赖**：无新依赖；仅既有 `serde_json`、`axum`、`reqwest`、`tokio` 与测试设施。
