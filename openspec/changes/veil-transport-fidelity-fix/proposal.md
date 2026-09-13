## Why

独立审计（2026-09-13，传输保真维）在 LLM 网关入站/出站路径确认 14 项待收敛偏差（`T1`-`T14`），均违反既有契约、官方 API 语义或 README 声明：

- **入站请求保真**：`T1` 入站 query string 未转发上游——`src/handler/llm/dispatch.rs:62` 取 `parts.uri.path()`，URL 拼接只用 path，`GET /v1/models?limit=10`、Azure `?api-version=` 静默丢失，与 README §5「任意 `/{tail}` 透传」矛盾。
- **出站响应保真**：`T2` 非流对话路径丢弃上游全部响应头（`src/handler/llm/nonstream.rs:253` 的 `(StatusCode, String).into_response()` 被 axum 强制 `text/plain; charset=utf-8`、`:275-277` 的字节体被强制 `application/octet-stream`），`content-type`/`Retry-After`/`x-request-id`/rate-limit 头全丢；`T6` 非流还原用字节级 `restore_response_with_spans`（`:231`）而流式用 JSON 转义变体（`src/service/redaction/scope.rs:194`、`src/handler/llm/pump/spawn.rs:496`），vault 明文含 `"`/`\` 时写破 JSON 后整响应回退未还原原文；`T10` 错误/超限/空体响应缺 `x-veil-protocol`（仅 JSON 后处理分支置位）。
- **超时与容量边界**：`T3` 共享 client 的 30s 总超时（`src/state.rs:154`）经 reqwest `TotalTimeoutBody` 覆盖整个响应体读取（含流式），长流被截断；非流重试每次重置 30s（`src/service/llm_gateway/mod.rs:207-245`，最坏 ~123s，与 README 声明不符）；`T4` `NONSTREAM_MAX_BYTES` 非内存边界——`src/handler/llm/nonstream.rs:148` 先 `up.bytes()` 全量读入、`:156` 才判长，超限判定无内存保护（可 OOM）。
- **协议识别**：`T5` 宽容尾缀吞掉官方子路径（`src/service/llm_gateway/protocol.rs:54-78`）：`/v1/messages/count_tokens` 判 Anthropic、`GET /v1/responses/{id}` 判 Responses，触发改写/注入/审计，甚至以合成阻断体取代原响应对象；`/v1/messages/batches`、`/v1/responses/{id}/cancel`、`/input_items` 同类。
- **审计与用量口径**：`T7` Anthropic 流式 `total_tokens` 跨事件低估（`src/service/llm_gateway/usage.rs:71-75` 按单事件派生 total、`:92-103` 再对派生值取 max，`start{in:100,out:1}` + `delta{out:50}` 得 101 而非 150）；`T11` `web_search_call` 审计字段疑漏（`src/service/llm_gateway/tool.rs:109-130` 只读顶层 `queries/query`，官方条目疑为 `action:{type:"search",query}`）；`T8` skip 分段后不递归 stringified JSON（`src/service/redaction/scope.rs:293-318`），工具参数内新 PII 漏检。
- **重试与判序**：`T13` 重试分类过窄（`src/service/llm_gateway/mod.rs:228-237` 仅 `is_connect/is_timeout` 退避），其余 `Err`（解码/行中 reset 等拿头前瞬断）直接 502，弱于 Python 对 `ServerDisconnectedError`/`ClientConnectionError` 统一退避 3 次；`T14` 非流超限/空体判定顺序与 Python 差异未文档化（`src/handler/llm/nonstream.rs:155-158` 对 `status<400` 判超限）。
- **记录与转出**：`T9` NonDialog `NonstreamOutcome::Stream` 死臂（`src/handler/llm/dispatch.rs:180-219`、`src/handler/llm/nonstream.rs:96`）仅登记，由 change `veil-arch-hygiene-closeout` H11 承接，本 change 不重复修复；`T12` NonDialog 字节透传契约引用（README §7.6）与 query 语义补充说明。

真相源为 `src/handler/llm/dispatch.rs`、`src/handler/llm/nonstream.rs`、`src/handler/llm/pump/spawn.rs`、`src/service/llm_gateway/mod.rs`、`src/service/llm_gateway/protocol.rs`、`src/service/llm_gateway/usage.rs`、`src/service/llm_gateway/tool.rs`、`src/service/redaction/scope.rs`、`src/state.rs`。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/` 与 `tests/`。

引用规范：RFC 9110 §7.6.1（逐跳头）；OpenAI Chat Completions / OpenAI Responses / Anthropic Messages 官方语义（query 参数透传、`Retry-After` 与限流头、`/v1/messages/count_tokens`、`GET /v1/responses/{id}` 响应检索与 `cancel`/`input_items` 子资源、`web_search_call.action.query`、Anthropic usage 事件聚合）；Python 原仓 `_llm.py`（超限/空体判序、`ServerDisconnectedError`/`ClientConnectionError` 退避分类）。

## What Changes

- **`T1` query 保序转发**：入站 URL 改为 `path + ("?" + raw_query)`（`Uri::query()` 原样，保序、保百分号编码、保空值与重复键；无 query 不加 `?`），NonDialog 与对话路径同源；补 `GET /v1/models?limit=10&after=abc` 与对话路径 query 用例；`src/handler/llm/dispatch.rs:62/124` 为落点。
- **`T2` 非流响应头透传**：非流对话响应在消费 body 前快照上游头，按 `src/service/llm_gateway/hop.rs:41 filter_hop_headers_counted`（`downstream` 方向）过滤后转发，保留 `content-type`，透传 `Retry-After`/`x-request-id`/rate-limit 头；仅追加 `x-veil-*`；JSON 分支与错误透传分支同等处理。
- **`T3` 流式独立超时 client**：新增启动期构造、共享注入的流式 client（MUST NOT 在请求路径构造），不设覆盖整响应体读取的总超时（可选读空闲超时）；非流/透传继续用既有 30s 总超时 client；非流重试预算与被截断长流口径文档化（README §1/§7.2 同步）。
- **`T4` 非流有界读取**：`content-length` 预检 > cap 直接 502 `response_too_large`；读取改用 `bytes_stream()` 有界累计（超限即停读 + 502，不再 `up.bytes()` 全量读入）；补超大响应体不 OOM 用例。
- **`T5` 协议尾判定收紧**：`lenient_match` 排除官方子资源——`v1/messages/{count_tokens|batches}`、`v1/responses/{任意单段}`（响应对象检索及其子资源）判 `Protocol::NonDialog` 字节透传；保留严格尾缀、尾斜杠与既有 `src/service/llm_gateway/protocol.rs` 一层宽容语义（`/v1/chat/completions/extra` 仍为 Chat）；补各子路径用例。
- **`T6` 非流还原 JSON 转义**：非流 JSON 分支改用转义还原变体（等价 `src/service/redaction/scope.rs:194 restore_response_with_spans_json`），明文含 `"`/`\` 时还原后 JSON 仍可解析且不出现占位符回退；补构造性用例。
- **`T7` usage total 跨事件口径**：`total_tokens` 取显式 total 的 `max`；各事件均无显式 total 时，以合并后 `max(prompt)+max(completion)` 归一，不再对各事件派生 total 取 max；补 `start`+`delta` 跨事件用例。
- **`T8` skip 分段递归重检**：按还原区间切段后，可解析段重新 JSON walk（含嵌套 stringified JSON），跳过段保持字节原样；补「同响应既还原凭据又含工具参数内新 PII」用例。
- **`T10` `x-veil-protocol` 统一**：非流对话路径的错误透传、超限 502、空体 502 响应统一置 `x-veil-protocol`（`chat`/`anthropic`/`responses`），与成功分支一致；补 429/502 用例。
- **`T11` web_search 审计字段**：`retrieval_args` 增读官方 `action.query`（及 `action.queries` 形态），legacy 顶层 `queries/query` 回退保留；apply 阶段用真实 Responses payload 核验并补审计用例。
- **`T13` 重试分类扩宽**：拿头前（`send()` 返回 `Ok` 前）的 connect/timeout/request/body 类瞬断统一按 0.5s→1s→2s 退避最多 3 次；拿到响应后不重试；补 mock RST 用例。
- **`T14` 非流判序与观测口径**：超限判定维持 canonical `runtime-parity-limits`「`status<400` 且 `len > cap` → 502 `response_too_large`、错误状态不改写」口径；与 Python 的指标/日志差异（Python `_is_nonstream_oversize` 无状态门、oversize 分支记 `metrics_ctx['status']=502` + warning、本仓无独立指标）在 design/README 记录；补 `len>8MB` 非 JSON 200 体用例。
- **`T9`/`T12` 记录项**：`T9` 仅登记转出（`veil-arch-hygiene-closeout` H11）；`T12` 在 design 记录 NonDialog 字节透传契约引用（README §7.6）并在 README §7.6 补 query 保序转发语义说明。

## Capabilities

### New Capabilities

- `transport-fidelity-fix`：LLM 网关传输保真契约——入站 query 保序转发、非流上游响应头透传、流式独立无总超时 client、非流响应体有界读取、协议尾判定排除官方子资源、非流还原 JSON 转义、usage total 跨事件口径、还原区间跳过后的嵌套重检、网关错误响应统一协议头、检索调用官方 action 审计、拿头前瞬断重试分类、非流超限/空体判序声明。

### Modified Capabilities

- 无。既有 canonical spec（`llm-gateway`、`runtime-parity-limits`、`http-client-singleton`、`llm-streaming-parity` 等）的行为口径不在本 change 内改写；apply/archive 阶段如需同步 canonical 措辞，随归档流程处理。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `T1` | HIGH | query 保序保编码追加上游 URL（无 query 不加 `?`）；NonDialog + 对话路径测试 | 1.1、1.2 |
| `T2` | HIGH | 非流响应头 hop 过滤后透传（保 `content-type`、`Retry-After` 等）；测试 200 JSON 与 429 | 2.1、2.2 |
| `T3` | HIGH | 流式独立无总超时 client；非流 30s 保留；补 >30s mock 长流测试 | 4.1、4.2 |
| `T4` | MED | content-length 预检 + 有界读取（超限即 502）；超大响应体不 OOM 测试 | 5.1、5.2 |
| `T5` | MED | 排除 `count_tokens`/`batches`/`v1/responses/{id}` 等官方子资源（判 NonDialog）；各子路径测试 | 6.1、6.2 |
| `T6` | MED | 非流 JSON 体改用转义还原变体；含引号/反斜杠明文还原测试 | 7.1、7.2 |
| `T7` | LOW | total 取显式 max 或合并后 `max(prompt)+max(completion)`；跨事件测试 | 8.1、8.2 |
| `T8` | LOW | skip 分段后可解析段重新 walk（含嵌套 stringified JSON）；混合场景测试 | 9.1、9.2 |
| `T9` | LOW | 仅登记：NonDialog `NonstreamOutcome::Stream` 死臂由 `veil-arch-hygiene-closeout` H11 承接 | 13.1 |
| `T10` | LOW | 错误/超限/空体响应统一置 `x-veil-protocol`；429/502 测试 | 3.1、3.2 |
| `T11` | OPEN | `retrieval_args` 补 `action.query`（含 `action.queries`）；真实 payload 核验 + 审计测试 | 10.1、10.2 |
| `T12` | 记录 | NonDialog 字节透传契约引用（README §7.6）+ query 语义补充说明 | 13.2 |
| `T13` | MED | 拿头前瞬断统一退避（connect/timeout/request/body）；mock RST 测试 | 11.1、11.2 |
| `T14` | LOW | 维持 canonical 判序；记录指标/日志差异；`len>8MB` 非 JSON 200 测试 | 12.1、12.2 |

## Non-Goals（显式）

- **`T9` 不修**：NonDialog `NonstreamOutcome::Stream` 死臂由 change `veil-arch-hygiene-closeout` H11 负责，本 change 不触碰该分支，仅在覆盖表与 design D13 交叉引用。
- **不改流式缓冲/hold 语义**：`AuditHold`/boundary 放行与流式还原链路由独立 change（`veil-stream-fidelity-fix`）范围承载，本 change 只处理 `T1`-`T14` 所列传输面。
- **不改审计 verdict 判定口径与脱敏 recognizer 集合/采样策略**。
- **不新增依赖**：仅复用既有 `reqwest`（含 `stream` feature）、`axum`、`serde_json` 与既有测试设施。
- **不改 `src/`、`tests/` 与 README**：本 change 只交付规划 artifacts，实现与文档改动留待 apply 阶段；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-transport-fidelity-fix/` 下 `proposal.md`、`design.md`、`specs/transport-fidelity-fix/spec.md`、`tasks.md`（`.openspec.yaml` 已在位）。
- **apply 阶段改动面**：`src/handler/llm/dispatch.rs`、`src/handler/llm/nonstream.rs`、`src/handler/llm/mod.rs`、`src/handler/llm/pump/spawn.rs`（仅 `T6` 涉及的 JSON 分支口径核对）、`src/service/llm_gateway/mod.rs`、`src/service/llm_gateway/protocol.rs`、`src/service/llm_gateway/usage.rs`、`src/service/llm_gateway/tool.rs`、`src/service/redaction/scope.rs`、`src/state.rs`、`src/config/env_parse.rs`（如新增读空闲超时常量）、对应单测、`README.md` §5/§7.2/§7.6 与 §4 口径。
- **影响系统**：入站 URL 保真、非流响应头保真、长流存活性、非流内存边界、协议分发正确性、非流还原正确性、Anthropic 用量统计、检索审计覆盖、瞬断恢复能力。
- **依赖**：无新依赖；`http-client-singleton` 语义以「启动期构造 + 共享注入」满足（新增流式 client 同属启动期构造）。
