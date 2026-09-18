# Proposal

## Why

第八轮审计（7 维度代码级复核 + 逐项证据核实，Oracle 只读审计基线 `master@4c6ac13`）确认整体健康，但发现 4 项 Major、12 项 Minor 与 2 项 Nit：

- **R8-01（Major，审计误阻断）**：`mark_responses_done` 以「仅 `frags` 之和」计算旧值，官方 Responses 函数调用流（`response.function_call_arguments.done` 与 `response.output_item.done` 双投递完整参数）第二次调用再次累加 `total_bytes`，字节只泄漏不归还；多工具流累积至 `AUDIT_HOLD_MAX_BYTES` 后误触 `audit-hold-overflow`，阻断合法大参数调用并清仓。
- **R8-02（Major，终端契约破坏）**：`terminal.rs` 残余帧路径无 `terminal_sent()`/`block_injected()` 守卫（与 `event_loop.rs` 主循环守卫不对称），阻断/终端之后仍可能下发一条内容帧，违反「任一终端后无数据帧」与「reject 消费流」两条不变量。
- **R8-03（Major，安全 fail-open）**：还原守卫失败时回退到**掩码前**的 `cleaned`（`frame_feed.rs`）或上游原文（`nonstream.rs`），丢弃已计算的响应侧新 PII 掩码——上游模型生成的 PII 以明文下发。
- **R8-04（Major，上游可控溢出）**：合成 Responses 序号 `synth_seq_base` 的 `c + 1` 与 `responses_sequence` 的 `1 + base` 为裸加，上游 `sequence_number = u64::MAX` 时 debug 构建 panic、release 回绕为 0（非单调）。
- **12 项 Minor**：R8-05 越界 index 静默 `u64 as u32` 截断（绕过溢出桶）；R8-06 上游终端帧经 `BoundaryHold` 滞留至 EOF（上游挂起即下游挂起）；R8-07 审计阻断不终止上游读取循环（下游 mpsc 不闭合）；R8-08 Anthropic opaque 帧仍经跨缝 hold，签名载荷可被掩码破坏；R8-09 上游头克隆+过滤逻辑两处重复实现；R8-10/R8-11 `sse_event_count`「生产统一计数」声明不成立（`record_injected_event` 为 `#[cfg(test)]`）；R8-13 `truncated_line_dropped_bytes` 只写不读（无 getter、admin 不可见）；R8-15 Anthropic `custom_tool_call` 数组分支用数组下标作桶（跨 `content_block` 串扰）；R8-16 `stream:true` + 上游 2xx 非 SSE 走纯字节透传，跳过用量/审计/还原/新 PII 掩码（审计 fail-open 面）；R8-17 请求侧零替换仍执行 `strip_partials`，静默改动转发字节；R8-18 还原守卫对象键名严格比较，键位 token 还原被判破损（连带触发 R8-03 的泄漏路径）。
- **2 项 Nit**：R8-12 README 符号锚仍指 `spawn.rs`（实际 `spawn/event_loop.rs`/`pump/event.rs`）；R8-14 测试专用符号被文档按生产口径引用。
- **审查补充（R8-19，Momus 复审新增）**：canonical「Opaque 字段原字节透传」把 `thinking`（含 `thinking_delta`）整体列为 opaque，但实现（`event_loop.rs` opaque 臂谓词 `is_anthropic_opaque_event && !is_anthropic_thinking_event`）有意让**纯 `thinking_delta`** 走 `TokenCarry` + 响应侧新 PII 掩码（MSP-4/2.28）；canonical 过宽且与实现分歧。本 change 借 R8-08 delta 显式二分并锁定回归。

6 项待决策已由 Oracle 逐项裁定（D1～D6，详见 `design.md`）：终端后残余帧**恒丢弃**；还原守卫**先掩码后逐层回退**并彻底删除未掩码回退；阻断后**立即终止**上游读取；`sse_event_count` **降级为解析侧计数 + 测试辅助**（不建生产统一计数）；`stream:true` + 2xx 非 SSE JSON **收窄为非流完整后处理链**；守卫对象键按 **token 形态一一结构配对**放宽。

## What Changes

按修复分组（G0→(G1∥G2∥G4)→G3→G5，见 design.md）：

- **G0 契约冻结**
  - **R8-18/D6**：`restore_guard.rs::inner_json_intact` 对象分支改为「条目数相等 + 同名键逐键递归 + 仅占位符侧**完整 token 形态键**可与还原侧新增键配对（双射且与同名键集互补）+ 容器类型同类」；新增私有 `is_token_shaped_key`；SHALL NOT 扩大既有 `_ => true` 兜底。
  - **R8-10/R8-11/R8-14/D4**：`src/service/sse/parser.rs` 字段文档更正为「`sse_event_count` = 解析层数据事件计数（分块/同块等价口径基准）；注入帧生产计数唯一为 `GatewayMetrics::add_sse_event`，解析计数按声明排除合成帧」；**删除** test-only 的 `record_injected_event`（`parser.rs:176-177`，其唯一用途是伪造已不成立的两口径相等）；`sse_event_count_consistency`（`src/service/sse.rs:261-275`）重写为断言声明差值（`sse_event_total() - sse_event_count ==` 合成帧数），SHALL NOT 再断言逐帧相等。**新增/修订 delta**：`stream-fidelity-fix` MODIFIED「SSE 事件计数口径一致」。
- **G1 安全回退**
  - **R8-03/D2**：`emit_restored_json_frame` 落地阶梯——① `mask(restore(frame))`（守卫通过即用）；② 守卫失败 warn + `record_restore_fallback` 后回退 `mask(placeholder)`；③ 仍失败**流丢帧**；`FrameSink` 增 `scope`、`RestoredFrame` 增 `mask_fallback`（opaque 臂 `false` 保签名字节、普通臂与残余臂 `true`）。`nonstream.rs` 阶梯 ①`restored`(masked) ②`retry_stripped` ③`mask(text)` ④全失败 `502 E_PII_UNAVAILABLE`；**删除** `restored = text` 与未掩码占位符回退。
  - **R8-08**：Anthropic **签名/密文载体帧**（`signature_delta`、`redacted_thinking`、携 `signature`/`redacted_data` 的 `thinking`/`content_block_start`，即谓词 `is_anthropic_opaque_event && !is_anthropic_thinking_event`）SHALL NOT 进入 `PrefixHold`/`BoundaryHold` 跨缝合掩码路径，保证签名载荷字节完整；**纯 `thinking_delta`（不携 `signature`/`redacted_data`）SHALL NOT 视为 opaque**，保持 `TokenCarry` 跨帧缝合 + 响应侧新 PII 掩码路径不变（R8-19 分歧收敛）。签名/密文载体帧的守卫失败 SHALL 字节恒等回退（不丢帧、记 `restore_fallback` 恰一次）。
- **G2 终端与生命周期**
  - **R8-02/D1**：`terminal.rs` 残余帧路径加 `!terminal_sent() && !block_injected()` 守卫，终端后残余帧一律丢弃（正常 EOF 收尾且未发终端时的既有放行语义不变）。
  - **R8-06**：Anthropic/Responses 上游终端帧发出后即 `mark_loop_terminated()`，终端由 `finish`→`finalize` 的 flush 立即送达，不再依赖上游 EOF；Chat `[DONE]` 路径不变（保留 usage 尾帧）。
  - **R8-07/D3**：`apply_reject_block` 在 `commit` 后统一 `mark_loop_terminated()`，阻断即停止拉取上游并尽快闭合下游流（已累计 usage 不丢失）。
  - **R8-04**：`synth_seq_base` 与 `responses_sequence` 全部改 `saturating_add`（对齐 `hold.rs` R5-17 饱和约定）。
- **G3 协议路由**
  - **R8-16/D5**：从 `nonstream.rs::serve_nonstream` 抽出 `pub(super) async fn process_upstream_response(up, ctx, req_conv, req_model) -> NonstreamOutcome`（`req_conv`/`req_model` 由 fetch 前的请求体快照派生、随参传入；JSON 与非 JSON 分支内置该函数，读体后分类）；`dispatch.rs` 流式分支把 `status>=400 || !is_event_stream` 拆为——`status>=400` 走既有 `stream_upstream_passthrough`；`status<400 && !is_event_stream` 构造 `NonstreamCtx { stream_flag: false, non_json_passthrough: true, .. }` 并无条件调 `process_upstream_response`（2xx JSON → 非流完整后处理链、命中 `Block` → `nonstream_block_body`；2xx 非 JSON → 字节透传 + warn + 计数）。新增 `NonstreamCtx` 策略位 `non_json_passthrough`（`false` 保留原生非流的 2xx 非 JSON → 502 `E_EMPTY_BODY` 语义）；保留 `NonstreamOutcome::Stream` 臂。
  - **R8-09**：dispatch 内联的上游头克隆改调 `nonstream::clone_upstream_headers`（提为 `pub(super)`），dispatch 侧保留 `strip_veil_internal_headers`。
- **G4 审计记账**
  - **R8-01**：`mark_responses_done` 旧值改用 `slot.held_bytes()`（与释放口径同源），并补「`total_bytes` == `Σ args_by_index` 各值长度 + `Σ responses_slots.held_bytes()`」守恒断言（`pending_bytes` 为独立维度不计入）。
  - **R8-05**：`outer_event_index` 越界值改走 `bucket_from_raw_index` 溢出桶语义或返回 `None`，SHALL NOT 静默 `as u32` 截断。
  - **R8-15**：Anthropic `custom_tool_call` 数组分支改用复合桶函数 `anthropic_item_bucket(block_bucket, item_index)`（D10：`item_index == 0` 且块键在合法域时退化为纯块键、与对象分支等价；越界走有界哈希溢出桶），与对象分支同口径单射。
- **G5 文档与计数**
  - **R8-12**：README 符号锚改指 `src/handler/llm/pump/spawn/event_loop.rs` 与 `src/handler/llm/pump/event.rs`。
  - **R8-13**：新增 `truncated_line_dropped_bytes_count()` getter，并在 `src/handler/admin.rs::admin_metrics_body`（`src/handler/admin.rs:140` 的 `"sse_events"` 旁）只增 `truncated_line_dropped_bytes` 顶层字段。
  - **R8-14**：修正 `README.md` §7.2 计数口径句——「无合成帧的纯上游流下 `sse_event_count`、`add_sse_event()` 与转发帧数逐一致；注入合成帧仅计入 `add_sse_event`，解析计数按 `stream-fidelity-fix`「SSE 事件计数口径一致」显式排除（声明与实现一致）」。
  - **R8-17**：`redact_request_with_report` 在 `replaced == false && custom_snapshot.is_empty()` 时不再执行 `strip_partials`，改为字节保真返回。

### Non-goals

- 不实现 `sse_event_count` 的生产统一计数（D4 采纳选项 a；计数设计上留在调用点）。
- 不保留任何「回退未掩码上游原文」路径；不重发上游请求（R7-05 与 R8-16 均不重发）。
- 不扩展 `scripts/check_doc_paths.py` 语义；不改 `agg` 切分；不新增下游响应头。
- 不新增配置项/环境变量/依赖；不重开 R7 已裁决项。

## Capabilities

### New Capabilities

（无）

### Modified Capabilities

- `stream-fidelity-fix`: 流式上游 2xx 非 SSE 的 `application/json` 正文改走非流完整后处理链、2xx 非 JSON 维持字节透传（MODIFIED「流式上游错误状态透传」）；显式声明解析计数排除合成注入帧、生产注入计数唯一（MODIFIED「SSE 事件计数口径一致」）。
- `llm-edge-gateway`: 非流还原回退阶梯改为「掩码占位符帧 / 502 `E_PII_UNAVAILABLE`」，删除回退上游原文（MODIFIED「非流还原回退前残缺重试」）。
- `gateway-fidelity`: 流式守卫失败回退掩码后占位符帧、二次失败丢帧（MODIFIED「流式还原 JSON 破帧防护」）；opaque 帧 SHALL NOT 进跨缝掩码（MODIFIED「Opaque 字段原字节透传」）。
- `redaction`: 残余帧守卫回退阶梯与对象键 token 形态配对（MODIFIED「残余帧 JSON 转义还原」）；请求侧零替换路径字节保真（ADDED「请求侧零替换字节保真」）。
- `redaction-audit-coverage`: 重复 `.done` 字节不二次累加（MODIFIED「Responses 审计字节去重」）；工具分桶单射与越界 index 归属（ADDED「工具分桶单射与越界 index 归属」）。
- `stream-protocol-parity`: 终端后残余帧恒丢弃、上游终端即时送达、阻断后停止拉取上游（ADDED 三条）；`truncated_line_dropped_bytes` 可读（MODIFIED「Overlong lines are marked not silently dropped」）。
- `llm-protocol-hardening`: 合成帧序号饱和加法（MODIFIED「Responses 合成帧序号完整」）。

## Impact

- **代码**：`src/service/redaction/restore_guard.rs`、`src/handler/llm/pump/spawn/frame_feed.rs`、`src/handler/llm/pump/spawn/restore_emit.rs`、`src/handler/llm/nonstream.rs`、`src/handler/llm/dispatch.rs`、`src/handler/llm/pump/spawn/terminal.rs`、`src/handler/llm/pump/spawn/event_loop.rs`、`src/handler/llm/pump/spawn/event_loop/reject.rs`、`src/service/block_inject/frames.rs`、`src/service/audit/hold.rs`、`src/handler/llm/pump/event.rs`、`src/service/llm_gateway/tool.rs`、`src/service/redaction/scope.rs`、`src/service/llm_gateway/metrics.rs`、`src/handler/admin.rs`、`src/service/sse/parser.rs`（及 `src/service/sse.rs` 测试）、`src/service/llm_gateway/tool/bucket.rs`；新增/扩展单测（`restore_guard`、`restore_emit`、`nonstream`、`dispatch`、`terminal`、`event_loop`、`hold/tests.rs`、`tool/tests.rs`、`scope` 与流式回归）。
- **文档**：`README.md`（§7.2 计数口径与符号锚、§7.2 2xx 非 SSE 分流口径、§7.7 请求零替换字节保真）。
- **规范**：上述 7 个 canonical capability 的 change-local delta（归档时合并，含 `stream-fidelity-fix` 新增「SSE 事件计数口径一致」MODIFIED）；本 change SHALL NOT 手改 `openspec/specs/**`。
- **无 API 路径/环境变量/依赖变更**；R8-03/R8-16 为安全修复型行为变更（更严），R8-17 为字节保真修复，均不构成配置迁移 BREAKING。
