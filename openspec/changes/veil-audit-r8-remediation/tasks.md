# Tasks

> 说明：本 change 的 spec 修正经 change-local delta 承载，canonical `openspec/specs/**` 由归档步骤（`openspec archive`）合并；apply 阶段 SHALL NOT 手改 canonical。验收命令中的测试名可在实现时按仓库既有命名微调，但 SHALL 保留同名语义与断言目标。
>
> 分组拓扑（见 design D5/D8）：**G0 →（G1 ∥ G2 ∥ G4）→ G3 → G5**；G2 组内串行（`event_loop`/`terminal`/`terminator` 状态耦合）；G3 必须在 G1 之后（同改 `nonstream.rs`）。

## 1. G0 契约冻结（最先，可并行）

- [x] 1.1 `src/service/redaction/restore_guard.rs::inner_json_intact` 对象分支改写（`R8-18`/D6）：要求两侧条目数相等；同名键逐键递归；仅当占位符侧键为完整 token 形态（`__VG_CRED_<≥6 位>__`/`__PII_<seq>_<8 hex>__`）时允许与还原侧新增键一一配对（双射且与同名键集互补）；容器类型同类；SHALL NOT 扩大 `_ => true`。新增私有 `is_token_shaped_key`（引用 `credential_vault::TOKEN_PREFIX` 与 `pii::detector::PII_TOKEN_PREFIX`，校验完整形态）。验证：`restore_guard` 单测——正例「键 token 还原 + 值完好」接受且不触发 `restore_fallback`；负例「内层 stringified 破损」「条目数不等」「多一非 token 键」「Object↔String 类型漂移」全部拒绝；并**显式改写既有用例** `inner_json_intact_recursive_cases`（`restore_guard.rs:118-135`）——`inner_json_intact({"a":1},{"a":1,"b":2})` 的既有断言 `true` 在条目数相等约束下 SHALL 改为 `false`（`b` 为非 token 键）；`cargo test restore_guard` 通过。
- [x] 1.2 `src/service/sse/parser.rs` 口径更正与 test-only 删除（`R8-10`/`R8-11`/`R8-14`/D4）：字段文档（:108-112）改为「解析层数据事件计数（分块/同块等价口径基准）；注入帧生产计数唯一为 `GatewayMetrics::add_sse_event`，解析计数按 `stream-fidelity-fix`「SSE 事件计数口径一致」显式排除合成帧」；**删除** `record_injected_event`（`parser.rs:176-177`，已是 `#[cfg(test)]`、无生产调用点）；重写 `src/service/sse.rs:261-275` 的 `sse_event_count_consistency` 为「push 2 个数据事件后 `sse_event_count == 2`；`add_sse_event()` 3 次后 `sse_event_total() == 3` 且 `sse_event_total() - sse_event_count == 1`」。验证：`grep -n "逐一致" src/service/sse/parser.rs` 零命中、`grep -n "record_injected_event" src/` 零命中；`cargo test sse_event_count_consistency` 通过且 SHALL NOT 断言两口径逐帧相等；delta 中存在 `stream-fidelity-fix` MODIFIED「SSE 事件计数口径一致」。

## 2. G1 安全回退（依赖 G0 的守卫语义）

- [x] 2.1 `src/handler/llm/pump/spawn/restore_emit.rs` 回退阶梯（`R8-03`/D2）：`FrameSink` 增 `scope: &'a Scope`；`RestoredFrame` 增 `mask_fallback: bool`；`emit_restored_json_frame` 内实现——① 守卫通过用 `mask(restore(frame))`；② 失败 `warn` + `metrics.record_restore_fallback()` 后回退 `scope.redact_response_new_pii_with_skip(vault, detector, placeholder, &[])` 所得掩码占位符帧；③ 仍失败返回空帧（不 `feed`、不下发）；④ `mask_fallback:false`（opaque 签名/密文载体臂，D11）时守卫失败直接回退 `placeholder` 字节——字节恒等、不丢帧、不施掩码，并记 `restore_fallback` 恰一次。`src/handler/llm/pump/spawn/frame_feed.rs::guard_restored_frame_parsed` 保持纯判定；`guard_restored_frame`（`#[cfg(test)]` 重导出）签名不变并标注测试专用。验证：`cargo test restore_emit` 通过；新增单测断言「守卫失败 → 下游零新检出 PII 明文、JSON 合法、`restore_fallback` 恰 +1」与「opaque 失败 → 字节逐字等于上游帧、不丢帧」。
- [x] 2.2 三调用点接线（D2）：`event_loop.rs` opaque 臂 `mask_fallback:false`（保签名字节恒等）；常规臂与 `terminal.rs` 残余臂 `true`。验证：`grep -n "mask_fallback" src/handler/llm/pump/` 命中三处；`cargo test` 相关流式用例全绿且 opaque 帧字节恒等断言不变。
- [x] 2.3 `src/handler/llm/nonstream.rs` 阶梯（`R8-03`）：①`restored`(masked) ②`retry_stripped(&restored)` ③`mask(text)`；④全失败 `VeilError::PiiUnavailable`（`502 E_PII_UNAVAILABLE`）；**删除** `restored = text` 未掩码回退。验证：新增单测——守卫失败返回掩码体（零新检出 PII 明文）；掩码自身失败返回 502；`cargo test nonstream` 通过。
- [x] 2.4 `R8-08`/`R8-19`/D9：把当前 opaque 臂谓词抽为**显式命名谓词**（如 `is_anthropic_seam_transparent`，语义 = `is_anthropic_opaque_event(v) && !is_anthropic_thinking_event(v)`，即签名/密文载体）；**仅该载体帧**不进 `PrefixHold`/`BoundaryHold` 跨缝合掩码路径（无掩码直通或等价字节区间排除）。**MUST NOT** 复用裸 `is_anthropic_opaque_event`（会切断 thinking 缝合）。纯 `thinking_delta`（`delta.type=="thinking_delta"` 且无 `signature`/`redacted_data`）SHALL 保持 `TokenCarry` 跨帧缝合 + `redact_response_new_pii_with_skip` 路径不变。验证：新增三组单测——① `signature_delta` 与邻帧跨缝拼出 PII/hint → 字节恒等、未被 `mask_span_bytes` 改写；② 纯 `thinking_delta` 两帧跨缝拼出 PII → 命中被掩码且发生 `TokenCarry` 缝合；③ 既有 opaque 字节恒等用例（`restore_emit.rs::sse_protocol_roundtrip_invariants` K④）全绿。

## 3. G2 终端与生命周期（组内串行）

- [x] 3.1 `R8-02`/D1：`src/handler/llm/pump/spawn/terminal.rs` 残余路径加 `if !terminator.terminal_sent() && !terminator.block_injected()` 守卫（包住 `residual_frame_payload` 分支；位置在 `emit_restored_json_frame` 之前）。不得改动 `drain_prefix_hold`+`boundary.flush`+发送段、D6/空流守门、`blocked` 分支与 `release_audited()`。验证：新增单测——① 上游「完整 JSON 帧 → 终端帧 → 无空行收尾的完整 JSON 残余」断言终端后零数据帧、`terminal_sent`/`terminal_injected` 恰一；② 阻断后残余被丢弃；③ 正常 EOF（无终端）残余放行语义不变；`cargo test` 相关用例通过。
- [x] 3.2 `R8-06`：Anthropic/Responses 上游终端帧发出后即 `mark_loop_terminated()`，由 `finish`→`finalize` 的 flush 立即送达（不依赖上游 EOF）；Chat `[DONE]` 路径不动（保留 usage 尾帧）。验证：新增单测——上游发终端后**不 EOF** 时下游立即收到终端且流闭合；Chat usage 尾帧透传用例零回归。
- [x] 3.3 `R8-07`/D3：`src/handler/llm/pump/spawn/event_loop/reject.rs::apply_reject_block` 末尾统一 `state.terminator.mark_loop_terminated();`（`Frames` 与幂等 `None` 两分支）。验证：新增单测——阻断后上游不 EOF 时泵任务在阻断帧后结束、下游流闭合、恰一终端、阻断前已累计 usage 不丢失；R7-01 pending 终审恰一次用例零回归。
- [x] 3.4 `R8-04`：`src/service/block_inject/frames.rs::synth_seq_base` 改 `cursor.map_or(0, |c| c.saturating_add(1))`，`responses_sequence` 及各合成帧序号改 `saturating_add`（对齐 `hold.rs` R5-17）。验证：新增单测——上游 `sequence_number = u64::MAX` 后触发阻断/截断合成，断言不 panic、不回绕非单调；`cargo test frames` 与序号用例全绿。

## 4. G3 协议路由（必须在 G1 之后）

- [x] 4.1 抽取 `src/handler/llm/nonstream.rs::process_upstream_response`：签名 `pub(super) async fn process_upstream_response(up: reqwest::Response, ctx: NonstreamCtx, req_conv: Option<String>, req_model: &str) -> NonstreamOutcome`（D12）；JSON/非 JSON 分支**内置该函数**（有界读体后分类）；`NonstreamCtx` 增策略位 `pub non_json_passthrough: bool`；`serve_nonstream` 保留 `fwd_headers`、`req_value/req_conv/req_model` 快照（须在 fetch move `body` 前）、fetch 与失败 `empty_body_response`、`NonstreamCtx{ non_json_passthrough:false, .. }` 装配后委托之；保留 `NonstreamOutcome::Stream` 臂与 `should_pump_stream` 判定。新增字段后**所有** `NonstreamCtx` 构造点须同步（`serve_nonstream` = `false`、dispatch 新分支 = `true`、测试内构造点如 `dispatch.rs:573`）。验证：`cargo test nonstream` 全绿；`grep -n "non_json_passthrough" src/handler/llm/nonstream.rs` 命中默认 `false` 装配；原生 2xx 非 JSON 仍 502 `E_EMPTY_BODY`。
- [x] 4.2 `src/handler/llm/dispatch.rs` 流式分支分流（`R8-16`/D5/D12）：把 `if status_u16 >= 400 || !is_event_stream(&resp_ct)` 拆为——`status_u16 >= 400` → 既有 `stream_upstream_passthrough`；`status<400 && !is_event_stream(&resp_ct)` → 构造 `NonstreamCtx{ stream_flag: false, non_json_passthrough: true, .. }` 并无条件调 `process_upstream_response(up, ctx, rw.init_conv.clone(), &req_model)`（2xx JSON → 非流完整后处理链、`Block` → `nonstream_block_body`；2xx 非 JSON → 字节透传 + warn + 计数）。验证：`grep -n "status_u16 >= 400" src/handler/llm/dispatch.rs` 显示该条件已不含 `|| !is_event_stream`；`grep -n "non_json_passthrough: true" src/handler/llm/dispatch.rs` 命中新分支；新增单测 6 项（危险 tool 阻断、响应侧新 PII 掩码、零命中逐字节、`status>=400` 原样、2xx 非 JSON 字节 + warn、R7-05 非流+SSE 复用回归）。
- [x] 4.3 `R8-09`：`src/handler/llm/nonstream.rs::clone_upstream_headers` 提为 `pub(super)`，`dispatch.rs` 内联克隆改调之并保留 `strip_veil_internal_headers`。验证：`grep -n "clone_upstream_headers" src/handler/llm/` 命中非流与 dispatch 两处；多值头用例全绿。
- [x] 4.4 `README.md` §7.2 同步 2xx 非 SSE 分流口径（D13）：「2xx 非 `text/event-stream` 且正文为 `application/json` → 非流完整后处理链（用量 + 审计 + 还原 + 响应侧新 PII 掩码；`Block` → `nonstream_block_body`）；2xx 非 JSON → 字节透传 + warn + 计数；`status>=400` 与进入 SSE 泵路径口径不变」。验证：`grep -n "application/json" README.md` 命中该分流句；该段与 `stream-fidelity-fix`「流式上游错误状态透传」一致。

## 5. G4 审计记账（可并行）

- [x] 5.1 `R8-01`：`src/service/audit/hold.rs::mark_responses_done` 的旧值改用 `slot.held_bytes()`（分片与已存 `done_args` 之和；与释放口径同源），或对 `done_args == Some(args)` 幂等早退。验证：新增单测——`function_call_arguments.done` + `output_item.done` 同参数双投递后 `total_bytes` 不重复累加、释放后无残留；守恒断言「`total_bytes` == `args_by_index` 各值长度之和 + 各 `responses_slots` `held_bytes()` 之和」（即 `release_audited`/`release_pending_audited` 的归还口径；`pending_bytes` 为独立维度不计入）；`cargo test hold` 通过。
- [x] 5.2 `R8-05`：`src/handler/llm/pump/event.rs::outer_event_index` 越界值改走 `bucket_from_raw_index` 溢出桶语义或返回 `None`，SHALL NOT `n as u32` 静默截断（注意：`bucket_from_raw_index`/`bucket_digest`/`overflow_bucket` 当前为 `bucket.rs` 私有 `fn`，需提为 `pub(crate)` 或经 `bucket_index_of` 既有入口暴露后再由 `event.rs` 复用）。验证：新增单测——`index`/`output_index = 2^32` 时不操作错误槽（路由溢出桶或按缺失处理）；既有分桶用例零回归。
- [x] 5.3 `R8-15`/D10：在 `src/service/llm_gateway/tool/bucket.rs` 新增 `pub(crate) fn anthropic_item_bucket(block_bucket: u32, item_index: u32) -> u32`（`item_index == 0` **且** `block_bucket < ANTHROPIC_BLOCK_MAX` 时返回 `block_bucket`（对象分支等价）；合法域 `item_index >= 1` 用 `ANTHROPIC_ITEM_BASE | (block_bucket << 8) | (item_index - 1)`，`ANTHROPIC_ITEM_BASE = 1<<24`、`ANTHROPIC_BLOCK_MAX = 1<<16`、`ANTHROPIC_ITEM_MAX = 1<<8`，上界 `0x01FF_FFFF < TOOL_BUCKET_OVERFLOW_BASE`；越界（含 `block_bucket >= ANTHROPIC_BLOCK_MAX`）`warn` + `overflow_bucket(bucket_digest(((block_bucket as u64) << 32) ^ item_index as u64))`）；`src/service/llm_gateway/tool.rs:327-334` 数组臂改为 `custom_obj_to_call(emit_warn, anthropic_item_bucket(bucket, j as u32), item)`，对象臂 `custom_obj_to_call(emit_warn, bucket, obj)` 不变。验证：同一事件两个 `content_block` 各含 2 项 `custom_tool_call` → 4 个 `ToolCall.index` 两两互异；`anthropic_item_bucket(bucket_i, 0) == bucket_i`；越界落 `overflow_bucket` 保留带；`cargo test tool` 相关用例通过。

## 6. G5 文档与计数（最后统一跑 gate）

- [x] 6.1 `R8-12`：`README.md:673`/`:678` 符号锚改指 `src/handler/llm/pump/spawn/event_loop.rs`（TRN-1 主循环/事件计数）与 `src/handler/llm/pump/event.rs`（TRN-7 提取）。验证：`grep -n "pump/spawn.rs" README.md` 零命中（或仅剩确指薄壳的合法引用）；`python3 scripts/check_doc_paths.py` 通过。
- [x] 6.2 `R8-13`：`src/service/llm_gateway/metrics.rs` 增 `truncated_line_dropped_bytes_count()` getter（当前只有 `record_truncated_line_dropped_bytes`，`metrics.rs:171`），`src/handler/admin.rs::admin_metrics_body`（`src/handler/admin.rs:140` 的 `"sse_events"` 旁）只增 `"truncated_line_dropped_bytes"` 顶层字段（与既有 `"truncated"` 对象不冲突、不删不改既有键）。验证：新增/扩展单测断言字段存在且随丢弃字节递增；`src/handler/admin/tests/observability.rs` 中枚举字段名的既有用例同步补键后全绿。
- [x] 6.3 `R8-17`：`src/service/redaction/scope.rs::redact_request_with_report` 在 `replaced == false && custom_snapshot.is_empty()` 时不再执行 `strip_partials`，字节保真返回；有替换时清理语义不变。验证：新增单测——零替换且正文含 `__VG_`/`__PII_` 片段时转发体逐字节不变；有替换时确证残缺仍被剥离；`cargo test scope` 与 `cache_fidelity` 全绿。
- [x] 6.4 `R8-14`/D13：修订 `README.md:671-673` 计数口径句——「**无合成帧**的纯上游流下 `sse_event_count`、`add_sse_event()` 与转发帧数逐一致；注入合成帧（阻断/截断/真空终止）仅计入 `add_sse_event`，解析计数按 `stream-fidelity-fix`「SSE 事件计数口径一致」显式排除（声明与实现一致）」。验证：`grep -n "sse_event_count" README.md` 显示「无合成帧…显式排除」，不再出现无条件的「逐一致」表述。

## 7. 最终验证与复审

- [x] 7.1 `cargo fmt --check` 通过。
- [x] 7.2 `cargo clippy --tests --all-targets -- -D warnings` 全绿（含 G1–G5 新代码）。
- [x] 7.3 `cargo test` 全绿（含 1.1/2.1/2.3/2.4/3.1–3.4/4.1/4.2/4.3/5.1–5.3/6.1–6.3 新用例；记录用例数与新增名单）。
- [x] 7.4 `python3 scripts/check_doc_paths.py` 与 `python3 scripts/check_file_sizes.py` 全绿。
- [x] 7.5 `openspec validate veil-audit-r8-remediation --strict` 通过（7 个 delta 合法；MODIFIED 标题与 canonical 逐字一致）。
- [x] 7.6 `bash scripts/gate.sh` 通过；缺 Python venv/SDK 前置时以 `GATE_SKIP_CONFORMANCE=1` 显式跳过并如实登记，缺 Go 工具链时以 `GATE_SKIP_GO=1` 显式跳过（不静默）。
- [x] 7.7 逐发现复核 delta 覆盖（19 项含审查补充、无遗漏）：R8-01→`redaction-audit-coverage`；R8-02→`stream-protocol-parity`；R8-03→`llm-edge-gateway`+`gateway-fidelity`+`redaction`；R8-04→`llm-protocol-hardening`；R8-05/R8-15→`redaction-audit-coverage`；R8-06/R8-07→`stream-protocol-parity`；R8-08→`gateway-fidelity`；R8-10/R8-11/R8-14→`stream-fidelity-fix`「SSE 事件计数口径一致」+ §1.2/§6.4；R8-09→D7/D12（§4.3）；R8-12/R8-13→D7 + §6.1/§6.2；R8-16→`stream-fidelity-fix`；R8-17→`redaction`；R8-18→`redaction`；R8-19→`gateway-fidelity`「Opaque 字段原字节透传」。验证：`grep -rn "R8-0[1-9]\|R8-1[0-9]" openspec/changes/veil-audit-r8-remediation/` 逐项命中。
- [x] 7.8 Oracle 复审已实施变更：逐项核验 D1–D6 落地与 R7/R5 不变量零回归；无 Blocking/Major 遗漏方视为通过；Minor 处置按复审结论登记（design Open Questions）。

## 8. 归档登记（非本 apply 范围，不计入 tasks 勾选）

归档阶段执行 `openspec archive veil-audit-r8-remediation`，由 delta 合并修正 canonical；归档前 SHALL 先处置未归档的 `veil-audit-r7-remediation`（Complete 未归档，避免 delta 合并顺序与 canonical 漂移）。归档后复核项：README §7.2（计数口径句 + 2xx 非 SSE 分流句 + 符号锚）、§7.7 与 canonical 相关字面量零漂移；`stream-fidelity-fix`「SSE 事件计数口径一致」与「流式上游错误状态透传」的 canonical 合并结果与本 delta 逐字一致。该步骤属归档阶段，不作为本 apply 的完成前置。
