# Design

## Context

见 `proposal.md` → Why。影响本设计的既有约束：

- 基线 `master@4c6ac13`（R7 修复已合入），本轮为第八轮审计（R8）；19 项发现（18 项审计 + 1 项复审补充 R8-19）与 6 项待决策均已由 Oracle 逐项裁定（本设计 Decisions 即裁定结果，标记「Oracle 已裁决」）。
- canonical specs 为真相源，只能经 change 的 delta 修改（本 change 7 个 delta）；本 change SHALL NOT 手改 `openspec/specs/**`（归档时由 `openspec archive` 合并）。
- **终端决策单一所有者**：`StreamTerminator`（`plan_*`/`commit`）只产出计划，帧发送与计数留在调用点（`synth_flush`/`event_loop`/`terminal`）；`mark_loop_terminated`/`set_truncated` 由调用点执行。
- **计数留在调用点**（BLOCKER-1）：注入帧的生产计数唯一为 `GatewayMetrics::add_sse_event`；parser 不在注入路径上，`sse_event_count` 仅在解析路径自增。
- `release_audited()` 仅清 `done_seen` 槽；R7-01 的两段协同（全局完成臂释放 + 终端 pending 循环）为 pending 恰一次语义基础，本 change SHALL NOT 回退。
- **边界滞留**：`PII_HOLD_MAX`（默认 64）使响应侧帧整帧延迟一级；终端帧同样经 `BoundaryHold`，flush 时机决定下游闭合时点。
- **opaque 帧**（Anthropic 签名/密文载体 `signature`/`redacted_thinking`/携 `signature` 的 `thinking`）既有 requirement 已要求跳过响应侧新 PII 扫描与 JSON 重序列化，但当前仍参与跨缝 hold；纯 `thinking_delta` 明文不属于 opaque（见 D9/R8-19）。
- `stream:true` + 上游 2xx 非 SSE 现走 `stream_upstream_passthrough`（hop 过滤 + `x-veil-protocol` + 有界字节转发）；正文已由有界读缓冲（受 `NONSTREAM_MAX_BYTES` 约束），无新增缓冲放大。
- 请求侧 `redact_request_with_report` 在零替换时仍调用 `strip_partials`；`restore_guard::inner_json_intact` 对象分支按**键名严格相等**比较。

## Goals / Non-Goals

**Goals:**

- 消除 4 项 Major（R8-01 误阻断 / R8-02 终端后帧 / R8-03 PII 泄漏 / R8-04 序号溢出）。
- 收敛 12 项 Minor + 2 项 Nit；19 项发现（含 R8-19）在本 change 内均有任务与验证可追溯（含 D7 登记与 D8 归属）。
- 7 个 delta 与 19 项发现一一可追溯；`openspec validate --strict` 通过。

**Non-Goals:**

- 不实现 `sse_event_count` 的生产统一计数（D4 采纳「显式声明排除并立 delta」而非回灌解析侧）。
- 不保留任何「回退未掩码上游原文」路径（D2）。
- 不重发上游请求（R7-05 与 R8-16 均不重发）；不新增配置项/环境变量/依赖/下游响应头。
- 不改 `agg` 切分、不扩展 `scripts/check_doc_paths.py` 语义、不重开 R7 已裁决项。

## Decisions

### D1（R8-02）终端后残余帧恒丢弃（Oracle 已裁决）

- **选项 A（采纳）**：只要 `terminator.terminal_sent() || terminator.block_injected()` 为真，残余帧一律不下发（**不区分是否 block**）。
- **选项 B（拒绝）**：仅阻断态丢弃——上游终端之后仍可能下发内容帧，违反「任一终端后无数据帧」与「reject 消费流」两条不变量。
- **实现形态**：`terminal.rs` 中把 `if let Some(payload) = residual_frame_payload(&residual) { … }` 整体包进 `if !terminator.terminal_sent() && !terminator.block_injected() { … }`；守卫置于 `residual_frame_payload` 调用之后（半帧本就被丢弃）、`emit_restored_json_frame` 之前。
- **不得改动**：`drain_prefix_hold`+`boundary.flush`+发送段（终端前滞留内容的送达通道）、D6/空流守门、`blocked` 分支与 `hold.release_audited()`。
- **规格**：`stream-protocol-parity` ADDED「终端后残余帧恒丢弃」。

### D2（R8-03）还原守卫回退阶梯：先掩码、后逐层回退（Oracle 已裁决）

- **选项 A（采纳）**：① 主产物 `mask(restore(frame))`；② 守卫失败 warn + `record_restore_fallback` 后回退 `mask(placeholder)`；③ 仍失败 → 流丢帧 / 非流 `502 E_PII_UNAVAILABLE`；**彻底删除**回退未掩码原文的路径。
- **选项 B（拒绝）**：保留 `placeholder_frame.to_string()`（`frame_feed.rs`）与 `restored = text`（`nonstream.rs`）——响应侧新 PII 明文外泄，属 fail-open。
- **理由**：响应侧新 PII 掩码与还原同为安全控制；`placeholder` 恒为合法 JSON，掩码为 ASCII 替换不破 JSON，故第二级实质必过；终点 fail-closed。
- **实现形态**：`frame_feed.rs::guard_restored_frame_parsed` 保留为纯判定（回退决策上移）；`restore_emit.rs` 的 `FrameSink` 增 `scope: &'a Scope`、`RestoredFrame` 增 `mask_fallback: bool`，`emit_restored_json_frame` 内实现阶梯；三调用点——`event_loop.rs` opaque 臂 `mask_fallback:false`、常规臂 `true`、`terminal.rs` 残余 `true`；`nonstream.rs` 阶梯 ①`restored`(masked) ②`retry_stripped` ③`mask(text)` ④ `VeilError::PiiUnavailable`（502）。
- **不得改动**：`record_restore_fallback` 恰一次语义、opaque 臂字节恒等、`pii_unavailable` 的 502 收敛、skip 区间语义。
- **规格**：`llm-edge-gateway` MODIFIED「非流还原回退前残缺重试」；`gateway-fidelity` MODIFIED「流式还原 JSON 破帧防护」；`redaction` MODIFIED「残余帧 JSON 转义还原」。
- **opaque 豁免（见 D11）**：签名/密文载体帧（`mask_fallback:false`）守卫失败 SHALL 字节恒等回退（不丢帧、不施掩码、记 `record_restore_fallback` 恰一次）；该豁免仅限签名/密文载体，纯 `thinking_delta` 与残余臂（`mask_fallback:true`）不适用；两 requirement 需互引以防漂移。

### D3（R8-07）审计阻断后立即终止上游读取（Oracle 已裁决）

- **选项 A（采纳）**：`apply_reject_block` 在 `commit` 后统一调用 `terminator.mark_loop_terminated()`（`Frames` 与幂等 `None` 两分支），**不继续 drain 到 EOF**。
- **选项 B（拒绝）**：继续读到 EOF 以补尾部 usage——下游 mpsc 保持打开、客户端可能挂起；尾部 usage 对已阻断响应无实际价值。
- **互操作**：`run_pump` 在 `terminated()` 处 break → `finish` → `terminal::finalize`；因 `terminal_sent()==true`，`should_apply_midstream_terminal`/`should_synthesize_empty_stream` 均为假 → **无第二终端**；`PumpEnv` 的 tx 克隆随 `RequestKeepalive::drop` 释放 → 下游 `rx` 收 `None`；R7-01 的 `finalize` pending 终审与 `release_pending_audited` 仍恰一次。
- **不得改动**：阻断帧发送、`note_sticky_rejected`/`audit_blocked`、`record_aux_counts`、`PumpOutcome.block_injected`。
- **规格**：`stream-protocol-parity` ADDED「审计阻断后停止拉取上游」。

### D4（R8-10/R8-11/R8-14）解析计数显式排除合成帧（Oracle 修订裁决）

- **裁定（选项 a + 立 delta）**：canonical `stream-fidelity-fix`「SSE 事件计数口径一致」明写「注入的合成帧 SHALL 被纳入计数，**或被显式声明排除且该声明与实现一致**」。本 change 采纳**显式声明排除**：`SseParser::sse_event_count` 仅统计解析路径产出的数据事件（分块/同块等价口径基准）；审计 hold 阻断、截断收尾、真空流最小终止等路径注入的合成帧 SHALL NOT 计入解析计数；生产注入帧的计数唯一来源为 `GatewayMetrics::add_sse_event`（覆盖下游实际发出的全部帧，含合成帧）。因此本 change **新增 MODIFIED delta**「SSE 事件计数口径一致」——先前「无 delta」的判断是对 canonical 的误读（注入帧的纳入/排除恰是该条款的显式约束对象），已纠正。
- **选项 b（拒绝）**：把注入计数回灌 parser——与「计数留在调用点」冲突，且 `add_sse_event` 已是合成帧生产计数的单一来源。
- **实现形态**：`src/service/sse/parser.rs` 字段文档（:108-112）改为「解析层数据事件计数；注入帧生产计数唯一为 `GatewayMetrics::add_sse_event`」；**删除** `record_injected_event`（`parser.rs:176-177`，test-only，其唯一用途是伪造已不成立的两口径相等，保留会成为与新声明直接矛盾的 false affordance）。
- **测试**：`src/service/sse.rs:261-275` 的 `sse_event_count_consistency` 重写——push 2 个数据事件后 `sse_event_count == 2`；`add_sse_event()` 3 次后 `sse_event_total() == 3` 且 `sse_event_total() - sse_event_count == 1`（锁定声明差值）；SHALL NOT 再断言两口径逐帧相等。
- **规格**：`stream-fidelity-fix` MODIFIED「SSE 事件计数口径一致」（新）；R8-11/R8-14 由本 delta + README 计数口径修订（D13）闭环。

### D5（R8-16）`stream:true` + 上游 2xx 非 SSE 收窄为非流完整后处理链（Oracle 已裁决）

- **选项 iii（采纳，收窄的 fail-closed）**：`status<400` 且正文可解析为 JSON → 复用非流完整后处理链（用量 + 工具审计 + 还原 + 响应侧新 PII 掩码；审计命中 `Block` 以 `nonstream_block_body` 替换）；`status>=400` 错误体维持字节透传；2xx 非 JSON 正文维持字节透传 + warn + 计数。
- **理由**：审计与响应侧新 PII 掩码是安全控制不能 fail-open；正文已被有界读缓冲（受 `NONSTREAM_MAX_BYTES`），无新增放大；非流链零替换/零掩码时逐字节保真，仅确有阻断/掩码/还原时改变字节——该改变正是安全所需。
- **实现形态（由 D12 取代，签名与分支位置一律以 D12 为准）**：抽取 `pub(super) async fn process_upstream_response(up, ctx, req_conv, req_model)`；JSON/非 JSON 分支内置该函数（有界读体后分类）；`dispatch.rs` 流式分支为 `status_u16 >= 400` → 既有 `stream_upstream_passthrough`，否则 `NonstreamCtx{ stream_flag:false, non_json_passthrough:true, .. }` 无条件调新函数（2xx JSON → 完整链；2xx 非 JSON → 字节透传 + warn + 计数）。此处保留摘要，细节见 D12。
- **注意**：`should_pump_stream(json, true)` 为真，故新路径 `stream_flag` **必须传 `false`**，避免二次进入 SSE 泵判定；`NonstreamOutcome::Stream` 臂保留为防御性字节泵。
- **不得改动**：R7-05（非流请求 + 上游 SSE 复用已取得响应、不重发）、`status>=400` 错误体字节与状态透传、SSE 入泵路径（`status<400` 且 `text/event-stream`）。
- **R8-09 一并收敛**：dispatch 内联的上游头克隆改调 `nonstream::clone_upstream_headers`（提为 `pub(super)`），dispatch 侧保留 `strip_veil_internal_headers`。
- **规格**：`stream-fidelity-fix` MODIFIED「流式上游错误状态透传」；README §7.2 同步。

### D6（R8-18）`restore_guard` 对象键比较放宽但收紧结构（Oracle 已裁决）

- **规则（采纳）**：键集合不同时 SHALL 要求 (i) 条目数相等；(ii) 同名键仍逐键递归；(iii) 仅当占位符侧键为**完整 token 形态**（`__VG_CRED_<≥6 位>__` 或 `__PII_<seq>_<8 hex>__`）时才允许与还原侧「新增键」配对；(iv) 配对 SHALL 双射且与同名键集互补；(v) 容器类型 SHALL 同类（Object↔Object、Array↔Array）；MUST NOT 扩大既有 `_ => true` 兜底以接受类型漂移。
- **理由**：修复 R7-02 对象键入脱敏后「占位符键 ≠ 还原明文键」导致的守卫假阴性（进而触发 R8-03 泄漏）；健壮性来自 `(String,String)` 分支对 stringified JSON 的**解析**（真正破损仍被拒），键名放宽不改变 JSON 有效性判定。
- **实现形态**：改写 `restore_guard.rs::inner_json_intact` 的 Object 分支；新增私有 `is_token_shaped_key(k: &str) -> bool`（引用 `credential_vault::TOKEN_PREFIX` 与 `pii::detector::PII_TOKEN_PREFIX` 并校验**完整**形态）；Array/String 分支与 `restore_guard_ok` 签名不变。
- **不得改动**：`(String,String)` 的 stringified-JSON 递归、Array 长度/逐位比较、`_ => true` 兜底的既有适用范围。
- **规格**：`redaction` MODIFIED「残余帧 JSON 转义还原」。

### D7 无 delta 项登记（保证 19 项无遗漏）

- **R8-09**（上游头克隆+过滤重复实现）→ 并入 D5 的 G3 统一 helper，**行为不变**，无 delta。
- **R8-10/R8-11/R8-14**（`sse_event_count` 生产口径不成立 / 注释漂移 / test-only 符号被按生产口径引用）→ 见 **D4**：**已改为有 delta**（`stream-fidelity-fix`「SSE 事件计数口径一致」）+ parser 注释更正 + `record_injected_event` 删除；README 计数口径句修订见 **D13**。
- **R8-12**（README 符号锚漂移）→ 文档修正，**无 delta**（`check_doc_paths` 只校验符号存在，语义归属靠 README 更新）。
- **R8-19**（审查补充：canonical「Opaque 字段原字节透传」把 `thinking`（含 `thinking_delta`）整体列为 opaque，与实现的「纯 `thinking_delta` 走 `TokenCarry` + 掩码」分歧）→ 见 **D9** + `gateway-fidelity` MODIFIED「Opaque 字段原字节透传」，**有 delta**（借 R8-08 一并收敛并锁回归）。
- 说明：上述项在 `tasks.md` 中均有独立任务与验证，19 项发现逐项可追溯。

### D8 delta 形态与能力归属

- **MODIFIED（既有 requirement 更正）**：`stream-fidelity-fix`「流式上游错误状态透传」/「SSE 事件计数口径一致」；`llm-edge-gateway`「非流还原回退前残缺重试」；`gateway-fidelity`「流式还原 JSON 破帧防护」/「Opaque 字段原字节透传」；`redaction`「残余帧 JSON 转义还原」；`redaction-audit-coverage`「Responses 审计字节去重」；`stream-protocol-parity`「Overlong lines are marked not silently dropped」；`llm-protocol-hardening`「Responses 合成帧序号完整」。所有 MODIFIED 标题与 canonical 逐字一致（校验与归档按名匹配）。
- **ADDED（新覆盖）**：`redaction`「请求侧零替换字节保真」；`redaction-audit-coverage`「工具分桶单射与越界 index 归属」；`stream-protocol-parity`「终端后残余帧恒丢弃」/「上游终端帧即时送达」/「审计阻断后停止拉取上游」。
- **避免双真相源（互引）**：`gateway-fidelity`「流式还原 JSON 破帧防护」承载回退阶梯；`redaction`「残余帧 JSON 转义还原」承载单一 helper 与 `inner_json_intact` 语义；二者显式互引。终端/循环三条归 `stream-protocol-parity`，状态机细节引用 `architecture-cleanup` 的 `StreamTerminator` 单一所有者边界。
- **R8-05 归属说明**：`outer_event_index` 越界语义与 D6 同属审计记账正确性，归 `redaction-audit-coverage` ADDED「工具分桶单射与越界 index 归属」。

### D9（R8-08 定界 + R8-19）opaque 二分：签名/密文载体 vs 纯 `thinking_delta`（Oracle 已裁决）

- **裁定**：R8-08 仅作用于既有 opaque 臂谓词 `is_anthropic_opaque_event(v) && !is_anthropic_thinking_event(v)`——即**签名/密文载体帧**（`signature_delta`、`redacted_thinking`、携 `signature`/`redacted_data` 的 `thinking`/`content_block_start`）。**纯 `thinking_delta`**（`delta.type == "thinking_delta"` 且无 `signature`/`redacted_data`）SHALL NOT 视为 opaque，保持 `TokenCarry` 跨帧缝合 + `redact_response_new_pii_with_skip` 路径不变。
- **理由**：`event.rs:325` 的 `is_anthropic_thinking_event` 已表达该二分；canonical 原文把 `thinking`（含 `thinking_delta`）整体列为 opaque 属过宽，且与实现/README §7.11 冲突（R8-19）。若以裸 `is_anthropic_opaque_event` 为门会切断 thinking 缝合，回归 MSP-4/2.28。
- **实现形态**：抽出显式命名谓词（如 `is_anthropic_seam_transparent`）用于 hold 旁路，MUST NOT 复用裸 `is_anthropic_opaque_event`。
- **规格**：`gateway-fidelity` MODIFIED「Opaque 字段原字节透传」（opaque 集合收窄 + 纯 thinking_delta 独立段 + 跨缝句限定 + 新增 scenario）。
- **回归**：① `signature_delta` 与邻帧跨缝拼出 PII/hint → 字节恒等、未被 `mask_span_bytes` 改写；② 纯 `thinking_delta` 两帧跨缝拼出 PII → 命中被掩码且发生缝合；③ 既有 opaque 字节恒等用例（`restore_emit.rs::sse_protocol_roundtrip_invariants` K④）全绿。
- **谓词备注（Minor 6）**：`is_anthropic_thinking_event` 的 `delta` 分支（`event.rs:335-338`）仅判 `delta.type`、**不检查** `signature`/`redacted_data`（其上方 doc `:321-324` 声称检查，代码与注释本身已分歧）；故 opaque 载体枚举以**谓词**为准，`gateway-fidelity` 文本 SHALL NOT 引入「`delta` 为 `thinking_delta` 且携 `signature`/`redacted_data`」的子类（已移除）；该 doc/code 分歧登记为后续观察项（不属本 change 修复范围）。

### D10（R8-15）复合数组项桶函数（Oracle 已裁决）

- **裁定**：**不**复用/重载 `anthropic_bucket_index`（其 `(outer, block, fallback)` 语义与对象分支共用、返回值即块身份）。新增独立函数：

  ```rust
  /// R8-15：Anthropic 数组项复合桶键——块键 + 块内位置位域单射；
  /// item_index == 0 退化为纯块键（与对象分支等价）。
  pub(crate) fn anthropic_item_bucket(block_bucket: u32, item_index: u32) -> u32
  ```

- **位域方案**（保持 `< TOOL_BUCKET_OVERFLOW_BASE = 0xFF00_0000`）：`ANTHROPIC_ITEM_BASE = 1 << 24`、`ANTHROPIC_BLOCK_MAX = 1 << 16`、`ANTHROPIC_ITEM_MAX = 1 << 8`；`item_index == 0 && block_bucket < ANTHROPIC_BLOCK_MAX` → 返回 `block_bucket`（对象分支等价）；`block_bucket < ANTHROPIC_BLOCK_MAX && item_index < ANTHROPIC_ITEM_MAX`（`item_index >= 1`）→ `ANTHROPIC_ITEM_BASE | (block_bucket << 8) | (item_index - 1)`（上界 `0x01FF_FFFF < 0xFF00_0000`）；其余（含 `block_bucket >= ANTHROPIC_BLOCK_MAX`，避免 `block_bucket ∈ [ANTHROPIC_ITEM_BASE, OVERFLOW_BASE)` 时 `(block_bucket, 0)` 与 `(0, 1)` 桶碰撞）→ `warn` + `overflow_bucket(bucket_digest(((block_bucket as u64) << 32) ^ item_index as u64))`。
- **`outer_index` 存在的退化语义**：此时 `anthropic_bucket_index` 对同事件所有块返回同一块键（既有对象分支语义），`item_index` 成为唯一区分维度；Anthropic **非流消息解析**的常态为 `outer_index` 缺失、块键 = 块枚举位（逐块互异），注入性成立。
- **`block_bucket` 语义**：即调用点已算出的 `anthropic_bucket_index(outer_index, b, i)`——已按「外层 `index` > 块 `index` > 枚举位」编码块身份，故复合 `(block_bucket, item_index)` 等价 `(outer_index, content_block_index, array_item_index)`，无需改其签名。
- **调用点**：`tool.rs:327-334` 数组臂改 `custom_obj_to_call(emit_warn, anthropic_item_bucket(bucket, j as u32), item)`；对象臂 `custom_obj_to_call(emit_warn, bucket, obj)` 不变。
- **规格**：`redaction-audit-coverage` ADDED「工具分桶单射与越界 index 归属」（函数名与断言同步）。
- **测试**：同一事件两个 `content_block` 各含 2 项 `custom_tool_call` → 4 个 `ToolCall.index` 两两互异；`anthropic_item_bucket(bucket_i, 0) == bucket_i`；越界（`block_bucket >= 2^16` 或 `item_index >= 256`）落 `overflow_bucket` 保留带。

### D11（R8-08 守卫失败）opaque 字节恒等豁免（Oracle 已裁决）

- **裁定**：签名/密文载体帧守卫失败 → **字节恒等回退到掩码前占位符（上游原始帧）**，**不丢帧**（丢帧破坏签名连续性），并记 `warn` + `record_restore_fallback`（恰一次）。
- **理由**：opaque 臂以 `json_aware:false` + `placeholder = ev.data`（原始上游帧）运行，契约本就字节透明；D2 的 `mask_fallback:false` 即为此。若仍套用「SHALL NOT 回退未掩码上游原文」，归档后 canonical 与实现自相矛盾。
- **实现形态**：`RestoredFrame.mask_fallback:false` 时，守卫失败直接回退 `placeholder` 字节（不调用掩码）；纯 `thinking_delta` 与残余臂 `mask_fallback:true`，不享豁免。
- **规格**：`gateway-fidelity` 两条 requirement 互引 + `redaction`「残余帧 JSON 转义还原」指回豁免。

### D12（D5 抽取签名与分流位置）（Oracle 已裁决）

- **裁定**：签名为

  ```rust
  pub(super) async fn process_upstream_response(
      up: reqwest::Response,
      ctx: NonstreamCtx,
      req_conv: Option<String>,
      req_model: &str,
  ) -> NonstreamOutcome
  ```

  JSON-vs-非 JSON 分支**必须在该函数内部**（体在该函数内有界读取并分类；`up` 会被消费，dispatch 无法先读后传）。向 `NonstreamCtx` 增收策略位 `pub non_json_passthrough: bool`（`false`：原生非流保持 2xx 非 JSON → 502 `E_EMPTY_BODY`；`true`：`stream:true` + 2xx 非 SSE 分流，2xx 非 JSON → 字节透传 + warn + 计数）。
- **分支顺序**（函数内）：① `is_passthrough(ctx.req.protocol)` → `passthrough_upstream_response`；② `looks_sse = should_pump_stream(&resp_ct, ctx.stream_flag)`，`status<400 && looks_sse && !redact_only` → `Stream(up, req_conv)`（保留 R7-05 臂；dispatch 传 `stream_flag:false` 且已排除 event-stream，防御性不触发）；③ 有界读（`status<400` → `read_bounded_body`，`>=400` → `read_error_body_bounded`），`is_json = parse_json_bytes(&bytes).is_some()`；④ **新增且先于 `classify_empty`**：`status<400 && !is_json && ctx.non_json_passthrough` → `Responded(build_downstream_response(...))` + warn + 计数；⑤ `classify_empty`（原生 2xx 非 JSON/空体 → 502，语义不变）及其后 `redact_only`/JSON 完整链/`is_error_status`/NLP-6 全部原样。
- **调用方**：`dispatch.rs` 把 `status_u16 >= 400 || !is_event_stream(&resp_ct)` 拆为——`status_u16 >= 400` → 既有 `stream_upstream_passthrough`；否则 `NonstreamCtx { stream_flag: false, non_json_passthrough: true, .. }` 并无条件调 `process_upstream_response(up, ctx, rw.init_conv.clone(), &req_model)`（`req_model` 已在 `dispatch.rs:325` 就绪）。
- **`serve_nonstream` 保留**：`fwd_headers`、`req_value/req_conv/req_model` 快照（必须在 `fetch_upstream_with_retry` move `body` 前，`nonstream.rs:83-89`）、fetch + 失败 `empty_body_response`、`NonstreamCtx { non_json_passthrough:false, .. }` 装配，随后委托新函数；`NonstreamOutcome` 两臂复用。
- **规格**：`stream-fidelity-fix` MODIFIED「流式上游错误状态透传」。

### D13（M5/R8-14 + R8-16 文档）README 口径修订（Oracle 已裁决）

- **裁定**：`README.md` §7.2 两处必须改，登记为 **change 文档影响（no delta）**，配任务与可验证断言：
  - `README.md:671-673`：「`sse_event_count`、`add_sse_event()` 计数与转发帧数逐一致」改为「**无合成帧**的纯上游流下三者逐一致；注入合成帧（阻断/截断/真空终止）仅计入 `add_sse_event`，解析计数按 `stream-fidelity-fix`「SSE 事件计数口径一致」显式排除（声明与实现一致）」；同段 `spawn.rs` 锚改 `spawn/event_loop.rs`（并入 R8-12）。
  - `README.md:739-743`：「或 2xx 非 `text/event-stream` 正文一律按非流口径保状态与正文字节透传」改为「2xx 非 `text/event-stream` 且正文为 `application/json` 者走非流完整后处理链（用量 + 审计 + 还原 + 响应侧新 PII 掩码；审计命中 `Block` 以 `nonstream_block_body` 替换）；2xx 非 JSON 正文按字节透传状态与正文并记 warn 与计数；`status>=400` 及进入 SSE 泵路径口径不变」。
- **验证**：`grep -n "application/json" README.md` 命中新分流句；`grep -n "sse_event_count" README.md` 显示「无合成帧…显式排除」；`grep -n "pump/spawn.rs" README.md` 零命中。

## Risks / Trade-offs

- [D2 删除未掩码回退可能增加丢帧/502 概率] → 第二级掩码不破 JSON、实质必过；终点 fail-closed 优于泄漏；熵源故障由既有 502 `E_PII_UNAVAILABLE` 承接，负例测试锁定。
- [D5 改变既有「非 SSE 一律字节透传」口径，属用户可感知变更] → 仅 2xx JSON 分支、仅在确有审计/掩码/还原时改变字节；零命中逐字节保真；README/canonical 同批修订；非配置 BREAKING。
- [D3 提前终止可能丢失尾部 usage] → 阻断帧前事件的 usage 已在 `handle_event` 累计；尾部 usage 对已阻断响应无价值；测试锁定「已累计用量不丢失」。
- [D6 放宽键比较可能接受破损] → 条目数/双射/同类容器约束 + 负例测试（内层破损 + 键 token 化、条目数不等、类型漂移）锁定；`_ => true` 范围不扩大。
- [D1 与 D3 同改 `event_loop`/`terminal`，状态耦合] → G2 组内**串行**实施，每步跑目标用例。
- [R7 不变量回归] → 见下节回归矩阵。
- [D9 改动 canonical 的 opaque 分类] → 显式二分 + 三条回归（signature 跨缝不被改写 / thinking_delta 缝合与掩码 / K④ 字节恒等），确保 MSP-4/2.28 零回归。
- [D10 新桶函数位域与既有域冲突] → 上界 `0x01FF_FFFF < 0xFF00_0000` 且与低位块键域不相交；`item_index == 0` 等价对象分支，断言锁定。
- [D12 `non_json_passthrough` 策略位被误用] → 默认 `false` 保持原生 502 语义，仅 dispatch 新分支置 `true`；测试锁定两条路径分野。

## R7 不变量与既有承诺回归

- **R7-01（pending 恰一次）**：D3 提前终止使 `finalize` 更早运行但仍恰一次；补「阻断发生在 EOF 前，pending 槽仅终审一次、`release_pending_audited` 不二次执行」测试。
- **R7-02（对象键脱敏）**：D6 放宽不得扩大 `_ => true`；用「内层破损 + 键 token 化」负例锁死。
- **R7-05（非流 + SSE 复用、不重发）**：D5 抽取 `process_upstream_response` 时原样保留 `NonstreamOutcome::Stream` 臂与 `should_pump_stream` 判定；补回归。
- **R5-14（fail-closed）**：D2 终点必须是丢帧/502；熵源故障测试锁定。
- **R5-05/R5-43（上游 2xx 状态逐字）**：D5 只改非 SSE 分支；SSE 入泵路径不加门控、不改状态码。
- **R5-17（饱和约定）**：R8-04 统一 `saturating_add`。
- **字节守恒**：R8-01 改 `held_bytes()` 后补「`total_bytes` == `args_by_index` 各值长度之和 + 各 `responses_slots` `held_bytes()` 之和」守恒断言（`pending_bytes` 为独立维度、不计入），防 `release_*` 口径漂移。
- **R8-19（thinking 缝合）**：D9 仅对签名/密文载体旁路跨缝 hold；纯 `thinking_delta` 的 `TokenCarry` 缝合与响应侧掩码由回归测试锁定（`restore_emit` K④ + 新增「thinking_delta 仍参与跨帧掩码」「signature_delta 跨缝不被改写」）。

## Migration Plan

- 无配置/数据/schema/环境变量迁移；`git revert` 提交组即可回滚（无持久化影响）。
- D2/D5/D6 为安全修复型行为变更（更严）；R8-01/R8-04/R8-17 为正确性/字节保真修复；R8-12/R8-13 为文档/可观测。均不构成配置 BREAKING。

## Open Questions

- R8-13 的 `/_admin/metrics` 字段暴露若引发 admin 兼容测试成本过高，可降级为「仅 getter + 后续 change 暴露字段」（Oracle 允许）；本 change 默认两者都做。
- R8-16 的 2xx 非 JSON 分支是否需要独立指标（而非仅 warn + 计数）——本 change 不新增 admin 字段，登记后续候选。
- 归档复核项：R8-17 与 `llm-gateway`「上游 prompt cache 前缀保真」的措辞互引是否需在归档时合并登记。
