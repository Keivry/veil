## Context

独立六维审查（2026-09-13）在 LLM 网关三协议流式面确认 11 项保真偏差（见 proposal Why 与覆盖表）。现状真相源：

- 抑制判据过宽：`src/service/audit/hold.rs:283` 的 `held()=!completed&&!rejected` 在流开始即为真；`src/handler/llm/pump/decide.rs:108-114` 的 `should_suppress_held_output(!minor, hold_held, out_data_nonempty)` 不含审计模式与 pending 判据；`src/handler/llm/pump/spawn/event_loop.rs:177-180` keepalive gate 与 `:532-538` 输出抑制同源（`S1`/`S8`）。
- 全局完成误判：`hold.rs:188-235` 的 `is_complete_event` 把 `response.output_item.done`/`response.function_call_arguments.done` 当全局完成，且 `hold.rs:116-122` 在 `completed` 后提前返回（`S2`）。
- 合成终端不 flush：`spawn.rs:258-284` 直接发送合成 `response.failed`，滞留帧拖到 `spawn.rs:642` EOF（`S3`）。
- 逐帧还原无跨帧缝合：`src/service/credential_vault.rs:40-51`、`src/service/pii/chunk.rs:124` 的残缺剥离、`src/service/redaction/leaf.rs:200-231` 的形态扫描、`spawn.rs:486-510` 的还原调用；`src/service/redaction/seam.rs:177-197` 仅掩码跨缝残片（`S4`）。
- 传输错误静默：`spawn.rs:162` `while let Ok(chunk) = upstream.chunk().await` 遇 `Err` 直接退出（`S5`）；断流终端与 `truncated_mode` 口径未固化（`S11`）。
- 流式错误被改写：`src/handler/llm/dispatch.rs:252-268` 的 `rw.stream_flag` 分支不看状态码一律转泵；`src/handler/llm/pump/event.rs:18-40` 的 `build_sse_response` 恒 200（`S6`）。
- 字节不回收：`hold.rs:88-96` 只累加，`clear_index`（`hold.rs:248-252`）与 `mark_completed` 不递减（`S7`）。
- 截断强制置位：`spawn.rs:603-630` 合成 `send` 失败仍置 `terminal_sent=true`（`S9`）。
- Python 审批挂起保活未迁移（`_llm.py:1948-1969`），Rust 流式审批不挂起（README §6.4）（`S10`）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 README；不碰审计 verdict 与脱敏 recognizer；不新增依赖。

## Goals / Non-Goals

**Goals：**

- 给出 `S1`–`S9`、`S11` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证；`S10` 以 Non-Goal 显式记录。
- 把「默认逐帧增量」「审计持有最小化」「Responses 槽级/全局完成隔离」「合成终端保序」「跨帧占位符缝合」「断流终端策略」「流式错误透传」「hold 字节回收」「截断置位守门」收敛为 spec 契约，README §6.4/§7.2/§8.6 与行为同批同步。
- 固化断流终端策略与 `truncated_mode` 口径（`S11`），消除「静默 EOF 无终止」与各协议口径漂移。

**Non-Goals：**

- **`S10` 不迁移 Python 审批挂起期独立保活**（`_llm.py:1948-1969`）：流式审批维持不挂起、不合成阻断帧（README §6.4）；恢复挂起语义需新 change 交付。
- 不伪造成功语义：断流不得合成伪造内容/usage，Anthropic 不补 `message_stop`，Responses 只出 `response.failed`。
- 不改审计 verdict 判定口径、脱敏 recognizer 集合与采样策略、usage `max` 口径、`stream_options` 注入合并语义。
- 不改 `src/` 实现与 README（本 change 只交付规划）；不提交 commit。

## Decisions

### D1：抑制与 keepalive 门控统一为「仅未完成 tool 分片」（`S1`/`S8`）

**决策**：`AuditHold` 新增 pending 判据（Chat/Anthropic：存在未在完成事件审计后释放的 `args_by_index` 分片；Responses：存在 `!done_seen` 的槽）。`decide::should_suppress_held_output` 改判 `audit_hold_on && hold.has_pending_fragments() && out_data_nonempty && !minor`；`spawn.rs:532-538` 调用点接线。完成事件审计后（允许与 `NeedApproval` 建单均算已判定）相关槽释放出抑制集；keepalive gate（`spawn.rs:213-216`）使用同一判据，`AUDIT_MODE=off` 时抑制恒 false（默认逐帧）。

**理由**：`held()` 表达「流级未完成」，无法区分「确有分片被持有」与「流刚开头」；默认 `off` 模式下 hold 仍累积分片（`spawn.rs:342-378` 不含模式判断），导致整条流被抑制。以 pending 分片为唯一持有信号，既不放松审计持有语义（tool 分片仍 hold-until-complete），又恢复文本帧逐帧增量；`NeedApproval` 语义是「建单不阻塞流」（README §6.4），故判定后必须释放，否则 approve 模式会持续抑制。

**备选**：保留 `held()` 仅加快照位（`completed` 初值改 true）——无法区分分片持有与流开头，且 `completed` 语义被污染，不采用；按协议分别打补丁——口径漂移复现，不采用。

### D2：Responses 全局完成收窄为三元，per-item done 走槽级审计（`S2`）

**决策**：`AuditHold::is_complete_event` 的 `matches!` 集合移除 `response.output_item.done`/`response.function_call_arguments.done`，加入 `response.incomplete`（与 `is_terminal_event` 的 `completed/failed/incomplete` 对齐）。新增槽级完成判定（`response.output_item.done`/`response.function_call_arguments.done`）：`spawn.rs:361-363` 改为槽级判据调用 `mark_responses_done` 并对该槽执行审计与清理；`spawn.rs:483-485` 的全局 `mark_completed` 仅由三元事件触发。

**理由**：`response.*.done` 是 per-item 槽完成，不是流完成；现行实现使首个 item done 即置全局完成，后续 item 因 `push_responses_fragment` 的 `completed` 提前返回而跳过累积与审计（危险参数逃逸）。全局完成仅认官方三元事件后，多 item 阻断在槽级命中，且与既有 canonical `llm-streaming-parity`「到 done 后审计」口径一致。

**备选**：保留 per-item done 为全局完成、仅在 `push_responses_fragment` 中去掉 `completed` 提前返回——全局完成仍提前置位，后续槽建槽逻辑与审批/finish 语义混乱，不采用。

### D3：合成终端前 flush 边界滞留帧（`S3`）

**决策**：`ResponsesAction::SynthesizeFailed` 分支（`spawn.rs:258-284`）与截断合成路径（`spawn.rs:620-629`）在发送终端帧前，先 `boundary.flush()` 把滞留内容帧并入 `agg` 并发送，再发送合成终端；终端后不再有数据帧。阻断路径维持既有 `agg.clear()/boundary.clear()`（阻断语义不释放危险内容），不走 flush。

**理由**：`[DONE]`/`[message_stop]` 终止路径已有 flush 先例（`spawn.rs:576`）；合成 failed 属失败终端，滞留帧是终端前的合法内容（还原/审计已放行），丢弃破坏保序；`response.failed` 先于末段 delta 会误导下游。阻断路径已显式清理且语义为「不泄漏参数」，保持 clear。

**备选**：合成前 `boundary.clear()`（丢滞留内容）——错误合成场景无阻断语义，丢内容属额外损失，不采用。

### D4：还原层跨帧 carry 缝合（`S4`）

**决策**：在流泵还原层（`spawn.rs:486-510` 调用点）维护请求级跨帧 carry：帧还原文本若以「占位符合法前缀的残缺形态」结尾（`__VG_CRED_`、`__PII_` 及 `[0-9A-Za-z_]*` 续段，形态判定复用 `cred_partial_re`/`pii_partial_re` 的前缀语义），则把该后缀从本帧移入 carry、不落盘；下一帧先与 carry 拼接再执行还原（凭证/PII token 由映射还原），随后检测新的帧尾残片；流结束（正常/截断/错误）时残余 carry 按既有 `strip_cred_partials`/`strip_pii_partials` 口径剥离。`src/service/redaction/seam.rs:177-197` 的跨缝掩码保留为第二道防线。

**理由**：SSE 帧是独立 JSON 对象，token 跨帧时两半分属不同 JSON 文本，无法在原始字节层缝合；在还原后的文本层拼接前缀与续段可命中完整 token 并还原明文，且不改变帧独立性（carry 长度有界：单 token 形态上限）。流末剥离保证未配对残片不外泄（fail-closed 不回退原文）。

**备选**：延迟整帧至下一帧（延迟大且需改帧边界）——不采用；依赖 `seam.rs` 掩码即可——只掩码不还原，实测明文丢失缺陷保留，不采用。

### D5：`chunk()` Err 显式分支与观测（`S5`）

**决策**：`spawn.rs:162` 的 `while let Ok(chunk)` 改为显式 `match`：`Err(e)` 记录 warn（含错误与已转发量）并置截断观测（经统一 `set_truncated` 与新增/复用指标），随后按 D6 终端策略收尾；`Ok(None)` 维持正常 EOF 路径。

**理由**：传输错误与正常结束当前不可区分，监控无信号；显式分支让截断可观测且终端策略有统一挂点。

### D6：断流终端策略固化（`S11`）

**决策**：

- **Chat**：中途断流（未发终端的异常 EOF 或 `chunk()` 报错）补发恰一 `data: [DONE]` 并记 `truncated_mode=open_ended`；已见 `finish_reason` 情形与既有 P1 补发口径合并实现（同一收尾路径，避免 `should_backfill_chat_done` 的 `truncated_mode_set` 条件竞态）。
- **Anthropic**：不合成 `message_stop`（不伪造成功终止），仅记 `open_ended` 观测。
- **Responses**：已发帧时合成恰一 `response.failed`（失败语义）并记 `synthesized_failed`；零帧时维持真空流最小终止（既有 `empty_stream_frames`）。
- 三协议终端恒恰一；README §7.2/§8.6 与本决策同批同步。

**理由**：`[DONE]` 是 Chat 传输层终止标记，可安全合成（不携带成功/内容/usage 语义）；Anthropic `message_stop` 是语义成功终止，断流合成属伪造成功，与「不伪造」原则冲突，故只观测；Responses `response.failed` 本身即失败语义，中途断流合成属如实归因。与既有真空流策略（三协议均补最小终止）衔接：真空流走 `empty_stream_frames`，中途断流走本策略。

**备选**：Anthropic 也补最小 `message_stop`（`stop_reason=null`）——语义上仍宣称消息成功闭合，且与 `error` 即终端口径混淆，不采用；Chat 不补——严格下游悬置（既有 P1 要消除的缺陷形态），不采用。

### D7：流式上游错误状态透传门（`S6`）

**决策**：`dispatch.rs:252-268` 在 `fetch_upstream_with_retry` 成功后先判定：上游 `status>=400` 或响应 `content-type` 非 `text/event-stream` → 读取正文字节并按原状态返回（与非流路径透传语义一致，受 `NONSTREAM_MAX_BYTES` 上限约束），不进入 SSE 泵；仅当 `status<400` 且 `content-type` 为 `text/event-stream` 时才走 `spawn_stream_pump` + `build_sse_response`。

**理由**：上游 4xx/5xx 的 JSON/HTML 正文是下游诊断真相，改写为 200 SSE 会让客户端把错误解析为流式成功；非 SSE 正文（如 HTML 网关页、空体）进入 SSE 泵同样产生假协议流。门控与非流路径「错误状态保状态保正文」一致。

**备选**：仅看状态码不看 `content-type`——2xx 非 SSE 仍会产生假流，不采用。

### D8：hold 字节按槽记账与回收（`S7`）

**决策**：`AuditHold` 为每个活跃槽记录字节并维护活跃总量；`clear_index`（Chat/Anthropic 槽清理）、Responses per-item done 的槽审计清理、`mark_completed`/`mark_rejected` 归还对应字节（拒绝/完成即归零）。溢出判定基于活跃字节：长流中多个已完成调用不再累积计入，真实超限（单调用活跃分片累计超 `AUDIT_HOLD_MAX_BYTES`）仍 fail-closed 并清仓。

**理由**：cap 的目的是约束未完成分片的无界累积；已完成并审计的槽字节滞留会随工具调用数线性增长并误判溢出。按槽记账使「同时活跃」与「历史累计」解耦，且回收点与 D2 的槽生命周期一致。

### D9：截断合成发送成功才置位（`S9`）

**决策**：`spawn.rs:603-630` 截断合成循环中，仅当 `pump_tx.send` 成功后才置位 `terminal_sent`（以及 `any_frame_sent`/转发计数）；全部发送失败（下游已断）时不置位，空流守门不被强制掩盖；`PumpOutcome` 如实反映未注入终端。

**理由**：`terminal_sent` 是「终端已实际下行」的真相位；发送失败即未下行，强制置位会让守门语义与观测失真（`terminal_injected`/metrics 撒谎）。下游已断时置位无实际收益。

### D10：`S10` Non-Goal 记录（不迁移 Python 挂起保活）

**决策**：`_llm.py:1948-1969` 的审批挂起期独立保活不迁移；本仓 `AUDIT_MODE=approve` 下危险调用转 pending 记录，不挂起流、不合成阻断帧（README §6.4 已声明）。spec「流式审批不挂起声明」为该行为契约；恢复 Python 语义需新 change 并撤回该声明。

## Risks / Trade-offs

- [`S1` 抑制收紧导致 tool 参数提前外泄] → 抑制仍要求 `audit_hold_on` 且存在未完成分片，hold-until-complete 与阻断语义未动；`AUDIT_MODE=off` 本就不审计，透传符合语义。回归覆盖 block/approve 两模式。
- [`S2` 槽级审计时机提前] → 审计结论时点由全局完成提前到 per-item done，与 canonical `llm-streaming-parity`「done 后审计」一致；既有 e2e 断言（如 `tests/http_e2e_truncation_matrix.rs`）需随口径更新。
- [`S3` flush 合成终端] → 错误场景下滞留帧可能是半截 token；与 `S4` carry/剥离配合，先落帧沿既有残缺清理，不新增泄漏面。
- [`S4` carry 延迟一帧] → token 跨帧时该前缀延迟到下一帧才输出，最大延迟一帧、长度有界；异常流末尾残余按残缺剥离，不泄漏原文。与 `PII_FUZZY_RESTORE` 等开关无耦合。
- [`S5`/`S11` 终端策略变化影响既有测试] → Chat 中途断流从 open-ended 改为补 `[DONE]`；Anthropic 维持不补；Responses 已发帧补 `failed`。README §7.2/§8.6 同批声明，`truncated_mode` 观测保留供监控感知。
- [`S6` 错误体读取上限] → 非 SSE/错误体沿用 `NONSTREAM_MAX_BYTES` 上限；超限行为按非流口径处理，避免大体积错误体拖垮网关。
- [`S7` 回收与审计数据保留的边界] → 已审计槽在清理时回收字节；若后续需要全局复核，审计结论/记录已落，数据保留与容量解耦。
- [`S8` keepalive 行为变化] → 无分片流恢复周期保活，长 thinking 流依赖保活的下游行为更稳定；有分片时维持抑制（原意）。
- [`S9` 置位收紧] → 下游已断场景无实际影响；`PumpOutcome` 观测更如实，依赖 `terminal_injected` 的测试需核对。

## Migration Plan

1. 按 tasks 顺序落地：先判据与槽位（`S1`/`S8`/`S2`/`S7`），再保序与缝合（`S3`/`S4`），再观测与终端（`S5`/`S11`/`S9`），最后透传（`S6`）与记录（`S10`）。
2. 每组独立 `cargo test`；README §6.4/§7.2/§8.6 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；下游可感知的行为变化（逐帧增量、断流补 `[DONE]`、错误状态透传、Responses 中途断流补 `failed`）由 README §7.2/§8.6 声明。

## Open Questions

- 无。`S1`–`S9`、`S11` 均已裁定；`S10` 为显式 Non-Goal。若 apply 阶段实测 Anthropic/Responses 严格 SDK 对中途断流补帧有额外要求，以 spec「中途断流终端策略」Scenario 为准补充并回到本 design 记录差异。
