# Design

## Context

见 `proposal.md` → Why。影响本设计的既有约束：

- 本轮审计（r7）出现 **2 项 Major 运行时缺陷**（R7-01 审计 fail-open、R7-02 键位脱敏旁路）、4 项 Minor 行为/可观测缺陷（R7-03/R7-04/R7-05/R7-07）与 2 项 Minor 文档/可观测性缺口（R7-08/R7-09）；修复方向已由 Oracle 逐项裁决，本 change 不重新裁决（见 Decisions 的「Oracle 已裁决」标记）。
- canonical specs 为真相源，只能经 change 的 delta 修改（本 change 6 个 delta）；本 change SHALL NOT 手改 `openspec/specs/**`（归档时由 `openspec archive` 合并）。
- 终端帧发送与计数留在调用点：`architecture-cleanup`「流式阻断/终止帧注入单一所有者」要求 `StreamTerminator` 只产出计划，`set_truncated` 等计数在调用点执行——R7-03 的修复遵循该边界（计划携带观测，调用点落观测）。
- `release_audited()`（`src/service/audit/hold.rs`）现仅清理 `done_seen` 槽（`retain(|_, slot| !slot.done_seen)`），`!done_seen` 槽**不被移除**——这是 R7-01 恰一次语义的关键约束（若只在终端追加 pending 循环而不在全局完成臂释放，会双审）。
- `src/service/json_walk.rs::json_walk_nested` 的 Object 分支映射 `(k, v) => (k, json_walk_nested(v, ...))`，键位从不触达 leaf；请求侧（`scope.rs::redact_request`）与响应侧新 PII 扫描（`scope.rs:444`）共用 `json_walk::process_text`。
- `src/service/sse/meta.rs::set_truncated` 自带 Responses-only 守卫（`SynthesizedFailed && !protocol.is_responses()` 直接返 false），R7-03 的调用点无需再加协议门控。
- `src/handler/llm/dispatch.rs::gateway_serve` 流的非流分支用 `state.http_client`（`HTTP_TIMEOUT_SECS` 总超时）执行 `serve_nonstream`；`NonstreamOutcome::Stream`（`src/handler/llm/nonstream.rs`，`looks_sse && status<400 && !req.redact_only`）复用**已取得**的上游响应转字节泵，不重发请求。

## Goals / Non-Goals

**Goals:**

- 消除 R7-01/R7-02 两项 Major：Responses 截断 pending 槽在终端必审且恰一次；JSON 对象键位与值位同 leaf 口径脱敏，含碰撞回退。
- 收敛 4 项 Minor 行为/可观测缺陷：R7-03 截断观测、R7-04 协议门控、R7-05 超时口径声明、R7-07 测试专用收编。
- 修正 2 项 Minor 文档/声明缺口：R7-08 静默忽略语义、R7-09 字段名与豁免集。
- 6 个 delta 与 8 项发现一一可追溯；`openspec validate --strict` 通过。

**Non-Goals:**

- 不为非流遇 SSE 重发上游请求（见 D5）。
- 不引入 R7-08 的提取门控/告警/计数（见 D7；登记为后续候选）。
- 不重开 R7-06 等未纳入本轮决策清单的审计项（见 D10）。
- 不扩展 `scripts/check_doc_paths.py`（延用 r6 D1 边界）；不改 `agg` 切分、不新增下游响应头、不改任何配置默认值。

## Decisions

### D1 R7-01：全局完成臂释放 + 终端 pending 循环（Oracle 已裁决）

- **选项 A（采纳）**：两段协同——① `event_loop.rs` 全局完成臂审计 `responses_pending_triples()` 且未 `Block` 后，调用新增 `AuditHold::release_pending_audited()` 移除已判定 `!done_seen` 槽并归还字节（饱和算术，口径与 `release_audited` 的 `held_bytes` 一致）；② `terminal.rs` 终端最终审计追加 pending 槽循环（`protocol.is_responses() && !hold.is_rejected()`，done 槽在前、pending 槽在后），verdict 处置与 done 槽逐字一致（`Block` → `mark_rejected()` 且 `blocked_index` 取该 triple 自身 `output_index`；`NeedApproval` → 建 pending 记录；`Allow` → 无动作）。
- **选项 B（拒绝）**：只在终端追加 pending 循环——审计事实源显示 pending 槽在全局完成臂未被移除，清理完成流会在终端被**二次审计**（重复建单/重复计数），违反恰一次。
- **选项 C（拒绝）**：只在全局完成臂审计——中途截断（无全局完成）时 pending 槽永不评估，即当前 fail-open 缺陷本身。
- **恰一次论证**：两个 triple 集合在 `terminal.rs` 内互斥（`tool_triples` 的 Responses 部分为 done 槽，pending 为 `!done_seen`）；跨 `event_loop`/`terminal` 的重叠由释放消除——释放后终端 pending 集合为空。`Block` 时 `mark_rejected()` 已清仓，无需再释放；`NeedApproval`/`Allow` 均视为已判定并释放。
- **顺序**：done 槽先审、pending 槽后审；组内不承诺哈希序。

### D2 R7-02：键位 leaf + 碰撞回退（Oracle 已裁决，选项 A）

- **选项 A（采纳）**：Object 分支对键位调用 leaf（键按**纯字符串 leaf** 处理，MUST NOT 走 stringified-JSON 递归）；以**原始键集合**做碰撞回退——替换后键 `rk != k` 且与原始键或已选键同名时保留原键；结果 Map 成员唯一、插入序保持。
- **选项 B（拒绝）**：继续跳过键位并文档化——PII/凭据以键形态明文上游，且响应侧全文还原会命中键位 token（请求不问、响应却还原），属 fail-open。
- **选项 C（拒绝）**：键位也走 stringified-JSON 递归展开——键串是「名字」而非 JSON 文档位置，递归展开会把键结构改写并放大碰撞面，超出修复必要。
- **覆盖论证**：键串内嵌敏感子串由 leaf 的子串扫描覆盖（不递归）；token 形态键由注册侧 TokenShape 守卫跳过（原样保留）；键位替换使 `replaced` 置位 → 同置 `x-veil-normalized`；还原侧全文扫描已覆盖键位，无需新增路径。

### D3 R7-03：计划携带 `SynthesizedFailed`，调用点无条件落观测（Oracle 已裁决）

- **选项 A（采纳）**：`plan_responses_error` 返回 `truncated: Some(TruncatedMode::SynthesizedFailed)`；Responses error 臂解构 `truncated`，`commit` 后调用 `set_truncated`（无条件，镜像 terminal.rs::plan_midstream 调用点；`set_truncated` 自带 Responses-only 守卫）。`terminal_ok` 仍只决定 commit 的终端帧位/`terminal_injected`，不用于门控观测。
- **选项 B（拒绝）**：在 `plan_responses_error` 内直接写 `StreamMeta`——违反 terminal 状态单一写者与「计数/观测仍在调用点」的既有边界。
- **选项 C（拒绝）**：以 `terminal_ok` 门控 `set_truncated`——与中途断流调用点口径分裂（下游早断时截断观测丢失），且 README/canonical 声称的 `synthesized_failed` 仍可出现空窗。
- **不新增 helper**：调用点内联解构 + 一次 `set_truncated`，与 midstream 调用点同形。

### D4 R7-04：顶层 `system` 门控到 Anthropic（Oracle 已裁决）

- **选项 A（采纳）**：`extract_system` 中顶层 `system` 读取条件加 `protocol.is_anthropic()`；Chat 仅 `messages` 首条 `system`/`developer`；Responses 仅 `instructions`（不变）。同步修正代码注释与 README §7.3 为明确措辞。
- **选项 B（拒绝）**：保留双协议读取并文档化——Chat 请求多带一个非标准字段即静默换键，属会话键不稳定源，且 canonical 仅给 Anthropic `MAY 顶层 system`，没有 Chat 的说法。
- **delta 形态**：采用 ADDED 聚焦要求（见 D9），不重写 150 行的「会话键分层推导与租户命名空间」。

### D5 R7-05：声明为非流总超时语义（Oracle 已裁决，选项 B）

- **选项 B（采纳）**：声明「非流请求遇上游 SSE 经非流 client 总超时转发，超时按中途断流终端路径收尾；长流须显式 `stream:true`」，README §7.2 登记。
- **选项 A（拒绝）**：改用流式 client 重发/继续——上游请求已被消费、重发是非幂等第二次模型调用；且 `NonstreamOutcome::Stream` 已持有响应体，重发会双倍计费与语义错位。
- **选项 C（拒绝）**：非流遇 SSE 直接 502——新增 wire 行为，改变既有可用路径（短 SSE 响应原本可用）。

### D6 R7-07：`#[cfg(test)]` 收编（Oracle 已裁决）

- **选项 A（采纳）**：`dedupe_terminal_frames` 与 `count_done` 加 `#[cfg(test)]`，与已收编的 `terminal_count` 同口径；核查 `src/service/block_inject.rs` 门面重导出（glob `pub use {frames::*, terminal::*}` 随收编自动收窄；若存在显式重导出则同加 gating），以 `cargo build`（非 test）与 `cargo test` 双构建验证。
- **选项 B（拒绝）**：保持 `pub` 并加注释——本轮审计口径要求仅测试引用符号收编；注释登记不能替代 gating。
- 零生产行为变更：两个函数无生产调用点（grep 已核实），其字符串分派与 `_ => responses` 默认臂仅测试可见。

### D7 R7-08：README 声明静默忽略（Oracle 裁决二选一，采纳较低风险选项 b）

- **选项 b（采纳）**：README §7.3 明确「协议外原生键静默忽略（不命中、不告警、不计数）」；零运行时改动，不动键推导热路径。
- **选项 a（本轮拒绝，登记后续候选）**：提取侧按协议门控 + 出现协议外键时 warn/计数——会新增可观测面（计数需落 `observability-admin` 规范与快照/序列字段），对 Minor 项属扩大范围；且白名单结果两案一致，收益仅为告警。若后续需要可观测性，另立 change 交付。
- 不变量：**就第 2 级协议原生键白名单而言**，任何协议派生出的会话键 MUST 与本 change 前逐位一致（白名单结果不变）；第 3 级因 R7-04 的 `system` 门控产生的变化不在此不变量范围（避免与 R7-04 行为变更字面冲突）。

### D8 R7-09：精确字段名与完整豁免集（Oracle 已裁决）

- §7.2 缓存字段名：README 改为精确的 `cache_read_input_tokens`/`cache_creation_input_tokens`（实现指针 `src/service/llm_gateway/usage.rs::cached_columns`），delta 落 `stream-protocol-parity`「Model and cache columns restored」。
- §7.9 豁免集：README 补齐为 `{ } " [ ] , :`（或声明为有意保留的结构符超集）；delta 落 `redaction-audit-coverage`「跨缝掩码 JSON 结构保真」（该 canonical 已要求豁免集覆盖 `,`/`:`，README 属单侧遗漏）。
- 双侧同步（Momus m1/m2）：代码侧 doc comment 同为陈旧简写，须与 README 同批修订——`src/service/redaction/seam.rs:224`（旧集 `{ } " [ ]` → 完整集，与 `:226`/`:238` 一致）与 `src/service/llm_gateway/usage.rs:26`（简写 → 全名，与 `:39`/`:42` 一致）；delta 的「README 与实现 SHALL 同批修订，SHALL NOT 单侧漂移」据此可验收。

### D9 delta 形态与能力归属

- **ADDED（新覆盖）**：R7-01（`redaction-audit-coverage`，Responses pending 终端审计是既有 Chat 条款的协议补全）；R7-04+R7-08（`redaction`，聚焦「协议门控与静默忽略」，避免重写大 requirement 导致 scenario 丢失）。
- **Momus M1（双真相源）处理**：`redaction` ADDED requirement 的第 2 段不含白名单重述，改为**交叉引用** canonical「会话键分层推导与租户命名空间」（Anthropic/Chat 原生键禁令），本 requirement 仅承载新增的「静默忽略（不告警/不计数）」与 R7-04 的 Chat `system` 门控；避免同能力双真相源。
- **Momus M2（不变量措辞）处理**：ADDED requirement 与 D7 的「逐位一致」不变量均显式限定为**第 2 级协议原生键白名单**，排除 R7-04 第 3 级 `system` 门控导致的预期变化，消除与同 requirement 行为变更的字面冲突。
- **Momus m3（邻接互引）处理**：`redaction-audit-coverage` ADDED requirement 显式与既有「截断未完成 tool 落审计」条款分工互引（后者=审计/告警记录、前者=完整 verdict 通道 + 恰一次），SHALL NOT 视为重复。
- **MODIFIED（既有 requirement 更正）**：R7-02（`redaction` FIX-5：原文「不改变键名」被键位脱敏修正）；R7-03（`llm-protocol-hardening` 错误帧终端：Responses 截断观测由括号注升级为可验收 SHALL）；R7-05（`transport-fidelity-fix` 超时策略：补非流遇 SSE 分支）；R7-07（`deadcode-positional-cleanup` 零引用符号：补两个具名符号）；R7-09（§7.2 → `stream-protocol-parity`；§7.9 → `redaction-audit-coverage`）。
- **取舍说明**：`redaction`「会话键分层推导与租户命名空间」约 150 行（20 个 scenario），MODIFIED 需整段复制替换；R7-04/R7-08 采用 ADDED 聚焦要求，与既有 requirement 无冲突（既有句「Anthropic MAY 另取顶层 `system`」继续成立）。
- 所有 delta 的 MODIFIED requirement 标题与 canonical 逐字一致（校验与归档按名匹配）。

### D10 范围登记：R7-06 不重开

- R7-06（`redact_only` 进流式泵）不在本轮 Oracle 裁决与 task 清单内。基线 `src/handler/llm/nonstream.rs` 的转泵判定已含 `!ctx.req.redact_only` 守卫（`looks_sse && status_u16 < 400 && !ctx.req.redact_only`），`dispatch.rs` 的流式分支仅在请求显式 `stream:true` 时进入；本 change 不重新裁决，登记为后续复核候选（如需）。

## Risks / Trade-offs

- [R7-02 为可观测行为变更：键位 PII 由明文变为占位符] → 安全修复方向（fail-closed）；上游若以键名做语义判别会看到占位符键——属脱敏契约的应有覆盖面，登记于 delta 与 README §7.7 既有重序列化声明之下。
- [键位碰撞回退可能保留敏感原键（回退不替换）] → 仅在替换后键与原始键/已选键同名时发生；保留原键保证成员不丢失（fail-safe 优先于 fail-open 的替换冲突），场景由单测锁定。
- [R7-01 释放后终端不再兜底 pending] → 释放仅发生在全局完成臂已对全部 pending 槽完成 verdict 评估（无 `Block`）之后；`Block` 路径走 `mark_rejected()` 清仓。若实现漏调释放则表现为双审（可测），若漏调终端循环则表现为截断 fail-open（可测），两向均有回归用例。
- [R7-03 无条件落观测可能与「发送成功才置位」混淆] → 该约束（`stream-fidelity-fix`「截断合成发送成功才置位」）约束的是 `terminal_sent`/帧计数位；`truncated_mode` 观测在中途断流调用点本就无条件落。delta 明示二者边界。
- [R7-07 `#[cfg(test)]` 可能破坏非 test 构建的重导出] → 门面为 glob 重导出，随 `cfg` 自动收窄；若发现显式重导出则同加 gating，`cargo build` + `cargo test` 双验证。
- [R7-05 声明可能被误读为新增限制] → README 明示既有行为、零代码变更；长流建议显式 `stream:true`（既有独立 client 语义）。

## Migration Plan

- 无配置/数据/schema/环境变量迁移；`git revert` 单提交组即可回滚（无持久化影响）。
- R7-02 为安全修复型可观测变更（键位脱敏）；R7-01 为审计 fail-closed 修正（更严）；R7-03/R7-05/R7-08/R7-09 为观测/文档对齐。均不构成 BREAKING 配置迁移。

## Open Questions

- R7-08 选项 a（提取门控 + warn/计数）是否另立 change 交付——需评估 `observability-admin` 的计数面与快照字段；本 change 明确不作为。
- R7-06（`redact_only` 进泵）基线是否已由 `nonstream.rs` 的 `!ctx.req.redact_only` 守卫完全覆盖——本 change 不裁决，登记后续复核。
- R7-09 §7.9 的文档形态选择「列全 `{ } " [ ] , :`」还是「声明为有意保留的超集」——本 change 采用列全（与 `src/service/redaction/seam.rs::mask_span_bytes` 逐一对应）；如需改述为超集，须与 `redaction-audit-coverage` delta 同批修改。
- R7-03 下游早断观测双计（Oracle 复审 Minor，登记为已声明边界）：下游已断时 `commit(ResponsesError, frames_sent=false)` 留在 `Open`，`terminal.rs` 空流合成门可能再落一次 `set_truncated`，`truncated_count` 可能为 2。delta 明示「不低于一次」，且中途断流（`plan_midstream`）本为同型既有行为，故本 change 保持一致、不引额外行为变更；如需严格恰一，另立 change 在空流合成门加 `meta.truncated_mode.is_none()` 守卫（影响 midstream，超出本 change 范围）。
