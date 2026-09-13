## Context

第三轮 Oracle 终局复核（2026-09-13）对 change `veil-reverify-fix` 交付面做收口判定，确认 4 项残留（`S1`–`S4`，见 proposal Why 与覆盖表）。现状真相源：

- **`S1` 紧急吊销转审批无消费方**：`emergency_revoke`（`src/service/credential/vault_ops.rs:423-442`）未命中管理 token / `file_present` / 内网三通道时，于 `:441` 返回 `Err(record_pending(state, key, "emergency_revoke转常规审批", "", None).await)`。`record_pending`（`src/service/credential/approval.rs:83-96`）只走 `submit_pending` 建单 + 抛 `202`，不 spawn 后台 waiter；重试不查 `DecisionTable`（`approval.rs:140`），故批准后吊销不执行、retry 恒 `202`。`approval_async_202`（`approval.rs:244-292`）的完整闭环仅被 `approval_dual_mode`（`approval.rs:317-333`）的凭据路径调用；sibling change `veil-reverify-fix` 的 spec「异步凭据审批消费闭环」子句原文含「及紧急吊销转常规审批入口」，其 SHALL 未兑现。现有测试 `src/service/credential/approval/tests.rs:121` 仅断言首次 `202`。
- **`S2` 已决票永久滞留**：`sweep_orphans`（`src/service/matrix/approval.rs:263-281`）对 `e.decided.is_some()` 恒 `return true`（保留），无 TTL；无 waiter 消费的已决票永久驻留 `pending`，`GET /health` 的 `pending` 不归零、矩阵侧票无界增长。与 `S1` 旧路径联动即复现。
- **`S3` 决策消费顺序**：`approval_async_202` 命中 `Some(BeginOutcome::Decided(CredentialDecision::Approved))` 时于 `src/service/credential/approval.rs:255-257` 直接 `return query_keepass(...)`；而 `DecisionTable::begin`（`approval.rs:157-169`）在返回 `Decided` 前已 `entries.remove(key)`（一次性消费）。取库失败则批准态已丢，客户端只能重新审批。
- **`S4` 审计行截断破 JSON**：`log_event`（`src/service/audit/log.rs:413-431`）先 `serde_json::to_string(event)`（`:414`），再 `sanitize_for_log(&line)`（`:417`）。`sanitize_for_log`（`:44-51`）末步 `truncate_chars(&masked, AUDIT_SUMMARY_TRUNCATE_CHARS)`（`:22` = 4096）。超长事件被从中间切断 → 非法 JSON 行（metrics JSONL 解析失败），无测试。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 sibling change 目录；不引入新依赖；阻塞模式与三通道豁免判据不动。

## Goals / Non-Goals

**Goals：**

- 给出 `S1`–`S4` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「紧急吊销转审批同一决策闭环」「已决票有界回收」「批准先取库后消费」「审计行超长仍合法 JSON」收敛为 spec 契约。
- 明确 `S1` 采纳推荐方案 a（接决策闭环）而非方案 b（删 spec 子句）及其理由；登记方案 b 与相关写面。

**Non-Goals：**

- 不直接改写 sibling change 目录（`S1` 方案 b 仅登记，见 D1）。
- 不改阻塞模式（`CREDENTIAL_BLOCK_WAIT=1`）语义。
- 不改脱敏 recognizer 形态集合与 `sanitize_for_log` 整串 4096 口径（`S4` 仅改字段级落点，见 D4）。
- 不改三通道豁免判据（管理 token / `file_present` / 内网来源任一即直接吊销）。
- 不引入跨请求持久化决策存储（`S1`/`S3` 复用进程内 `DecisionTable`）。

## Decisions

### D1：`S1` 采纳**方案 a**——紧急吊销转常规审批改走 `approval_async_202` 决策闭环

**决策**：采纳推荐方案 a。`emergency_revoke`（`src/service/credential/vault_ops.rs:423-442`）未命中三通道时不再裸 `record_pending`，改为走 `approval_async_202` 同一闭环，批准动作为 `revoke_caller`：

- 为承载「批准动作不同」（凭据取库 vs 吊销注册），把 `approval_async_202` 泛化为带**批准动作选择**的入口（如枚举 `ApprovedAction::FetchCredential{entry,field,use_token}` / `ApprovedAction::Revoke{key}`，或抽出同构的带动作变体），共享 `DecisionTable`、后台 waiter `await_credential_approval`（`approval.rs:346`）、`clear_terminal_pending`（`approval.rs:39`）与重试复用语义。凭据路径行为不变（`query_keepass`）。
- `emergency_revoke` 的决策键（`pending_key`）SHALL 稳定可复现：默认由吊销定位键派生（如 `revoke:<key>` 或注册表解析出的 `caller_path`），保证同一请求重试命中同一表项。
- 三态分派：批准 → `revoke_caller`（`vault_ops.rs:410`）返回成功（条目 `revoked=true`、`enabled=false`）；拒绝/超时 → `403`；未决 → `202 + E_PENDING` 复用既有票。
- apply 阶段补 E2E 四态（见 tasks 1.2）：`202` → `✅` → retry 吊销生效；`❎` → `403`；超时 → `403`；未决 → `202` 不重复建单。

**理由**：方案 a 使实现与 change `veil-reverify-fix` spec「异步凭据审批消费闭环」的 SHALL（含紧急吊销入口）一致，且复用既有决策表/waiter/清理设施，改动面最小；紧急吊销转审批的本质与凭据审批同属「建单 → 人工裁决 → 消费落定」，唯一差异是批准后的动作。方案 b（仅修订 spec 删除「及紧急吊销转常规审批入口」子句）会让规范迁就缺陷，且该入口的「批准后吊销不执行、retry 恒 `202`」是用户可感知的功能缺陷（止损通道在转审批场景失效），不应以删条款收场。

**备选（登记，不采纳）**：方案 b——修订 spec 删除紧急吊销入口子句并声明该场景不保证异步消费。仅在「转审批路径实际不可达」或「改造成本超过收益」时方可考虑；经复核该路径在生产可达（公网来源 + 无 token + 无文件），且改造复用既有设施，故不采纳。本 change 不改写 sibling 目录，如后续仍有需要，另立 change 并在其中修订 sibling 规范文本。

### D2：`S2` 已决票按 TTL 回收，`sweep_orphans` 不再恒保留已决票

**决策**：`sweep_orphans`（`src/service/matrix/approval.rs:263-281`）对 `decided.is_some()` 的票按其落定时刻施加有界回收 TTL（与未决票分支 TTL 同口径族：凭据类 `CREDENTIAL_TIMEOUT_SECS`、审计/解锁类 `ORPHAN_SWEEP_SECS`），或改为「消费后移除」语义（`clear_terminal_pending` 已覆盖有 waiter 路径，本项兜底无 waiter 路径）。回收后 `GET /health` 的 `pending` 归零、矩阵侧票数有界。apply 阶段补「已决无 waiter 票超 TTL 被回收」与「多周期后票数有界」测试（见 tasks 2.2）。

**理由**：已决票的决策终态已由消费方（`DecisionTable` / 内存 pending）承载，矩阵侧保留决定态仅用于 waiter 轮询命中，无 waiter 时无保留价值；恒 `retain` 使无界增长成为必然。TTL 回收与「消费后移除」二选一，priority 取风险最低、与既有清扫机制一致者（TTL 回收复用 60s 清扫循环）。

**备选**：把已决票改为立即移除——可能与仍在轮询的 waiter 竞态（反应与 poll 之间），不采用；不做改动——无界增长与 `health pending` 不归零保留，不采用。

### D3：`S3` 批准决策「先成功取库再消费」

**决策**：命中已批准时，先执行动作（凭据路径 `query_keepass`；`S1` 吊销路径 `revoke_caller`），**成功后**再消费决策表项；取库/执行失败时保留已批准态（不清表项），使同一请求重试仍按已批准执行。实现方式二选一：把「消费」从 `DecisionTable::begin` 内移出到动作成功之后，或在动作失败时回滚重新插入 `Decided`；priority 取不产生「消费—回滚」窗口者（即 begin 只读不消费 / 消费显式化）。apply 阶段补「取库失败后重试仍得凭据」用例（见 tasks 3.2）。

**理由**：`DecisionTable::begin`（`approval.rs:157-169`）当前在返回 `Decided` 前即 `remove(key)`，是「一次性消费」语义；对纯读取型动作无害，但当动作可能失败（取库需解锁/后端）时，先消费即丢批准。批准是稀缺人工结果，不应因下游瞬时失败白弃。

**备选**：取库失败返回 `500` 并让用户重新审批——浪费人工批准，体验差；把 `query_keepass` 纳入决策落定（waiter 内预取）——waiter 生命周期与凭据明文驻留内存扩大，不采用。

### D4：`S4` 审计行改为**字段级先脱敏后截断**再序列化，整串入口口径不变

**决策**：`log_event`（`src/service/audit/log.rs:413-431`）不再对序列化后的整行调 `sanitize_for_log`（`:417`），改为在序列化前走字段级处理：对事件 JSON 中所有字符串值（递归）执行「先脱敏后截断」——复用 `mask_secret_forms`（`:53`）的脱敏与 `truncate_chars`（`:366`）的 4096 字符截断，字段级应用——再 `serde_json::to_string`。由此落盘行恒为合法 JSON，且超长自由文本被限长、零明文。`sanitize_for_log` 保留为整串摘要/通知路径入口，其「先脱敏后截断」次序与 4096 口径不变（既有 `audit_summary_*` 测试保绿）。apply 阶段补 `>4096` 事件「`serde_json` 可解析且零明文」测试（见 tasks 4.2）。

**理由**：整行截断与 JSON 结构互斥——JSON 行必须在语义完整时才是合法值；把体积控制下沉到「自由文本字段」维度，既保结构又保零明文，且与 `AUDIT_SUMMARY_TRUNCATE_CHARS` 的「摘要文本上限」语义自然对齐。保留 `sanitize_for_log` 整串口径可避免波及审批摘要/Matrix 通知等既有调用点。

**备选**：仅检测超长并放弃写入——丢审计证据，不采用；对整行截断后补闭合括号——伪造/丢失字段，不采用；提高整行上限——超长仍可越界，只延后问题，不采用。

## Risks / Trade-offs

- [`S1` 泛化 `approval_async_202` 引入回归] → 凭据路径行为须逐字保持（批准取库/拒绝/超时/未决）；以既有 async `202` E2E 四态保绿 + 新增吊销 E2E 四态锁定。
- [`S1` 吊销决策键不稳定导致重试重复建单] → `pending_key` 由吊销定位键派生并要求可复现；以「未决重试不增 pending / 不重复建单」测试锁定。
- [`S2` TTL 回收与 waiter 竞态] → 回收 TTL 不短于 waiter 轮询窗口（与分支 TTL 同族）；以「已决有 waiter 正常消费 + 已决无 waiter 超 TTL 回收」两用例区分。
- [`S3` 消费显式化引入并发重复消费] → 决策表受 `Mutex` 保护，动作在锁外执行时需以「表项保留 + 幂等动作」避免双取；以重试用例与 `DecisionSlot` 观测锁定。
- [`S4` 字段级限长改变审计行体积口径] → 单行不再严格 ≤4096（多字段各自 ≤4096），总体由 10MB×5 轮转约束；以 design 声明与测试断言「合法 JSON + 零明文」为准，不承诺整行 ≤4096。
- [`S4` 递归处理漏字段导致明文残留] → 字段遍历须覆盖所有 JSON 字符串值（含嵌套对象/数组）；以「超长事件零明文」用例锁定。

## Migration Plan

1. 按 tasks 顺序落地：先 `S1` 决策闭环（功能可用性），再 `S2` 票据回收（资源上界），再 `S3` 消费顺序（幂等），最后 `S4` 日志保真，收尾门禁。
2. 每组独立 `cargo test -p veil <组>`；README §6.7 / §4 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化；决策表与票据均为进程内状态，回滚无残留。
4. 发布口径：`S1`/`S3` 恢复 README §6.7 承诺的异步三态（下游可感知：紧急吊销批准后重试生效）；`S2` 为运维可观测性修复（`health pending` 归零）；`S4` 恢复审计 JSONL 可解析性。

## Open Questions

- 无。`S1` 已裁定采纳方案 a（方案 b 登记于 D1）；`S2` 回收方式（TTL vs 消费后移除）在 apply 阶段以「与 waiter 无竞态」为裁决基线；`S3` 消费显式化的锁粒度在 apply 阶段以 `DecisionTable` 现状评估；`S4` 字段级限长的具体遍历点在 apply 阶段按字段集合确定，不改变零明文与合法 JSON 两条硬约束。
