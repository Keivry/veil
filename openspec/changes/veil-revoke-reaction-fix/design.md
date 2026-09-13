## Context

`veil-residual-closeout` 落地 `S1` 后，紧急吊销转常规审批已接入 `approval_decision_closure` 决策闭环（`src/service/credential/vault_ops.rs:441-453`）。Oracle 终局复核该交付面时登记 `NEW-1`（本 change `T1`），并附带 `T2`/`T3` 已知局限。现状真相源：

- **`T1` 自动放行标志被丢弃**：`reaction_to_decision`（`src/service/matrix/branch.rs:170-175`）对 `MatrixBranch::Register | MatrixBranch::HashChange` 将 `🔓`（`REACTION_AUTO_UNLOCK`，`src/service/matrix/branch.rs:92`）映射为 `(true, auto=true)`；`from_reason`（`src/service/matrix/branch.rs:22-41`）把含「吊销/revoke」的原因归入 `Register`，故紧急吊销转审批票为 `Register` 分支，`🔓` 可落定为「批准且 auto」。闭环后台 waiter（`src/service/credential/approval.rs:299-303`）仅调用 `await_credential_approval`（`src/service/credential/approval.rs:382-388`）取 `Option<bool>`，**从不读取** `applied_auto`（`src/service/matrix/approval.rs:134`），随后 `clear_terminal_pending` 移除矩阵侧票并 `record_credential_decision` 记为 `Approved`（`src/service/credential/approval.rs:224-233`）。重试命中 `Decided(Approved)` 即执行注入的批准动作（`revoke_caller`）。**因 `clear_terminal_pending` 会移除矩阵侧票，`applied_auto` 必须在清理前读取，否则回读为 `None`。**
- **常规吊销路径已有 `!auto` 守卫**：`revoke_caller_with_approval`（`src/service/credential/vault_ops.rs:341-403`）在 `ask` 后读取 `applied_auto`，以 `decision == Some(true) && !auto` 才执行吊销；`🔓` 时返回 `403`（`src/service/credential/vault_ops.rs:381`、`:402`），注释明列「`❎`（含 `🔓`）」保持原状（`src/service/credential/vault_ops.rs:341-345`）。紧急路径缺同一守卫，两路径语义分歧。
- **测试缺口**：`emergency_revoke_async_202_closure`、`emergency_revoke_202_e2e`（`src/service/credential/vault_ops/tests.rs:556-760`）覆盖 `✅`/`❎`/超时/未决，未覆盖 `🔓`。
- **`T2` 无 single-flight**：`approval_decision_closure` 命中 `Decided(Approved)` 时在决策表之外执行动作（`src/service/credential/approval.rs:270-276`），无 per-key 动作锁；同一 `pending_key` 并发重试可各执行一次。
- **`T3` 审计单行口径**：`veil-residual-closeout` 的 `S4` 改为字段级限长后，单行不再严格 ≤4096（仅 10MB 轮转兜底）；`S4` 测试目录未先清理会读到陈旧首行。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 sibling change 目录；不引入新依赖；不改 `reaction_to_decision` 映射、不改注册路径、不改阻塞模式。

## Goals / Non-Goals

**Goals：**

- 给 `T1` 的可实施方案与可验证场景，使紧急吊销转审批的 `🔓` 与常规吊销路径一致地按拒绝处理（`403`、条目原状），`✅` 仍正常吊销。
- 把「吊销类审批排除自动放行」与「自动放行语义不外溢」收敛为 spec 契约。
- 为 `T2`（无 single-flight）、`T3`（审计单行口径/测试卫生）登记已知局限，声明本 change 不改动行为。

**Non-Goals：**

- 不改常规吊销路径的 `!auto` 守卫（已正确，仅对齐紧急路径）。
- 不改注册/哈希变更 `🔓` 的「保持原状」语义与 `apply_register_approval`。
- 不实现 single-flight、不加审计单行硬上限、不改 `S4` 测试清理（仅登记）。
- 不直接改写 sibling change 目录（`T2`/`T3` 仅在本 change 登记）。

## Decisions

### D1：`T1` 采纳**方案 a**——吊销类审批在闭环内排除 `auto`（`🔓` 视为拒绝）

**决策**：采纳方案 a。在闭环后台 waiter（`src/service/credential/approval.rs:299-303`）中，`await_credential_approval` 返回后、`clear_terminal_pending` 移除矩阵侧票**之前**读取 `applied_auto(&event_id)`；对声明为「拒绝自动放行」的 lane，在 `decision == Some(true) && auto` 时把落表决策改写为 `Denied`（而非 `Approved`）。

- `approval_decision_closure`（`src/service/credential/approval.rs:255`）增加 auto 策略参数：紧急吊销 lane 传 `Reject`（`Some(true) && auto` → `Denied`），凭据 lane 传 `Accept`（行为不变；其 `Credential` 分支本就不接受 `🔓`，`reaction_to_decision` 返回 `None`）。
- `emergency_revoke`（`src/service/credential/vault_ops.rs:444-454`）以 `Reject` 调用闭环。
- 三态对外不变：`✅` → 执行 `revoke_caller` 并返回成功（`revoked=true`、`enabled=false`）；`🔓`/`❎`/超时 → 重试 `403`；未决 → `202` 复用票。差异仅在 `🔓` 由「误批准」纠正为「拒绝」。

**关键实现约束**：`applied_auto` 必须早于 `clear_terminal_pending`（后者 `state.approval().remove(event_id)` 会移除带 `auto` 的矩阵侧票，之后回读恒 `None`）；落表改写须与现有 `record_credential_decision` 同批完成，避免重试窗口内状态不一致。

**理由**：改动面最小（仅 waiter 一处读标志 + 一个策略参数），与常规吊销路径 `!auto` 守卫语义一致，对凭据/注册/审计路径零行为影响；复用既有 `applied_auto` 观测，不新增状态。`🔓` 的语义是「保持原状」，对破坏性吊销不可作为批准。

**备选（登记，不采纳）**：
- 方案 b——把 `auto` 贯穿问询与决策表：将 `await_credential_approval` 扩为返回 `(bool, bool)`（或新增带 auto 变体），`DecisionTable` 存 `(decision, auto)`，在 `approval_decision_closure` 命中 `Decided` 时对吊销动作加 `!auto` 守卫。改动面大（问询签名、决策表项、阻塞路径调用点），收益与方案 a 等价；如后续需在决策层持久观测 auto 再立 change。
- 方案 c——在 `branch.rs` 对吊销票禁 `🔓`：`Register` 分支无法区分注册票与吊销票，需新增分支或按票改写映射，且会波及注册 `🔓` 保持语义，不采纳。

### D2：`T2` 无 single-flight——**登记为已知局限，本 change 不改**

**决策**：`approval_decision_closure` 命中 `Decided(Approved)` 时在决策表锁外执行批准动作（`src/service/credential/approval.rs:270-276`），同一 `pending_key` 的并发重试理论上可各执行一次（凭据重复取库 / 吊销重复落定；吊销动作 `revoke_caller` 于 `src/service/credential/vault_ops.rs:406-417` 对已吊销条目幂等，重复执行不产生二次破坏，但凭据双取与计时仍非严格单飞）。本 change 仅登记，不引入 per-key 动作锁或幂等执行框架。

**理由**：彻底 single-flight 需动作级锁/幂等语义，超出「修正 `🔓` 误触发」的最小修复边界；现有决策表 `begin`/`consume` 已保证「决策一次性落定」，缺口仅在动作执行层。若生产需要严格单飞，另立 change 并在其中设计 per-key 动作锁与并发用例。

### D3：`T3` 审计单行口径与测试卫生——**登记为已知局限，本 change 不改**

**决策**：`veil-residual-closeout` 的 `S4` 改为「字段级先脱敏后截断」，单行不再严格 ≤4096（多字段各自 ≤4096，总体由 10MB×5 轮转约束），此为设计声明的既定取舍；`S4` 测试目录未先清理会读到陈旧首行属测试卫生问题。本 change 仅登记，不恢复整行上限、不改测试清理。

**理由**：两项目均与 `🔓` 误触发无关，混入会扩大回归面；保持本 change 单一职责。

### D4：测试策略——`🔓` 纳入吊销 E2E，并锁定「不外溢」

**决策**：新增「`🔓` 于吊销票 → 不执行吊销且 `403`、条目原状」用例；在既有 `emergency_revoke_202_e2e` 基础上覆盖 `🔓`；补注册审批 `🔓` 维持 `disabled`、凭据/审计分支 `🔓` 不落定的回归断言。

**理由**：缺口之所以未被发现，正因四态测试未含 `🔓`；把 `🔓` 纳入同一 E2E 可在行为层锁定「与常规路径一致」，同时用注册/凭据回归防止修复外溢。

## Risks / Trade-offs

- [`🔓` 改写为 `Denied` 影响凭据 lane] → 策略参数按 lane 区分（吊销 `Reject`、凭据 `Accept`）；凭据分支不接受 `🔓`，以既有凭据 `202` 测试保绿锁定。
- [`applied_auto` 读取晚于清理恒为 `None`] → 明确要求先读后清；以「`🔓` 后重试 `403`」用例锁定读取时序，若时序错误该用例会退化为吊销成功而失败。
- [改写落表与矩阵清理不同批导致重试窗口异常] → 与 `record_credential_decision` 同 `tokio::spawn` 顺序执行（先读 auto → 清矩阵票 → 落表）；以「未决重试 `202` 不重复建单」既有断言防回归。
- [修复外溢到注册 `🔓`] → 不改 `reaction_to_decision` 与注册路径；以「注册审批 `🔓` 维持 `disabled`」回归用例锁定。
- [`T2`/`T3` 不修留下已知缺口] → 在 design 明示为已知局限并记录触发条件与后续处置建议；不在本 change 承诺行为变更，避免未验证的并发/日志语义回归。

## Migration Plan

1. 按 tasks 顺序落地：先 `T1` 闭环 auto 策略与 `applied_auto` 读取（安全修复），再回归用例，再 README §6.7 同步，最后门禁；`T2`/`T3` 仅 design 登记，无代码步骤。
2. `cargo test -p veil emergency_revoke_auto_reaction_rejected`、`emergency_revoke_202_e2e` 与既有 `emergency_revoke_async_202_closure` 全绿；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化；决策表与票据均为进程内状态，回滚无残留。
4. 发布口径：紧急吊销转审批的 `🔓` 由「不可逆吊销」纠正为「拒绝（`403`、条目原状）」，与常规吊销路径一致；下游可感知差异仅限误用 `🔓` 的场景。

## Open Questions

- 无。`T1` 已裁定采纳方案 a（方案 b/c 登记于 D1）；`T2`/`T3` 已登记为已知局限，处置建议留待后续独立 change。
