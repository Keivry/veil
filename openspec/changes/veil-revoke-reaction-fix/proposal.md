## Why

`veil-residual-closeout` 落地 `S1` 后，紧急吊销未命中管理 token / 文件在位（`file_present`）/ 内网来源三通道时，已由裸 `record_pending` 改走 `approval_decision_closure` 决策闭环（`src/service/credential/vault_ops.rs:441-453`），实现「批准 → `revoke_caller`、拒绝/超时 → `403`、未决 → `202` 复用票」。Oracle 对 `veil-residual-closeout` 终局复核时登记了一处**破坏性误触发**缺口（`NEW-1`），并附带两项已知局限：

- **`T1`（MED，破坏性误触发）**：`🔓`（`REACTION_AUTO_UNLOCK`）在吊销票上被当作 `✅` 执行吊销。`reaction_to_decision`（`src/service/matrix/branch.rs:170-175`）对 `MatrixBranch::Register | MatrixBranch::HashChange` 将 `🔓` 映射为 `(true, auto=true)`——本意「保持原状」的自动放行；`from_reason`（`src/service/matrix/branch.rs:22-41`）把含「吊销/revoke」的原因归入 `Register` 分支，紧急吊销转审批票即属此列。闭环后台 waiter（`src/service/credential/approval.rs:299-303`）经 `await_credential_approval`（`src/service/credential/approval.rs:382-388`）仅取得 `bool`、**丢弃 `auto`**，随即 `clear_terminal_pending`（`src/service/credential/approval.rs:39`）移除矩阵侧票并把决策记为 `Approved`；同一请求重试命中 `Decided(Approved)` 即执行 `revoke_caller`。而常规吊销路径（`src/service/credential/vault_ops.rs:374-403`）显式读取 `applied_auto` 并以 `decision == Some(true) && !auto` 守卫，`🔓` 保持条目原状（`src/service/credential/vault_ops.rs:341-345` 注释明列「`❎`（含 `🔓`）」）。两条吊销路径对 `🔓` 语义不一致，紧急路径下一个误触反应即可不可逆吊销条目，且无二次确认。现有 `emergency_revoke_async_202_closure`、`emergency_revoke_202_e2e`（`src/service/credential/vault_ops/tests.rs:556-760`）覆盖 `✅`/`❎`/超时/未决四态，但**未覆盖 `🔓`**，缺口未被守护。
- **`T2`（LOW-MED，已知局限）**：已批准动作无 single-flight。决策表消费后动作在锁外执行（`src/service/credential/approval.rs:270-276`），同一 `pending_key` 的并发重试理论上可各执行一次批准动作（凭据重复取库 / 吊销重复落定）。本 change 仅登记，无行为改动。
- **`T3`（LOW，已知局限）**：`S4` 审计行改为字段级限长后，单行不再严格受限 4096（仅 10MB 轮转兜底）；且 `S4` 测试目录未先清理会读到陈旧首行。本 change 仅登记，无行为改动。

本 change 只交付规划 artifacts（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 sibling change 目录；真相源为 `src/service/matrix/branch.rs`、`src/service/credential/approval.rs`、`src/service/credential/vault_ops.rs`。

## What Changes

- **`T1` 吊销类审批排除 `auto`（采纳方案 a）**：闭环后台 waiter（`src/service/credential/approval.rs:299-303`）在 `await_credential_approval` 返回后、`clear_terminal_pending` 移除矩阵侧票**之前**读取 `applied_auto(&event_id)`；对声明为「拒绝自动放行」的 lane（紧急吊销）在 `decision == Some(true) && auto` 时把落表决策改写为 `Denied`，使重试命中 `Decided(Denied)` 返回 `403` 且条目保持原状。`approval_decision_closure`（`src/service/credential/approval.rs:255`）增加 auto 策略参数（吊销 `Reject`、凭据 `Accept`），`emergency_revoke`（`src/service/credential/vault_ops.rs:423-454`）以 `Reject` 调用；`✅ (true, false)` 行为不变。与常规吊销路径 `!auto` 守卫语义对齐。
- **`T1` 回归守护**：补 `🔓` 于吊销票 → 不执行吊销且返回 `403`；`✅` → 正常吊销成功（`revoked=true`、`enabled=false`）；注册审批 `🔓` 维持 `disabled`（不激活、不吊销）；凭据/审计分支 `🔓` 仍不落定。
- **README §6.7 同步**：写明吊销类审批票的 `🔓` 按拒绝处理、`✅` 仍执行吊销，与常规吊销路径一致。
- **`T2`/`T3` 登记**：仅落 design（D2/D3）为已知局限，声明本 change 不实现 single-flight、不加审计单行上限、不改测试目录清理。
- **Git 边界**：本 change 不改写 sibling change 目录（`veil-residual-closeout` 的 `NEW-1`/`NEW-3` 仅在本 change 登记）；如需 single-flight 或审计单行硬上限，另立 change。

## Capabilities

### New Capabilities

- `revoke-reaction-fix`：锁定吊销反应误触发缺口（`T1`）的修复契约——紧急吊销转常规审批决策闭环 SHALL 排除 `🔓` 自动放行（`🔓` 按拒绝 → `403`、条目原状），`✅` 仍正常吊销，且与常规吊销路径及注册 `🔓` 保持原状语义一致；并为已知局限 `T2`/`T3` 登记不改动契约。

### Modified Capabilities

- 无。`openspec/specs/` 既有契约不新增/修改；本 change 新增 capability 承载 `T1` 行为收敛，README §6.7 相关段随 apply 阶段与行为同批更新。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `T1` | MED（破坏性误触发） | 闭环 waiter 在 `clear_terminal_pending` 前读取 `applied_auto`；吊销 lane（`Reject`）将 `decision == Some(true) && auto` 改写为 `Denied` → 重试 `403` 且条目原状；`✅` 不变；补 `🔓`/`✅` 与注册/凭据回归 | 1.1、1.2、1.3 |
| `T2` | LOW-MED | 已批准动作无 single-flight（锁外执行，并发同键重试可重复执行）：仅 design D2 登记，无行为改动 | —（仅 design 登记） |
| `T3` | LOW | `S4` 单行不再严格 ≤4096（仅 10MB 轮转兜底）与 S4 测试目录未先清理：仅 design D3 登记，无行为改动 | —（仅 design 登记） |

## Non-Goals（显式）

- **不改常规吊销路径**：`revoke_caller_with_approval`（`src/service/credential/vault_ops.rs:341-403`）的 `!auto` 守卫语义不变，仅让紧急路径与之对齐。
- **不改注册/哈希变更 `🔓` 语义**：注册审批 `🔓` 维持条目 `disabled`（`apply_register_approval`，`src/service/credential/vault_ops.rs:238-258`），本 change 不触碰注册路径。
- **不实现 single-flight（`T2`）**：不引入 per-key 动作锁或幂等执行；仅登记。
- **不加审计单行硬上限、不改测试清理（`T3`）**：不恢复整行 4096、不改 `S4` 测试目录处理；仅登记。
- **不改写 sibling change 目录**：`veil-residual-closeout` 的登记项不在本 change 直接改写；本 change 只写自身目录。
- **不改 `reaction_to_decision` 映射与分支归类**：不动 `Register | HashChange` 的 `🔓` 映射（方案 c 登记不采纳），不动 `from_reason` 归类。
- **不改建单路径白名单与阻塞模式**：`CREDENTIAL_BLOCK_WAIT=1` 阻塞路径与建单白名单不变，仅收敛默认异步 `202` 闭环的 `🔓` 裁决。

## Impact

- **新增文件**：`openspec/changes/veil-revoke-reaction-fix/` 下 `proposal.md`、`design.md`、`specs/revoke-reaction-fix/spec.md`、`tasks.md`（`.openspec.yaml` 已存在）。
- **apply 阶段改动面**：`src/service/credential/approval.rs`（waiter 捕获 `applied_auto` + auto 策略参数）、`src/service/credential/vault_ops.rs`（`emergency_revoke` 传 `Reject`）、`src/service/credential/vault_ops/tests.rs`（`🔓` 用例）、`README.md` §6.7。
- **影响系统**：紧急吊销转审批的安全性（阻塞误触反应导致的不可逆吊销）；两条吊销路径的 `🔓` 语义一致性。凭据/注册/审计路径的 `🔓` 语义不受影响。
- **依赖**：无新依赖；复用 `approval().applied_auto`（`src/service/matrix/approval.rs:134`）与既有决策表设施。
