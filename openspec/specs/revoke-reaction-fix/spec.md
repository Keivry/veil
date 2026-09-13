# revoke-reaction-fix Specification

## Purpose
锁定 `veil-residual-closeout` 收口判定后登记的吊销反应误触发缺口（`T1`）的修复契约：紧急吊销转常规审批的决策闭环 SHALL 排除 `🔓`（`REACTION_AUTO_UNLOCK`）自动放行，使 `🔓` 与常规吊销路径一致地按拒绝处理（`403`、条目保持原状），`✅` 仍正常执行吊销；同时锁定「自动放行语义不外溢」，保证注册/哈希变更路径的 `🔓` 保持原状、凭据/审计分支 `🔓` 仍不落定。已知局限 `T2`（已批准动作无 single-flight）、`T3`（审计单行 4096 口径与测试卫生）仅登记于 design，不在本契约内变更行为。

## Requirements

### Requirement: 吊销类审批排除自动放行

系统 SHALL 在紧急吊销转常规审批的决策闭环中，将 `🔓`（`REACTION_AUTO_UNLOCK`，`auto=true`）落定的批准视为拒绝：SHALL NOT 仅凭 `decision == Some(true)` 执行 `revoke_caller`；SHALL 在矩阵侧票被移除（`clear_terminal_pending`）之前读取 `applied_auto` 标志，并在 `decision == Some(true) && auto` 时把决策落表为拒绝，使后续同一请求重试 SHALL 返回 `403` 且条目保持原状（`revoked=false`、`enabled` 不变）。系统 SHALL 使该行为与常规吊销路径的 `decision == Some(true) && !auto` 守卫语义一致，SHALL NOT 出现同一 `🔓` 反应在两条吊销路径上一条吊销、一条拒绝的分歧。

#### Scenario: `🔓` 反应不执行吊销

- **WHEN** 紧急吊销未命中管理 token / 文件在位（`file_present`）/ 内网来源三通道而转常规审批返回 `202`，审批人回复 `🔓`，随后客户端对同一请求重试
- **THEN** 重试返回 `403`，且注册条目保持原状（`revoked=false`、`enabled` 不变，未执行吊销）

#### Scenario: `✅` 反应正常吊销

- **WHEN** 紧急吊销转常规审批建单返回 `202`，审批人回复 `✅`，随后客户端对同一请求重试
- **THEN** 重试返回成功且注册条目 `revoked=true`、`enabled=false`

#### Scenario: 与常规吊销路径语义一致

- **WHEN** 相同的 `🔓` 反应分别落在常规吊销审批票与紧急吊销转常规审批票上
- **THEN** 两条路径均按拒绝处理（重试返回 `403`、不执行吊销），不出现语义分歧

### Requirement: 自动放行语义不外溢

系统 SHALL 保持 `🔓` 在注册/哈希变更分支上的既有「保持原状（不执行破坏性动作）」语义：注册审批票的 `🔓` SHALL 维持条目 `disabled`（不激活、不吊销），SHALL NOT 因本修复把注册路径的 `🔓` 改为拒绝或批准。系统 SHALL 保持凭据与审计分支不接受 `🔓`（`reaction_to_decision` 返回 `None`、不落定任何决议）的既有行为。

#### Scenario: 注册审批 `🔓` 保持原状

- **WHEN** 注册审批票收到 `🔓`
- **THEN** 条目保持 `disabled`（既不激活为 `enabled=true`、也不置 `revoked=true`），行为与修复前一致

#### Scenario: 凭据/审计分支 `🔓` 仍不落定

- **WHEN** 凭据或审计分支的审批票收到 `🔓`
- **THEN** 该反应不落定任何决议（`reaction_to_decision` 返回 `None`），行为与修复前一致

### Requirement: 已知局限登记

系统 SHALL 将「已批准动作无 single-flight（并发同 `pending_key` 重试可重复执行批准动作）」与「审计单行不再严格受限 4096（仅 10MB 轮转兜底）、`S4` 测试目录未先清理」登记为已知局限，SHALL NOT 在本契约内承诺对二者的行为变更；如需严格单飞或审计单行硬上限，SHALL 另立 change 交付。

#### Scenario: 已知局限显式登记

- **WHEN** 审阅本 change 的 design 与 spec
- **THEN** `T2`（无 single-flight）与 `T3`（审计单行口径/测试卫生）均被显式标注为已知局限且声明无行为改动，不被误认为本 change 的交付范围
