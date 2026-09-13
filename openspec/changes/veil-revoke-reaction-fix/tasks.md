## 1. `T1` 吊销类审批排除 `auto`

- [x] 1.1 `src/service/credential/approval.rs:299-303` 闭环后台 waiter 在 `await_credential_approval` 返回后、`clear_terminal_pending` 移除矩阵侧票之前读取 `applied_auto(&event_id)`；`approval_decision_closure`（`src/service/credential/approval.rs:255`）增加 auto 策略参数——吊销 lane 传 `Reject`，在 `decision == Some(true) && auto` 时把落表决策改写为 `Denied`（否则保持原决策）；凭据 lane 传 `Accept`（行为不变）；`emergency_revoke`（`src/service/credential/vault_ops.rs:444-454`）以 `Reject` 调用；`✅ (true, false)` 仍执行 `revoke_caller`
  - 验证：`cargo test -p veil emergency_revoke_auto_reaction_rejected` 通过；`🔓` 后重试 `403` 且条目 `revoked=false`、`enabled` 不变
  - 验证：`grep -n "applied_auto\|clear_terminal_pending" src/service/credential/approval.rs` 显示 `applied_auto` 读取先于 `clear_terminal_pending`
  - 验证：`grep -n "Reject\|applied_auto" src/service/credential/vault_ops.rs` 显示 `emergency_revoke` 以拒绝自动放行策略调用闭环
- [x] 1.2 补 `T1` 回归用例：吊销票 `✅` 正常吊销（`revoked=true`、`enabled=false`）；吊销票 `🔓` 复用 `emergency_revoke_202_e2e` 断言 `403` 且条目原状；注册审批 `🔓` 维持 `disabled`（不激活、不吊销）；凭据/审计分支 `🔓` 不落定
  - 验证：`cargo test -p veil emergency_revoke_202_e2e` 通过；含 `🔓` 场景且 `✅` 场景吊销生效
  - 验证：`cargo test -p veil emergency_revoke_async_202_closure` 与既有 `✅`/`❎`/超时/未决断言全绿（无回归）
  - 验证：注册审批 `🔓` 与凭据/审计 `🔓` 回归用例通过（自动放行语义不外溢）
- [x] 1.3 更新 README §6.7：写明吊销类审批票的 `🔓` 按拒绝处理（重试 `403`、条目原状）、`✅` 仍执行吊销，与常规吊销路径及注册审批 `🔓` 保持原状的口径一致
  - 验证：`grep -n "🔓" README.md` 在 §6.7 命中「吊销 `🔓` 按拒绝」口径

## 2. 已知局限登记（`T2`/`T3`，无行为改动）

- [x] 2.1 design D2/D3 登记已批准动作无 single-flight（锁外执行，并发同键重试可重复执行）与 `S4` 单行不再严格受限 4096（仅 10MB 轮转兜底）/`S4` 测试目录未先清理；明确本 change 不实现 single-flight、不加审计单行硬上限、不改测试清理，如需处置另立 change
  - 验证：`grep -n "single-flight\|4096\|测试目录" openspec/changes/veil-revoke-reaction-fix/design.md` 命中登记结论
  - 验证：spec「已知局限登记」requirement 的 Scenario 覆盖 `T2`/`T3` 两项且声明无行为改动

## 3. 门禁与回归

- [x] 3.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退（基线以 apply 时 `cargo test` 为准）
- [x] 3.2 `openspec validate veil-revoke-reaction-fix --strict` 0 failures；`python3 scripts/check_doc_paths.py` 退出码 0
  - 验证：`openspec validate veil-revoke-reaction-fix --strict` 输出 `is valid`
  - 验证：`python3 scripts/check_doc_paths.py` 输出 `OK` 且退出码 0
