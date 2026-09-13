## 1. `S1` 紧急吊销转常规审批决策闭环

- [x] 1.1 `src/service/credential/approval.rs:244-292` 泛化 `approval_async_202` 接纳「批准动作选择」（凭据取库 `query_keepass` / 吊销 `revoke_caller`），共享 `DecisionTable`（`:140`）、后台 waiter `await_credential_approval`（`:346`）与 `clear_terminal_pending`（`:39`）；`src/service/credential/vault_ops.rs:441` 的紧急吊销未命中三通道分支由裸 `record_pending` 改走该闭环：批准执行 `revoke_caller`（`vault_ops.rs:410`）并返回成功、拒绝/超时返回 `403`、未决返回 `202 + E_PENDING` 复用既有票；吊销决策键（`pending_key`）由吊销定位键派生且稳定可复现；三通道豁免判据（管理 token / `file_present` / 内网）与凭据路径行为不变
  - 验证：`cargo test -p veil emergency_revoke_async_202_closure` 通过；批准后条目 `revoked=true`、`enabled=false`，拒绝/超时返回 `403`，未决返回 `202` 且 `pending_len()` 不增
  - 验证：`grep -n "record_pending" src/service/credential/vault_ops.rs` 在转审批分支不再命中（改由 `approval_async_202` 承载）
  - 验证：既有 `cargo test -p veil async_202` 全绿（凭据路径无回归）
- [x] 1.2 补 `S1` E2E 四态：转常规审批建单 `202` → 反应 `✅` → 同请求重试吊销生效；`❎` → 重试 `403` 且条目原状；无回复至超时 → 重试 `403`；未决 → 重试 `202` 且不新建第二单
  - 验证：`cargo test -p veil emergency_revoke_202_e2e` 通过；四场景状态码与条目状态符合 spec「紧急吊销转常规审批决策闭环」
  - 验证：`cargo test -p veil emergency_revoke_exemptions_and_approval_flow` 通过（三通道豁免保绿）
- [x] 1.3 design D1 登记采纳方案 a 及理由，并登记备选方案 b（修订 sibling spec 删除「及紧急吊销转常规审批入口」子句）为不采纳；明确本 change 不改写 sibling 目录、方案 b 如仍需要另立 change
  - 验证：`grep -n "方案 a\|方案 b\|采纳" openspec/changes/veil-residual-closeout/design.md` 命中采纳结论与备选登记

## 2. `S2` 已决无 waiter 票据 TTL 回收

- [x] 2.1 `src/service/matrix/approval.rs:263-281` 的 `sweep_orphans` 对 `e.decided.is_some()` 不再恒保留：按落定时刻施加有界回收 TTL（与分支 TTL 同族），或改为消费后移除语义；回收后 `GET /health` 的 `pending` 归零、矩阵侧待审批票数有界
  - 验证：`cargo test -p veil decided_ticket_ttl_reclaim` 通过；已决无 waiter 票超 TTL 后 `pending_len()` 下降、`health.pending` 归零
  - 验证：`grep -n "decided.is_some()" src/service/matrix/approval.rs` 显示已决票进入有界回收而非无条件 `retain`
- [x] 2.2 补回收测试：连续产生多张已决无 waiter 票并经多个清扫周期后，矩阵侧票数有界、不随产生次数单调增长；已决有 waiter 的正常消费路径不受 TTL 影响
  - 验证：`cargo test -p veil sweep_orphans_bounded` 通过；多周期断言票数上界与 `health pending` 归零
  - 验证：`cargo test -p veil pending_len` 相关既有测试全绿

## 3. `S3` 批准决策先取凭据后消费

- [x] 3.1 `src/service/credential/approval.rs:255-257` 调整为「先成功执行批准动作（`query_keepass`；`S1` 吊销路径为 `revoke_caller`）再消费决策表项」：把消费从 `DecisionTable::begin`（`:157-169`）的 `remove` 移出到动作成功之后，或动作失败时回滚重新插入 `Decided`；取库失败保留批准态使重试仍可执行
  - 验证：`cargo test -p veil approved_decision_fetch_failure_retry` 通过；首次取库失败后决策槽位仍为 `Approved`，重试成功返回凭据并消费
  - 验证：`cargo test -p veil async_202_decision_table` 通过（一次性消费语义在成功路径保持）
- [x] 3.2 补失败重试用例：模拟取库失败（如后端未解锁/瞬时错误）→ 已批准不丢 → 同请求重试取回凭据；成功后该决策被消费、不被后续重试复用
  - 验证：`cargo test -p veil approved_decision_not_lost_on_fetch_error` 通过；断言失败不丢批准、成功即消费

## 4. `S4` 审计 JSONL 超长仍合法

- [x] 4.1 `src/service/audit/log.rs:413-431 log_event` 改为序列化前对事件 JSON 所有字符串值（递归）执行「先脱敏后截断」限长（复用 `mask_secret_forms` 的脱敏与 `truncate_chars` 的 4096 口径，字段级应用），再 `serde_json::to_string`；移除对整行 `sanitize_for_log` 的调用（`:417`）；`sanitize_for_log`（`:44`）保留为整串摘要/通知入口，次序与 4096 口径不变
  - 验证：`cargo test -p veil audit_overlong_line_valid_json` 通过；构造序列化后 `>4096` 字符的事件，断言落盘行 `serde_json::from_str` 可解析且字段结构未因截断缺失
  - 验证：`grep -n "sanitize_for_log" src/service/audit/log.rs` 显示 `log_event` 不再对整行调用，整串入口保留
- [x] 4.2 补 `>4096` 事件「合法 JSON + 零明文」测试：自由文本字段含 `sk-` 长串，断言输出含 `[REDACTED:*]`、不含明文材料、且可被 `serde_json` 解析
  - 验证：`cargo test -p veil audit_overlong_zero_plaintext` 通过；断言零明文与合法 JSON 同时成立
  - 验证：`cargo test -p veil audit_summary` 相关既有测试全绿（整串口径不回归）

## 5. 门禁与回归

- [x] 5.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退（基线 `cargo test` 1080 passed）
- [x] 5.2 `openspec validate veil-residual-closeout --strict` 0 failures；`python3 scripts/check_doc_paths.py` 退出码 0
  - 验证：`openspec validate veil-residual-closeout --strict` 输出 `is valid`
  - 验证：`python3 scripts/check_doc_paths.py` 输出 `OK` 且退出码 0
