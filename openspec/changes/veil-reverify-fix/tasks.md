## 1. `R1` 审计摘要先脱敏后截断与超长 PEM 零明文

- [x] 1.1 `src/service/audit/log.rs:44/53/55`：恢复「先脱敏后截断」——`sanitize_for_log` 固定为「剥控制字符 → `mask_secret_forms(完整输入)` → `truncate_chars(masked, 4096)`」；`mask_secret_forms` 移除首行 `truncate_ref_chars(s, AUDIT_SUMMARY_TRUNCATE_CHARS)`，改为在完整输入上扫描；以一次性小写预计算（`secret_kv_at` 复用）+ 单趟前向扫描保持近似线性，禁止逐位置重建整串小写
  - 验证：`cargo test -p veil summary_redacts_before_truncation_utf8_safe` 通过；断言 `sk-` + 9000×`a` + `尾` 的输出为 `[REDACTED:secret]尾` 且长度 ≤4096
  - 验证：`cargo test -p veil audit_summary_linear_bound` 通过（20 万字符对抗输入近线性完成，未回退 O(n²)）
  - 验证：`cargo test -p veil mask_secret_forms_large_input` 通过（接近 1MB 输入仍掩盖密钥形态且零明文）
- [x] 1.2 `src/service/audit/log.rs` 补 >4096 字符 PEM 回归：构造 `-----BEGIN PRIVATE KEY-----` + 超过 4096 字符的 base64 材料 + `-----END PRIVATE KEY-----`，断言整体置 `[REDACTED:private_key]` 且无 base64 明文
  - 验证：`cargo test -p veil long_pem_block_redacted` 通过；断言输出含 `[REDACTED:private_key]`、不含构造的 base64 材料
  - 验证：`cargo test -p veil audit_summary_forms` 与 `cargo test -p veil audit_summary_zero_plaintext` 通过（既有 PEM 短块与各形态不回归）
- [x] 1.3 保绿既有脱敏测试并锁定长输入逐字口径：`b9_deny_summary_dual_shapes`、`audit_summary_forms`、`audit_summary_zero_plaintext`、`audit_summary_linear_bound`、`mask_secret_forms_large_input` 全绿，且先脱敏后截断对未命中形态的长输入输出与旧口径逐字一致
  - 验证：`cargo test -p veil audit::log` 全绿

## 2. `R2` 异步 `202` 凭据审批消费闭环

- [x] 2.1 `src/service/credential/approval.rs`：新增进程内 `DecisionTable`（键 = `pending_key`，值 = 批准/拒绝/超时，容量有界、TTL 与 `PendingApprovals::PENDING_TTL_SECS` 同口径）；`approval_dual_mode:117` 非阻塞分支 `:125-127` 建单后 spawn 后台 waiter `ask(event_id, timeout)`，将 `Some(true)`/`Some(false)`/`None` 决策按 `pending_key` 落表后仍返回 `202`
  - 验证：`cargo test -p veil async_202_decision_table` 通过；断言后台 waiter 落定后决策表按 key 可查，未决/超时语义区分正确
- [x] 2.2 `src/service/credential/auth.rs:201/217` 与 `src/service/credential/vault_ops.rs:441`：入口先查决策表——批准 → 继续 `query_keepass` 返回凭据；拒绝/超时 → `403`；未决或无记录 → `202 + E_PENDING`；同一 `pending_key` 已有建单时复用，不重复建单
  - 验证：`cargo test -p veil async_202_retry_reuses_ticket` 通过；重试后 `state.approval.pending_len()` 不增、内存 pending 不重复插入
  - 验证：`grep -n "await_credential_approval" src/` 显示其接入消费路径或由 `DecisionTable` 取代，不再为生产零调用
- [x] 2.3 补 async-202 E2E 四态：建单 `202` → `✅` → 重试得凭据；`❎` → 重试 `403`；未决 → 重试 `202`；无回复至超时 → 重试 `403`
  - 验证：`cargo test -p veil async_202_e2e` 通过；四场景状态码与凭据返回符合 README §6.7

## 3. `R3` 审批建单路径规格与实现对齐（裁决 b：排除）

- [x] 3.1 在本 change design D3 与 spec「审批建单路径白名单」记录裁决 (b)：`audit-hold` 仅内存 pending（README §6.4）、`unlock`/`hash-change` 无 Matrix 建单路径，明确 `SHALL NOT` 建单及理由；登记 apply 写面（README §6.4/§6.7、sibling change 规范文本的后续修订），本 change 不直接改写 sibling 目录
  - 验证：`grep -n "裁决\|SHALL NOT" openspec/changes/veil-reverify-fix/design.md openspec/changes/veil-reverify-fix/specs/reverify-fix/spec.md` 命中排除口径与理由
- [x] 3.2 修订 `src/service/credential/approval/tests/f1.rs` 的 `audit_hold_approval_real_event_id` 命名/范围：改为反映通用 `MatrixBranch::Audit` 建单（如 `audit_branch_pending_uses_real_event_id`），或改走真实 audit-hold 路径并断言仅内存 pending；同步 README §6.4/§6.7 路径集合表述
  - 验证：`cargo test -p veil audit_branch_pending_uses_real_event_id` 通过；`grep -rn "audit_hold_approval_real_event_id" src/` 无旧误导命名残留
  - 验证：`grep -n "audit-hold\|hash-change\|unlock" README.md` 的路径集合表述与 spec 一致

## 4. `R4` 弱守护修正（F9/F10）

- [x] 4.1 `src/approval.rs:102/189` 与 `src/main.rs:122-123`：修正 F9 符号/路径引用（`init_no_sync_sweeper_observable` 在 `src/approval.rs`，非 `src/service/credential/approval.rs`）；把「无 spawn」断言升级为对生产 init 的结构化断言——默认构造 `sweeper_spawn_count()==0` 且不自启清扫，仅显式 `spawn_sweeper()` 递增，覆盖 `main` 构造/显式 spawn 时序
  - 验证：`cargo test -p veil init_no_sync_sweeper_observable` 通过；`grep -rn "init_no_sync_sweeper" src/service/credential/approval.rs` 无命中（幽灵路径消除）
- [x] 4.2 `src/main.rs:177/192/193`：F10 将 `preflight_probe` 改为调用可注入的真实启动序函数（副作用经注入计数可观测），或删除误导性 helper；保留并强化 `include_str!`（`:193`）白名单门禁排序检查（早于 `startup_tpm_in`/`init_sqlite`/`spawn_sweeper`）
  - 验证：`cargo test -p veil startup_whitelist_fail_fast` 通过；`grep -n "preflight_probe" src/main.rs` 显示其调用真实启动序函数已删除

## 5. `R5` 已知局限与命名登记

- [x] 5.1 design D5 登记：F7 TPM 同步子进程守护为名称/标记制（非调用图，`src/service/tpm.rs`/`src/main.rs` 整文件豁免可绕，防误用非防蓄意）；F8「analyzer」为测试键名（`src/service/pii/detector/tests.rs`），生产为全局 `ValidationCache`（`src/service/pii/detector.rs:427`）；无行为改动
  - 验证：`grep -n "F7\|F8\|ValidationCache\|名称/标记制" openspec/changes/veil-reverify-fix/design.md` 命中两条登记说明

## 6. 门禁与回归

- [x] 6.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 6.2 `openspec validate veil-reverify-fix --strict` 0 failures；`python3 scripts/check_doc_paths.py` 退出码 0
  - 验证：`openspec validate veil-reverify-fix --strict` 输出 `is valid`
  - 验证：`python3 scripts/check_doc_paths.py` 输出 `OK` 且退出码 0
