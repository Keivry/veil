## 1. `C1` 注册审批链恢复（三态与超时）

- [x] 1.1 `src/service/credential/vault_ops.rs:181-224` `register_caller_extended` 注册成功后创建审批单（`MatrixBranch::Register`，携带 `reg_id` 与 `caller_path`），复用双模口径：默认返回 `202` 抛单，`CREDENTIAL_BLOCK_WAIT=1` 时阻塞等待 300s；不再把「落盘返回」视为注册完成
  - 验证：`cargo test -p veil register_requires_approval` 通过；默认模式注册返回 `202` 且 `state.pending.len()` 增 1；阻塞模式在 reaction 前不返回
- [x] 1.2 三态落定实现：`🔓 (approved=true, auto=true)` 保持 `disabled`；`✅ (true, false)` 调 `set_enabled(true)`；`❎ (false, _)` 与等待超时置 `revoked=true`；落定消费 `ReactionOutcome::Applied` 的 `auto` 标志并回写对应条目
  - 验证：`cargo test -p veil register_approval_three_state` 通过；三态与超时各断言 `enabled`/`revoked` 终值；超时后取用被拒
- [x] 1.3 README §6.7/§7.5 同步注册审批链口径（默认 `202` 抛单、`CREDENTIAL_BLOCK_WAIT=1` 阻塞 300s、超时吊销）
  - 验证：`grep -n "注册审批" README.md` 命中新增段落且不再声称注册直接生效

## 2. `C2` 吊销审批确认

- [x] 2.1 `src/service/credential/vault_ops.rs:226-237` `revoke_caller` 接入审批链：常规吊销建单（`reg_id`/`caller_path`），`✅` 后执行 `revoked=true`；`❎`/超时保持条目原状；`MatrixBranch::from_reason` 补「吊销/revoke」到 `Register` 分支映射
  - 验证：`cargo test -p veil revoke_requires_approval` 通过；未获批准时条目状态不变且 `202` 建单；批准后 `revoked=true`
- [x] 2.2 README §7.5 登记常规吊销需确认与紧急吊销旁路分工（管理 token/文件在位/内网三通道）
  - 验证：`grep -n "吊销" README.md` 命中审批确认与旁路说明

## 3. `C3` 哈希变更三态与 handler 契约

- [x] 3.1 `src/registry/store.rs:292-313 approve_hash_change_with_script_sha256` 补三态落定参数：`🔓` 保持 `allow_mode` 不变；`✅` 置 `allow_mode = Some(AutoApprove::Pending)`（人工）；`❎` 置 `enabled=false`；三态均写 `old_hash`/`old_hash_expires_at`/`script_sha256`
  - 验证：`cargo test -p veil hash_change_three_state` 通过；三态后 `allow_mode`/`enabled`/`old_hash_expires_at` 终值符合 design D3
- [x] 3.2 `src/handler/credential.rs:352-366 approve_hash_change_handler` 增 `reg_id`/`reaction` 可选入参：`reg_id` 缺省回退 `caller_path`，`reaction` 缺省按保持自动；`serde(default)` 不因缺参返回 `400`
  - 验证：`cargo test -p veil approve_hash_change_handler_contract` 通过；缺 `reg_id`/`reaction` 行为与既有等价、返回成功
- [x] 3.3 README §6/§7.5 登记哈希变更三态语义与 `reg_id`/`reaction` 契约
  - 验证：`grep -n "哈希变更" README.md` 命中三态描述

## 4. `C4` 生产旧格式迁移接入

- [x] 4.1 `src/registry/store.rs:167-185 load_from` 接入旧格式一次性迁移：新格式解析/完整性失败且含 `version/callers` 旧形态时调 `migrate_python_registry`（`.bak` 备份 fail-closed → 写回新格式 → 返回内存态）；`src/registry/migrate.rs` 迁移函数去掉生产零引用的 `#[cfg(test)]` gating
  - 验证：`cargo test -p veil load_from_migrates_legacy` 通过；旧格式样例加载成功、`.bak` 存在、文件已为新格式；`grep -rn "migrate_python_registry" src/registry/` 命中生产调用
- [x] 4.2 README §5/§7.5 文档化迁移时机（加载期一次性）、`.bak` 备份与只读挂载 fail-closed 行为
  - 验证：`grep -n "旧格式" README.md` 命中迁移说明

## 5. `C5` 按名吊销/重名 409

- [x] 5.1 `src/registry/store.rs:224-271` 注册判重扩展：`path` 已存在或 `name` 非空且与未吊销条目重名 → `Conflict`；新增按 `name` 定位（未吊销集合内至多一条）；`src/handler/credential.rs:280-299 RevokeBody`/`revoke_key` 增 `name` 字段并纳入解析顺序
  - 验证：`cargo test -p veil register_duplicate_name_409` 与 `cargo test -p veil revoke_by_name` 通过；同名注册 409、`{"name":...}` 吊销命中、吊销后同名可复用
- [x] 5.2 README §5 登记 `get revoke --name` 与重名 409
  - 验证：`grep -n "重名 409" README.md` 命中

## 6. `C6` lock/forget 清理接线

- [x] 6.1 `src/service/matrix/bot.rs:170-201` 文本指令处理接入网关侧清理：`lock` 清口令缓存 + KeePass 会话 + 内存 pending（`clear_all`）+ 矩阵 pending（`lock_reject_all`/`lock_clear_all`）+ PII scope；`forget` 清 token 映射并以真实条数回执（替换固定 0）
  - 验证：`cargo test -p veil lock_clears_vault_and_pending` 通过；lock 后凭据取用失败、pending 清零；`cargo test -p veil forget_clears_token_map_counted` 通过；回执计数与清理数一致
- [x] 6.2 README §8.4 更新 lock/forget 行为声明（清理范围与回执口径）
  - 验证：`grep -n "lock" README.md` 命中清理接线说明

## 7. `C7` 审批票 TTL/清扫统一

- [x] 7.1 `src/service/matrix/approval.rs:233-240 sweep_orphans` 清扫语义统一：存在阻塞等待者的未决票在阻塞超时（300s）前不被删除（按分支 TTL：`Register`/`HashChange`/`Credential` 取 `CREDENTIAL_TIMEOUT_SECS`，`Audit`/`Unlock` 维持 60s）；保持无等待者孤儿票回收
  - 验证：`cargo test -p veil blocking_ticket_survives_60s_sweep` 通过；建单后推进测试时钟越过 60s，`resolve` 仍可解除阻塞并返回凭据
- [x] 7.2 design.md D7 记录 TTL 统一决策与备选（全局 300s / `waiting` 标记）
  - 验证：`grep -n "C7" openspec/changes/veil-credential-flow-parity/design.md` 命中「阻塞票」决策

## 8. `C8` 双 pending 表原子清理

- [x] 8.1 抽统一终态清理：`src/service/credential/approval.rs` 在 `ask` 返回拒绝/超时路径同时清内存侧（`state.pending().remove(key)`）与矩阵侧；批准路径同批清理；注册/吊销/哈希变更落定终态同批；`GET /health pending`（`src/handler/mod.rs:26`）即时一致
  - 验证：`cargo test -p veil pending_tables_atomic_cleanup` 通过；`ask` 超时/批准后 `state.pending.len()==0` 且 `approval.pending_len()==0`
- [x] 8.2 README §4 阈值表复核 health pending 口径（终态即时清理，非 60s 延迟）
  - 验证：`grep -n "pending" README.md` 命中一致性说明（若判定无需新增条款，由 design D8 记录理由）

## 9. `C9` TPM 并发隔离

- [x] 9.1 `src/service/tpm.rs:165-210 unseal` 工作目录改每次调用唯一（`veil-tpm-{pid}-{nanos}-{seq}`，`seq` 为进程内原子计数），`Guard` 继续成功/失败清理；不引入全局锁串行化
  - 验证：`cargo test -p veil tpm_concurrent_unseal_isolated` 通过；并发多次解封全部成功、工作目录互不相同、无中间对象覆盖
- [x] 9.2 清理语义回归：成功/失败/提前返回路径均不残留临时目录
  - 验证：`cargo test -p veil tpm_tempdir_cleanup` 通过

## 10. `C10` 审批消息可读上下文

- [x] 10.1 `src/service/credential/approval.rs:30-51 submit_pending` 摘要补条目/字段/调用方元数据（签名扩展接收 `entry`/`field`，`approval_dual_mode` 传入）；敏感值不落消息
  - 验证：`cargo test -p veil approval_message_context` 通过；消息含 `entry`/`field`/`caller_path`，不含凭据明文与 Secret
- [x] 10.2 README §6.7/§7.5 登记审批消息内容口径
  - 验证：`grep -n "审批消息" README.md` 命中

## 11. `C11` 限流维度裁决落地

- [x] 11.1 按 design D11 裁决保留按调用方维度（`caller_path:caller_hash` 2s；注册按 `source` 1s），补跨调用方隔离测试与同调用方 `429` 测试
  - 验证：`cargo test -p veil credential_rate_per_caller` 通过；同一调用方窗口内第二次 `429`，另一调用方不受影响
- [x] 11.2 README §3/§4 登记相对 Python 全局单桶的有意差异与回退条款（另立 change）
  - 验证：`grep -n "限流" README.md` 命中维度差异声明

## 12. `C12` 旧哈希宽限语义登记

- [x] 12.1 文档化 Rust 修正（真置 `now+3600` vs Python 死码）并补边界测试：宽限内旧 hash 可用、`old_hash_expires_at` 后失效
  - 验证：`cargo test -p veil old_hash_grace_window` 通过；`exp - 1s` 可用、`exp + 1s` 失效
- [x] 12.2 design.md D12 记录 `C12` 为正向修正（含 `src/registry/entry.rs:40`/`:53-62` 证据）
  - 验证：`grep -n "C12" openspec/changes/veil-credential-flow-parity/design.md` 命中

## 13. `C13` 紧急吊销网段裁决落地

- [x] 13.1 按 design D13 裁决保留现有网段（`localhost`/`::1`/`127/8`/`10/8`/`172.16/12`/`192.168/16`/`169.254/16`/`100.64/10`/`fd00::/8`/`fe80::/10`）与 `file_present`，补放行/拒绝网段测试与代理头不可伪造测试
  - 验证：`cargo test -p veil emergency_revoke_network_ranges` 通过；各放行网段直接吊销、公网来源转审批、伪造 `X-Forwarded-For` 无效
- [x] 13.2 README §7.5 列明网段清单与「只认 TCP 远端」声明
  - 验证：`grep -n "169.254" README.md` 与 `grep -n "100.64" README.md` 命中

## 14. `C14` 注册表存储语义裁决落地

- [x] 14.1 `src/registry/store.rs:115-140 write_atomic` 补 fsync：tmp 写完 `sync_all`，rename 后父目录 fsync；fail-closed 完整性校验与 `BTreeMap` 稳定排序保留并文档化
  - 验证：`cargo test -p veil registry_write_fsync` 通过（含落盘失败注入路径）；损坏文件加载返回 `Err` 不回落空表
- [x] 14.2 多 `.kdbx`/`.key` 配对测试与登记（排序取末位 + 仅同名配对，不取首个 `.key`）
  - 验证：`cargo test -p veil kdbx_key_pairing` 通过；`src/config/custom_file.rs:14-42` 语义与 README §1 同字

## 15. 登记项核验（`C15`/`C16`/`C17`/`C18`）

- [x] 15.1 `C15` 核验 `/credential` 信封 `{ok,credential}`（`src/handler/credential.rs:32-39`，README §5）测试在位，缺则补测试；design D15 登记
  - 验证：`cargo test -p veil credential_envelope` 通过；失败时补测并登记，不改行为
- [x] 15.2 `C16` 按 design D16 维持双必填并登记为有意收紧：补缺 `caller_path`/缺 `caller_hash` 各 `403` 测试，README 声明收紧与迁移（补 `caller_path`）
  - 验证：`cargo test -p veil caller_path_required_403` 通过；`grep -n "caller_path" README.md` 命中收紧说明
- [x] 15.3 `C17`/`C18` 核验登记：`ct_eq`/`secret_eq` 时序安全与未 enrolled 兼容放行测试在位
  - 验证：`cargo test -p veil secret_eq` 与 `cargo test -p veil unenrolled` 通过；design D15/D17 记录证据（`src/auth.rs:11-37`、`src/service/credential/auth.rs:184-186`）

## 16. 门禁与回归

- [x] 16.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 16.2 `openspec validate veil-credential-flow-parity --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 16.3 `python3 scripts/check_doc_paths.py` 退出码 0（apply 后 README/spec 路径引用仍有效）
  - 验证：脚本输出 `OK:` 且退出码 0；新增 `src/*.rs` 引用全部对应真实文件
