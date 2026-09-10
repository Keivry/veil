## D1. 死符号删除

- [x] D1.1 删 `CredentialVault::contains_token`（credential_vault.rs:155）
  - Verify：grep 零引用；`cargo test` 全绿
- [x] D1.2 删 `CredentialVault::global`（credential_vault.rs:78）
  - Verify：grep 零引用；全绿
- [x] D1.3 处置 `snapshot` + `VaultSnapshot`：先复核 `version()` 引用；删除或 `#[cfg(test)]` 收编；测试改走生产等价路径
  - Verify：处置决定与注释登记；`cargo test credential_vault` 全绿
- [x] D1.4 删 `CredentialVault::redact`；测试改走 `redact_with_map`/`snapshot_p2t`
  - Verify：`grep "\.redact(" src/` 无测试残留；全绿
- [x] D1.5 删 `has_chat_terminal` / `should_discard_after_terminal`（terminal.rs:16/61）与相关断言
  - Verify：`cargo test block_inject` 全绿
- [x] D1.6 删 `reject_new_dangerous_during_hold`（hold.rs:293）与测试
  - Verify：`cargo test hold` 全绿
- [x] D1.7 删或 `#[cfg(test)]` 收编 `AUDIT_TIMEOUT_SECS`（branch.rs:8）；测试引用同步
  - Verify：`cargo test` 全绿
- [x] D1.8 `#[cfg(test)]` 收编 leaf 三辅助（勿误伤 `Config` 同名方法）
  - Verify：生产段无引用；相关测试全绿
- [x] D1.9 design 附录记录测试函数数量增减
  - Verify：增减 ≤0 或逐条说明

## D2. 残留空码

- [x] D2.1 auth.rs:199-231 删 `effective` 死赋值（保留控制流）
  - Verify：`cargo test auth` 全绿
- [x] D2.2 credential/approval.rs:28-33 删 NoopApproval 丢弃调用
  - Verify：`cargo test approval` 全绿

## D3. classify_empty 收敛

- [x] D3.1 删 `StreamInjectThen502` 变体、`is_stream` 参数与分支（mod.rs:151/173）
  - Verify：`grep StreamInjectThen502` 零命中
- [x] D3.2 更新调用点（nonstream.rs:139 等）与测试（四分支→三分支、更名）
  - Verify：`cargo test` 全绿
- [x] D3.3 注释指向 `should_synthesize_empty_stream`
  - Verify：注释存在

## D4. resolve_upstream 确定性

- [x] D4.1 缺省回退改端口升序取首 + warn（mod.rs:189-197）
  - Verify：新单测（双端口取最小、重复一致）通过

## D5. emit 阈值常量

- [x] D5.1 `sse/emit.rs:36` `4096` → `FAST_EMIT_THRESHOLD_BYTES` + 注释
  - Verify：`cargo test sse` 全绿

## D6. events 测试辅助清理

- [x] D6.1 删 `loopback_grace` / `observability_disabled`（events.rs:90/102）；`load_admin_token_file` 保留
  - Verify：`cargo test admin` 全绿；相关测试调整
- [x] D6.2 复核 observability 404 由 router/e2e 覆盖
  - Verify：e2e 断言存在

## D7. ENV 回环声明闭合

- [x] D7.1 README §6 增 6.6 BREAKING；首句「五处」→「六处」（README.md:243）
  - Verify：grep「六处」命中；§6.6 存在
- [x] D7.2 README §7.4 表增「ENV/ALLOW_LOOPBACK_NO_TOKEN 不读取」行
  - Verify：表行存在

## D8. 收口

- [x] D8.1 design 附录保持「已评估无需动作」全清单
  - Verify：附录含全部条目
- [x] D8.2 门禁：`cargo test` + `cargo clippy --all --all-targets -- -D warnings` + `python3 scripts/check_doc_paths.py`
  - Verify：全绿
