## 1. `B1` 注册表落盘移出 async 执行器与全局写锁

- [x] 1.1 `src/registry/store.rs:236`：`save_to` 拆为锁内纯段 `to_file_bytes(&self) -> Result<Vec<u8>>`（entries 完整性 + `serde_json::to_vec_pretty`）与锁外纯字节 `write_atomic(path, &[u8]) -> Result<()>`（`create_dir_all` + tmp 写 + `ensure_0600` + rename + `ensure_0600`）；`save_to` 保留为两段组合的同步兼容入口（迁移路径/测试继续可用）
  - Verify: `cargo test -p veil atomic_save_and_integrity_check` 与 `cargo test -p veil saved_file_permissions_0600` 通过（既有原子落盘与 0600 权限语义不变）
  - Verify: `grep -n "fn to_file_bytes\|fn write_atomic" src/registry.rs` 命中，且 `write_atomic` 函数体内不引用 `CallerRegistry`（纯字节写盘）
- [x] 1.2 `src/state.rs`/`src/service/credential/mod.rs:48-63`：新增写路径全序点（`AppState` 的 `Arc<tokio::sync::Mutex<()>>` + `AppStateParts` 访问器）；`src/service/credential/vault_ops.rs:184-190/195-201/245-251` 改为「全序点 → 写锁内改内存并取 bytes → 释放写锁 → `spawn_blocking(write_atomic).await` → 释放全序点」；失败由 `.ok()` 改显式 warn（design D1）
  - Verify: `cargo test -p veil register_caller`、`cargo test -p veil revoke`、`cargo test -p veil approve_hash_change` 全绿
  - Verify: `grep -n "save_to\|spawn_blocking" src/service/credential/vault_ops.rs` 三处写路径均无写锁内同步 `save_to`（改为 spawn_blocking 组合）
- [x] 1.3 补并发/故障回归：慢落盘下读路径不等待、并发写不旧覆盖新、落盘失败可观测
  - Verify: `cargo test -p veil slow_save_not_blocking_reads` 通过（注入落盘延迟，断言并发鉴权读先返回）
  - Verify: `cargo test -p veil save_order_preserved` 与 `save_failure_observable` 通过（全序点保序；注入写失败走 warn 路径且不 panic）

## 2. `B2` 流式每帧还原复杂度与凭据表规模解耦

- [x] 2.1 `src/service/redaction/scope.rs:108-113 restore_response`：step1 由 `vault.restore()`（全量快照 + 整表正则）改为逐 token `restore_one` 直查重建（复用 `scan_token_forms`，与 `:119-126 restore_response_one` 同源）；step2–step4 顺序与语义不变
  - Verify: `cargo test -p veil restore_per_token_parity` 通过（多 token/未注册/幻觉/PII/相邻 token/JSON 转义混合样本，与全量路径逐字节一致）
  - Verify: `cargo test -p veil request_redact_response_restore` 与 `response_new_pii_not_restored` 全绿
- [x] 2.2 `src/service/credential_vault.rs:60-141`：为响应侧脱敏（p2t）加「注册时失效」缓存（`generation + Arc<Snapshot>` 含预编译 alternation 正则，注册/LRU 逐出失效，双检重建）；`scope.rs:176-191 redact_response_new_pii` 与 `leaf.rs:147-196 redact_leaf_response` 改消费 `Arc<Snapshot>`，每帧仅 Arc 克隆；`replace_all_by_map` 不再出现在逐帧路径（`spawn.rs:72` 每流一次快照同步改走缓存）
  - Verify: `cargo test -p veil stream_frame_no_full_snapshot` 通过（`snapshot_calls` 与 p2t 深克隆计数不随帧数增长）
  - Verify: `cargo test -p veil` 响应侧脱敏/新 PII 用例全绿（输出字节不变）
- [x] 2.3 注册失效正确性与并发：帧间注册新凭据后可还原；并发注册 + 还原无丢失/无死锁
  - Verify: `cargo test -p veil restore_after_register` 通过（缓存失效后新 token 可还原）
  - Verify: `cargo test -p veil restore_concurrent_register` 通过（结果与串行语义一致、无 panic）
- [x] 2.4 复杂度回归锁定：以 `MAX_TOKEN_ENTRIES` 上限表 + 多帧断言每帧快照计数不随表规模增长（复用 X3 `snapshot_calls` 设施，不做墙钟耗时断言）
  - Verify: `cargo test -p veil stream_restore_complexity` 通过（大表与空表每帧快照计数一致为 0 增量）
  - Verify: 既有 `cargo test -p veil snapshot` 相关测试全绿无回退

## 3. `B3` 锁中毒恢复与正则触顶防护

- [x] 3.1 `src/service/credential_vault.rs:86/156/191`：`.expect` 改统一恢复助手（`PoisonError::into_inner` + 首次 warn）；`replace_all_by_map:180-198` 正则改 `RegexBuilder` 加显式大小上限，编译失败/触顶回退逐键 `str::replace`（design D3）
  - Verify: `cargo test -p veil vault_poison_recovery` 通过（注入中毒后 `register`/`restore`/`strip_hallucinated` 正常且告警可断言）
  - Verify: `cargo test -p veil alternation_fallback` 通过（构造编译失败映射，输出正确、无 panic）
- [x] 3.2 `src/service/pii/scope.rs:238/279/286` 同口径；`contains_request_token:270-274` 静默 `unwrap_or(false)` 改恢复后真实结果（可见性归属由 `veil-hygiene-round5` D1 决定，本任务不改可见性）；`count_malformed` 字面正则提升 `OnceLock` 静态
  - Verify: `cargo test -p veil pii_poison_recovery` 通过（中毒后隔离查询返回真实值、计数正常、无 panic）
  - Verify: `grep -n "expect(\"PII scope 锁无毒\")\|expect(\"计数锁无毒\")\|expect(\"形态正则恒合法\")" src/service/pii/scope.rs` 无命中
- [x] 3.3 正则规模上限复核：以 `MAX_TOKEN_ENTRIES=5000` 构造最大 alternation，断言编译成功或走回退且结果与逐键替换一致
  - Verify: `cargo test -p veil regex_size_ceiling_max_entries` 通过（无 panic、结果正确）
  - Verify: `cargo test -p veil replace_all_by_map` 既有用例全绿

## 4. `B4` `integrity_of` 显式传播

- [x] 4.1 `src/registry/store.rs:189`：`integrity_of` 改 `Result<String>`；`load_from:218`/`save_to:238`（拆分后 store.rs）/`migrate_python_registry:381` 调用点传播（加载拒绝、保存中止不落盘）；补 `#[cfg(test)]` 故障注入 seam
  - Verify: `cargo test -p veil integrity_serialize_failure` 通过（注入序列化失败 → `load_from` 返回存储错误、`save_to` 不产生 tmp/rename）
  - Verify: `grep -n "unwrap_or_default" src/registry.rs` 不再命中完整性计算路径
- [x] 4.2 既有完整性语义回归：sha 失配拒绝加载、原子保存后校验通过、Python 旧格式迁移保留 .bak
  - Verify: `cargo test -p veil atomic_save_and_integrity_check` 通过
  - Verify: `cargo test -p veil legacy_python_format_migration_keeps_bak` 通过

## 5. `B5` `bind_script_sha256` 阻塞化与输入校验

- [x] 5.1 `src/registry/store.rs:59-80`：拆纯函数 `script_sha256_of_bytes` + async 读取入口（`spawn_blocking`）；加路径长度（≤4096）与大小上限（`BIND_SCRIPT_MAX_BYTES = 16 MiB`）校验，超限/不可读回退 `sha256(expected_hash:caller_path)` 并 warn
  - Verify: `cargo test -p veil bind_script_size_cap` 通过（超限不读全量、回退结果与派生公式一致）
  - Verify: `cargo test -p veil bind_script_path_length` 通过（超长路径不 panic、按回退处理）
- [x] 5.2 `CallerRegistry` 增预计算入口（`register_extended`/`approve_hash_change` 的 `*_with_script_sha256` 变体，apply 时定）；`vault_ops.rs:184-192/245-251` 在取全序点/写锁前 await 读取，锁内无文件 I/O
  - Verify: `cargo test -p veil register_offlock_hash` 通过（读盘发生在写锁外，注入延迟时写锁不被持有）
  - Verify: `cargo test -p veil approve_hash_change` 与 `cargo test -p veil registry` 全绿
- [x] 5.3 路径校验兼容性结论：确认存量调用方路径形态（README/Go 示例为绝对路径）；若非全绝对，按 design D5 降级为长度+大小上限并回写 design
  - Verify: `cargo test -p veil bind_script_relative_path` 通过（行为与 decision 一致）
  - Verify: `grep -n "BIND_SCRIPT_MAX_BYTES" src/registry.rs` 命中常量与校验分支

## 6. `B6` `registry.rs` 门面拆分为子模块

- [x] 6.1 新建 `src/registry/entry.rs`（`CallerEntry`/`RegisterParams`/`OLD_HASH_GRACE_SECS`）与 `src/registry/acl.rs`（`AuthorizationDecision`/`authorize_entry`/`status_emoji` 等），`src/registry.rs` 门面 `mod` + `pub use` 重导出
  - Verify: `cargo test -p veil` 全绿（既有 `crate::registry::*` 引用零改动编译）
  - Verify: `python3 scripts/check_file_sizes.py` 退出码 0（新文件 ≤800）
- [x] 6.2 新建 `src/registry/store.rs`（`CallerRegistry`/`RegistryFile`/`integrity_of`/load 与 save 两段/`now_unix_secs`/`bind_script_sha256`）与 `src/registry/migrate.rs`（`migrate_python_registry`）；门面仅 `mod`+`pub use`+守卫
  - Verify: `cargo test -p veil file_len_under_800_or_split` 通过且守卫字面未被改写（`include_str!("registry.rs")`，阈值 800）
  - Verify: `cargo clippy --tests --all-targets -- -D warnings` 退出码 0
- [x] 6.3 边界与协同：拆分仅模块移动/可见性/re-export，无函数删除；与 `veil-hygiene-round5` D2（`migrate_python_registry` 测试专用化）叠加顺序明确（round5 先行则原样平移 gating 后形态；本 change 先行则 round5 在 `registry/migrate.rs` 叠加），与 `veil-code-hygiene-closeout` 死码清理不重叠
  - Verify: apply 阶段 `git diff --stat` 显示 registry 相关仅拆分文件新增/移动，无函数删除
  - Verify: `grep -rn "fn migrate_python_registry" src/registry.rs src/registry/` 恰一处定义（形态随 round5 结论，无双重定义/丢失）

## 7. 记录项与门禁

- [x] 7.1 design D7 记录 6 个 700+ 行观察项（`placeholder.rs` 737/`env_parse.rs` 720/`custom_file.rs` 718/`spawn.rs` 717/`audit/hold.rs` 710/`pii/scope.rs` 708）与不拆理由
  - Verify: `grep -n "737\|720\|718\|717\|710\|708" openspec/changes/veil-runtime-robustness/design.md` 命中六项
  - Verify: `python3 scripts/check_file_sizes.py` 退出码 0（观察不改，红线未破）
- [x] 7.2 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - Verify: 三条命令退出码 0；新增测试全绿、无既有测试回退
  - Verify: `cargo test -p veil` 输出 0 failed（含 `B1`–`B6` 全部新增用例）
- [x] 7.3 `openspec validate veil-runtime-robustness --strict` 0 failures
  - Verify: 命令输出 `is valid`
  - Verify: `openspec list --json | grep veil-runtime-robustness` 命中该 change
