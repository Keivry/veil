## Why

运行时健壮性深度审查（2026-09-11，凭据/网关运行时执行面）确认 6 项待收敛偏差（`B1`–`B6`），集中在「同步阻塞 I/O 占住 async 执行器与全局写锁」「流式热路径每帧全量克隆凭据表 + 正则重编译」「std 锁中毒后持续降级」「完整性计算静默弱化」与「注册表职责混合」：

- **`B1`（High，可用性/尾延迟）**：`src/service/credential/vault_ops.rs:185-189/196-200/246-250` 在 `state.registry().write().await` 守卫作用域内调用 `registry.save_to()`；`src/registry/store.rs:236` 的 `save_to` 执行 `create_dir_all` + `std::fs::write` + `rename` + `set_permissions` 全同步阻塞，未走 `spawn_blocking`——磁盘慢时占住 tokio worker 与全局写锁，注册/吊销/哈希变更及并发鉴权读全部排队，尾延迟无界。
- **`B2`（High，性能）**：`src/handler/llm/pump/spawn/event_loop.rs:571-599/491/603` 每 SSE 帧调用 `restore_response_with_spans`（`src/service/redaction/scope.rs:133`）→ 第 138 行 `restore_response` → `CredentialVault::restore`（`src/service/credential_vault.rs:151`）→ `snapshot_t2p()`（`:126-134`）在 `std RwLock` 读锁下 `clone()` 整张表（上限 `MAX_TOKEN_ENTRIES=5000`，`credential_vault.rs:22`），随后 `replace_all_by_map`（`:180-198`）做 `sort/escape/join/Regex::new`；同帧 `redact_response_new_pii`（`scope.rs:185`）再次 `snapshot_p2t().clone()`，`redact_leaf_response`（`leaf.rs:154`）再对明文→token 表重建 alternation 正则。同文件第 146 行已有逐 token `restore_one`（`credential_vault.rs:139`）却只用于 span 计算，未用于主还原。
- **`B3`（Medium，可用性）**：`src/service/credential_vault.rs:86/156/191`、`src/service/pii/scope.rs:238/279/286` 用 `.expect("...锁无毒")`/`.expect("...恒合法")`；`src/handler/llm/dispatch.rs:46-58` 的 `spawn_contained` 把 panic 转 500，但一旦 std 锁中毒，后续每请求永久 500（不自愈）；`pii/scope.rs:270-274 contains_request_token` 以 `.map(...).unwrap_or(false)` 静默吞中毒（隔离判定可能误报「不包含」）；`credential_vault.rs:191` 由运行时数据拼接 alternation 正则并 `.expect`，规模触顶时有 panic 风险。
- **`B4`（Low，完整性弱化）**：`src/registry/store.rs:189 integrity_of` 用 `serde_json::to_string(entries).unwrap_or_default()`——序列化失败时以空串算 sha256，加载侧完整性校验静默变弱（`load_from:218` 仍会比对通过）。
- **`B5`（Medium，阻塞+输入来源）**：`src/registry/store.rs:59-80 bind_script_sha256` 对请求体来源的 `caller_path`（`src/handler/credential.rs:232-237/301`）做同步 `std::fs::read`，且位于 `registry.write().await` 写锁内（`register_extended:291`、`approve_hash_change:335` 调用）；任意路径读取无大小/路径校验，构成阻塞面与存在性/内容哈希探测面。
- **`B6`（Low-Med，结构）**：`src/registry.rs` 746 行职责混合：`CallerEntry`（`:16-42`）+ `RegistryFile` 完整性（`:185-203`）+ load/save 原子落盘（`:208-253`）+ ACL 判定（`:65-145`）+ `bind_script_sha256`（`:191`）+ `migrate_python_registry`（`:372-469`）+ `now_unix_secs`（`:47`），逼近 800 红线（`file_len_under_800_or_split` 守卫 `:476-486`）。
- **记录项（观察）**：另有 6 个 700+ 行踩线文件（`placeholder.rs` 737 / `env_parse.rs` 720 / `custom_file.rs` 718 / `spawn.rs` 717 / `audit/hold.rs` 710 / `pii/scope.rs` 708，2026-09-11 实测）均 ≤800 红线，任务要求「观察不强制拆」，记 design D7，不立修复任务（与并行起草的 `veil-hygiene-round5` D5 同清单同口径，双记不冲突）。

引用规范：Tokio 任务模型（阻塞操作走 `spawn_blocking`，不得占 tokio worker）；`std::sync::PoisonError::into_inner` 恢复语义；OpenSpec `arch-file-size-closeout` spec（800 行红线与 `file_len_under_800_or_split` 守卫保持有效且不被改写）。真相源为 `src/service/credential/vault_ops.rs`、`src/registry.rs`、`src/handler/llm/pump/spawn.rs`、`src/service/redaction/{scope,leaf}.rs`、`src/service/credential_vault.rs`、`src/service/pii/scope.rs`、`src/handler/llm/dispatch.rs`。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`。

## What Changes

- **`B1` 落盘移出 async 执行器与全局写锁**：`registry.rs` 的 `save_to` 拆为锁内纯段 `to_file_bytes`（完整性+序列化）与锁外纯字节 `write_atomic`（目录/tmp/rename/权限）；`vault_ops.rs` 三处写路径改为「写路径全序点 → 写锁内改内存并取 bytes → 释放写锁 → `spawn_blocking(write_atomic).await`」，落盘失败由 `.ok()` 静默改为显式可观测（design D1）。
- **`B2` 消除每帧全量克隆与正则重编译**：主还原（token→明文）改逐 token `restore_one` 直查；响应侧脱敏（明文→token）改 vault 内「注册时失效」的 `Arc<Snapshot>`（含编译后 alternation 正则）缓存，每帧仅 Arc 克隆；还原步骤序与输出字节不变（design D2）。
- **`B3` 锁中毒可恢复**：`credential_vault.rs:86/156/191`、`pii/scope.rs:238/279/286` 的 `.expect` 改统一 `PoisonError::into_inner` 恢复助手（首次 warn）；`contains_request_token` 静默 `unwrap_or(false)` 改返回真实结果；`count_malformed` 字面正则提升静态；`replace_all_by_map` 正则编译失败/触顶回退逐键替换（design D3）。
- **`B4` `integrity_of` 显式传播**：返回 `Result<String>`；序列化失败使加载拒绝、保存中止（不写 tmp/不 rename），不再以空串充当哈希使校验通过（design D4）。
- **`B5` `bind_script_sha256` 阻塞化与输入校验**：拆纯函数 + async `spawn_blocking` 读取；加路径长度（≤4096）与文件大小上限（`BIND_SCRIPT_MAX_BYTES = 16 MiB`）校验，超限/不可读走 `expected_hash` 派生回退并 warn；`vault_ops` 在取写锁前完成读取（design D5）。
- **`B6` `registry.rs` 结构拆分**：`src/registry.rs` 保留门面（`mod` + `pub use`），新增 `src/registry/{entry,store,acl,migrate}.rs`；`file_len_under_800_or_split` 守卫与公开路径 `crate::registry::*` 保持有效；不删死代码（design D6）。
- **记录项落 design.md**：6 个 700+ 行文件「观察不强制拆」记录（design D7），不立修复任务。
- **文档同步**：若 apply 阶段确认存在对外可见行为变化（B4 拒绝加载、B5 回退告警），在 README 相应段落补一句声明；无配置项与协议面变化。

## Capabilities

### New Capabilities

- `runtime-robustness`：运行时执行面健壮性契约——注册表写路径不占 async 执行器与全局写锁、流式每帧还原复杂度与凭据表规模解耦、std 锁中毒可恢复不降级、完整性计算失败显式传播、脚本哈希读取有界且不阻塞 worker、registry 模块结构拆分保持契约与红线。

### Modified Capabilities

- 无。`openspec/specs/` 既有契约行为不动（`arch-file-size-closeout` 的 800 行红线与守卫语义被本 change 遵循而非修改）；本 change 新增 capability，README 仅在出现对外可见行为变化时随 apply 同步。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `B1` | HIGH（可用性/尾延迟） | 锁内只改内存与取字节、锁外 `spawn_blocking` 落盘；写路径全序点保证落盘顺序；失败可观测 | 1.1、1.2、1.3 |
| `B2` | HIGH（性能） | 主还原逐 token `restore_one`；p2t 侧「注册时失效」`Arc<Snapshot>` 缓存；消除每帧全量快照与 `Regex::new` | 2.1、2.2、2.3、2.4 |
| `B3` | MED（可用性） | 锁获取 `PoisonError::into_inner` 恢复；静默 `unwrap_or(false)` 显式化；正则触顶回退不 panic | 3.1、3.2、3.3 |
| `B4` | LOW（完整性弱化） | `integrity_of` → `Result`，序列化失败拒绝加载/拒绝落盘 | 4.1、4.2 |
| `B5` | MED（阻塞+输入来源） | `bind_script_sha256` 读取 `spawn_blocking` 化 + 路径/大小校验；不占写锁 | 5.1、5.2、5.3 |
| `B6` | LOW-MED（结构） | `registry.rs` 拆 `registry/{entry,store,acl,migrate}.rs`；守卫保持有效；不删死码 | 6.1、6.2、6.3 |
| 记录项 | —（观察） | 6 个 700+ 行文件（≤800）「观察不强制拆」记 design D7 | 7.1 |

## Non-Goals（显式）

- **不删死代码、不做测试专用化 gating**：死代码摘除与 `#[cfg(test)]` 收编由 hygiene 类 change 承接——`veil-code-hygiene-closeout` 与并行起草的 `veil-hygiene-round5`（其 D1 收编 `PiiScope::contains_request_token`、D2 收编 `CallerRegistry::migrate_python_registry`）；本 change 只做结构拆分（`B6`）与锁中毒语义修复（`B3`），不删任何函数/常量、不改可见性归属，三处交叉（`contains_request_token`/`migrate_python_registry`/700+ 行记录项）见 design D3/D6/D7。
- **不迁 tokio 锁**：`B3` 选 `PoisonError::into_inner` 恢复而非 `tokio::sync` 锁迁移（避免全链路 async 化，见 design D3）。
- **不变更脱敏语义**：PII recognizer 集合、还原步骤序（凭据还原 → PII 还原 → 幻觉剥离 → 残缺清理）与替换结果字节不变；`B2` 只改复杂度路径，不改结果。
- **不新增外部依赖、不改配置项默认值**；注册路径校验若确认存在合法相对路径调用方，降级为长度/大小上限（见 design D5 与 Open Questions）。
- **不做内存-磁盘一致性补偿机制**（WAL/重试/版本号丢弃旧写）：`B1` 只把 I/O 移出锁与执行器并让失败可观测；持久化补偿另立 change。
- **不改 `src/`、既有 change、既有 `openspec/specs/` 与 README**：本 change 只交付规划 artifacts；实现与文档改动留待 apply 阶段；不提交 commit。
- **不强制拆其余 700+ 行文件**：`placeholder.rs`/`env_parse.rs`/`custom_file.rs`/`spawn.rs`/`audit/hold.rs`/`pii/scope.rs` 记录为观察项（design D7），不在本 change 拆。
- **与 `veil-gateway-fidelity-fix` 的编辑面重叠由串行合入约定收敛**：两 change 均触及 `src/service/redaction/scope.rs`（`redact_response_new_pii*`/`restore_response*`）与 `src/handler/llm/pump/spawn.rs`（还原/脱敏调用段）；apply 阶段按「行为保真（gateway）先、复杂度重构（本 change B2/B3）后」串行合入，或同批由同一实现负责；禁止双方各自重写同一函数体。

## Impact

- **新增文件**：`openspec/changes/veil-runtime-robustness/` 下 `proposal.md`、`design.md`、`specs/runtime-robustness/spec.md`、`tasks.md`、`.openspec.yaml`。
- **apply 阶段改动面**：`src/registry.rs`（门面拆分并新增 `src/registry/{entry,store,acl,migrate}.rs`）、`src/service/credential/vault_ops.rs`、`src/service/credential_vault.rs`、`src/service/redaction/scope.rs`、`src/service/redaction/leaf.rs`、`src/service/pii/scope.rs`、`src/state.rs`（`B1` 写路径全序点与 `AppStateParts` 访问器）、`src/handler/llm/pump/spawn.rs`（如逐帧快照消除涉及接线调整）、对应单测；README 仅在有对外可见行为变化时同步。
- **影响系统**：注册/吊销/哈希变更写路径延迟与并发性、SSE 每帧 CPU/分配、锁故障恢复语义、注册表完整性与脚本哈希读取输入面、registry 模块结构。
- **依赖**：无新依赖；仅 `tokio`（`spawn_blocking`，既有）、`std::sync::PoisonError`、`regex`（既有）与既有测试设施。
