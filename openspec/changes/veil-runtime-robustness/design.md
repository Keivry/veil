## Context

运行时健壮性深度审查（2026-09-11）在凭据/网关运行时执行面确认 6 项待收敛偏差（见 proposal Why 与覆盖表）。现状真相源：

- **`B1` 写路径在写锁内同步落盘**：`vault_ops.rs:184-190/195-201/245-251` 的 `register_caller_extended`/`revoke_caller`/`approve_hash_change` 在 `state.registry().write().await` 守卫内调用 `save_to`；`registry.save_to`（`registry.rs:228-253`）全同步（`create_dir_all`/`std::fs::write`/`ensure_0600`/`rename`），失败以 `.ok()` 静默吞掉。数据真相源：`AppState.registry: Arc<tokio::sync::RwLock<CallerRegistry>>`（`state.rs:42/77`），写路径经 `AppStateParts::registry()`（`service/credential/mod.rs:52`）访问。
- **`B2` 每帧全量克隆 + 正则重编译**：`spawn.rs:451/491/603`（每帧还原）与 `:452/492/604`（每帧响应侧脱敏）→ `scope.rs:133 restore_response_with_spans` → `:108-113 restore_response`（step1 `vault.restore`）→ `credential_vault.rs:151 restore` → `snapshot_t2p().clone()`（`:126-134`）→ `replace_all_by_map`（`:180-198`，`sort/escape/join/Regex::new`）；响应侧 `scope.rs:185` 每帧 `snapshot_p2t().clone()` → `leaf.rs:154 redact_with_map` 再建明文→token 正则。`spawn.rs:72` 已有一处**每流一次**的 `snapshot_p2t`（不计入逐帧成本）。既有 X3/D4 设施：`restore_one`（`credential_vault.rs:139-141`）与 `snapshot_calls` 计数（`:63-64/127-129/144-148`）。
- **`B3` 锁中毒与正则触顶**：`credential_vault.rs:86/156/191` `.expect("凭据 vault 锁无毒")`/`.expect("转义后 map 键正则恒合法")`；`pii/scope.rs:238` `.expect("PII scope 锁无毒")`、`:279` `.expect("形态正则恒合法")`、`:286` `.expect("计数锁无毒")`、`:270-274` 静默 `.map(...).unwrap_or(false)`；`dispatch.rs:46-58` panic → 500。
- **`B4` 完整性弱化**：`registry.rs:200-203 integrity_of` 的 `unwrap_or_default`；调用点 `load_from:218`（比对）、`save_to:238`、`migrate_python_registry:381`。
- **`B5` 同步读任意路径**：`registry.rs:191-198 bind_script_sha256`（`std::fs::read`），调用点 `register_extended:291`、`approve_hash_change:335`、`migrate_python_registry:440`；`caller_path` 请求体来源见 `handler/credential.rs:232-237/301`。
- **`B6` 结构混合**：`registry.rs` 746 行；守卫测试 `file_len_under_800_or_split`（`:476-486`，`include_str!("registry.rs")`，阈值 800）。
- **记录项**：`placeholder.rs` 737 / `env_parse.rs` 720 / `custom_file.rs` 718 / `spawn.rs` 717 / `audit/hold.rs` 710 / `pii/scope.rs` 708，均 ≤800。

约束：既有 canonical `arch-file-size-closeout` spec 要求 `registry.rs` 的 `file_len_under_800_or_split` 守卫「保持有效且不被改写」（阈值不得放宽）；`scripts/check_file_sizes.py` 全仓扫描兜底。并行变更 `veil-hygiene-round5`（2026-09-11 起草）与本 change 在 `contains_request_token`（D1）、`migrate_python_registry`（D2）与 700+ 行记录项（D5）三处相交：本 change 只做结构拆分与中毒语义修复，不做可见性/测试专用化 gating，交叉处置见 D3/D6/D7。本 change 只写规划 artifacts，不改 `src/`、既有 change 与 `openspec/specs/`，不提交 commit。

## Goals / Non-Goals

**Goals：**

- 给出 `B1`–`B6` 的可实施方案（决策 + 理由 + 备选）与可独立验证的场景，apply 阶段逐项落地。
- 把「落盘不占 async 执行器/写锁」「每帧还原与凭据表规模解耦」「锁中毒可恢复」「完整性失败显式」「脚本哈希读取有界」「registry 结构拆分」收敛为 spec 契约。
- 记录 6 个 700+ 行观察项与 hygiene 类 change 的边界，防止后续 change 重复或冲突。

**Non-Goals：**

- 不删死代码（hygiene 类 change 承接）、不迁 `tokio` 锁、不改脱敏结果语义、不新增依赖、不做 WAL/回滚补偿、不拆其余 700+ 行文件、不提交 commit。

## Decisions

### D1：`B1` 锁内只改内存，锁外 `spawn_blocking` 落盘（写路径全序点保序）

**决策**：把 `CallerRegistry::save_to` 拆为两段纯操作：`to_file_bytes(&self) -> Result<Vec<u8>>`（锁内调用：构造 `RegistryFile`（entries 克隆 + `integrity_of`）+ `serde_json::to_vec_pretty`，纯 CPU）与 `write_atomic(path: &Path, bytes: &[u8]) -> Result<()>`（`create_dir_all` + tmp 写 + `ensure_0600` + `rename` + `ensure_0600`，纯字节落盘，不引用注册表）；`save_to` 保留为两段组合的同步兼容入口（`migrate_python_registry` 与测试继续可用）。`vault_ops.rs` 三处写路径改为：

1. 取写路径全序点 `registry_save_lock().lock().await`（新增于 `AppState` 的 `Arc<tokio::sync::Mutex<()>>`，经 `AppStateParts` 暴露；读路径不经过该点）；
2. `registry.write().await` 守卫内改内存并 `to_file_bytes()` 取 `bytes`，随后释放写锁；
3. `tokio::task::spawn_blocking(move || write_atomic(&path, &bytes)).await`（I/O 在阻塞池，写锁已释放）；
4. 落盘失败由 `.ok()` 改为 `tracing::warn!` 可观测（best-effort 语义显式化，不做回滚），随后释放全序点。

**理由**：文件 I/O 属阻塞操作，放 tokio worker 会拖慢同线程任务，放 `write().await` 守卫内会让所有读（`lookup_by_path`/`lookup_by_hash` 鉴权查询）排队。拆两段后 I/O 既不占执行器也不占写锁。全序点保证「先变更先落盘」——若只把 I/O 移出写锁而无序，两个并发写可能以旧快照后完成覆盖新快照（last-writer-wins 取反）；全序点仅序列化三条低频管理写路径，不影响读与 SSE 转发。序列化留在锁内是有意取舍：保证 bytes 与内存状态同源一致（无 TOCTOU），且注册表体量小（调用方注册表，非 5000 条凭据表）。响应在落盘完成后返回，保持「请求成功即已持久化」的既有语义。

**备选**：(a) 锁内克隆整个 `CallerRegistry` 后锁外 `spawn_blocking(save_to)`——语义等价但多一次 entries 克隆与重复完整性计算，不采用；(b) `save_to` 整体进 `spawn_blocking` 但仍在写锁内 await——写锁跨 I/O 持有，未满足要求，不采用；(c) 专用持久化线程 + channel 单消费（天然保序）——引入生命周期/关闭/错误回传语义，超出本 change，不采用；(d) 每写带 generation 并在落盘侧丢弃旧代——可免全序点但引入跨层版本状态，复杂度高于收益，不采用。

### D2：`B2` 主还原逐 token 直查 + p2t 侧「注册时失效」缓存

**决策**：
- **还原侧（token→明文）**：`Scope::restore_response`（`scope.rs:108-113`）的 step1 由 `vault.restore()`（全量 `snapshot_t2p().clone()` + 整表 alternation 正则）改为逐 token 直查重建：用 `scan_token_forms`（`leaf.rs:200`）扫出 token 形态，命中 `restore_one`（`credential_vault.rs:139`）替换为明文、未命中保持原样；step2–step4（PII 还原 → 幻觉剥离 → 残缺清理）与顺序不变。`restore_response_with_spans` 已用同一逐 token 路径算 span（`scope.rs:141-148`），主还原与其共用后结果自洽。
- **脱敏侧（明文→token）**：`redact_response_new_pii`（`scope.rs:185`）与 `redact_leaf_response`（`leaf.rs:154`）需要枚举全部明文，无法逐 token 直查，故在 `CredentialVault` 内维护「注册时失效」缓存：`CacheState { generation: u64, snapshot: Arc<Snapshot> }`，`Snapshot` 含 p2t 映射与预编译 alternation 正则；`register`/LRU 逐出时自增 `seq` 使缓存失效；访问器 `Arc<Snapshot>` 采用「读锁快检 + 不一致时写锁重建一次」的双检模式，每帧仅 Arc 克隆（O(1)），正则仅在注册后首次使用时重建一次。
- 还原/脱敏输出字节与步骤序不变；`spawn.rs:72` 的每流一次快照保留或改走缓存（apply 时统一）。

**理由**：逐 token 直查为 O(帧内 token 数)，与凭据表规模解耦，彻底移除还原侧全量克隆与整表正则；明文字符串的「全出现点替换」必须枚举键集合，因此脱敏侧只能靠缓存摊销——注册是低频（每新明文一次），帧是高频，缓存把 O(n) 成本从每帧移到每次注册后首帧。

**备选**：(a) 每帧全量克隆（现状）——本次要消除的缺陷；(b) 每流一次快照并贯穿全流——消除多数克隆但可见性从「帧时点」变为「流起点」（并发请求注册的新凭据对本流不可见；同请求凭据在响应前已注册，故实际安全），可作为过渡，但未消除正则构建成本且引入「快照时点」语义，不作为主决策；(c) 纯逐键 `str::replace` 循环替代 alternation——O(k·text) 且无正则语义，不采用；(d) 还原侧也做 regex 缓存——t2p 有更优的直查路径，缓存属多余状态，不采用。

### D3：`B3` 锁中毒 `PoisonError::into_inner` 恢复 + 正则失败回退

**决策**：
- 统一恢复助手（如 `fn recover<T>(r: LockResult<T>) -> T { r.unwrap_or_else(PoisonError::into_inner) }`，首次恢复打 `tracing::warn!`）：应用于 `credential_vault.rs:86/156`、`pii/scope.rs:238/286`。
- `pii/scope.rs:270-274 contains_request_token` 的 `.map(...).unwrap_or(false)` 改为恢复后返回**真实结果**（中毒不得静默降级为「不包含」）。
- `count_malformed`（`pii/scope.rs:277-290`）的字面量形态正则提升为 `OnceLock` 静态，消除每调用 `Regex::new` 与 `.expect("形态正则恒合法")`。
- `replace_all_by_map`（`credential_vault.rs:180-198`）不再 `.expect`：用 `RegexBuilder` 加显式大小上限；编译失败/触顶时回退为逐键 `str::replace`（仅异常路径付 O(k·n)）。
- 复核规模上限：以 `MAX_TOKEN_ENTRIES=5000` 构造最大 alternation 验证编译成功或回退无损。

**理由**：std 锁中毒源于前序 panic，`.expect` 让其经 `spawn_contained`（`dispatch.rs:46-58`）转 500 且**永久**失败；`into_inner` 保持可用性，且移除输入可触发的正则 panic 后，vault/scope 的 mutator 不再有 panic 点，不变式不被破坏。`contains_request_token` 是跨请求隔离判定口径，静默 false 会把「锁异常」伪装成「隔离正确」，属安全相关误报。

**备选**：(a) 全量迁 `tokio::sync::RwLock`（无中毒）——`register`/`restore`/`strip_hallucinated`/`len` 等同步 API 需全链路 async 化（含 `leaf.rs` 同步叶回调），改动面过大，不采用；(b) 遇中毒重建锁并清空映射——凭据映射丢失会导致还原失效与占位符外泄风险，不采用；(c) 仅对 `expect` 加 `catch_unwind`——锁已中毒、每请求 catch 无法恢复，不采用。

**协同**：`veil-hygiene-round5` D1 将 `contains_request_token` 降为 `#[cfg(test)]`（生产零引用）。两 change 改同一函数：本 change 修「中毒静默 false」语义（若该函数已测试专用化，修复落在测试专用定义上，保证隔离断言不因中毒被误判通过），round5 负责可见性归属。建议 round5 先行或同批落地；本 change 不改变该函数可见性，仅替换锁获取与结果表达。

### D4：`B4` `integrity_of` 返回 `Result`，失败拒绝而非弱化

**决策**：`integrity_of`（`registry.rs:200-203`）签名改 `Result<String>`；`load_from:218` 失败返回 `VeilError::Storage` 拒绝加载，`save_to:238` 失败中止写盘（不产生 tmp/rename），`migrate_python_registry:381` 失败走既有错误路径。补 `#[cfg(test)]` 故障注入 seam 以锁定错误分支。

**理由**：`unwrap_or_default` 在序列化失败时以空串充当全部条目的哈希，会让「完整性校验」恒真（等于静默关闭），是 fail-closed 原则的反面；显式传播使失败可见且不可绕过。

**备选**：(a) 保留默认值但加 `tracing::error!`——校验仍会通过，弱化未消除，不采用；(b) panic——可用性问题（B3 同类），不采用。

### D5：`B5` `bind_script_sha256` 阻塞化 + 路径/大小校验

**决策**：
- 拆为纯函数 `script_sha256_of_bytes(&[u8]) -> String` 与 async 读取入口 `bind_script_sha256_async(caller_path, expected_hash)`：`spawn_blocking` 内做长度/大小校验与 `read`；超限/不可读/空文件走既有「`sha256(expected_hash:caller_path)`」回退并 `warn`（非致命，保持注册可用）。
- 校验：`caller_path` 非空且长度 ≤ 4096 字节（PATH_MAX）；文件大小上限 `BIND_SCRIPT_MAX_BYTES = 16 MiB`（脚本哈希用途，远超常规脚本体积）；超限不读全量、按回退路径处理。
- API 迁移：`CallerRegistry::register_extended`/`approve_hash_change` 增加「script_sha256 预计算」入口（倾向新增 `*_with_script_sha256` 变体，保持既有签名不变；apply 时按改动面定）；`vault_ops.rs` 在获取全序点/写锁**前** await 异步读取，锁内不再有文件 I/O。`bind_script_sha256` 同步函数保留（测试与迁移内部用），生产写路径不再调用。
- 绝对路径强制：待定项（见 Open Questions），默认先只做长度 + 大小校验，避免破坏合法相对路径调用方。

**理由**：路径来自请求体（`credential.rs:232-237/301`），无校验的任意读在异步热路径构成阻塞面与存在性/内容哈希探测面；阻塞化 + 上限把两者收敛到有界，且读取移到写锁外与 `B1` 目标一致。

**备选**：(a) 完全移除文件读取、只信 `caller_hash`——改变 `script_sha256` 语义与既有注册数据，不采用；(b) 路径根白名单（env 配置）——兼容性未知、可能拒绝存量调用方，列为后续候选而非本 change 决策；(c) 在写锁内 await `spawn_blocking`——锁跨 await 持有且读取顺序难保，违背 `B1` 目标，不采用。

### D6：`B6` `registry.rs` 门面 + 子模块拆分

**决策**：`src/registry.rs` 保留为门面（模块文档 + `mod entry/store/acl/migrate;` + `pub use` 重导出），新增：

- `registry/entry.rs`：`CallerEntry`、`RegisterParams`、`OLD_HASH_GRACE_SECS`、旧哈希宽限判定；
- `registry/acl.rs`：`AuthorizationDecision`、`authorize_entry`、`status_emoji` 及字段授权辅助；
- `registry/store.rs`：`CallerRegistry`、`RegistryFile`、`integrity_of`、load 与 save 两段（D1）、`bind_script_sha256`（D5）、`now_unix_secs`；
- `registry/migrate.rs`：`migrate_python_registry` 与 Python 旧格式映射。

公开路径 `crate::registry::{CallerEntry, CallerRegistry, RegisterParams, AuthorizationDecision, bind_script_sha256, OLD_HASH_GRACE_SECS}` 经 re-export 保持兼容；`file_len_under_800_or_split` 守卫保留在门面文件且字面不改写（`include_str!("registry.rs")` 仍指向门面自身），各子模块受 `scripts/check_file_sizes.py` 全仓扫描与既有 `≤800` 红线约束。

**理由**：746 行逼近 800 红线（余量 54 行），完整性/存储/ACL/迁移四类职责耦合；拆后单文件职责单一、后续改动局部化，并为 D1/D5 的 store 变更提供独立落点。

**备选**：(a) 仅抽小函数不拆模块——行数问题不解决，不采用；(b) 任意切到 800 行以下——无职责边界，不采用；(c) 顺带删除死代码——越界（转出，见 Non-Goals）。

**协同**：`veil-hygiene-round5` D2 将 `migrate_python_registry` 移入 `#[cfg(test)]`。本拆分保留该符号与语义原样平移：若 round5 先行，`registry/migrate.rs` 承载 gating 后形态（若 round5 选择测试模块内联，则 `migrate.rs` 可并入 store 测试段，apply 时以 round5 落地形态为准）；若本 change 先行，round5 在 `registry/migrate.rs` 上叠加 gating。禁止两 change 各自移动/删除同一符号造成双重定义。

### D7：记录项——700+ 行踩线文件观察不强制拆

**决策**：`placeholder.rs` 737 / `env_parse.rs` 720 / `custom_file.rs` 718 / `spawn.rs` 717 / `audit/hold.rs` 710 / `pii/scope.rs` 708（2026-09-11 实测）记录为观察项：均 ≤800 红线（余量 63–92 行），本轮不强制拆。其中 `spawn.rs`/`pii/scope.rs` 在本 change 有功能改动（`B2`/`B3`），功能与结构改动分离以保可回滚；后续越线时按 `arch-file-size-closeout` 流程拆分。

**理由**：红线未破且拆分收益/风险比不足；避免结构 diff 淹没功能 diff。与 `veil-hygiene-round5` D5 同清单同口径——两 change 均只记录、不拆分，互不冲突。

## Risks / Trade-offs

- [`B1` 内存先行、落盘失败不回滚：内存与磁盘短暂不一致/重启丢最新变更] → 失败显式 warn + design 记录 best-effort 语义；WAL/重试/回滚为 Non-Goal，留待后续 change。
- [`B1` 全序点串行化写路径] → 仅注册/吊销/哈希变更三条低频管理写路径经全序点；读路径与 SSE 转发不受影响，预期无吞吐损失。
- [`B2` 逐 token 路径与全量替换存在语义差] → 以 `scan_token_forms` 形态 + `restore_one` 直查等价性测试锁定（含未注册/幻觉/PII/相邻 token/JSON 转义边界）；不一致即测试失败。
- [`B2` p2t 缓存与注册并发] → 双检重建保证失效后最多重建一次；并发注册期间帧输出可能与「帧时点最新表」差一次注册（下一帧收敛），以正确性测试与复杂度测试共同锁定。
- [`B3` poison 恢复使用 panic 中断后的中间状态] → 移除输入触发的 panic 点后 mutator 无 panic；恢复路径打 warn，生产应同时修复 panic 根因。
- [`B3` 正则回退路径 O(k·n)] → 仅编译失败/触顶时触发，属异常路径；正常路径不受影响。
- [`B4` Result 化错误分支近乎不可达] → 以 test seam 注入锁定；`load_from` 对篡改文件的拒绝行为不变。
- [`B5` 大小/长度校验拒绝合法输入] → 阈值宽松（16 MiB/4096）且超限走回退而非拒绝，注册仍成功；绝对路径强制待兼容性确认（Open Questions），默认不做。
- [`B5` 存在性/内容哈希探测面] → 需三因子鉴权前置；根白名单为后续候选；spec 只声明「读取有界」而非「路径可信」。
- [`B6` 拆分触及可见性/测试路径] → re-export 保持 `crate::registry::*` 可用；`cargo test`/clippy 全量门禁；守卫字面与红线保持。
- [记录项后续越线] → 仓库级 `scripts/check_file_sizes.py` 与各文件既有守卫兜底，越线即触发拆分任务。

## Migration Plan

1. 按 tasks 顺序落地：先 `B1`/`B4`/`B5`（store 落盘与读取路径），再 `B2`（还原热路径），再 `B3`（锁与正则），最后 `B6` 结构拆分（在功能 diff 稳定后执行，避免结构噪声）。
2. 每组独立跑 `cargo test -p veil <组>`；`B6` 后全量 `cargo test` 与 `scripts/check_file_sizes.py`。
3. 回滚策略：`B1`–`B5` 可按 diff 节回滚；`B6` 为纯模块移动，可整体 revert，无数据/接口迁移。
4. 发布口径：无配置项与协议面变化；若 apply 确认 `B4`/`B5` 存在对外可见语义（拒绝加载/回退告警），在 README 相应段落补一句声明。

## Open Questions

- `B5` 是否强制绝对路径：apply 阶段先确认存量调用方（README 示例与 Go 客户端均为绝对路径）是否 100% 绝对；若非，则降级为长度/大小上限并回写本 design。
- `B2` 的 p2t 消除范围：若叶回调改造面超出预期，可先消除主还原 t2p 克隆（高收益）并把 p2t 缓存列为紧随项；范围收缩必须在 tasks/spec 显式标注，不得静默缩范围。
- `D7` 观察项是否在后续轮次统一拆分：由后续 change 决定，本 change 不变更。
