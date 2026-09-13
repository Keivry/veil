## 1. `H1` 兼容垫片零生产引用守护

- [x] 1.1 `src/service/audit_hold.rs` 保持仅重导出与 DEPRECATED 指引（不改语义），新增守护测试：扫描 `src/` 中的 `audit_hold::` 字面，白名单仅垫片文件本体与测试，任何生产新增引用即失败（沿用 `src/service/mod.rs` 声明锁定的扫描模式）
  - 验证：`cargo test -p veil audit_hold_zero_production_refs` 通过；向 `src/handler/` 临时加 `audit_hold::` 字面时该测试失败
  - 验证：`grep -rn "audit_hold::" src/` 仅命中 `src/service/audit_hold.rs` 注释/重导出与守护测试白名单
- [x] 1.2 proposal Non-Goals 与 design D1 固化「保留垫片、删除列为备选不采用（canonical 要求路径保留 + 删除属 BREAKING 符号面）」，防止后续 change 反向删除
  - 验证：`grep -n "H1" openspec/changes/veil-arch-hygiene-closeout/design.md` 命中 D1 决策与备选理由
  - 验证：`grep -rn "code-quality-cleanup" openspec/changes/veil-arch-hygiene-closeout/` 命中 canonical 依据

## 2. `H2` 网关度量固定键原子计数

- [x] 2.1 `src/service/llm_gateway/mod.rs:34-111`：`GatewayMetrics` 四组 `Mutex<HashMap<String,u64>>`（lenient/truncated/hop_filtered/conv_missing）改为固定键 `AtomicU64`（lenient 协议尾 3、truncated 模式 2、hop 方向 2、conv 原因 5），保留 `record_*`/`*_count(&str)` 方法与语义
  - 验证：`cargo test -p veil gateway_metrics_atomic_keys` 通过；已知键精确计数、`src/service/sse/meta.rs` 两模式与 `src/handler/llm/dispatch.rs`/`src/handler/llm/nonstream.rs`/`src/handler/llm/pump/event.rs` 调用点全部编译通过
  - 验证：`grep -n "Mutex<HashMap" src/service/llm_gateway/mod.rs` 四组旧字段命中数为 0
- [x] 2.2 未知键归 `other` 桶并 warn 一次，写点（`:55,68,88,101`）与读点（`:62,75,95,108`）走同一固定键映射；`src/handler/admin.rs:266-269` 的 `chat_tail_lenient` 三键读数不变
  - 验证：`cargo test -p veil gateway_metrics_unknown_key_other` 通过；未知键不影响已知键读数
  - 验证：`cargo test -p veil admin_metrics_keys_unchanged` 通过；`/_admin/metrics` 的 `chat_tail_lenient`/`truncated`/`sse_events` 键名与 JSON 形态与改动前一致
- [x] 2.3 并发压测单测：多任务并发对同一已知键各记录 N 次，读数恰为总量；方向/模式隔离仍成立
  - 验证：`cargo test -p veil gateway_metrics_concurrent_count` 通过；`hop_filtered` 上下游隔离与 `truncated` 两模式隔离断言不变
  - 验证：既有 `cargo test -p veil gateway_tests hop` 与 `src/service/llm_gateway/hop.rs` 单测全绿无回退

## 3. `H3` 审计 env/home 显式注入

- [x] 3.1 `src/service/audit/normalize.rs:150-199`：`expand_vars_single` 移除 `std::env::var` 回退（`:170,:188`），仅使用传入 `env` 映射；未命中保留字面（`${VAR}`/`$VAR`）
  - 验证：`cargo test -p veil expand_vars_injected_only` 通过；空映射下 `$HOME`/`${HOME}` 输出字面，不读宿主机环境
  - 验证：`grep -n "std::env::var" src/service/audit/normalize.rs` 命中数为 0
- [x] 3.2 `src/service/audit/rules.rs`：`extract_path_tokens`/`expand_home`（`:124-142`）改由注入 home 决定，`is_dangerous`（`:278-284`）的 `HashMap::new()` 改传启动期 env 快照（经既有 `AuditPolicy` 或显式参数承载，apply 阶段定名）
  - 验证：`cargo test -p veil audit_dangerous_injected_env` 通过；注入 home/env 后 `~/x` 与 `${VAR}` 展开由注入值唯一决定
  - 验证：`grep -n "std::env::var" src/service/audit/rules.rs` 命中数为 0；`is_dangerous` 调用点全部在 `AuditPolicy`（或显式 env）在位下编译
- [x] 3.3 确定性单测：空注入与两套定制注入判定同一输入，结果分别稳定且互不依赖宿主机；策略语义（拆链/别名/`..`）回归不动
  - 验证：`cargo test -p veil audit_deterministic_env_matrix` 通过；同快照重复运行结果一致
  - 验证：`cargo test -p veil audit_rules` 全绿；proposal/design 交叉引用 `veil-audit-rules-parity` `A5`，本 change 未改语义管线

## 4. `H4` 注册解析归服务层

- [x] 4.1 新建 `src/service/credential/` 内 `register_map` 子模块（apply 阶段定名），把 `parse_register_entries`/`parse_register_allow_mode` 语义实现为纯映射函数：输入原始 `entries`/`entry`/`field`/`fields`/`allow_mode`/`auto`，输出 `RegisterParams.entries` 与 `allow_mode`；不依赖 handler DTO
  - 验证：`cargo test -p veil register_map_pure` 通过；对象/数组/字符串/单条目/`fields` 各形态映射与旧实现逐字段一致
  - 验证：`grep -n "RegisterBody" src/service/credential/` 命中数为 0（service 不反向依赖 handler）
- [x] 4.2 `src/handler/credential.rs:80-221,250-261`：删除本地解析函数，handler 仅提取原始字段并调用服务层映射；更新模块/层边界注释为「纯透传层，业务语义归 service」
  - 验证：`grep -n "fn parse_register_entries\|fn parse_register_allow_mode" src/handler/credential.rs` 命中数为 0
  - 验证：`cargo test -p veil register_caller_handler` 通过；注册接口行为与改动前一致
- [x] 4.3 迁移原解析相关单测到服务层模块并补等价矩阵用例（含 `allow_mode` 非法值回退 `auto`、空条目兜底）
  - 验证：`cargo test -p veil register_map` 全绿；既有 `src/handler/credential.rs` 注册单测迁移后不回退

## 5. `H5` 源码文件体量红线与拆分点

- [x] 5.1 `src/service/pii/scope.rs`（772，内联测试 `325-772` 共 448 行）外置为 `src/service/pii/` 下测试子模块（`scope_tests.rs`），在 `src/service/pii.rs` 以 `#[cfg(test)] mod scope_tests;` 声明；`scope.rs` 路径不变
  - 验证：`python3 scripts/check_file_sizes.py` 退出 0；`src/service/pii/scope.rs` 移除内联测试后行数显著下降且路径仍存在
  - 验证：`cargo test -p veil pii` 全绿；测试用例数与迁移前一致，无删除
- [x] 5.2 `src/handler/llm/pump/spawn.rs`（772，`spawn_stream_pump` `61-772`）抽 `guard`（`43-57`）与 `terminal`（`600-753`）到 `src/handler/llm/pump/spawn/` 子模块（`guard.rs`/`terminal.rs`），`spawn.rs` 内 `mod guard; mod terminal;` 声明并按需重导出；帧循环主体不动
  - 验证：`python3 scripts/check_file_sizes.py` 退出 0；`src/handler/llm/pump/spawn.rs` 路径仍存在且行数 ≤800
  - 验证：`cargo test -p veil pump spawn terminal` 全绿；`spawn_stream_pump` 对外签名与行为不变
- [x] 5.3 拆分后文档路径与引用终检：README 与 spec 中 `src/handler/llm/pump/spawn.rs`、`src/service/pii/scope.rs` 引用不悬空；全量 e2e 无回退
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0，无新增 FAIL
  - 验证：`cargo test -p veil --tests` 全绿；`cargo test -p veil --test http_e2e_sse_loop` 等结构相关 e2e 无回退

## 6. `H6` 健康探针组装归服务层

- [x] 6.1 `src/service/credential/mod.rs:67-78`：`HealthStatus` 扩 `unlocked`/`pending`/`llm_secrets` 字段，`health_status` 经 `AppStateParts`（`keepass()`/`pending()`/`vault()`）组装；模块文档固化「只读快照 + trait 访问边界」
  - 验证：`cargo test -p veil health_status_full_fields` 通过；三新字段由 trait 数据组装
  - 验证：`grep -n "pub fn health_status" src/service/credential/mod.rs` 命中新实现
- [x] 6.2 `src/handler/mod.rs:16-29`：`health_handler` 改为序列化 `service::health_status` 结果，删除对 `state.keepass`/`state.pending`/`state.vault` 的直读；`/health` 字段只增不减行为不变
  - 验证：`grep -n "state.keepass\|state.pending\|state.vault" src/handler/mod.rs` 命中数为 0
  - 验证：`cargo test -p veil health_handler` 与 `cargo test -p veil --test http_e2e_*` 中 `/health` 断言全绿，字段名与语义不变

## 7. `H7` 锁序不变量与审查

- [x] 7.1 在 `src/service/credential/vault_ops.rs`、`src/service/pii/custom.rs`、流内 keepalive gate 所属模块文档固化锁序不变量与审查清单：`registry_save_lock → registry.write()`、`strikes → disabled`、keepalive gate 不逆序获取 hold 锁
  - 验证：`grep -n "锁序" src/service/credential/vault_ops.rs src/service/pii/custom.rs` 命中三处不变量声明
  - 验证：design D7 为审查清单真源，`grep -n "H7" openspec/changes/veil-arch-hygiene-closeout/design.md` 命中
- [x] 7.2 新增源码扫描守护测试：对已登记写路径（`register_caller_extended`/`revoke_caller`/`emergency_revoke`、`account_rule`、keepalive gate）断言锁获取顺序；新增未登记写路径需登记
  - 验证：`cargo test -p veil lock_order_invariants` 通过；构造逆序样例时测试失败
  - 验证：`cargo test -p veil --test http_e2e_vault_stability` 全绿；无运行时锁实现改动（锁中毒归 `P14`）

## 8. `H8` TPM 同步子进程调用约束

- [x] 8.1 `src/service/tpm.rs` 模块文档声明：同步 `Command`/忙轮询（`:95-146`）与 `is_available`（`:153-163`）仅允许启动期与 `spawn_blocking` 内调用，禁 async 上下文直调；忙轮询保留在阻塞语境
  - 验证：`grep -n "spawn_blocking\|禁 async" src/service/tpm.rs` 命中约定声明
  - 验证：design D8 记录「不迁移 `tokio::process`」理由
- [x] 8.2 新增调用点守护测试：扫描 `src/` 中 TPM 同步调用（`RealTpm`/`tpm2_*`），白名单仅 `src/service/tpm.rs`、启动期（`src/main.rs`）、`src/keepass.rs:200` 的 `spawn_blocking` 闭包，其余即失败
  - 验证：`cargo test -p veil tpm_sync_call_sites` 通过；违规样例被拦截
  - 验证：`cargo test -p veil tpm` 全绿；启动/解锁路径行为不变

## 9. `H9` HTTP 客户端构造失败可见

- [x] 9.1 `src/state.rs:148-161`：`build_http_client` 抽可注入构造核心（`#[cfg(test)]` 可注入失败），失败时 `tracing::warn!` 记录原因并返回显式降级 `Client::new()`（或启动即错，见 design D9），删除 `unwrap_or_else(|_| ...)` 静默吞错
  - 验证：`grep -n "unwrap_or_else(|_|" src/state.rs` 命中数为 0（或仅保留显式降级分支并含 warn）
  - 验证：`cargo test -p veil http_client_build_failure_visible` 通过；注入失败时 warn 含原因、返回可用客户端
- [x] 9.2 正常配置路径回归：合法 `Config` 构造客户端行为与改动前一致（timeout/pool 配置照常）
  - 验证：`cargo test -p veil http_client` 全绿；`cargo test -p veil --test http_e2e_*` 无回退
  - 验证：design D9 记录 warn+降级与启动即错两案取舍

## 10. `H10` 失败通知有界跟踪

- [x] 10.1 `src/service/matrix/` 内新增通知子模块（`notify.rs`，apply 阶段定名）：`NotificationSpool` 持单一 `Arc<MatrixBot>` + 有界 `tokio::sync::mpsc` 队列 + 常驻消费者（`JoinHandle` 由 spool 持有，停机 abort/等待口径明确）；`notify_*` 用 `try_send`，满队列丢弃并计数 + warn
  - 验证：`cargo test -p veil notification_spool_bounded` 通过；容量满时占用不超限、丢弃计数 + 告警、无无界任务
  - 验证：`grep -n "tokio::spawn" src/service/credential/vault_ops.rs` 命中数为 0（通知改经 spool）
- [x] 10.2 `src/service/credential/mod.rs` 的 `AppStateParts` 增暴露访问器；`src/main.rs` 运行期启动消费者并接入 `src/service/credential/vault_ops.rs:122-134` 与 `src/service/credential/approval.rs:89-102` 同类通知
  - 验证：`cargo test -p veil notification_spool_reuse` 通过；多次通知仅一个 Bot 实例与一个消费者
  - 验证：`cargo test -p veil --test http_e2e_credential` 全绿；失败通知仍为 best-effort，凭据返回语义不变
- [x] 10.3 spool 生命周期测试：注入 fake sink + 小容量，验证有界、丢弃计数、消费者可跟踪与停机口径
  - 验证：`cargo test -p veil notification_spool_lifecycle` 通过
  - 验证：`cargo test -p veil --test http_e2e_approval` 全绿无回退

## 11. `H11` NonDialog 透传单一入口

- [x] 11.1 抽 NonDialog 专用透传入口（返回 `Response`，无 `Stream` 臂），`src/handler/llm/dispatch.rs:180-219` 删除不可达的 `NonstreamOutcome::Stream` 匹配臂；`src/handler/llm/nonstream.rs:96` 的 `is_passthrough` 早返分支随之下沉/收敛，`NonstreamOutcome::Stream`（`nonstream.rs:146`）仅保留对话路径语义
  - 验证：`grep -n "NonstreamOutcome::Stream" src/handler/llm/dispatch.rs` 在 NonDialog 分支命中数为 0（仅对话分支保留）
  - 验证：`cargo test -p veil nondialog_passthrough` 通过；`is_passthrough` 判定与透传路径语义不变
- [x] 11.2 行为不变测试：NonDialog 常规透传与「上游意外回 SSE」两场景状态码/正文字节逐字节一致，`nondialog_passthrough` 计数照常
  - 验证：`cargo test -p veil --test http_e2e_nondialog_passthrough` 全绿
  - 验证：proposal/design 交叉引用 `veil-transport-fidelity-fix` `T9` 转出；`grep -n "H11" openspec/changes/veil-arch-hygiene-closeout/design.md` 命中 D11

## 12. `H12` 集成测试脚手架统一

- [x] 12.1 新增 `tests/common/mod.rs`：导出 `base_env()`、`test_app(opts) -> (Router, AppState)` 与 `test_app_router(opts) -> Router`、`serve(app) -> (String, JoinHandle<()>)`，选项覆盖 `extra`/`cfg_mut`/`db`/`locked` 四参数族；`#![allow(dead_code)]` 避免各 crate 未用告警；Cargo 不改
  - 验证：`test -f tests/common/mod.rs` 且 `cargo test --no-run` 编译通过
  - 验证：`grep -n "fn serve" tests/common/mod.rs` 命中统一实现，字节等价于原 18 处拷贝
- [x] 12.2 18 个 `tests/*.rs`（含 `tests/http_e2e_approval.rs:36`、`tests/sentinel_sdk_replay.rs:31`）删除本地 `test_app()`/`serve()`/`base_env()` 拷贝，改 `mod common;` + 调用统一脚手架；`tests/mask_engine_diff.rs`/`tests/audit_perf_bound.rs`/`tests/sentinel_check_tests.rs` 三纯单测文件不动
  - 验证：`grep -rln "fn test_app" tests/*.rs` 仅命中 `tests/common/mod.rs`
  - 验证：`grep -rln "fn serve(" tests/*.rs` 仅命中 `tests/common/mod.rs`
- [x] 12.3 全部集成测试以统一脚手架运行，断言集与改动前等价
  - 验证：`cargo test -p veil --tests` 全绿；无测试用例删除或断言放松
  - 验证：design D12 记录四族参数化与不引入 dev-dependency

## 13. 门禁与归档准备

- [x] 13.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增守护/并发/确定性测试全绿，无既有测试回退
- [x] 13.2 `python3 scripts/check_file_sizes.py` 与 `python3 scripts/check_doc_paths.py` 退出 0
  - 验证：两脚本输出 `OK`/无 FAIL；`src/handler/llm/pump/spawn.rs`、`src/service/pii/scope.rs` 路径仍存在
- [x] 13.3 `openspec validate veil-arch-hygiene-closeout --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 13.4 交叉引用与边界终检：`A5`（审计语义归 `veil-audit-rules-parity`）、`P14`（锁中毒归 `veil-pii-parity-closeout`）、`T9`（由本 change `H11` 承接）三处互引一致；README 引用的 `src/` 路径不悬空
  - 验证：`grep -rn "veil-audit-rules-parity\|veil-pii-parity-closeout\|veil-transport-fidelity-fix" openspec/changes/veil-arch-hygiene-closeout/` 命中三处交叉引用
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0；`git diff --name-only` 不含 `src/`、`tests/`、`README.md`（本 change 规划期只交付 artifacts）
