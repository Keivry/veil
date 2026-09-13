## Why

独立审计（2026-09-13，架构卫生面）确认 12 项发现（`H1`-`H12`）。均不违反功能契约，但累积技术债、确定性与资源跟踪风险，且部分项与既有 canonical 契约/模块自述漂移：

- **死码与死臂（`H1`/`H11`）**：`src/service/audit_hold.rs` 为零生产引用的兼容垫片；`src/handler/llm/dispatch.rs:180-219` 的 NonDialog `NonstreamOutcome::Stream` 臂因 `src/handler/llm/nonstream.rs:96` 首部透传早返而不可达。
- **热路径并发（`H2`）**：`src/service/llm_gateway/mod.rs:36-40` 四组 `Mutex<HashMap<String,u64>>`（`lenient`/`truncated`/`hop_filtered`/`conv_missing`）在请求/帧热路径上串行化，与同结构 `AtomicU64` 计数器（`:41-50`）口径分裂。
- **确定性与资源跟踪（`H3`/`H8`/`H9`/`H10`）**：`src/service/audit/rules.rs:135-142` 直读 `HOME`、`src/service/audit/normalize.rs:170,188` 的 `${VAR}` 回退进程 env，判定随环境漂移；`src/service/tpm.rs:105-145` 同步子进程忙轮询；`src/state.rs:159-160` HTTP client 构造失败静默丢配置；`src/service/credential/vault_ops.rs:122-134` KeePass 失败通知 fire-and-forget 无跟踪。
- **分层边界（`H4`/`H6`）**：`src/handler/credential.rs:80-221` 承载 ~120 行 DTO→域解析、`src/handler/mod.rs:25-27` 直读 `state.keepass/pending/vault`，与 handler 自述「纯透传层」不符。
- **可维护性（`H5`/`H7`/`H12`）**：7 文件贴近 800 行上限（两文件 772/余量 28）；锁序未文档化；15+ `tests/*.rs` 复制 `test_app()+serve()` 脚手架（签名六族漂移）。

真相源：`src/service/audit_hold.rs`、`src/service/llm_gateway/mod.rs`、`src/service/audit/rules.rs`、`src/service/audit/normalize.rs`、`src/handler/credential.rs`、`src/handler/mod.rs`、`src/handler/llm/dispatch.rs`、`src/handler/llm/nonstream.rs`、`src/service/credential/vault_ops.rs`、`src/service/credential/approval.rs`、`src/service/pii/custom.rs`、`src/service/pii/scope.rs`、`src/handler/llm/pump/spawn.rs`、`src/service/tpm.rs`、`src/state.rs`、`tests/*.rs`。

交叉引用：`H3` 与 change `veil-audit-rules-parity`（`A5`）互引——本 change 只做 env/home 注入机制与确定性，不重复实现策略语义；`H7` 对 `src/service/pii/custom.rs:321-322` 仅固化锁序，锁中毒 panic 由 change `veil-pii-parity-closeout`（`P14`）承接；`H11` 为 change `veil-transport-fidelity-fix`（`T9`）显式转出项，本 change 唯一负责。

## What Changes

- **`H1` 死垫片守护（保留 + 守护测试）**：`src/service/audit_hold.rs` 保留为兼容重导出并已有 DEPRECATED 指引；新增守护测试拒绝任何生产 `audit_hold::` 字面（垫片自身与测试白名单除外）；删除方案仅登记为备选（canonical `code-quality-cleanup` spec 要求路径保留，删除属 BREAKING 符号面，不采用）。
- **`H2` 热路径计数改固定键原子**：`GatewayMetrics` 四组 `Mutex<HashMap<String,u64>>` 改固定键 `AtomicU64`（协议尾 `/` 截断模式 `/` hop 方向 `/` conv 缺失原因四组有限键集），保留 `lenient_count`/`truncated_count`/`hop_filtered_count`/`conv_missing_count` 既有读接口与 `/_admin/metrics` 键名；未知键归 `other` 桶并 warn；补并发计数压测单测。
- **`H3` 审计 env/home 显式注入**：`expand_vars_single` 移除 `std::env::var` 回退（`src/service/audit/normalize.rs:170,188`），`extract_path_tokens`/`expand_home` 的 `HOME` 改注入（`src/service/audit/rules.rs:135-142`），`is_dangerous` 的 `HashMap::new()`（`rules.rs:283`）改注入启动期 env 快照；补空/定制 env 确定性单测。语义管线改动归 `veil-audit-rules-parity`（`A5`），本项不重复。
- **`H4` 注册 DTO→域解析下沉 service**：`parse_register_entries`/`parse_register_allow_mode`（`src/handler/credential.rs:80-221`）下沉为 service 层纯映射函数（`src/service/credential/` 内 `register_map` 子模块，apply 阶段定名），handler 仅提取原始字段并委派；迁移对应单测；更新层边界注释。
- **`H5` 贴近上限文件拆分**：`src/service/pii/scope.rs`（772）内联测试（`325-772`，448 行）外置为 `src/service/pii/` 下的测试子模块；`src/handler/llm/pump/spawn.rs`（772）抽 `guard`（`43-57`）与 `terminal`（`600-753`，154 行）子模块到 `src/handler/llm/pump/spawn/` 目录，保留 `spawn.rs`/`scope.rs` 文件路径不变；`check_file_sizes.py` 与既有测试全绿。
- **`H6` health 组装下沉 service**：`/health` 的 `unlocked`/`pending`/`llm_secrets` 由 `service::health_status` 经 `AppStateParts` 组装（trait 已暴露 `keepass()`/`pending()`/`vault()`），`src/handler/mod.rs:16-29` 仅序列化；`AppStateParts` 访问边界文档化；`/health` 字段只增不减行为不变测试。
- **`H7` 锁序不变量文档化**：模块文档固化已知锁序（`registry_save_lock → registry.write()`、`strikes → disabled`、流内 keepalive gate），新增路径审查清单 + 源码扫描守护测试；当前无死锁证据，仅固化不变量。
- **`H8` TPM 同步子进程约定与守护**：`src/service/tpm.rs` 模块文档声明「同步子进程仅启动期与 `spawn_blocking` 内调用，禁 async 上下文直调」；新增守护测试扫描生产调用点（启动期/`src/keepass.rs:200` 白名单），违规即失败；不迁移 `tokio::process`（避免改同步 trait 面）。
- **`H9` HTTP client 构造失败不静默**：`build_http_client`（`src/state.rs:148-161`）构造失败不再 `.unwrap_or_else(|_| Client::new())` 静默丢 timeout/pool 配置，改记 warn 并保留显式降级路径（或启动即错，见 design D9）；补测试。
- **`H10` KeePass 失败通知统一有界 spool**：`src/service/credential/vault_ops.rs:122-134` 的每失败新建 Bot + 无跟踪 `tokio::spawn` 改为复用实例 + 有界队列 + 常驻消费者（`JoinHandle` 跟踪、满队列丢弃计数/warn）；`src/service/credential/approval.rs:89-102` 同类通知并入同一 spool；补有界/跟踪/复用测试。
- **`H11` NonDialog 死臂删除**：`src/handler/llm/dispatch.rs:180-219` 不可达的 NonDialog `NonstreamOutcome::Stream` 臂删除，NonDialog 透传走专用入口（返回 `Response`，无 `Stream` 臂）；`NonstreamOutcome::Stream` 仅保留对话臂语义；NonDialog 字节透传行为不变测试。
- **`H12` 测试脚手架收敛**：新增 `tests/common/mod.rs` 统一 `base_env`/`test_app`/`serve`（参数化 `extra`/`cfg_mut`/`db`/`locked` 与元组返回），18 个 `tests/*.rs`（含 `tests/http_e2e_approval.rs`、`tests/sentinel_sdk_replay.rs`）删除本地拷贝改 `mod common;`；三个纯单测文件不动；全部 e2e 保持绿。
- **文档同步（apply 阶段）**：`H2`/`H4`/`H6`/`H8`/`H10`/`H11`/`H12` 涉及的模块/层边界注释与 README 必要说明随行为同批更新（行为不变项不新增外部契约）。

## Capabilities

### New Capabilities

- `arch-hygiene-closeout`：架构卫生收敛后的内部契约——死垫片零生产引用守护、热路径计数固定键原子化、审计 env/home 显式注入确定性、handler 纯透传分层边界、文件体量红线与拆分点、health 组装下沉、锁序不变量、TPM 同步子进程调用约束、HTTP client 构造失败不静默、失败通知有界跟踪、NonDialog 透传单一入口、测试脚手架统一。

### Modified Capabilities

- 无。canonical `openspec/specs/` 既有契约行为不动；`H1` 保留垫片与 `H11` 删除死臂均为内部结构收敛，对外可观测行为不变（`H2` 指标键名、`/health` 字段、NonDialog 字节透传、审批 202/300s 语义均保持）。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `H1` | low | 保留兼容垫片（已有 DEPRECATED 指引）+ 零生产 `audit_hold::` 引用守护测试；删除仅登记为备选（canonical 要求路径保留） | 1.1、1.2 |
| `H2` | med | 四组 `Mutex<HashMap>` → 固定键 `AtomicU64`（协议尾/截断模式/hop 方向/conv 原因），读接口与 `/_admin/metrics` 键名不变，未知键归 `other`；并发压测 | 2.1、2.2、2.3 |
| `H3` | med | env/home 显式注入（移除 `std::env::var` 回退与 `HashMap::new()`），审计判定随环境不漂移；空/定制 env 确定性单测；语义重做归 `A5` | 3.1、3.2、3.3 |
| `H4` | med | `parse_register_entries`/`parse_register_allow_mode` 下沉 service 纯映射函数，handler 仅透传；单测迁移；层边界注释 | 4.1、4.2 |
| `H5` | med | `scope.rs` 外置 448 行测试、`spawn.rs` 抽 `terminal`/`guard` 子模块；红线保持全绿、路径与文档引用不变 | 5.1、5.2、5.3 |
| `H6` | low | `/health` 组装下沉 `service::health_status` 经 `AppStateParts`；handler 零直读字段；字段只增不减行为不变测试 | 6.1、6.2 |
| `H7` | low | 锁序不变量入模块文档 + 新路径审查清单 + 源码扫描守护测试（`registry_save_lock→registry.write()`、`strikes→disabled`、keepalive gate） | 7.1、7.2 |
| `H8` | low | TPM 同步子进程「仅启动期/`spawn_blocking`」约定文档化 + 调用点守护测试；不迁移 `tokio::process` | 8.1、8.2 |
| `H9` | low | `build_http_client` 失败不静默丢配置：显式 warn 降级或启动即错；补测试 | 9.1、9.2 |
| `H10` | low | 失败通知统一有界 spool（复用实例 + 有界队列 + `JoinHandle` 跟踪 + 丢弃计数），`approval.rs` 同类通知并入 | 10.1、10.2、10.3 |
| `H11` | low | 删除 `dispatch.rs:180-219` NonDialog `NonstreamOutcome::Stream` 死臂，改专用透传入口（返回 `Response`）；字节透传行为不变测试（`T9` 转出承接） | 11.1、11.2 |
| `H12` | low | `tests/common/mod.rs` 统一 `base_env`/`test_app`/`serve`（四参数族 + 元组返回），18 文件迁移；全部 e2e 绿 | 12.1、12.2、12.3 |

## Non-Goals（显式）

- **`H3` 不重做策略语义**：参数规范化管线语义（文本赋值挖掘、别名折叠、`..` 归一等）归 change `veil-audit-rules-parity`（`A5`），本 change 只做 env/home 注入机制与确定性；若 `A5` 先落地，本项按其后签名适配，不重复实现。
- **`H7` 不修锁中毒 panic**：`src/service/pii/custom.rs` 的 `.expect("检测器锁无毒")` 中毒修复归 change `veil-pii-parity-closeout`（`P14`）；本项仅固化锁序不变量，不改锁实现。
- **`H1` 不删除兼容垫片**：canonical `openspec/specs/code-quality-cleanup/spec.md` 要求 `src/service/audit_hold.rs` 路径与符号保留；删除需 canonical MODIFIED delta 且属 BREAKING 符号面，本 change 不采用（仅在 design D1 登记备选与理由）。
- **`H8` 不迁移 `tokio::process`**：改异步需重构同步 `TpmUnlock` trait 及 `spawn_blocking` 调用面，收益不抵改动面；采用「约定 + 守护测试」（见 design D8）。
- **不改可观测行为与外部契约**：`H2` 指标键名、`H6` `/health` 字段、NonDialog 字节透传、流式/审批语义与阈值不变；本 change 不新增 BREAKING 配置项。
- **不改 `src/`、`tests/` 与 README**：本 change 只交付规划 artifacts；实现与文档改动留待 apply 阶段；不改 `openspec/changes/` 内任何既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-arch-hygiene-closeout/` 下 `proposal.md`、`design.md`、`specs/arch-hygiene-closeout/spec.md`、`tasks.md`（`.openspec.yaml` 已就位）。
- **apply 阶段改动面**：`src/service/audit_hold.rs`、`src/service/mod.rs`、`src/service/llm_gateway/mod.rs`、`src/service/llm_gateway/{protocol,hop,tool}.rs`、`src/handler/admin.rs`、`src/service/audit/{rules,normalize,policy}.rs`、`src/handler/credential.rs`、`src/service/credential/{mod.rs,vault_ops.rs,approval.rs}`、`src/service/pii/{scope.rs,custom.rs}`、`src/handler/llm/pump/spawn.rs`、`src/handler/llm/pump.rs`、`src/handler/llm/{dispatch.rs,nonstream.rs}`、`src/handler/mod.rs`、`src/service/tpm.rs`、`src/keepass.rs`、`src/state.rs`、`src/service/matrix.rs`、`src/service/credential/mod.rs`、`tests/common/mod.rs` 与 18 个 `tests/*.rs`，以及对应单测与必要注释。
- **影响系统**：网关度量并发写入路径、审计判定确定性、凭据注册分层、模块体量与拆分点、健康探针组装、锁序可审计性、TPM 调用约束、HTTP 客户端构造失败可见性、Matrix 通知资源跟踪、NonDialog 透传结构、集成测试脚手架复用。
- **依赖**：无新依赖；沿用既有 `tokio`（`mpsc`/`spawn_blocking`）、`axum`、`reqwest`、`serde_json`、`std::sync::atomic` 与测试设施。
