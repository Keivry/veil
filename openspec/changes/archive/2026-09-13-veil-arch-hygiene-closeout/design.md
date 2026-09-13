## Context

独立审计（2026-09-13）在架构卫生面确认 12 项发现（`H1`-`H12`，见 proposal Why 与覆盖表）。现状真相源：

- `src/service/audit_hold.rs` 仅 `pub use super::audit::{...}`，全仓零生产引用（grep `audit_hold::` 仅本文件注释自命中）；`src/service/mod.rs:9` 仍声明 `pub mod audit_hold;`。canonical `openspec/specs/code-quality-cleanup/spec.md` 要求该路径与符号保留。
- `GatewayMetrics`（`src/service/llm_gateway/mod.rs:34-51`）四组 `Mutex<HashMap<String,u64>>` 与 8 个 `AtomicU64` 混用；写点 `:55,68,88,101`、读点 `:62,75,95,108`。键集实际有限：`lenient`（`chat/completions`/`v1/messages`/`v1/responses`）、`truncated`（`open_ended`/`synthesized_failed`，见 `src/service/sse/meta.rs:10-21`）、`hop_filtered`（`upstream`/`downstream`）、`conv_missing`（`failed`/`block`/`truncated`/`nondialog-stream`/`nonstream-block`）。
- `src/service/audit/rules.rs:283` 用空 `HashMap` 调 `canonicalize_args`，`normalize.rs:170,188` 回退 `std::env::var`，`rules.rs:135-142` 读 `HOME`——判定随进程环境漂移、单测不确定。语义管线重做由 `veil-audit-rules-parity`（`A5`）负责。
- `src/handler/credential.rs:80-221` 的 `parse_register_entries`（~120 行）+ `parse_register_allow_mode`；`src/handler/mod.rs:16-29` 直读 `state.keepass/pending/vault`。
- `src/service/pii/scope.rs` 772 行（内联测试 `325-772`，448 行）；`src/handler/llm/pump/spawn.rs` 772 行（`spawn_stream_pump` 单函数 `61-772`，测试外置 `spawn_tests.rs`）。其余贴近线文件余量 45-82（见 design 迁移节）。
- 锁序未文档化：`src/service/credential/vault_ops.rs:214-216`（`registry_save_lock → registry.write()`）、`src/service/pii/custom.rs:321-322`（`strikes → disabled`）、流内 keepalive gate；`src/service/tpm.rs:105-145` 忙轮询 + `:159` 同步 `Command`。
- `src/state.rs:159-160` `.build().unwrap_or_else(|_| reqwest::Client::new())` 静默丢 timeout/pool；`src/service/credential/vault_ops.rs:122-134` 每失败新建 Bot + `tokio::spawn` 无跟踪（`src/service/credential/approval.rs:89-102` 同类）。
- `src/handler/llm/dispatch.rs:180-219` NonDialog `NonstreamOutcome::Stream` 臂因 `src/handler/llm/nonstream.rs:96` 首部透传早返不可达；`tests/*.rs` 18 文件复制 `test_app()`/`serve()`（签名六族）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 README；对外可观测行为不变；`H3` 语义归 `A5`、`H7` 锁中毒归 `P14`、`H11` 为 `T9` 转出项；无新依赖。

## Goals / Non-Goals

**Goals：**

- 给出 `H1`-`H12` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「零生产引用守护」「固定键原子计数」「env/home 显式注入」「分层边界」「文件体量红线与拆分点」「锁序不变量」「TPM 调用约束」「构造失败不静默」「通知有界跟踪」「NonDialog 单一入口」「测试脚手架统一」收敛为 spec 契约。
- 固化「保留兼容垫片」「不迁移 `tokio::process`」「不做 DTO 解析入 registry 域」「测试文件外置」等决策理由，防止后续 change 反向漂移。

**Non-Goals：**

- 不重做审计规范化语义（`A5`）、不修 PII 锁中毒 panic（`P14`）、不反向触碰 `T9` 转出前的 `veil-transport-fidelity-fix` 决策。
- 不改任何对外可观测行为：`/_admin/metrics` 键名、`/health` 字段、NonDialog 字节透传、流式/审批/阈值语义均不变。
- 不删 `src/service/audit_hold.rs`（见 D1）；不改 `TpmUnlock` trait 为 async（见 D8）；不给 `tests/common` 引入新 dev-dependency（见 D12）。
- 不改 `src/`、`tests/` 与 README（apply 阶段才实施）。

## Decisions

### D1：`H1` 保留兼容垫片 + 零生产引用守护，删除列为备选不采用

**决策**：`src/service/audit_hold.rs` 保留为兼容重导出（已有 DEPRECATED 指引），在 `src/service/mod.rs` 模块声明不变；新增守护测试扫描 `src/`，断言除垫片文件本体与测试白名单外零 `audit_hold::` 字面。删除方案仅在 proposal Non-Goals 登记。

**理由**：canonical `openspec/specs/code-quality-cleanup/spec.md` 明确要求该路径收敛为「仅重导出加废弃指引」且符号保留；删除会移除 `veil::service::audit_hold` 公开符号面（BREAKING），需 canonical MODIFIED delta，超出只增不改的收口范围。审计诉求「零生产引用」由守护测试承接，而非靠删除达成。

**备选**：删除文件 + 模块声明（全门禁可绿，但违反 canonical 并要求 canonical delta），不采用；保持现状不守护（无法防回流），不采用。

### D2：`H2` 四组 `Mutex<HashMap>` 改固定键 `AtomicU64`，读接口与键名不变

**决策**：`GatewayMetrics` 把 `lenient`/`truncated`/`hop_filtered`/`conv_missing` 改为固定键原子计数器（按已知键集枚举映射到 `AtomicU64`）；保留 `record_*`/`*_count(&str)` 方法签名与语义（已知键精确、未知键归 `other` 桶并 warn 一次）。`/_admin/metrics` 的 `chat_tail_lenient` 三键与 `truncated`/`sse_events` 读数不变。

**理由**：键集由调用点决定且有限（协议尾 3、截断模式 2、hop 方向 2、conv 原因 5），固定键原子即可消除热路径 `Mutex<HashMap>` 串行点，并与既有 `AtomicU64` 计数器口径统一；`&str` 读接口保留使外部键名契约与 `src/handler/admin.rs:266-269` 零改。

**备选**：分片 `Mutex<HashMap>`（仍持锁、复杂度更高），不采用；删 `&str` 接口改枚举签名（波及全部调用点与测试、外部键名面变化），不采用。

### D3：`H3` env/home 经注入视图显式传入，纯逻辑零进程 env 读取

**决策**：`src/service/audit/normalize.rs` 的 `expand_vars_single` 删除 `std::env::var` 回退（仅用传入 `env`）；`src/service/audit/rules.rs` 的 `extract_path_tokens`/`expand_home` 改由注入的 home 决定；`is_dangerous` 的 `HashMap::new()`（`rules.rs:283`）改传启动期 env 快照（经既有 `AuditPolicy` 或显式参数承载，apply 阶段定名，优先复用 `AuditPolicy` 以免动公开签名）。快照由 `Config`/启动路径捕获，测试以空/定制 map 构造确定性用例。

**理由**：判定读进程 env 使同输入随部署漂移、单测依赖宿主机；显式注入后纯函数可复现，且与 Python 原仓 `os.environ` 语义经「启动期快照」等值保持。语义管线（拆链、别名、`..`、文本赋值挖掘）重做归 `A5`，本项只动 env/home 来源，避免双 change 重复实现。

**备选**：继续读进程 env（缺陷保留），不采用；把 env 快照塞进全局 `OnceLock`（仍是隐式全局，测试难隔离），不采用。

### D4：`H4` 注册 DTO→域解析下沉 service 纯映射函数

**决策**：`src/handler/credential.rs:80-221` 的 `parse_register_entries`/`parse_register_allow_mode` 下沉为 service 层纯映射函数（`src/service/credential/` 内 `register_map` 子模块，apply 阶段定名），输入为原始 JSON 值/字符串（不依赖 handler DTO 类型），输出 `crate::registry::RegisterParams` 的 `entries`/`allow_mode`；handler 仅提取字段并委派。对应单测随函数迁移。

**理由**：handler 模块自述「纯透传层，业务语义归 service」；DTO→域映射是业务语义，下沉后层边界与自述一致，且纯函数可独立单测。映射输入取原始值而非 `RegisterBody`，避免 service 反向依赖 handler（保持 `service -> handler` 边不存在）。

**备选**：下沉进 `src/registry.rs`（registry 域不应知道 handler DTO，且其已是门面+子模块结构），不采用；留在 handler 仅加注释（边界仍失真），不采用。

### D5：`H5` 先外置测试再抽尾段子模块，保留 `scope.rs`/`spawn.rs` 路径

**决策**：

- `src/service/pii/scope.rs`：内联 `#[cfg(test)] mod tests`（`325-772`，448 行）外置为 `src/service/pii/` 下的测试子模块（`scope_tests.rs`），在 `src/service/pii.rs` 以 `#[cfg(test)] mod scope_tests;` 声明；生产段（`1-324`）按需再按 poison/token/分配器/注册/还原边界评估，本轮至少完成测试外置。
- `src/handler/llm/pump/spawn.rs`：抽 `guard`（`43-57`）与 `terminal`（`600-753`，154 行）到 `src/handler/llm/pump/spawn/` 子目录模块（`guard.rs`/`terminal.rs`），在 `spawn.rs` 内 `mod guard; mod terminal;` 声明并按需 `pub(crate)` 重导出；帧循环主体（`162-599`，多可变状态）不动，避免跨模块可变借用 churn。
- 两文件保留原路径（Rust 2018 mixed layout：`spawn.rs` + `spawn/` 子目录），README 与 spec 的 `src/handler/llm/pump/spawn.rs`、`src/service/pii/scope.rs` 引用不悬空。

**理由**：`scope.rs` 测试占 58%，外置是零生产语义 churn 的最大红利；`spawn.rs` 尾段（截断/补 DONE/空流合成）依赖少、内聚，与既有 `decide`/`event`/`block_inject` 纯函数边界对齐，是低风险缝。保留文件路径避免 `check_doc_paths.py` 与 README 行号引用连带返工。

**备选**：`spawn.rs` 转 `spawn/mod.rs`（文档路径 `spawn.rs` 悬空，check_doc_paths 失败），不采用；硬拆帧循环（跨模块多可变借用，churn/回归风险高），不采用。

### D6：`H6` health 组装下沉 `service::health_status`，handler 仅序列化

**决策**：`service::health_status` 经 `AppStateParts`（已暴露 `keepass()`/`pending()`/`vault()`）组装 `unlocked`/`pending`/`llm_secrets`（`HealthStatus` 加字段），`src/handler/mod.rs` 仅把 `HealthStatus` 序列化为既有 JSON 形态；handler 不再直读 `state.keepass/pending/vault`。`AppStateParts` 的访问边界与「只读快照」语义写入模块文档。

**理由**：与 `A1` 依赖倒置（trait 读态）一致，纯组装逻辑归服务层；`/health` 字段名与只增不减契约不变，属行为不变的内部收敛。

**备选**：handler 内保留直读仅加注释（边界仍失真），不采用；给 handler 传更窄的专用 trait（新增抽象超出 finding），不采用。

### D7：`H7` 锁序不变量文档化 + 审查清单 + 源码扫描守护

**决策**：在 `src/service/credential/vault_ops.rs`、`src/service/pii/custom.rs`、流内 keepalive gate 所属模块文档固化锁序不变量：① `registry_save_lock` 先于 `registry.write()`（写路径统一序）；② `strikes` 先于 `disabled`；③ keepalive gate 不逆序获取 hold 锁。新增审查清单（design 本节为清单真源）与源码扫描守护测试（沿用 `src/service/mod.rs` 声明锁定的扫描模式），对已登记写路径断言获取顺序。

**理由**：当前无死锁证据，属预防性固化；源码扫描测试与项目既有 `service_layer_declaration_matches_implementation` 模式一致，成本低且可回归。锁中毒 panic 归 `P14`，本项不改锁实现。

**备选**：仅口头约定（无回归保护），不采用；引入运行时锁序检测（重依赖/侵入），不采用。

### D8：`H8` TPM 同步子进程「仅启动期/`spawn_blocking`」约定 + 守护测试

**决策**：`src/service/tpm.rs` 模块文档声明：同步 `Command`/忙轮询实现仅允许启动期与 `spawn_blocking` 内调用，禁在 async 上下文直调；新增守护测试扫描 `src/` 中 `RealTpm`/`tpm2_*` 调用点，仅白名单 `src/service/tpm.rs`、启动期（`src/main.rs`）与 `src/keepass.rs:200` 的 `spawn_blocking` 闭包，违规即失败。忙轮询保留在阻塞语境（可接受）。

**理由**：当前调用点已合规（启动期 + `spawn_blocking`），核心风险是未来新增 async 直调；约定 + 守护把隐性约束显性化。迁移 `tokio::process` 需把同步 `TpmUnlock` trait 与 `spawn_blocking` 调用面改异步，收益不抵改动面。

**备选**：迁移 `tokio::process` + async trait（改动面大、连锁 `src/keepass.rs`/`startup_tpm_in`），不采用；不设守护（约束不落地），不采用。

### D9：`H9` HTTP client 构造失败显式 warn + 保留降级客户端

**决策**：`build_http_client`（`src/state.rs:148-161`）把构造结果抽为可注入内部核心（`#[cfg(test)]` 可注入必然失败），生产路径失败时 `tracing::warn!` 记录失败原因并以 `Client::new()` 显式降级（保留可用性），不再 `unwrap_or_else(|_| ...)` 静默吞错。启动即错（`AppState::new -> Result`）列为备选。

**理由**：`Config` 已校验并 `max(1)` 钳位 timeout/pool，构造失败概率极低，fail-fast 会强迫 `AppState::new` 全链改 `Result`（测试与调用点大波及）；warn + 显式降级在低风险下消除「静默丢配置」缺陷，且可通过注入失败单测锁定告警与降级行为。

**备选**：启动即错（fail-closed，但 `AppState::new` ripple 大），不采用；维持静默（缺陷保留），不采用。

### D10：`H10` 失败通知统一有界 spool（复用实例 + 跟踪 + 丢弃计数）

**决策**：在 `src/service/matrix/` 内新增通知子模块（`notify.rs`，apply 阶段定名）承载 `NotificationSpool`：持 `Arc<MatrixBot>`（进程内复用，不再每失败新建）+ 有界 `tokio::sync::mpsc` 队列 + 常驻消费者任务（`JoinHandle` 由 spool 持有，Drop/停机时 abort/等待口径明确）；`notify_*` 用 `try_send`，满队列丢弃并记计数 + warn（不阻塞请求热路径）。`src/service/credential/vault_ops.rs:122-134` 与 `src/service/credential/approval.rs:89-102` 改经 spool（经 `AppStateParts` 暴露）；消费者在 `src/main.rs` 运行期启动。测试以可注入 sink + 小容量验证有界/跟踪/复用。

**理由**：失败通知是 best-effort，但「每失败新建 Bot + 无界 `tokio::spawn` 无跟踪」在故障风暴下无背压、无法观测；有界 spool 统一入口并把资源生命周期显式化。`src/service/matrix/` 是 Matrix 通知的既有归属（`MatrixBot` 定义处）。

**备选**：仅复用 `Arc<MatrixBot>` 仍 fire-and-forget（仍无背压/跟踪），不采用；改同步 `await` 发送（拖慢失败路径、放大风暴），不采用。

### D11：`H11` 删除 NonDialog 死臂，改专用透传入口

**决策**：`src/handler/llm/dispatch.rs:180-219` 的 `NonDialog` 分支不再经 `NonstreamOutcome::Stream` 匹配，改调用专用透传入口（返回 `Response`，无 `Stream` 臂）；`src/handler/llm/nonstream.rs:96` 的 `is_passthrough` 早返分支随之下沉/收敛，`NonstreamOutcome::Stream` 仅保留对话路径（`nonstream.rs:146`）语义。以「NonDialog 请求上游意外回 SSE 仍按字节透传」的既有 e2e 锁定行为不变。

**理由**：透传路径首部早返使 `Stream` 臂不可达，死臂给读者错误暗示（以为 NonDialog 会解析 SSE）；专用入口使类型即契约（透传不产 `Stream`）。`T9` 已把该分支显式转出给本 change，`veil-transport-fidelity-fix` 不触碰。

**备选**：保留调用 + `unreachable!()`/断言（运行期炸弹、可读性差），不采用；仅加注释（死臂仍在），不采用。

### D12：`H12` `tests/common/mod.rs` 统一 harness，参数化四族

**决策**：新增 `tests/common/mod.rs` 导出 `base_env()`、`test_app(opts) -> (Router, AppState)`/`test_app_router(opts) -> Router`、`serve(app) -> (String, JoinHandle<()>)`，以选项结构覆盖现存四参数族（`extra`/`cfg_mut`/`db`/`locked`）与两类返回（Router 或 `(Router, AppState)`）；18 个 `tests/*.rs` 删本地拷贝并 `mod common;`（每 crate 独立编译，`common/mod.rs` 非 test target，Cargo 无需 `[[test]]`）；`tests/common/mod.rs` 加 `#![allow(dead_code)]` 以避免各文件未用符号告警。三个纯单测文件（`tests/mask_engine_diff.rs`、`tests/audit_perf_bound.rs`、`tests/sentinel_check_tests.rs`）不动。

**理由**：`serve` 18 处逐字节一致、`test_app` 六族漂移，统一后新增 e2e 零拷贝；参数化设计保留各文件既有 env/db/locked/cfg 差异，迁移是等价替换。无新依赖、无需改 Cargo。

**备选**：按签名族拆多个 helper 文件（仍分散、导入面复杂），不采用；宏生成 harness（可读性与调试成本高），不采用。

## Risks / Trade-offs

- [`H2` 改原子后未知键静默丢] → 未知键归 `other` 桶并 warn 一次，`/_admin/metrics` 已知三键断言 + 并发压测锁定总数一致；键名契约不变。
- [`H3` 移除进程 env 回退改变生产行为] → 注入快照取启动期进程 env，与现状等值；仅「快照后环境变化」场景不同（启动后 env 变更本就不应影响判定），README 无需 BREAKING（内部实现），design 记录。
- [`H5` 抽取子模块引入可见性/调用面回归] → 经父模块重导出保持路径；`spawn.rs`/`scope.rs` 路径与 README 引用不变；拆分后 `check_file_sizes.py` + 全量单测绿。
- [`H9` warn+降级后配置仍被丢弃] → 降级行为显式可见（warn 含原因）且可观测；若后续要求 fail-closed，另立 change（design D9 备选）。
- [`H10` spool 满队列丢弃通知] → best-effort 语义不变，丢弃记计数 + warn；有界防故障风暴放大。
- [`H12` 共享 `common` 被某文件未用告警] → `#![allow(dead_code)]` + 仅 `mod common;`；e2e 全绿锁定等价。
- [跨 change 落地顺序] → `H3` 与 `A5` 同触 `normalize.rs`/`rules.rs`：本项仅改注入源，`A5` 改语义；若 `A5` 先落地，本项按 `A5` 后签名适配。`H7` 不改 `custom.rs` 锁实现（`P14` 负责）。

## Migration Plan

1. 按 tasks 顺序落地：先零/低 churn 项（`H1`/`H6`/`H8`/`H9`），再注入与分层（`H3`/`H4`），再并发与通知（`H2`/`H10`），再结构拆分（`H5`/`H11`/`H12`），最后锁序文档（`H7`）与门禁。
2. 每组独立 `cargo test -p veil <组>`；结构类项以现有 e2e 锁定行为不变；`cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`check_file_sizes.py`、`check_doc_paths.py` 全绿。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；全部改动为内部结构/注入/跟踪收敛，对外行为与指标/健康字段不变。

## Open Questions

- 无。`A5`/`P14` 边界已在 D3/D7 与 proposal Non-Goals 固化；若 apply 阶段 `AuditPolicy` 不便于承载 env 快照，按 D3「显式参数」备选落地并回写本 design 差异。
