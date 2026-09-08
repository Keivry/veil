## Why

审查确认分层正确（`router→handler→service→state→config`，`http_client` 单例、`spawn_blocking` 包 rusqlite、`moka/keepass` 选型克制），但 4 处架构债与 6 处文档不一致未立项：`handler.rs` 2532 行（凭据与 LLM 泵混居，`gateway-pipeline-units` 未完全落地）；`credential_hits/register_hits: Mutex<HashMap>` 只插不扫（Python 有 1000 次/60s 双触发清扫，长跑内存涨）；Metrics `wal_checkpoint(TRUNCATE)` 与 `QueueFull 丢最老计 dropped` 只有语义继承无显式单测；KeePass 串行化语义未文档化；文档侧 `redaction.rs:246 off 视为启用` 与 `Config::is_falsy` 矛盾、`10MB vs 8MB` 表头缺“是否接入口”致误读、Go 对接表缺 `registrations` 鉴权列、端口章节“不存在多端口重构”措辞自相矛盾、`VeilError` 状态码分散、`approve` 与跨片 hold 若选 B 案需进 BREAKING/威胁模型。本 change 一次收敛，不碰网关语义与测试门限。

## What Changes

- **架构 1，拆 `handler.rs`**：按 `gateway-pipeline-units` 收尾拆为 `handler/credential.rs` + `handler/llm.rs`（`request_rewrite/nonstream/stream_pump` 接线），`router.rs` 只做路由装配；`error.rs` 头部集中状态码表（`Pending→202/Auth→403/RateLimited→429` 等）。
- **架构 2，限流表有界化**：`credential_hits/register_hits` 加容量上限（`MAX_ENTRIES=4096`）+ `check_rate` 内联双触发清扫（对齐 Python 双触发语义：超 1000 键或距上次清扫超 60s 时清过期键，不新增后台任务，口径以 `design.md D2` 为准），`admin` 限流清扫语义文档化。
- **架构 3，可观测与并发显式化**：Metrics 加 `wal_checkpoint(TRUNCATE)` 定时 + `QueueFull` 丢最老单测；KeePass 串行化（`semaphore(1)` 等价）文档化到 `keepass.rs` 头注释；`registry RwLock` 维持现状（读多写少可接受，`check_entry_allowed` 已移出锁外），文档一句声明。
- **文档 4，六处一致性修复**：删 `redaction.rs:246 off` 矛盾注释以 `Config` 为准；阈值表加“是否接入口”列；Go 对接表加鉴权列（`registrations` 需管理面 token）；端口章节改写为“单进程单监听 + 宿主机入口区分”；`approve`/跨片 hold 若选 B 案则进 §6 BREAKING/威胁模型；`scripts/api_conformance.py` 与豁免注释同字。

## Capabilities

### New Capabilities

- `arch-docs-cleanup`：handler 拆分、限流有界、观测显式、六处文档一致性修复。

### Modified Capabilities

- 无。既有 spec 需求不动；只做结构拆分与文档收敛。

## Non-Goals（显式）

- 不改网关注入/阻断/审计语义（见 gateway/approval changes）。
- 不加测试门限（见 test-closure-round2）。
- 不改既有 change 文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-arch-docs-cleanup/` 下 proposal/design/specs/tasks；apply 阶段拆 `src/handler.rs`、改 `src/state.rs` 限流表、`src/service/metrics.rs` checkpoint、改 README 与注释。
- **影响系统**：长跑内存稳定性、代码可维护性、文档可信度；无协议行为变更（拆分保持行为一致，conformance 回归）。
- **依赖**：`rusqlite` checkpoint；限流清扫为请求路径内联，无需新增 `tokio` 后台任务；无需新依赖。
