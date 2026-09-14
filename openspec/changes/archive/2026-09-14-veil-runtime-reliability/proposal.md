## Why

独立六维审查（2026-09-14，运行时可靠性面）确认 4 项缺陷（RUN-1..RUN-4），其中 1 项 P1、3 项 P2，违反既有 spec/README 声明（指标以 sqlite 为准口径、管理面限流语义、审批等待行为）或造成静默数据丢失与无界内存增长：

- **`RUN-1`（P1）指标 sqlite 持久化从未接线 + `aggs` 无界增长**：`src/service/metrics/store.rs:183-196` 的 `flush`/`flush_to_sqlite_blocking` 零生产调用（仅测试引用）；`src/main.rs:126` 只调用 `backfill_from_sqlite`（读路径），写入路径永不落盘 → 重启丢全部指标；`aggs: Mutex<HashMap<AggKey, WindowAgg>>`（`src/service/metrics/store.rs:34`）无上限，窗口键随运行时长单调累积。
- **`RUN-2`（P2）管理面 IP 限流 map 无界**：`src/service/admin/state.rs:36` 的 `rate: Mutex<HashMap<IpAddr, Vec<Instant>>>` 每 IP 条目建后从不清理；`src/service/admin/ratelimit.rs::decide_rate_limit` 只对单条目做窗内裁剪，条目不回收。
- **`RUN-3`（P2）`ask()` 审批等待 50ms 忙轮询**：`src/service/matrix/approval.rs:239-266` 的 `ask` 在 `loop` 内 `tokio::time::sleep(Duration::from_millis(50))` 轮询 `pending` 决议，最长 300s 阻塞期内每秒约 20 次空转唤醒。
- **`RUN-4`（P2）上游读取错误静默吞没**：`src/handler/llm/nonstream.rs:361-375` 的 `read_bounded_body` 对 `chunk()` `Err` 直接返回 `BoundedBody::Complete(Vec::new())`；`src/handler/llm/nonstream.rs:146` 与 `src/handler/llm/dispatch.rs:328` 的 `up.bytes().await.unwrap_or_default()` 同样把读错误退化为空体，均无 warn、无指标。

真相源为上述 `src/` 文件、`README.md` §3/§4（管理面限流契约）与 canonical `openspec/specs/observability-admin/spec.md`（sqlite 用量口径以 sqlite 为准）。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 README；实现与文档同步留待 apply 阶段。

## What Changes

- **`RUN-1` 指标刷盘接线 + 聚合有界**：新增周期刷盘驱动（建议 60s interval，接线处见 design D1），并在进程退出时刷盘一次（`main.rs` 启动序列接入、关闭钩子见 design D1）；`aggs` 增加有界策略——按 retention 驱逐过期窗口 + 硬上限 `AGGS_MAX_ENTRIES` 的 LRU 驱逐，驱逐计入可观测计数。补「写入→重启→指标保留」「超上限后内存有界」回归测试。
- **`RUN-2` 限流条目有界清理**：为 `AdminState::rate` 增加周期清扫（TTL 无窗内命中即删）与硬上限驱逐，保持 `10/min/IP` 限流语义与 `Retry-After` 不变。补「大量不同 IP → 内存有界、限流仍生效」回归测试。
- **`RUN-3` 事件驱动唤醒**：`ask()` 由 50ms 轮询改为决议时唤醒（`watch`，机制见 design D3）；**`lock` 指令的两条决议路径 `lock_reject_all`/`lock_clear_all` 原先直接写 `entry.decided` 而绕过 `resolve`，须与 `resolve` 共用同一 `watch` 唤醒 setter**，否则 `lock` 期间阻塞的等待者收不到通知、空等至 `300s` TTL。外部行为（返回 `Some(decided)`/超时 `None`/超时清理）逐字不变。补「决议后即时醒来、无忙轮询」与「`lock` 期间 waiter 即时拒绝」回归测试。
- **`RUN-4` 读取错误可观测**：`read_bounded_body` 的 `Err` 分支与两处 `unwrap_or_default()` 记录 `tracing::warn!`（含错误与已读字节）并累加指标（指标落点见 design D4），对外语义（退化为空体、走既有空体分类）保持不变。补「上游读取错误在日志/指标可观测」回归测试。
- **文档同步**：`README.md` §3/§4（管理面限流契约）与 canonical `observability-admin` 相关段落如有口径补充在 apply 阶段与行为同批更新；本 change 不修改文档。

## Capabilities

### New Capabilities

- `runtime-reliability`：运行时可靠性契约——指标周期刷盘与关闭刷盘、重启后指标保留、指标聚合内存有界、管理面限流状态有界且语义不变、审批等待事件驱动（无忙轮询）、上游读取错误可观测。

### Modified Capabilities

- 无。本 change 新增 capability；既有 `openspec/specs/observability-admin/spec.md`（sqlite 用量口径与 `is_precise`、管理限流按 remote 与 SSE 5/IP）与 `openspec/specs/admin-ratelimit-contract/spec.md`（Admin 通用限流十每分）为本 change 的引用源与不变量约束：既有可观测契约（以 sqlite 为准、`10/min/IP`、`Retry-After`）不改变，本 change 只补齐「写入路径实际落盘」「状态内存有界」等运行时保障，故不产生 MODIFIED delta。若 apply 阶段实测需改既有 requirement 文本，另行提出并回到本 change 记录。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `RUN-1` | P1 | 周期刷盘（60s）+ 关闭刷盘接线；`aggs` 按 retention 驱逐 + 硬上限 LRU；写入→重启保留回归、超上限有界回归 | 1.1、1.2、1.3、1.4、1.5 |
| `RUN-2` | P2 | `AdminState::rate` 周期清扫（无窗内命中即删）+ 硬上限驱逐；限流语义不变；大量 IP 内存有界回归 | 2.1、2.2 |
| `RUN-3` | P2 | `ask()` 由 50ms 轮询改决议时唤醒（`watch`）；`resolve` 与 `lock_reject_all`/`lock_clear_all` 三路径共享同一 setter，`lock` 期间 waiter 即时拒绝；外部行为逐字不变；决议即时醒来 + 无忙轮询 + `lock` 即时唤醒/锁后正常路径/无丢唤醒回归 | 3.1、3.2、3.3 |
| `RUN-4` | P2 | `read_bounded_body` `Err` 与两处 `unwrap_or_default()` 记 warn + 指标；对外语义不变；上游错误可观测回归 | 4.1、4.2 |

## Non-Goals（显式）

- **不伪造指标数据**：重启保留只保证已刷盘窗口可回填，不承诺未刷盘窗口（进程被 `SIGKILL`）不丢失；不引入 WAL 之外的持久化机制。
- **不改既有可观测与限流契约**：`observability-admin`/`admin-ratelimit-contract` 声明的 `10/min/IP`、`Retry-After`、SSE `5/IP`、sqlite 口径与 `is_precise` 双条件均不变；本 change 只补运行时保障。
- **不改外部审批语义**：`ask()` 的返回值、超时归并与清理时序不变，仅替换内部等待原语；不迁移 Python 审批挂起保活（仍为既有 Non-Goal）。
- **不改「读取错误退化空体」的对外行为**：仅为可观测性补 warn/指标，是否传播错误另立 change 决策。
- **不改 `src/`、`tests/` 与 `README.md`**：本 change 只交付规划 artifacts，实现与文档改动留待 apply 阶段；不改 `openspec/changes/` 内其他既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-runtime-reliability/proposal.md`、`design.md`、`specs/runtime-reliability/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`src/service/metrics/store.rs`（刷盘驱动与 `aggs` 有界）、`src/service/metrics/aggregate.rs`（驱逐/计数）、`src/main.rs`（刷盘任务与关闭钩子接线）、`src/service/admin/state.rs` 与 `src/service/admin/ratelimit.rs`（限流条目有界）、`src/service/matrix/approval.rs`（事件驱动 `ask`）、`src/handler/llm/nonstream.rs` 与 `src/handler/llm/dispatch.rs`（读取错误观测）、对应单测/e2e。
- **影响系统**：指标重启保留与内存占用、管理面限流状态内存、审批等待的 CPU 空转、上游读取失败的运维可观测性。
- **依赖**：无新依赖；仅既有 `tokio`（`time`/`sync`）、`tracing`、`rusqlite`、`axum` 与测试设施。
