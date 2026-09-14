## Context

独立六维审查（2026-09-14）在运行时可靠性面确认 4 项缺陷（见 proposal Why 与覆盖表）。现状真相源：

- **写路径缺失**：`src/service/metrics/store.rs:183-196` 的 `flush`（异步快照 + `spawn_blocking` + 覆盖式 UPSERT）与 `:171-181` 的 `flush_to_sqlite_blocking`（`#[cfg(test)]`）在生产零调用；全仓 `.flush().await` 仅出现在测试（`src/service/metrics/store/tests.rs`、`src/service/metrics/aggregate/tests.rs`、`src/service/metrics/summarize.rs` 测试段）。`src/main.rs:126` 仅 `backfill_from_sqlite`（读）。
- **聚合无界**：`src/service/metrics/store.rs:34` `aggs: Mutex<HashMap<AggKey, WindowAgg>>`；`AggKey` 含 `granularity/window/protocol`（`src/service/metrics/aggregate.rs:144-148`），`window` 为 `d{days}`/`h{hours}`/`m{win}` 整数序键（`:168-182`），随运行时长单调新增。
- **限流无界**：`src/service/admin/state.rs:36` `rate: Mutex<HashMap<IpAddr, Vec<Instant>>>`；`src/service/admin/ratelimit.rs::decide_rate_limit` 仅 `hits.retain(...)` 裁单条目窗内命中，条目本身不删。
- **忙轮询**：`src/service/matrix/approval.rs:239-266` 的 `ask` 在 `loop` 内每 50ms `sleep` 后重查 `pending`（`:263`）。
- **静默吞错**：`src/handler/llm/nonstream.rs:361-375` `read_bounded_body` 的 `Err(_) => return BoundedBody::Complete(Vec::new())`；`src/handler/llm/nonstream.rs:146` 与 `src/handler/llm/dispatch.rs:328` 的 `up.bytes().await.unwrap_or_default()`。

引用源与不变量：`README.md` §3（限流规则：`10/min/IP` + `Retry-After` + 按 TCP 远端计数）、§4（阈值表：通用 admin 限流 `10/min`/IP）；canonical `openspec/specs/observability-admin/spec.md`「sqlite 用量口径与 is_precise」「管理限流按 remote 不读 XFF 与 SSE 5/IP」；canonical `openspec/specs/admin-ratelimit-contract/spec.md`「Admin 通用限流十每分」。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 README；不新增依赖；不改既有可观测/限流/审批对外契约。

## Goals / Non-Goals

**Goals：**

- 给出 `RUN-1`..`RUN-4` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「指标周期/关闭刷盘」「聚合内存有界」「限流状态有界」「审批事件驱动」「读取错误可观测」收敛为 spec 契约，既有对外语义逐字保留。
- 记录关键决策（刷盘周期、`aggs` 有界策略、唤醒机制、读错误观测落点）及其备选，供实现与复核对照。

**Non-Goals：**

- 不承诺「未刷盘窗口零丢失」：仅保证周期/关闭刷盘写出的窗口可回填；进程被强杀丢失内存窗口属已声明范围。
- 不改 `10/min/IP`、`Retry-After`、SSE `5/IP`、sqlite 口径与 `is_precise` 双条件（引用源不变量）。
- 不改 `ask()` 返回值/超时归并/清理时序；不迁移 Python 审批挂起保活。
- 不把上游读取失败改为向调用方传播新错误码（保持退化空体对外语义）。
- 不改 `src/` 实现与 README（本 change 只交付规划）；不提交 commit。

## Decisions

### D1：刷盘周期 `60s` + 关闭刷盘接线（`RUN-1`）

**决策**：新增周期刷盘驱动 `MetricsStore::spawn_flush_driver(interval)`（或等价自由函数），启动后台 `tokio::time::interval` 任务，默认间隔 `60s`（常量 `METRICS_FLUSH_INTERVAL_SECS = 60`，登记为内部常量）；每 tick 调用既有 `flush().await`，失败仅 `tracing::warn!`。`main.rs` 在 `state.notify.start()` 邻近处启动该驱动并持有 `JoinHandle`；`axum::serve` 改用 `with_graceful_shutdown(shutdown_signal())`，在 `SIGINT`/`SIGTERM` 后、进程返回前调用一次 `flush().await`（设短超时如 5s，避免退出悬挂）。`flush` 内部已是「快照 + `spawn_blocking`」，满足非阻塞要求。

**理由**：`60s` 与既有 `RateTable::SWEEP_SECS`/`PENDING_TTL_SECS`（README §4.1 注册的内部常量均为 60）同节奏，运维熟悉且写入放大可控；关闭刷盘消除「正常重启也丢指标」的主要缺口。周期与关闭双路径复用同一 `flush`，无新持久化机制。

**备选**：① 写时即时刷盘——每请求触盘，写入放大与锁竞争高，不采用；② 仅关闭刷盘无周期——长进程崩溃丢全部，观测不可用，不采用；③ 复用 PII 采样驱动的 broadcast 队列——指标为覆盖式窗口快照而非追加事件，语义不符，不采用。

### D2：`aggs` 有界＝retention 驱逐 + 硬上限 LRU（`RUN-1`）

**决策**：在写路径（`record_chat_extended`/`record_aux_counts` 落库前或独立周期清扫）执行两步约束：① **retention 驱逐**——与 `purge_retention_blocking` 同口径（daily 保留最新 32 窗×协议、hourly 保留 170 窗×协议、five_min 每协议只留最新窗口）删除内存中过期 `AggKey`；② **硬上限**——常量 `AGGS_MAX_ENTRIES`（建议 `4096`，与 README §4.1 `RateTable::MAX_ENTRIES` 同量级），超限时按 `WindowAgg` 的最近更新时刻 LRU 驱逐。新增可观测计数 `aggs_evicted_total` 与既有 `dropped` 一并暴露；被驱逐窗口已刷盘则 sqlite 数据不受影响，重启可回填。

**理由**：`aggs` 的键维度受 retention 约束，过期驱逐即恢复「内存窗口＝近期窗口」语义；硬上限兜底防御异常键膨胀（如协议串异常）。驱逐与刷盘解耦（先刷后逐不强制），因 sqlite 侧已有 retention 裁剪且回填覆盖式，驱逐仅损失「尚未被查询的内存态」而不破坏对外口径。

**备选**：① 仅硬上限无 retention——驱逐最新窗口会破坏近期查询，不采用；② 仅 retention 无硬上限——异常键仍可无界，不采用；③ `aggs` 改 `BTreeMap` 按窗口排序驱逐——`HashMap` 查找热路径更快，且 LRU 需额外时间戳字段，排序结构收益不抵改动面，不采用。

### D3：审批唤醒由 50ms 轮询改 per-entry `watch`，并覆盖 `resolve` 与 `lock` 全部决议写入路径（`RUN-3`）

**决策**：`MatrixApproval` 的 pending 条目 `PendingEntry` 增持 `notify: tokio::sync::watch::Sender<Option<bool>>`（`submit_branch` 建单时 `watch::channel(None)`，初值 `None`）。**所有决议写入路径统一经同一私有 setter**（如 `fn settle(entry: &mut PendingEntry, decided: bool, auto: bool)`），在**同一 `pending` 锁临界区**内完成 `decided`/`decided_at`/`auto` 写入与 `notify.send(Some(decided))`：

- `resolve_with_auto`（reaction 落定）：幂等短路后调用 setter。
- `lock_reject_all`（`lock` 拒绝落定）：遍历时对每个未决条目调用 setter（保留既有「返回落定条数」语义）。
- `lock_clear_all`（`lock` 全清）：对每个未决条目先调用 setter，再 `guard.clear()`——**send 先于清表**，接收端已持最新值（sender 随后被 drop 不丢已发值）。

`ask` 改为事件等待：持锁 `subscribe()` 取 `rx` 后先读 `*rx.borrow()`（覆盖「决议先写、后订阅」——`watch` 订阅只见当前值、不再触发 `changed()`），为 `Some(v)` 立即返回 `v`；否则 `timeout(remaining, rx.changed()).await` 循环，`changed()` 无论返回 `Ok(())` 还是 `Err(_)`（如 `lock_clear_all` 后 sender 被 drop）都先读 `*rx.borrow()`，`Some(v)` 即返回 `v`，`None` 再按票据缺失处理；订阅时票据不存在则单次等到 `remaining` 后按超时口径 `remove + None`（不轮询）。彻底超时路径维持既有 `warn + remove + None`。等待期内无固定 50ms 唤醒。外部返回语义、超时秒数与清理时序完全不变。

**理由**：`watch` 支持多等待者且自带「最新值 + 变更通知」，与「一个票据可能被多个 `ask`（`ask` 与 `ask_audit`、并发 8 `ask` 共票）观察」的实际用法匹配；`changed()` 即时唤醒，无固定间隔延迟，消除忙轮询。将 `lock` 纳入同一 setter 是因为 `lock_reject_all`/`lock_clear_all` 原先**直接写 `entry.decided = Some(false)`**（`src/service/matrix/approval.rs:188-223`）而绕过 `resolve`：若仅替换 `resolve` 侧为 `watch` 唤醒，`lock` 期间阻塞于 `ask` 的等待者将收不到通知、空等至 `300s` 分支 TTL 才返回拒绝——本 setter 使三路径共享同一唤醒机制，堵住该丢唤醒缺口。`decided` 写入与 `send` 同临界区消除「先写决议后发通知」间隙；`borrow()` 起点读与 `changed()` 后的兜底读消除「决议先写、后订阅」与「send 后 sender drop」两种丢唤醒。

**备选**：① 单条目 `Notify` + `notified()`——需处理「通知早于 `notified()` 注册」的丢唤醒竞态（`Notify::notify_waiters` 不记忆），健壮性不如 `watch`，不采用；② 全局 `broadcast` 决议事件——需按 `event_id` 过滤且多票据广播放大，不采用；③ 保留轮询但拉长间隔——仍属忙轮询且增加决议延迟，不采用；④ `lock` 路径继续直接写 `decided` 而不 notify——正是本次须修复的缺陷（等待者空等至 TTL），不采用。

### D4：读取错误记 warn + 计数器，保持退化语义（`RUN-4`）

**决策**：`read_bounded_body` 的 `Err(e)` 分支改为 `tracing::warn!(error = %e, read_bytes = buf.len(), "上游响应体读取失败，退化为空体")` 后仍返回 `BoundedBody::Complete(Vec::new())`；`nonstream.rs:146` 与 `dispatch.rs:328` 的 `unwrap_or_default()` 改为显式 `match`：`Ok(b) => b.to_vec()` / `Err(e) => { warn!(...); Vec::new() }`。新增计数落 `GatewayMetrics`（建议 `upstream_read_errors: AtomicU64` 与 `record_upstream_read_error()`/`upstream_read_error_count()`，与既有 `nondialog_passthrough` 同形态）或等价可观测点；对外仍走既有空体/错误分类路径。

**理由**：读取失败与正常空体当前在监控上不可区分，运维无法感知上游异常；warn + 计数是最小可观测面，且不触碰下游可见行为（避免把运维信号变成契约变更）。落 `GatewayMetrics` 与既有 `hop_filtered`/`nondialog_passthrough` 计数惯例一致，管理面可查。

**备选**：① 向调用方传播新错误码——改变对外契约且需下游配合，超出可靠性修复范围，不采用；② 仅日志不加指标——无法做阈值告警，不采用；③ 复用 `dropped` 计数——`dropped` 已表「环满丢弃」语义，混用会歧义，不采用。

## Risks / Trade-offs

- [`D1` 周期刷盘写入放大] → 60s 与 sweep/TTL 同节奏，且 `flush` 为覆盖式 UPSERT + WAL checkpoint，单次窗口数量受 `D2` 上限约束，放大有界。若实测写入压力大，可经常量调整间隔（内部常量，非外部契约）。
- [`D1` 关闭刷盘超时] → 退出路径对最终 `flush` 设短超时（建议 5s），避免 sqlite 卡顿拖住进程退出；超时仅记 warn，已周期刷盘的窗口仍在。
- [`D2` 驱逐与查询竞态] → 驱逐在 `aggs` 锁内进行，查询快照亦取同一锁，不存在半驱逐视图；驱逐计数供观测，若发现近期窗口被误逐可调大 `AGGS_MAX_ENTRIES`。
- [`D2` 驱逐与回填交互] → 驱逐仅作用于内存；重启回填会重新载入 sqlite 保留窗，故驱逐不造成重启后口径缺失（spec「驱逐不破坏重启保留」锁定）。
- [`D3` `watch` 决议与清理竞态] → 决议 `send` 与 `remove` 次序须保证「先决议后清理」；`ask` 在 `changed()` 唤醒后先读值再判超时，避免边界丢决议。回归须覆盖决议/超时/清理三径。
- [`D3` `lock` 路径丢唤醒] → `lock_reject_all`/`lock_clear_all` 原先直接写 `entry.decided` 而绕过 `resolve`；须与 `resolve` 共用同一 setter（同临界区 `send`）。`lock_clear_all` 的 `send` 必须先于 `guard.clear()`（sender 随条目 drop），且 `ask` 在 `changed()` 返回 `Err`（sender 已 drop）时仍以 `borrow()` 读到 `Some(false)` 并按拒绝即时返回，不得回退为空等 TTL。回归须覆盖「waiter 阻塞期间 `lock` 即时拒绝」。
- [`D3` 无重复发送/无丢唤醒] → 每个未决票据经 setter 至多发送一次决议（`resolve` 与 `lock` 均以 `decided.is_none()` 守门），`decided` 写入与 `send` 同临界区；回归须覆盖「先写决议后订阅」与「先订阅后写决议」两种次序均读到 `Some(decided)`，且无双重唤醒（无 panic/无重复消费）。
- [`D3` 多等待者] → `watch` 支持多观察者，`ask` 与 `ask_audit` 共用同一票据不互相吞通知；测试须覆盖并发等待者场景。
- [`D4` 指标基数] → 新增计数为全局单值 `AtomicU64`（非按 IP/模型维度），无基数爆炸风险。
- [既有测试依赖轮询时序] → `ask` 相关测试（`src/service/credential/approval/tests.rs`、`vault_ops/tests.rs` 中 `sleep(20ms)` 后断言）在事件驱动下只会更快更稳；若个别测试断言「轮询次数」需改为断言结果与延迟上界。

## Migration Plan

1. 按 tasks 顺序落地：先 `RUN-1`（刷盘接线 + `aggs` 有界，因涉及 `main.rs` 关闭钩子改动面最大），再 `RUN-2`（限流有界，独立小改），再 `RUN-3`（唤醒原语），最后 `RUN-4`（观测）。
2. 每组独立 `cargo test`；`README.md` §3/§4 若需口径补充与行为同批更新（如登记 `METRICS_FLUSH_INTERVAL_SECS`/`AGGS_MAX_ENTRIES` 为内部常量，加入 §4.1 附录）。
3. 回滚策略：按节 revert 对应 diff；无 schema 迁移（复用既有 `metrics_daily/hourly/five_min` 表）、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；对外可感知变化仅「重启后指标可保留」与「上游读取失败开始出现 warn/指标」两类，均为观测增强。

## Open Questions

- 无。`RUN-1`..`RUN-4` 均已裁定；若 apply 阶段实测关闭钩子与 `axum::serve` 的兼容性（如信号处理与既有 `sync_bot`/sweeper 任务收尾的交互）有额外约束，以 spec「指标按周期与关闭刷盘」Scenario 为准调整实现细节并回到本 design 记录差异。
