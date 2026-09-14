## 1. 指标刷盘与聚合有界（`RUN-1`）

- [x] 1.1 `src/service/metrics/store.rs` 新增周期刷盘驱动与常量：`METRICS_FLUSH_INTERVAL_SECS = 60`，提供 `MetricsStore::spawn_flush_driver(interval)`（`tokio::time::interval` 任务，每 tick 调既有 `flush().await`，失败仅 `tracing::warn!`）；`src/main.rs` 在 `state.notify.start()` 邻近处启动并持有 `JoinHandle`
  - 验证：`grep -n "spawn_flush_driver\|METRICS_FLUSH_INTERVAL_SECS" src/service/metrics/store.rs src/main.rs` 命中定义与启动调用点
  - 验证：`cargo test -p veil metrics_periodic_flush_persists` 通过；mock 时钟推进一个周期后 sqlite `metrics_daily` 出现对应窗口行，无需进程退出
- [x] 1.2 `src/main.rs` 关闭刷盘接线：`axum::serve` 改 `with_graceful_shutdown(shutdown_signal())`，在 `SIGINT`/`SIGTERM` 后调用一次 `flush().await`（带短超时，建议 `5s`），超时/失败仅 warn 不影响退出码
  - 验证：`grep -n "with_graceful_shutdown\|shutdown_signal" src/main.rs` 命中；关闭路径调用 `flush`
  - 验证：`cargo test -p veil metrics_flush_on_shutdown` 通过；触发关闭信号后最终一次 `flush` 被调用且退出码为 0
- [x] 1.3 `src/service/metrics/store.rs`（`aggs: Mutex<HashMap<AggKey, WindowAgg>>`）与 `src/service/metrics/aggregate.rs` 增加 `aggs` 有界：按既有 retention 口径（daily 32 窗×协议、hourly 170 窗×协议、five_min 只留最新窗口）驱逐过期窗口；新增常量 `AGGS_MAX_ENTRIES`（建议 `4096`）与 LRU 驱逐；新增可观测 `aggs_evicted_total`
  - 验证：`cargo test -p veil aggs_retention_eviction` 通过；注入超保留窗数的窗口后 `aggs` 条目数回落到保留范围
  - 验证：`cargo test -p veil aggs_hard_cap_lru` 通过；条目数不超过 `AGGS_MAX_ENTRIES` 且 `aggs_evicted_total` 递增
- [x] 1.4 重启保留与驱逐交互回归：写入→周期刷盘→重启回填，断言指标保留且不翻倍；被内存驱逐但已刷盘的窗口重启后可恢复
  - 验证：`cargo test -p veil metrics_restart_retains_flushed` 通过；重启后快照含重启前已刷盘窗口且数值不翻倍
  - 验证：`cargo test -p veil aggs_eviction_keeps_sqlite_recoverable` 通过；内存驱逐后回填仍恢复该窗口
- [x] 1.5 刷盘失败降级回归：sqlite 不可写时周期刷盘记 warn、服务继续、内存继续累计
  - 验证：`cargo test -p veil metrics_flush_failure_warns_and_continues` 通过；失败后进程不退出且后续记录仍可查

## 2. 管理面限流状态有界（`RUN-2`）

- [x] 2.1 `src/service/admin/state.rs`（`rate: Mutex<HashMap<IpAddr, Vec<Instant>>>`）与 `src/service/admin/ratelimit.rs` 增加有界管理：周期清扫窗内无命中的过期条目（TTL），并设硬上限（建议 `ADMIN_RATE_MAX_ENTRIES`）达上限时驱逐；`decide_rate_limit` 的阈值与 `Retry-After` 逻辑不动
  - 验证：`grep -n "ADMIN_RATE_MAX_ENTRIES\|sweep" src/service/admin/state.rs src/service/admin/ratelimit.rs` 命中清扫与上限定义
  - 验证：`cargo test -p veil admin_rate_map_bounded_under_many_ips` 通过；注入远超上限的不同 IP 后条目数不超过上限，进程内存不持续增长
- [x] 2.2 限流语义不变回归：清扫与驱逐后同 IP `10/min` 判定、`Retry-After` 取值范围与原测试一致；不同 IP 不受影响
  - 验证：`cargo test -p veil rate_limit_counts_by_direct_peer_ip rate_limit_window_rollover_and_retry_after_value` 全绿无回退
  - 验证：`cargo test -p veil admin_rate_sweep_preserves_semantics` 通过；过期条目被清理且清理后限流仍按 `10/min/IP` 生效

## 3. 审批等待事件驱动（`RUN-3`）

- [x] 3.1 `src/service/matrix/approval.rs` 的 pending 条目增持 `tokio::sync::watch::Sender<Option<bool>>`（初值 `None`），并引入**共享决议 setter**（如 `fn settle(entry, decided, auto)`：同一 `pending` 锁临界区内写 `decided`/`decided_at`/`auto` 后 `send(Some(decided))`）；`resolve_with_auto`、`lock_reject_all`、`lock_clear_all` **三处决议写入统一改走该 setter**（`lock_clear_all` 的 `send` 必须先于 `guard.clear()`）；`ask`（`:239-266`）改为 `timeout(remaining, rx.changed())` 事件等待（订阅后先读 `borrow()`，`changed()` 返回 `Ok`/`Err` 均以 `borrow()` 兜底），移除 `sleep(Duration::from_millis(50))` 轮询；超时路径维持既有 `warn + remove + None`
  - 验证：`grep -n "from_millis(50)" src/service/matrix/approval.rs` 无匹配；`grep -n "watch::\|fn settle" src/service/matrix/approval.rs` 命中 setter 与等待接收
  - 验证：`grep -n "decided = Some" src/service/matrix/approval.rs` 除 setter 内一处外无其他直接赋值（`lock_*`/`resolve` 均经 setter）
  - 验证：`cargo test -p veil ask_wakes_on_decision` 通过；决议写入后等待者即时返回对应决议值，延迟显著小于原 50ms 轮询间隔
- [x] 3.2 外部语义与无忙轮询回归：超时返回 `None` 并清理、按拒绝归并、多等待者（`ask` 与 `ask_audit`）不互相吞通知；等待期内无固定 50ms 重复唤醒
  - 验证：`cargo test -p veil ask_timeout_returns_none_and_cleans` 与 `ask_multi_waiter_notification` 全绿
  - 验证：`cargo test -p veil ask_no_busy_poll` 通过；等待期内轮询唤醒计数为零或不增长（行为可观测）
- [x] 3.3 `lock` 路径即时唤醒回归（同 D3 setter）：`lock_reject_all`/`lock_clear_all` 期间阻塞于 `ask` 的等待者即时按拒绝返回；锁后（含 `lock_clear_all` 清表后）正常建单/落定/消费路径不受影响；两种写入/发送次序均无丢唤醒、无重复发送
  - 验证：`cargo test -p veil ask_wakes_on_lock_reject` 通过；`lock` 期间阻塞于 `ask(300s)` 的等待者在远小于 `300s`（建议 `<1s`）内返回 `Some(false)`，未被 `300s` TTL 拖住，票据按既有口径清理
  - 验证：`cargo test -p veil approval_after_lock_clear_still_works` 通过；`lock_clear_all` 清表后重新 `submit_branch` 的票可经 `resolve` 正常落定并被 `ask` 读到决议（锁后正常审批路径可用）
  - 验证：`cargo test -p veil lock_notify_no_double_send_no_lost_wakeup` 通过；「先写决议后订阅」与「先订阅后写决议」两种次序均读到 `Some(false)`，每个 waiter 只被唤醒一次（无 panic/无重复消费）

## 4. 上游读取错误可观测（`RUN-4`）

- [x] 4.1 `src/handler/llm/nonstream.rs`：`read_bounded_body`（`:361-375`）的 `Err(_)` 分支改为 `tracing::warn!(error, read_bytes, ...)` 后仍返回 `BoundedBody::Complete(Vec::new())`；`:146` 的 `up.bytes().await.unwrap_or_default()` 改显式 `match` 并在 `Err` 记 warn；`src/handler/llm/dispatch.rs:328`（`stream_upstream_passthrough`）同样处理
  - 验证：`grep -n "read_bounded_body\|unwrap_or_default" src/handler/llm/nonstream.rs src/handler/llm/dispatch.rs` 显示读错误分支均含 `warn`
  - 验证：`cargo test -p veil upstream_read_error_logged` 通过；mock 上游读取中断时日志含错误与已读字节，且下游仍走既有空体/错误分类路径
- [x] 4.2 `src/service/llm_gateway/mod.rs` 的 `GatewayMetrics` 新增读错误计数（建议 `upstream_read_errors: AtomicU64` + `record_upstream_read_error()`/`upstream_read_error_count()`，与 `nondialog_passthrough` 同形态）并在 4.1 三处失败分支累加
  - 验证：`cargo test -p veil upstream_read_error_counter_accumulates` 通过；一次读取失败后计数递增 1，成功路径不递增
  - 验证：`cargo test -p veil upstream_read_error_semantics_unchanged` 通过；读取失败时下游状态码与正文形态与改动前一致，无新错误码

## 5. 门禁与归档准备

- [x] 5.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 5.2 `python3 scripts/check_doc_paths.py` 与 `python3 scripts/check_file_sizes.py` 退出 0
  - 验证：两条命令输出 OK，无 FAIL 项
- [x] 5.3 文档同步终检：`README.md` §3/§4（及 §4.1 内部常量附录如需登记 `METRICS_FLUSH_INTERVAL_SECS`/`AGGS_MAX_ENTRIES`）与 canonical `observability-admin`/`admin-ratelimit-contract` 口径一致、无旧表述残留
  - 验证：`grep -n "METRICS_FLUSH_INTERVAL_SECS\|AGGS_MAX_ENTRIES" README.md` 命中登记（若采纳登记）；`grep -n "10/min" README.md` 与 spec 口径一致
- [x] 5.4 `openspec validate veil-runtime-reliability --strict` 0 failures
  - 验证：命令输出 `is valid`；`openspec status --change veil-runtime-reliability` 显示 artifacts 齐全
