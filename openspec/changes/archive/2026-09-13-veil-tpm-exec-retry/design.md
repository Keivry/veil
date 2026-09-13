## Context

- `RealTpm::run`（`src/service/tpm.rs:139-194`）为同步子进程执行：`std::process::Command::spawn` + 10ms 忙轮询 + 30s 超时；受 H8/D8 约束（仅启动期与 `spawn_blocking` 内调用，不迁移 `tokio::process`）。
- 测试助手 `fake_tpm` 经 `write_executable`（`:410-416`）写入 mock `tpm2-*` 脚本后立即 exec；`ETXTBSY` 偶发（XFS + 多线程 harness 下写者未落定/exec 竞争），近期全量测试复现 2 次，隔离与复跑均绿。
- `is_available`（`:206-211`）以 `Command::output()` 执行 `tpm2_pcrread`，同样暴露于该竞争窗口。

## Goals / Non-Goals

**Goals：**

- 消除 `ETXTBSY` 引发的环境敏感 flake；对生产 exec 路径给出同样的健壮性保证。
- 不改变成功/失败/超时语义与错误文案；不引入新依赖。

**Non-Goals：**

- 不迁移 `tokio::process`、不改忙轮询与 30s 超时口径（H8/D8 维持）。
- 不改 mock 机制与测试断言集合；不引入跨平台抽象（项目为 Linux 专用）。

## Decisions

- **D1 重试条件**：`e.kind() == ErrorKind::ExecutableFileBusy || e.raw_os_error() == Some(26)`（ETXTBSY）；其余错误（`ENOENT`/`EACCES`/`EAGAIN` 等）立即透传。理由：ETXTBSY 是内核定义的瞬态竞争信号、重试安全（spawn 无副作用）；其他错误重试无意义或掩盖配置问题。备选（对所有 spawn 错误统一重试）被否：会拖慢真实错误上报。
- **D2 重试参数**：5 次尝试、10/20/30/40ms 递增退避（总上界 100ms）。理由：与本仓既有 10ms 轮询粒度一致，既不拖慢启动期，又足以覆盖文件落定窗口；备选（固定 50ms/无上限）被否：前者浪费、后者可能永久挂起。
- **D3 覆盖面**：`run` 与 `is_available` 共用助手；两处错误文案保持现状。
- **D4 可测试性**：抽 `retry_on_exec_busy<T>(max_attempts, op: impl FnMut() -> io::Result<T>) -> io::Result<T>` 纯函数；单测以闭包注入「busy N 次后成功/非忙错误/持续忙」三态，确定性覆盖，不依赖真实 exec 竞争。

## Risks / Trade-offs

- [失败路径延迟 ≤100ms] → 仅发生在 ETXTBSY 的罕见瞬态；正常路径零开销。
- [病态存储持续 ETXTBSY] → 达上限后仍返回原错误文案，行为与现状一致，不引入新静默失败。
- [重试次数消费在 spawn 阶段] → 不与 30s 子进程超时叠加（超时计时从成功 spawn 后开始，保持现状）。

## Open Questions

无。
