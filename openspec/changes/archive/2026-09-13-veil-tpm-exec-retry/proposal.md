## Why

`service::tpm::tests::tpm_tempdir_cleanup` 偶发 `ETXTBSY`（`Text file busy, os error 26`）导致测试失败：测试助手 `write_executable`（`src/service/tpm.rs:410-416`）写入并 `chmod` mock 脚本后，`RealTpm::run`（`src/service/tpm.rs:145`）立即 `exec` 该脚本；Linux 下 `execve` 与尚未落定的写者（XFS/多线程测试环境）存在竞争窗口。近期多次全量测试复现 2 次（隔离与复跑均绿）。同一窗口同样存在于生产 `unseal` 与 `is_available` 的首次 exec（`tpm2_createprimary` / `tpm2_pcrread`），构成环境敏感 flake 与真实健壮性缺口。

## What Changes

- `RealTpm::run` 与 `RealTpm::is_available` 的 `spawn` 接入**有界 ETXTBSY 重试**：仅在可执行文件忙（`ETXTBSY`）时重试（最多 5 次、10–40ms 递增退避）；其他 spawn 错误立即透传；达上限返回最后一次 ETXTBSY 错误，**错误文案与超时语义不变**。
- 抽出可单测纯助手 `retry_on_exec_busy<T>(max_attempts, op)`，覆盖「短时忙后成功 / 非忙错误立即透传 / 持续忙达上限」三态。
- 测试助手加固：`write_executable` 写入后 `sync_all`，缩小竞争窗口。

## Capabilities

### New Capabilities

- `tpm-exec-retry`：TPM 子进程 exec 在 ETXTBSY 下的有界重试契约（覆盖 `run` 与 `is_available`），不改变对外成功/失败与超时语义。

### Modified Capabilities

- 无。既有 canonical 规格（`tpm-unseal-correctness`、`runtime-robustness`）的对外行为不动；本 change 只增补 exec 阶段的健壮性口径。

## Impact

- 代码：`src/service/tpm.rs`（`run`、`is_available`、测试助手与新单测）。
- 行为：失败路径最多增加 ≤100ms 重试延迟；成功/失败/超时文案与语义不变。
- 文档：`design.md` 记录重试口径（必要时 README §4.1/§8 摘要引用）。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `E1` | MED（稳定性/健壮性） | `run`/`is_available` 接入 ETXTBSY 有界重试（5 次、10–40ms，仅忙时重试，文案不变） | 1.1、1.2 |
| `E2` | LOW | 纯助手三态单测（busy×2→Ok / 非 busy→立即 Err / busy×上限→Err 且次数精确） | 2.1 |
| `E3` | LOW | mock 脚本写入加固（`sync_all`）与稳定性验证（tpm 组循环 + 全量 ×3 + 门禁） | 2.2、3.1、3.2 |
