# tpm-exec-retry Specification

## Purpose
锁定 TPM 子进程 `exec` 在可执行文件忙（`ETXTBSY`）时的有界重试行为：消除 XFS/多线程测试环境下的环境敏感 flake，同时不改动对外成功、失败与超时语义。

## Requirements

### Requirement: ETXTBSY 有界重试

系统 SHALL 在 TPM 子进程 `spawn` 因可执行文件忙（`ETXTBSY`，`os error 26`）失败时，于上限内重试；默认上限 SHALL 为 5 次尝试，退避 SHALL 为递增 10ms/20ms/30ms/40ms。非 `ETXTBSY` 的 `spawn` 错误 SHALL 立即透传、不得重试。达到上限后 SHALL 返回最后一次 `ETXTBSY` 错误，错误文案 SHALL 保持既有口径（`TPM 子进程启动失败 <program>: <err>`）。重试 SHALL 只发生在 `spawn` 阶段，不得影响 30s 子进程超时语义。

#### Scenario: 短时忙后成功

- **WHEN** `spawn` 前两次返回 `ETXTBSY`、第三次成功
- **THEN** 调用返回成功结果，不向上抛出错误

#### Scenario: 非忙错误立即透传

- **WHEN** `spawn` 返回 `ENOENT`/`EACCES` 等非 `ETXTBSY` 错误
- **THEN** 不发生重试，立即返回该错误

#### Scenario: 持续忙达上限

- **WHEN** `spawn` 连续 5 次均返回 `ETXTBSY`
- **THEN** 返回最后一次 `ETXTBSY` 错误，且尝试次数恰为上限

### Requirement: 覆盖全部 TPM exec 入口

系统 SHALL 对 `RealTpm::run`（`tpm2_createprimary`/`tpm2_load`/`tpm2_unseal`）与 `RealTpm::is_available`（`tpm2_pcrread`）两处 `spawn` 应用同一重试助手；README/design 的重试口径说明 SHALL 与实际接线一致。

#### Scenario: 存活探测同样重试

- **WHEN** `tpm2_pcrread` 的 `spawn` 瞬时 `ETXTBSY` 后成功
- **THEN** `is_available()` 返回 `true`，不因瞬态忙判死
