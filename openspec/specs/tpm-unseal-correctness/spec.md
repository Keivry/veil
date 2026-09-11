# tpm-unseal-correctness Specification

## Purpose
修正 TPM 解封与密封模板、路径与启动注入三处 P0 错误，使硬件解封跨重启可用且无硬件时 fail-closed 语义明确。

## Requirements

### Requirement: 解封模板与密封一致

系统 SHALL 以与密封时相同的模板现场派生 primary（owner 层级、rsa2048、sha256），再执行 load + unseal。

#### Scenario: 跨重启解封

- **WHEN** 主机重启后使用保留的 `seal.pub/seal.priv` 解封
- **THEN** 解封成功且不报完整性错误

### Requirement: 密封路径与启动注入

系统 SHALL 从配置的 TPM 目录读取 `seal.pub` 与 `seal.priv`（MUST NOT 使用占位 workdir 路径）；启动期解出的密封字节 SHALL 注入 KeePass 口令提供器（MUST NOT 丢弃）；解锁后 SHALL 缓存主口令，查询路径复用缓存而非每次重解；口令为空或长度不足 SHALL 拒绝解锁。

#### Scenario: 路径正确

- **WHEN** `TPM_DIR` 下存在合法密封对且占位路径不存在
- **THEN** 系统从 `TPM_DIR` 解封成功

#### Scenario: 缓存复用

- **WHEN** 解锁后连续查询两次凭据
- **THEN** 第二次不重新执行解封命令且返回一致结果

### Requirement: Mock 门禁与超时

仅当 `VEIL_ALLOW_MOCK_TPM` 精确等于 `1` 时 SHALL 放行 Mock TPM 并打 warn 日志，其余值仍走硬件门禁 fail-closed；解封命令 SHALL 设超时并在失败时输出可诊断错误。

#### Scenario: 精确放行

- **WHEN** `VEIL_ALLOW_MOCK_TPM=true`（非 `1`）
- **THEN** 系统仍拒绝以 Mock 启动

#### Scenario: 无硬件拒启动

- **WHEN** 无 TPM 硬件且未显式放行
- **THEN** 系统拒绝启动并打印开发机指引
