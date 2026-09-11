# entry-transport-parity Specification

## Purpose
消除入口选路死代码与传输安全缺口：透传入站端口上下文使 `LLM_8878/8879` 生效或明确单端口、落实 credential-only 自动批准，并对齐 `mlockall`、恒时密钥比较、TPM 超时与 HOP 头集等安全语义，使部署行为与文档一致。

## Requirements

### Requirement: 选路与入口语义

`resolve_upstream` SHALL 透传入站端口上下文，使 `LLM_8878/8879` 生效；或删除死代码并文档明确单端口；`AUTO_APPROVE` credential-only 自动批准 SHALL 落实；`CREDENTIAL_MASTER_PASSWORD`/`CREDENTIAL_PORT` SHALL 给出兼容声明。

#### Scenario: 按端口选上游

- **WHEN** 请求从 8878 入口进入且配 `LLM_8878`
- **THEN** 系统转发到 `LLM_8878` 上游

### Requirement: 传输与密钥安全

linux SHALL 执行 `mlockall`（失败仅 warn）；`secret_eq` SHALL 用恒时比较消除长度泄漏；TPM 超时 SHALL 为 30s 并保留 stderr 诊断，`pcrread` 探测差异 SHALL 文档化；KeePass 候选 SHALL 取首条、`is_unlocked` 判口令非空，Recycle/Notes 跳过 SHALL 声明；HOP 头集差异 SHALL 文档化；`CREDENTIAL_PROXY_DEBUG_DIR` 四件落盘 SHALL 恢复或声明；紧急吊销 SHALL 补文件读取 + 三因子 + 内网判定对齐；`registrations` 鉴权变更 SHALL 声明。

#### Scenario: 内存锁定失败不拒启动

- **WHEN** `mlockall` 失败
- **THEN** 系统 warn 后继续启动

#### Scenario: 变长密钥不泄漏长度

- **WHEN** 比对不同长度密钥
- **THEN** 比较耗时恒定，不泄露长度
