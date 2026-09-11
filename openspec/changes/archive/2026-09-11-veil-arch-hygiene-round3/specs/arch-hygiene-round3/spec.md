## Purpose

收敛二次拆分、权限合一、锁与采样、死代码、文档一致性，无协议行为变更（legacy warn 只读提示）。

## ADDED Requirements

### Requirement: 网关入口文件按职责拆分且行为一致

系统 SHALL 将 `handler/llm/mod.rs` 按三单元拆分（勘误：原文 `handler/llm.rs` 单文件，拆分已落地，语义不变）、`llm_gateway/mod.rs` 按协议拆模块（勘误：原文 `llm_gateway.rs` 单文件，拆分已落地，语义不变），conformance SHALL 全绿，限值常量 SHALL 归属 `config.rs`。

#### Scenario: 拆分后行为一致

- **WHEN** 拆分合入后跑 conformance
- **THEN** 20/20 通过且对外 `handler::*` 与 `llm_gateway::*` 路径不变

### Requirement: 权限与 WAL 单一来源

系统 SHALL 以 `fs_perm.rs` 为唯一 0600/WAL 来源，三处调用方 SHALL 复用。

#### Scenario: 权限语义无漂移

- **WHEN** 比对三处旧拷贝与新函数
- **THEN** 语义同为 `0600 + -wal/-shm` 且参数单源

### Requirement: 异步锁与采样不卡热路径

系统 SHALL 不在 async 上下文持有同步锁，采样 SHALL 不在转发热路径同步写库。

#### Scenario: 高并发凭据无 executor 阻塞

- **WHEN** 并发凭据请求到达
- **THEN** 限流临界区无 `.await` 且尾延迟不因锁放大（注释 + 单测锁定语义）

### Requirement: 死代码清零且复用统一

系统 SHALL 删除零引用请求体与死字段，HMAC 比较 SHALL 单一实现。

#### Scenario: 零 `allow(dead_code)` 残留

- **WHEN** 全仓 grep `allow(dead_code)`
- **THEN** 零生产代码命中（`#[cfg(test)]` 除外）

### Requirement: 文档与代码一致且遗留变量可观测

系统 SHALL 修复 5 处过时路径注释，遗留三变量检出 SHALL 启动期 warn。

#### Scenario: 沿用旧名部署可发现

- **WHEN** 环境含 `CREDENTIAL_MASTER_PASSWORD` 等旧变量启动
- **THEN** 日志出现 warn 指引改名（行为仍为不读取）
