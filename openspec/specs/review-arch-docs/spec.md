# review-arch-docs Specification

## Purpose
收敛审批散射、胖文件体量、垫片归属、判定散射、常量归属三类架构卫生，加 README 两处文档修复，加 PII 与功能映射锁定，无协议行为变更（A4/A6/A9 只引用锁定）。

## Requirements

### Requirement: 审批职责文档集中且保活二选一锁定

系统 SHALL 在文档集中声明三审批文件分工，保活 SHALL 以 `RequestKeepalive` 为流内唯一实现并与管理面 60s 保活区分记录，`KeepaliveTracker` SHALL 记为已删不再立项。

#### Scenario: 审批分工可查

- **WHEN** 查阅审批收敛文档
- **THEN** `approval.rs` 存单据、`credential/approval.rs` 双模、`matrix.rs` 五分支流转三职责各自可定位

#### Scenario: 保活无双实现歧义

- **WHEN** 查阅保活声明
- **THEN** 10s 流内保活归 `RequestKeepalive`（`pump.rs` 经 `spawn_gated` 接线），60s 管理 SSE 保活分属不同链路，`KeepaliveTracker` 记为已删

### Requirement: 五大胖文件按阈值继续拆分且行为一致

系统 SHALL 将超 800 行的 `pump/audit/redaction/llm-mod/matrix` 五文件按 design D2 边界继续拆分，conformance SHALL 全绿，对外路径 SHALL 经 `mod.rs` 重导出不变。本项 SHALL 定性为可维护债，不计死代码。

#### Scenario: 拆分后行为一致

- **WHEN** 拆分合入后跑 conformance
- **THEN** 全绿且对外 `handler::*` 与 `llm_gateway::*` 路径不变

#### Scenario: 拆分边界可执行

- **WHEN** 查阅拆分文档
- **THEN** `pump` 四桶与 `audit` 三切边界明确，apply 可机械执行

### Requirement: 审计 hold 垫片并入且别名保留

系统 SHALL 将 `audit_hold.rs` 实现体并入 `audit.rs`（或其 hold 子模块），`audit_hold.rs` SHALL 缩为重导出垫片，对外 `crate::service::audit_hold::*` 路径 SHALL 不变。

#### Scenario: 旧路径不断裂

- **WHEN** 下游经 `crate::service::audit_hold::{HoldVerdict, AuditHold, RequestKeepalive}` 引用
- **THEN** 编译通过且语义与并入前一致

### Requirement: NonDialog 判定经单一谓词

系统 SHALL 提供 `is_passthrough(Protocol)` 谓词，六处散射点 SHALL 统一改用，语义 SHALL 与字面比对等价。

#### Scenario: 新增变体只改一处

- **WHEN** 全仓 grep `== Protocol::NonDialog` 与 `!= Protocol::NonDialog`
- **THEN** 除 `protocol.rs` 定义与单测外零生产命中，六处调用方均经谓词

### Requirement: 入口限值与 SSE 常量归属 config

系统 SHALL 以 `config` 为 `GATEWAY_BODY_LIMIT_BYTES` 与 SSE 三常量（16KB/30s/10s）的唯一来源，旧位置 SHALL 原位转发，阈值 SHALL 与 hardening specs 同字且只搬不改值。

#### Scenario: 阈值单源可查

- **WHEN** 查阅 `GATEWAY_BODY_LIMIT_BYTES` 与 `LINE_LIMIT_BYTES/EVENT_IDLE_TIMEOUT/KEEPALIVE_INTERVAL` 定义
- **THEN** 唯一定义在 `config`，旧位置仅转发且理由注释随行

#### Scenario: 过期下沉注清零

- **WHEN** 全仓 grep “将下沉”
- **THEN** 零命中（`error.rs:10` 改为“已归属 `config`”）

### Requirement: README 旧审批路径替换为新路径

系统 SHALL 将 README 中旧单文件 `credential.rs` 下的审批双模与哈希变更路径批量替换为 `credential/approval.rs`（双模）与 `vault_ops.rs`（哈希变更）新路径，`contract-docs` 路径可验证要求 SHALL 满足。

#### Scenario: 旧字面零残留

- **WHEN** 全仓 grep 旧路径字面
- **THEN** 零命中且新路径可定位到符号定义

### Requirement: 端口语义首行加粗单监听

系统 SHALL 在 README 端口语义章节首行加粗声明容器内单监听且不存在多端口运行时，后续三段 SHALL 与 §1 环境变量表同字（单监听、三映射、`resolve_upstream` 单测锁定）。

#### Scenario: 首行定调无误读

- **WHEN** 查阅 README 端口章节首行
- **THEN** 加粗含单监听声明，三映射表述为宿主机入口区分

### Requirement: PII recognizer 映射表完整

系统 SHALL 补本仓 detector 与原仓七类对照映射表，`BUILTIN_NAMES` 注释 SHALL 与数组长度一致（7 名恒 7，有单测互锁），缺失类 SHALL 列明原因与承接 change。

#### Scenario: 数量口径一致

- **WHEN** 查阅 `detector.rs` 模块头与 `BUILTIN_NAMES`
- **THEN** 注释记 7 而非 6，映射表覆盖七类，缺一列明

### Requirement: 功能映射只引用锁定不重复实现

系统 SHALL 对单端口多上游选路弱化、Go hardening 5.1 至 5.3 未闭环、`approve_hash_change` 非 full 降级加 `GET registrations` 鉴权收敛加限流收紧加 `DEBUG_DIR` 落盘缺失加五 BREAKING 做引用锁定，SHALL 不新增实现，owner SHALL 归原 change。

#### Scenario: 引用闭环无重复立项

- **WHEN** 比对本 spec 与 README 第 6 至 8 节
- **THEN** 逐项互引同字，无新增行为条目
