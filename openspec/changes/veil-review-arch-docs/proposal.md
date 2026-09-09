## Why

审查确认依赖方向健康（`router→handler→service→state→config` 单向，无循环），但 9 项架构卫生加文档加功能映射债未立项：审批逻辑四散（`approval.rs`＋`credential/approval.rs`＋`matrix.rs`）且保活双实现语义待锁定；五大胖文件（`pump` 约 1660 行、`audit` 约 1613 行、`redaction` 约 1466 行、`llm/mod` 约 1372 行、`matrix` 约 1307 行）超 `hygiene-round4` 800 行上限；`audit_hold.rs` 738 行垫片（`HoldVerdict/decide_via_gateway` 重导出归属 `audit.rs`）未并入；`NonDialog` 判定六处散射；`GATEWAY_BODY_LIMIT` 误置入口且 SSE 三常量（16KB/30s/10s）硬编码在 `service/sse.rs`；README 残留旧路径 `credential.rs::approval_dual_mode/approve_hash_change`；端口语义章节未首行加粗单监听声明；PII 6 对 7 recognizer 映射表缺失；单端口多上游选路弱化、Go hardening 5.1 至 5.3 未闭环、`approve_hash_change` 非 full 降级等功能映射未引用锁定。本 change 一次收敛，以拆分收敛与文档锁定为主，不改网关语义与测试门限。

## What Changes

- **架构收敛（C1 至 C5）**：审批四散统一文档（`RequestKeepalive` 唯一实现，`KeepaliveTracker` 已删，10s 流内保活与 60s 管理 SSE 分属不同链路）；五大胖文件按 `hygiene-round4` 模板继续拆（`pump` 按 NonDialog/空流守门/tool 分桶/hold 四分支，`audit` 按策略/判定/日志三切）；`audit_hold.rs` 并入 `audit.rs` 留别名；`NonDialog` 六处抽 `is_passthrough()` 谓词；`GATEWAY_BODY_LIMIT` 下沉 `config`，SSE 三常量下沉 `config`。
- **文档修复（D1 至 D2）**：README 旧路径批量替换为 `credential/approval.rs` 新路径；端口语义首行加粗单监听声明（容器内单监听加宿主机三映射，`resolve_upstream` 单测锁定）。
- **功能映射（A3/A4/A6/A9）**：补 PII detector 与原仓七类对照映射表；单端口多上游选路弱化、Go hardening 5.1 至 5.3 未闭环、`approve_hash_change` 非 full 降级加 `GET registrations` 鉴权收敛加限流收紧加 `DEBUG_DIR` 落盘缺失加 LRU/隔离/默认开五 BREAKING，均只做引用锁定（已在 README 第 6 至 8 节声明，不重复立项实现）。

## Capabilities

### New Capabilities

- `review-arch-docs`：审批收敛、胖文件拆分、垫片并入、谓词集中、常量下沉、文档修复、功能映射锁定。

### Modified Capabilities

- 无既有 spec 需求变更；纯结构与文档收敛（`hygiene-round4` 800 行阈值与 `contract-docs` 文档真源为准，阈值表述与 hardening specs 同字）。

## Non-Goals（显式）

- 不改既有 changes；不 commit。
- 不大改行为，以拆分收敛为主（网关阻断/审计语义不动，见 gateway 相关 changes）。
- 不加测试门限（见 test 相关 changes）。
- 不引入新运行时依赖。
- A4/A6/A9 只做引用锁定，不重复立项实现（实现 owner 归原 change）。
- 不复制 skill 块。

## Impact

- **新增文件**：`openspec/changes/veil-review-arch-docs/` 下 proposal/design/specs/tasks；apply 阶段拆 5 文件、并 1 文件、新增谓词与常量归属、改 README 两处与映射表。
- **影响系统**：可维护性与文档可信度；行为零变更（拆分 conformance 回归）。
- **依赖**：无新依赖。
