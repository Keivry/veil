## 1. 审批收敛与保活锁定（D1，C1 文档先行）

- [x] 1.1 三审批文件分工文档集中（`approval.rs` 存单据、`credential/approval.rs` 双模、`matrix.rs` 五分支加分表超时加 60s 清扫）
  - Verify: 文档逐项可定位到符号定义（`PendingApprovals`、`approval_dual_mode`、`MatrixBranch` 五分支）
  - Verify: 代码评审确认分工描述与实现一致，无行为改动
- [x] 1.2 保活二选一锁定（`RequestKeepalive` 唯一实现，10s 流内与 60s 管理 SSE 分链路，`KeepaliveTracker` 记已删）
  - Verify: 文档含 `spawn_gated` 接线位置（`pump.rs`）与间隔来源（`sse::KEEPALIVE_INTERVAL`）
  - Verify: 全仓 grep `KeepaliveTracker` 零生产命中（历史注释说明除外）

## 2. 胖文件拆分（D2，C2 最后执行）

- [x] 2.1 `pump` 按四桶拆（NonDialog 透传臂、空流守门、tool 分桶、hold 四分支）加对外重导出不变
  - Verify: 拆后单文件均不超 800 行且 `handler::*` 路径不变
  - Verify: conformance 全绿加全量 `cargo test` 通过
- [x] 2.2 `audit` 按三切拆（策略、判定、日志）加 `redaction/llm-mod/matrix` 按子域拆分
  - Verify: 拆后单文件均不超 800 行（H4.1 实测：`handler/llm/nonstream.rs` 804 超 4 行已备案，其余均 ≤800）且 `llm_gateway::*` 路径不变
  - Verify: conformance 全绿加阈值表述与 hardening specs 同字

## 3. 垫片并入（D3，C3）

- [x] 3.1 `AuditHold` 与 `RequestKeepalive` 实现体并入 `audit.rs`（或 hold 子模块），`audit_hold.rs` 缩为重导出垫片
  - Verify: 对外 `crate::service::audit_hold::*` 四符号引用编译通过
  - Verify: 全量 `cargo test` 通过且审计判定语义无变更

## 4. 谓词集中（D4，C4）

- [x] 4.1 新增 `protocol.rs::is_passthrough()` 并替换六处（`pump` 三处、`nonstream`、`rewrite`、`llm/mod` 各一处）
  - Verify: 除定义与单测外全仓 grep 字面比对零生产命中
  - Verify: 六处逐项列出文件行号比对，语义等价且全量测试通过

## 5. 常量下沉（D5，C5）

- [x] 5.1 SSE 三常量下沉 `config`（16KB/30s/10s 只搬不改值，理由注释随行，`sse.rs` 原位转发）
  - Verify: 唯一定义在 `config`，旧位置仅转发
  - Verify: 阈值表述与 hardening specs 同字逐项比对
- [x] 5.2 `GATEWAY_BODY_LIMIT` 归属注释补齐加 `error.rs` 过期注修正（“将下沉”改为“已归属 `config`”）
  - Verify: 全仓 grep “将下沉”零命中
  - Verify: `handler/llm/mod.rs` 转发不断裂且 413 行为单测通过

## 6. README 旧路径替换（D6，D1）

- [x] 6.1 批量替换旧路径为 `credential/approval.rs`（双模）与 `vault_ops.rs`（哈希变更）新路径
  - Verify: 全仓 grep 旧字面零命中
  - Verify: 新路径逐项可定位到符号定义，与 `contract-docs` 路径可验证要求一致

## 7. 端口语义首行加粗（D7，D2）

- [x] 7.1 首行加粗单监听声明（容器内单监听，不存在多端口运行时），后三段与 §1 同字保留
  - Verify: 首行加粗含单监听声明，三映射表述为宿主机入口区分
  - Verify: `resolve_upstream` 缺省语义单测锁定且文档评审通过

## 8. PII 映射表（D8，A3）

- [x] 8.1 补 detector 与原仓七类对照映射表，`BUILTIN_NAMES` 注释修正为 7 加长度断言单测互锁，缺一列明
  - Verify: 注释记 7 且单测断言 7 名恒 7
  - Verify: 映射表覆盖七类，缺失类有原因与承接 change

## 9. 功能映射引用锁定（D9，A4/A6/A9）

- [x] 9.1 引用锁定互引（选路弱化、Go 5.1 至 5.3、`approve_hash_change` 降级、鉴权收敛、限流收紧、`DEBUG_DIR` 缺失、五 BREAKING 迁移确认，均指 README 第 6 至 8 节）
  - Verify: 逐项与 README 第 6 至 8 节同字互引，无新增行为条目
  - Verify: owner 归属明确（Go 归 `veil-hardening` 第 5 节），文档评审确认零漂移
