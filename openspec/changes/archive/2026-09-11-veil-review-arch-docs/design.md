## Context

现状：功能正确，债集中在审批散射、文件体量、垫片、判定散射、常量归属、文档漂移、映射缺失七类共 9 项。约束：拆分行为一致（conformance 回归）；`hygiene-round4` 800 行阈值为真源；`contract-docs` 为文档真源；README 为唯一文档入口；A4/A6/A9 只引用锁定不重复实现。

## Goals / Non-Goals

**Goals：**

- 给出审批收敛与保活锁定的文档位置与二选一结论，使 apply 可机械执行。
- 给出五大胖文件拆分边界、垫片并入路径、谓词签名、常量归属。
- 给出 README 两处修复的精确位置与改后文案方向。
- 给出 PII 映射表与功能映射引用锁定的精确位置。

**Non-Goals：**

- 不重排 `service/` 内网关管线语义。
- 不改限流阈值、采样表结构、审计判定结论。
- A4/A6/A9 不新增实现，只引用 README 第 6 至 8 节锁定。

## Decisions

### D1：审批四散统一文档，保活二选一锁定 `RequestKeepalive`（C1）

**决策**：审批职责文档集中声明三文件分工：`src/approval.rs`（`PendingApprovals` 待审单据存储与问询网关 trait）、`src/service/credential/approval.rs`（`approval_dual_mode` 双模：202 抛单与 300s 阻塞等 reaction，唯一读取方见 `config/env_parse.rs` 接线注释）、`src/service/matrix.rs`（Matrix 五分支流转、300s/90s 分表超时、60s 孤儿清扫、`spawn_sync_loop` 同步）。保活二选一结论：`RequestKeepalive`（`audit_hold.rs:298`，`pump.rs` 经 `spawn_gated` 接线，间隔消费 `sse::KEEPALIVE_INTERVAL` 10s）为流内保活唯一实现；管理面 SSE 60s ping（`admin/sse.rs`）与 5min 强制重连分属不同链路，差异有意；`KeepaliveTracker` 时间戳自检形态生产零接线，已删除（见 `service/sse.rs:16` 注释），文档重申不再立项实现。

**理由**：四散的是文档缺口而非行为 bug，统一文档即收敛；双保活实为两条链路，合并会混淆语义。

**备选**：合并三审批文件为一，改动面大且扰动 Matrix 同步循环，不采用。

### D2：五大胖文件按 hygiene-round4 模板继续拆（C2）

**决策**：沿用 `hygiene-round4` 800 行上限与“`mod.rs` 重导出既有公开符号，对外路径不变”模板。`pump.rs`（约 1660 行）按四桶切：NonDialog 透传臂、空流守门（`bytes_written==0` 502）、tool 分桶（分片累积与完成判定）、hold 四分支（危险调用 pending 建单语义）；`audit.rs`（约 1613 行）按三切：策略加载、判定（`HoldVerdict/decide_via_gateway`）、日志落盘；`redaction.rs`（约 1466 行）、`handler/llm/mod.rs`（约 1372 行）、`matrix.rs`（约 1307 行）各按既有子域切分，对外 `pub use` 转发不断裂。本项定性为可维护债，不算死代码。

**理由**：超阈值文件致单测须全量 `AppState`，继续拆是 round3 未竟之事的延续。

**备选**：维持现状，仅加注释，不采用（阈值真源要求 800 行内）。

### D3：`audit_hold.rs` 738 行垫片并入 `audit.rs` 留别名（C3）

**决策**：`AuditHold` 累积结构与 `RequestKeepalive` 实现体移入 `audit.rs`（或其拆分后的 hold 子模块），`audit_hold.rs` 缩为重导出垫片（`pub use super::audit::{AuditHold, RequestKeepalive, HoldVerdict, decide_via_gateway}`），与现有 `HoldVerdict/decide_via_gateway` 重导出形态一致（见 `audit_hold.rs:12`）。对外 `crate::service::audit_hold::*` 路径不变。

**理由**：判定归属已在 `audit.rs`，累积实现留外即垫片倒置，并入后单一来源。

**备选**：反向并入（判定移回 `audit_hold.rs`），扰动审计判定调用方更多，不采用。

### D4：`NonDialog` 六处散射抽 `is_passthrough()` 谓词（C4）

**决策**：在 `llm_gateway/protocol.rs` 新增 `pub fn is_passthrough(Protocol) -> bool`（`NonDialog` 返回 true，其余 false），六处调用方统一改用：`pump.rs` 三处（透传臂、用量豁免、hold 豁免）、`nonstream.rs` 一处（透传守门）、`rewrite.rs` 一处（`stream_options` 注入守门）、`handler/llm/mod.rs` 一处（`is_chat` 判定）。语义与现有各处 `== NonDialog` / `!= NonDialog` 等价，不改行为。

**理由**：六处字面比对漂移即漏审，谓词集中后新增协议变体只改一处。

### D5：`GATEWAY_BODY_LIMIT` 下沉 `config`，SSE 三常量下沉 `config`（C5）

**决策**：`GATEWAY_BODY_LIMIT_BYTES` 已在 `config/env_parse.rs:42` 定义，`handler/llm/mod.rs:28` 原位转发保留；apply 补齐文档归属注释并删 `error.rs:10`“将下沉”过期注（改为“已归属 `config`”）。SSE 三常量（`LINE_LIMIT_BYTES` 16KB、`EVENT_IDLE_TIMEOUT` 30s、`KEEPALIVE_INTERVAL` 10s，现于 `service/sse.rs:9/12/18`）下沉 `config/env_parse.rs`，`sse.rs` 原位 `pub use` 转发；硬编码理由注释随常量迁移（16KB 行完整语义、30s 与 `HTTP_TIMEOUT_SECS` 对齐、10s 远小于 NAT 超时且与管理面 60s 分属不同链路）。

**理由**：入口限值与流常量散落即阈值漂移源，`config` 单一来源后阈值表可逐项引用。

### D6：README 旧路径批量替换（D1）

**决策**：README 环境变量全表 `CREDENTIAL_BLOCK_WAIT` 行与第 8.4 节中旧单文件 `credential.rs` 下的双模与哈希变更路径，批量替换为 `src/service/credential/approval.rs`（双模）与 `src/service/credential/vault_ops.rs`（哈希变更生效，见 `vault_ops.rs:223`）新路径；替换后全仓 grep 旧字面零命中。`contract-docs` 路径可验证要求为准，CI 脚本强制。

**理由**：旧路径已随 credential 服务拆分失效，文档引用断裂即失信。

### D7：端口语义首行加粗单监听声明（D2）

**决策**：README 端口语义章节首行加粗声明“容器内单监听，不存在多端口运行时”，随后保留现有三段（单进程单监听 `127.0.0.1:8877`、compose 三映射宿主机入口区分、`resolve_upstream(None)` 缺省唯一生效由单测锁定）。措辞与 §1 环境变量表 `PORT_887x` 行同字。

**理由**：首行不定调，读者易误读三映射为三监听；加粗首行后误读关闭。

### D8：PII 6 对 7 recognizer 映射表（A3）

**决策**：README 或 `detector.rs` 模块头补对照表：本仓 `BUILTIN_NAMES` 7 名（`email/phone/id_card/bank_card/ipv4/ipv6/api_key`，见 `detector.rs:32`，注释“6 recognizer”同步修正为 7）对照原仓七类；原仓有而本仓缺的一列明缺失原因与承接 change（不新增实现）。注释与 `BUILTIN_NAMES` 长度断言单测互锁（7 名恒 7）。

**理由**：数量口径（注释 6 对数组 7）已自相矛盾，映射表一次锁死防后续漂移。

### D9：A4/A6/A9 功能映射只引用锁定（A4/A6/A9）

**决策**：本 change 不新增实现，只在 spec 与 README 互引位置锁定：单端口多上游选路弱化声明（`resolve_upstream` 缺省语义，README §1 端口章节）；Go hardening 5.1 至 5.3 未闭环承接（README §8.3，owner 为 `veil-hardening` 第 5 节）；`approve_hash_change` 非 full 降级（README §8.4）加 `GET registrations` 鉴权收敛（§7.5）加 60/min 收紧至 10/min（§3，速率与 SSE 并发 5 正交）加 `DEBUG_DIR` 落盘缺失（§7.4/§8.2）加 LRU/隔离/默认开五 BREAKING（§6.1 至 §6.5 迁移确认）。上述均已在 README 第 6 至 8 节声明，本 change 只做引用锁定。

**理由**：重复立项实现会与原 change 打架，引用锁定保持单一 owner。

## Risks / Trade-offs

- [拆分引入循环依赖] → 编译失败 → `mod.rs` 只 re-export，共享类型不动，先编过再删旧文件。
- [垫片并入断裂外部引用] → 下游编译失败 → 原位 `pub use` 转发保留，对外路径不变，全量测试回归。
- [谓词集中漏改一处] → 语义分叉 → 六处清单逐项比对，全仓 grep `NonDialog` 复核零字面残留（`protocol.rs` 定义与单测除外）。
- [常量下沉改值误动] → 阈值漂移 → 只搬不改值，阈值表与 hardening specs 同字逐项比对。
- [文档改写与 spec 漂移] → 失信 → tasks 设文档契约比对任务，逐项核对同字。

## Migration Plan

1. 先 D6/D7/D8/D9 文档与映射锁定（零风险），再 D4 谓词、D5 常量下沉、D3 垫片并入，再 D1 审批文档，最后 D2 胖文件拆分（conformance 回归）。
2. 拆分未合入前不删旧文件；合入后单 PR 删旧。
3. 回滚：各决策独立 revert。

## Open Questions

- 无。
