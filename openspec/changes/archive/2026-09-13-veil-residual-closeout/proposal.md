## Why

第三轮 Oracle 终局复核（2026-09-13，对 change `veil-reverify-fix` 交付面的收口判定）确认 4 项残留缺口（`S1`–`S4`），其中 `S1` 为 MED 规格漂移、`S2` 为 LOW-MED 票据回收。门禁基线：`cargo test` 1080 passed、`openspec validate --all --strict` 81/0；下列缺口均未被既有测试捕获，或仅被弱守护覆盖：

- **`S1`（MED，规格漂移）**：紧急吊销转常规审批入口未接决策闭环。`src/service/credential/vault_ops.rs:441` 未命中三通道（管理 token / `file_present` / 内网）时仍 `record_pending(...)` 后返 `202`——该路径不 spawn 后台 waiter、重试不查决策表：批准后吊销不执行、retry 恒 `202`。change `veil-reverify-fix` 的 spec「异步凭据审批消费闭环」子句（原句明列「及紧急吊销转常规审批入口」）的 SHALL 未兑现；现有测试仅断言首次 `202`。要求 **推荐方案 a**——该入口改走 `approval_async_202` 决策闭环（批准 → 执行 `revoke_caller` 并返回成功；拒绝/超时 → `403`；未决 → `202` 复用票据）；补「`202` → 反应批准 → retry 吊销生效」E2E 与拒绝/超时用例。备选方案 b（修订 spec 删除该子句）仅登记于本 change，不改 sibling 目录。design 写明采纳哪个及理由。
- **`S2`（LOW-MED，票据回收）**：已决无 waiter 票据滞留。`src/service/matrix/approval.rs:266-269` 的 `sweep_orphans` 对 `e.decided.is_some()` 恒 `retain(true)`——已决票无 TTL 回收；与 `S1` 联动（旧路径无 waiter，反应落定后无人消费/移除）时 `GET /health pending` 不归零、矩阵侧票无界滞留。要求：为已决票加 TTL 回收（或消费后移除语义），补 `health pending` 归零/回收测试。
- **`S3`（LOW，消费顺序）**：批准决策消费顺序有误。`src/service/credential/approval.rs:255-257` 命中 `BeginOutcome::Decided(Approved)` 后先消费决策表项，再 `query_keepass` 取库——取库失败时批准决策已丢，客户端失去已批状态，只能重新审批。要求：改为先成功取库再消费（或失败回滚决策），补失败重试用例。
- **`S4`（LOW，日志保真）**：审计 JSONL 超长保真缺口。`src/service/audit/log.rs:417` 的 `log_event` 对**完整 JSON 行**调 `sanitize_for_log`（末步 `AUDIT_SUMMARY_TRUNCATE_CHARS = 4096` 截断）——超长事件被从中间切断，产出**非法 JSON 行**（metrics JSONL 解析失败），且无测试。要求：保证序列化输出超长时仍为合法 JSON（如序列化前对自由文本字段执行 4096 口径限长，或对截断行保结构），补 `>4096` 事件「仍可被 `serde_json` 解析且零明文」测试；保持先脱敏后截断与既有字段口径。

真相源为 `src/service/credential/vault_ops.rs`、`src/service/credential/approval.rs`、`src/service/credential/auth.rs`、`src/service/matrix/approval.rs`、`src/service/audit/log.rs`。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 sibling change 目录。

## What Changes

- **`S1` 紧急吊销转常规审批接决策闭环（推荐方案 a）**：`emergency_revoke`（`src/service/credential/vault_ops.rs:423-442`）未命中三通道时不再裸 `record_pending`，改为走与默认异步 `202` 同一闭环——批准执行 `revoke_caller`（`vault_ops.rs:410`）、拒绝/超时 `403`、未决 `202` 复用既有票。为承载「批准动作不同」（凭据取库 vs 吊销注册），`approval_async_202`（`src/service/credential/approval.rs:244`）泛化出批准动作选择（或抽出同构的带动作变体），共享 `DecisionTable`（`:140`）、后台 waiter、`clear_terminal_pending`（`:39`）与重试复用语义。补 E2E：「`202` → 反应批准 → retry 吊销生效（条目 `revoked=true`/`enabled=false`）」「拒绝 → retry `403`」「超时 → retry `403`」「未决 → retry `202` 且不重复建单」。备选方案 b（仅修订 spec 删除子句）登记于 design D1，本 change 不直接改写 sibling 目录。
- **`S2` 已决票据 TTL 回收**：`src/service/matrix/approval.rs:263-281` 的 `sweep_orphans` 对已决票加 TTL 回收（或改为消费后移除语义），使无 waiter 的已决票不再永久滞留；补 `health pending`（`GET /health`）归零/回收测试与矩阵侧票数不无界增长的断言。
- **`S3` 批准决策先取凭据后消费**：`src/service/credential/approval.rs:255-257` 改为先 `query_keepass` 成功后再消费 `Decided` 表项（或取库失败回滚决策），保证取库失败不丢批准；补「取库失败后重试仍可拿凭据（批准态保留）」用例。
- **`S4` 审计 JSONL 超长仍合法**：`src/service/audit/log.rs:413-431 log_event` 改为在序列化前对自由文本字段执行「先脱敏后截断」限长（复用 `sanitize_for_log` 的脱敏/截断口径，字段级应用），使超长事件的序列化行仍为合法 JSON；补 `>4096` 事件「`serde_json::from_str` 可解析且零明文」测试，保持 `sanitize_for_log` 作为整串摘要入口的既有 4096 口径不变。
- **记录项落 design.md**：`S1` 采纳方案 a 的理由与方案 b 登记；`S2` 回收口径；`S3` 顺序理由；`S4` 字段级限长与整串截断的分治边界。

## Capabilities

### New Capabilities

- `residual-closeout`：Oracle 终局复核 4 项残留（`S1`–`S4`）的修复契约——紧急吊销转常规审批与默认异步 `202` 同一决策闭环、已决票据 TTL 回收、批准决策先取凭据后消费、审计 JSONL 超长仍为合法 JSON 且零明文。

### Modified Capabilities

- 无。`openspec/specs/` 既有契约不新增/修改；本 change 新增 capability 承载 4 项行为收敛，README 相关段（§6.7 审批语义、§4 审计日志轮转/阈值）随 apply 阶段与行为同批更新。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `S1` | MED（规格漂移） | `vault_ops.rs:441` 紧急吊销转常规审批改走 `approval_async_202` 决策闭环（批准执行 `revoke_caller`、拒绝/超时 `403`、未决 `202` 复用）；泛化批准动作；E2E 四态 + retry 吊销生效 | 1.1、1.2、1.3 |
| `S2` | LOW-MED | `matrix/approval.rs:266-269` 已决票加 TTL 回收（或消费后移除）；`health pending` 归零/回收测试 | 2.1、2.2 |
| `S3` | LOW | `credential/approval.rs:255-257` 先 `query_keepass` 成功再消费 `Decided`（或失败回滚）；取库失败重试用例 | 3.1、3.2 |
| `S4` | LOW | `audit/log.rs:417` 序列化前对自由文本字段「先脱敏后截断」限长，超长行仍为合法 JSON；`>4096` 可解析且零明文测试 | 4.1、4.2 |

## Non-Goals（显式）

- **本 change 不改 `src/`、`tests/` 与 sibling change 目录**：只交付规划 artifacts；实现与测试改动留待 apply 阶段。`S1` 备选方案 b（修订 sibling 规范删除子句）仅在本 change design D1 登记，不直接改写 `openspec/changes/veil-reverify-fix/`。
- **不改阻塞模式（`CREDENTIAL_BLOCK_WAIT=1`）语义**：`S1`/`S3` 仅收敛默认异步 `202` 决策闭环，阻塞 `300s` 路径维持现状。
- **不改脱敏 recognizer 形态集合与采样策略**：`S4` 只改「字段级脱敏/截断 vs 整行截断」的落点，不动 `mask_secret_forms` 的识别集合与 `sanitize_for_log` 的整串 4096 口径。
- **不改三通道豁免判据**：`S1` 不动管理 token / `file_present` / 内网来源三者任一即直接吊销的旁路语义，仅改未命中后的转审批路径。
- **不引入跨请求持久化决策存储**：`S1`/`S3` 复用进程内 `DecisionTable`（有界 + TTL），不落盘、不新增依赖。
- **不对审计 JSONL 做模式迁移/回填**：`S4` 只保证新写入行合法，不扫描/修复既有 `audit.log`。

## Impact

- **新增文件**：`openspec/changes/veil-residual-closeout/` 下 `proposal.md`、`design.md`、`specs/residual-closeout/spec.md`、`tasks.md`（`.openspec.yaml` 已存在）。
- **apply 阶段改动面**：`src/service/credential/vault_ops.rs`、`src/service/credential/approval.rs`、`src/service/credential/auth.rs`（`S1` 决策闭环与批准动作泛化）；`src/service/matrix/approval.rs`（`S2` 已决票回收）；`src/service/audit/log.rs`（`S4` 字段级限长）；对应新增单测与 `README.md` §6.7 / §4。
- **影响系统**：紧急吊销转审批的端到端可用性（批准后重试吊销生效）；`health pending` 计数准确性与矩阵侧票内存上界；异步批准在取库失败下的可重试性；审计 JSONL 的可解析性（metrics 消费面）与零明文保证。
- **依赖**：无新依赖；复用既有 `tokio`、`serde_json`、`Mutex`/`HashMap` 与测试设施。
