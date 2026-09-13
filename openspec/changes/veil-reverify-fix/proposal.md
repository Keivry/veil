## Why

第二轮独立 Oracle 复核（2026-09-13，对 change `veil-oracle-followup-fix` 交付面回归）确认 5 项遗留/新引入缺口（`R1`–`R5`），其中 2 项为 HIGH。门禁基线：`cargo test` 1072 passed、`openspec validate --all --strict` 80/0；下列缺口均未被既有测试捕获或仅被弱守护覆盖：

- **`R1`（HIGH，脱敏回归）**：`src/service/audit/log.rs:44 sanitize_for_log` 语义为「先脱敏后截断」，但 `:55 mask_secret_forms` 内部先 `truncate_ref_chars(s, 4096)` 再脱敏——输入在脱敏前即被截断。`private_key_block_at`（`:155`）依赖 `-----END` 收敛判据；>4096 字符 PEM 私钥块的 `-----END` 落在截断线之外 → 整体不识别 → 前 4096 字符（含 base64 私钥材料）**明文**写入 `audit.log`，违反零明文与「先脱敏后截断」契约。同时长输入输出不再逐字一致（`sk-`+9000×`a`+`尾`：旧 `[REDACTED:secret]尾`，新 `[REDACTED:secret]`）。此为 F6「近似线性」修复引入的次序回归。
- **`R2`（HIGH，async 202 无消费方）**：`src/service/credential/approval.rs:117 approval_dual_mode` 非阻塞分支仅 `return Err(record_pending(...))`（建单 → `202`）；消费方 `await_credential_approval`（`:145`）生产零调用（仅 `src/service/credential/approval/tests.rs:188` 单测）。每次重试都会新建单 → 批准后重试仍 `202`；`✅` 落定结果无人读取。违反 README §6.7「默认异步 `202`…批准后重试返回凭据、拒绝后 `403`」。`src/service/credential/vault_ops.rs:441` 的紧急吊销转常规审批同样只抛单。
- **`R3`（MED，规格与实现漂移）**：change `veil-oracle-followup-fix` 的 spec/design/tasks 把 `audit-hold`、`unlock`、`hash-change` 列为 tracked-send 建单路径，但生产实现中：`audit-hold`（`src/handler/llm/pump/spawn.rs`）仅写内存 pending（README §6.4 明确流式审批不建 Matrix 单）；`unlock`/`hash-change` 无 Matrix 建单路径。测试 `src/service/credential/approval/tests/f1.rs` 的 `audit_hold_approval_real_event_id` 只调用通用 `submit_pending_with_branch`，未走生产 audit-hold 路径，命名与范围均误导。
- **`R4`（LOW，弱守护）**：F9「`init_no_sync_sweeper`」在 `src/service/credential/approval.rs` **不存在**（幽灵符号/路径）；真实断言 `sweeper_spawn_count` 与测试 `init_no_sync_sweeper_observable` 位于 `src/approval.rs`，且「无 spawn」断言对 `PendingApprovals::default()` 平凡，未覆盖生产 init（`src/main.rs:122-123` 的构造/`spawn_sweeper` 时序）。F10 `src/main.rs` 的 `startup_whitelist_fail_fast` 中 `preflight_probe` 是测试内重实现，副作用断言自证；仅 `include_str!` 字符串位置检查为真。
- **`R5`（LOW，登记项）**：F7 守护仍为名称/标记制（非调用图；`src/service/tpm.rs`/`src/main.rs` 整文件豁免，`tpm.rs` 内加非标记包装即可绕）；F8「analyzer」为测试键名（`src/service/pii/detector/tests.rs`），生产实为全局 `ValidationCache`（`src/service/pii/detector.rs`）。无行为改动，登记为已知局限与命名说明。

真相源为 `src/service/audit/log.rs`、`src/service/credential/approval.rs`、`src/service/credential/auth.rs`、`src/service/credential/vault_ops.rs`、`src/service/matrix/notify.rs`、`src/handler/llm/pump/spawn.rs`、`src/approval.rs`、`src/main.rs`、`src/service/tpm.rs`、`src/service/pii/detector.rs`。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 sibling change 目录。

## What Changes

- **`R1` 恢复「先脱敏后截断」并保持近线性**：`sanitize_for_log`（`src/service/audit/log.rs:44`）语义改为「对完整输入脱敏后再 `truncate_chars`」；`mask_secret_forms`（`:53`）不再前置 `truncate_ref_chars`（`:55`），改为在完整输入上以有界扫描完成识别。为不回退 O(n²)，apply 阶段采用一次性小写预计算（复用 `secret_kv_at` 的 `to_lowercase` 结果）与候选窗口，禁止逐位置重建整串小写/重复扫描。补 >4096 字符 PEM 回归（断言输出含 `[REDACTED:private_key]` 且零 base64 明文）与长 `sk-` 逐字一致回归；`audit_summary_forms`/`audit_summary_zero_plaintext`/`b9_deny_summary_dual_shapes`/`audit_summary_linear_bound` 保绿。
- **`R2` 实现 async 202 消费闭环**：`approval_dual_mode` 非阻塞分支建单后 spawn 后台 waiter `ask(event_id, timeout)`，将 `Some(true)`/`Some(false)`/`None` 决策按 `pending_key` 落入有界、带 TTL 的决策表（新增内部结构，容量/TTL 与 `PendingApprovals` 同口径）；`handle_credential`（`src/service/credential/auth.rs`）与紧急吊销入口先查决策表：批准 → 继续 `query_keepass` 返回凭据、拒绝/超时 → `403`、未决 → `202 + E_PENDING`；同一 `pending_key` 重试复用既有单，不再重复建单。补 async-202 E2E（202→`✅`→重试得凭据；`❎`→`403`；未决→`202`；超时→按拒绝 `403`）。
- **`R3` 审批建单路径规格与实现对齐（裁决 b：排除）**：裁决为 (b)——明确 `audit-hold`/`unlock`/`hash-change` **不**走 tracked-send 建单：`audit-hold` 仅写内存 pending（README §6.4 语义），`unlock`/`hash-change` 无 Matrix 建单路径（`notify_hash_change` 走 best-effort `notify_text`）。裁决与该写面登记写入本 change 的 design/spec；apply 阶段修订 `src/service/credential/approval/tests/f1.rs` 的测试命名/范围（改反映通用 `MatrixBranch::Audit` 建单，或改走真实路径），并同步 README §6.4/§6.7 可写面。**本 change 不直接改写 sibling change 目录**。
- **`R4` 强化弱守护**：修正 F9 的符号/路径引用（`init_no_sync_sweeper_observable` 在 `src/approval.rs`），并把「无 spawn」断言改为对生产 init 的结构化断言（默认构造不自启清扫，仅 `spawn_sweeper` 递增计数；覆盖 `src/main.rs:122-123` 的构造/显式 spawn 时序）；F10 改为调用可注入的真实启动序函数（副作用经注入计数可观测），或删除误导性 `preflight_probe` helper，保留并强化 `include_str!` 排序门禁。
- **`R5` 登记已知局限**：design 记录 F7 为名称/标记制守护（非调用图，整文件豁免可绕）与 F8「analyzer」为测试键名（生产为全局 `ValidationCache`），无行为改动。
- **记录项落 design.md**：`R3` 裁决与写面、`R4` 守护强化理由、`R5` 局限/命名，均记 design 决策。

## Capabilities

### New Capabilities

- `reverify-fix`：第二轮复核缺口的修复契约——审计摘要「先脱敏后截断」次序与超长 PEM 零明文、异步 `202` 凭据审批消费闭环（批准/拒绝/未决/超时三态在 async 模式成立）、审批建单路径白名单与规格对齐。

### Modified Capabilities

- 无。`R4`/`R5` 为测试守护与登记项，不改变产品行为；`openspec/specs/` 既有契约不新增/修改。行为变化（脱敏次序、async 消费）由本 change 新增 capability 承载，README §6.4/§6.7 随 apply 同批更新。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `R1` | HIGH | `sanitize_for_log` 恢复「先脱敏后截断」，`mask_secret_forms` 去前置截断；超长 PEM 整块识别零明文；长输入逐字一致；近线性不回退 | 1.1、1.2、1.3 |
| `R2` | HIGH | async 202 消费闭环：后台 waiter + 有界 TTL 决策表 + 入口三态分派；重试复用既有单不重复建单；E2E 四态 | 2.1、2.2、2.3 |
| `R3` | MED | 裁决 (b) 排除 `audit-hold`/`unlock`/`hash-change` 建单并说明理由；登记写面；修正 `f1.rs` 测试命名/范围 | 3.1、3.2 |
| `R4` | LOW | 修正 F9 幽灵符号/路径并改生产 init 结构化断言；F10 改可注入真实启动序函数或删除误导 helper，保留排序门禁 | 4.1、4.2 |
| `R5` | LOW | design 登记 F7 名称/标记制守护局限与 F8「analyzer」命名说明（无行为改动） | 5.1 |

## Non-Goals（显式）

- **本 change 不改 `src/`、`tests/` 与 sibling change 目录**：只交付规划 artifacts；实现与文档改动留待 apply 阶段。`R3` 的 sibling 规范文本修订以「本 change design/spec 登记裁决 + 写面」方式表达，不直接改写 `openspec/changes/veil-oracle-followup-fix/`。
- **不恢复 O(n²) 全量脱敏**：`R1` 修复必须同时保持近线性（`audit_summary_linear_bound` 保绿），不得以「先脱敏后截断」为由回退逐位置整串扫描。
- **不改脱敏 recognizer 集合与采样策略**：`R1` 只改「脱敏 vs 截断」次序与超长 PEM 识别，不动 `secret_prefix_at`/`email_at`/PEM 判定等形态集合。
- **不引入跨请求持久化决策存储**：`R2` 决策表为进程内有界 + TTL，不落盘、不新增依赖；重启即丢弃（与原 pending 内存语义一致）。
- **不改阻塞模式（`CREDENTIAL_BLOCK_WAIT=1`）语义**：`R2` 仅补默认异步 `202` 的消费闭环，阻塞 300s 路径维持现状。
- **不给 `RewriteOutput` 等既有结构增错误通道**：`R4` F10 在不改变生产启动序语义前提下抽可注入函数或删除 helper。

## Impact

- **新增文件**：`openspec/changes/veil-reverify-fix/` 下 `proposal.md`、`design.md`、`specs/reverify-fix/spec.md`、`tasks.md`（`.openspec.yaml` 已存在）。
- **apply 阶段改动面**：`src/service/audit/log.rs`、`src/service/credential/approval.rs`、`src/service/credential/auth.rs`、`src/service/credential/vault_ops.rs`（`R2` 决策表/入口分派）；`src/service/credential/approval/tests/f1.rs`、`src/approval.rs`、`src/main.rs`（`R3`/`R4` 测试守护）；对应新增单测与 `README.md` §6.4/§6.7。
- **影响系统**：审计日志零明文保证与摘要逐字一致、审计耗时上界；默认异步凭据审批的端到端可用性（批准后重试得凭据）；审批建单路径契约口径；测试守护真实性与启动序门禁强度。
- **依赖**：无新依赖；复用既有 `tokio`、`serde_json` 与测试设施。
