## Context

第二轮独立 Oracle 复核（2026-09-13）对 change `veil-oracle-followup-fix` 交付面做回归，确认 5 项缺口（`R1`–`R5`，见 proposal Why 与覆盖表）。现状真相源：

- **`R1` 脱敏次序回归**：`sanitize_for_log`（`src/service/audit/log.rs:44`）声明「先脱敏后截断」，但 `mask_secret_forms`（`:53`）在首行 `truncate_ref_chars(s, AUDIT_SUMMARY_TRUNCATE_CHARS)`（`:55`）先截断再脱敏。`private_key_block_at`（`:155`）需 `-----END` 收敛；>4096 字符 PEM 块截断后无 END → 不识别 → 前 4096 字符（含 base64 私钥材料）明文落盘。同时长输入输出不再逐字一致。此为 F6/D6「近似线性」修复的副作用。
- **`R2` async 202 无消费方**：`approval_dual_mode`（`src/service/credential/approval.rs:117`）非阻塞分支 `:125-127` 仅 `return Err(record_pending(...))`；`await_credential_approval`（`:145`）生产零调用（仅 `src/service/credential/approval/tests.rs:188`）。重试重复建单，`✅` 落定无人读取。`vault_ops.rs:441` 紧急吊销转常规审批同。
- **`R3` 规格与实现漂移**：change `veil-oracle-followup-fix` 的 spec/design/tasks 把 `audit-hold`/`unlock`/`hash-change` 列为 tracked-send 建单路径；生产实现中 `audit-hold`（`src/handler/llm/pump/spawn/event_loop.rs:350-356/472`）仅 `audit_pending.insert(PendingRecord::new(...))`，`notify_hash_change`（`src/service/credential/approval.rs`）走 best-effort `notify_text`，无 unlock 建单路径。测试 `src/service/credential/approval/tests/f1.rs` 的 `audit_hold_approval_real_event_id` 只调通用 `submit_pending_with_branch`。
- **`R4` 弱守护**：F9 引用的 `init_no_sync_sweeper` 在 `src/service/credential/approval.rs` 不存在；真实 `sweeper_spawn_count`/`init_no_sync_sweeper_observable` 在 `src/approval.rs`（`:102`/`:189`），断言对 `PendingApprovals::default()` 平凡，未覆盖 `src/main.rs:122-123` 的生产 init。F10 `src/main.rs:177 preflight_probe` 为测试内重实现（`:177-192`），副作用断言自证；仅 `include_str!`（`:193`）排序检查为真。
- **`R5` 登记项**：F7 守护为名称/标记制（`src/service/tpm.rs`/`src/main.rs` 整文件豁免可绕）；F8「analyzer」为测试键名（`src/service/pii/detector/tests.rs`），生产为全局 `ValidationCache`（`src/service/pii/detector.rs:427`）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 sibling change 目录；不引入新依赖；阻塞模式语义不动。

## Goals / Non-Goals

**Goals：**

- 给出 `R1`/`R2`/`R3` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「先脱敏后截断 + 超长 PEM 零明文」「异步 `202` 三态消费闭环」「审批建单路径白名单」收敛为 spec 契约。
- 记录 `R3` 裁决（排除路径）与写面、`R4` 守护强化理由、`R5` 已知局限与命名说明。

**Non-Goals：**

- 不恢复 O(n²) 全量脱敏（`R1` 须同时保近线性，见 D1）。
- 不改脱敏 recognizer 形态集合与采样策略。
- 不引入跨请求持久化决策存储（`R2` 决策表为进程内有界 + TTL）。
- 不改阻塞模式（`CREDENTIAL_BLOCK_WAIT=1`）语义。
- 不直接改写 sibling change 目录（`R3` 以本 change design/spec 登记裁决与写面，见 D3）。

## Decisions

### D1：`R1` 恢复「完整输入脱敏后再截断」，近线性经一次预计算保持

**决策**：`sanitize_for_log` 次序固定为「剥控制字符 → `mask_secret_forms(完整输入)` → `truncate_chars(masked, 4096)`」；`mask_secret_forms` 移除首行 `truncate_ref_chars`（`src/service/audit/log.rs:55`），在完整输入上扫描。为不回退 O(n²)，apply 阶段：(a) `secret_kv_at` 所需的小写串对整输入**一次性预计算**并在扫描中复用（不逐位置 `to_lowercase`）；(b) 形态识别保持单趟前向扫描（命中即产出占位符并跳过长度的既有结构）；(c) 截断仅在脱敏完成后以 `truncate_chars`（`:366`）做一次。`private_key_block_at`（`:155`）本身以 `find("-----END")` 收敛，完整输入下天然识别超长 PEM。

**理由**：原契约明确「先脱敏后截断」（注释与 `AUDIT_SUMMARY_TRUNCATE_CHARS` 文档），F6 为把逐位置 `to_lowercase`/远端 `@` 的 O(n²) 消除而前置截断，属于「以正确性换性能」的越权取舍。脱敏是安全前置，截断是落盘体积控制，两者次序不可交换。一次预计算小写 + 单趟扫描即可同时满足正确性与近线性（`audit_summary_linear_bound` 输入 20 万字符仍覆盖）。

**备选**：仅把 `truncate_ref_chars` 上限调大（如 64KB）——超长 PEM 仍可越界且未修正次序，不采用；截断后对尾部补 `-----END` 猜测——伪造判据，不采用；保留前置截断并声明例外——违反零明文，不采用。

### D2：`R2` 后台 waiter + 有界 TTL 决策表 + 入口三态分派

**决策**：新增进程内 `DecisionTable`（键 = `pending_key`，值 = 决策枚举，容量有界、TTL 与 `PendingApprovals::PENDING_TTL_SECS` 同口径）。`approval_dual_mode`（`src/service/credential/approval.rs:117`）非阻塞分支改为：`submit_pending` 取真实 id → 记录内存 pending → `tokio::spawn` 后台 `ask(event_id, timeout)` → 结果写入决策表（`Some(true)`/`Some(false)`/`None`）→ 返回 `Err(VeilError::PendingApproval{202})`。`handle_credential`（`src/service/credential/auth.rs:201/217` 调用点）与紧急吊销入口（`vault_ops.rs:441`）在调用 `approval_dual_mode` 前先查决策表：`Approved` → 继续 `query_keepass`；`Denied`/`TimedOut` → `403`；`Pending`/无记录 → 沿用 `202` 建单路径，且同一 `pending_key` 已有建单时复用（不重复建单）。决策被消费后清除表项（一次性语义）。

**理由**：README §6.7 承诺 async 模式「批准后重试返回凭据、拒绝后 `403`」，其成立前提是决策有人消费；当前 `await_credential_approval` 无生产调用，承诺落空。后台 waiter + 决策表是「建单即返 `202`」与「重试查决策」之间的最小闭环，且不改变阻塞模式。消除重试重复建单需以 `pending_key` 幂等映射到既有 `event_id`（复用 `submit_pending_with_branch` 的 key 语义）。

**备选**：在 `handle_credential` 内阻塞等待（即强制 `CREDENTIAL_BLOCK_WAIT`）——破坏默认异步语义，不采用；把决策表落盘持久化——超出内存 pending 语义且引入 IO/TTL 复杂度，不采用；仅在批准时改写 pending 记录——无法承载「拒绝/超时」三态统一，不采用。

### D3：`R3` 裁决 (b)——排除 `audit-hold`/`unlock`/`hash-change` 建单，并登记写面

**决策**：选 (b)（修订规范使其与实现一致），理由：

- `audit-hold`：README §6.4 明确「流式审批不挂起等待真人 `✅/❎`；拒绝/过期语义由凭据审批链承载」，`src/handler/llm/pump/spawn/event_loop.rs:350-356/472` 仅写内存 `audit_pending`。若强行建 Matrix 单，将与「流式不挂起」声明冲突且无消费方（同 `R2`）。
- `unlock`：生产无 Matrix 建单路径（全仓 grep 无对应 `submit_*` 调用）。
- `hash-change`：`notify_hash_change`（`src/service/credential/approval.rs`）为 best-effort `notify_text` 通知，非审批票。

apply 写面（登记，本 change 不直接改写 sibling 目录）：(1) 本 change spec「审批建单路径白名单」承载正确口径；(2) 后续同步 README §6.4/§6.7 明确路径集合与理由；(3) 修订 `src/service/credential/approval/tests/f1.rs` 的 `audit_hold_approval_real_event_id` 命名/范围——改为反映其实际覆盖（通用 `MatrixBranch::Audit` 建单，建议重命名为 `audit_branch_pending_uses_real_event_id`）或改走真实 audit-hold 路径并在测试内断言仅内存 pending；(4) sibling change 规范文本中「哈希变更、解锁、audit-hold」建单声明由本裁决驱动后续修订（跨 change 节奏由 orchestrator 决定，不在本 change 内改 sibling artifact）。

**理由**：实现侧「不建单」符合同仓 README 声明与安全语义（流式面不悬挂长连接）；把不存在的建单路径写进规范属过度声明（false assurance），误导后续审计把未覆盖路径当已覆盖。选 (b) 成本最低且不引入新的挂起/消费闭环风险。

**备选**：(a) 为三路径补建单——与 README §6.4 冲突、需一并交付消费方（扩大面至流式/密钥生命周期），不采用。

### D4：`R4` 守护强化——F9 结构化生产断言、F10 可注入真实启动序

**决策**：

- **F9**：修正引用——真实测试为 `src/approval.rs:189 init_no_sync_sweeper_observable`，`sweeper_spawn_count` 在 `src/approval.rs:102`。断言从「对 `PendingApprovals::default()` 平凡无 spawn」升级为对生产 init 的结构化断言：`PendingApprovals::default()` 构造后 `sweeper_spawn_count()==0` 且无后台任务；仅 `src/main.rs:122-123` 的显式 `spawn_sweeper()` 使其递增；并断言构造与显式 spawn 的先后（默认构造不自启清扫）。若可注入，覆盖 `main` 的启动序（构造 → 显式 spawn）。
- **F10**：`src/main.rs:177 preflight_probe` 删除或改为调用真实可注入的启动序函数（副作用——建数据目录/触 TPM/起后台任务——经注入 `AtomicUsize` 计数真实发生），保留并强化 `include_str!`（`:193`）的白名单门禁排序检查（门禁早于 `startup_tpm_in`/`init_sqlite`/`spawn_sweeper`）。

**理由**：F9 当前断言对默认构造平凡、且引用了不存在的符号路径，无法证明生产 init 行为；F10 的 `preflight_probe` 自建副作用再自断言，不触真实启动序，属自证。守护必须对真实代码路径断言，否则是 false assurance。

**备选**：F10 仅保留 `include_str!` 排序检查——丢失副作用门禁，不采用；把 `preflight_whitelist` 直接提取为接受注入计数器的生产函数——改动生产签名，若 apply 评估可控则优先，否则删除 helper 以排序检查为准。

### D5：`R5` 登记项——F7 名称/标记制守护、F8「analyzer」命名

**决策（无行为改动，仅登记）**：

- **F7**：TPM 同步子进程守护（`src/service/tpm.rs` ↔ `src/main.rs`）仍是名称/标记制，非调用图分析；整文件豁免（`src/service/tpm.rs`/`src/main.rs`）意味着在 `tpm.rs` 内新增非标记包装即可绕过。登记为已知局限：守护防误用而非防蓄意规避，后续如需强守护应引入基于调用图的静态分析或运行时断言（另立 change）。
- **F8**：单测中的「analyzer」是缓存键名（`src/service/pii/detector/tests.rs`），生产实现是全局 `ValidationCache`（`src/service/pii/detector.rs:427`）；命名差异非缺陷，登记说明以免复核再次误判。

**理由**：两者均属测试/文档可观测性口径，非产品行为；强行改造超出本 change 范围。登记已知局限可防止后续审计把「名称/标记制」当强守护。

## Risks / Trade-offs

- [`R1` 先脱敏后截断放大扫描范围] → 完整输入（可能接近 `AUDIT_HOLD_MAX_BYTES`）全量扫描 → 以一次性小写预计算 + 单趟扫描保持近线性；`audit_summary_linear_bound`（20 万字符）与 `mask_secret_forms_large_input`（接近 1MB）保绿作回归门禁。
- [`R2` 后台 waiter 生命周期/泄漏] → 每个建单 spawn 一个 waiter；若超时未落定或进程退出 → waiter 以 `ask` 超时自然结束，决策表有界 + TTL 回收，pending 既有 60s 清扫兜底。
- [`R2` 决策表与 pending 双状态一致性] → 决策被消费即清除；`clear_terminal_pending`（`src/service/credential/approval.rs`）在落定时同步清理两侧，避免「已决仍 `202`」或「已清仍读」。
- [`R2` 重试复用建单的幂等映射] → 需 `pending_key` → `event_id` 映射；由 `submit_pending_with_branch` 的 key 语义与决策表查询共同保证，apply 阶段以 E2E 四态锁定。
- [`R3` 排除路径被后续误读为「已实现」] → spec 明确 `SHALL NOT` 建单并说明理由，design D3 登记写面，测试重命名消除歧义。
- [`R4` F10 抽取生产启动序函数导致行为漂移] → 若必须改生产签名，以现有排序不变量 + 注入计数断言锁定；否则删除 helper，保留 `include_str!` 排序检查。
- [`R5` 登记后仍被当强守护] → design D5 显式标注「防误用非防蓄意」，并记录绕过面（整文件豁免）。

## Migration Plan

1. 按 tasks 顺序落地：先 `R1` 脱敏次序（安全前置），再 `R2` 消费闭环（功能可用性），再 `R3`/`R4`/`R5` 规格与守护登记，最后门禁。
2. 每组独立 `cargo test -p veil <组>`；README §6.4/§6.7 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化；决策表为进程内状态，回滚无残留。
4. 发布口径：`R1` 修复恢复零明文与逐字一致（对下游为正确性修复）；`R2` 恢复 README §6.7 承诺的 async 三态（下游可感知：批准后重试得凭据）；`R3` 为文档对齐（无运行时变化）。

## Open Questions

- 无。`R3` 已裁定 (b)；`R2` 决策表容量/TTL 具体数值在 apply 阶段以 `PendingApprovals::PENDING_TTL_SECS` 为基线确定；若 apply 实测 1MB 级输入在近线性门禁下仍超时，回到 D1 评估窗口化候选方案。
