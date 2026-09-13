# reverify-fix Specification

## Purpose
锁定第二轮独立 Oracle 复核（2026-09-13）确认的 HIGH/MED 行为缺口的修复契约：审计摘要「先脱敏后截断」次序与超长 PEM 零明文（`R1`）、异步 `202` 凭据审批消费闭环（`R2`）、审批建单路径白名单与规格对齐（`R3`）。`R4`（弱守护修正）与 `R5`（已知局限登记）为测试/文档面，不产生产品行为契约，记录于 design.md。

## Requirements

### Requirement: 审计摘要先脱敏后截断

系统 SHALL 先对**完整输入**执行密钥形态脱敏，再对脱敏结果按字符上限（4096）截断；SHALL NOT 在脱敏前截断输入。即 `sanitize_for_log` 的次序 SHALL 为「剥控制字符 → 完整输入脱敏 → 截断」，`mask_secret_forms` SHALL NOT 前置对输入的 `truncate_ref_chars`。PEM 私钥块 SHALL 依据 `-----BEGIN ... PRIVATE KEY-----` 与 `-----END ... PRIVATE KEY-----` 收敛判据整体识别并置 `[REDACTED:private_key]`，即使整块长度超过 4096 字符也 SHALL 识别，SHALL NOT 因截断丢失 `-----END` 而放行 base64 私钥材料。对未命中任何脱敏形态的长输入，输出 SHALL 与截断口径逐字一致（如 `sk-` + 9000×`a` + `尾` 的脱敏结果 SHALL 为 `[REDACTED:secret]尾`）。实现 SHALL 保持近似线性时间，SHALL NOT 回退逐位置重建整串小写等 O(n²) 扫描。

#### Scenario: 超长 PEM 块零明文

- **WHEN** 输入含一个总长超过 4096 字符的 PEM 私钥块（`-----BEGIN ... PRIVATE KEY-----` 与 `-----END ... PRIVATE KEY-----`，中间为 base64 私钥材料）
- **THEN** 输出含 `[REDACTED:private_key]`，且不含该 PEM 块的 base64 明文材料，截断后长度不超过 4096 字符

#### Scenario: 长 sk- 输入逐字一致

- **WHEN** 输入为 `sk-` 后接 9000 个 `a` 再接 `尾`
- **THEN** 输出为 `[REDACTED:secret]尾`（先脱敏后截断的逐字口径），与旧实现的 `[REDACTED:secret]` 不同即为回归

#### Scenario: 近线性保持

- **WHEN** 输入为 20 万字符的对抗性串（逐位候选 + 远端 `@`，如 `"." * n + "@" + "a" * n + ".1"`）
- **THEN** 脱敏在既有 `audit_summary_linear_bound` 上界内近似线性完成，不出现超时

### Requirement: 异步凭据审批消费闭环

系统 SHALL 在默认（`CREDENTIAL_BLOCK_WAIT` 未设或非真值）异步模式下为每个审批单建立后台消费方：建单后 SHALL spawn 后台等待 `ask(event_id, timeout)`，并把 `Some(true)`/`Some(false)`/`None` 决策按 `pending_key` 落定到有界、带 TTL 的决策表。后续同一请求进入 `handle_credential`（及紧急吊销转常规审批入口）时 SHALL 先查决策表：批准 → SHALL 继续执行 `query_keepass` 返回凭据；拒绝或超时 → SHALL 返回 `403`；未决 → SHALL 返回 `202 + E_PENDING`。系统 SHALL 在同一 `pending_key` 重试时复用既有审批单，SHALL NOT 每次重试重复新建单。决策表 SHALL 有界且带 TTL，SHALL NOT 无界增长。

#### Scenario: 批准后重试返回凭据

- **WHEN** 默认异步模式建单返回 `202`，审批人回复 `✅`，随后客户端对同一请求重试
- **THEN** 重试不再返回 `202`，而是返回凭据（`query_keepass` 结果）

#### Scenario: 拒绝后重试返回 403

- **WHEN** 默认异步模式建单返回 `202`，审批人回复 `❎`，随后客户端对同一请求重试
- **THEN** 重试返回 `403`

#### Scenario: 未决重试保持 202

- **WHEN** 默认异步模式建单后审批人尚未回复，客户端对同一请求重试
- **THEN** 重试返回 `202 + E_PENDING`，且不新建第二个审批单

#### Scenario: 超时按拒绝

- **WHEN** 默认异步模式建单后无任何回复直至审批超时
- **THEN** 后续重试返回 `403`（超时按拒绝处理）

### Requirement: 审批建单路径白名单

系统 SHALL 仅对产生**可决 Matrix 审批票**的路径（凭据、注册、吊销）经 tracked 发送以真实 Matrix event id 作为 pending 键建单。流式审计挂起（`audit-hold`）SHALL 仅记录内存 pending 记录，SHALL NOT 建 Matrix 审批票（README §6.4 流式审批不挂起语义）；`unlock` 与哈希变更 SHALL NOT 建 Matrix 审批票（哈希变更经 best-effort `notify_text` 通知）。审批建单路径的规范声明与生产实现 SHALL 一致；SHALL NOT 在规范中把不存在的建单路径列为 tracked-send 路径。

#### Scenario: audit-hold 仅内存 pending

- **WHEN** `AUDIT_MODE=approve` 下流式危险调用触发 `audit-hold`
- **THEN** 仅插入内存 pending 记录，不创建 Matrix 审批票，不阻塞流、不合成阻断帧

#### Scenario: 凭据/注册/吊销以真实 id 建单

- **WHEN** 凭据、注册或吊销路径需要人工审批
- **THEN** 经 tracked 发送取真实 event id 并以之为 pending 键建单，发送失败则 fail-closed

#### Scenario: 测试命名与范围对齐

- **WHEN** 审查 `src/service/credential/approval/tests/f1.rs` 中名为 `audit_hold_approval_real_event_id` 的测试
- **THEN** 该测试的命名与范围 SHALL 反映其实际覆盖（通用 `MatrixBranch::Audit` 建单）或改走生产 audit-hold 路径，SHALL NOT 以通用路径调用冒充 audit-hold 覆盖
