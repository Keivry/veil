# residual-closeout Specification

## Purpose
锁定第三轮 Oracle 终局复核（2026-09-13）确认的 4 项残留缺口（`S1`–`S4`）的修复契约：紧急吊销转常规审批与默认异步 `202` 同一决策闭环（`S1`）、已决无 waiter 票据 TTL 回收（`S2`）、批准决策先取凭据后消费（`S3`）、审计 JSONL 超长仍为合法 JSON 且零明文（`S4`）。

## Requirements

### Requirement: 紧急吊销转常规审批决策闭环

系统 SHALL 在紧急吊销未命中管理 token / 文件在位（`file_present`）/ 内网来源三通道而转常规审批时，走与默认异步 `202` 相同的决策闭环：建单后 SHALL spawn 后台等待 `ask(event_id, timeout)` 并把决策按 `pending_key` 落定到有界、带 TTL 的决策表；后续同一入口重试 SHALL 先查决策表——批准 → SHALL 执行 `revoke_caller` 并返回成功；拒绝或超时 → SHALL 返回 `403`；未决 → SHALL 返回 `202 + E_PENDING` 并复用既有审批单，SHALL NOT 重复新建单。系统 SHALL NOT 以「仅 `record_pending` 抛单、无后台消费方」的方式实现该转审批路径。批准后的吊销 SHALL 使条目 `revoked=true` 且 `enabled=false`（与常规吊销同一落定语义）。

#### Scenario: 批准后重试吊销生效

- **WHEN** 紧急吊销未命中三通道而转常规审批返回 `202`，审批人回复 `✅`，随后客户端对同一请求重试
- **THEN** 重试不再返回 `202`，而是返回成功且注册条目 `revoked=true`、`enabled=false`

#### Scenario: 拒绝后重试 403

- **WHEN** 紧急吊销转常规审批建单返回 `202`，审批人回复 `❎`，随后客户端对同一请求重试
- **THEN** 重试返回 `403`，且注册条目保持原状（未吊销）

#### Scenario: 超时后重试 403

- **WHEN** 紧急吊销转常规审批建单返回 `202`，无任何回复直至审批超时，随后客户端对同一请求重试
- **THEN** 重试返回 `403`（超时按拒绝处理），且注册条目保持原状

#### Scenario: 未决重试 202 复用

- **WHEN** 紧急吊销转常规审批建单返回 `202`，审批人尚未回复，客户端对同一请求重试
- **THEN** 重试返回 `202 + E_PENDING`，且不新建第二个审批单（既有票复用）

### Requirement: 已决票据 TTL 回收

系统 SHALL 为已落定（`decided.is_some()`）且无等待者消费的矩阵侧审批票施加有界回收（按 TTL 或消费后移除语义），SHALL NOT 使已决票永久滞留于 `sweep_orphans`。回收后 `GET /health` 的 `pending` 计数 SHALL 归零（与审批终态即时归零口径一致），矩阵侧待审批票数 SHALL NOT 随已决无 waiter 票据无界增长。

#### Scenario: 已决无 waiter 票据被回收

- **WHEN** 一张已落定但无阻塞等待者消费的矩阵侧审批票超过其回收 TTL
- **THEN** 该票被清扫移除，`GET /health` 的 `pending` 归零，待审批票数不再包含它

#### Scenario: 已决票不无界滞留

- **WHEN** 连续产生多张已决且无 waiter 的票据并经过多个清扫周期
- **THEN** 矩阵侧待审批票数有界，不随票据产生次数单调增长

### Requirement: 批准决策先取凭据后消费

系统 SHALL 在默认异步 `202` 决策闭环中，对命中「已批准」的决策先成功取得凭据（`query_keepass`）再消费该决策表项；若取库失败，SHALL NOT 丢弃批准决策，而 SHALL 保留批准态（或回滚决策）使同一请求重试仍能取回凭据。系统 SHALL NOT 在成功取库之前移除已批准决策。

#### Scenario: 取库失败保留批准态可重试

- **WHEN** 决策表命中已批准，但首次取库失败（如库未解锁/后端瞬时错误）
- **THEN** 该批准态不丢失，同一请求重试时仍按已批准执行取库；取库成功后返回凭据并消费决策

#### Scenario: 取库成功后消费决策

- **WHEN** 决策表命中已批准且取库成功
- **THEN** 返回凭据，且该已批准决策被消费（不再被后续重试复用）

### Requirement: 审计 JSONL 超长仍为合法 JSON

系统 SHALL 保证审计事件 `log_event` 落盘的行为合法 JSON 行：当事件的序列化文本超过摘要截断口径（`AUDIT_SUMMARY_TRUNCATE_CHARS = 4096`）时，系统 SHALL 在序列化前对自由文本字段执行「先脱敏后截断」限长（或对截断行保结构），使落盘行 SHALL 仍可被 `serde_json` 解析，SHALL NOT 从中间切断 JSON 结构产出非法行。超长事件 SHALL 保持零明文（密钥形态经既有 recognizer 掩盖）。整串摘要入口 `sanitize_for_log` 的「先脱敏后截断」次序与 4096 口径 SHALL 保持不变。

#### Scenario: 超长事件仍可解析

- **WHEN** 审计事件序列化后超过 4096 字符并写入审计日志
- **THEN** 落盘行为合法 JSON，`serde_json::from_str` 可解析，字段结构未因截断缺失

#### Scenario: 超长事件零明文

- **WHEN** 超长事件含密钥形态自由文本（如 `sk-` 长串）
- **THEN** 落盘行不含该明文材料，含对应 `[REDACTED:*]` 占位符，且仍为合法 JSON

#### Scenario: 整串摘要口径不回归

- **WHEN** 以整串调用 `sanitize_for_log`（摘要/通知路径）
- **THEN** 输出仍为先脱敏后按 4096 字符截断的结果，次序与口径与既有实现一致
