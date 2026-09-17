# Spec Delta

## MODIFIED Requirements

### Requirement: WHATWG 缓冲与 slow / fast 双速

流式转发 SHALL 使用 WHATWG 缓冲语义；网关 SHALL 提供两种下游发送语义（`src/service/sse/emit.rs::select_emit`）：`Speed::Slow` 见文即吐（聚合缓冲非空即整段返回），`Speed::Fast` 攒至 `FAST_EMIT_THRESHOLD_BYTES`（4096 字节）阈值再返回。`is_punct_boundary` SHALL 保留为既有 API，但下游 SSE 聚合缓冲（`agg`）恒以帧终止 `\n\n` 结尾，故生产调用点（`src/handler/llm/pump/spawn/event_loop.rs` 对 `state.agg` 的 `select_emit`）标点分支不可达——`Speed::Fast` 的实际生效边界为 4096 字节阈值（`R6-06`）；本要求 SHALL NOT 声称标点在聚合路径可达，SHALL NOT 为此改动 `agg` 切分（保留 `STP-6` 攒批裁决，避免回退逐帧即吐）。二者 SHALL 由 `audit_mode` 派生（`src/handler/llm/pump/spawn/setup.rs`：`AuditMode::Off` → `Speed::Fast`，其余 → `Speed::Slow`），MUST NOT 作为独立配置项暴露。SHALL NOT 声称 `Fast` 服务脱敏完整性——`Fast` 用于审计关闭（无 hold 需求）的低帧数路径，`Slow` 为审计开启时的即时转发路径。

#### Scenario: slow 档低延迟

- **WHEN** `audit_mode` 非 Off（审计开启）
- **THEN** 派生 `Speed::Slow`，聚合缓冲非空即转发（见文即吐），延迟最低

#### Scenario: fast 档聚合转发

- **WHEN** `audit_mode` 为 Off（审计关闭）
- **THEN** 派生 `Speed::Fast`，聚合缓冲达到 `FAST_EMIT_THRESHOLD_BYTES`（4096 字节）阈值时转发，帧内容不变

#### Scenario: 标点分支生产不可达且已声明

- **WHEN** 核查 `Speed::Fast` 的标点边界在生产路径的可达性
- **THEN** 文档与规范一致声明「`agg` 恒以 `\n\n` 结尾，标点分支不可达，实际边界为 4096 字节阈值」；`is_punct_boundary` 单测仍以裸串覆盖其语义，且未以 `agg` 切分改动回退 `STP-6`
