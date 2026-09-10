## Why

六维深度审查（2026-09-10）维度 6 / 维度 1 确认两处非流审计缺陷：

- **P2-1 非流审计不传白名单（纵深防御不一致）**：流式走 `evaluate_with_whitelist`（`spawn.rs:341/376`），非流 `evaluate_nonstream` 签名不含白名单（`frames.rs:242-249`）内部调 `evaluate`（`frames.rs:256`）。`AUDIT_MODE=approve` + 空白名单时流式降级 block、非流不降级——仅靠启动门禁（`env_parse.rs:307-310` 拒启动）兜底。原仓 `audit_tool_call` 以实例状态持白名单，流/非流同口径；Rust 双入口是原仓不存在的差异。
- **非 2xx 上游 JSON 错误体可被合成 200 阻断体**：`nonstream.rs:143` 对任意状态码 JSON 进全链，`evaluate_nonstream` 命中 `Block` 时 `:181` 恒返回 `200 + nonstream_block_body`，与 README §7.2 声明「非 502/401 错误 JSON 下游状态码与正文保留」冲突（如 400 `truncation:disabled` 体内含危险 tool_call 时被替换为 200 阻断体）。

本 change 统一非流/流式判定入口（白名单同口径）并修正错误状态下的阻断合成边界；不改流式语义、阻断帧形态与 TSS。

## What Changes

- **T1 白名单同口径**：`evaluate_nonstream` 增 `approval_whitelist: &[String]` 参数，内部改调 `evaluate_with_whitelist`；`NonstreamCtx` 增 `approval_whitelist` 字段（构造点 `dispatch.rs:175/227` 传 `state.config.approval_whitelist`）；更新 `block_inject.rs` 测试调用点。
- **T2 单入口收敛**：删除 `evaluate`（`verdict.rs:66`），统一为 `evaluate_with_whitelist`；全量更新调用点与测试（约 28 处，集中在 verdict.rs / block_inject.rs 测试）；空白名单降级语义保留；`verdict.rs:59-65` 双入口注释改写。
- **T3 错误状态不合成阻断体**：审计判定照常执行；仅当上游 2xx（`status_u16 < 300`）且 `Block` 时合成 200 阻断体（现状保持）；错误状态（4xx/5xx，除既有非 JSON 502/401 豁免）`Block` 时**不合成、状态与正文保留**，审计日志与指标记录「错误响应内危险调用」。`NeedApproval` 语义不变（pending 透传）。
- **T4 测试矩阵**：approve 非空白名单 → pending 透传；approve 空白名单直调 → block 降级（注明生产不可达）；block + 2xx → 200 阻断体；block + 400 JSON → 状态保留 + 审计记录；流/非流 verdict 对照 e2e。

## Capabilities

### New Capabilities

- `nonstream-audit-align`：非流审计白名单同口径与错误状态阻断边界的可验证场景。

### Modified Capabilities

- 无。既有 `nonstream-compliance` 的 SHALL 文本不变（B-case pending 透传保持）；「白名单同口径」与「错误状态不合成阻断体」两条边界由本 change 的 `nonstream-audit-align` capability 锁定。

## Non-Goals（显式）

- 不改流式审计、阻断帧形态、TSS 四态、hold 阈值。
- 不改启动门禁（approve 空白名单拒启动保持）。
- 不改 `nonstream_block_body` 协议形态；不改 502/401 非 JSON 豁免。
- 不提交 commit。

## Impact

- **新增文件**：本目录文档；`frames.rs` / `verdict.rs` / `nonstream.rs` / `dispatch.rs` / `block_inject.rs` 及测试更新。
- **影响系统**：非流审计判定入口统一——行为仅两处变化（空白名单直调降级、错误状态不合成阻断体）；流式零变更。
- **顺序**：与 `veil-arch-file-size-closeout` 同触 `nonstream.rs`（及 `block_inject.rs`），建议结构变更先行（S1.8 先合）。
- **依赖**：`cargo test`（含 `http_e2e_approval`/`audit_*`）。
