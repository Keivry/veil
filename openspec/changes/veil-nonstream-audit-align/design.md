## Context

两处非流审计缺陷（P2-1 白名单双入口、错误状态阻断合成越界）。真源：`openspec/specs/nonstream-compliance`（「Non-stream approval aligns with streaming B-case」）与 README §7.2（错误 JSON 状态码与正文保留）。启动门禁 `env_parse.rs:307-310` 已保证 approve 必有非空白名单。

## Goals / Non-Goals

**Goals：** 非流/流式判定同口径（单入口）；错误状态阻断不掩盖上游状态；测试矩阵覆盖四条边界 + 对照。

**Non-Goals：** 不动流式、不动阻断帧、不动门禁、不动 TSS。

## Decisions

### D1：白名单经 ctx 显式注入

决策：`NonstreamCtx` 增 `approval_whitelist: Vec<String>` 字段，构造点传 config；`evaluate_nonstream(..., approval_whitelist: &[String])`。

理由：保持显式依赖注入（与 `StreamPumpCtx.approval_whitelist` 同形态），避免全局态；测试可传空/非空直调。

备选：从 config 全局读取（隐藏依赖、不利测试），不采用。

### D2：删除 `evaluate`，单入口 `evaluate_with_whitelist`

决策：删除 `verdict.rs:66` `evaluate`；所有调用点（生产 + 测试）改用 `evaluate_with_whitelist`。测试统一经 `service::audit::test_whitelist()`（内部 `TEST_WHITELIST` 非空常量）提供白名单；需验证降级的用例显式传 `&[]`。

理由：双入口是本缺陷根因；T1 后 `block_inject` 已改走白名单入口，原注释「删任一都会断调用方」不再成立。

风险：测试机械改动约 28 处；缓解：逐模块 `cargo test` 验证，不改断言语义。

### D3：阻断合成边界 = 2xx

决策：`Block` 合成 200 阻断体仅当 `status_u16 < 300`；错误状态（4xx/5xx）不合成，审计照记（日志 + 指标），状态与正文保留。

指标选择（T3.2）：复用 `audit_blocks` 列，不新增计数。该列语义为「审计判定命中 Block 的次数」，与流式 `record_aux_counts(..., audit_blocked)` 同列同义；错误状态命中虽未替换下游响应（危险调用不构成实际执行），仍属审计命中，计入该列并以 `tracing::warn!(status, protocol)` 记录。备选「新增独立计数」须扩 metrics 表、flush 与查询面，收益不足，不采用。

理由：与 README §7.2 声明一致；错误响应中的危险调用不构成实际执行（上游已失败），合成 200 会掩盖故障并误导下游。

保留：2xx `Block` → 200 阻断体为既有声明行为；`NeedApproval` → pending 透传不变。

备选：错误状态也阻断（掩盖故障）或完全不审计（丢观测）均不采用。

### D4：与文件体量 change 的顺序

决策：本 change 触 `nonstream.rs`/`block_inject.rs`/`frames.rs`/`verdict.rs`；`veil-arch-file-size-closeout` 先迁 `nonstream.rs` 测试至兄弟文件。同窗口时 S1.8 先合，本 change 逻辑改动后随。

## Risks / Trade-offs

- T2 删除 `evaluate` 触及大量测试：机械替换 + 保留断言；风险为误改语义，缓解为逐模块执行与 diff 复核。
- T3 改变错误状态下的下游可见行为（不再 200 阻断体）：属修正而非破坏，README 已有声明背书；e2e 锁定。
