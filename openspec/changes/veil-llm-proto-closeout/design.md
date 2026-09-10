## Context

三协议网关面 4 项偏差/风险与 4 项待锁定；真源为 `openspec/specs/stream-protocol-parity`、`nonstream-compliance` 与三协议官方规范。决策依据：用户选定 P1-1 选项 (b)（收窄为仅 Chat），其余按审查报告建议处理。

## Goals / Non-Goals

**Goals：** Responses 不再收到规范外 `stream_options.include_usage`；空流差异有测试与书面声明；Chat 缺 `[DONE]` 场景可观测；四项待锁定项有测试或文档口径。

**Non-Goals：** 不动 TSS、阻断帧、审计 verdict、PII。

## Decisions

### D1（B1）：收窄为仅 Chat + 回退条款（R1）

决策：`should_inject_stream_options` 匹配仅 `Protocol::Chat`；Responses 不注入。Responses 流式用量经 `response.completed` 携带，`extract_usage_stream`（`usage.rs:177-191`）三级回退已闭环（F-P1a）。

理由：官方 Responses `stream_options` 仅 `include_obfuscation`；消除规范外字段；保留 Chat 用量采集。

**R1 回退条款**：若 apply 后实测真上游（muse-spark / zen/go）Responses 用量缺失回归，则恢复注入并转为「选项 (a) 文档声明」路线（README §7.2 明示依赖上游宽容），以回归对比数据为准。

**apply 结论（2026-09-10）**：本地 mock/e2e 验证通过——单测 `responses_usage_recorded_from_completed_without_injection` 证明 Responses 不注入仍自 `response.completed.response.usage` 记录用量（12/45/57）；`cargo test` 全绿、`scripts/api_conformance.py` 三协议 SDK 全绿。真上游（muse-spark / zen-go）用量对照因本环境不可达，**延后至部署环境执行**；R1 回退条款保持待命（未触发）。

备选：维持现状 + 文档声明（用户未选）；按上游配置化注入（复杂化，不采用）。

### D2（B2）：空流保持 open-ended + 声明与证据

决策：不改行为（`stream-protocol-parity` 已定调「no fabricated success termination」），补：Anthropic 单测、三协议 e2e 对照、README §8.6 声明；Hermes stub 证据复核分级处置——①证实存在→保持 open-ended 并登记证据；②无法证实→§8.6 标注「待人工确认」open item（owner：下游集成）并触发后续 change 评估「补终止帧」路线（修订 spec 后实施）。

理由：spec 为先；「确认再决」优于「猜测改行为」；同时保留审查建议中的补帧升级通道，不擅自越 spec 实施。

备选：立即补 chat/anthropic 终止帧（违背现 spec），不采用；保留升级通道（证据不足 → 后续 change 修订 spec）。

### D3（B3）：无 DONE 可观测而非合成

决策：Chat 通道记录 `finish_reason` 非 null（soft-terminal 信号）；流末 `!terminal_sent && saw_finish_reason` 时 `set_truncated(OpenEnded)` + warn + 指标；**不合成 `[DONE]`**。

理由：合成终端破坏「no fabricated termination」原则；可观测标记即可定位上游异常与下游空等风险。

### D4（B4/B5/B6/B7）：锁定项处置

- **B4**：行为不变（已声明），补测试 + 字面复核。
- **B5**：先核验，不一致则最小修复（原则：审计恰一次、槽清理幂等）。
- **B6**：行为不变，补断序容忍单测 + README 口径句（透传优先，不丢帧）。
- **B7**：行为不变（注释已声明有意保守），补 README 口径句 + 核验既有测试。

### D5（B5）：`message_delta` 双角色核验结论——一致，无需修复

核验：`message_delta` 仅承担**粘滞终止**角色（`src/handler/llm/pump/event.rs:66`，用于 reject 后的丢弃路径）；**按槽清理**由 `content_block_stop`/`item_done` 驱动（`src/service/audit/hold.rs:239-244` `is_index_complete_event` + `:248-252` `clear_index`），`message_delta` 有意既非全局完成事件也非按槽完成事件（`hold.rs:188-235`）。两角色正交、不重叠，审计恒恰一次、无重复清理。审查报告「`message_delta` 参与按槽清理」的表述与代码不符，属待锁定项订正，**不适用修复**。回归由 `message_delta_after_slot_stop_does_not_duplicate_audit`（hold 层）与 `anthropic_tool_use_stop_plus_message_delta_audits_once`（泵 e2e）锁定。

## Risks / Trade-offs

- **B1**：若上游（无规范依据地）依赖请求携带 `include_usage` 才回传 usage，将出现用量缺失；R1 给出回退路径，sentinel/conformance 回归覆盖。缓解：apply 时对真上游做一次用量对照（tasks B1.5）。
- **B2**：若下游 Hermes 无 stub 保护，空流将表现为客户端错误；§8.6 的 open item 与证据清单是唯一出口，需人工确认闭环。
- **B3**：仅可观测，下游行为不变；避免为缓解「无 DONE」而伪造终端。
