## Context

维度 5 汇编（15 组）+ D7 未闭环项。审查口径：全仓 grep 引用计数（src + tests），仅测试引用即视为可清理；有生产引用者列入附录不动。

## Goals / Non-Goals

**Goals：** 零生产零引用符号清零；`resolve_upstream` 确定性以测试锁定；`ENV` 回环免 token 以 BREAKING 声明闭合。

**Non-Goals：** 不动有用符号、不动 proto/审计语义（他 change 负责）、不实现回环免 token。

## Decisions

### D1：删除 vs `#[cfg(test)]` 收编的判定

决策：以「测试是否仍验证独有语义」分派：

- **直接删**：`contains_token`、`global`、`has_chat_terminal`、`should_discard_after_terminal`、`reject_new_dangerous_during_hold`、`AUDIT_TIMEOUT_SECS`（测试未验证独有语义，相关断言删除或改断言生产行为）。
- **删除并改测**：`snapshot` + `VaultSnapshot`、`redact`——若「只读快照透传/版本稳定」语义已由生产等价路径（`snapshot_p2t` + `redact_with_map`）覆盖，则删类型、测试改走生产路径；否则 `#[cfg(test)]` 收编并注释「测试专用快照语义」。
- **`#[cfg(test)]` 收编**：leaf 三辅助（生产走 `Config`；注意 `Config` 同名方法勿误伤）。

理由：消除误导性 API 面，同时不损失有意义的测试覆盖。

### D2：`classify_empty` 收敛

决策：删 `StreamInjectThen502` 变体、`is_stream` 参数与分支；`empty_body_502_four_branches` 测试改为三分支并更名；注释指向 `should_synthesize_empty_stream`（流式空流唯一策略）。

理由：生产不可达的双策略并存易误用。

### D3：`resolve_upstream` 确定性

决策：无默认上游时按端口升序取首个并 warn；补测试锁定。README §2「取首个」语义随之确定。

备选：报错拒绝启动（对既有单端口部署不兼容），不采用。

### D4：D7 选择 BREAKING 声明而非实现

决策：`ENV=dev`/`ALLOW_LOOPBACK_NO_TOKEN` 不实现；README §6.6 声明「回环免 token 未迁移」+ §7.4 表行；§6 首句「五处」→「六处」。

理由：回环免 token 为 dev-only 逃生口，生产不建议；`veil-full-parity-fix` spec 允许「恢复或声明」二选一。

备选：实现回环免 token（扩大攻击面），不采用。

## Risks / Trade-offs

- D1 删除测试可能减少断言总数：允许（清理的是无效断言），但测试函数总数应尽量守恒；tasks 要求记录增减并逐条说明。
- D3 改变多端口缺省行为：属修正，warn 便于迁移。
- D4 是「声明」而非「实现」：若后续确有 dev 回环需求，另立 change 实现并撤回 BREAKING。

## 附录：已评估无需动作（本轮审查结论，全部登记）

- `audit_hold.rs` 纯重导出垫片（有意保留兼容路径）。
- `rewrite.rs:175-189` 死代码申报已核实为**误报**（位于 `#[cfg(test)]` 测试模块内，生产段 L1-105 自洽），无动作。
- 审批三文件职责正交（`approval.rs` / `credential/approval.rs` / `matrix/approval.rs`，H3.1 已裁定非垫片）。
- Content-Type 不参与协议分发（对齐原仓 tail-only，非缺陷）。
- Chat 流式 usage 仅顶层（符合官方 `include_usage` 末帧语义）。
- Responses `error` → `response.failed` 统一（声明行为；测试锁定见 `veil-llm-proto-closeout` B4）。
- 凭据占位符门控 `\d{6,}` 窄于 vault `\d{4,}`（有意保守；文档口径见 B7）。
- 非流 `req_conv` 提取口径（非 JSON 双 None；注入不改 id，语义等价）。
- Go F3 三项（存量直连/三因子两场景/阻断终止）仍由 `veil-hardening` 5.1-5.3 承接（未闭环登记，不在本批 change 范围）。
- conformance 口径差异（原仓 pytest 12 例 vs Rust `scripts/api_conformance.py` 20 例）已在 `veil-review-followup-test-gap`（T-M9）注明，保持既有声明。
- README §8 既有遗留（NonDialog F1、调试落盘 F2、入口与审批语义 F4、测试口径 T-M7/T-M9）保持。

### 附录补充：D1.9 测试函数数量增减登记

计数口径：`grep -rn '#\[test\]\|#\[tokio::test\]' src/ tests/`。D1 实施前后：**736 → 735（净 −1）**，逐条说明：

- `hold.rs::new_dangerous_calls_rejected_during_hold` **删除（−1）**：仅回显预留函数自身返回值，未验证生产独有语义（注释已声明「流泵未接线」）。
- `credential_vault.rs::snapshot_readonly_passthrough_with_stable_version` **更名并改走生产等价路径（±0）**：改为 `snapshot_maps_and_redact_with_map_reflect_registrations`（`snapshot_p2t`/`snapshot_t2p` + `redact_with_map`/`restore`），覆盖不变。
- 其余均为既有测试内断言裁剪（`has_chat_terminal`/`should_discard_after_terminal`/`AUDIT_TIMEOUT_SECS` 断言），函数数量不变。
