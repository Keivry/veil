## 1. 非流后处理完整性（H1/C5/C6/C7）

- [x] 1.1 502/401 走完整后处理：`nonstream.rs:110-114` 改为记录 usage + 审计判定 + 还原链路（还原失败回退原文），补 502/401 还原回归单测
- [x] 1.2 非流 JSON 破裂回退：`nonstream.rs:183-188` 还原后双 `_jloads` 校验，失败回退上游原文并 warn，补破裂 JSON 单测
- [x] 1.3 非流残缺剥离：补 `strip_partials`（凭据 `__VG_CRED_` + PII `__PII_` 残缺前缀），补残缺透出回归单测
- [x] 1.4 非流 approve 对齐：`block_inject.rs:269-290` `NeedApproval` 改为 pending+透传（仅 `deny` 阻断），补 approve 非流单测

## 2. index 优先级统一（H2）

- [x] 2.1 `tool.rs:185-191` 改外层优先，与 `pump.rs:832,844` 一致；`pump.rs:367 clear_index` 按统一槽位
- [x] 2.2 抽取共享分桶函数（`tool.rs` 唯一实现，pump 复用），删除双实现
- [x] 2.3 补交错 index 冲突回归单测（outer 0/1 + inner 3/5 流/非流同槽断言）

## 3. 截断残缺丢弃 TSS-03（H3）

- [x] 3.1 tool 分片 hold-until-complete：未 `done` 分片截断即丢弃不转发，记 `truncated_tool_dropped` 计数
- [x] 3.2 `_synthesize_truncation` 覆盖 chat/anthropic 残缺丢弃路径（与 C8 空流合成联动验证）
- [x] 3.3 补 TSS-03 截断 E2E（残缺 tool 不到下游断言）

## 4. 泵入口钳位（H4）+ NonDialog 决策（F1）

- [x] 4.1 `pump.rs:74-98` 钳位 `pii_boundary_chars/hold_max`（0→默认+warn，超 8MB→截断+warn），补非法值单测
- [x] 4.2 NonDialog 臂补 `nondialog_passthrough` 计数 + README 声明透传语义（流量验证后若需还原另立任务）
- [x] 4.3 全量门禁：`cargo fmt --check` + `clippy --tests -- -D warnings` + `cargo test` 全绿
