# Spec Delta

## ADDED Requirements

### Requirement: Responses pending 工具槽终端最终审计（恰一次）

`R7-01`：系统 SHALL 在 Responses 流终端收尾（清除持仓）前，对仍缺 per-item `.done` 的 pending 工具槽（`responses_pending_triples()`，`!done_seen`）执行与 done 槽同 verdict 通道的最终审计评估，门控为 `protocol.is_responses()` 且持仓未置拒绝态；评估顺序 SHALL 为先 done 槽（`hold.tool_triples()` 的 Responses 部分）后 pending 槽。verdict 处置 SHALL 与 done 槽逐字一致：`Block` → 置拒绝态且 `blocked_index` 取**该 triple 自身 `output_index`**（与 done 槽同源）；`NeedApproval` → 建 pending 记录；`Allow` → 无动作。Chat/Anthropic 的 `args_by_index` 终端审计口径 SHALL NOT 改变。本 requirement 与既有「截断未完成 tool 落审计」条款分工互引：后者要求截断时对未完成 tool 产生不含明文的审计/告警记录，本 requirement 补齐 Responses pending 槽走**完整 verdict 通道**（可 `Block`/建单）与恰一次语义，二者 SHALL NOT 视为重复。

恰一次语义 SHALL 由两段协同保证：全局完成臂对 pending 槽审计且未 `Block` 后 SHALL 释放这些已判定槽（移除 `!done_seen` 槽并按其记账字节归还，饱和算术），使终端 pending 循环在**无截断的清理完成**流上自然为 no-op、同一槽 SHALL NOT 被二次审计；**中途截断**（未发全局完成）时 pending 槽保留至终端并恰被审计一次。释放 SHALL NOT 影响 done 槽与 `mark_rejected()`/`mark_completed()` 的既有清理语义。

#### Scenario: 清理完成不双审

- **WHEN** 危险 pending 槽经全局完成臂审计并释放后流正常收尾
- **THEN** 终端 pending 循环为 no-op，该槽恰审计一次（无重复阻断、无重复建单），阻断终端恰一

#### Scenario: 截断 pending 危险槽阻断

- **WHEN** 未发全局完成的截断流中 pending 槽携带危险参数且审计模式非 `Off`
- **THEN** 终端审计命中 `Block`，`blocked_index` 为该槽自身 `output_index`，危险明文不透出，阻断终端恰一

#### Scenario: 截断 pending 需审批建单一次

- **WHEN** 截断流中 pending 槽经终端审计命中 `NeedApproval`
- **THEN** 恰建一条 pending 记录，不重复建单

#### Scenario: 已拒绝不重复审计

- **WHEN** 持仓已置拒绝态
- **THEN** 终端 pending 循环不执行（门控未满足），既有拒绝清理语义不变

#### Scenario: Chat/Anthropic 终端审计不变

- **WHEN** 运行既有 Chat/Anthropic 终端最终审计回归
- **THEN** 口径与结果逐项不变，无新增/删除审计评估

## MODIFIED Requirements

### Requirement: 跨缝掩码 JSON 结构保真

系统 SHALL 保证跨缝掩码（`mask_span_bytes`）不掩码 JSON 结构符（`R7-09`），掩码豁免集 SHALL 覆盖 `{` `}` `"` `[` `]` 及 `,`/`:` 等结构字符（或改 JSON-aware 掩码达同效）；SHALL NOT 因跨缝掩码把结构符替换为 `*` 而导致帧 JSON 不可解析。README §7.9 SHALL 列出完整豁免集（`{` `}` `"` `[` `]` `,` `:`）或将其实质声明为有意保留的结构符超集，SHALL NOT 截断为 `{ } " [ ]` 而遗漏 `,`/`:`（实现指针为 `src/service/redaction/seam.rs::mask_span_bytes`；README 与实现 SHALL 同批修订，SHALL NOT 单侧漂移）。

#### Scenario: 跨缝命中覆盖结构符仍可解析

- **WHEN** 跨缝待掩码区间覆盖 `,`/`:` 等 JSON 结构符
- **THEN** 掩码后帧仍可 `serde_json` 解析，结构符原样保留、仅非结构位掩码

#### Scenario: 常规跨缝掩码语义不变

- **WHEN** 跨缝命中为纯数据区间（不含结构符）
- **THEN** 两侧残片按既有口径掩码，输出与既有跨缝掩码行为一致

#### Scenario: README §7.9 豁免集完整

- **WHEN** 核查 README §7.9 的逐字符豁免集与 `src/service/redaction/seam.rs` 的掩码豁免实现
- **THEN** 文档列出完整豁免集（`{ } " [ ] , :`）或声明为有意保留的结构符超集，零命中遗漏 `,`/`:` 的截断表述
