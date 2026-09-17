# Design

## Context

见 `proposal.md` → Why。影响本设计的既有约束：

- R6 审计的运行时行为变更仅 1 项（上游同名多值响应头逐值透传）；其余为文档/规范（README + canonical spec）收敛，零行为变更。
- canonical `docs-contract-sync`「文档行号引用可校验」明确 `scripts/check_doc_paths.py` 的职责边界为「路径存在性 + 行号在界」，被引行内容与文档语义的一致性由 code review 保证；该 capability 同时规定「内容可能漂移的行号锚点 SHALL 改用符号锚点」。
- canonical specs 为真相源，只能经 change 的 delta 修改（本 change 6 个 delta）。
- `http::response::Builder::header` 在 `http` crate 1.5.0 中调用 `head.headers.try_append(...)`（`response.rs` 的 `Builder::header` 实现），即 **append 语义**。

## Goals / Non-Goals

**Goals:**

- 消除 R6 的 6 项审计发现（AUDIT-01…06），使 README/canonical spec 与实现重新一致。
- 7 处漂移锚点符号化，抗后续重构漂移。
- 上游同名多值响应头逐值透传，并补齐回归覆盖。

**Non-Goals:**

- 不扩展 `scripts/check_doc_paths.py` 做锚点语义校验（见 D1）。
- 不给 SSE 成功响应新增 `x-veil-protocol`（见 D3）。
- 不复活 `Speed::Fast` 标点分支、不改 `agg` 切分（见 D4）。
- 不重审 R5 已裁决项（D1–D15）、不引入任何其他 wire/配置变更。

## Decisions

### D1 锚点策略：符号锚点优先（选项 A）

- **选项 A（采纳）**：7 处漂移锚点改为符号锚点（`文件::符号`），如 `src/handler/llm/nonstream.rs::oversize_response`、`src/error.rs::VeilError::status_code`、`src/service/credential/vault_ops.rs::emergency_revoke`、`src/service/llm_gateway/mod.rs::classify_empty`。
- **选项 B（拒绝，作为 A 的补充）**：仅校正行号——下轮大改会再次漂移，且违反 canonical「符号锚点优先」口径。
- **选项 C（Oracle 推荐，本轮拒绝并登记为后续 change）**：扩展 `scripts/check_doc_paths.py` 校验「行号—内容」语义一致性。**冲突点**：canonical `docs-contract-sync`「文档行号引用可校验」明确脚本职责边界为「路径存在性 + 行号在界」，并规定语义一致由 code review 保证；采纳 C 需先修订该 canonical 要求（属策略变更，非本轮审计修复范围）。故本轮采纳 A 并把 C 登记为后续 change。

### D2 多值响应头：克隆端 `insert → append`（选项 A）

- **选项 A（采纳）**：`src/handler/llm/nonstream.rs::clone_upstream_headers` 与 `src/handler/llm/dispatch.rs::stream_upstream_passthrough` 两处克隆循环由 `HeaderMap::insert` 改 `HeaderMap::append`，并各补一条多值回归测试。
- **选项 B（拒绝）**：显式声明「响应头折叠为末值」——保真缺口需下游知悉，且与「透传」语义不符。
- **关键修正**：装配端（`for (k,v) in resp_headers.iter() { builder.header(k,v) }`）**无需改动**——`Builder::header` 为 append 语义（`http` crate 1.5.0 的 `response.rs` 内 `try_append`）。审计探索代理曾主张装配端为 insert 语义，经 crate 源码核实为误判；以源码为准。
- **安全性**：`strip_veil_internal_headers` 与 `filter_hop_headers_counted` 均按去重键 `remove`，不依赖单值；网关自置头（`with_protocol_header`）继续用 `insert` 覆盖同名上游头，语义不变。

### D3 `x-veil-protocol` 范围：收窄注释措辞（选项 A）

- **选项 A（采纳）**：仅收窄 `src/handler/llm/mod.rs:61` 注释为「非流对话路径 + 流式错误透传路径」。
- **选项 B（拒绝）**：给 SSE 成功臂新增该头——新增 wire 行为，需同步更多 spec 与测试，超出审计修复范围。
- **事实核查**：README 仅两处提及 `x-veil-protocol`（均在 §7.2：`README.md:741` 状态码透传段与 `:751` 内部头隔离段），**均无「统一/全部路径」措辞**；过宽表述仅存在于源码注释。故 README 无重复修复项（proposal 中「README 措辞」以核查结论为准）。

### D4 `Speed::Fast` 标点：文档对齐现实（选项 A）

- **选项 A（采纳）**：`llm-gateway` spec 与 README §7.2 改述为「实际边界为 `FAST_EMIT_THRESHOLD_BYTES`（4096 字节）；`agg` 恒以 `\n\n` 结尾，标点分支生产不可达；`is_punct_boundary` 保留为 API」。
- **选项 B（拒绝）**：实现「去尾部换行后再判标点」使标点可达——改变下游发送节奏（帧数/首字节延迟），与 `STP-6` 攒批裁决冲突，需重测且有回退风险。

## Risks / Trade-offs

- [上游返回非法重复 `content-length` 时 `append` 会保留两条] → 上游协议违规场景；HOP/解码过滤按去重键处理，错误状态透传本就要求字节保真；可接受，且在回归测试中只断言合法多值头（`Set-Cookie`/`warning`）。
- [符号锚点在文件重命名后失效] → `check_doc_paths.py` 仍校验 `src/...rs` 路径存在性，会 FAIL 而非静默通过，可接受。
- [D1 与 Oracle 推荐（选项 C）不一致] → 已在 D1 记录冲突依据（canonical 边界）；phase-3 Oracle 复审可复核，如有异议按复审结论修订。
- [Fast 措辞调整可能被误读为行为变更] → 规范与 README 明确声明「零行为变更、`is_punct_boundary` 与既有单测不变」。
- [`docs-contract-sync` delta 同时改动「测试口径标签」与「错误码正面档」两条 requirement 全文] → MODIFIED 要求复制全文，已逐条比对原 requirement + 全部 scenario，未丢信息。

## Migration Plan

- 无配置/数据/wire 迁移；推送后无需运维动作（多值头透传为保真修正，非 BREAKING：原折叠行为从未声明）。
- 回滚：`git revert` 单提交即可（无 schema 变更、无持久化影响）。

## Open Questions

- 是否在后续 change 采纳 D1 的选项 C（`check_doc_paths.py` 锚点语义校验）——需先修订 canonical `docs-contract-sync`「文档行号引用可校验」的职责边界；本 change 明确不作为，登记为后续候选。
- canonical `docs-contract-sync`「README 源码定位指针与实现一致」正文保留 R5 历史漂移叙述字面量 `src/handler/llm/dispatch.rs:150`（README 已无该指针）——属 R5 既有登记、非本轮范围，本 change 不改该 requirement。
