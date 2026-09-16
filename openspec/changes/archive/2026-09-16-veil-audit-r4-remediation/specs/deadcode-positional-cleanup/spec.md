## MODIFIED Requirements

### Requirement: 生产重复逻辑有界抽取

系统 SHALL 将以下生产重复且语义关键的处理收敛为单一实现并复用：① 还原守卫纯逻辑（`inner_json_intact` 与 `restore_guard_ok`）收敛至零 axum 依赖的 `service::redaction::restore_guard`，供流式 `frame_feed` 与非流路径共用；② `x-veil-*` 内部头剥离收敛为 `llm_gateway::strip_veil_internal_headers`；③ `NORMALIZED_HEADER_NAME`/`NORMALIZED_HEADER_VALUE` 提升为生产 `pub(crate) const` 并替换字面量；④ Chat `[DONE]` 帧统一走 `chat_done_frame()`；⑤ SSE `data:` 帧构造统一走 `sse::data_frame`。

系统 SHALL 追加收敛：⑥ 还原帧发送收敛为单一 `emit_restored_json_frame`（handler 层，恒守卫 + 失败回退占位符帧），残余帧与正常帧共用；⑦ 下游 `x-veil-protocol` 头名提升为生产 `pub(crate) const PROTOCOL_HEADER_NAME`（与 `NORMALIZED_HEADER_NAME` 同址常量区）并替换 `src/handler/llm/dispatch.rs:366`、`src/handler/llm/nonstream.rs:239,509,554`、`src/handler/llm/mod.rs:61` 的字面量；⑧ `src/service/redaction/leaf.rs` 的近同形 helper 对（`prescan_custom`/`prescan_custom_response`、`redact_leaf_inner`/`redact_leaf_response`）以 `bool` 参（或共享私有实现）合并为单一实现；⑨ **文件体量驱动的有界抽取**（`B-2`，`veil-audit-r4-remediation`）：把 Responses 工具类型派生面（`responses_item_tool_name`、`responses_derived_tool_kind` 与 Responses `output[]`/delta 工具收集 helper）迁至 sibling 模块（如 `src/service/llm_gateway/tool_responses.rs`<!-- doc-paths-ignore -->），使其在 A/B 增补后 `src/service/llm_gateway/tool.rs`（当前 788 行）与各触及文件均 ≤800 行。

**文件体量约束（`B-2`）**：本 change 所有源码任务的落点文件 SHALL 在改动后满足 `scripts/check_file_sizes.py` 的 800 行硬上限（计全文件总行）。新增的 `emit_restored_json_frame` SHALL NOT 落在 `src/handler/llm/pump/spawn/event_loop.rs`（当前 753 行，已近上限）——SHALL 置于 sibling/新模块或 `src/handler/llm/pump/spawn/terminal.rs`（当前 343 行，余量充足）。

抽取 SHALL 为行为保持，字节与判定结果 SHALL 不变（请求表 vs 响应表注册语义、`minted` 追踪、仲裁与 `apply_spans` 逐项不变）。**测试内断言文本**（含 `#[cfg(test)] mod tests` 内的 `"data: [DONE]\n\n"` 字面量）与 `hop.rs` 动态项处理 SHALL NOT 纳入本次抽取。canonical `r2 归档勾选更正与保留范围声明` 中「`x-veil-protocol` 内联保留 SHALL NOT 属收敛范围」的旧声明 SHALL 被本要求取代（见相邻 requirement）。

#### Scenario: 还原守卫单一实现

- **WHEN** 检查流式帧路径与非流路径的还原守卫
- **THEN** 两处均调用 `service::redaction::restore_guard` 的共享谓词，无逐字重复实现，判定等价

#### Scenario: 内部头剥离与 DONE 帧单点

- **WHEN** grep `strip_veil_internal_headers` 与 `chat_done_frame`
- **THEN** 各自仅一处定义，全部调用点复用，剥离/信封字节与既有口径等价

#### Scenario: 还原帧发送单一 helper

- **WHEN** 检查残余帧路径与正常帧路径的还原发送点
- **THEN** 均调用 `emit_restored_json_frame`，守卫与失败回退口径一致，无内联直通

#### Scenario: 协议头名常量化

- **WHEN** grep `"x-veil-protocol"` 的生产代码
- **THEN** 仅命中 `PROTOCOL_HEADER_NAME` 常量定义，字面量全部被替换，响应头值不变

#### Scenario: leaf helper 合并行为保持

- **WHEN** 调用合并后的 `prescan_custom`/`redact_leaf_inner` 等价入口
- **THEN** 请求表与响应表注册、凭据还原授权与 PII 双向语义逐项不变，既有 `scope_tests`/`custom/tests` 全绿

#### Scenario: Responses 工具派生面抽取后行数合规

- **WHEN** A/B 增补落地并执行 `python3 scripts/check_file_sizes.py`（或逐文件 `wc -l`）
- **THEN** `src/service/llm_gateway/tool.rs` 抽出的 Responses 派生面已迁至 sibling 模块，`tool.rs` 与新增 sibling 文件均 ≤800 行，门禁 exit 0

#### Scenario: 还原帧 helper 落点不越线

- **WHEN** 检查 `emit_restored_json_frame` 的定义落点
- **THEN** 其不在 `src/handler/llm/pump/spawn/event_loop.rs`（避免 753 行文件越 800 上限），而在 sibling/新模块或 `src/handler/llm/pump/spawn/terminal.rs`（343 行）

### Requirement: r2 归档勾选更正与保留范围声明

本 change SHALL 显式注记：r2 归档变更 `veil-audit-r2-remediation` 的 `tasks.md` §8.4 勾选存在虚高，已在 `veil-audit-r3-remediation` 的 design 覆盖表中更正；归档目录 SHALL NOT 被修改（仅注记，apply 期历史快照非现行契约）。

r2/r3 声明的 `ValidationCache` 内联保留 SHALL NOT 属本 change 范围。`x-veil-protocol` 内联保留的旧声明 SHALL 被**取代**：其头名 SHALL 收敛为 `PROTOCOL_HEADER_NAME` 生产常量并替换全部字面量（与 `x-veil-normalized` 已常量化口径一致），SHALL NOT 继续以「内联保留」为由阻止收敛。该取代仅改声明与常量收敛，**SHALL NOT** 改变线协议头名与头值（改名即 BREAKING，本次不改名）。

#### Scenario: 更正注记存在

- **WHEN** 查阅 r3 design 覆盖表与 canonical `deadcode-positional-cleanup` spec
- **THEN** 含 r2 归档 §8.4 勾选更正的注记，归档目录未被修改

#### Scenario: x-veil-protocol 内联保留被取代

- **WHEN** 核查 `x-veil-protocol` 头名的收敛口径
- **THEN** spec 声明其由 `PROTOCOL_HEADER_NAME` 常量承载、字面量已替换；旧「内联保留」声明不再生效，线协议头名/头值不变

#### Scenario: 保留范围不重开

- **WHEN** 核查本 change 范围
- **THEN** `ValidationCache` 内联保留不在范围内，未被重开
