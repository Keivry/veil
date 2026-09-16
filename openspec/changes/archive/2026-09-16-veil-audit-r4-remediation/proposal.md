## Why

本 change 承载 2026-09-16 第四轮独立七维只读审查（r4）的修复规划：对上一批已归档变更 `veil-audit-r3-remediation`（基线 `25a9f7d`，15 本地提交）做只读复审后，登记 **P2×4、P3×8、架构×1** 及一批定性/证伪结论，覆盖审计对称性、内置工具覆盖、非对话秘密上行、出口/解析保真、死代码冗余、文档缺口、观测口径七个方向，并新增 **N（四态截断指标白名单收口）**——该项系 Momus 复审发现的 spec↔code 活矛盾（canonical 已锁四态，代码仅三态白名单）。

审查基线门禁全绿（`bash scripts/gate.sh` 七步 exit 0：fmt / clippy `-D warnings` / 1371 tests / doc-paths / file-sizes / conformance（24 项真 SDK 口径，见下「待核对」）/ go vet+test），故这些均为现有门禁未捕获的**二阶缺陷**：**审计不对称绕过（非流 `output[]` 漏审内置工具，与流式结论相反）、`computer_call` 全路径未覆盖、`count_tokens` 携带对话负载却零脱敏字节透传、残余帧缺守卫回退、CR 载荷出口/解析不对称、四态截断指标白名单仅三态（`upstream_error` 被误判非法）、注释/文档过度声明、`PENDING_EVENTS` 溢出错标**——而非已知失败回归。

本 change 的规划口径**不重开**已归档 r3 的有意偏离；仅对经 Oracle 裁断或 Momus 复审确认的残余缺陷给出最小正确性收敛方案。**本 change 为 artifacts-only（规划），apply 期才落源码**。

## What Changes

### 一、Responses 内置工具审计对称性（`A`/`B`/`G`）

- **A（P2）非流 `/v1/responses` `output[]` 漏审内置工具**：`src/service/llm_gateway/tool.rs:647-659` 的 `is_tool` 未调用 `responses_item_tool_name`（`:219-231`），导致 `code_interpreter_call`（字段 `code`）与 `shell_call`（字段 `action.command`）被 `continue` 跳过；流式 `response.output_item.done`（`:542-552`）与 `*.delta`（`:202-214`）已覆盖 → **审计不对称绕过**。修复机制（M-1 精确化）：仅放宽 `is_tool` **不够**——`output[]` 既有分支经 `custom_obj_to_call`（`tool.rs:176-198`）走 `custom_tool_parts`，而内置条目无 `name`/`arguments`/`input`，结果 `name=None` 且 args 空。故：① `is_tool` 增补 `responses_item_tool_name(item_type).is_some()`；② 非 function/non-custom 的内置条目经**派生名路径**（与既有检索 early-return `:662-683` 同形）建条目，名由 `responses_item_tool_name` 派生、参按 item-done 路径同口径回退（`["arguments","code","command","input"]` → `retrieval_args` → `item.action` 序列化，`:572-581`）；③ 补非流 `output[]` 单测（断言派生的**非空名 + 非空 args**）+ 流/非流同结论 parity 测试。测试盲区：`src/service/llm_gateway/tool/tests.rs:61-101` 的 `item_done_type_coverage` 只覆盖 `response.output_item.done`，须补 `output[]` 全量体用例。
- **A/B（B-2）`tool.rs` 文件体量**：`src/service/llm_gateway/tool.rs` 现 **788 行**（`check_file_sizes.py` 硬上限 800），A/B 增补生产码会越线 → 须先把 Responses 工具类型派生面（`responses_item_tool_name`、`responses_derived_tool_kind` 与 Responses `output[]`/delta 工具收集 helper）抽至 sibling 模块（如 `src/service/llm_gateway/tool_responses.rs`<!-- doc-paths-ignore -->），使改动后各文件 ≤800 行。
- **B（P2）`computer_call`（computer use）覆盖**：`responses_item_tool_name`（`:219-231`）与 `responses_derived_tool_kind`（`:202-214`）均无 computer 分支。决策（Oracle）：**覆盖 computer**，用 `contains("computer")` 兼容 `computer_call`/`computer_call_output`/`computer_use_preview`，参数取 `action`；`responses_derived_tool_kind` 的 computer 分支为**防御性（DEFENSIVE）覆盖**（全仓 `grep computer src/` 零命中，无现行上游 delta 样本）；并声明 `image_generation_call`（大 payload / 无可执行参数）为**非目标**。
- **`local_shell_call` 覆盖现状（精确口径，MINOR 1）**：`contains("shell")` 仅存在于 `responses_item_tool_name`（`tool.rs:222`），今日仅覆盖 `response.output_item.done` 路径；非流 `output[]` 的 `is_tool`（`:650-656`）**在 A 落地前无 shell 分支**；`responses_derived_tool_kind`（`:205-206`）仅匹配 delta 事件子串 `shell_call_command`（不匹配 item 类型）。
- **G（P3）注释过度声明**：`src/service/llm_gateway/tool.rs:216-218` 声称 item-done 路径与「非流路径同结论」，实际非流路径未用该函数（见 A）→ 随 A 修正注释（验收以 A 的 parity 行为测试为准，注释变更仅为 code-review 项，见 M-5）。

### 二、Anthropic `count_tokens` 秘密上行（`C`）

- **C（P2）`/v1/messages/count_tokens` 与 `/v1/messages/batches` 被判 NonDialog**（`src/service/llm_gateway/protocol.rs:81-94,112-114`）→ 字节透传、零脱敏；`count_tokens` 携带与正式 messages 相同的 `messages`/`system`/`tools` 负载 → **秘密明文上行**。决策（Oracle）：**`count_tokens` 改为 redact-only 对话变体**——执行请求侧脱敏 + 占位符说明注入门控，**跳过**审计判定、响应侧还原与新 PII 扫描、阻断合成、用量记账；**仍保留** hop 过滤与有界读。**`batches` 声明为例外（非目标）** 并写明理由与后续 change 指向。
- **观测计数（M-2 降级为「登记现状、不新增维度」）**：既有 `nondialog_passthrough` 为**无参单原子**计数（`src/service/llm_gateway/metrics.rs:98,149-157`），**SHALL NOT** 改为按端点的键控计数器、**SHALL NOT** 新增导出指标族。`count_tokens` 收窄后不计该计数；`batches` 与其他 NonDialog 端点继续计数。要求「新增按端点的 NonDialog 透传观测计数」**撤销**（不可实现且无必要）。

### 三、流式出口与解析保真（`D`/`E`/`K`/`M`）

- **D（P3）残余帧还原缺守卫回退**：`src/handler/llm/pump/spawn/terminal.rs:207-228` 仅 `restore_response_with_spans_json` + `redact_response_new_pii_with_skip` 后直接 `feed_output_frame`，未调用 `guard_restored_frame_parsed`（正常帧在 `src/handler/llm/pump/spawn/event_loop.rs:626,643-648` 有守卫且失败回退占位符帧）。修复：抽单一 `emit_restored_json_frame(...)`（内部恒守卫 + 失败回退），残余帧与正常帧共用。**落点约束（B-2）**：`event_loop.rs` 现 **753 行**，该 helper **SHALL NOT** 落在 `event_loop.rs`，应置于 sibling/新模块或 `terminal.rs`（343 行）。
- **E（P3）`data_frame` 只按 `\n` 拆分，而解析侧把裸 `\r` 当行终止**（`src/service/sse/emit.rs:9-24` vs `src/service/sse/parser.rs:207-226,327`）；`emit.rs:9-13` 注释「严格互逆」为**过度声明**。修复（B-3 可达化）：`data_frame` 按行终止集合（`\n`/`\r\n`/`\r`）拆分，**SHALL NOT** 把裸 CR 留在单条 `data:` 行内；解析侧以单 `\n` 连接（`parser.rs:327`）为**已锁定**行为，故含裸 CR 载荷声明为 **LF 归一**（**移除「逐字节一致（含 `\r\n`）」的不可达断言**）；修正注释；补回归测试（裸 CR 载荷 → 已声明 LF 归一值、恰一事件、无 `event:` 名错配），并纳入既有往返测试 `src/service/sse/cr_tests.rs:73`。
- **M（P3，Oracle Q4）`PENDING_EVENTS_MAX=8` 溢出当前「丢最旧」**（`src/service/sse/parser.rs:341-369`）会保留部分 pending 造成后续 data 帧 `event:` 名错配 → 决策改为**溢出清空整队 + 记录观测计数/告警**（fail-safe：宁缺信封不错标）；补单测（9 个纯 event 块后 data 帧无 event 标签 + 计数递增）。安全影响为 P3（终端/opaque/审计判定读 JSON 内 `type`，不读 `event` 行）。
- **K（架构）本 change 仅做最小正确性收敛**：统一 `emit_restored_json_frame`（D）+ 协议往返不变量测试（CR 载荷、纯 event 洪泛、redact↔restore 组合、opaque 帧字节恒等）；**完整 `StreamTerminator` 收敛（阻断/终止帧注入去重）登记为后续独立 change，非本 change 范围**。

### 四、Anthropic 扩展思考连续性（`H`）

- **H（P3）`thinking_delta` 文本被还原为明文，而 `signature`（opaque，不还原）是对占位符文本签名**；请求级随机 token 使下一轮重脱敏字节不同 → 签名校验/思考连续性断。决策：本 change **仅登记为已知限制**并**按 requirement 名**写明条件性缓解依赖 `veil-pii-conversation-cache` 的 requirement「Anthropic thinking 签名连续性（条件性收益与残余限制）」（该 requirement 明示会话级稳定 token 为**必要条件而非充分条件**）；**MUST NOT** 承诺网关校验上游签名或无条件连续（MINOR 9）。

### 五、死代码/冗余与注释（`F`/`I`）

- **I（P3）`x-veil-protocol` 仍为字面量**（`src/handler/llm/dispatch.rs:366`、`src/handler/llm/nonstream.rs:239,509,554`、`src/handler/llm/mod.rs:61`）而 `x-veil-normalized` 已常量化（`src/service/redaction/leaf.rs:23,25`）→ 补 `PROTOCOL_HEADER_NAME` 常量并替换（**重新打开** r3 声明的「`x-veil-protocol` 内联保留」）。
- **I（P3）近同形 helper 对合并**：`src/service/redaction/leaf.rs:59`（`prescan_custom`）vs `:79`（`prescan_custom_response`）、`:132`（`redact_leaf_inner`）vs `:193`（`redact_leaf_response`）以 `bool` 参合并。
- **I（澄清）`data: [DONE]\n\n` 字面量**：`src/service/block_inject.rs:35,48-49,152-153` 均在 `#[cfg(test)] mod tests`（:21 起）；生产已统一走 `chat_done_frame()`（`src/service/block_inject/frames.rs:303`；调用点 `src/handler/llm/pump/spawn/event_loop.rs:742`、`src/handler/llm/pump/synth_flush.rs:93`）→ 按 canonical `deadcode-positional-cleanup` 的「测试内断言文本 SHALL NOT 纳入抽取」登记，**不改生产源码**（可选测试字面量收敛）。
- **F（P3）注释与实际变体数不符**：`src/service/sse/meta.rs:3` 注释写「TruncatedMode 三态」，实际 4 变体（`src/service/sse/meta.rs:10-17`）；同一陈旧「三态」注释亦见 `src/service/metrics/aggregate.rs:30`（**F 扩域**，B-1 同批）→ 改注释并登记。**验收为行为性**（四态白名单落点测试，见 M-5/§八），注释变更仅为 code-review 项。

### 六、文档缺口（`J`）

- **J（P3）README 缺 `E_EMPTY_BODY` 正面档**（现仅 `README.md:669` 否定式提及；代码 `src/error.rs:86-97`，触发于非流 200 空体/非 JSON → 502，见 `src/handler/llm/nonstream.rs` + `src/handler/llm/dispatch.rs:150`）→ 补正面说明。README §4 表（`README.md:253`）称「502 + `response_too_large` JSON 体」，**并未**声称字段名为 `error.code`（M-4）→ 将该行「补 `error.type` 字段名以对齐 `src/handler/llm/nonstream.rs:566`」降级为**可选（SHOULD）措辞对齐**，**移除「纠正错误表述」框架**（本 change 不得自身引入过度声明）。归档 r3 `tasks.md` 的 `file:line` 锚点系统性漂移 10~100 行且 4.4 指向错文件（实际 `src/service/pii/detector.rs:498`，声称 `src/service/pii/custom.rs:395-396`；`custom.rs` 对应位置现为请求侧脱敏扫描签名，`Arc::clone` 在 `:401`，MINOR 2）→ 在本 change 的 design 中登记「归档锚点不回改」口径（`scripts/check_doc_paths.py` 已对 `openspec/changes/archive/**` 整体豁免行号在界断言，:67/:71-72）；`scripts/README.md` 与脚本口径一致，无需改动。

### 七、定性结论（`L`，逐项已在 design.md 写明）

- 非流 `String::from_utf8_lossy`（`src/handler/llm/nonstream.rs:257`）非字节保真 → 仅文档化（守卫 + 回退已兜底）；
- 流式错误体透传不设上限 vs 非流有界（`src/handler/llm/dispatch.rs:369-372`；注意 `Body::from_stream` 惰性、**非**内存无界）→ 文档化为**有意策略差异**；
- Chat `stream_options` 畸形态整体替换为 `{"include_usage":true}` + warn（`src/service/llm_gateway/protocol.rs:194-197`）→ 维持现状（`README.md:605-608` 已声明，核对一致性即可）；
- 非流 `restore_guard_ok(..., None)` 二次解析（`src/handler/llm/nonstream.rs:272`）→ 仅性能、不改（正确性无缺口，`src/service/redaction/restore_guard.rs:20-26` 在 `None` 时内部解析并执行 `inner_json_intact`）。

### 八、四态截断指标白名单收口（`N`，B-1；`llm-gateway`/`observability-admin`）

- **N（P2）四态截断白名单 live spec↔code 矛盾**：r3 已把第 4 态 `TruncatedMode::UpstreamError`（`src/service/sse/meta.rs:16`，经 `src/service/sse/meta.rs:47` 的 `m.record_truncated(mode.as_str())` 记录）落地，但**至少六处**仍用三态白名单：(a) `src/service/llm_gateway/metrics.rs:54-55` `TRUNCATED_MODE_KEYS: [&str; 3]` → `upstream_error` 落 `other` 桶 + 每进程一次伪 warn（`metrics.rs:26-41`）；(b) `src/service/metrics/store.rs:109-116` 丢 `upstream_error` 并记伪「非法值」warn；(c) `src/service/metrics/aggregate.rs:30-31` 注释「唯一三态」+ `TRUNCATED_MODES: [&str; 3]`、`WindowAgg` 字段 `:175-177`、快照字段 `:271-273`、series 字段 `:296-298`、match 臂 `:337-342`、SQL 列 `src/service/metrics/store.rs:310-312`；(d) `src/handler/admin.rs:129-133` 仅导出三标签。canonical `openspec/specs/llm-gateway/spec.md:118-143`（「截断三态（唯一值）」，正文四态）与 `openspec/specs/observability-admin/spec.md:127-146`（「truncated_mode 三态落 metrics 分标签计数」，四态）**已要求四态分标签计数** → **活矛盾**。修复：四态白名单在 `metrics.rs` / `metrics/store.rs` / `metrics/aggregate.rs` / `handler/admin.rs` 全量补齐，各态递增**自身**标签并在持久化/快照/导出各含独立槽；schema 采用**加列式**（新增 `upstream_error` 独立列 + `DEFAULT 0`，旧库经既有 `ALTER TABLE ADD COLUMN` 补列，只加不改旧列，见 design §N 决策与兼容影响）。验收为**行为性**（四态各自递增自身标签 + 落盘/导出各见自身标签；`upstream_error` 不落 `other`、不记非法值 warn），非 grep 字符串守护。

## Capabilities

### New Capabilities

无（本 change 只修改既有 capability）。

### Modified Capabilities

- `llm-protocol-hardening`: 非流 `output[]` 工具判定与流式对称（A/G）；Responses 内置工具类型审计覆盖新增 computer 分支（B）。
- `transport-fidelity-fix`: `count_tokens` 由 `NonDialog` 收窄为 redact-only 对话变体，`batches` 显式例外（C）；NonDialog 观测计数登记现状（不新增端点维度，M-2）。
- `redaction`: 残余帧还原经统一 `emit_restored_json_frame`（恒守卫 + 失败回退）（D）。
- `stream-fidelity-fix`: `data_frame` 按行终止集合拆分、裸 CR 载荷声明 LF 归一（E/B-3）。
- `gateway-transport-fidelity`: `PENDING_EVENTS` 溢出由「丢最旧」改为「清空整队 + 计数」（M）。
- `deadcode-positional-cleanup`: `PROTOCOL_HEADER_NAME` 常量与替换、leaf 近同形 helper 合并、`emit_restored_json_frame` 抽取、Responses 派生面文件体量抽取、重开 `x-veil-protocol` 内联保留条款（I/K/B-2）。
- `docs-test-parity`: 源码注释指针准确（`meta.rs` 四态、`tool.rs` 同结论措辞）、归档 r3 锚点漂移口径登记（F/G/J）。
- `docs-contract-sync`: README `E_EMPTY_BODY` 正面档与 §4 合成体字段可选措辞对齐（J/M-4）。
- `llm-gateway`: 四态截断白名单端到端齐备（进程内计数/落盘白名单/快照/导出）（N/B-1）。
- `observability-admin`: 四态截断分标签计数加列持久化与四态导出（N/B-1）。

## Non-goals

- 不重开 r2/r3 已声明的有意偏离（Anthropic 中途断流不补终端、跨槽放行序、`ValidationCache` 内联保留）。
- **`batches` 端点脱敏**：`v1/messages/batches` 为异步批处理元数据端点，其响应不含对话机密且形态为分页对象；保持 `NonDialog` 字节透传，另立 change 评估。
- **`image_generation_call` 审计**：无可执行参数且 payload 为图像大对象，纳入审计 hold 会放大体量；显式非目标。
- **完整 `StreamTerminator` 重构**（阻断/终止帧注入去重收敛）登记为后续独立 change。
- **全局跨会话确定性 token**：与请求隔离隐私硬要求冲突，非目标（`H` 的缓解依赖 conversation 级缓存，另立 change）。
- **上游缓存命中率测量**：命中率为 provider 侧计费指标，网关侧不可见真值（既有 wont-measure 声明）。
- **Anthropic 签名校验**：网关不校验上游签名，`H` 仅登记限制。
- **NonDialog 端点维度观测计数**（M-2）：既有单原子计数形态维持，不新增键控维度、不新增导出指标族（`C` 的观测登记现状）。
- 不新增导出指标（`M` 仅内部计数 + warn；`N` 为既有四态标签补齐，不新增指标族）。
- 不引入新 crate 依赖；不改 `NONSTREAM_MAX_BYTES` / 审计上限 / token 形态等既有阈值。

## 待核对（登记，不臆断）

- **conformance 用例数实测 = 24（原文案 23 陈旧，已按 live 实测修订）**：`scripts/api_conformance.py:794` 打印 `len(RESULTS)`；`bash scripts/gate.sh` 第 6 步 live 实测输出 `共 24 项，失败 0 项`（全 gate 七步 exit 0），四阻断相为 `chat 阻断`/`anthropic 阻断`/`responses 截断`/`responses 非流阻断`。分解：`run_normal_phase` 14 项（`:689-700`）+ `run_credential_phase` 5 项（`:454-457`）+ 无库 503 1 项（`:471`）+ `run_block_phase` **4** 项（`:761-764`，含 `responses 非流阻断`）= **24 = 14 常规 + 4 阻断 + 5 取用 + 1 无库 503**（原「3 阻断」已陈旧）。`README.md:900-902` §8.5、canonical `docs-contract-sync` 与本 change delta `specs/docs-contract-sync/spec.md` 已同批由 23→24（3 阻断→4 阻断）修订；详细口径见 `design.md` §5。**MINOR 8 澄清**：计数差异**不影响** gate 第 6 步——`gate.sh` 第 6 步仅看 `api_conformance.py` 的**退出码**（全项通过即 0），**不比较项数**；故只影响 README §8.5 与 `docs-contract-sync` 的**文案口径**，不改变门禁判定。
