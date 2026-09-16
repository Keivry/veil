## 1. Responses 内置工具审计对称性（`A`/`G`；`llm-protocol-hardening`）

- [x] 1.1（A，M-1）`src/service/llm_gateway/tool.rs:647-659` 非流 Responses `output[]` 的 `is_tool` 增补 `|| responses_item_tool_name(item_type).is_some()`（复用 `:219-231`，勿复制字面量）；**内置条目名/参派生**：non-function/non-custom 的内置条目经**派生名路径**建条目（与既有检索 early-return `:662-683` 同形）——名由 `responses_item_tool_name(item_type)` 派生，参按 item-done 路径同口径回退（`["arguments","code","command","input"]` → `retrieval_args`（`:105-141`）→ `item.action` 整体 `serde_json::to_string`，`:572-581` 同口径）；function/custom tool 维持 `custom_obj_to_call` 路径。新增单测 `responses_output_builtin_tools_audited`，覆盖 function/custom/code_interpreter/shell/mcp/file_search/web_search/computer，**断言各内置条目派生名非空且 args 非空**（真实条目：`code_interpreter_call` 携带 `code`、`shell_call` 携带 `action`）
  - 验证：`cargo test -p veil responses_output_builtin_tools_audited` 通过；真实 `code_interpreter_call`/`shell_call` 条目**非空派生名 + 非空 args**（行为断言，非 grep 守护）

- [x] 1.2（A）补流/非流同结论 parity 测试 `responses_output_stream_nonstream_parity`：同一工具条目分别经 `response.output_item.done`（`:542-552`）与非流 `output[]`（`:647-659`）提取，断言 `(name, args, bucket)` 逐一致
  - 验证：`cargo test -p veil responses_output_stream_nonstream_parity` 通过；两路径每类型不一致即失败（此测试同时为 G 的唯一行为判据）

- [x] 1.3（A/G）`src/service/llm_gateway/tool/tests.rs:61-101` 的 `item_done_type_coverage` 仅覆盖 `response.output_item.done`；补 `output[]` 全量体用例（可并入 1.1 单测），并核对 `src/service/llm_gateway/tool.rs:216-218` 注释与实现一致（A 落地后「同结论」成立；注释准确性为 code-review 项，M-5）
  - 验证：`cargo test -p veil item_done_type_coverage` 与新增用例均通过

## 2. `computer_call` 覆盖（`B`；`llm-protocol-hardening`）

- [x] 2.1（B）`src/service/llm_gateway/tool.rs:219-231`（`responses_item_tool_name`）与 `:202-214`（`responses_derived_tool_kind`）新增 computer 分支：用 `contains("computer")` 兼容 `computer_call`/`computer_call_output`/`computer_use_preview`，派生名 `"computer"`；参数取 `action`（沿用 1.1 的 action 回退）；新增单测 `responses_computer_call_audited`（流式 item-done 与非流 `output[]` 两路径为主；delta 分支按 **DEFENSIVE** 登记，无上游样本不判失败，MINOR 7）
  - 验证：`cargo test -p veil responses_computer_call_audited` 通过；item-done 与 `output[]` 两路径 `name == Some("computer")` 且 args 来自 `action`

- [x] 2.2（B，MINOR 1）canonical `openspec/specs/llm-protocol-hardening/spec.md` 与 delta 同批声明（精确口径）：`local_shell_call` 今日仅由 `responses_item_tool_name` 的 `contains("shell")`（`src/service/llm_gateway/tool.rs:222`）在 item-done 路径覆盖、非流 `output[]`（`:650-656`）随 A 覆盖、`responses_derived_tool_kind`（`:205-206`）仅匹配 `shell_call_command` 子串；`image_generation_call` 为**非目标**（无可执行参数 + 图像大 payload）
  - 验证：核查 delta spec 含 `local_shell_call`/`image_generation_call`/computer 精确路径边界三条声明；`openspec validate veil-audit-r4-remediation --strict` 通过

## 3. `count_tokens` redact-only（`C`；`transport-fidelity-fix`）

- [x] 3.1（C）`src/service/llm_gateway/protocol.rs:81-94`（`is_official_subresource`）与 `:112-114` 将 Anthropic `count_tokens` 由「NonDialog 排除」改为 **redact-only 对话变体**（判定产物携带 redact-only 语义）；`:139-153` 的 `resolve_protocol`/`is_passthrough` 保留 `NonDialog` 唯一透传语义，穷举 `match` 完整；`batches` 保持 `NonDialog` 例外
  - 验证：`cargo test -p veil count_tokens_redact_only` 通过；`POST /v1/messages/count_tokens` 请求体 `messages` 内 PII 被占位符替换

- [x] 3.2（C）redact-only 路径执行请求侧脱敏（`scope.redact_request`）+ 占位符说明注入门控（`should_inject_placeholders`）；**跳过**审计判定、响应侧还原与新 PII 扫描、阻断合成、用量记账；**保留** hop 过滤与有界读（受 `NONSTREAM_MAX_BYTES` 约束）；新增测试断言无 usage 记录、响应不还原、字节保真
  - 验证：`cargo test -p veil count_tokens_redact_only` 通过；断言无 usage 记录、响应不还原

- [x] 3.3（C，M-2 登记现状、M-3 新命名测试）NonDialog 观测计数**登记现状、不新增端点维度**：沿用无参单原子 `record_nondialog_passthrough`（`src/service/llm_gateway/metrics.rs:98,149-157`），**SHALL NOT** 改为端点键控计数、**SHALL NOT** 新增导出指标族；`count_tokens` 收窄后不计该计数，`batches` 与其他 NonDialog 端点继续计；canonical `openspec/specs/transport-fidelity-fix/spec.md` 与 delta 同批声明。**新增**测试 `nondialog_passthrough_batches_only`（不复用既有 `nondialog_passthrough_counter_accumulates`）
  - 验证：`cargo test -p veil nondialog_passthrough_batches_only` 通过；`batches` 计 NonDialog 透传递增、`count_tokens` 不计（新语义由新命名测试承载，M-3）
  - 验证：核查 delta spec「非对话子资源透传观测计数」requirement 声明「不新增端点维度、不新增导出指标族」

## 4. 残余帧守卫与协议往返（`D`/`K`；`redaction`/`deadcode-positional-cleanup`）

- [x] 4.1（D，B-2）在 handler 层抽单一 `emit_restored_json_frame(...)`：内部依次 `json_aware_line` 重序列化（如需）→ `guard_restored_frame_parsed`（含 metrics + warn）→ 守卫失败**回退占位符帧** → 成功才 `feed_output_frame`；保持 `src/service/redaction/restore_guard.rs:1-5` 零 axum 依赖边界。**落点**：`src/handler/llm/pump/spawn/event_loop.rs` 当前 753 行，该 helper **SHALL NOT** 落在 `event_loop.rs`——置于 sibling/新模块或 `src/handler/llm/pump/spawn/terminal.rs`（343 行）
  - 验证：`grep -rn "fn emit_restored_json_frame" src/handler/llm/pump/spawn/` 命中单一定义，且不在 `event_loop.rs`
  - 验证：`cargo test -p veil residual_frame_guard_fallback` 通过；构造还原后非法 JSON 的残余帧 → 输出回退占位符帧并记 metrics

- [x] 4.2（D）`src/handler/llm/pump/spawn/terminal.rs:207-228` 残余帧路径改为调用 `emit_restored_json_frame`（替换 `:214-228` 的直通 `feed_output_frame`）；`src/handler/llm/pump/spawn/event_loop.rs:616-648` 两臂（`:626` 与 `:643-648`）同批改用同一 helper
  - 验证：`grep -rn "emit_restored_json_frame" src/handler/llm/pump/spawn/` 命中残余帧与正常帧三处调用
  - 验证：`cargo test -p veil` 全绿（既有正常帧与残余帧用例行为不变）

- [x] 4.3（D）补回归：残余帧守卫失败必须回退占位符帧而非非法 JSON（新增 `residual_frame_guard_fallback`），并覆盖正常帧共用 helper 的等价性
  - 验证：`cargo test -p veil residual_frame_guard_fallback` 通过

- [x] 4.4（K）协议往返不变量测试：① CR 载荷往返（见 5.1）；② 纯 `event:` 洪泛（见 5.3）；③ redact↔restore 组合；④ opaque 帧字节恒等（`src/handler/llm/pump/spawn/event_loop.rs:616-626`）；新增测试 `sse_protocol_roundtrip_invariants`
  - 验证：`cargo test -p veil sse_protocol_roundtrip_invariants` 通过；四类不变量全部断言
  - 验证：design §K 明确「完整 `StreamTerminator` 收敛为非本 change 范围」

## 5. 流式出口与解析（`E`/`M`；`stream-fidelity-fix`/`gateway-transport-fidelity`）

- [x] 5.1（E，B-3 可达化）`src/service/sse/emit.rs:14-24` 的 `data_frame` 改为按行终止集合（`\n`/`\r\n`/`\r`）拆分，**SHALL NOT** 把裸 CR 留在单条 `data:` 行内（保持数据行原样）；修正 `:9-13` 的「严格互逆」注释为「与解析侧行终止集合相关、含裸 CR 载荷按已声明 LF 归一」；新增测试 `sse_data_frame_cr_roundtrip`（含裸 CR/CRLF：断言解析得**已声明 LF 归一**值、恰一事件、无 `event:` 名错配），**不以「逐字节一致（含 `\r\n`）」为断言**；纳入既有往返测试 `src/service/sse/cr_tests.rs:73`（`sse_multiline_data_roundtrip`）
  - 验证：`cargo test -p veil sse_data_frame_cr_roundtrip` 与 `cargo test -p veil sse_multiline_data_roundtrip` 通过
  - 验证：裸 CR 载荷断言为已声明 LF 归一（如 `a\rb` → `a\nb`），无「逐字节一致（含 `\r\n`）」断言

- [x] 5.2（E/B-3）canonical `openspec/specs/stream-fidelity-fix/spec.md:291-308` 与 delta 同批声明：行终止集合拆分 + **LF 归一**（含裸 CR/CRLF 载荷不承诺逐字节恒等）；`src/service/sse/parser.rs:327` 的单 `\n` 连接为锁定行为
  - 验证：核查 delta `多行 data 出口保真` requirement 含 LF 归一声明且移除「逐字节一致（含 `\r\n`）」；`openspec validate veil-audit-r4-remediation --strict` 通过

- [x] 5.3（M）`src/service/sse/parser.rs:341-369` 的 `pending_events` 溢出改为**清空整队**（`clear()`）+ 递增 `pending_events_dropped` + 每流首次 warn（复用 `pending_events_drop_warned`）；`:370-378` 的消费语义与正常流计数不变；新增测试 `pending_events_overflow_clears_queue`（9 个纯 `event:` 块后 data 帧无 event 标签 + 计数递增）
  - 验证：`cargo test -p veil pending_events_overflow_clears_queue` 通过；正常配对流 `sse_event_count`/出口帧计数不变

- [x] 5.4（M）canonical `openspec/specs/gateway-transport-fidelity/spec.md:8-42` 与 delta 同批修订：溢出由「丢最旧」改为「清空整队」（fail-safe：宁缺信封不错标）；`id` 最近值与 `pending_retry` 单值语义不变；不新增导出指标
  - 验证：`grep -n "清空\|丢最旧\|pending_events" openspec/specs/gateway-transport-fidelity/spec.md` 命中新口径
  - 验证：`openspec validate --all --strict` 通过

## 6. 注释、限制声明与定性口径（`F`/`G`/`H`/`L`；`docs-test-parity`）

- [x] 6.1（F，B-1 扩域 + M-5 行为验收）`src/service/sse/meta.rs:3` 注释「三态」改为「四态」并登记（实际变体 `:10-17`：`SilentDiscard`/`OpenEnded`/`SynthesizedFailed`/`UpstreamError`）；**同批修正 `src/service/metrics/aggregate.rs:30` 的陈旧「唯一三态」注释**。注释准确性为 **code-review 项**；**验收为行为性**（10.4 的四态白名单落点测试）
  - 验证：`cargo test -p veil truncated_mode_four_state_labels` 通过（四态齐备、各态落点独立，见 10.4）
  - 验证：code review 确认两处注释与 `src/service/sse/meta.rs:10-17` 四变体一致（不以 grep 命中「四态」为验收，M-5）

- [x] 6.2（G，M-5）`src/service/llm_gateway/tool.rs:216-218` 注释随 1.1 落地后核准「item-done 路径与 delta/非流路径同结论」成立；如实现走共享私有实现而非同函数，则改述为准确表述。**唯一行为判据为 1.2 的 parity 测试**；注释准确性为 **code-review 项**
  - 验证：`cargo test -p veil responses_output_stream_nonstream_parity` 通过

- [x] 6.3（H，MINOR 9）canonical `openspec/specs/llm-protocol-hardening/spec.md` 与 delta 登记 Anthropic 思考签名连续性为**已知限制**：网关不校验上游签名、不承诺无条件连续；条件性缓解**按 requirement 名**依赖后续 change `veil-pii-conversation-cache` 的 `openspec/changes/veil-pii-conversation-cache/specs/llm-gateway/spec.md` requirement「Anthropic thinking 签名连续性（条件性收益与残余限制）」（会话级稳定 token 为**必要条件**）
  - 验证：核查 delta spec 与 design §H 均按 requirement 名引用依赖；`openspec validate veil-audit-r4-remediation --strict` 通过

- [x] 6.4（L）canonical `openspec/specs/gateway-transport-fidelity/spec.md`/`openspec/specs/stream-fidelity-fix/spec.md` 与 delta 登记四项定性结论：非流 `from_utf8_lossy` 非字节保真（`src/handler/llm/nonstream.rs:257`）、流式错误体惰性透传 vs 非流有界（`src/handler/llm/dispatch.rs:369-372`）、Chat `stream_options` 畸形态 warn + 整体替换维持现状（`src/service/llm_gateway/protocol.rs:194-197`；`README.md:605-608` 已声明）、非流 `restore_guard_ok(..., None)` 二次解析仅性能不改（`src/handler/llm/nonstream.rs:272`；`src/service/redaction/restore_guard.rs:20-26`）
  - 验证：核查 delta `传输面既有差异声明` requirement 含四项；`openspec validate --all --strict` 通过
  - 验证：`README.md:605-608` 与 `src/service/llm_gateway/protocol.rs:194-197` 措辞一致（核对即可，不改行为）

- [x] 6.5（证伪登记）design.md §3 已列：F3/F5 为 FALSE POSITIVE（`src/service/redaction/restore_guard.rs:20-26`；minted 授权 `src/service/redaction/scope.rs:177`，MINOR 5）、F1 降级 P3、F6 assistant 文本不审计为既定非目标、「流式错误体无界」为疑误（`src/handler/llm/dispatch.rs:369-372`）、E 的「逐字节一致（含 `\r\n`）」不可达；本任务核对 design 全覆盖、无静默省略
  - 验证：design §3 含 F3/F5/F1/F6/疑误/E 六项登记，且 F5 以 minted 授权为主依据（MINOR 5）

## 7. 死代码/冗余收敛（`I`；`deadcode-positional-cleanup`）

- [x] 7.1（I）新增 `pub(crate) const PROTOCOL_HEADER_NAME: &str = "x-veil-protocol"`（与 `src/service/redaction/leaf.rs:23` 的 `NORMALIZED_HEADER_NAME` 同址共享常量区），替换 5 处字面量：`src/handler/llm/dispatch.rs:366`、`src/handler/llm/nonstream.rs:239,509,554`、`src/handler/llm/mod.rs:61`
  - 验证：`cargo test -p veil` 全绿（响应头值不变）；生产面字面量收敛为常量（常量定义与测试除外）

- [x] 7.2（I）`src/service/redaction/leaf.rs:59`（`prescan_custom`）vs `:79`（`prescan_custom_response`）以 `bool` 参（或共享私有实现）合并；`:132`（`redact_leaf_inner`）vs `:193`（`redact_leaf_response`）同法合并；**行为保持**（请求表 vs 响应表、`minted` 追踪、仲裁/`apply_spans` 逐项不变）
  - 验证：`cargo test -p veil scope_tests` 与 `cargo test -p veil` 全绿；PII 双向语义不变

- [x] 7.3（I，澄清）`src/service/block_inject.rs:35,48-49,152-153` 的 `"data: [DONE]\n\n"` 均在 `#[cfg(test)] mod tests`（:21 起）；生产已统一 `chat_done_frame()`（`src/service/block_inject/frames.rs:303`；`src/handler/llm/pump/spawn/event_loop.rs:742`、`src/handler/llm/pump/synth_flush.rs:93`）→ 按 canonical `deadcode-positional-cleanup`「测试内断言文本 SHALL NOT 纳入抽取」**不改生产源码**；在 delta spec 登记该澄清（可选：测试字面量改用 `chat_done_frame()`）
  - 验证：delta spec 含「测试内断言文本不纳入抽取」登记；生产零直写 `data: [DONE]`

- [x] 7.4（B-2，前置）**文件体量抽取**：`src/service/llm_gateway/tool.rs` 现 788 行、`src/handler/llm/pump/spawn/event_loop.rs` 现 753 行，A/B/D 增补前须先把 Responses 工具类型派生面（`responses_item_tool_name`、`responses_derived_tool_kind` 与 Responses `output[]`/delta 工具收集 helper）迁至 sibling 模块（如 `src/service/llm_gateway/tool_responses.rs`<!-- doc-paths-ignore -->）；`emit_restored_json_frame` 避开 `event_loop.rs`（见 4.1）。**本任务 SHALL 先于 1.1/2.1 执行**
  - 验证（中间锚点，B-2/M-6）：抽取完成、**1.1/2.1 增补前**，`src/service/llm_gateway/tool.rs` 须 ≤780 行（现 788 行，仅抽 `:200-214`/`:216-231` 两小函数 ≈31 行 → ≈757 行；A+B 预计再加 20-30 行 → ≈785-795 行，对 ≤800 仅余 <10 行余量）。此为前置中间门，与下方 post-change ≤800 门并存
  - 验证：`python3 scripts/check_file_sizes.py` exit 0；`src/service/llm_gateway/tool.rs` 与新增 sibling 文件均 ≤800 行（逐文件 `wc -l` 复核）
  - 验证：`cargo test -p veil` 全绿（抽取为行为保持、re-export 完整，A/B 增补后不越线）

## 8. 文档缺口与归档锚点（`J`；`docs-contract-sync`）

- [x] 8.1（J）README 补 `E_EMPTY_BODY` 正面档（触发条件：非流 200 空体/非 JSON → 502；错误体字段形态；与 `response_too_large` 的先后关系），以 `src/error.rs:86-97,110`（`:88` 码名、`:110` 502）与 `src/handler/llm/dispatch.rs:150` 为准
  - 验证：`grep -n "E_EMPTY_BODY" README.md` 命中正面档（非仅 `:669` 否定式）
  - 验证：正面档描述与 `src/error.rs:110`（`EmptyBody → BAD_GATEWAY`）一致

- [x] 8.2（J，M-4）README §4 表行 `README.md:253` 的字段名对齐降级为**可选（SHOULD）**：README 现措辞「`502` + `response_too_large` JSON 体」**并未**称字段名为 `error.code`，故不属错误表述；可选补 `error.type` 以对齐代码（`src/handler/llm/nonstream.rs:566`），未对齐不判失败；**移除「纠正错误表述」框架**；canonical `openspec/specs/docs-contract-sync/spec.md` 与 delta 同批登记
  - 验证：核查 delta spec 与 design §J 均表述为「可选对齐、非纠错」；零命中「纠正错误表述」定性
  - 验证：若执行对齐则 §4 行含 `error.type`（未执行不判失败）

- [x] 8.3（J，MINOR 2）归档 r3 锚点漂移口径登记：design.md 注明 r3 归档 `tasks.md` 4.4 称 `src/service/pii/custom.rs:395-396`（容器）而实际容器在 `src/service/pii/detector.rs:498`；`custom.rs` 对应位置现为请求侧脱敏扫描签名，`Arc::clone` 在 `:401`（**锚点修正，MINOR 2**）；归档目录**不回改**（`scripts/check_doc_paths.py:67,71-72` 的 `ARCHIVED_PREFIX` 行号在界豁免）；`scripts/README.md` 已与脚本口径一致，**无需改动**
  - 验证：`grep -n "detector.rs:498\|不回改\|ARCHIVED_PREFIX\|custom.rs:401" openspec/changes/veil-audit-r4-remediation/design.md` 命中
  - 验证：`python3 scripts/check_doc_paths.py` exit 0（归档引用按处数打印未校验、无 FAIL）

## 9. 边界、待核对与门禁（`K`；`docs-contract-sync`）

- [x] 9.1（K）design.md 与 delta 显式登记非目标：`batches` 脱敏、`image_generation_call` 审计、完整 `StreamTerminator` 重构、全局跨会话确定性 token、上游缓存命中率测量、Anthropic 签名校验、NonDialog 端点维度观测计数（M-2）；apply 期不得顺手扩范围
  - 验证：`grep -n "Non-goals\|非目标\|StreamTerminator" openspec/changes/veil-audit-r4-remediation/proposal.md openspec/changes/veil-audit-r4-remediation/design.md` 命中全部
  - 验证：`openspec validate veil-audit-r4-remediation --strict` 通过

- [x] 9.2（已完成，MINOR 8）conformance 用例数口径：`scripts/api_conformance.py:794` 打印 `len(RESULTS)`；`README.md:900-902` 与 canonical `docs-contract-sync`（`:97-109`）声明 23 项 → apply 期已以 gate 第 6 步实测为准：**24 项、失败 0 项**（4 阻断相具名），并已同批修订 README §8.5、canonical `docs-contract-sync` 与 `test-coverage-fill`（`:53,:58,:68`）及本 change delta 为 24 / 4 阻断（归档目录内旧文案按 `ARCHIVED_PREFIX` 豁免不回改）；**SHALL NOT** 未实测前臆断。**澄清（MINOR 8）**：计数差异**不影响 gate 第 6 步**——`gate.sh` 第 6 步仅看脚本**退出码**（全项通过即 0）、不比项数，故仅影响 README §8.5 / spec 文案
  - 验证：design §5 与 proposal「待核对」均含「不影响 gate 第 6 步」澄清
  - 验证：apply 期 `python3 scripts/api_conformance.py` 输出项数与 README §8.5 一致（live 实测 = 24）

## 10. 四态截断指标白名单收口（`N`，B-1；`llm-gateway`/`observability-admin`）

- [x] 10.1（N）`src/service/llm_gateway/metrics.rs:54-55` 的 `TRUNCATED_MODE_KEYS: [&str; 3]` 扩为 `[&str; 4]`（含 `upstream_error`）；`GatewayMetrics::truncated` 的 `KeyedCounters` 容量（`:68`）与初始化（`:92`）同步为 4。`record_truncated("upstream_error")` 须命中具名键，**不落 `other` 桶**、**不触发未知键 warn**（`src/service/llm_gateway/metrics.rs:26-41`）
  - 验证：`cargo test -p veil truncated_mode_four_state_labels` 中 `truncated_count("upstream_error") == 1` 且 `other == 0`（唯一可观测断言；`src/service/llm_gateway/metrics.rs:12 other_warned` 无访问器、warn 经 `tracing::warn!` 发出，**不可断言**，故不以「无未知键 warn」为判据）

- [x] 10.2（N）`src/service/metrics/aggregate.rs:30` 注释改「四态」、`:31` `TRUNCATED_MODES` 扩为 4 项；`WindowAgg` 增 `t_upstream_error`（`:175-177` 同区）、`MetricsSnapshot` 增 `truncated_upstream_error`（`:271-273`）、`SeriesPoint` 增 `truncated_upstream_error`（`:296-298`）、`snapshot()` match 臂增 `upstream_error`（`:337-342`）；`src/service/metrics/store.rs:109-116` 对 `upstream_error` 走合法分支（不记「非法值」warn、不丢弃）；聚合落标签（`src/service/metrics/store.rs:168-173`）；**加列式 schema**：三表 `CREATE TABLE` 增 `t_upstream_error INTEGER NOT NULL DEFAULT 0`（`src/service/metrics/store.rs:298-348`）+ 既有补列循环加入该列（`src/service/metrics/store.rs:350-365`）+ UPSERT 列/参数（`src/service/metrics/store.rs:431-465`）；**读取/回填位于 `src/service/metrics/aggregate.rs`（**非** `store.rs`）**：`query_series_blocking`（`:412-470`，SELECT `:425-429`）+ `backfill_rows_blocking`（`:473-523`）。**最高风险编辑点（`row.get` 索引为编译器不校验的隐式列序契约）**：`query_series_blocking` 的 SELECT 增 `t_upstream_error`（15 → 16 列），`SeriesPoint` 读取须新增 `row.get(15)`（现有 `row.get(12..14)` 见 `:460-462`）；`backfill_rows_blocking` 的 SELECT 在 `buckets` 前增列，`row.get(15)`（`buckets`，现见 `:488`）须后移为 `row.get(16)`、`t_synth` 读取后新增 `t_upstream_error`；两处列序须逐列复核，错列将静默取错值或编译失败
  - 验证：`cargo test -p veil truncated_mode_four_state_labels` 通过；一次 `upstream_error` 记录后独立列/字段 = 1、三枚旧标签不变、无「非法值」warn
  - 验证：旧库（缺列）启动经 `ALTER TABLE ... ADD COLUMN` 补列成功、`DEFAULT 0`，既有列读取不变（加列式迁移，只加不改）

- [x] 10.3（N）`src/handler/admin.rs:129-133` 的 `truncated` 对象增 `upstream_error`（`/_admin/metrics` 四态导出）；canonical `openspec/specs/llm-gateway/spec.md:118-143`（requirement「截断三态（唯一值）」）与 `openspec/specs/observability-admin/spec.md:127-146`（requirement「truncated_mode 三态落 metrics 分标签计数」）与 delta（`specs/llm-gateway/spec.md`、`specs/observability-admin/spec.md`）同批声明四态白名单落点与加列迁移
  - 验证：`/_admin/metrics` 快照 `truncated` 对象含 `upstream_error`；`openspec validate veil-audit-r4-remediation --strict` 通过
  - 验证：delta 两 spec 的 requirement header 与 canonical 逐字一致（MODIFIED 场景保全）

- [x] 10.4（N，M-3/M-5）**行为验收测试**（新命名 `truncated_mode_four_state_labels`，不复用既有测试名）：断言四态白名单齐备（`TRUNCATED_MODE_KEYS`/`TRUNCATED_MODES` 各含 `silent_discard`/`open_ended`/`synthesized_failed`/`upstream_error`）；依次以四态记录，四枚标签各自 = 1、互不串计；四态之外的值四枚标签均不递增（`tracing::warn!` 告警**不可断言**，不作判据，仅 `truncated_count` 桶可观测）；`upstream_error` 的落点覆盖 metrics/store/aggregate/admin 四类
  - 验证：`cargo test -p veil truncated_mode_four_state_labels` 通过；**行为断言**（非 grep 字符串守护，M-5）；`upstream_error` 判据为 `truncated_count("upstream_error") == 1` 且 `other == 0`
  - 验证：`openspec validate veil-audit-r4-remediation --strict` 与 `openspec validate --all --strict` 通过

## 验证门禁（Verification Gate）

- [x] G-1 `bash scripts/gate.sh` 七步全绿（fmt / clippy `-D warnings` / test / doc-paths / file-sizes / conformance / go vet+test），任一步非零退出即本 change 未完成
- [x] G-2 `openspec validate veil-audit-r4-remediation --strict` 通过（等价：`openspec validate --changes --strict`）；`openspec validate --all --strict` 亦通过（新增 `llm-gateway`/`observability-admin` delta 归入同一 change 项，全量项数见实测输出）
- [x] G-3 `python3 scripts/check_doc_paths.py` exit 0；本 change 内所有 `src/...rs:NNN` 锚点存在且在界（归档引用按处数打印「未校验」，不计 FAIL；规划期新模块路径以 `<!-- doc-paths-ignore -->` 标注）
- [x] G-4 `python3 scripts/check_file_sizes.py` exit 0；B-2 抽取后 `src/service/llm_gateway/tool.rs` 与新增 sibling 文件均 ≤800 行，`emit_restored_json_frame` 不在 `event_loop.rs`
- [x] G-5 归档晋升：apply 完成后按 r2/r3 先例将本 change 的 `specs/*/spec.md` delta 晋升 canonical `openspec/specs/**`（同批直改 + 归档时 early-sync no-op），含新增 `llm-gateway`/`observability-admin` delta
- [x] G-6 本 change 规划期（artifacts-only）不改 `src/**`、`tests/**`、`scripts/**`、`README.md`、`openspec/specs/**` 与任何其他 change 目录；不归档、不 `git add/commit`、不运行 `cargo`
