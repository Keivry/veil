# Tasks

> 本 change 为 artifacts-only（规划）；以下任务在 apply 期执行。每个任务的验证命令/断言写在任务描述内。行号仅为导航，落码时以符号锚点为准。文件体量红线 800 行，任何净增须先抽取 sibling 模块并跑 `python3 scripts/check_file_sizes.py`。

## 1. 协议保真与终端

- [x] 1.1 `src/service/llm_gateway/protocol.rs`：新增 `Protocol::spec()`（只读常量表）最小字段 `done_terminator: Option<&str>` 与 `terminal_event_types`，仅 Chat 的 `done_terminator` 为 `Some("[DONE]")`；**只迁移明确列出的消费者**（`[DONE]` 短路 + `event.rs::is_terminal_event`），现有至少四组协议事件集合（见 design D8）其余**不**迁移；验证：单测断言三协议 `spec()` 字段值，且 `is_terminal_event` 改读 `spec().terminal_event_types` 后既有终端判定用例全绿，`cargo clippy -D warnings` 通过（R5-24/D8）。
- [x] 1.2 `src/handler/llm/pump/spawn/event_loop.rs`：`[DONE]` 短路分支改为读 `env.protocol.spec().done_terminator` 判定，非 Chat 不置终端、不透出；同步**逐一列明** `is_done_payload` 其余调用点（`src/service/sse/parser.rs:402/432`、`src/handler/llm/pump/event.rs:131`、`event_loop.rs:255/362`）中哪些必须迁移、哪些以「低层字符串判定、协议门控在消费点」声明为非目标（写入 5.5 注释清单）；验证：新增单测「Responses/Anthropic 收到上游 `data: [DONE]` → 下游无 `[DONE]` 且恰一官方终端」，并断言非 Chat `[DONE]` 后到达帧不再被终端守卫抑制、`add_sse_event` 计数变化已声明，Chat 既有去重测试仍绿（R5-01/D2）。
- [x] 1.3 `src/handler/llm/pump/event.rs::stream_model_of`：补第三级回退 `response.model`（`v.get("model")` → `v["message"]["model"]` → `v["response"]["model"]`，与 `extract_conv_id` 的 `response.id` 回退对称、无条件性）；验证：单测 `response.completed` 嵌套 model 被提取，且流/非流同 model 分桶 parity 通过（R5-02）。
- [x] 1.4 `src/service/block_inject/frames.rs::chat_block_frames`：增 `conv_id: Option<&str>` 与 `model: &str` 入参（缺失回退 `blocked-0`/`unknown_model`），`protocol_block_frames` 的 Chat 臂传入；**补 model 贯通路径**：`TerminalCtx`（`terminal.rs:32-66`）当前不含 `stream_model`、`finish.rs:24-52` 未传 → 须补字段并从 `state.stream_model` 传入，`plan_block` 签名与两个调用点（`apply_reject_block`、`terminal.rs:154-160`）都要改（Anthropic/Responses 见 1.8）；验证：新增三协议 parity 单测「流式阻断帧 id/model 与非流 `nonstream_block_body` 同口径」，`block_frame_choice_coverage` 仍绿（R5-03）。
- [x] 1.5 `src/handler/llm/pump/spawn/event_loop.rs`：Anthropic `error` 终端一并记 `TruncatedMode::UpstreamError`；验证：单测断言 Anthropic `error` 事件后 `truncated_mode == upstream_error`，且四态白名单落点导出各见自身标签（R5-04）。
- [x] 1.6 `src/handler/llm/pump/event.rs::build_sse_response`：增状态码入参并在 `src/handler/llm/dispatch.rs` 传入上游 2xx 原状态；验证：单测「上游 206+SSE → 下游 206」，`<400` 入泵门未放宽（R5-05/D4）。
- [x] 1.7 `src/handler/llm/pump/spawn/terminal.rs` + `terminator.rs`：已终端后收尾命中 `Block` 时保留 `block_injected=true`、记 `warn!`（不含明文）并计入 `audit_blocks`；**须新增独立状态位/新 state**（不触发 `mark_terminal`、不改 `terminal_injected`，因现有状态机无法表达该组合，见 design D3），并**显式调用 `terminator.note_sticky_rejected()`**（`audit_blocks` 位与 `block_injected` 不同位）计入计数；验证：新增单测锁定「不注入第二终端 + `block_injected` 为 true + `audit_blocked`/计数递增 + `terminal_injected` 保持原值」（R5-35/D3）。
- [x] 1.8 三协议阻断帧 `model` 回显（R5-39，与 1.4 合批）：`anthropic_block_frames_full`（`frames.rs:104`）、`responses_failed_frame`（`:189`）与 `responses_sequence`（`:220`/`:231`）的硬编码 `unknown_model` 参数化并回显上游 model（缺失回退 `unknown_model`），与非流 `nonstream_block_body` 三协议口径一致；验证：三协议 parity 单测通过，`check_doc_paths.py` 通过（R5-39）。

## 2. 会话级缓存与键推导

- [x] 2.1 `src/service/redaction/conversation_key.rs::extract_first_user`：`input` 为字符串时返回 `None`；验证：单测「标量 input 请求落第 4 级且 `record_request_fallback` 递增；数组 input 正常命中第 3 级」（R5-06/D1）。
- [x] 2.2 `src/service/redaction/conversation_key.rs` + `src/handler/llm/dispatch.rs`：原生键与稳定前缀字段按协议白名单（Anthropic 忽略 `prompt_cache_key`/`previous_response_id`；Chat 忽略 `previous_response_id`；Chat/Anthropic 用 `messages`/`system`，Responses 用 `input`/`instructions`）；验证：**正例 + 反例**双向单测（Chat 体带 `previous_response_id` 不命中第 2 级；Anthropic 体带 `prompt_cache_key` 不命中）（R5-07）。
- [x] 2.3 `src/handler/llm/dispatch.rs`：`strip_conversation_header` 改为无条件剔除（去除 `is_conversation()` 门控）；验证：单测「`PII_SCOPE_MODE=request` + 自定义非 `x-veil-` 头名 → 该头不出现在转发头」（R5-36/D7）。
- [x] 2.4 `src/handler/llm/dispatch.rs`（`build_request_scope`）+ `src/service/redaction/conversation_key.rs`（`valid_explicit_header`）：仅对 **D9 三类可判定事件**记 `warn!` + 内部计数，**不新增**下游响应头——① 推导返 `None` 落 L4：`conversation_key_fallback`（复用 `record_request_fallback()` 落点）；② `store` 缺失（`dispatch.rs:150`）：`conversation_store_missing`；③ 显式头存在但非法（`conversation_key.rs:98-106`）：`conversation_header_invalid`。「换键/变级」无状态不可观测 → Non-Goal，不登记；验证：单测断言三键各自递增且响应头集合未新增 `x-veil-*` 项（R5-08/D9）。
- [x] 2.5 `src/handler/llm/pump/spawn/event_loop.rs` + `src/handler/llm/nonstream.rs`：`record_response_id` 失败**先区分三类原因再计数**——(a) 无写回上下文（`request` 模式/键未推导）、(b) 非 `Protocol::Responses` 门控、(c) 响应 id 缺失；**仅 (c)** 记 `conversation_writeback_miss`（否则默认 `request` 模式每个 Responses 响应都会误计），保持仅 Responses 写入；验证：单测「`request` 模式无 id 响应 → 不误计；`conversation` 模式 Responses 缺 id → 计数 +1 且不 panic」（R5-09）。
- [x] 2.6 `src/state.rs` + 配置：新增 `PII_PREV_ID_MAX_ENTRIES`（**未设置时取 `PII_SCOPE_MAX_CONVERSATIONS` 的生效值**，非钉死 1024）驱动 `PreviousResponseMap` 容量并记逐出计数；验证：单测「映射容量独立于 PII 会话容量；`PII_SCOPE_MAX_CONVERSATIONS=2048` 且未设新变量时映射容量为 2048（任意配置零行为变化）」，README §1 环境变量表补该变量（R5-10/D10）。
- [x] 2.7 `src/config/env_parse/pii_scope.rs`：`PII_SCOPE_KEY_HEADER` 启动期**保留名校验**（拒绝 `authorization`/`x-api-key`/`api-key`/HOP 集/`host` 等，或限定 `x-veil-*` + 显式放行清单），非法值拒启动（fail-closed）；验证：单测「保留名 → 启动错误且信息具名；`x-veil-*` 合法值放行」（R5-40/D7）。

## 3. 数值安全与 fail-closed

- [x] 3.1 `src/config/validate.rs::has_placeholder_token_shape`：改为字节级匹配（不切 `str` 边界）；验证：新增中文/多字节自定义文案单测不 panic，且既有 token 形态检测用例全绿（R5-13）。
- [x] 3.2 `src/error.rs` + `src/service/redaction/leaf.rs` + `src/service/pii/scope.rs` + 调用链：**在 `src/error.rs` 新增 `E_PII_UNAVAILABLE` 变体并映射 `502`（码字面集中定义于 `src/error.rs`）**；拆分 `register` 失败类——token 形态静默跳过；熵源/内部故障 `warn!` + 计数 + **fail-closed**（该请求 502）。须把脱敏链改为**可失败**（`Result`）或引入等价 side-channel 失败标志，沿 `redact_leaf_inner`（walk 回调，`leaf.rs:208-211`）→ `Scope::redact_request_with_report → (String,bool)` → `request_rewrite → RewriteOutput`（`rewrite.rs:99-105`）→ `gateway_serve` 上传；**响应侧** `redact_response_new_pii*`（`event_loop.rs:669-677`）同样 fail-closed。熵源故障注入手法：以 test-only 可注入的熵源抽象或 `#[cfg(test)]` 故障开关注入失败。验证：单测「注入熵源故障 → 请求侧与响应侧均 502 + 无未脱敏体转发；token 形态值 → 静默跳过不报错」（R5-14/D5）。
- [x] 3.3 `src/service/pii/scope.rs`：请求/响应表**分设序号空间**（spec 只声明可观测不变量「一条目 ↔ 一序号、不跨表回查」，实现式枚举不进 spec）；验证：单测「两表各占满后新分配不再共享哨兵序号 + `fuzzy` 回查不歧义」，并更新聚合上界注释（R5-15/D6）。
- [x] 3.4 `src/service/llm_gateway/tool.rs`：索引提取改 `try_from`，越界值按**原始索引摘要**分入有界哈希溢出桶（`hash(idx) % K`，K 为有界常量并计入容量）+ `warn!`（**拒绝固定单一溢出桶**，见 design D12）；legacy Chat `function_call` 改用枚举下标；验证：单测「越界索引不与合法索引碰撞 + 同 choice 多 `function_call` 不互相覆盖」。**红线**：`tool.rs` 现 748/800 行，须先抽出 sibling 小函数（先例 `tool_responses.rs`）或给出净增行数预算，落码后跑 `python3 scripts/check_file_sizes.py`（R5-16/D12）。
- [x] 3.5 `src/service/audit/hold.rs`：`slot.next_seq += 1`、`slot.next_seq.max(seq_no + 1)`、`total_bytes +=` 统一 `saturating_add`（`seq_no + 1` 的**入参极值** `u64::MAX` 分支亦须饱和）；验证：单测「`sequence_number = u64::MAX` 不 panic、不重复键、`next_seq`/`total_bytes` 不溢出」（R5-17）。
- [x] 3.6 `src/service/metrics/aggregate.rs`：脏数据 warn + 计数（不静默归零）、`i64` 经 `try_from`/`max(0)` 收敛；验证：单测「不可解析桶值 → warn + 计数 + 有界值；负存储值 → 不符号失真」（R5-18）。

## 4. 规范文本与文档同步

- [x] 4.1 `README.md` §7.2/§7.3/§7.6/§7.7/§7.11/§8.6：按本 change 的 delta spec 同步**六处**口径（`stream_options` 仅 Chat、空流不转 502、Anthropic 阻断五件套 vs 真空最小终止、非流 usage 三级回退、`Speed` 由 `audit_mode` 派生、空体 502 四分支一致性）；**并**按 R5-11 补 §7.3/§7.7 占位符说明跨轮前缀增长边界、按 R5-12 补 §7.3/§7.11 缓存稳定性边界声明；验证：`python3 scripts/check_doc_paths.py` 通过 + 与 `openspec/specs/llm-gateway/spec.md` 文本同字抽查（R5-19/R5-11/R5-12）。
- [x] 4.2 `README.md` + `src/handler/llm/nonstream.rs:376` + `src/service/llm_gateway/hop.rs:36`：终端合成/空流实现指针改指 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator` 与 `src/service/block_inject/frames.rs::empty_stream_frames`；`dispatch.rs` 漂移锚点校正为符号锚点；**README 与两处源码注释**把幽灵符号 `hop_filtered_total` 改指 `record_hop_filtered`/`hop_filtered_count`（或显式标注为度量名）；验证：`check_doc_paths.py` 通过 + 人工复核符号存在（R5-22）。
- [x] 4.3 `README.md`：登记用户可感知行为变化（R5-02 model 分桶、R5-04 Anthropic `error` 计入 `upstream_error`、R5-03/R5-39 三协议阻断帧回显 id/model、R5-05 2xx 状态透传、R5-14 新 502 `E_PII_UNAVAILABLE`、R5-36/R5-40 无条件剔头与保留名校验）与 D1/D5 语义变化；验证：README 变更段落经 `check_doc_paths.py` 且人工比对 delta spec 无冲突（R5-19/R5-22）。
- [x] 4.4 `src/handler/llm/pump/spawn/setup.rs`：澄清旧「七 bool」注释（唯一状态在 `StreamTerminator`；`decide.rs`/`event.rs` 同名项为纯函数入参）；**并**复核 `src/service/sse/meta.rs`、`src/service/metrics/aggregate.rs`、`src/config/env_parse.rs`、`src/main.rs`、`src/service/llm_gateway/tool.rs` 的注释指针准确（陈旧「三态」→「四态」等）；验证：注释不再可被读为现存状态字段，`cargo clippy` 通过（R5-22）。
- [x] 4.5 复核登记项：逐条确认 R5-28/R5-29/R5-30/R5-31/R5-32/R5-33/R5-34/R5-38 **无需代码改动**（垫片/重导出/派生函数/已修注释/pub 收紧；`tool_responses` 合并理由已更正为「收益低于风险」）；验证：`git diff` 中不出现 `audit_hold.rs`、`state.rs:31` 重导出、`tool_responses.rs` 合并（R5-28/R5-29/R5-30/R5-31/R5-32/R5-33/R5-34/R5-38）。
- [x] 4.6 `specs/redaction/spec.md`（R5-20）：行号引用漂移改**符号锚点**——`resolve_upstream`、`x-veil-*` 剔除、`previous_response_id` 写入点、`ConversationScopeStore` 装配区间；验证：文本已落 + `check_doc_paths.py` 通过 + 人工复核符号存在（R5-20/D14）。
- [x] 4.7 `specs/stream-protocol-parity/spec.md`（R5-21）：多 choice 措辞与显式单 choice 声明同字（「静默丢失」改为「按显式声明覆盖范围（当前 `index==0`）」）；验证：文本已落 + `openspec validate --strict` 通过（R5-21）。
- [x] 4.8 `specs/llm-gateway/spec.md`（R5-37）：补占位符说明「容器缺失即不注入（Anthropic 缺 `system` 新建例外）」声明；验证：文本已落 + `check_doc_paths.py` 通过（R5-37/D11）。
- [x] 4.9 `specs/llm-gateway/spec.md`（R5-41）：截断 requirement **不改名**——canonical `openspec/specs/docs-test-parity/spec.md` 按「截断三态（唯一值）」互引，`## RENAMED Requirements` 会破坏跨 spec 引用；改为在正文加「命名残余声明」（名称保留为历史锚点、口径以正文四态为准，已落于 delta `### Requirement: 截断三态（唯一值）`）；验证：`openspec validate --strict` 通过 + delta 内「命名残余声明」在位 + canonical 无其它「三态」正文残留（R5-41/D14）。
- [x] 4.10 新增 `protocol-compliance-fix` 与 `llm-streaming-parity` 两个 delta（R5-42，sibling 负责）：FIX-2/流式 parity 收敛为「阻断五件套 / 真空最小二帧 / 正常不合成」，与 `llm-gateway` delta 同字；验证：三文件文本同字抽查 + `openspec validate --strict` 通过（R5-42）。
- [x] 4.11 新增 `llm-critical-compliance` delta（R5-43，sibling 负责）：E4「流式恒 200」限定为「阻断帧**正文**对称（状态码随上游 2xx 透传）」，并同步 README §7.2；验证：`openspec validate --strict` 通过 + README §7.2 无「流式恒 200」旧表述（R5-43/D15）。

## 5. 结构收敛（有界）

- [x] 5.1 生产 JSON 解析统一经 `src/service/json_walk.rs::{strip_bom, jloads}`（优先 `src/handler/llm/dispatch.rs`、`src/handler/llm/nonstream.rs`、`src/handler/llm/pump/spawn/frame_feed.rs`）；验证：单测「BOM 前缀体被正常解析（原为解析失败回退）」+ `check_doc_paths.py` 通过（R5-23）。
- [x] 5.2 转发头 preamble 收敛为**每方向单一 helper**——上游 `src/handler/llm/mod.rs::forward_headers`、下游 `src/handler/llm/nonstream.rs::clone_upstream_headers`（由 `snapshot_downstream_headers` 复用）；调用点不重复「剥 hop/剥内部头/计数」三步 preamble。验证：方向头集合 parity 单测通过，`filter_hop_headers_counted` 仍为唯一逐跳实现（R5-25；「单一参数化 helper」原措辞与两 helper 实现不符的偏差已在 architecture-cleanup delta（D4）更正）。
- [x] 5.3 阻断臂「拒绝即消费」结构化（`apply_reject_block` 恒消费触发帧，或调用点无条件 return）；验证：单测「拒绝后不再透出本帧内容」（R5-26）。
- [x] 5.4 `/_admin/health` 限流豁免补行为断言；验证：单测「连续 **11** 次 `/_admin/health` 不 429（均 200）；`/_admin/metrics` 第 11 次 429 带 `retry-after`」（R5-27）。
- [x] 5.5 `src/service/llm_gateway/protocol.rs` 的「新增协议检查清单」注释标注 `ProtocolSpec` 迁移进度（第一步字段已落、已迁移消费者、未迁移的四组事件集合、全量字段为后续 change）；**并**把本 change 触及的 `architecture-cleanup` MODIFIED requirement 中残留硬行号（`event_loop.rs:160-173`、`terminal.rs:158-171` 与 I-1…I-5）转为**符号锚点**，人工复核符号存在；验证：注释与实现一致、`check_doc_paths.py` 通过、`cargo clippy` 通过（R5-24/D8/D14）。

## 6. 验证与门禁

- [x] 6.1 `cargo fmt --check` 与 `cargo clippy --all-targets -- -D warnings` 零告警；验证：两条命令 exit 0。
- [x] 6.2 `cargo test` 全量通过（含本 change 新增的单测/parity 测试）；验证：测试摘要无失败，新增测试可点名列出。
- [x] 6.3 门禁脚本全绿：`python3 scripts/check_doc_paths.py`、`python3 scripts/check_file_sizes.py`（仓库 `scripts/` 下**无** `check_tests.py`，勿引用不存在脚本；七步统一门禁入口为 `scripts/gate.sh`）；验证：两条命令 exit 0，且改动文件均未越 800 行红线。
- [ ] 6.4 `bash scripts/gate.sh` 实测 **6/7 步通过 + 第 6 步显式跳过**：以 `GATE_SKIP_CONFORMANCE=1 bash scripts/gate.sh` 执行，步骤 1(fmt)/2(clippy -D warnings)/3(单测)/4(doc-paths)/5(file-sizes)/7(go vet+test) 通过，**第 6 步（live SDK 一致性 `scripts/api_conformance.py`）显式跳过**——原因：固定 venv `../../Python/credential-proxy/.venv/bin/python` 不存在（脚本断言 pin `openai==3.5.0`/`anthropic==1.1.x`/`pykeepass`，且仓库无 `requirements*.txt`/`pyproject.toml` 可复现该环境）。复现指引：准备上述 pin 的 Python venv，必要时经 `VEIL_CONFORMANCE_PYTHON` 覆盖解释器路径，再不带 `GATE_SKIP_CONFORMANCE` 重跑即可执行第 6 步。**不主张 7/7、不主张 conformance 通过项数**（本机未实测 conformance 结果）。
- [x] 6.5 `openspec validate veil-audit-r5-remediation --strict` 通过；验证：exit 0。
- [x] 6.6 完成后 `@oracle` 复审并修复其发现（重点：D1/D3/D5 语义正确性、`ProtocolSpec` 单源是否真的无双源残留、fail-closed 路径无明文外泄）；验证：Oracle 结论逐条闭环，修复后重跑 6.1–6.5。**实测闭环**：Oracle 复审裁定 fix-then-ship（阻塞 D1/D2/D3，建议同批 D4/D5/D7）；D1–D9 已逐条修复——D1 网关载荷 JSON 解析统一（13 处 in-scope 站点全迁 `json_walk::{strip_bom, jloads}`）、D2 序号不变量正文化＋空转测试重写、D3 删除实现中不存在的 allow-list 句、D4 改「每方向单一 helper」、D5 tasks 勾选＋conformance 显式跳过如实登记、D6 登记截断/真空帧 model 回显、D7 写回计数口径精确定义、D8 登记 `chat_bucket_raw` 合法域收紧、D9 legacy 非 modeled 包装 `#[cfg(test)]` 收编（10 个）；修复后 6.1–6.5 重跑全绿（1491 测试、184 文件 ≤800 行、doc-paths 3632/255/272 通过）。
- [x] 6.7 提交：按仓库 Conventional Commits 风格（`feat(gateway): 第五轮审计修复（R5-01…R5-43）` 之类）提交并推送；验证：`git log -1 --stat` 与本 change 任务面一致，`git push` 成功。
- [x] 6.8 符号锚点人工复核（D14）：逐一核对本 change 全部 `path::symbol` 引用符号真实存在（`scripts/check_doc_paths.py` **不校验符号存在**）；重点 `llm-protocol-hardening` delta 的 `tool.rs:222`/`:650-656`/`:572-581`（实为 `tool_responses.rs` 符号）；验证：人工清单逐项通过，错指改符号锚（R5-20/R5-22/D14）。
