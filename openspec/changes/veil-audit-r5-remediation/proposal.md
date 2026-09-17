# Proposal

## Why

本 change 承载 2026-09-17 第五轮独立七维只读审查（r5）的修复规划：对一个已高度成熟、门禁全绿的基线（`e6f678c`，紧接 `veil-stream-terminator-convergence` 归档）做只读复审，覆盖 **① bug ② 架构更优方案 ③ 文档/注释与代码一致性 ④ 死代码与冗余 ⑤ 三协议（`/v1/chat/completions`、`/v1/responses`、`/v1/messages`）处理是否合规 ⑥ 会话级缓存命中友好 ⑦ 不破坏结构/语义/工具调用** 七个方向。

审查由 1 个 Oracle 深度审读 + 5 路并行探索（死代码、文档一致性、panic/吞错、协议分支矩阵、会话缓存字节稳定性）构成，产出约 60 条候选结论，复核后登记为问题 ID `R5-01`…`R5-43`（ID 按复核追加顺序分配，与章节非严格连续；`R5-39`…`R5-43` 为二次复核/Oracle 裁决追加登记）。**关键前提：候选结论已逐条复核，误报已被显式剔除**（见 §六）——例如「`Speed::Slow/Fast` 双速未实现」「`audit_hold.rs` 垫片为死代码」「`tool_responses` 两函数逐行重复」「`arch-docs-cleanup` spec 不存在」经复核均为**误报**（误报登记共六条，含 `R5-32`/`R5-38`），若不剔除会把「有意保留」当缺陷修掉。

经复核为**真实缺口**的结论收敛为以下五类二阶缺陷（前四轮门禁未捕获、且非已知回归）：

1. **协议保真**：`[DONE]` 终端短路不判协议（Anthropic / Responses 被 Chat 收尾）；Responses 流式模型取值漏嵌套 `response.model`（流/非流分桶分裂）；流式阻断帧（Chat/Anthropic/Responses）硬编码 `blocked-0`/`unknown_model`（丢会话与模型连续性，与非流三协议回显矛盾）；Anthropic `error` 终端漏 `upstream_error` 观测标记；SSE 泵响应状态码恒 200。
2. **会话级缓存**：Responses **标量 `input`** 被当作「首个 user turn」参与第 3 级稳定前缀键 → 每轮换键、token 失稳并使会话存储 churn（`conversation` 模式对该形态静默失效）；会话键**原生键读取无协议门控**（代码宽于 canonical：Anthropic 也可被 `prompt_cache_key`/`previous_response_id` 命中）；换键/回退仅计数、无 warn；`previous_response_id` 写回失败静默；映射容量与 `PII_SCOPE_MAX_CONVERSATIONS` 耦合。
3. **数值安全 / fail-closed**：`has_placeholder_token_shape` 按字节递增却用 `str` 切片 → **含多字节字符的自定义占位符文案必 panic**（配置可达）；`PiiScope::register` 把「token 形态拒绝」与「CSPRNG 熵源故障」共用 `Err(_) => continue` → 熵源故障时**静默明文上行**（fail-open）；序号空间请求/响应表共享 → 饱和后哨兵复用致 `fuzzy` 还原歧义；工具桶索引 `as u32` 截断 + legacy `function_call` 固定桶 0 碰撞；审计 hold `next_seq`/`total_bytes` 非饱和算术；指标聚合脏数据静默归零。
4. **规范与文档一致性**：`llm-gateway` spec 六处文本与实现矛盾（`stream_options` 注入范围、空流 502 口径、Anthropic 终止「五件套」与真空最小终止混述、非流 usage 单层 vs 三级回退、`Speed` 被描述为「配置档」实为 `audit_mode` 派生、空体 502 四分支一致性）；`redaction` spec 四类行号引用漂移；`stream-protocol-parity` 多 choice 措辞与显式单 choice 声明未对齐；README 四处实现指针因终端收敛而过时 + 旧七 bool 注释残留 + 幽灵符号 `hop_filtered_total`。
5. **结构收敛（有界）**：JSON 解析旁路中央 `jloads(strip_bom)`；协议分派散布（`ProtocolSpec` 两步收敛）；转发头 preamble 三处重复；阻断臂「拒绝即消费」缺结构化保证；`/_admin/health` 限流豁免缺行为断言。

审查基线门禁全绿（`bash scripts/gate.sh` 七步 exit 0：fmt / clippy `-D warnings` / 单测 / doc-paths / file-sizes / conformance（24 项）/ go vet+test），故上述均为**二阶缺陷**而非已知失败回归。

**本 change 为 artifacts-only（规划），apply 期才落源码。** 涉及产品语义的决策点已在 `design.md` 逐条定档（D1–D15）。

## What Changes

### 一、协议保真与终端（`CONF`，能力：`llm-protocol-hardening` / `stream-protocol-parity` / `stream-fidelity-fix` / `llm-gateway`）

- **R5-01（P2）`[DONE]` 短路不判协议**：`src/handler/llm/pump/spawn/event_loop.rs::handle_event` 的 `is_done_payload` 短路分支与协议无关：进入即 `mark_upstream_terminal()` 并无条件推入 `chat_done_frame()`。后果：**Responses 下游收到零个 `response.*` 终端**（`mark_upstream_terminal` 令中段/空流合成分支双短路），**Anthropic 下游收到协议外事件**，违反 canonical `llm-protocol-hardening`「Responses 恒恰一终端」。修复：该分支门控 `env.protocol.is_chat()`；非 Chat 视 `data: [DONE]` 为**非事件**（不置终端、不透出），交既有中段/空流合成路径产出协议正确终端（决策 **D2**）。触发面有限（仅上游自身非合规地发 `[DONE]` 而缺官方终端），对合规上游零变化。
- **R5-02（P3）Responses 流式模型漏嵌套 `response.model`**：`src/handler/llm/pump/event.rs:217-221` `stream_model_of` 仅取顶层 `model` 与 `message.model`（Anthropic 形状）；Responses `response.completed` 的 model 在 `response.model` → 流式恒回退 `req_model`，而非流（`src/handler/llm/nonstream.rs:186-190`）读上游回显 → **同一 Responses 调用流/非流 model 分桶系统性分裂**。修复：补第三级回退（`response.model`），与 `extract_conv_id` 的 `response.id` 回退对称。
- **R5-03（P3）流式 Chat 阻断帧丢 conv/model**：`src/service/block_inject/frames.rs:38-62` `chat_block_frames(reason)` 签名不收 conv/model，硬编码 `id="blocked-0"`、`model="unknown_model"`；而 `src/service/block_inject/frames.rs:141-160` `protocol_block_frames` 的调用点（`event_loop.rs:161-170`）已为全协议算好 `conv_id`/`blocked_index`，Chat 臂静默丢弃；非流 `nonstream_block_body`（同文件 `:324-429`）三协议**均回显上游 id/model**。后果：流式 Chat 阻断恒归 `blocked-0`/`unknown_model`，按会话/模型聚合的审计与 metrics 断链。修复：`chat_block_frames` 增 `conv_id`/`model` 参数（缺失回退现值），与非流同口径；与 R5-39 合并为「三协议阻断帧 `model` 回显」（Chat 侧另需 `conv_id` 回显），补三协议 parity 单测。
- **R5-04（P3）Anthropic `error` 终端漏 `upstream_error` 标记**：`event_loop.rs:230-237` 仅 `is_chat_error_terminal`（顶层 `error` 且无 `choices`）记 `TruncatedMode::UpstreamError`；Anthropic `error` 同属终端（`event.rs:244-256`）却落 `truncated_mode=None`，三类「上游错误即终端」只有两类可观测。修复：Anthropic `error` 终端同记 `upstream_error`（`set_truncated` 对该值本就开放），并补四态白名单落点验证。
- **R5-05（P3）SSE 泵响应状态码恒 200**：`src/handler/llm/pump/event.rs:43-44` `build_sse_response` 硬编码 `StatusCode::OK`；入口门控（`src/handler/llm/dispatch.rs:344-357`）仅排除 `status>=400 || !is_event_stream`，故上游 `201/202/206` + `text/event-stream` 进入泵后下游恒收 200，而非流臂（`nonstream.rs:310`、`error_streaming_response:509`）保留上游状态 → 流/非流口径不对称。修复：`build_sse_response` 增状态码入参并透传上游 2xx 原状态（P2 不变；**不**放宽 `<400` 入泵门）。
- **R5-35（P3）终端已置位后收尾命中 `Block` 的语义与 canonical 行为保持条款冲突**：`src/handler/llm/pump/spawn/terminal.rs:147-170` 收尾终审命中 `Block` 时，仅当 `terminator.plan_block(...)` 返回 `TerminalPlan::Frames` 才发送并 `commit`；`src/handler/llm/pump/spawn/terminator.rs:177-179` 在 `!is_open()`（流已终端：上游 `message_stop`/`response.completed`/`[DONE]`/错误帧）时返回 `None`。重构前（`f10eae6^`）该臂会置 `block_injected=true`、注入阻断帧并 `mark_terminal(meta)`；现行为**不再注入第二终端**（方向更正确），但 `PumpOutcome.block_injected` 由 `true` 变 `false`、`StreamMeta.terminal_injected` 不置位、且该次阻断**无 warn、无计数**（危险参数随 `agg.clear()`/`pending_tool_frames.clear()` 丢弃而不可观测）。这与 canonical `openspec/specs/architecture-cleanup/spec.md`「流式阻断/终止帧注入单一所有者」的**行为保持**声明直接矛盾，且偏差只登记在 commit message。修复（决策 **D3**）：保留「不注入第二终端」，但保留 `block_injected=true` 语义 + 记 `warn!`（不含明文）+ 计入 `audit_blocks` 观测，并**修订 canonical**：在该 requirement 下新增 Scenario「已终端后收尾审计命中 Block：不注入第二终端、保留 `block_injected=true`、记 warn 与阻断计数」+ 单测锁定（替换「逐项行为保持」的绝对表述）。
- **R5-39（P3）Anthropic/Responses 流式阻断帧硬编码 `unknown_model`**：`src/service/block_inject/frames.rs` 的 `anthropic_block_frames_full`（`anthropic_message_start(id, "unknown_model")`，审查时点 `:104`）、`responses_failed_frame`（`:189`）与 `responses_sequence`（`:220`/`:231`）均硬编码 `model="unknown_model"`；而非流 `nonstream_block_body` 三协议**均回显上游 model**（同文件 `:354-358`/`:381-385`/`:415-419`）。后果：流式 Anthropic/Responses 阻断体模型归 `unknown_model`，与非流及（R5-03 修复后的）流式 Chat 口径不一致，按模型聚合的审计/metrics 断链；R5-03 的 parity 理由对其余两协议同样成立。修复：阻断帧 `model` 参数化并回显上游 model（缺失回退 `unknown_model`），与 R5-03 合并为「三协议阻断帧 `model` 回显」；补三协议 parity 单测。spec 家：`stream-protocol-parity` delta。

### 二、会话级缓存命中友好（`CACHE`，能力：`redaction` / `observability-admin` / `llm-gateway`）

- **R5-06（P2）Responses 标量 `input` 使第 3 级会话键每轮漂移**：`src/service/redaction/conversation_key.rs:179-195` `extract_first_user` 对 `input` 为 `String` 时返回**整串**；`:199-208` `canonical_stable_prefix` 只需 `tools`+`system`+`first_user` 齐备即命中第 3 级。后果：Responses 单轮简写形态（`input` 为字符串）+ `instructions` + `tools` 的**多轮会话每轮换键** → 同明文不复用 token（前缀字节失稳）+ 每轮向 `ConversationScopeStore` 插入新条目（容量 1024 LRU 挤出他租户）。属跨协议不对称（Chat/Anthropic `messages` 数组与 Responses 数组 `input` 均稳定）。修复（决策 **D1**）：第 3 级仅接受 turn 锚点可确定的前缀——`input` 为标量时**不参与** `first_user`（返回 `None`），落第 4 级并由既有 `record_request_fallback()` 计入观测；canonical `redaction` 与 README §7.3 同步登记该形态。
- **R5-07（P2）会话键原生键无协议门控 + 稳定前缀跨协议取字段**：`src/handler/llm/dispatch.rs:159-164` 对三协议无差别读顶层 `prompt_cache_key`/`previous_response_id`，`derive_conversation_key`（`conversation_key.rs:230-252`）无 protocol 参数全接受；canonical `redaction`「会话键分层推导」明写「Chat/Responses 的 `prompt_cache_key`、Responses 的 `previous_response_id`」。后果：向 Anthropic 体塞 `prompt_cache_key`、向 Chat 体塞 `previous_response_id` 即可跨协议命中/污染命名空间（租户指纹隔离租户但不隔离协议）。附带 **U2b**：`extract_system`（`:160-175`）对任意协议读 `instructions`，`extract_first_user`（`:179-195`）对任意协议读 `messages` → Chat 体的 `instructions` 会被当 system、Responses 体的 `messages` 会被当首轮。修复：按协议白名单取键与取字段（Anthropic 忽略二者；Chat 忽略 `previous_response_id`），并与 canonical/README §7.3 同字。
- **R5-08（P2）会话键回退/换键静默**：`dispatch.rs:170-182`（推导 `None` → 逐请求 + `record_request_fallback()`）与 `:150-153`（store 缺失 → 回退）仅计数，无 warn、无每请求可观测标记；四级「首个命中者胜」使某轮漏带显式头/键即静默换键（`conversation_key.rs:98-106` 超 256B/控制字符亦静默降级）。排障无法定位「哪轮失稳」。修复（决策 **D9**，收窄为**可判定事件**）：① 推导返 `None` 落 L4；② `store` 缺失；③ 显式头存在但非法被静默丢弃——三者记 `tracing::warn!`（**不含**键值/头值/明文/token，遵守 `redaction` 日志不泄露条款）+ 内部计数；**不新增**下游响应头（`x-veil-scope` 登记为非目标）；「中途换键/变级」因每请求无状态推导而不可观测，登记为非目标（不写入 spec 制造不可验证条款）。
- **R5-09（P3）Responses 流式 `previous_response_id` 写回失败静默**：`event_loop.rs:207-211` 与 `nonstream.rs:224-227` 经 `record_response_id` 写映射，失败（无 `id`/解析失败/非 Responses）走 `let _ =` 无计数 → 映射缺项致下一轮落第 4 级。修复：先区分三类原因再计数——(a) 无写回上下文（`request` 模式/键未推导）、(b) 非 `Protocol::Responses` 门控、(c) 响应 id 缺失；**仅 (c)** 计 `conversation_writeback_miss`（否则默认 `request` 模式下每个 Responses 响应都会误计）。保持「仅 Responses 写入」不变。
- **R5-10（P3）`PreviousResponseMap` 容量与 PII 会话容量耦合**：`src/state.rs:192-194` 以 `PII_SCOPE_MAX_CONVERSATIONS` 同时作映射容量，高并发 Responses 会话超限即静默逐出旧 `response_id` → 下一轮换键。修复（决策 **D10**）：映射容量独立化（新增 `PII_PREV_ID_MAX_ENTRIES`，**未设置时回退到 `PII_SCOPE_MAX_CONVERSATIONS` 的生效值**以零行为变化）并记录逐出计数（取解耦方案）。
- **R5-11（P3）占位符说明注入的跨轮前缀增长未声明**：`src/handler/llm/rewrite.rs:83-97` 仅当体内**已含** token 才注入说明（`placeholder.rs:37-49`），故首轮无 PII、次轮出现 PII 时头部会新增一条 system → **turn1→N 前缀字节必然增长**（合法但未被 canonical/README 声明为已接受）。修复：canonical `llm-gateway`「占位符说明头部注入跨轮字节恒定」补登记该边界（同会话两轮**均含 token** 时前缀字节一致；token 首次出现那轮允许前缀增长），README §7.3/§7.7 同步。
- **R5-12（P3）缓存稳定性声明补齐**：`conversation_key.rs:199-208,149-156`（稳定前缀依赖 `tools`+`system`+首 user 三者冻结）、`:89-95,75-84`（租户指纹含**完整上游基址含 path/query** 与凭据头 → 轮换即换命名空间）、`placeholder.rs`/`env_parse.rs:88-90`（自定义文案变更即换前缀）、`json_walk.rs:142-143,80-98,110-112`（`>1M`/`>128 层`/`>5 层 stringified` 回退改变序列化形状）→ 均为**已成立但未声明**的边界，补 canonical `redaction` 与 README §7.3/§7.11 声明（不改代码）。

### 三、数值安全与 fail-closed（`ROBUST`，能力：`runtime-robustness` / `redaction` / `stream-fidelity-fix` / `stream-protocol-parity` / `llm-protocol-hardening`）

- **R5-13（P2）`has_placeholder_token_shape` UTF-8 切片 panic**：`src/config/validate.rs:114-141` 按字节 `i += 1` 前进却做 `text[i..]` 切片 → `i` 落入多字节字符中间即 panic。触发：自定义 `PII_PLACEHOLDER_PROMPT_TEXT` 含**任何**多字节字符（中文文案为最可能形态），启动期 panic。修复：改 `as_bytes()` 上的字节匹配（或 `text.get(i..)` 守卫），保持语义不变；补中文文案单测。
- **R5-14（P3）`register` 失败 fail-open**：`src/service/redaction/leaf.rs:205-212` 把 `PiiScope::register` 的**两类**失败（值本身即 token 形态 → 应跳过；CSPRNG 熵源不可用 → 应失败收敛）共用 `Err(_) => continue`。后果：熵源故障时明文**原样转发上游**且无 warn、无计数。修复（决策 **D5**）：拆分错误类型——token 形态静默跳过；熵源/内部故障记 `warn!`+指标并按**fail-closed**（该请求不转发未脱敏体，返回 502 `E_PII_UNAVAILABLE` 语义）收敛。
- **R5-15（P3）序号空间跨表共享致饱和歧义**：`src/service/pii/scope.rs:66-73` `used_seqs` 单集合（注释自述「请求/响应表共享序号空间」）、`:79-107` `alloc_seq`/`release_seq`、`:169-192` 两表各自 LRU。两表各限 1000 却共用 1..=1000：**并集饱和后 `alloc_seq` 恒返回哨兵 `PII_MAX_ENTRIES+1`** → 多个 token 共享同序号，`fuzzy` 还原（`:241-258`）按序号回查会把截断形 token 映射到另一表明文（`PII_FUZZY_RESTORE=1` 时归错值）；且饱和时 `find_free_from` 每次扫满 1000 步，与「均摊 O(1)」注释不符。修复（决策 **D6**）：请求/响应表分设序号空间，保持可观测不变量「一条目 ↔ 一序号、不跨表回查」；同步修正 README §6.3「`used_seqs` = 全部在用序号」口径与 `redaction` 聚合上界条。
- **R5-16（P3）工具桶索引截断与 legacy 桶碰撞**：`src/service/llm_gateway/tool.rs` 多处 `as u32` 截断（客户端/上游可控的 `choices[].index`/`tool_calls[].index`/`output_index`/`block.index`），且 `chat_bucket` 以 16 位掩码 `(ci<<16)|(idx&0xFFFF)` 使 `0` 与 `65536` 碰撞同一 hold 槽；`tool.rs:276-292` legacy `function_call` 在同一 choice 内**恒桶 0**（同文件 `custom_tool_call` 用枚举下标），单 choice 多 `function_call` 时审计槽互相覆盖。修复：改 `try_from` + **有界哈希溢出桶**（按原始索引摘要 `hash(idx) % K`，K 有界并计入容量）+ warn，**拒绝固定单一溢出桶**（会把越界值重新撞进同一槽），legacy `function_call` 改用枚举下标回退；补碰撞/多条目单测。
- **R5-17（P3）审计 hold 非饱和算术**：`src/service/audit/hold.rs:201-206` `slot.next_seq += 1` / `.max(seq_no+1)` 在 `sequence_number = u64::MAX`（上游可控）时 release 包裹 → `BTreeMap` 键复用、审计分片错位；`:111,214` `total_bytes += …` 与相邻 `saturating_*` 不一致。修复：统一 `saturating_add`（含 `slot.next_seq += 1` 与 `slot.next_seq.max(seq_no + 1)` 的**入参极值**分支——`seq_no + 1` 须用 `saturating_add` 处理 `u64::MAX`）；补边界单测（`u64::MAX` 序号不 panic、不重键）。
- **R5-18（P3）指标层脏数据静默失真**：`src/service/metrics/aggregate.rs:503` `parse().unwrap_or(0)` 把损坏桶静默记 0（监控失真）、`:512-519` `i64 as u64` 使负值变大数。修复：脏数据 warn + 计数（不静默归零）、`i64` 经 `try_from`/`max(0)` 收敛。

- **R5-36（P3）会话键头仅在 `conversation` 模式剔除**：`src/handler/llm/dispatch.rs:253-256` 的 `strip_conversation_header` 被 `if state.config.pii_scope_mode.is_conversation()` 门控；而 canonical `redaction`「会话键头不转发不入日志」条款**无条件**要求「自定义头名同样剔除」，且 `src/config/env_parse/pii_scope.rs:68-70` 对自定义头名**不做** `x-veil-*` 约束。后果：`PII_SCOPE_MODE=request`（默认）+ 自定义非 `x-veil-` 头名时该头随请求**转发上游**（默认头名因 `x-veil-*` 前缀被通用内部头剔除掩盖，故长期未被发现）。修复：**无条件**剔除（成本一次 `HeaderMap::remove`），与 canonical 条款对齐；补「request 模式自定义头名不转发」单测。<!-- doc-paths-ignore -->
- **R5-40（P3）`PII_SCOPE_KEY_HEADER` 无命名约束，与无条件剔头组合可删除真实鉴权头**：`src/config/env_parse/pii_scope.rs:68-70` 仅要求该头名非空，无保留名/命名空间校验；与 D7/R5-36 的「无条件剔除」组合后，若运维误配为 `authorization`（或 `x-api-key`/`api-key` 等），网关将在**所有模式**（含默认 `request`）静默删除真实鉴权头再转发上游 → 上游鉴权断链且无提示。修复：启动期对 `PII_SCOPE_KEY_HEADER` 做保留名校验（拒绝 `authorization`/`x-api-key`/`api-key`/HOP 集/`host` 等，或限定 `x-veil-*` + 显式放行清单），非法值拒启动（fail-closed）；补单测。spec 家：`redaction` delta。

### 四、规范与文档一致性（`DOCS`，能力：`llm-gateway` / `redaction` / `stream-protocol-parity` / `docs-contract-sync` / `docs-test-parity` / `llm-critical-compliance` / `protocol-compliance-fix` / `llm-streaming-parity`）

- **R5-19（P3）`llm-gateway` spec 文本与实现矛盾（六处）**：
  1. `openspec/specs/llm-gateway/spec.md:44-54`「`stream_options` 仅 chat / responses 注入」+ 场景「chat 或 responses … 注入默认」—— 实现**仅 Chat**（`src/service/llm_gateway/protocol.rs:192-199` 首行 `if !protocol.is_chat() { return false }`；Responses 用量经 `response.completed` 三级回退）。→ spec 收窄为「仅 Chat」，与 README §7.2 同字。
  2. 同 spec `:80-90`「空流 … 整体仍转为 502」+ 场景「补足终止块后返回 502 口径」—— 实现为**补最小可解析终端、不转 502**（`src/service/block_inject/frames.rs:1-9` + README §8.6；502 仅非流空体/非 JSON）。→ spec 更正。
  3. 同 spec `:92-115` Anthropic「五件套」写在「阻断/空流/正常结束」下 —— 实现**阻断 = 五件套**、**真空流 = 最小二帧**（`message_start`+`message_stop`）、**正常结束不合成**。→ 拆分为两个 Scenario 并区分。
  4. 同 spec `:181-192`「responses 系 SHALL 捕获**单层** `response.usage`」—— 实现/README 为**三级回退**（顶层 → `response.usage` → `response.response.usage`，`src/service/llm_gateway/usage.rs`）。→ spec 更正。
  5. 同 spec `:68-79` 与 `:193-207` 把 `slow`/`fast` 描述为「**配置**双速档」（「配置为 slow 档」）—— 实现为 `Speed::Slow/Fast` 由 **`audit_mode` 派生**（`src/handler/llm/pump/spawn/setup.rs:108-111`：`Off → Fast`，否则 `Slow`），非独立配置项；且原文「fast 聚合利于脱敏完整性」的理由与派生方向相反（Fast 用于审计关闭时）。→ spec 改为「由 `audit_mode` 派生的两档发送语义」并更正理由；移除不存在的「配置档」表述。
  6. 同 spec `:229-247`「空体 502 四分支一致性」仍写「流式空流（零有效分片）SHALL 按 FIX-2 注入终止后转 502」+ 场景「流式空流注入转 502」—— 与第 2 项同一事实矛盾（仅**流式**分支为假；非流 `status==200` 空体/非 JSON 的 502 分支为真，须原样保留）。→ spec 仅更正该流式分支。
- **R5-20（P3）`redaction` spec 行号引用漂移**：`:283`（`resolve_upstream` 称「取自 `src/handler/llm/dispatch.rs:145`」——定义在 `src/service/llm_gateway/mod.rs`，调用在 `dispatch.rs` 选上游处）；`:292,372`（称 `x-veil-*` 由 `src/handler/llm/mod.rs:45-46` 剔除——实际通用内部头剔除在其后，会话键头剔除在 `dispatch.rs`）；`:292`（`previous_response_id` 写入点行号与当前实现不符）；`:376`（`ConversationScopeStore` 装配区间 `src/state.rs:37-71/88-163` 已漂移）。修复：全部改为**符号锚点**（函数名 + 语义）或校正后的行号，降低再次漂移。
- **R5-21（P3）`stream-protocol-parity` 多 choice 措辞**：`openspec/specs/stream-protocol-parity/spec.md:98-110` 写「SHALL NOT 仅覆盖 choice 0 而静默丢失其它 choice」—— 实现为**显式声明**的单 choice 覆盖（`src/service/block_inject/frames.rs:35-37` + `block_frame_choice_coverage` 测试锁定 + README TRN-6）。→ spec 改为「按显式声明覆盖范围（当前为 `index==0` 单 choice；审计阻断为流级动作）」并与实现同字（消除「静默」歧义）。
- **R5-22（P3）README 实现指针与注释残留**：`README.md` 多处实现指针因 `veil-stream-terminator-convergence` 收敛而过时（中途断流终端仍指 `pump/spawn.rs`+`synth_flush.rs`，未指 `spawn/terminator.rs` 单入口；空流守门仍指 `spawn.rs`；`dispatch.rs` 行号锚点漂移）；`src/handler/llm/pump/spawn/setup.rs` 附近旧「七 bool」清单注释易被误读为现存状态字段（实际唯一状态在 `StreamTerminator`）；`src/handler/llm/nonstream.rs` 与 `src/service/llm_gateway/hop.rs` 引用**不存在**的符号 `hop_filtered_total`（真实为 `record_hop_filtered`/`hop_filtered_count`）。修复：更新指针为符号锚点、澄清旧 bool 注释、改正幽灵符号名。

- **R5-37（P3）占位符说明注入「容器缺失」三协议不对称未声明**：`src/service/llm_gateway/placeholder.rs` 的 schema 判定三臂不对称——Anthropic 缺 `system` 时**自动新建并注入**；Chat 要求 `messages` 为数组（缺失即**不注入**）；Responses 要求 `input`/`instructions` 至少其一存在（双缺 → warn 后**不注入**）。后果：畸形/极简请求下 Anthropic 恒得说明，而 Chat/Responses 体内已含 token 却无说明（模型更易误读占位符）；该不对称仅在代码注释与单测中体现，canonical `llm-gateway`「占位符注入三条件」未声明。修复：canonical 补声明「容器缺失即不注入（Anthropic 例外：缺 `system` 时新建）」或在 Chat/Responses 侧对齐新建容器（决策 **D11**，取**前者**：不新建 `messages`/`input` 以免破坏上游 schema）。
- **R5-41（P3）canonical `llm-gateway` requirement 名与正文不一致**：canonical `openspec/specs/llm-gateway/spec.md` 的 requirement 名为「截断三态（唯一值）」（审查时点 `:116`），但其正文与白名单为**四态**（`silent_discard`/`open_ended`/`synthesized_failed`/`upstream_error`）——文档名实不符。本 change 原只治 `src/service/sse/meta.rs`/`src/service/metrics/aggregate.rs` 的陈旧「三态」注释，未登记该 canonical 名。修复：在 `llm-gateway` delta 以 `## RENAMED Requirements` 把 requirement 名收敛为「截断四态（唯一值）」（仅改 requirement 名，scenario 名不动），或显式登记该名为历史锚点；补文档一致性核对。spec 家：`llm-gateway` delta。
- **R5-42（P3）FIX-2 与流式 parity 跨 spec 未和解**：canonical `openspec/specs/protocol-compliance-fix/spec.md:20-37` 的 FIX-2 仍无条件写「Anthropic 依五件套顺序补」，canonical `openspec/specs/llm-streaming-parity/spec.md:42` 亦写「Anthropic SHALL 以五件套有序收尾」；而本 change 的 `llm-gateway` delta 新增「真空流最小二帧 / 正常结束不合成」并声称与 FIX-2「同字」→ 归档后互斥且真相源陈旧。修复：新增 `protocol-compliance-fix` delta 与 `llm-streaming-parity` delta，把 FIX-2/流式 parity 限定为「阻断 = 五件套；真空流 = 最小二帧；正常结束不合成」，与 `llm-gateway` delta 同字；删除或实质落实「同字」互引。spec 家：两个新 delta（`protocol-compliance-fix`、`llm-streaming-parity`）。
- **R5-43（P3）E4「流式恒 200」与 2xx 状态透传直接冲突**：canonical `openspec/specs/llm-critical-compliance/spec.md:80/90` 的 E4 requirement 与场景写「流式恒 200」，与 D4/R5-05（上游 2xx 状态透传）直接冲突；README §7.2 亦写「与流式恒 200 闭合对称」。修复：新增 `llm-critical-compliance` delta，把 E4 的「恒 200」限定为「阻断帧**正文**对称（状态码随上游 2xx 透传）」（决策 D15），并同步 README §7.2；补单测。spec 家：新 delta `llm-critical-compliance`。

### 五、结构收敛（有界）（`ARCH`，能力：`architecture-cleanup` / `admin-ratelimit-contract`）

- **R5-23（P3）JSON 解析旁路中央 helper**：`src/service/json_walk.rs:24-27` 提供 `strip_bom`/`jloads` 单一入口，但生产侧仍有旁路直调（`src/handler/llm/dispatch.rs:275`、`src/handler/llm/nonstream.rs:540`、`src/handler/llm/pump/spawn/frame_feed.rs`、`src/service/audit/policy.rs` 等）→ BOM 前缀体在旁路解析失败并静默走回退分支。修复：生产路径统一经 `jloads(strip_bom(..))`（非流/调度两处优先），保留行为（BOM 体从「解析失败回退」变为「正常解析」）。
- **R5-24（P3）协议分派分散 → `ProtocolSpec`（两步）**：`src/service/llm_gateway/protocol.rs:48-53` 以注释列出「新增协议需同步的 8 个文件」，但差异仍散落为 `match protocol`/`is_anthropic()` 分支（R5-01 正是这类分散导致的协议泄漏）。修复（决策 **D8**）：**第一步**落 `ProtocolSpec` 常量表的最小字段（至少 `done_terminator: Option<&str>` 与 `terminal_event_types`），`Protocol::spec()` 单一来源替换 `[DONE]` 判定并迁移**明确列出的**终端集合消费者（`event.rs::is_terminal_event` 等，直接闭合 R5-01；现有至少四组协议事件集合，其余不迁移，见 design D8）；**第二步**（全量字段迁移）登记为**后续独立 change**（本 change 非目标）。
- **R5-25（P3）转发头 preamble 三处重复**：`src/handler/llm/mod.rs`（`forward_headers`）、`src/handler/llm/dispatch.rs`、`src/handler/llm/nonstream.rs` 各自重复「剥内部头 + 选 `DECODE_ENABLED` + 计数」三步。修复：抽单一 `forward_headers_for(dir)`，调用点仅传方向；`hop.rs` 既有 `filter_hop_headers_counted` 保持唯一实现。
- **R5-26（P3）阻断臂「拒绝即消费」缺结构化保证**：`event_loop.rs` 的 `apply_reject_block(...)` 返回 `false` 时**不 return**，落至正常帧还原/放行路径并 `select_emit` 下发 → 若谓词集合失配，内容会在阻断终端**之后**透出。当前全部 `reject_reason` 设置点都在 `is_audit_due_event`/`is_index_complete` 门内故不可达，但这是无编译期保护的隐式不变量。修复：`apply_reject_block` 恒返回「已消费」（或调用点无条件 `return`），把不变量结构化。
- **R5-27（P3）`/_admin/health` 限流豁免缺行为断言**：`src/service/admin/ratelimit.rs:40-46` 的 `admin_rate_exempt_paths()`/`is_rate_exempt()` 在生产侧**仅**被 `src/handler/admin.rs:362` 的 `debug_assert` 与单测引用（release 下 `debug_assert` 被剥离）；豁免实际由 health handler **不调用** `rate_limited` 实现，故该 `debug_assert` 是自证式（断言常量含该路径，而非断言「health 不被限流」）。修复：补**行为断言**（连续 11 次 `/_admin/health` 不返回 429，`/_admin/metrics` 第 11 次返回 429 带 `retry-after`），使 canonical `admin-ratelimit-contract`「唯一豁免集」条款有可验证落点；`is_rate_exempt` 保留为声明式单一来源。

### 六、复核为误报 / 有意保留（登记，不修）

- **R5-28（误报更正）`Speed::Slow/Fast` 双速确实存在**：`src/service/sse/emit.rs:61,81-99` 实现 `Slow`（见文即吐）与 `Fast`（攒至标点边界或 4KB）；探索代理「全仓无 slow/fast 实现」为大小写/目录检索偏差导致的误报。**保留**「口径措辞需修」（并入 R5-19.5）。
- **R5-29（有意保留）`audit_hold.rs` 垫片与 `state.rs` 重导出**：`src/service/audit_hold.rs` 为 DEPRECATED 兼容垫片，且 `src/service/mod.rs:121` 的 `audit_hold_zero_production_refs` 测试**锁定「零生产引用」**；`src/state.rs:31` 的 `SQLITE_BUSY_TIMEOUT_MS` 重导出注释自述「防外部引用断裂」。二者均为**有意保留**，删除会与既有声明/测试冲突 → **不修**。
- **R5-30（误报更正）`tool_responses` 两函数非重复**：`responses_derived_tool_kind`（匹配 **delta 事件类型**：`code_interpreter_call_code`/`shell_call_command`/`mcp_call_arguments`/`custom_tool_call_input`/`computer`）与 `responses_item_tool_name`（匹配 **item 类型**：`code_interpreter`/`shell`/`mcp`/`computer`/`custom_tool`）匹配域与判定顺序均不同（后者 `custom_tool` 在末位），合并为表会改变行为 → **不合并**，仅登记「同域不同形」为设计现状。
- **R5-31（误报更正）`arch-docs-cleanup` spec 存在**：`openspec/specs/arch-docs-cleanup/spec.md`（4 requirements）实际存在，README §7.7 对其的引用**有效**，探索代理 C17 判断有误 → **不修**。
- **R5-32（误报更正）终端合成已单入口**：`veil-stream-terminator-convergence`（`f10eae6`）已把阻断/终止帧决策收敛为 `StreamTerminator`（`src/handler/llm/pump/spawn/terminator.rs` 的 `plan_*` + `commit`），`frames.rs` 仅定义帧、`synth_flush.rs` 仅发送计数 → 探索代理「终端合成仍在四层各断言」为未计入最近重构的误报 → **不修**（R5-24 的 `ProtocolSpec` 属另一维度）。
- **R5-33（后续独立 change）pub 全域暴露系统性审计**：全仓 `pub` + glob 重导出（`src/service/mod.rs`、`handler/llm/mod.rs`、`config.rs` 等）使 `cargo check` 对「公开但无人用」符号失明（实测 `dead_code`/`unused` 警告 0 条）。收紧可见性涉及 70+ 文件与测试引用面，**登记为独立 change**（非目标），本 change 仅保留对**已确认零引用且无声明保护**符号的处置（本次复核后为零项）。
- **R5-34（已排查无项）**：孤儿模块/文件（0）；注释掉的代码块（0）；`TODO/FIXME/HACK`（仅历史闭环声明，0 可行动项）；`#[allow(dead_code)]`（0）；生产 `todo!`/`unimplemented!`/`unreachable!`（0）；生产裸锁 `unwrap`（0，`lock_or_recover` 全覆盖）。
- **R5-38（误报更正）指标时钟 `unwrap` 为测试代码**：`src/service/metrics/summarize.rs` 的 `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()` 位于 `#[cfg(test)]` 的 `test_support` 模块内（非生产路径）；生产指标时钟读取（`metrics/store.rs`/`metrics/sample.rs`/`admin/state.rs`）已用 `.map(...).unwrap_or(0)` → **不修**（对应 R5-18 已收窄为仅脏数据失真）。

## Capabilities

### New Capabilities

无（本 change 只修改既有 capability）。

### Modified Capabilities

- `admin-ratelimit-contract`: `/_admin/health` 豁免补行为断言（连续放行 vs 第 11 次 429）。
- `architecture-cleanup`: 已终端后收尾命中 `Block` 的语义登记（不注入第二终端 + 保留 `block_injected` + warn/计数，修订行为保持条款）；生产 JSON 解析统一经 `jloads(strip_bom)`；`ProtocolSpec` 最小字段单一声明（`done_terminator`/`terminal_event_types`，仅迁移明确列出的消费者）；转发头 preamble 单一 helper；阻断「拒绝即消费」结构化。
- `docs-contract-sync`: README 实现指针改符号锚点、旧七 bool 注释澄清、幽灵符号 `hop_filtered_total` 更正；行号引用→符号锚点转换（含被改 requirement 的硬行号，归 R5-20/R5-22/D14）。
- `docs-test-parity`: 源码注释指针准确（`hop_filtered_total`、`setup.rs` 旧 bool 清单、`meta.rs`/`aggregate.rs` 陈旧「三态」注释、`config/env_parse.rs`/`main.rs`/`tool.rs` 注释）。
- `llm-critical-compliance`（新）: E4「流式恒 200」限定为「阻断帧**正文**对称（状态码随上游 2xx 透传）」，与 R5-05/D4/D15 同字；README §7.2 同步。
- `llm-gateway`: `stream_options` 注入范围收窄为仅 Chat；空流不转 502（补最小终端）；Anthropic 阻断五件套与真空最小终止分野；非流 usage 三级回退；`Speed` 由 `audit_mode` 派生的措辞更正；占位符说明注入「token 首次出现那轮允许前缀增长」边界登记与「容器缺失即不注入（Anthropic 新建例外）」声明；截断 requirement 名「三态」→ 四态收敛或登记（R5-41）。
- `llm-protocol-hardening`: `[DONE]` 短路仅对 Chat 生效（非 Chat 视为非事件，交终端合成产出恰一终端）；Anthropic `error` 终端记 `upstream_error`；工具桶索引**有界哈希溢出桶**与 legacy `function_call` 桶号修正。
- `llm-streaming-parity`（新）: 「Anthropic SHALL 以五件套有序收尾」按「阻断五件套 / 真空最小二帧 / 正常不合成」三态限定（R5-42），与 FIX-2 及 `llm-gateway` 同字。
- `observability-admin`: 会话键回退/换键 warn 与计数；`previous_response_id` 写回失败计数；`PreviousResponseMap` 容量独立化与逐出计数。
- `protocol-compliance-fix`（新）: FIX-2 从无条件五件套收敛为「阻断五件套 / 真空最小二帧 / 正常不合成」（R5-42），与 `llm-gateway`/`llm-streaming-parity` 同字。
- `redaction`: 第 3 级稳定前缀不接受 Responses 标量 `input`；协议原生键与稳定前缀字段按协议白名单；会话键头**无条件**剔除；`PII_SCOPE_KEY_HEADER` 启动期保留名校验（R5-40）；`register` 熵源故障 fail-closed；请求/响应表序号空间分离；行号引用改符号锚点；缓存稳定性边界声明补齐（含 MUST NOT 承诺清单扩展）。
- `runtime-robustness`: 配置文本校验字节级安全（不得 panic）；指标聚合脏数据显式告警。
- `stream-fidelity-fix`: 流式上游 2xx 非 200 状态透传；审计 hold 字节计数饱和。
- `stream-protocol-parity`: 阻断帧多 choice 措辞与显式单 choice 声明同字；Responses 流式 model 取 `response.model` 三级回退；hold 放行的 `sequence_number` 饱和安全；三协议阻断帧 `model` 回显（R5-39）。

## Impact

- **代码面**：`src/handler/llm/{dispatch,rewrite,nonstream,mod}.rs`、`src/handler/llm/pump/{event.rs,spawn/{event_loop,setup,terminal}.rs}`、`src/service/llm_gateway/{protocol,usage,tool}.rs`、`src/service/block_inject/frames.rs`、`src/service/redaction/{conversation_key,leaf}.rs`、`src/service/pii/scope.rs`、`src/service/audit/hold.rs`、`src/service/metrics/{aggregate,summarize}.rs`、`src/service/sse/emit.rs`、`src/config/validate.rs`、`src/state.rs`。
- **契约面（spec）**：`admin-ratelimit-contract` / `architecture-cleanup` / `docs-contract-sync` / `docs-test-parity` / `llm-critical-compliance`（新） / `llm-gateway` / `llm-protocol-hardening` / `llm-streaming-parity`（新） / `observability-admin` / `protocol-compliance-fix`（新） / `redaction` / `runtime-robustness` / `stream-fidelity-fix` / `stream-protocol-parity` 共 14 个 canonical capability 的 delta。
- **用户可见行为变更（非 BREAKING，需 README/release note 登记）**：Responses 流式 model 分桶更正；Anthropic `error` 终端计入 `upstream_error`；流式三协议阻断帧 `id`/`model` 回显（原 `blocked-0`/`unknown_model`）；SSE 泵透传上游 2xx 状态；`conversation` 模式下 Responses 标量 `input` 形态**改判为逐请求**（原静默换键 → 现明确降级并计数）；熵源故障改 fail-closed（新增 502 语义）；`PII_SCOPE_KEY_HEADER`（含自定义非 `x-veil-` 名）在**所有模式**转发前剔除（原仅 `conversation` 模式）。
- **门禁**：须保持 `bash scripts/gate.sh` 七步全绿；`scripts/check_doc_paths.py` 对新增/修改的 spec 行号引用须可解析；新增/修改文件须守 800 行红线（`event_loop.rs` 现 789 行、`tool.rs` 现 748 行、`conversation_key.rs` 413 行、`redaction/scope.rs` 675 行——改动须避免越线，必要时按既有 B-2 口径抽取 sibling 模块）。
- **风险**：R5-01 的协议门控若误伤合规上游的 `[DONE]`（Chat 正常路径不受影响，因门控仅排除非 Chat）；R5-06 改判会使部分 Responses 客户端**失去**原本（错误地）拥有的会话级稳定 → 属**修正**但需 README/spec 同步并在 release note 明示；R5-14 的 fail-closed 会在熵源故障时**拒绝服务**（决策 D5 已定档：`E_PII_UNAVAILABLE` + 502）；R5-40 的保留名校验会在误配头名（如 `authorization`）时**拒启动**（属 fail-closed 修正，需 README 环境变量表登记）。

## Non-goals

- **不重开** r2/r3/r4 已声明的有意偏离（Anthropic 中途断流不补终端、跨槽放行序、`x-veil-protocol` 内联等）。
- **不删除** `audit_hold.rs` 兼容垫片与 `state.rs` 重导出（测试锁定的有意保留，见 R5-29）。
- **不合并** `tool_responses` 两派生函数（匹配域不同，见 R5-30）。
- **不做** pub 全域可见性收紧（独立 change，见 R5-33）。
- **不做** `ProtocolSpec` 全量字段迁移（仅落最小字段闭合 R5-01，第二步独立，见 R5-24）。
- **不新增**下游可观测响应头（不引入 `x-veil-scope`；仅 warn + 内部计数，见 R5-08/D9）。
- **不改**既有阈值（`NONSTREAM_MAX_BYTES`、审计上限、`PII_MAX_ENTRIES`、`PII_SCOPE_TTL_SECS`、`PII_SCOPE_MAX_CONVERSATIONS` 默认值、SSE 并发、admin 限流）。
- **不新增** crate 依赖；**不改**上游缓存命中率测量口径（wont-measure 保持）。
- **不校验** Anthropic 扩展思考签名（既有残余限制声明不变）。

## 待核对（登记，不臆断）

- 本 change 的 `file:line` 均为审查时点（`e6f678c`）实测值；apply 期须以**符号锚点**复核后落码（行号仅作导航）。
- **R5-02 已锁定实现（无条件性）**：`stream_model_of` 按 `v.get("model")` → `v["message"]["model"]` → `v["response"]["model"]` **三级回退**，与 `extract_conv_id` 的 `response.id` 回退对称；**不**保留「若无上游样本再定」的条件性，apply 期以官方 Responses SSE 形态与 conformance 用例复验即可。`design.md` Open Questions 与之保持一致（无未决项）。
- R5-04 的 `upstream_error` 四态白名单落点已在 r4（N）覆盖进程内/落盘/快照/导出四处；本 change 仅补**触发面**（Anthropic `error`），apply 期须复验四处均自动生效（无需再加列）。
- 探索代理上报的「原生键无协议门控」具体分歧面（Chat 吃 `previous_response_id`、Anthropic 吃 `prompt_cache_key`）须在 apply 期写**双向**单测锁定（正例命中 + 反例不命中）。
- **工具约束（场景名不可重命名）**：MODIFIED delta 中的 canonical scenario 名由 `openspec validate --strict`（`findMissingCurrentScenarios`）按多重性校验，**不可重命名或删除**；同名的 `## REMOVED` + `## ADDED` 对亦被拒绝。legacy 场景名（如「Anthropic 三件套终止」）仅作历史锚点，语义以正文（WHEN/THEN）为准；标题与正文不一致者须改**正文**或新增场景，不得改旧场景名。
- **P3-25 归属**：`docs-contract-sync` delta 新增的「在界校验≠内容一致性 / 符号锚点优先」段为 prose-only，显式归属 R5-22（D14），随该能力的行号→符号锚点转换一并落地。
