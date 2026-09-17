# Design

## Context

见 `proposal.md` — Why。本节只记录塑造方案实现的现状与约束。

- **成熟度**：仓库已历 r2/r3/r4 三轮审计修复 + `veil-gateway-transport-fidelity` + `veil-stream-terminator-convergence`，门禁 `bash scripts/gate.sh` 七步全绿；canonical `openspec/specs/` 约 90 个 capability。故本 change 的目标是**最小正确性收敛**，不重开已声明偏离。
- **文件体量红线**：`scripts/check_file_sizes.py` 硬上限 800 行。本 change 需改动的热点文件当前行数：`src/handler/llm/pump/spawn/event_loop.rs` **789**（最紧）、`src/service/llm_gateway/tool.rs` 748、`src/service/llm_gateway/placeholder.rs` 738、`src/service/redaction/scope.rs` 675、`src/handler/llm/dispatch.rs` 670、`src/handler/llm/rewrite.rs` 658、`src/service/llm_gateway/mod.rs` 644、`src/handler/llm/nonstream.rs` 600、`src/service/redaction/conversation_key.rs` 413。**任何净增代码须先按既有 B-2 口径抽取 sibling 模块**（先例：`tool_responses.rs` 即为满线抽取产物）。
- **文档门禁**：`scripts/check_doc_paths.py` 校验 README/spec 中的 `src/...` 路径与行号引用可解析。既有实践：spec 内的行号引用会随重构漂移（本 change 的 R5-20/R5-22 即此类），故新写入的引用**优先符号锚点**（`path::symbol`）。
- **既有声明必须尊重**：`audit_hold.rs` 兼容垫片有 `audit_hold_zero_production_refs` 测试锁定；`state.rs` 的 `SQLITE_BUSY_TIMEOUT_MS` 重导出注释自述「防外部引用断裂」；`tool_responses.rs` 两派生函数匹配域不同。这些**不是缺陷**（见 proposal §六）。
- **协议现实**：三对话协议 + `NonDialog` 透传；`Protocol` 判定与 `stream_options` 注入的真相源是 `src/service/llm_gateway/protocol.rs`；终端决策的**单一所有者**是 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator`（`plan_*` + `commit`），帧定义仍在 `src/service/block_inject/frames.rs`，发送/计数在 `synth_flush.rs`/`terminal.rs`。
- **会话级作用域**：`PII_SCOPE_MODE=conversation` 时键推导四级（显式头 → 协议原生键 → 稳定前缀 → 逐请求），存储为 LRU+TTL 的 `ConversationScopeStore`，token 稳定性依赖「同会话同明文复用 `PiiScope` 内既有 token」。

## Goals / Non-Goals

**Goals**

- 闭合协议保真缺口（`[DONE]` 跨协议泄漏、Responses 流式 model 分桶、流式 Chat 阻断帧 conv/model、Anthropic `error` 观测、SSE 泵状态码）。
- 让 `conversation` 模式在「Responses 标量 `input`」形态下**不再静默失效**（明确降级 + 可观测），并使原生键/前缀字段**按协议收窄**到 canonical 已声明的集合。
- 消除可被配置/上游触发的 panic 与 fail-open：占位符文案校验、`register` 熵源故障、序号空间饱和、索引截断、hold 算术、指标脏数据。
- 让 canonical spec 与 README 与实现**同字**（含最近终端收敛带来的指针漂移）。
- 有界结构收敛：JSON 解析单一入口、`ProtocolSpec` 最小字段、转发头 preamble 单一 helper、拒绝即消费结构化。

**Non-Goals**

- 不重开 r2/r3/r4 已声明偏离；不删除有意保留的兼容垫片/重导出；不合并 `tool_responses` 两函数。
- 不做 pub 全域可见性收紧、不做 `ProtocolSpec` 全量字段迁移、不新增下游可观测响应头、不新增 crate、不改既有阈值。
- 不引入配置/默认值 BREAKING：`PII_SCOPE_MODE` 默认 `request` 行为逐项不变；三对话协议的正常/合规路径输出不变。但 **6 项用户可感知行为变更**（含 R5-14 新 502 `E_PII_UNAVAILABLE` 语义、R5-36 无条件剔头）须在 README/release note 明示。

## Decisions

### D1 — Responses **标量** `input` 不获得会话级作用域（采纳 Oracle 建议）

**决定**：第 3 级（稳定前缀）仅接受 turn 锚点可确定的形态——Chat/Anthropic 的 `messages` 数组首个 `role=user`、Responses 的**数组** `input` 首条 `role=user`；`input` 为**字符串**时 `extract_first_user` 返回 `None` → 第 3 级不可命中 → 落第 4 级逐请求 + 既有 `record_request_fallback()` 计数，不报错。

**理由**：标量 `input` 是「当前轮全文」，每轮增长 → HMAC 输入每轮不同 → 每轮新建会话键与 `PiiScope`：既使 token 失稳（前缀字节变化），又每轮向容量 1024 的 store 插入新条目挤出他租户会话；且无任何报错/回退计数（静默）。改为明确降级后：观测可见、容量可控、语义与 canonical「条件性稳定」一致。

**备选**：(a) 保留现状并仅补文档——被否，因它让 `conversation` 模式对该类客户端**静默不生效**且消耗 LRU 预算；(b) 对 `canonical_stable_prefix` 另寻锚点（如取 `instructions`）——被否，`instructions` 亦随轮次可变，会制造新的不稳定来源。

### D2 — 非 Chat 协议的 `data: [DONE]` 视为**非事件**（采纳 Oracle 建议）

**决定**：`[DONE]` 短路分支门控 `env.protocol.is_chat()`。非 Chat 时：不置终端、不透出，交既有中段/空流合成路径产出恰一协议终端。

**理由**：现状下 Responses 下游会收到**零个** `response.*` 终端（`mark_upstream_terminal` 令两条合成分支双短路），Anthropic 下游收到协议外事件，违反 canonical「Responses 恒恰一终端」。门控后对合规上游（官方终端 + 尾部 `[DONE]`）行为不变——那种 `[DONE]` 本来已被终端守卫丢弃。

**备选**：把 `[DONE]` 归一为各协议终端帧——被否，会伪造上游未表达的完成语义（Responses 需 `response.completed` 全字段，`[DONE]` 不携带）。

### D3 — 已终端后收尾审计命中 `Block`：不注入第二终端，但保留阻断语义与观测（采纳 Oracle 建议）

**决定**：保留 `f10eae6` 后的新行为（`plan_block` 在非开态返回 `None` → 不注入第二终端），但：① 仍将 `PumpOutcome.block_injected` 置 `true`（语义 = 「本次收尾审计判定为阻断」）；② 追加 `warn!`（不含明文/token）；③ 计入 `audit_blocks`；④ 修订 canonical `architecture-cleanup`「流式阻断/终止帧注入单一所有者」：以显式 Scenario 登记该分支，替换「`PumpOutcome` 逐项与重构前一致」的绝对表述，并加单测锁定。

**结构性要求（Oracle 裁决，tasks 1.7 必须落地）**：现有 `StreamTerminator` **无法**表达「`block_injected=true` 且 `terminal_sent=true` 且 `terminal_injected=false`」组合——`block_injected()` 仅在 `TerminalState::{Blocked,EmptyStream}` 为真（`terminator.rs:112-117`）；上游已终端后 `state == UpstreamTerminal`，`plan_block` 于 `:177-179` 非开态返回 `None`；`commit(Block)` 会顺带 `mark_terminal` 置 `terminal_injected`（`:324-331`），违反「不注入第二终端」。故修法**必须新增独立状态位/新 state**（不触发 `mark_terminal`、不改 `terminal_injected`），并在收尾命中 `Block` 的分支显式置该位；`plan_block` 签名与两个调用点（`apply_reject_block`、`terminal.rs:154-160`）都要相应处理。另：`audit_blocks` 计数来自 `terminator.audit_blocked()`（`finish.rs:68`），该位仅由 `note_sticky_rejected()`（`terminator.rs:150-153`）置位，**与 `block_injected` 不是同一位** → 必须显式调用 `note_sticky_rejected()` 或等价计数路径，不能只改 `block_injected`。

**理由**：双终端会破坏「恰一终端」；但当前实现把该次阻断变成**完全不可观测**（无帧、无计数、无日志），且危险参数随 `agg.clear()`/`pending_tool_frames.clear()` 丢弃。保留语义位 + warn + 计数即可在不牺牲协议正确性的前提下恢复可观测性。canonical 的「行为保持」绝对条款与已落地的收敛相矛盾，必须以 Scenario 显式化而非依赖 commit message。

**备选**：(a) 恢复旧行为（注入阻断帧 + `mark_terminal`）——被否，破坏终端唯一性；(b) 仅改 canonical 不提观测——被否，留下「阻断发生却无痕」的盲区。

### D4 — SSE 泵透传上游 2xx 原状态（采纳 Oracle 建议）

**决定**：`build_sse_response` 增状态码入参，透传上游 2xx 状态（含 `201/202/206`）；`<400` 入泵门**不放宽**。

**理由**：与非流臂（保留上游状态）口径一致；上游经缓存/代理返回 `206` 时下游不应被改写为 `200`。

**备选**：显式声明「流式恒 200」为有意差异——被否，无业务理由，且非流已保留状态。

### D5 — `register` 失败：token 形态静默跳过，熵源/内部故障 fail-closed（采纳 Oracle 建议）

**决定**：`PiiScope::register` 的两类失败分离——「值本身即 token 形态」保持静默跳过（既有语义）；「CSPRNG 不可用 / 内部故障」记 `warn!`（不含明文/token）+ 指标，并**fail-closed**：该请求不转发未脱敏体，返回 **502 + `E_PII_UNAVAILABLE`**。错误码**定档**：在 `src/error.rs` 新增 `E_PII_UNAVAILABLE` 变体并映射 `502`（不再「apply 期定名」，见 Open Questions 已随之收敛）；码字面集中定义于 `src/error.rs`，spec 只引用码名。

**链式改造要求（Oracle 裁决，tasks 3.2 必须落地）**：`register` 在 `leaf.rs:208-211` 的 **walk 回调**内（`redact_leaf_inner` 返回 `String`），经 `Scope::redact_request_with_report → (String,bool)`、`request_rewrite → RewriteOutput`（`rewrite.rs:99-105`）直到 `gateway_serve` 目前**无 `Result` 出口**。fail-closed 须把该链改为可失败（返回 `Result`/错误）**或**引入等价 side-channel 失败标志并沿链上传；仅在 `register` 处 `warn` 无法让调用方拒绝请求。**响应侧同样适用**：`redact_response_new_pii*`（`event_loop.rs:669-677`）的 `register` 失败也须 fail-closed（否则响应侧新检出 PII 未注册即明文外泄），tasks 3.2 须显式覆盖该调用点。

**理由**：熵源故障时当前实现**静默把明文原样转发上游**——安全路径 fail-open 且不可观测。fail-closed 与本项目「脏配置/异常态拒绝服务而非降级」的总体口径一致。

**备选**：(a) 仅 warn + 计数但继续转发（fail-open）——被否，与「脱敏网关」的安全目标冲突；(b) 启动期预检熵源——不足，故障可能运行期发生。

### D6 — 请求表与响应表**分设序号空间**（采纳 Oracle 建议）

**决定**：请求侧与响应侧各自使用独立序号空间；可观测不变量为「**一条目 ↔ 一序号、不跨表回查**」。同步修正 canonical `redaction` 的聚合上界条与 README §6.3「`used_seqs` = 全部在用序号」口径。实现式枚举（独立空间/跨表校验）不在 spec 中二义列出，spec 只声明该可观测不变量。

**理由**：现状两表各限 1000 却共用 1..=1000：并集饱和后 `alloc_seq` 恒返回哨兵 `PII_MAX_ENTRIES+1`，多 token 共享序号 → `fuzzy` 还原（按序号回查）可能把截断形 token 映射到另一表明文（`PII_FUZZY_RESTORE=1` 时归错值）；且饱和时每次分配扫满 1000 步，与「均摊 O(1)」注释不符。

**备选**：把序号空间扩至两表之和——被否，治标且仍会在更高占用下饱和；保留哨兵但禁用 `fuzzy` 按序号回查——被否，削弱既有还原能力。

### D7 — 会话键头**无条件**剔除（采纳 Oracle 建议）

**决定**：`strip_conversation_header` 不再以 `pii_scope_mode.is_conversation()` 为前提；`request` 模式下自定义（非 `x-veil-`）头名同样在转发前剔除。

**理由**：canonical「会话键头不转发不入日志」为无条件条款，且自定义头名**不受** `x-veil-*` 前缀剥离的保护 → 现状在默认模式下会把它转发上游。

**备选**：把 canonical 条款限定到 `conversation` 模式——被否，泄露面与模式无关，收窄 spec 会保留隐患。

**配套（R5-40，防止无条件剔除放大配置误用）**：`PII_SCOPE_KEY_HEADER` 解析（`src/config/env_parse/pii_scope.rs:68-70`）当前仅要求非空、无任何命名约束。无条件剔除后，若运维把头名误配为 `authorization`/`x-api-key`/`api-key`/HOP 集/`host` 等，网关会在**所有模式**删除真实鉴权头再转发上游（静默断链）。故本 change 增加**启动期保留名校验**：命中保留名一律拒启动（fail-closed），或限定 `x-veil-*` + 显式放行清单；补单测。spec 家：`redaction` delta。

### D8 — `ProtocolSpec` 分两步：本 change 只落**最小字段**（采纳 Oracle 建议，限定范围）

**决定**：第一步引入 `Protocol::spec()`（或等价只读常量表）并至少承载 `done_terminator: Option<&str>` 与 `terminal_event_types`，**直接替换** `[DONE]` 判定，并迁移**明确列出的**终端集合消费者（`event.rs::is_terminal_event` 等，见 tasks 1.1/1.2）；全量字段迁移（`line_terminator`/`accepts_stream_options`/`empty_stream_frames`/`block_frames`/`synthetic_status` 等）登记为**后续独立 change**（非目标）。

**范围限定（Oracle 裁决）**：现有协议相关事件集合**至少四组、互不相同**——`event.rs:244-256`（真终端）、`:91-104`（粘滞抑制终端，含 `content_block_stop`/`message_delta`）、`:160-183`（Responses failed/incomplete/error）、`:261-263`（Chat error terminal）。单个 `terminal_event_types` 字段**不足以也不得**声称替换全部集合；只迁移明确列出的消费者，其余保留原判定（否则改行为）。`is_done_payload` 的其余调用点（`service/sse/parser.rs:402/432`、`pump/event.rs:131`、`event_loop.rs:255/362`）中，哪些必须迁移、哪些以「低层字符串判定、协议门控在消费点」声明为非目标，须在 tasks 1.1/1.2 逐一列明，避免 apply 期自由裁量。

**理由**：`[DONE]` 泄漏正是「协议差异散落在各文件分支」的产物；以最小字段先闭合该类缺口，收益确定、风险可控；全量迁移会触及 usage/tool/frames/placeholder/event_loop 五处，需独立设计与验证预算。

**备选**：本 change 直接做全量 `ProtocolSpec`——被否，与「最小正确性收敛」的范围相悖，且会显著抬高回归面。

### D9 — 会话作用域降级只做「warn + 内部计数」，**不新增**下游响应头（本 change 决策）

**决定**：warn/计数的范围**收窄为可判定事件**，三者均记 `tracing::warn!`（**不含**键值/头值/明文/token，遵守 canonical 日志不泄露条款）+ 内部计数，**不**引入 `x-veil-scope` 之类下游头：
1. 键推导返 `None` → 落 L4（逐请求）；
2. `store` 缺失（`dispatch.rs:150`）→ 回退；
3. 显式头**存在但非法**被静默丢弃（`conversation_key.rs:98-106` 超 256B/控制字符）。

**Non-Goal（不得写入 spec 制造不可验证条款）**：「中途换键/变级」因 `derive_conversation_key`（`conversation_key.rs:230-252`）与 `build_request_scope`（`dispatch.rs:138-192`）**完全无状态、每请求独立推导**，无「上次命中级别」记录，**不可观测**；本 change 不新增每租户/会话「上次级别」状态面。若后续需要，独立 change 交付。

**理由**：下游头会扩张用户可见契约（`x-veil-normalized` 已有先例，但每一枚都需 README/并发/兼容评估）；本 change 只需排障可见性，warn + 计数（经 `/_admin/metrics` 既有导出面）足够。若后续确有需求，另立 change 评估契约扩张。

**备选**：新增 `x-veil-scope: conversation|fallback|switched`——被否（非目标，避免契约扩张与「内部头是否应外露」的口径争论）。

### D10 — `PreviousResponseMap` 容量**独立**化（本 change 决策）

**决定**：新增独立上界（`PII_PREV_ID_MAX_ENTRIES`）；**未设置时回退到 `PII_SCOPE_MAX_CONVERSATIONS` 的生效值**（配置相关默认，而非钉死字面 `1024`——若运维设 `PII_SCOPE_MAX_CONVERSATIONS=2048` 且未设新变量，映射容量仍为 2048），并记录映射逐出计数。spec 只写「未设置时取 `PII_SCOPE_MAX_CONVERSATIONS` 的生效值」，不钉死数字。

**理由**：映射条目与 PII 会话条目生命周期/成本不同，耦合会让「PII 会话容量」调参意外影响 Responses 的 `previous_response_id` 解析成功率；默认值相等 ⇒ **零行为变化**，纯为解耦与观测。

**备选**：保持耦合、仅在 canonical 登记——被否，解耦成本极低且能消除一个隐蔽耦合。

### D11 — 占位符说明「容器缺失」不对称：**声明而非新建**（本 change 决策）

**决定**：保留现状（Anthropic 缺 `system` 自动新建；Chat 需 `messages` 为数组、Responses 需 `input`/`instructions` 至少其一，缺失即不注入并 warn），并在 canonical `llm-gateway`「占位符注入三条件」中显式声明。

**理由**：为 Chat 新建 `messages`、为 Responses 新建 `input` 会**伪造**客户端请求结构，可能破坏上游 schema 校验或改变语义（例如把无 messages 的请求变成含 system 的对话）；而 Anthropic 的 `system` 本就是可选字段，新建风险低（既有实现且经测试）。故按「风险最低者新建、其余声明」定档。

**备选**：三协议统一新建容器——被否（伪造结构）；统一不注入——会破坏既有 Anthropic 行为（BREAKING）。

### D12 — 工具桶索引：确定性**收敛**而非静默截断（本 change 决策）

**决定**：`tool.rs` 的索引提取不再 `as u32` 静默截断——越界值经 `try_from` 检测后**按原始索引摘要分入有界哈希溢出桶**（`hash(idx) % K`，`K` 为有界常量并**计入容量**）并记 `warn!`；legacy Chat `function_call` 在同一 choice 内改用**枚举下标**回退（与 `custom_tool_call` 同式）。措辞由「消除碰撞」改为「**不与合法索引碰撞**」。

**明确拒绝**：**固定单一溢出桶**——它把所有越界值重新撞进同一 hold 槽，与「消除不同取值碰撞同一桶」自相矛盾（只是把碰撞从低基数搬到溢出区）；亦不采用「丢弃越界条目」（漏审）。有界哈希溢出桶 + warn 是「不丢、不撞、可观测」的最小方案。

**理由**：截断 + 16 位掩码会把不同取值映射到同一 hold 槽，导致审计槽互相覆盖（漏审或错并）；而「丢弃越界条目」会漏审。

**备选**：(a) 拒绝整个请求——过重（畸形 index 不应致请求失败）；(b) 保留截断仅加注释——被否（碰撞仍在）。

### D13 — 已声明的「死代码/垫片」不做处置（本 change 决策）

**决定**：`audit_hold.rs` 垫片、`state.rs` 重导出、`tool_responses` 两函数均**保留**；pub 全域可见性收紧登记为**独立 change**。本 change 仅落实「零引用且无声明保护」的符号（复核后为零项）。

**理由**：前三者有测试/注释/文档的显式保留声明，删除会与既有契约冲突；后者的收益（可维护性）与风险（70+ 文件、测试引用面、doc-paths 检查）不成比例，需独立规划。

**备选**：借本轮一并收紧——被否，超出「最小正确性收敛」范围，且会把一个纯审计修复 change 变成大范围重构。

### D14 — 文档引用策略：**符号锚点优先**（本 change 决策）

**决定**：本 change 修正的 spec/README 引用一律改为符号锚点（`path::symbol`）或语义描述；无法用符号表达的（如阈值表行号）保留行号但须通过 `scripts/check_doc_paths.py`。

**理由**：本轮 R5-20/R5-22 的根因即行号漂移（终端收敛后 4 处指针过时）；符号锚点在重构后仍然可解析。注意 `scripts/check_doc_paths.py` 只校验路径/行号**在界**、**不校验符号是否存在**，故符号锚点须**人工复核**（Oracle 已证本 change 的 `llm-protocol-hardening` delta 引用 `tool.rs:222`/`:650-656`/`:572-581` 实为 `tool_responses.rs` 符号），并须在 tasks 6.3 加人工复核步骤。

### D15 — E4「流式恒 200」修订：SSE 2xx 状态透传须出 `llm-critical-compliance` delta（本 change 决策）

**决定**：D4/R5-05 的 SSE 2xx 状态透传与 canonical `openspec/specs/llm-critical-compliance/spec.md:80/90` 的 E4「流式恒 200」直接冲突。本 change 必须**同时**新增 `llm-critical-compliance` delta，把 E4 的「恒 200」限定为「阻断帧**正文**对称（状态码随上游 2xx 透传）」，并把 README §7.2「与流式恒 200 闭合对称」改为「与阻断体正文对称闭合」；补单测锁定「上游 2xx 非 200 + Block → 下游同状态码 + 阻断体」。

**理由**：若不修订，归档后 canonical 内 E4 与 `stream-fidelity-fix` delta 互斥，且 README 与实现矛盾（Momus P0-3 / R5-43）。

**备选**：放弃状态透传、保留恒 200——被否，与非流臂口径不对称且无业务理由（D4 已否）。

## delta 编写约束（工具强制，apply/archive 期不得违反）

- **场景名不可重命名**：MODIFIED delta 中的 canonical `#### Scenario:` 名由 `openspec validate --strict`（`findMissingCurrentScenarios`）按多重性校验，重命名/删除既有场景即失败；同名的 `## REMOVED` + `## ADDED` 对亦被拒绝（“Requirement present in both ADDED and REMOVED”）。`## RENAMED Requirements` 只改 **requirement** 名（`FROM:`/`TO:`），不改 scenario 名。
- **legacy 场景名仅作历史锚点**：如「Anthropic 三件套终止」等标题可能描述旧口径，语义以正文（WHEN/THEN）为准；标题与正文不一致时只改**正文**或新增场景，不得改旧场景名（Momus P0-4 的修法边界）。
- **delta 结构**：`## MODIFIED Requirements` / `## ADDED Requirements` / `## REMOVED Requirements` / `## RENAMED Requirements`；每 scenario 恰 4 个 `#`；既有 capability 不写 `## Purpose`。
- **`check_doc_paths.py` 能力边界**：只校验「路径存在 + 行号在界」，**不校验符号是否存在**；故 D14 的符号锚点转换须**人工复核**（Oracle 已证 `llm-protocol-hardening` delta 的 `tool.rs:222/650-656/572-581` 实为 `tool_responses.rs` 符号），并在 tasks 6.3 显式加人工复核步骤。

## Risks / Trade-offs

- **[D1 改判影响既有客户端]** 原本（错误地）依赖标量 `input` 命中会话级的 Responses 客户端会失去跨轮 token 稳定 → **缓解**：视为修正，README/spec/release note 明示「标量 `input` 形态不获得会话级作用域」，并保证回退路径行为与请求级完全一致（不报错、不误还原）。
- **[D2 门控误伤]** 若某上游在**官方终端之前**发 `[DONE]` 作为唯一终态（非合规），门控后 Responses 不再收到 `[DONE]`，改由合成产出 `response.failed` → **缓解**：这是协议正确行为（恰一终端）；conformance 用例覆盖「非 Chat 的 DONE 不短路」。
- **[D3 与 canonical 冲突]** 修订 canonical 的「行为保持」条款等于承认收敛引入了登记外偏差 → **缓解**：以 Scenario + 单测显式登记，并把偏差写进 canonical（不再只存于 commit message）。
- **[D5 fail-closed 拒绝服务]** 熵源故障时该请求被拒（502 + `E_PII_UNAVAILABLE`）而非降级转发 → **缓解**：熵源故障概率极低；warn + 指标可定位；错误码在 `src/error.rs` **新增变体**（属本 change 明示的契约面变更，须 README/release note 登记）；调用链改造（leaf walk 回调 → `request_rewrite` → `gateway_serve` 及响应侧）须保证失败可上传，tasks 3.2 覆盖。
- **[D3 状态机扩展]** 现有 `StreamTerminator` 无法表达目标组合，须新增独立状态位（不触发 `mark_terminal`）并显式 `note_sticky_rejected()` 计入 `audit_blocks` → **缓解**：tasks 1.7 给出状态位与计数落地方式；单测锁定「不注入第二终端 + `block_injected=true` + 计数递增」。
- **[D10 默认语义]** 若 spec 钉死字面 `1024` 而 design 取「生效值」，非默认配置下会出现非零行为变化 → **缓解**：spec 只写「未设置时取 `PII_SCOPE_MAX_CONVERSATIONS` 生效值」，不钉死数字；tasks 2.6 按此验证。
- **[文件体量红线 / 落地点]** `event_loop.rs` 789/800、`tool.rs` 748/800、`spawn.rs`/`terminal.rs` 亦接近 → **缓解（红线落地）**：R5-01/D8 优先落 `terminator.rs`/`protocol.rs`；tasks 1.2/1.5（`event_loop.rs`）与 3.4（`tool.rs`）**须先抽取 sibling 模块或给出净增行数预算**，任何净增前先跑 `python3 scripts/check_file_sizes.py`；先例 `tool_responses.rs`。
- **[D8 部分迁移的半成品风险]** 只落两个字段、且现有协议事件集合至少四组 → **缓解**：只迁移 tasks 明确列出的消费者（`is_terminal_event` 等），其余声明 Non-Goal 并保留原判定；在 `protocol.rs` 注释清单标注迁移进度与未迁移集合，**不**要求「全部判定点改 `spec()`」。
- **[D15 跨 spec 和解]** E4 与 README §7.2 若不同步修订，归档后与 `stream-fidelity-fix` delta 互斥 → **缓解**：新增 `llm-critical-compliance` delta（tasks 4.x），README §7.2 同批改。
- **[序号空间分离的兼容性]** 分离后同会话内序号可能跳号（请求侧不再受响应侧占用影响）→ **缓解**：序号本身是内部实现细节，token 字符串稳定性不受影响（`rand8` + 同值复用语义不变）；canonical 明确「序号不承诺连续性」。
- **[登记 N 项「不修」的审计覆盖度]** 读者可能认为漏修 → **缓解**：proposal §六 逐条给出「有意保留/误报」的证据与出处，design 决策 D13 记录处置原则。

## Migration Plan

1. **无数据迁移**：不涉及 sqlite schema 变更（R5-04 复用 r4 已加列的四态白名单）、不涉及配置项废弃（`PII_PREV_ID_MAX_ENTRIES` 未设置时回退到 `PII_SCOPE_MAX_CONVERSATIONS` 的生效值）。
2. **部署顺序**：单进程二进制，直接替换；无灰度要求。
3. **回滚**：`PII_SCOPE_MODE` 保持默认 `request` 时全部改动对该模式无影响（除 D7 的无条件头剔除与 D2 的非 Chat `[DONE]` 观感变化）；如需回滚，直接回退二进制即可，无状态残留。
4. **README/release note**：须列出 proposal §Impact 的**用户可感知行为变更**（R5-02 / R5-03+R5-39 / R5-04 / R5-05 / R5-06 / R5-14 / R5-36+R5-40，含新 502 `E_PII_UNAVAILABLE` 与无条件剔头/保留名校验）及 D9/D10 的观测面新增；其中 README §7.2（2xx 透传与 E4 正文对称）、§7.3/§7.7（R5-11）、§7.3/§7.11（R5-12）、§1 环境变量表（`PII_PREV_ID_MAX_ENTRIES`、`PII_SCOPE_KEY_HEADER` 保留名校验）必列。
5. **门禁**：`bash scripts/gate.sh` 七步 + `python3 scripts/check_doc_paths.py` + `python3 scripts/check_file_sizes.py` 全绿方可提交。

## Open Questions

无。所有会改变 spec、方案或任务拆解的决策（D1–D15）已定档：`E_PII_UNAVAILABLE` 码字面已锁定于 `src/error.rs`；R5-02 的三级回退已**无条件**锁定（无「待上游样本再定」的条件性）；D9 的「中途换键不可观测」已显式列为 Non-Goal（不写进 spec）。仅实现期非契约细节（抽取出的 sibling 模块名、D3 新增状态位的字段名）可在 apply 期按既有约定确定，不影响 spec 与任务拆解。
