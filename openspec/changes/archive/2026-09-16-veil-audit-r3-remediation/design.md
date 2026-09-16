# Design — veil-audit-r3-remediation

## Context

本 change 修正 2026-09-16 第三轮六维审查（范围 `494f2bc..2785974`）登记的 **P1×2、P2×13、P3×24** 全部发现。审查基线门禁全绿，故问题均为门禁未覆盖的二阶缺陷：热路径无界增长、跨请求还原授权缺失、规范真相源自相矛盾、声明强于实现、文档指针漂移。

决策来源：三份独立 oracle 咨询（协议保真簇、安全/资源/架构簇、残留补漏簇），共裁决 **32 项**，其中 **12 项以「不改代码 + 显式声明」收口**。三位 oracle 对审计前提提出 **8 处纠偏**（见「纠偏记录」），本设计全部采纳。

设计原则（沿用仓库既有哲学）：spec 即真相源；接受的偏离必须显式声明并锁测试；fail-closed 优先；不引入新依赖；不改变 wire 字节除非另有声明。

---

## Goals

1. 消除两项 P1：跨请求凭据明文泄露（B3）、非流 Responses 阻断体不合规（F-01）。
2. 消除 P2 资源上限缺口（D1/D2）、协议序号非单调（F-02/F-03）、规范真相源冲突（F-06）、声明与实现背离（ARH/D4 backstop）。
3. 使「声明」与「实现」可机械校验：凡收窄声明处，同批修订 canonical spec 文本；凡改造处，附锚点测试。
4. 全部变更在 `gate.sh` 七步下可验证，且不引入新 FAIL。

## Non-Goals

- 不重开 r2 已声明的有意偏离（Anthropic 中途断流不补终端、跨槽放行序、`ValidationCache`/`x-veil-protocol` 内联）。
- 不统一 `responses_block_frames`（`status:"completed"`）与 `responses_failed_frame`（`status:"failed"`）的流内语义（另立 change）。
- 不实现 `check_doc_paths.py` 的内容级语义校验（本次降级措辞 + 声明，见 D-DOC）。
- 不为 Go 工具链增加版本字符串硬校验（见 D-GO）。
- 不抽取 `frames.rs` 的信封格式 helper（会与 TRN-2 lossy 边界冲突，见 D-DECL-3）。
- 不引入新 crate 依赖。

## 可选后续（本 change 范围外，仅登记）

1. `src/service/redaction/leaf.rs:102,157` 的同类同步内置扫描经 `json_walk` 叶回调运行在 async 任务（输入为帧内字符串而非缝窗）——与 I-B 同源但量级不同；若 I-B 声明成立，可在后续 change 统一 offload 策略。
2. `frames.rs` 信封格式 5 处重复可抽 `sse_event(event, data)` 单一实现，需逐字保字节（含 `:75-81` 的双花括号 `format!` 转义）。
3. 流内 `responses_block_frames`（`status:"completed"`）与 `responses_failed_frame`（`status:"failed"`）的语义统一。

---

## Decisions

### 簇 A：协议合成帧与流式出口（RSP / CHC / ANTH / SSE）

#### A-1 · F-01（P1）非流 Responses 阻断体补齐必需字段

**决策**：修代码。`src/service/block_inject/frames.rs:348-351` 的阻断体改为与流式 `responses_failed_frame`（`:141-144`）同形：
`{id, object:"response", created_at, model, status:"failed", output:[], error:{message}}`。

- `output` 恒空数组（阻断为失败，无输出产物）。
- `model` 优先回显上游归一值，缺失才 `"unknown_model"`（与同函数 chat/anthropic 分支 `:306-310`、`:333-337` 同口径；不采用流式的硬编码 `unknown_model`）。
- `id` 优先上游 `id` → `conv_id` → 合成；`created_at` 优先上游 → now。
- `error` **仅保留 `message`**（不合成 `code`/`param`），与流式逐字段对齐。

**理由**：canonical `llm-protocol-hardening/spec.md:159-171` 明文要求合成响应对象含 `output`/`status` 等字段且不得掩盖；非流 chat/anthropic 分支已回显上游，仅 Responses 分支漏做。`upstream` 参数在调用点已传入（`frames.rs:396`）。

**锚点**：`frames.rs:348-351`（改）、`:141-144`（对照）、`:276-347`；调用点 `handler/llm/nonstream.rs:220-238`；conformance 断言 `scripts/api_conformance.py`。

**回滚**：单点还原 3 行。

---

#### A-2 · F-02 / F-03（P2）Responses 合成帧序号游标

**决策**：修代码。泵内新增 `responses_seq_cursor: Option<u64>`，规则精确定义如下：

1. **更新条件**：仅在协议为 Responses 且帧为可解析 JSON 时更新；取 `extract_responses_seq(v)`（`event.rs:246-251`）。
2. **更新公式**：`cursor = Some(max(cursor.unwrap_or(0), seq))`；**缺 `sequence_number` 的帧不更新**（README §7.2 断序容忍）；**回退值忽略**（只取 max）。
3. **更新时机**：每帧解析后、任何分流前（`event_loop.rs:181` 之后）——覆盖次要帧、被 hold 缓冲帧、被替换的 error 帧，即"已出现过的最大上游序号"。
4. **真空流**：零帧 → `cursor = None` → `base = 0`，维持现有 0..6 全序列与测试 `synth_frames_sequence_number_monotonic`（`frames.rs:555-573`）不变。
5. **中途注入/阻断**：`base = cursor.map_or(0, |c| c + 1)`，作为 7 帧序列起始；`synthesize_truncation` 传 `Some(base)` 给 `responses_failed_frame`（当前误传 `None`，`frames.rs:409-413`）。
6. **`type:"error"` 单帧**：保留既有行为——沿用上游 error 自带的 `sequence_number`（`event.rs:187`、`event_loop.rs:256-261`）；既有断言 `event.rs:571-580` 的 `"sequence_number":7` 不破。

**理由**：审计阻断在 `Speed::Slow`（审计开，`setup.rs:104-108`）下逐帧外发，阻断帧再发 0..6 必然倒退。`protocol_block_frames`（`frames.rs:99-117`）与 `synthesize_truncation`（`:405-414`）是仅有注入点，均可在调用点取得 base。

**风险**：游标过早推进（被丢弃帧抬高 base）只造成跳号；因 base 恒 `>` 所有已发序号，仍满足官方"单调、可跳号"语义。

**锚点**：`frames.rs:197-248`、`:134-153`、`:405-414`、`:99-117`；`pump/spawn/event_loop.rs:156-181`（游标更新点）、`:256-261`、`:541-547`；`pump/spawn/terminal.rs:31-64`、`:157-163`、`:244-256`；`pump/synth_flush.rs:54-59`、`:125-135`；`pump/spawn/setup.rs:111-133`；`pump/event.rs:246-251`。

**回滚**：复原 0..6 与 `None`。

---

#### A-3 · F-04（P3）Anthropic 阻断帧补 `message_start`

**决策**：修代码 + 修订 canonical。新增 `anthropic_block_frames_full(reason, index, conv_id)`，在既有四帧之前补恰一 `message_start`（空 `content`、null `stop_reason`、usage 全 0）；`id = conv_id 非空 ? conv_id : "blocked-0"`、`model = "unknown_model"`——**复用 `anthropic_vacuum_frames`（`frames.rs:433-455`）的构造口径**，抽出 `anthropic_message_start(id, model)` 单实现。旧 2 参函数委托新函数（`conv_id = None`）以缩减测试改动面。`message_stop` 保持空对象。canonical `gateway-protocol-fix/spec.md:22-29` 的"四件套顺序"同步修订为"五件套顺序"。

**理由**：官方 Anthropic Messages SSE 以 `message_start` 为首事件；缺失时严格 SDK 的流式累加器无初始 message 快照。conformance `api_conformance.py:717-729` 仅断言 `message_stop`/`content_block_stop` 存在，加首帧不破。

**同批 canonical 对齐（独立复核补充）**：除 `gateway-protocol-fix` 外，canonical `protocol-compliance-fix/spec.md:20-30`（FIX-2 三协议终止闭合，自述为终止权威定义）、`llm-gateway/spec.md:94-102`（三协议终止闭合，声明与 FIX-2 同字）、`llm-streaming-parity/spec.md:42`（还原与终止）仍述 Anthropic「三件套」终止；三处 SHALL 同批增补 delta 对齐五件套，否则归档后真相源自相矛盾。

**锚点**：`frames.rs:72-83`（改）、`:433-455`（复用形态）、`:99-117`（分派）；测试 `block_inject.rs:56-95`（改名/断言首帧）、`handler/llm/stream_fidelity_tests.rs:322-332`。

**回滚**：删首帧、复原 spec。

---

#### A-4 · F-05（P3）Anthropic 中途断流语义规范化 —— **不改代码**

**决策**：保持 `synth_flush.rs:108-113` 现状（仅记 `truncated_mode=open_ended`，不合成 `message_stop` 或任何终端数据帧），在 canonical `llm-protocol-hardening/spec.md:27-39` 增补一条 Requirement 明确**真空流**（零帧，走最小 `message_start`+`message_stop`）与**中途断流**（已发内容帧后异常 EOF，仅记观测）的分野，**SHALL NOT** 依历史行为伪造成功终止。

**理由**：README §7.2、§8.6 已同字声明，属有意设计；缺口仅在于 canonical spec 只写了真空流，真相源不完整。严格 SDK 侧 `message_stop` 缺失属已声明偏离。

**锚点**：`synth_flush.rs:108-113`（不改）；`frames.rs:421-455`（对照）；`llm-protocol-hardening/spec.md:27-39`。

**回滚**：无行为变更。

---

#### A-5 · F-07（P3）多行 data 出口保真

**决策**：修代码。出口将含换行的 data 载荷按 `\n` 拆为多条带 `data:` 前缀的行后再补块终止空行，与解析侧 WHATWG 单 `\n` 连接（`parser.rs:309`）严格互逆；**SHALL NOT** 输出无前缀裸行。

实现：抽 `pub(crate) fn data_frame(prefix: &str, data: &str) -> String` 于 `src/service/sse/` 门面，对 `data.split('\n')` 逐行输出 `data: <line>\n` 后补空行；替换 5 处：`frame_feed.rs:118`、`terminal.rs:196`、`terminal.rs:226`、`synth_flush.rs:31`、`event_loop.rs:674`（`:677` 的 `[DONE]` 无多行问题，可选同用）。`event:`/`id:`/`retry:` 信封前缀不受影响。

**理由**：JSON 载荷经 `json_aware_line` 重序列化后必为单行，缺口只在非 JSON 多行 data；此时 WHATWG 消费者静默截断到首行。修出口是唯一既不违 spec（`stream-fidelity-fix/spec.md:263-280`「SHALL NOT flatten」）也不改解析语义的路径。

**锚点**：`parser.rs:309`；`frame_feed.rs:107-121`、`terminal.rs:194-197`、`:224-227`、`synth_flush.rs:29-32`、`event_loop.rs:672-677`。

**回滚**：复原 5 处 format。

---

#### A-6 · F-08（P3）Chat 错误载荷帧即终端

**决策**：修代码。判据：**`v.get("error").is_some() && v.get("choices").is_none()`**（顶层 `error` 且无 `choices`），置于 `event_loop.rs` 的 Chat 分支；命中即 `state.terminal_sent = true`，不再注入 `[DONE]`；观测新增 `TruncatedMode::UpstreamError`（`meta.rs:9-14`）以区别于 `open_ended`。**同批 canonical 同步（审查复核补充）**：`llm-gateway/spec.md:108-122`「截断三态（唯一值）」与 `observability-admin/spec.md:126-128`「三态之外的值 SHALL NOT 落该指标」SHALL 扩为四态白名单（`silent_discard`/`open_ended`/`synthesized_failed`/`upstream_error`），否则新态会触犯既有条款。`SynthesizedFailed` 的协议适用范围口径不变。

**误报分析**：`is_terminal_event`（`event.rs:229`）对 Chat 恒 false；`extract_tool_fragments`/`is_minor_event`（`event.rs:320-336`）均需 `choices`；顶层 `error` 与 `choices` 共存、或 choice 内含 `error` 字段的形态不满足判据，不误伤。

**理由**：`synth_flush.rs:87-107` 在 EOF 时无条件为 Chat 补 `[DONE]` 并把 `clean_close=false` 记为 `open_ended`，造成观测误归因。canonical `llm-protocol-hardening/spec.md:8-25` 的补发条件为"出现非 null `finish_reason`"，error 帧不满足，故不补属合规。README §7.2 增补"错误载荷帧即终端"。

**锚点**：`event.rs:219-231`、`:295-339`；`synth_flush.rs:87-107`；`event_loop.rs:178-180`；`sse/meta.rs:9-24`。

**回滚**：删判据。

---

#### A-7 · F-09（P3）Content-Type 大小写不敏感

**决策**：修代码。新增 `pub(crate) fn is_event_stream(content_type: &str) -> bool`（取 `;` 前段 trim 后 `eq_ignore_ascii_case("text/event-stream")`）于 `src/handler/llm/mod.rs`；`should_pump_stream`（`mod.rs:89-91`）与 `dispatch.rs:258` 的裸 `contains` 同批改用该谓词，消除第二站点；`nonstream.rs:103` 经 `should_pump_stream` 自动受益。`stream_flag` 回退语义不变。

**纠正**：实际决策站点为 **2 处**（非审计所称 3–4）；`router.rs:327` 是响应头测试断言，勿改。

**锚点**：`dispatch.rs:255-267`、`llm/mod.rs:86-91`、`nonstream.rs:103`。

**回滚**：恢复 `contains`。

---

#### A-8 · F-10（P3）跨槽 hold 放行序 —— **不改代码**

**决策**：按 canonical `stream-protocol-parity/spec.md:124-136`「无法保序时显式声明并由测试锁定」条款登记：放行序定义为"每槽按到达序取出、由该槽完成事件驱动"；跨槽并行 item 的相对 `sequence_number` 次序 **SHALL NOT** 被保证。新增交错并行 item 用例锁定实际放行序。

**理由**：`toolbuf.rs:7-22` 按 `pending` 数组到达序取出，放行由各槽完成事件驱动（`event_loop.rs:318-379`）。跨槽严格排序会引入"等待可能永不到达的 `.done`"风险，与 hold-until-complete 的 fail-closed 语义冲突；下游断序容忍已在 README §7.2 声明。既有 `toolbuf.rs:45-107` 已锁定"到达序 + 按槽"。

**锚点**：`toolbuf.rs:7-22`（不改）、`:45-107`（加用例）；`event_loop.rs:318-379`（不改）；`stream-protocol-parity/spec.md:124-136`。

---

#### A-9 · B1（P2）残余帧 JSON 转义还原

**决策**：修代码。`pump/spawn/terminal.rs:208` 的 `restore_response_with_spans` 改为 `restore_response_with_spans_json`（与正常帧同口径：`pump/spawn/event_loop.rs:570`、`:578` 处的 `restore_response_with_spans_json`），使还原明文中的 `"`/`\`/控制字符按深度转义写入。

**理由**：`residual_frame_payload` 保证残余帧为完整 JSON，故 `_json` 变体（`scope.rs:219-251`，按深度转义）适用；现状用逐字插入变体（`scope.rs:204`）会在明文含引号时产出非法 JSON。

**锚点**：`terminal.rs:208`（改）、`spawn/event_loop.rs:570/578`（对照；`spawn/terminal.rs` 全文仅 295 行，勿引 `:576-578`）；`redaction/scope.rs:204`、`:219-251`。

**回滚**：单点还原函数名。

---

### 簇 B：脱敏与会话保真（RED / PII）

#### B-1 · B4（P3）未闭合 JSON 片段深度计

**决策**：修代码（保守、上下文感知）。在 `scope.rs:434-457` 的 `token_restore_depths` 中计算 `fragment_ctx` 并透传进 `collect_token_depths`（`:459-481`）：
1. 帧 `type == "response.function_call_arguments.delta"`（Responses，`delta` 字段即 JSON 片段）；
2. `type == "content_block_delta"` 且 `delta.type == "input_json_delta"`（Anthropic）；
3. 子树键名为 `partial_json` 或 `arguments`。

命中载体时，对**以 `{`/`[` 开头但整体不可解析**的字符串按 `depth+1` 计入。**完整可解析容器分支（`:491-501`）优先级不变**；载体以外的普通字符串（如 `delta.text`）**SHALL NOT** 加一。

**降级条款**：若实现中发现载体判定不可靠，降级为"声明该限制 + 锁定回归用例"，**SHALL NOT** 采用无差别加一（那会使纯文本被过度转义）。

**理由**：`collect_string_depths`（`:485-508`）仅对完整容器用 `depth+1`；未闭合片段落 `scan_token_forms` 分支用当前 `depth`（外层字符串 = 1），而该 token 实际将随片段拼接进入**内层 JSON**，应转义 2 层。写入点为 `restore_response_with_spans_json`（`:219-251`，按 span 取 depth 于 `:241-245`）。

**锚点**：`scope.rs:423-429`、`:434-457`、`:459-481`、`:485-508`、`:219-251`；测试 `scope_p2_tests.rs`、`json_walk.rs:300`。

**回滚**：撤 `fragment_ctx` 传参。

---

#### B-2 · B2（P3）`chat_bucket` spec 纠偏 —— **不改代码**

**决策**：canonical `redaction-audit-coverage/spec.md:116-123` 文本更新为位域公式 `(ci << 16) | (idx & 0xFFFF)`（`ci, idx < 2^16` 内单射无碰撞；`ci=0` 与历史 `ci*64+idx` 等值）。代码 `tool.rs:147-152` 不动。

**理由**：已确认全仓无解码方——`chat_bucket` 仅出现在编码侧 `tool.rs:263/304/322` 与测试（`tool/tests.rs:111-129`、`fragments/tests.rs:553-577`）；`metrics/aggregate/tests.rs:174` 的 `record_chat_buckets_by_normalized_model` 是同名不同概念。桶键只作去重标识、无逆运算。旧公式在 `idx>=64` 时与下一 choice 桶 0 碰撞，spec 条款本身是缺陷。`ci=0` 等价锚点已由既有测试锁定。

**锚点**：`tool.rs:143-152`（不改）；`redaction-audit-coverage/spec.md:116-123`（改）。

---

#### B-3 · D3（P2）自定义规则聚合超时不记账

**决策**：修代码。`scan_custom` 在**聚合墙钟超时**（`tokio::time::timeout` 到期）或阻塞任务 panic 时：**SHALL NOT** 对任何规则执行超时记账；仅记一条全局 warn（含规则数与预算）并返回零命中。规则停用**仅**由 batch 内逐规则 `find_iter` Err 路径触发（连续 `RE_DOS_STRIKES=3` 次）。

**否决的选项**：审计建议的"超时后逐规则重扫定位元凶"不可行——`spawn_blocking` 不可取消，慢任务仍占阻塞池线程，且慢路径本身可能再超时，且 `tokio::time::timeout` 到期时**拿不到** batch 的逐规则结果。

**已知残余（显式登记）**：持续慢规则会使每帧零自定义命中（custom PII 的 fail-open），但不再全量停用；唯一可观测面是新增的全局 warn。若后续需更强语义，另立 change 加全局熔断器。

**锚点**：`custom.rs:390-486`、`:489-504`；`detector.rs:37`；`custom/tests.rs:52-107`（既有单测断言单次超时不触发三连停用，与本修法一致）。

**回滚**：恢复 `:440-449` 的批量记账。

---

#### B-4 · ARH-4（P2）规则集 Arc 化 + 批量记账

**决策**：修代码。
1. `PiiDetector::custom` 改 `RwLock<Arc<Vec<(String, fancy_regex::Regex, String)>>>`；`scan_custom` 仅 `Arc::clone`（替换 `custom.rs:395-396` 的 `Arc::new(recover(read).clone())` 深克隆）。唯一写点 `:236` 用 `Arc::make_mut(&mut guard).push(...)`（启动/测试期无并发，零拷贝）。`spawn_blocking` 闭包 `'static` 由 Arc 满足。
2. `account_rule` 批量为 `account_rules_batch(&[(name, timed_out)])`：单次获取 `strikes` → `disabled`（保持 `custom.rs:3-5` 锁序），逐规则成功清零/超时累计/三连停用 + warn，跳过已停用者；替换 `:479-484` 的每规则双锁。

**理由**：canonical `architecture-cleanup/spec.md:121-138` 明确"SHALL NOT 每帧克隆规则集"（fancy_regex 的 `RegexImpl::Wrap` 含 `pattern:String` + `delegated_pattern:String`，克隆非纯 Arc）。语义（超时记账状态机、三连停用、warn 文案、扫描命中）逐项不变。

**锚点**：`custom.rs:3-5`、`:236`、`:266`、`:281`、`:395-396`、`:400-406`、`:455-484`、`:489-504`；`detector.rs:495`；`custom/tests.rs:333,377`（锁序守护需新形签名）。

**回滚**：恢复 clone 与逐规则锁。

---

### 簇 C：授权与资源上限（CRD / RES）

#### C-1 · B3（P1）响应侧凭据还原改为请求级授权（minted-set）

**决策**：修代码。`Scope` 新增请求级 `Mutex<HashSet<String>>`（随请求销毁），在**请求侧脱敏实际产生替换**处记录本请求产出的凭据 token（由 `P2tSnapshot::redact` 的替换值收集，经 `redact_leaf` 汇总）。

**关键约束**：白名单必须是"本请求脱敏**实际产出**的 token"，**SHALL NOT** 以"请求体中出现过的 token"为依据——后者会让调用方自带的 `__VG_CRED_\d{4,}__` 字面量被跨请求还原，漏洞原样保留。

- 响应还原（`Scope::restore_response_one`、`restore_cred_tokens`）仅在 `token ∈ minted-set` 时调用 `CredentialVault::restore_one` / 全量还原。
- 未命中者**SHALL NOT** 还原，并按幻觉 token 剥离：`strip_hallucinated`（`credential_vault.rs:319-330`）增 `allowed` 入参（或等价过滤），使未授权 token 形态不透出下游（fail-closed）。
- `CredentialVault` **SHALL** 保持进程单例与跨请求同 token 语义；`make_cred_token` 六位零填充、`token_re` `\d{4,}`、placeholder 门控 `\d{6,}`、prompt-cache 关联**均不变**。

**理由**：泄漏链成立——`dispatch.rs:156-159` 每请求建 `Scope`，`:201-209` 请求侧脱敏，`:213-228` 同一 `Arc<Scope>` 复用为响应 scope；`redact_leaf`（`leaf.rs:100`）只做明文→token，字面 token 被 `protected_spans` 保护后原样上行；响应侧 `restore_response_one`（`scope.rs:136-143`）→ `restore_one`（`credential_vault.rs:296-298`）**全局查表**，把该 token 换成任意历史请求的凭据明文。合法还原的充分条件成立：响应里的凭据 token 只可能来自本请求脱敏产出（下游永远只收到明文；多轮对话每轮重新脱敏 → `register` 复用同一 token，`credential_vault.rs:209-213`；PII 已是请求级 `Scope::pii`，README §7.3）。

**规范同步**：`credential-vault-singleton` spec 增补「还原授权为请求级」条款；README §7.3 登记该行为收紧（原先会还原的字面 token 现按未授权剥离，属安全修复非兼容回归）。

**同批 canonical 清理（独立复核补充）**：canonical `credential-vault-singleton/spec.md:22-24`「PII 全局持久双模」要求"提供 PII 全局持久开关（默认关闭）"且 `:10` 述"全局 PII 注册表"，与实现（`Scope::pii` 请求级、`env_parse.rs` 无该开关）及本 change「PII 为请求级容器、跨请求不互见」声明冲突；本 change SHALL 为该 spec 增补 delta 收窄/作废该 requirement（保留请求级隔离口径），SHALL NOT 任其与请求级声明并存。

**风险**：约 20 处直接调 `restore_response*` 的测试（`scope_tests.rs`、`scope_p2_tests.rs`、`credential_vault.rs`）需先经一次请求侧脱敏（或经 `#[cfg(test)]` 播种入口）。

**锚点**：`credential_vault.rs:32,36,209-213,214,296-298,315,319-330`；`scope.rs:74-97,136-143,150-210,376-393`；`leaf.rs:92-146`；`dispatch.rs:156,201,213`。

**回滚**：还原 `restore_one` 直查语义（单点）。

---

#### C-2 · D4（P2）`DecisionTable::begin` 施软上限

**决策**：修代码 + 修订 canonical。`begin` 顺序：`sweep(now)` → 循环驱逐终态 `Decided`（按 `created` 升序、key 字典序 tie-break）直至有空位 → 满表且**仅余 `InFlight`** 时新增 `BeginOutcome::Saturated`，三个调用点映射为 `VeilError::RateLimited{retry_after_secs: 60}`（`429 + Retry-After`），并递增 `overflow_count` + 记 warn。

- **SHALL NOT** 驱逐 `InFlight`。
- **SHALL NOT** 对新键返回伪造的 `202 + E_PENDING`（新键无票，伪 pending 会让 Go 客户端退避轮询不存在的单据直至超时）。
- 同键在途仍 `202 + E_PENDING`（复用既有票）。
- 容量沿用 `DECISION_TABLE_MAX_ENTRIES=4096`（`approval.rs:212`）。

**理由**：canonical `architecture-cleanup/spec.md:24` 的 backstop 理由（"InFlight 由 Matrix 审批票并发度天然约束"）不成立——Matrix 无并发上限，`begin(Reserved)` 会 tracked 发送 + 预置 reaction + `tokio::spawn` 最长 300s 的 waiter，无界。**必须同批修订该 spec 条款**，否则实现与 spec 再次背离。

**锚点**：`credential/approval.rs:212,237-249,266-293`；调用点 `vault_ops.rs:320-340,436-456`、`approval.rs:422-450`；`error.rs:113`；`architecture-cleanup/spec.md:24,36-39`。

**回滚**：移除 `Saturated` 分支。

---

#### C-3 · D1（P2）`pending_tool_frames` 记账 fail-closed

**决策**：修代码（采纳 oracle 的 (c) 方案，**否决审计的 (a)/(b)**）。真实无界路径为"上游对**同一 index** 持续发**零字节** tool 分片"：`push_fragment`（`hold.rs:104-106`）`or_default()` 不新增条目、`total_bytes += 0`，`entries_over_cap`（`:114-116`）恒 false，而 `event_loop.rs:602-606` 每帧仍 push 一条 `(buckets, prefix, restored_data)`。故：

1. `AuditHold` 新增 `account_pending_frame(bytes) -> HoldVerdict`：条目维度复用 `AUDIT_HOLD_MAX_ENTRIES=4096`，字节维度以**独立计数器**受 `AUDIT_HOLD_MAX_BYTES` 约束。
2. `event_loop.rs:602` push **前**调用；返回 `Rejected` 即走既有 `reject_reason = "audit-hold-overflow"` 阻断臂（`:529-557`）。
3. **不静默丢弃**：走 fail-closed 阻断（与字节/条目超限同语义清仓，`:119-127`），被清参数已在 hold 内由终审 `tool_triples`/`responses_pending_triples`（`terminal.rs:115-171`）评估。

**理由**：Chat 的 `is_terminal_event` 恒 false（`event.rs:229`）、流式 client 无总超时（README §7.2），故可无限累积。攻击面需审计模式非 `off`（生产安全默认）+ 协议 `is_dialog` + 上游半可信/被攻陷 → P2 成立。

**风险**：帧字节 ≈ args + 信封，独立字节计数可能略早于 hold 触发（可接受，fail-closed）。

**锚点**：`hold.rs:80-116`；`event_loop.rs:383-389,602-606,529-557`；`decide.rs:89-96`；`terminal.rs:103-113,153,176-191`；`setup.rs:60`；`stream-fidelity-fix/spec.md:133,145-147`。

**回滚**：单函数调用点。

---

#### C-4 · D2（P2）`pending_events` 硬上限

**决策**：修代码。`SseParser::pending_events` 设硬上限 `PENDING_EVENTS_MAX = 8`，超限**丢弃最旧**并计数（`pending_events_dropped`，经 `take_*` 访问器由泵排入观测，仿 `truncated_line_dropped_bytes`），每流首次超限记 warn。TRN-1 的 `event` FIFO 配对与 `id` 最近值语义、以及"分块信封流与同内容非分块流的事件/帧计数逐一致"**不变**；仅对连续 >8 个 `event:`-only 块（畸形流）丢最旧。`pending_retry` 已是单值，无需上限。**不新增导出指标**（畸形输入、warn 可观测），在 spec 声明。

**WHATWG 核查**：规范中 `event:`-only 块在空行分发时即清空 event buffer、**不会**配对到后续 `data` 块；本仓 TRN-1 的跨块 FIFO 配对是**有意保真偏离**（由 canonical `gateway-transport-fidelity` spec 锁定），故不能改成"只留最后 1 个"。

**锚点**：`parser.rs:117-124`（常量）、`:279-351`（push `:326`、消费 `:341-345`）；`gateway-transport-fidelity/spec.md:10`。

**回滚**：移除上限常量与分支。

---

### 簇 D：架构与边界（ARH）

#### D-1 · ARH-2（P2）单帧单解析收敛

**决策**：修代码。每帧 `ev.data` 的 JSON 解析收敛为 `event.rs::parse_event_data` 单点；`sticky_terminal_event`（`event.rs:125-136`）、`responses_failed_incomplete`（`:140-159`）、`responses_error_object`（`:166-188`）改收 `parse_event_data` 产物（`Option<&Value>`），原字符串签名降为 `#[cfg(test)]` 包装（`event.rs` 内约 25 处测试零改）。生产调用点 `event_loop.rs:192/214/235` 传 `parsed.as_ref()`；metric 语义（解析失败才 `record_terminal_fallback()`）保留。

**守护升级为双守卫**：(1) `event.rs::parse_event_data` 内含 `#[cfg(test)]` 解析计数器 + `take_parse_count`，在泵 e2e 用例中断言每帧恰 1 次；(2) `model_bucket_tests.rs:12-23` 的源码计数之外，增加"`event.rs` **生产段**（首个 `#[cfg(test)]` 之前）`from_str` 计数为 0"的源码守护——现守卫只看 `event_loop.rs` 的 `strip_bom(&ev.data)` 形态，正是它能漏掉这 3 处的原因。

**锚点**：`event.rs:125-136,140-159,166-188`（`:355-610` 测试面）；`event_loop.rs:155-160,192,214,235`；`model_bucket_tests.rs:12-23`。

**回滚**：恢复字符串签名。

---

#### D-2 · ARH-8（P3）`filter_hop_headers_counted` 用 `Vec<HeaderName>`

**决策**：修代码。`hop.rs:46-64` 的 `keys: Vec<String>` 改 `Vec<HeaderName>`（`.keys().cloned()`），`is_hop(k.as_str())` 直比、`remove(&k)` 直取；去掉 `k.to_lowercase()`（`hop.rs:61`，冗余：`HeaderMap` 插入即把自定义头名规范化为小写，既有单测 `hop.rs:86-114` 已锁定该不变量）。`Connection` 头内动态项保持 `Vec<String>` 并保留 lower+trim（自由文本，`:48-55`）。

**声明**：剥离计数与方向 `debug_assert` 语义不变；性能收益为**假设**（每请求少 N 次 String 分配 + N 次名字重解析），**SHALL NOT** 作为对外性能承诺，待 bench。另在 `hashset_reuse_equivalence`（`hop.rs:228`）注释显式声明"锁行为等价，不锁分配属性"。

**锚点**：`hop.rs:42-79`、`:210-255`。

**回滚**：恢复 `Vec<String>`。

---

#### D-3 · ARH-9 / ARH-10 / ARH-11 —— **收窄 canonical spec（不改代码）**

**决策**：三处均以显式声明收窄 `architecture-cleanup/spec.md:168-208` 的 over-claim 文本，**SHALL NOT** 继续收敛代码。

- **ARH-9**：收敛对象限定为协议**判定/分派谓词**（已为 `Protocol` 类型化方法：`is_chat`/`is_responses`/`is_dialog`/终态/审计到期/次要事件/`wire_name`）；逐协议**差异产物构造**（帧序列/usage/placeholder/tool 提取分支）**SHALL NOT** 视为重复分派。剩余 `match protocol` 集中地：`synth_flush.rs:86`、`event.rs:92/106/221/238/297`、`block_inject/terminal.rs:24/63`、`frames.rs:106/283/422`、`usage.rs:37/139/180`、`tool.rs:242`、`placeholder.rs:193`。
- **ARH-10**：`UpstreamStatus` 的强制范围限定为网关**边界/分发点**（已在 `dispatch.rs:322` 使用）；纯谓词 `classify_empty`（`mod.rs:241-245`）的 `u16` 入参**SHALL** 为例外（调用方保证来自 reqwest `StatusCode` 派生值）。
- **ARH-11**：仅对已枚举不变量（hop 方向 `hop.rs:42-45`、tool 位域 `tool.rs:149-150`、carry 剥离 `carry.rs:44`）提供 `debug_assert`/类型守护；**SHALL NOT** 承诺覆盖未枚举项。

**理由**：规格说了算、不许静默 over-claim；这三条 spec 文本对现实的描述过强，而代码侧属自然差异而非缺陷。

**锚点**：`architecture-cleanup/spec.md:168-208`；上述源文件。

**回滚**：无（纯文本）。

---

#### D-4 · 声明锁与越层边界

**决策**：修代码 + 强化守护。
1. `src/service/llm_gateway/mod.rs:309` 的 `axum::body::Bytes` 改 `bytes::Bytes`（`bytes = "1"` 已是直接依赖，`Cargo.toml:33`），使"service 生产仅允许 `axum::http::HeaderMap` 纯数据白名单"声明成立。
2. 声明锁守护（`service/mod.rs:29-68`）改为：在**首个 `#[cfg(test)]` 之前的生产前缀**上 token-scan `axum::`，非白名单文件命中即失败；白名单文件（`llm_gateway/hop.rs`、`llm_gateway/mod.rs`）内每个 `axum::` 之后须为 `http::`。现状用 `src.contains("use axum")`（`service/mod.rs:61`），而真实用法是 `use {super::GatewayMetrics, axum::http::HeaderMap}`（`hop.rs:3`）与 `axum::http::HeaderMap,`（`llm_gateway/mod.rs:8`）→ 检测与白名单双双失效。
3. `RegisterParams` 的字段 trim 与构造下沉为 `service::register_map::parse_register_params`（`handler/credential.rs:161-180` 改为调用）；`registry::HashChangeOutcome::from_reaction`（`:307`）**保留**为领域解析器并声明为已知边界。

**锚点**：`service/mod.rs:29-68`；`hop.rs:3`；`llm_gateway/mod.rs:8,309`；`handler/credential.rs:161-180,307`；`Cargo.toml:33`。

**回滚**：逐点还原。

---

### 簇 E：管理面（OPS）

#### E-1 · D5（P3）`series?since=` 非法值 400

**决策**：修代码。`GET /_admin/series` 的 `since` **SHALL** 仅接受 `[dhm]<整数>` 形态（与 `day_key`/`hour_key`/`five_min_key` 产出同形），非法值返回 `400 + E_BAD_REQUEST`（消息列明合法形态），**SHALL NOT** 以 `i64::MIN` 回退为全量无过滤。与既有 `granularity`/`range` 非法即 400 的口径一致（`admin.rs:430-452`）。README §3 与 canonical spec 补注取值形态。epoch/日期支持须另立 change（拒绝：新增格式解析面与歧义，裸整数既可为 epoch 又可为序号）。

**锚点**：`handler/admin.rs:405-483`（`since` 在 `:454`）；`metrics/aggregate.rs:183-188,412-445`。

**回滚**：恢复 no-op 过滤。

---

#### E-2 · D6（P3）宽限去重表 TTL 驱逐

**决策**：修代码。`static GRACE_NOTIFY_DEDUP: OnceLock<Mutex<HashMap<String, u64>>>`（value = `expires_at`）。`first_grace_notification(dedup_key, expires_at, now_secs)`：命中返回 false；`len >= GRACE_NOTIFY_DEDUP_MAX(4096)` 时先 `retain(|_, e| *e > now)`，仍满则逐出 `expires_at` 最小者并 warn，再插入。**SHALL NOT** 整表清空。与 `RateTable`（`ratelimit.rs:19-21,54-59,71-75`）的"容量触发清扫 + 硬上限逐出"模式一致。调用点 `approval.rs:573-584` 已持有 `expires_at`。

**锚点**：`credential/approval.rs:20-41,573-584`；`ratelimit.rs:19-21,54-75`。

---

#### E-3 · 门控 404 安全头

**决策**：修代码。`src/handler/admin.rs:47` 的 `with_security_headers` 提升为 `pub(crate)`，`src/router.rs:26-33` 的 `observability_gate` 在 `OBSERVABILITY_DISABLE=1` 的 404 分支复用同一函数（`router.rs:10` 已 `use handler::{self, admin}`）。**SHALL NOT** 修改 canonical spec 措辞（`observability-admin/spec.md:140,152` 的契约成立）。

**理由**：五项头（`cache-control`/`pragma`/`x-content-type-options`/`x-frame-options`/`referrer-policy`）均为通用响应头，**不泄露**管理面存在性；与同语义的非 disable 未知子路径 404（`admin.rs:730-738` 已带齐 5 头）保持一致。现有 e2e 仅断言状态码（`tests/http_e2e_admin_matrix.rs:245-255`）。

**验证**：扩展 `tests/http_e2e_admin_matrix.rs:240-260`，对三个路径的 authed/anon 404 均断言 `cache-control` 含 `no-store`；同时确认非 `/_admin` 路径不受影响（`:257-258`）。

**回滚**：还原 gate 分支。

---

### 簇 F：死代码与去重（DCD）

#### F-1 · DCD-5 收敛

**决策**：修代码。5 个仅测试引用的 `pub` 项降为 `#[cfg(test)] pub(crate)`（与既有 `conv_missing_count`/`terminal_fallback_count` 模式一致）：`GatewayMetrics::truncated_count`（`llm_gateway/mod.rs:137`）、`hop_filtered_count`（`:147`）、`nondialog_passthrough_count`（`:172`）、`MatrixApproval::pending_event_ids`（`matrix/approval.rs:364`）、`chunk::scan_builtin`（`pii/chunk.rs:237`，唯一调用者 `detector.rs:551` 所在 `scan_spans` 为 `#[cfg(test)]`）。

**理由**：canonical `deadcode-positional-cleanup` spec 要求仅测试使用的可见性收敛为 `#[cfg(test)]`。

**锚点**：`llm_gateway/mod.rs:137,147,151-152,172,180-189`；`matrix/approval.rs:364`；`pii/chunk.rs:237`；`detector.rs:545-551`。

---

#### F-2 · 有界去重抽取

**决策**：修代码（范围以"生产重复且语义关键"为界）。

1. **`inner_json_intact` + 守卫谓词下沉**：把 `frame_feed.rs:80-103` 与 `nonstream.rs:534-558`（及 `guard_ok` `:64-76` / `restore_guard_ok` `:522-530`）的**纯逻辑**收敛到 `service::redaction`（新 `restore_guard` 子模块，**零 axum 依赖**），暴露 `inner_json_intact(&Value, &Value)` 与 `restore_guard_ok(restored, placeholder, placeholder_parsed: Option<&Value>)`；`guard_restored_frame_parsed`（metrics/warn 包装）留在 handler `frame_feed`，`nonstream` 复用共享谓词。
2. **`x-veil-*` 剥离**抽 `service::llm_gateway::strip_veil_internal_headers(&mut HeaderMap)`，替换 `llm/mod.rs:47-54`、`dispatch.rs:335-342`、`nonstream.rs:564-571`。
3. **`data_frame`**：见 A-5。
4. **`NORMALIZED_HEADER_NAME/VALUE`**（`redaction/leaf.rs:14,17`，现为 `#[cfg(test)]`）提升为生产 `pub(crate) const`，替换 `nonstream.rs:230,595`、`dispatch.rs:366`、`pump/event.rs:46` 的字面量。
5. **Chat `[DONE]`** 两处（`block_inject/frames.rs:60`、`event_loop.rs:677`）统一走 `chat_done_frame()`（`frames.rs:257`）。

**不纳入**：测试内断言文本（非生产口）、`hop.rs` 动态项处理（与 ARH-8 合并）。

**锚点**：见各行内标注；`deadcode-positional-cleanup` spec。

---

### 簇 G：文档与门禁口径（DOC）

#### G-1 · 指针与语义修正批（现行文档，非归档）

| 位置 | 现指向 | 修正为 |
|---|---|---|
| `README.md:408` | `event_loop.rs:414` | 符号锚 `src/handler/llm/pump/spawn/event_loop.rs::handle_event`（首插入点 `:353`；`:468/:511` 同符号） |
| `README.md:726` + `credential-auth-hardening/spec.md:29` | `vault_ops.rs:458-464` | `vault_ops.rs:555-561`（`admin_ok` 的 `OBSERVABILITY_ADMIN_TOKEN` 比较） |
| `docs-test-parity/spec.md:34,39` | `env_parse.rs:469-478` | `env_parse.rs:493`（`validate_approve_whitelist`） |
| 同上 | `main.rs:45` | `main.rs:46` |
| 3 处源码注释（`audit/verdict.rs:44-45`、`block_inject.rs:464-465`、`audit.rs:28`） | 同步 `env_parse.rs:493` | 同左 |
| `docs-contract-sync/spec.md:47` | `env_parse.rs:342-347` | `env_parse.rs:295-296`（`OBSERVABILITY_DISABLE` 证据） |
| `go-client-interop/spec.md:77` | `credential.rs:147-183` | `credential.rs:61-101` / `:190-199` |
| `credential-flow-parity/spec.md` 低危偏移 | `:10/:34/:58/:223/:247` | 按现行行号校正 |
| `credential-flow-parity/spec.md:120` | PII 缓存描述 | 校正为实际（无全局 PII 缓存；请求级 `Scope::pii`） |
| 陈旧注释 | `placeholder.rs:26`、`metrics/store/tests.rs:107`、`pump.rs:1-6` | 校正（`pump` 子模块枚举补 `carry`/`decide`） |

#### G-2 · 未 enrolled 语义纠正

**决策**：`credential-flow-parity/spec.md:311-323` **与** `credential-api/spec.md:10,20-21`（审计只点了前者，实际两处同载）均改写为"未 enrolled 默认**转审批**（`AUTO_APPROVE=false` 时才 `403`）"，并指向真相源 `credential-auth-hardening/spec.md:89-101`；同步修正 `credential-flow-parity/spec.md:4` 的 Purpose 措辞。代码为 `auth.rs:262-280`（未 enrolled 且 `Deny` → 403，否则 `approval_dual_mode`）。

#### G-3 · F-06 双 canonical 收口

**决策**：删除 `stream-protocol-parity/spec.md:8-20` 整节（「Empty streams stay open-ended for chat/anthropic」），替换为一条迁移声明：Chat 真空流补恰一 `[DONE]`、Anthropic 最小 `message_start`+`message_stop`、Responses 恰一 `response.failed`；`truncated_mode` 保留 `open_ended`/`synthesized_failed` 观测口径；**SHALL NOT** 依历史文本实现开放结尾。**更正（独立复核）**：旧条款并非仅存于 `stream-protocol-parity`——canonical `llm-proto-closeout` 同载旧语义，故本 change 一并修订（见 G-3b）；原文「已核对无其他 canonical 引用旧条款」为误（将「change 目录已归档」误当「canonical 已失效」）。`stream-protocol-parity` 其余条款（含 `:96` 干净收尾不误记 `open_ended`）不动。另补 `stream-fidelity-fix/spec.md:95` 的 `clean_close` 例外（Chat 干净 EOF 仅补 `[DONE]`、不记 `open_ended`）。

#### G-3b · F-06 扩展：`llm-proto-closeout` 旧条款同步

**决策**：为 canonical `llm-proto-closeout` 增补 delta：
1. MODIFIED「空流三协议语义与差异声明」——三协议真空流**均走最小终止**（Chat 恰一 `[DONE]`、Anthropic 最小 `message_start`+`message_stop`、Responses 恰一 `response.failed`），删除「Chat/Anthropic 保持 open-ended、零合成帧」；
2. MODIFIED「Chat 缺 [DONE] 可观测」——对齐 `clean_close` 例外与上游错误帧语义（干净 EOF 仅补 `[DONE]` 且不记 `open_ended`；带顶层 `error` 帧记 `upstream_error` 而非 `open_ended`；**SHALL NOT** 在 `finish_reason` 非 null 的正常收尾后记 `open_ended`）。

**理由**：该 canonical 由已归档 change `veil-llm-proto-closeout` 晋升而来——change 目录归档但 spec 仍活跃，且 `:49` 的「`finish_reason` 后 SHALL NOT 合成 `[DONE]`」与 `llm-protocol-hardening` 的补发口径直接冲突。不修则归档后真相源仍自相矛盾。

**锚点**：`openspec/specs/llm-proto-closeout/spec.md:28-40`、`:47-54`。

#### G-4 · 门禁措辞降级 + 声明

**决策**：`check_doc_paths.py` 的 docstring、`scripts/gate.sh:8`、`scripts/README.md:29`、r2 `tasks.md:395` 的"行号**语义**校验"改述为"行号**范围**校验（存在性 + 在界内）"；canonical `docs-test-parity` spec 增补声明"被引行内容与文档语义的一致性由 code review 保证，门禁脚本不校验"。

**理由**：脚本只校验路径存在 + `1 <= start <= end <= 行数`（`:244`），不校验内容；通用语义锚点不可靠（引用形态多样、误报率高、锚表自身会腐化——r2→r3 漂移即证据）。

**升级触发条件（登记）**：若同类内容漂移再现，改为登记式语义锚点表（`(源文件, 引用原文) → 期望正则`，仅登记关键锚点）。

**归档失效指针处置（F-11/G）**：r2 归档 `tasks.md:36/:37/:103` 指向不存在的 `handler/llm/pump/hold.rs`（r2 规划期源码相对路径，本仓未落点）、`:114` 行号漂移。判定：**归档目录禁改**，本 change 仅注记为"apply 期历史快照，非现行契约"。已核实 `check_doc_paths.py` 的 `SCAN_DIRS`（`:51`）与 `rglob("*.md")`（`:281`）**会**扫描归档目录，`hold.rs` 引用已由 `_PLANNING_REFS`（`:157`）随 `_ARCHIVED_PLANNING_CHANGE`（`:184`）双 base 注册为 `PENDING_REFS`（`:187-188`）→ 打印 PENDING、exit 0、零 FAIL。apply 期实证后加固：6.6 下沉使 `src/handler/credential.rs` 315→312 行，令归档 `2026-09-11-veil-code-hygiene-closeout` 的 `credential.rs:297-315` 三处引用越界；脚本据此新增 `ARCHIVED_PREFIX`（`:67`）与 `is_archived_doc`（`:71-72`），对 `openspec/changes/archive/**` 整体豁免行号在界断言并按处数打印「归档文档行号引用 N 处未校验」（路径存在性仍校验、悬空引用仍须 `PENDING_REFS` 登记），与本 spec「指向冻结归档语料的引用 SHALL NOT 被回改」同源。**SHALL NOT** 扩展 `PENDING_REFS`/`PENDING_LINE_REFS`（对已登记项冗余、对未越界项无效）。

#### G-5 · 文档完整性缺口

补：`PROXY_URL` / `PROXY_HTTP_TIMEOUT`（README §5）、`VEIL_APPROVAL_E2E_URL` / `VEIL_APPROVAL_E2E_CALLER`、`scripts/README.md:33-38` 的 `PENDING_LINE_REFS` 说明、README §7.2 的 `total_tokens` 求和回退语义。

---

### 簇 H：Go 客户端（GO）

#### H-1 · 非法 env 回退对齐

**决策**：修代码。`parseDurationEnv` 的 `def` 改为与文档一致的 `300*time.Second`（`get/internal/approval.go:42`、`get/internal/proxy.go:18`），非法值（如 `5min`，Go `ParseDuration` 不接受）回退时 `fmt.Fprintf(os.Stderr, …)` 告警（**非** fail-fast，避免脚本硬失败）。

#### H-2 · 退出码语义

**决策**：修代码。`get/cmd/register.go:18`、`get/cmd/revoke.go:16`（及其余子命令）的 `flag.ExitOnError` 改 `flag.ContinueOnError`；`flag.ErrHelp` → 退出 0，其余解析错误 → 打印用法后退出 1；退出码 2 **专用于**「已受理未完成」。

#### H-3 · 审批测试真实形状

**决策**：修代码（测试）。`get/internal/approval_test.go:180/203` 主用例改用真实 Rust 202 形状（`{"error":{"code":"E_PENDING",…}}`，断言 `regID == ""`）；另留一条 Python 基线（顶层 `reg_id`）用例覆盖 `proxy.go:269-274` 的回退；回退逻辑**保留**并注明"对 Rust 服务器恒不命中"。`scripts/go_interop_e2e.py` 无 `reg_id` 断言，改动安全。

#### H-4 · `TestApprovalPollIntervalClamped` 判别点重写

**决策**：修代码（测试）。现用例（`approval_test.go:244-259`）以 `approvalTimeout=50ms` 驱动，`count==1` 实际由 `approval.go:160` 的 deadline 守卫解释；若单次 POST 耗时超过 50ms，**删去** `approval.go:138-142` 的钳制仍会通过 → 无判别力。修正：改为「长超时（如 30s）+ 记录型 `sleepFn`（记录每次休眠参数）+ 两元素脚本响应（先 `202 + E_PENDING`、后终态 200）」。断言：`count()==2`、**恰好一次休眠**、且 `slept[0] == 2s`（`approval.go:141` 的钳制下界）；钳制被删则 `slept[0]==0` 而失败。**SHALL NOT** 引入可注入时钟或真实休眠；不改生产代码。

---

### 簇 I：保留 + 显式声明（不改代码）

| 项 | 声明内容 | 锚点 |
|---|---|---|
| **B（同步内置扫描）** | `boundary_spans` 在 pump async 任务同步执行内置扫描，但**不接收整帧**：窗口由 `BoundaryHold::push` 构造为 `tail_window(held)+head_window(data)`，上界 `2×PII_HOLD_MAX`（默认 128 字符；配置上界 1MiB），且 `window==0` 时不调用。该热路径同步 CPU 为 O(PII_HOLD_MAX) 非 O(帧)；**SHALL NOT** 为每帧新增 `spawn_blocking`（派发开销 > 扫描，且与 ARH-4 单批 offload 设计相悖）。 | `spawn/setup.rs:158-167`；`redaction/seam.rs:32-75`；`custom.rs:387-407`；`chunk.rs:150-155`；`env_parse.rs:42-45,459-467` |
| **C-1（`shutdown_wired`）** | 源码字符串守护（`include_str!` + `find`/`contains`）断言优雅停机接线顺序、禁止二次构造 `AppState`、要求复用 `CleanupHandles`；**非行为覆盖**，等价重写可绕过，刷盘行为已由 `main.rs:318-330` 行为锁定。保留并声明局限；**SHALL NOT** 在本 change 引入进程级 harness。升级触发：停机接线再现静默断链且源码守护未拦截时另立 change。 | `main.rs:280-316`、`:318-330`；`service/mod.rs:303-333` |
| **C-2 / C-3（`service_invariant_guards`、`hashset_reuse_equivalence`）** | **审计前提有误**：二者本就是行为断言（`#[should_panic]` 直调方向不变量；构造真实 `HeaderMap` 断言过滤计数与保留头），非源码字符串守护 → **无需变更**。仅对 ARH-8 补注"锁行为等价，不锁分配属性"。 | `hop.rs:210-255` |
| **D（`responses_failed_frame` 信封）** | 保留手写 `format!`：`responses_frame` **无条件**写 `sequence_number`，失败帧仅在上游 error 携带序号时写（`frames.rs:149-151`）；改走 `responses_frame` 会为"序号不可得"情形**新增**字段，改变 wire 字节并违反 README §7.2 的 TRN-2 lossy 边界（"可得时写入"）。信封格式在 `frames.rs` 内至少 5 处重复（`:58-60`、`:75-81`、`:152`、`:158`、`:452-453`），单点统一不构成收敛。信封去重（抽 `sse_event`）列为可选后续。 | `frames.rs:134-159`、`:58-81`、`:452-453`；`event.rs:539,577,591,612`；`event_loop.rs:257` |
| **E（gate.sh Go 版本）** | Go ≥1.21 默认 `GOTOOLCHAIN=auto`，会依 `get/go.mod` 的 `go 1.22` 自动选型/下载；硬性版本 fail-fast 会把本可成功的环境误判失败；Go <1.21 时版本指令在 `vet`/`test` 阶段明确报错并非零退出，已 fail-closed。**SHALL NOT** 增加版本字符串比较；在 `gate.sh` 头注、README §8.5、`scripts/README.md` 声明"Go 版本由 `go.mod` 在 vet/test 阶段强制"。 | `gate.sh:21-23,28,69-80,90-96`；`get/go.mod` |

---

## 纠偏记录（审计前提修正，均已采纳）

1. **B3 严重度 P2 → P1**：跨请求凭据明文泄露 + token 序号可枚举。
2. **B3 修法定义**：白名单必须是"本请求脱敏**实际产出**的 token"，而非"请求体中出现过的 token"。
3. **D1 修法**：审计的 (a)"hold 状态门控"与 (b)"completed 后也记账"**均无效**（真实路径为同 index 零字节分片：不增条目、不增字节），须用 (c) 独立记账。
4. **D3 修法**：审计的 (b)"超时后逐规则重扫"不可行（`spawn_blocking` 不可取消、超时分支拿不到逐规则结果），(a) 即最小正确。
5. **ARH-9/10/11**：应**收窄 spec 文本**而非继续收敛代码。
6. **F-09 站点数**：实际 **2 个**决策站点（非 3–4）。
7. **C-2/C-3**：`service_invariant_guards` 与 `hashset_reuse_equivalence` **本就是行为断言**，不属源码字符串守护 → 无需强化。
8. **G（归档指针）**：`check_doc_paths.py` **已扫描归档目录**，且 `hold.rs` 引用已登记为 `PENDING`；`:114` 行号未越界故静默通过 → **无需扩表**，仅文档注记。

---

## Risks / Trade-offs

| 风险 | 缓解 |
|---|---|
| B3 修法改动约 20 处测试的调用前置 | 用 `#[cfg(test)]` 播种入口；回滚为单点还原 |
| A-2 游标推进过早导致序号跳号 | base 恒 `>` 已发序号，满足"单调可跳号"；新增真空流与中途注入对照测试 |
| C-3 独立字节计数可能略早触发 | fail-closed 语义可接受；复现"同 index 零字节分片"回归锁定 |
| B-1 载体判定误纳 `delta.text` 致过度转义 | 只认事件 `type` + 键名组合，不认裸 `delta`；不可靠则降级为声明 + 用例 |
| D-4 声明锁强化对新写法产生误报 | 限定生产前缀 + `axum::http::*` 白名单形态 |
| 文档/ spec 行号在同批改动后漂移 | 每步跑 `check_doc_paths.py`；本次已按"范围校验"口径声明为能力边界 |

---

## 覆盖表（审查发现 → 决策 → 任务簇）

| 发现 | 级别 | 决策 | 任务簇 |
|---|---|---|---|
| F-01 非流 Responses 阻断体 | P1 | A-1 | 1 |
| B3 凭据 token 全局还原 | P1（上调） | C-1 | 5 |
| B1 残余帧非转义 | P2 | A-9 | 1 |
| D1 `pending_tool_frames` 无界 | P2 | C-3 | 5 |
| D2 `pending_events` 无界 | P2 | C-4 | 3 |
| D3 聚合超时全批记账 | P2 | B-3 | 4 |
| D4 `begin` 无软上限 | P2 | C-2 | 5 |
| F-02/F-03 合成帧 seq | P2 | A-2 | 2 |
| F-06 双 canonical 冲突 | P2 | G-3 | 7 |
| F-06（`llm-proto-closeout` 侧旧条款） | P2 | G-3b | 7 |
| F-08 截断态 canonical 同步（三态→四态） | P2 | A-6 | 2 |
| ARH-2 多解析 | P2 | D-1 | 6 |
| ARH-4 规则集深克隆 | P2 | B-4 | 4 |
| F-04 Anthropic 缺 `message_start` | P3 | A-3 | 2 |
| F-04 扩展：三处 canonical「三件套」旧声明 | P3 | A-3 | 2 |
| B3 扩展：`credential-vault-singleton` PII 全局持久双模冲突 | P2 | C-1 | 5 |
| F-05 Anthropic 中途断流 | P3 | A-4（声明） | 7 |
| F-07 多行 data | P3 | A-5 | 3 |
| F-08 Chat error 帧 | P3 | A-6 | 2 |
| F-09 Content-Type 大小写 | P3 | A-7 | 3 |
| F-10 跨槽放行序 | P3 | A-8（声明） | 7 |
| F-11 归档失效指针 | P3 | G-4（注记） | 7 |
| B2 `chat_bucket` spec | P3 | B-2（改 spec） | 4 |
| B4 未闭合片段深度 | P3 | B-1 | 4 |
| D5 `since` fail-open | P3 | E-1 | 8 |
| D6 宽限去重清表 | P3 | E-2 | 8 |
| ARH-8 `hop.rs` 分配 | P3 | D-2 | 6 |
| ARH-9/10/11 over-claim | arch | D-3（收窄 spec） | 6 |
| 声明锁失效 + `Bytes` | arch | D-4 | 6 |
| 越层 `RegisterParams` | arch | D-4 | 6 |
| DCD-5 5 项 test-only pub | P3 | F-1 | 9 |
| 重复：`inner_json_intact` 等 | P3 | F-2 | 9 |
| 门控 404 安全头 | P3 | E-3 | 8 |
| 同步内置扫描（B） | arch | I-B（声明） | 6 |
| `shutdown_wired`（C-1） | arch | I-C（声明） | 6 |
| `responses_failed_frame` 信封（D） | P3 | I-D（声明） | 7 |
| gate.sh Go 版本（E） | P3 | I-E（声明） | 10 |
| 文档指针批 + 完整性缺口 | P3 | G-1/G-5 | 7 |
| 未 enrolled 语义 | P3 | G-2 | 7 |
| Go env/退出码/测试形状 | P3 | H-1/H-2/H-3 | 10 |
| `TestApprovalPollIntervalClamped` | P3 | H-4 | 10 |
| 覆盖缺口（SDK 断言/e2e/多行 data） | P2 | 各修法附测试 | 1/2/3/11 |

---

## 门禁与验证策略

1. 每任务完成即跑 `bash scripts/gate.sh`（七步：fmt / clippy / test / check_doc_paths / check_file_sizes / api_conformance / go vet+test）。
2. `spec` 变更走本 change 的 spec delta，归档时晋升 canonical；行号引用同步校准（`check_doc_paths.py` 只校验范围，内容由评审保证）。
3. 新增测试优先"锚点测试"（断言行为等价的判别性用例），避免源码字符串守护新增。
4. 门禁不得出现新 FAIL；`check_doc_paths.py` 现测 exit 0、0 FAIL。
5. **spec 修订工作流（口径统一，M1）**：spec 修订以本 change 的 `specs/<capability>/spec.md` delta 为归档晋升载体，**并在 apply 期同步直改 canonical `openspec/specs/**`**（沿用 r2 先例：r2 tasks 4.19 等即直改 canonical 并 `grep openspec/specs/...` 验证）；归档时 OpenSpec 对同内容为 early-sync no-op。因此 tasks 中各 spec 任务的 `grep openspec/specs/...` 验证在 apply 期为有效判别，**SHALL NOT** 表述为"仅经 delta 承载、不改 canonical"。
