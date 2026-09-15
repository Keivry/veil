## Context

六维深度审查（2026-09-11）在 LLM 网关三协议流式/非流式面确认 11 项待收敛偏差（见 proposal Why 与覆盖表）。现状真相源：

- Responses 终止合成分支（`src/handler/llm/pump/spawn/event_loop.rs:203-218`）在 `terminal_sent` 检查前执行，`response.completed` 后仍可能合成 `response.failed`（`N1`）；`incomplete` 被当 failed 处理并注入 7 帧序列，丢弃 `incomplete_details`（`P4`）。
- Chat 见 `finish_reason` 后不补 `[DONE]`（`spawn.rs:663-677`）；真空流三协议仅 Responses 有终止（`src/service/block_inject/frames.rs:293-297`、`spawn.rs:614`）（`P1`/`P2`）。
- SSE 解析对块末孤立 `\r` 立即切行（`src/service/sse/parser.rs:117-160`），TCP 分片刻在 `\r`/`\n` 间断开时 `event:`/`data:` 分属两事件（`N3`）；无冒号 `data` 行被整行忽略（`P11`）。
- 非流 `classify_empty`（`src/service/llm_gateway/mod.rs:159-175`）把非 502/401 且非 JSON 的错误体替换为合成 `502 E_EMPTY_BODY`（`N2`）。
- 脱敏注入分支重解析失败回退未脱敏 `body_value`（`src/handler/llm/rewrite.rs:62-69`）（`P7`）。
- 工具提取双实现漂移：`extract_tool_calls`（`tool.rs:140`，缺参/缺 id warn）vs `extract_tool_fragments`（`fragments.rs:14`，静默）；Responses `output[]` 桶号非流用 `output_index.unwrap_or(i)`（`tool.rs:462-466`）、流式恒用 `i`（`fragments.rs:446/452/457/480`）（`X2`/`P9`）。

约束：本 change 只写规划 artifacts，不改 `src/` 与 README；不碰审计 verdict 与脱敏 recognizer；`P3`/`P5`/`P10` 维持现状；`P8`（= `X5`）转出。

## Goals / Non-Goals

**Goals：**

- 给出 `N1`/`N2`/`N3`/`P1`/`P2`/`P4`/`P7`/`P9`/`X2`/`P11` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「恒恰一终端」「真空流可解析终止」「非 JSON 错误体透传」「同调用同结论」收敛为 spec 契约，README §7.2/§8.6 与行为同批同步。
- 记录 `P5`/`P3`/`P10` 的 COMPLIANT 审计结论与证据，防止后续 change 误改正确路径。

**Non-Goals：**

- 不改 `TruncatedMode` 枚举（`P1`/`P2` 的 metrics 口径维持 `open_ended`，见 D2/D3）。
- 不引入新依赖、不改 `stream_options` 合并语义、不改 usage `max` 口径。
- 不给 `RewriteOutput` 增错误通道（`P7` 选投递脱敏字节方案，见 D7）。
- 不删除 `placeholder.rs:175-189` 死分支（`P8` 由 `veil-code-hygiene-closeout` 承接，见 D11）。

## Decisions

### D1：`N1` 守卫置于合成分支首行，先于 `responses_failed_sent` 判定

**决策**：`spawn.rs:218` 的 Responses 分支首行加 `if terminal_sent { continue; }`，再由后续逻辑处理 `error` 合成与 `response.failed` 透传。

**理由**：`terminal_sent` 是「已向下游发出终端」的唯一真相；`responses_failed_sent` 只防重复合成，不感知 `response.completed` 已置位的 `terminal_sent`。常规路径的终端抑制已由 `spawn.rs:265/467/519` 覆盖（`P5` 证据），缺口仅在该前置分支（`spawn.rs:223` 守卫）；守卫放首行同时覆盖 `is_error`/`is_incomplete`/`is_failed` 三种帧。

**备选**：把 `responses_failed_sent` 扩为三态（seen_completed/seen_failed/seen_incomplete）——状态机膨胀且与 `terminal_sent` 冗余，不采用。

### D2：Chat `[DONE]` 可安全合成（`P1`/`P2`）

**决策**：`finish_reason` 出现即记软终止信号（`spawn.rs:177` 既有 `saw_finish_reason`）；**流结束时**若从未见 `[DONE]`，flush 边界后补发恰一 `data: [DONE]`；零帧真空流同样补发恰一 `[DONE]`。`truncated_mode` 仍记 `open_ended`（如实描述上游截断形态），不新增枚举。

**为什么可安全合成**：`[DONE]` 是 Chat SSE 的传输层终止标记，不携带成功/内容/usage 语义；上游 200 返回空流或 `finish_reason` 后断流时，缺失 `[DONE]` 会让严格下游（Hermes 等）悬置或触发 `JSONDecodeError`。合成不伪造 `finish_reason`、不生成 choices 内容、不改 usage 记录，仅补齐线级终止。

**为什么不在 `finish_reason` 帧处立即合成**：`stream_options.include_usage=true` 时上游在 `finish_reason` 分片之后、`[DONE]` 之前还会发一个 `choices: []` 的 usage 尾帧；若立即置 `terminal_sent`，后续 JSON 帧会在 `spawn.rs:256` 被抑制，usage 丢失、metrics 失真。因此改为在流结束处补发（此时 usage 尾帧已透传），spec 场景「finish_reason 后断流补 DONE」锁定 usage 保留。

**为什么真空流也补**：与 `P2` 一致——零帧流同样需要可解析收尾；Responses 真空已有 failed，Chat 真空补 `[DONE]` 不伪造完成语义（空 choices + 终止符）。

**备选**：立即合成（丢 usage，不采用）；保持 open-ended 不补（本次修复要消除的缺陷，README §8.6 同步）。

### D3：Anthropic 真空流补最小 `message_start`+`message_stop`（`P2`）

**决策**：真空流（零帧）补最小合法信封：`message_start`（`message.content=[]`、`stop_reason=null`、usage 全 0、model 回退口径既有）+ `message_stop`；不注入 `content_block_*`、不声称语义 stop_reason。同时把 `type:"error"` 视为终端：`error` 透传后不再发任何帧，尤其不得注入 `message_stop`。

**理由**：Anthropic SSE 以 `message_start` 开始、`message_stop` 结束；缺终止帧下游 SDK 解析悬置或报错。真空流无错误可归因，若用 `error` 事件方案会把「上游空流」误报为上游故障（语义错误），故选最小信封方案。最小信封不含内容块与 stop_reason，不构成「伪造成功」；`error` 后不补 `message_stop` 是因为 `error` 本身即终端，追加会违反「恒恰一终端」。

**备选**：发 `error` 事件——语义误归因，不采用；保持 open-ended——本次修复要消除的缺陷。

### D4：Responses `incomplete` 原样透传、`error` 单帧 `failed`、全序列仅真空流（`P4`）

**决策**：

- `response.incomplete` 是官方合法终止（如 `max_output_tokens`），**原样透传**并作为唯一终端，不转换、不合成，保留 `incomplete_details`；`is_terminal_event`（`event.rs:154-167`）覆盖 `incomplete` 以置位终端。
- `type:"error"` 仅合成**单帧** `response.failed`（`response.error.message` 携带上游 error message），不再注入 7 帧序列。
- 含 `output_index` 的 7 帧全序列（`responses_truncated_frames`）**仅真空流**（`empty_stream_frames`）使用；`spawn.rs:541-568` 截断丢弃路径与 `synthesize_truncation` 同步改单帧 `response.failed`（`response.error.message="truncated"`）。

**为什么 `incomplete` 不得转为 `failed`**：两者语义不同（`incomplete` 表示因 token 上限等提前结束，`failed` 表示错误失败），下游对 `incomplete` 有独立处理/重试路径；转换会丢失 `incomplete_details` 且伪造失败。

**为什么 `error` → 单帧 failed**：`error` 是失败语义，`response.failed` 是其官方终止形态；单帧最小面避免在流中段注入 `output_index:0` 的 `output_item.added` 等序列——若此前已流出 `output_index:0` 的 item，再注入同 index 违反序号单调（`sequence_number` 断序容忍不覆盖重复 index）。真空流没有已流出 item，全序列用于补齐严格客户端所需的 item 生命周期，语义与序号均安全。

**备选**：`incomplete` 也合成全序列——丢 `incomplete_details` 且序号冲突，不采用；`error` 保留全序列——序号冲突，不采用。

### D5：`N3` 块末 `\r` 的跨块判定延后（`swallow_lf` 等价「暂存待合并」）

**决策**：`push_text` 扫描到块末孤立 `\r` 时，行终止保持立即生效（不改变既有单块语义），但记录跨块状态（`swallow_lf`）：下一块首字节为 `\n` 时按 `\r\n` 消费该 `\n`（不再产生空行），否则按孤立 `\r` 处理并清除状态。

**理由**：WHATWG 行终止为 `\r\n`、`\r`、`\n`；TCP 分片可能在 `\r` 与 `\n` 间断开。把 `\r` 原始字节留在 `text_carry` 的方案会在 EOF 时无法归还已终止的行（`residual_json_aware` 只返回残余文本、不返回事件），并改变既有 `data: z\r\r` 单块语义（现有测试 `src/service/sse.rs:34-35`）；`swallow_lf` 与「暂存 `\r` 待下一块合并」行为等价且不动单块语义。

**备选**：块末 `\r` 存入 `text_carry` 延后切行——EOF 事件归还与既有测试冲突（前述），不采用；不处理——合规缺陷保留，不采用。

### D6：`N2` 非 JSON 错误体原样透传

**决策**：`classify_empty` 与 `nonstream.rs` 收敛为：`status>=400` 且非 JSON（含空体）→ 原样透传状态码与正文字节；`status<400` 非 JSON → 维持现状（合成 502 空体）；502/401 的 JSON 完整后处理链不变。README §7.2 豁免范围同步为 4xx/5xx 非 JSON 全豁免。

**理由**：上游错误状态与正文是下游诊断真相（429 限流文案、500 HTML、404 说明）；现有实现只豁免 502/401，其余被替换为 `E_EMPTY_BODY` 属于吞错，且与 README 声明漂移。空体错误同样透传（保证「保留状态 + 正文」逐字节一致）。

**备选**：仅扩展豁免到 4xx——遗漏 5xx，不采用；全部非 JSON 透传（含 2xx）——改变成功路径现有语义，超出本 finding，不采用。

### D7：`P7` 回退改投脱敏字节（fail-closed）

**决策**：`rewrite.rs` 注入分支重解析 `redacted_text` 失败时，转发 `redacted_text` 字节（`original_valid` 时）；`normalized_out` 仅在成功重序列化时置位。抽纯函数承载决策以便构造性测试。

**理由**：脱敏后重解析失败属病态场景，安全优先于可用性——脱敏字节可能令上游 400，但绝不外泄原文；本地拒收需给 `RewriteOutput` 增错误通道与调用方分支，扩大改动面。头部声明不再撒谎（未重序列化不置位）。

**备选**：直接拒绝请求——需错误通道，apply 成本高，不采用（若后续有需要另立 change）。

### D8：`X2`/`P9` 工具提取共享 helper 与桶号对齐

**决策**：把字段归一、合成 id、Responses `output[]` 桶号提取抽到 `service/llm_gateway/tool.rs` 的 crate-internal helper，新增 `emit_warn: bool` 参数保持现值（非流 warn、流式静默）；两公有入口签名不变；流式 `output[]` 桶号对齐 `item.output_index.unwrap_or(i)`。

**理由**：README §6.5「同调用同结论」为既有契约，双实现漂移（warn 有无、桶号口径）是缺陷温床；共享 helper 消除漂移且不改变任何线上可观测结果（除流式不再数组下标错桶）。

**备选**：合并两入口为单函数——返回类型不同（`ToolCall` vs 四元组），合并引入更大重构，不采用；仅在 fragments 复制非流逻辑——漂移复现，不采用。

### D9：`P11` 无冒号 `data` 行按空值字段处理

**决策**：`dispatch_block` 对无冒号的 `data` 行 push 空串（与多 `data:` 行 `\n` 合并语义一致）；其他无冒号行维持忽略。

**理由**：WHATWG 字段解析：行内无冒号时 field=整行、value=""；`data` 字段值为空串仍参与 data 缓冲。现实现整行忽略，多 `data:` 行合并时丢一段换行，属解析偏差。

### D10：`P3`/`P5`/`P10` 审计结论 = **audited COMPLIANT, no change**

- **`P3`（`stream_options`）audited COMPLIANT, no change**：`protocol.rs:111-130` 仅 `Protocol::Chat` 注入、按 key 合并（用户显式 `include_usage:false` 保留不覆写）、Responses/Anthropic 不注入；`rewrite.rs:55-66`（注入分支）与 `rewrite.rs:106-119`（`apply_stream_options_injection` 回退决策，P7 后仍注入即声明 `x-veil-normalized`）；与 README §7.2 及官方规范（Responses 仅 `include_obfuscation`）一致。证据：`should_inject_stream_options` 返回条件与非 Chat 早退；`inject_stream_options` 用 `entry(...).or_insert(true)` 保留既有键。
- **`P5`（终端去重常规路径）audited COMPLIANT, no change，缺口由 `N1` 收口**：`terminal.rs:23-57` chat 归一恰一 `[DONE]`、anthropic 恰一 `message_stop`、responses 恰一 `completed/failed`；`spawn.rs:265`（JSON 分支终端后跳过）、`467`（`event_terminal` 置位）、`519`（`[DONE]` 分支终端后跳过）在常规路径正确抑制终端后帧。唯一缺口是 `N1` 覆盖的前置合成分支（`spawn.rs:223` 守卫，任务 1.1/1.2 收口），故不另立修复。
- **`P10`（usage 口径）audited COMPLIANT, no change**：`usage.rs:92-103` 五列（prompt/completion/total/cached_read/cached_write）逐列取 `max`；`usage.rs:213-217` 三级回退（顶层 `usage` → `response.usage` → `response.response.usage`，含流式 `response.completed`）；与 README §7.2 同字。不变更。

### D11：`P8`（= `X5`）转出交叉引用

**决策**：`placeholder.rs:175-189` 死分支删除由 change `veil-code-hygiene-closeout` 负责；本 change 不触碰 `placeholder.rs`，仅在 proposal 覆盖表与 design 本条交叉引用，避免双 change 重复删除。

## Risks / Trade-offs

- [`N1` 守卫收紧后终端后帧全丢] → 若上游终端后还有合法元数据帧（当前协议无此语义）→ 以 spec「恒恰一终端」为准，属有意；回归测试覆盖 `completed → error/incomplete`。
- [`P1` 补 `[DONE]` 被下游视为异常] → 下游若依赖「缺 DONE 判截断」→ README §7.2 显式声明补发口径，`truncated_mode=open_ended` 指标保留，监控可继续感知上游异常。
- [`P2` Anthropic 最小信封被严格客户端拒收] → 若 SDK 要求 `message_delta` → 以 spec 场景「真空流最小终止」为准；apply 阶段若实测需要可补 `message_delta`（不改变「不伪造内容/成功」约束），须同步 spec。
- [`N2` 透传后下游 SDK 解析非 JSON 失败] → 错误状态本属异常路径，透传保真优于合成 502；README §7.2 声明。
- [`P4` 单帧 failed 丢失 `[truncated]` 文本] → 诊断信息改由 `response.error.message` 承载（`truncated`/上游 error message）；如监控依赖合成文本需同步调整。
- [`X2` helper 抽取引入行为漂移] → `emit_warn` 参数逐入口保留现值 + 交叉一致性测试锁定；apply 阶段逐单测比对。

## Migration Plan

1. 按 tasks 顺序落地：先解析与终端守卫（`N3`/`P11`/`N1`），再终止语义（`P1`/`P2`/`P4`），再透传与提取（`N2`/`P7`/`P9`/`X2`），最后记录与门禁。
2. 每组独立 `cargo test -p veil <组>`；README §7.2/§8.6 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；下游可感知的行为变化（补终止帧、错误体透传、单帧 failed）由 README §7.2/§8.6 声明。

## Open Questions

- 无。`P3`/`P5`/`P10` 已裁定维持现状；若 apply 阶段实测 Anthropic 最小信封需额外帧（如 `message_delta`），以 spec「最小终止序列」Scenario 为准补充并回到本 design 记录差异。
