## 1. P1 协议合成帧（`F-01`/`B1`；`llm-protocol-hardening`/`redaction`）

- [x] 1.1（F-01）`src/service/block_inject/frames.rs:348-351` 非流 Responses 阻断体补齐必需字段，改为与流式 `responses_failed_frame`（`:141-144`）同形：`{id, object:"response", created_at, model, status:"failed", output:[], error:{message}}`；`output` 恒空数组、`status` 恒 `failed`；`model` 优先回显上游归一值（与同函数 chat/anthropic 分支 `:306-310`、`:333-337` 同口径，缺失才 `"unknown_model"`）；`id` 优先上游 `id` → `conv_id` → 合成；`created_at` 优先上游 → now；`error` **仅保留 `message`**（不合成 `code`/`param`）；构造面 `:276-347`，调用点 `src/handler/llm/nonstream.rs:220-238`；新增 `nonstream_responses_block_body_required_fields` 测试
  - 验证：`grep -n "object\|status\|output" src/service/block_inject/frames.rs` 命中 `:348-351` 附近补齐 object/status/output 字段
  - 验证：`cargo test -p veil nonstream_responses_block_body_required_fields` 通过；五字段齐全、`output` 为空数组、`error` 无 `code`/`param`

- [x] 1.2（B1）`src/handler/llm/pump/spawn/terminal.rs:208` 残余路径的 `restore_response_with_spans` 改为 `restore_response_with_spans_json`（与 `src/handler/llm/pump/spawn/event_loop.rs:570`、`:578` 两处正常帧同口径），使明文含 `"`/`\`/控制字符时按深度转义（`src/service/redaction/scope.rs:219-251`）写入，替代逐字插入变体（`:204`）；新增 `residual_frame_json_escape_restore` 测试
  - 验证：`grep -n "restore_response_with_spans_json" src/handler/llm/pump/spawn/event_loop.rs` 命中 `:570`、`:578` 两处（对照锚点；terminal.rs 仅 295 行、无 `:576-578`）
  - 验证：`cargo test -p veil residual_frame_json_escape_restore` 通过；明文含双引号/反斜杠的残余帧还原后仍为合法 JSON

- [x] 1.3（F-01）`src/service/block_inject/frames.rs:276-347` 补 `#[cfg(test)]` 锚点断言覆盖 `upstream` 回显三级回退（`model`/`id`/`created_at`），并覆盖调用点 `src/handler/llm/nonstream.rs:220-238` 传空 `upstream` 的降级路径
  - 验证：`grep -n "unknown_model\|conv_id\|created_at" src/service/block_inject/frames.rs` 命中三级回退分支
  - 验证：`cargo test -p veil nonstream_responses_block_body_upstream_echo` 通过；上游 `model`/`id` 存在时回显、缺失时回退默认

## 2. Responses 与 Anthropic 合成帧（`F-02`/`F-03`/`F-04`/`F-08`；`llm-protocol-hardening`/`gateway-protocol-fix`）

- [x] 2.1（F-02/F-03）`src/handler/llm/pump/spawn/event_loop.rs:156-181` 新增 `responses_seq_cursor: Option<u64>`：仅协议为 Responses 且帧为可解析 JSON 时取 `extract_responses_seq(v)`（`src/handler/llm/pump/event.rs:246-251`）更新，公式 `cursor = Some(max(cursor.unwrap_or(0), seq))`；缺 `sequence_number` 的帧不更新、回退值忽略；更新时机在每帧解析后、任何分流前（`:181` 之后），覆盖次要帧/被 hold 缓冲帧/被替换的 error 帧；新增 `responses_seq_cursor_tracks_max` 测试
  - 验证：`grep -n "responses_seq_cursor\|extract_responses_seq" src/handler/llm/pump/spawn/event_loop.rs` 命中游标声明与更新点
  - 验证：`cargo test -p veil responses_seq_cursor_tracks_max` 通过；缺序号帧不推进、回退值不降游标

- [x] 2.2（F-02/F-03）`src/service/block_inject/frames.rs:99-117`（`protocol_block_frames`）与 `:405-414`（`synthesize_truncation`）以 `base = cursor.map_or(0, |c| c + 1)` 为 7 帧起始基准，`synthesize_truncation` 传 `Some(base)` 给 `responses_failed_frame`（修正当前误传 `None`，`:409-413`）；真空流零帧 `base=0`，既有 0..6 全序列与测试 `synth_frames_sequence_number_monotonic`（`:555-573`）不变；`type:"error"` 单帧沿用上游自带序号（`src/handler/llm/pump/event.rs:187`、`spawn/event_loop.rs:256-261`）；新增 `synth_frames_sequence_number_after_block` 测试（`synth_frames_sequence_number_monotonic` 为既有）
  - 验证：`grep -n "map_or(0\|base\|responses_failed_frame" src/service/block_inject/frames.rs` 命中两处注入点传 base
  - 验证：`cargo test -p veil synth_frames_sequence_number_monotonic` 与 `cargo test -p veil synth_frames_sequence_number_after_block` 均通过；阻断帧 base 严格大于已发序号

- [x] 2.3（F-04）`src/service/block_inject/frames.rs:72-83` 新增 `anthropic_block_frames_full(reason, index, conv_id)`，在既有四帧前补恰一 `message_start`（空 `content`、null `stop_reason`、usage 全 0），抽出 `anthropic_message_start(id, model)` 复用真空流构造（`:433-455`），`id = conv_id 非空 ? conv_id : "blocked-0"`、`model = "unknown_model"`；旧 2 参函数委托新函数（`conv_id = None`）；`message_stop` 保持空对象；分派点 `:99-117` 同步；canonical `openspec/specs/gateway-protocol-fix/spec.md:22-29` 的"四件套顺序"改"五件套顺序"；新增 `anthropic_block_frames_message_start_first` 测试
  - 验证：`grep -n "anthropic_message_start\|anthropic_block_frames_full\|message_start" src/service/block_inject/frames.rs src/service/block_inject.rs` 命中抽出与补首帧
  - 验证：`cargo test -p veil anthropic_block_frames_message_start_first` 通过；首帧为 `message_start` 且原四帧内容/顺序不动

- [x] 2.4（F-08）`src/handler/llm/pump/spawn/event_loop.rs:178-180` 的 Chat 分支置判据 `v.get("error").is_some() && v.get("choices").is_none()`（顶层 error 且无 choices），命中即 `state.terminal_sent = true`、不再注入 `[DONE]`；`src/service/sse/meta.rs:9-24` 新增 `TruncatedMode::UpstreamError` 以区别于 `open_ended`；新增 `chat_error_frame_is_terminal` 测试
  - 验证：`grep -n "UpstreamError\|terminal_sent\|choices" src/handler/llm/pump/spawn/event_loop.rs src/service/sse/meta.rs` 命中判据与新增枚举
  - 验证：`cargo test -p veil chat_error_frame_is_terminal` 通过；error 帧后无 `[DONE]`、`choices` 含 error 字段的正常形态不误伤

- [x] 2.5（F-08）`src/handler/llm/pump/synth_flush.rs:87-107` 对齐 A-6 判据（error 帧终端不再补 `[DONE]`、不记 `open_ended`）；补单测覆盖 `is_terminal_event`（`src/handler/llm/pump/event.rs:219-231`）对 Chat 恒 false、`extract_tool_fragments`/`is_minor_event`（`:295-339`）均需 `choices` 故不误伤的边界
  - 验证：`grep -n "open_ended\|terminal_sent" src/handler/llm/pump/synth_flush.rs` 命中 error 分支不再记 `open_ended`
  - 验证：`cargo test -p veil chat_error_frame_no_done_no_open_ended` 通过；观测为 `UpstreamError`

- [x] 2.6（GAP-2 · A-6 补充）为 canonical `llm-gateway`（`openspec/specs/llm-gateway/spec.md:108-122` 截断三态）与 `observability-admin`（`openspec/specs/observability-admin/spec.md:126-128` 三态白名单）增补 delta（本 change delta 承载：`openspec/changes/veil-audit-r3-remediation/specs/llm-gateway/spec.md`、`openspec/changes/veil-audit-r3-remediation/specs/observability-admin/spec.md`），将截断态由三态扩为**四态**白名单 `silent_discard`/`open_ended`/`synthesized_failed`/`upstream_error`；`SynthesizedFailed` 的协议适用范围口径不变；**SHALL NOT** 让新增 `upstream_error` 触犯"三态之外的值 SHALL NOT 落该指标"旧条款；新增 `chat_error_frame_upstream_error` 测试
  - 验证：`grep -n "silent_discard\|open_ended\|synthesized_failed\|upstream_error" openspec/changes/veil-audit-r3-remediation/specs/llm-gateway/spec.md` 命中四态白名单
  - 验证：`cargo test -p veil chat_error_frame_upstream_error` 通过；新态 `upstream_error` 落 metrics 且四态口径与 canonical 一致

## 3. 流式出口与解析（`F-07`/`F-09`/`D2`；`stream-fidelity-fix`/`gateway-transport-fidelity`）

- [x] 3.1（F-07）抽 `pub(crate) fn data_frame(prefix: &str, data: &str) -> String` 于 `src/service/sse/` 门面（`src/service/sse.rs`，可置 `src/service/sse/emit.rs` 并重导出）：对 `data.split('\n')` 逐行输出 `data: <line>\n` 后补空行；替换 5 处重复构造 `src/handler/llm/pump/spawn/frame_feed.rs:118`、`src/handler/llm/pump/spawn/terminal.rs:196`、`:226`、`src/handler/llm/pump/synth_flush.rs:31`、`src/handler/llm/pump/spawn/event_loop.rs:674`；`event:`/`id:`/`retry:` 信封前缀不受影响；新增 `sse_data_frame_multiline_split` 测试
  - 验证：`grep -rn "data_frame\|data: {" src/service/sse.rs src/service/sse/ src/handler/llm/pump/` 命中单一实现替换 5 处
  - 验证：`cargo test -p veil sse_data_frame_multiline_split` 通过；含换行载荷拆为多条带前缀行、无裸行

- [x] 3.2（F-09）新增 `pub(crate) fn is_event_stream(content_type: &str) -> bool`（取 `;` 前段 trim 后 `eq_ignore_ascii_case("text/event-stream")`）于 `src/handler/llm/mod.rs:86-91`；`should_pump_stream`（`mod.rs:89-91`）与 `src/handler/llm/dispatch.rs:255-267`（`:258` 裸 `contains`）同批改用该谓词，消除第二决策站点；`src/handler/llm/nonstream.rs:103` 经 `should_pump_stream` 自动受益；`stream_flag` 回退语义不变、`src/router.rs:327` 的响应头测试断言勿改；新增 `content_type_event_stream_case_insensitive` 测试
  - 验证：`grep -rn "is_event_stream\|text/event-stream" src/handler/llm/` 命中两处站点改用谓词、无裸 `contains`
  - 验证：`cargo test -p veil content_type_event_stream_case_insensitive` 通过；大小写/带参数/前后空白均识别

- [x] 3.3（D2）`src/service/sse/parser.rs:117-124` 新增 `PENDING_EVENTS_MAX = 8`；`:279-351` 的 push（`:326`）超限丢最旧 + 计数 `pending_events_dropped`（经 `take_*` 访问器由泵排入观测，仿 `truncated_line_dropped_bytes`）+ 每流首次 warn；消费点 `:341-345` 语义不变；`pending_retry` 单值无需上限；**不新增导出指标**；新增 `pending_events_hard_cap_drops_oldest` 测试
  - 验证：`grep -n "PENDING_EVENTS_MAX\|pending_events_dropped" src/service/sse/parser.rs` 命中常量与丢弃计数分支
  - 验证：`cargo test -p veil pending_events_hard_cap_drops_oldest` 通过；连续 >8 个 `event:`-only 块丢最旧且计数正确

- [x] 3.4（D2）canonical `openspec/specs/gateway-transport-fidelity/spec.md:10` 声明 `pending_events` 上限与丢弃计数（不新增导出指标）；校对 TRN-1 的 `event` FIFO 配对与 `id` 最近值语义、以及"分块信封流与同内容非分块流的事件/帧计数逐一致"条款不变；新增 `sse_chunked_envelope_counts_match_unchunked` 测试
  - 验证：`grep -n "PENDING_EVENTS_MAX\|pending_events_dropped\|8" openspec/specs/gateway-transport-fidelity/spec.md` 命中上限声明
  - 验证：`cargo test -p veil sse_chunked_envelope_counts_match_unchunked` 通过；计数语义不变

## 4. 脱敏与会话保真（`B4`/`B2`/`D3`/`ARH-4`；`redaction`/`redaction-audit-coverage`/`pii-custom-compat`）

- [x] 4.1（B4）`src/service/redaction/scope.rs:434-457`（`token_restore_depths`）计算 `fragment_ctx` 并透传进 `collect_token_depths`（`:459-481`）：命中载体（`type == "response.function_call_arguments.delta"`；或 `type == "content_block_delta"` 且 `delta.type == "input_json_delta"`；或子树键名 `partial_json`/`arguments`）时对**以 `{`/`[` 开头但整体不可解析**的字符串按 `depth+1` 计入；完整可解析容器分支（`:485-508`）优先级不变；载体以外普通字符串（如 `delta.text`）**SHALL NOT** 加一；写入点为 `restore_response_with_spans_json`（`:219-251`）；若载体判定不可靠则降级为"声明限制 + 锁定回归用例"，**SHALL NOT** 无差别加一；新增 `fragment_depth_unclosed_json_plus_one` 测试
  - 验证：`grep -n "fragment_ctx\|input_json_delta\|partial_json" src/service/redaction/scope.rs` 命中载体判定与透传
  - 验证：`cargo test -p veil fragment_depth_unclosed_json_plus_one` 通过；`delta.text` 不受影响、完整容器行为不变

- [x] 4.2（B2）canonical `openspec/specs/redaction-audit-coverage/spec.md:116-123` 文本更新为位域公式 `(ci << 16) | (idx & 0xFFFF)`（`ci, idx < 2^16` 内单射无碰撞、`ci=0` 与历史 `ci*64+idx` 等值）；代码 `src/service/llm_gateway/tool.rs:143-152` 不动；补回归锁定 `ci=0` 等价锚点
  - 验证：`grep -n "ci << 16\|0xFFFF" openspec/specs/redaction-audit-coverage/spec.md` 命中位域公式
  - 验证：`cargo test -p veil chat_bucket_bitfield_ci0_equivalence` 通过；`ci=0` 桶键与历史公式等值

- [x] 4.3（D3）`src/service/pii/custom.rs:390-486`（`scan_custom`）聚合墙钟超时（`tokio::time::timeout` 到期）或阻塞任务 panic 时**SHALL NOT** 对任何规则执行超时记账，仅记一条全局 warn（含规则数与预算）并返回零命中，删除 `:440-449` 的批量记账；规则停用**仅**由 batch 内逐规则 `find_iter` Err 路径触发（连续 `RE_DOS_STRIKES=3` 次，`:489-504`）；调用点 `src/service/pii/detector.rs:37` 同步；新增 `custom_aggregate_timeout_no_strike` 测试
  - 验证：`grep -n "account_rule\|timeout\|warn" src/service/pii/custom.rs` 命中超时分支不再逐规则记账、仅全局 warn
  - 验证：`cargo test -p veil custom_aggregate_timeout_no_strike` 通过；单次聚合超时不触发三连停用

- [x] 4.4（ARH-4）`src/service/pii/custom.rs:395-396`（`PiiDetector::custom` 容器）改 `RwLock<Arc<Vec<(String, fancy_regex::Regex, String)>>>`；`scan_custom` 仅 `Arc::clone`（替换深克隆 `Arc::new(recover(read).clone())`）；唯一写点 `:236` 用 `Arc::make_mut(&mut guard).push(...)`（`spawn_blocking` 闭包 `'static` 由 Arc 满足）；调用点 `src/service/pii/detector.rs:495` 同步；新增 `custom_ruleset_arc_no_deep_clone` 测试
  - 验证：`grep -n "Arc<Vec\|Arc::clone\|Arc::make_mut" src/service/pii/custom.rs` 命中 Arc 容器替换深克隆
  - 验证：`cargo test -p veil custom_ruleset_arc_no_deep_clone` 通过；扫描结果与停用状态机语义不变

- [x] 4.5（ARH-4）`src/service/pii/custom.rs:455-484` 的 `account_rule` 批量为 `account_rules_batch(&[(name, timed_out)])`：单次获取 `strikes` → `disabled`（保持 `:3-5` 锁序），逐规则成功清零/超时累计/三连停用 + warn，跳过已停用者；替换 `:479-484` 的每规则双锁；`src/service/pii/custom/tests.rs:333,377` 锁序守护适配新形签名；新增 `custom_account_rules_batch_lock_order` 测试
  - 验证：`grep -n "account_rules_batch\|strikes\|disabled" src/service/pii/custom.rs` 命中批量单次加锁、无每规则双锁
  - 验证：`cargo test -p veil custom_account_rules_batch_lock_order` 通过；锁序与停用状态机逐项不变

## 5. 授权与资源上限（`B3`/`D1`/`D4`；`credential-vault-singleton`/`credential-approval-dual-mode`/`architecture-cleanup`）

- [x] 5.1（B3）`src/service/redaction/scope.rs:74-97` 的 `Scope` 新增请求级 `Mutex<HashSet<String>>`（随请求销毁）；在请求侧脱敏**实际产生替换**处记录本请求产出的凭据 token——由 `:376-393` 与 `src/service/redaction/leaf.rs:92-146`（`redact_leaf`）汇总 `P2tSnapshot::redact` 的替换值；**SHALL NOT** 以"请求体中出现过的 token"为白名单；`src/handler/llm/dispatch.rs:156,201,213` 每请求建 `Scope` 并复用为响应 scope 的接线不变；新增 `minted_set_records_only_produced_tokens` 测试
  - 验证：`grep -n "minted\|HashSet<String>\|redact_leaf" src/service/redaction/scope.rs src/service/redaction/leaf.rs` 命中请求级 minted-set 与替换值收集
  - 验证：`cargo test -p veil minted_set_records_only_produced_tokens` 通过；调用方自带字面量 token 不进白名单

- [x] 5.2（B3）`src/service/redaction/scope.rs:136-143`（`restore_response_one`）与 `:150-210`（`restore_cred_tokens`）仅在 `token ∈ minted-set` 时调用 `CredentialVault::restore_one`（`src/service/credential_vault.rs:296-298`）/ 全量还原；未命中者**SHALL NOT** 还原，并按幻觉 token 剥离——`strip_hallucinated`（`credential_vault.rs:319-330`）增 `allowed` 入参（或等价过滤）使未授权 token 形态不透出下游；`CredentialVault` 保持进程单例（`:32,36,214,315`）；`make_cred_token` 六位零填充、`token_re` `\d{4,}`、placeholder 门控 `\d{6,}`、prompt-cache 关联（`:209-213`）均不变；新增 `restore_unauthorized_token_stripped` 测试
  - 验证：`grep -n "minted\|allowed\|strip_hallucinated" src/service/redaction/scope.rs src/service/credential_vault.rs` 命中还原门控与 allowed 过滤
  - 验证：`cargo test -p veil restore_unauthorized_token_stripped` 通过；未授权 token 不还原且被剥离

- [x] 5.3（B3）canonical `openspec/specs/credential-vault-singleton/spec.md` 增补「还原授权为请求级」条款；`README.md` §7.3 登记行为收紧（字面 token 现按未授权剥离属安全修复、非兼容回归）；约 20 处直接调 `restore_response*` 的测试（`src/service/redaction/scope_tests.rs`、`src/service/redaction/scope_p2_tests.rs`、`src/service/credential_vault.rs`）先经一次请求侧脱敏或经 `#[cfg(test)]` 播种入口
  - 验证：`grep -n "请求级\|minted\|还原授权" openspec/specs/credential-vault-singleton/spec.md README.md` 命中授权条款
  - 验证：`cargo test -p veil scope` 全绿；既有还原测试经播种后不回退

- [x] 5.4（D1）`src/service/audit/hold.rs:80-116` 的 `AuditHold` 新增 `account_pending_frame(bytes) -> HoldVerdict`：条目维度复用 `AUDIT_HOLD_MAX_ENTRIES=4096`，字节维度以**独立计数器**受 `AUDIT_HOLD_MAX_BYTES` 约束；`src/handler/llm/pump/spawn/event_loop.rs:602-606` push **前**（`:602`）调用，返回 `Rejected` 走既有 `reject_reason = "audit-hold-overflow"` 阻断臂（`:529-557`），**不静默丢弃**；调用面 `:383-389`、`src/handler/llm/pump/decide.rs:89-96`、`src/handler/llm/pump/spawn/terminal.rs:103-113,153,176-191`、`src/handler/llm/pump/spawn/setup.rs:60` 核对；新增 `pending_tool_frames_same_index_zero_byte_flood_bounded` 测试
  - 验证：`grep -n "account_pending_frame\|AUDIT_HOLD_MAX_ENTRIES\|audit-hold-overflow" src/service/audit/hold.rs src/handler/llm/pump/spawn/event_loop.rs` 命中记账与阻断臂
  - 验证：`cargo test -p veil pending_tool_frames_same_index_zero_byte_flood_bounded` 通过；同 index 零字节分片洪泛下有界且被阻断

- [x] 5.5（D4）`src/service/credential/approval.rs:237-249`（`DecisionTable::begin`）顺序改为 `sweep(now)` → 循环驱逐终态 `Decided`（按 `created` 升序、key 字典序 tie-break）直至有空位 → 满表且**仅余 `InFlight`** 时新增 `BeginOutcome::Saturated`；`:266-293` 调用点及 `src/service/credential/vault_ops.rs:320-340,436-456`、`src/service/credential/approval.rs:422-450` 映射为 `VeilError::RateLimited{retry_after_secs: 60}`（`src/error.rs:113`，`429 + Retry-After`）并递增 `overflow_count` + 记 warn；**SHALL NOT** 驱逐 `InFlight`、**SHALL NOT** 对新键伪造 `202 + E_PENDING`；容量沿用 `DECISION_TABLE_MAX_ENTRIES=4096`（`approval.rs:212`）；同键在途仍 `202 + E_PENDING`；同批修订 canonical `openspec/specs/architecture-cleanup/spec.md:24,36-39` 的 backstop 条款；新增 `decision_table_begin_saturated_429` 与 `decision_table_begin_saturated_metrics` 测试
  - 验证：`grep -n "Saturated\|RateLimited\|overflow_count" src/service/credential/approval.rs src/service/credential/vault_ops.rs` 命中新增分支与映射
  - 验证：`cargo test -p veil decision_table_begin_saturated_429` 通过；满表仅余 InFlight 返回 429、同键在途仍 202
  - 验证：`grep -n "approval_decision_overflow_total\|decision_table_size" src/service/credential/approval.rs` 命中既有指标键保留；`cargo test -p veil decision_table_begin_saturated_metrics` 通过——饱和路径后 `approval_decision_overflow_total` 递增、`decision_table_size` 正常导出递增，防 `begin` 改造致指标退化

## 6. 架构与边界（`ARH-2`/`ARH-8`/`ARH-9`/`ARH-10`/`ARH-11`/声明锁/越层边界/同步扫描声明/守护声明；`architecture-cleanup`）

- [x] 6.1（ARH-2）`src/handler/llm/pump/event.rs:125-136`（`sticky_terminal_event`）、`:140-159`（`responses_failed_incomplete`）、`:166-188`（`responses_error_object`）改收 `parse_event_data` 产物 `Option<&Value>`，原字符串签名降为 `#[cfg(test)]` 包装（`:355-610` 测试面零改）；生产调用点 `src/handler/llm/pump/spawn/event_loop.rs:192/214/235` 传 `parsed.as_ref()`；metric 语义（解析失败才 `record_terminal_fallback()`）保留；新增 `parse_event_data_single_parse` 测试
  - 验证：`grep -n "fn parse_event_data\|Option<&Value>" src/handler/llm/pump/event.rs` 命中三函数改签名
  - 验证：`cargo test -p veil parse_event_data_single_parse` 通过；每帧恰 1 次解析、fallback metric 语义不变

- [x] 6.2（ARH-2）守护升级：`src/handler/llm/pump/event.rs::parse_event_data` 加 `#[cfg(test)]` 解析计数器与 `take_parse_count`，泵 e2e 用例断言每帧恰 1 次；`src/handler/llm/pump/model_bucket_tests.rs:12-23` 源码守护增加"`event.rs` **生产段**（首个 `#[cfg(test)]` 之前）`from_str` 计数为 0"检查；新增 `event_rs_production_prefix_no_from_str` 测试
  - 验证：`grep -n "take_parse_count\|from_str\|cfg(test)" src/handler/llm/pump/event.rs src/handler/llm/pump/model_bucket_tests.rs` 命中双守卫
  - 验证：`cargo test -p veil event_rs_production_prefix_no_from_str` 通过；生产段零 `from_str`

- [x] 6.3（ARH-8）`src/service/llm_gateway/hop.rs:46-64` 的 `keys: Vec<String>` 改 `Vec<HeaderName>`（`.keys().cloned()`），`is_hop(k.as_str())` 直比、`remove(&k)` 直取、去掉 `:61` 的 `k.to_lowercase()`；`Connection` 头内动态项（`:48-55`）保持 `Vec<String>` + lower+trim；`hashset_reuse_equivalence`（`:228`）注释显式声明"锁行为等价，不锁分配属性"；性能收益标注为**假设**（待 bench）、不作对外承诺；剥离计数与方向 `debug_assert` 语义不变
  - 验证：`grep -n "Vec<HeaderName>\|to_lowercase\|remove(&" src/service/llm_gateway/hop.rs` 命中 HeaderName 直取、动态项保留 lower
  - 验证：`cargo test -p veil hashset_reuse_equivalence` 与 `cargo test -p veil hop` 全绿；过滤计数与保留头不变

- [x] 6.4（ARH-9/ARH-10/ARH-11）canonical `openspec/specs/architecture-cleanup/spec.md:168-208` 收窄三处 over-claim：ARH-9 收敛对象限定为协议**判定/分派谓词**（`Protocol` 类型化方法），逐协议差异产物构造（`src/handler/llm/pump/synth_flush.rs:86`、`src/handler/llm/pump/event.rs:92/106/221/238/297`、`src/service/block_inject/terminal.rs:24/63`、`src/service/block_inject/frames.rs:106/283/422`、`src/service/llm_gateway/usage.rs:37/139/180`、`src/service/llm_gateway/tool.rs:242`、`src/service/llm_gateway/placeholder.rs:193`）**SHALL NOT** 视为重复分派；ARH-10 `UpstreamStatus` 强制范围限定为网关**边界/分发点**（`src/handler/llm/dispatch.rs:322`），纯谓词 `classify_empty`（`src/service/llm_gateway/mod.rs:241-245`）的 `u16` 入参**SHALL** 为例外；ARH-11 仅对已枚举不变量（hop 方向 `hop.rs:42-45`、tool 位域 `tool.rs:149-150`、carry 剥离 `src/handler/llm/pump/carry.rs:44`）提供守护，**SHALL NOT** 承诺未枚举项
  - 验证：`grep -n "判定/分派\|边界/分发点\|未枚举" openspec/specs/architecture-cleanup/spec.md` 命中三处收窄文本
  - 验证：`cargo test -p veil` 全绿；本任务无代码伴随改动（纯 spec）

- [x] 6.5（声明锁 + `Bytes`）`src/service/llm_gateway/mod.rs:309` 的 `axum::body::Bytes` 改 `bytes::Bytes`（`bytes = "1"` 已是直接依赖，`Cargo.toml:33`）；`src/service/mod.rs:29-68` 声明锁守护改为对**首个 `#[cfg(test)]` 之前的生产前缀** token-scan `axum::`，非白名单文件命中即失败，白名单文件（`src/service/llm_gateway/hop.rs:3`、`src/service/llm_gateway/mod.rs:8`）内每个 `axum::` 之后须为 `http::`；新增 `service_production_prefix_axum_whitelist` 测试
  - 验证：`grep -n "bytes::Bytes\|生产前缀\|axum::http" src/service/llm_gateway/mod.rs src/service/mod.rs` 命中 Bytes 替换与强化守护
  - 验证：`cargo test -p veil service_production_prefix_axum_whitelist` 通过；非法 `axum::` 命中即失败

- [x] 6.6（越层 `RegisterParams`）`src/handler/credential.rs:161-180` 的 `RegisterParams` 字段 trim 与构造下沉为 `src/service/credential/register_map.rs::parse_register_params`（handler 仅调用）；`src/handler/credential.rs:307` 的 `registry::HashChangeOutcome::from_reaction` 保留为领域解析器并声明为已知边界；新增 `parse_register_params_trim` 测试
  - 验证：`grep -n "parse_register_params" src/service/credential/register_map.rs src/handler/credential.rs` 命中构造下沉与调用点
  - 验证：`cargo test -p veil parse_register_params_trim` 通过；trim 与构造语义不变

- [x] 6.7（同步内置扫描 B）canonical `openspec/specs/architecture-cleanup/spec.md` 增补声明：`boundary_spans` 在 pump async 任务同步执行内置扫描但**不接收整帧**，窗口由 `BoundaryHold::push` 构造为 `tail_window(held)+head_window(data)`，上界 `2×PII_HOLD_MAX`（默认 128 字符；配置上界 1MiB），`window==0` 时不调用；该热路径同步 CPU 为 O(PII_HOLD_MAX) 非 O(帧)；**SHALL NOT** 为每帧新增 `spawn_blocking`。锚点 `src/handler/llm/pump/spawn/setup.rs:158-167`、`src/service/redaction/seam.rs:32-75`、`src/service/pii/custom.rs:387-407`、`src/service/pii/chunk.rs:150-155`、`src/config/env_parse.rs:42-45,459-467`
  - 验证：`grep -n "2×PII_HOLD_MAX\|spawn_blocking\|同步" openspec/specs/architecture-cleanup/spec.md` 命中同步扫描声明
  - 验证：`cargo test -p veil` 全绿；本任务无代码伴随改动

- [x] 6.8（守护声明 `shutdown_wired` C-1）canonical `openspec/specs/architecture-cleanup/spec.md` 增补源码字符串守护声明：断言优雅停机接线顺序、禁止二次构造 `AppState`、要求复用 `CleanupHandles`；**非行为覆盖**（等价重写可绕过），刷盘行为已由 `src/main.rs:318-330` 行为锁定；保留并声明局限、**SHALL NOT** 引入进程级 harness；登记升级触发条件（停机接线再现静默断链且源码守护未拦截时另立 change）。锚点 `src/main.rs:280-316,318-330`、`src/service/mod.rs:303-333`
  - 验证：`grep -n "shutdown_wired\|源码字符串\|CleanupHandles" openspec/specs/architecture-cleanup/spec.md` 命中守护声明
  - 验证：`cargo test -p veil shutdown_wired` 全绿；声明与现有守护一致

## 7. 文档与门禁口径（`F-06`/`F-05`/`F-10`/`F-11`/`G-1`/`G-2`/`G-3`/`G-4`/`G-5`/`I-D`；`stream-protocol-parity`/`llm-protocol-hardening`/`stream-fidelity-fix`/`docs-test-parity`/`docs-contract-sync`/`go-client-interop`/`credential-flow-parity`/`credential-api`）

- [x] 7.1（F-06）删除 canonical `openspec/specs/stream-protocol-parity/spec.md:8-20` 整节「Empty streams stay open-ended for chat/anthropic」，替换为迁移声明（Chat 真空流补恰一 `[DONE]`、Anthropic 最小 `message_start`+`message_stop`、Responses 恰一 `response.failed`；`truncated_mode` 保留 `open_ended`/`synthesized_failed` 观测口径；**SHALL NOT** 依历史文本实现开放结尾）；`:96` 干净收尾条款不动；另补 canonical `openspec/specs/stream-fidelity-fix/spec.md:95` 的 `clean_close` 例外（Chat 干净 EOF 仅补 `[DONE]`、不记 `open_ended`）
  - 验证：`grep -rn "Empty streams stay open-ended" openspec/specs/` 无残留（归档目录除外）
  - 验证：`cargo test -p veil vacuum_stream_three_protocol_e2e_comparison` 通过；三协议真空流最小终止对照一致

- [x] 7.2（F-05）canonical `openspec/specs/llm-protocol-hardening/spec.md:27-39` 增补一条 Requirement，明确**真空流**（零帧，走最小 `message_start`+`message_stop`）与**中途断流**（已发内容帧后异常 EOF，仅记 `truncated_mode=open_ended`，**SHALL NOT** 合成 `message_stop`）的分野；`src/handler/llm/pump/synth_flush.rs:108-113` 代码保持现状（A-4），对照 `src/service/block_inject/frames.rs:421-455`；新增 `anthropic_midstream_eof_no_message_stop` 测试
  - 验证：`grep -n "真空流\|中途断流" openspec/specs/llm-protocol-hardening/spec.md` 命中分野条款
  - 验证：`cargo test -p veil anthropic_midstream_eof_no_message_stop` 通过；不合成终端

- [x] 7.3（F-10）canonical `openspec/specs/stream-protocol-parity/spec.md:124-136` 按「无法保序则显式声明并由测试锁定」条款登记：放行序定义为"每槽按到达序取出、由该槽完成事件驱动"，跨槽并行 item 的相对 `sequence_number` 次序 **SHALL NOT** 被保证；`src/handler/llm/pump/toolbuf.rs:45-107` 补交错并行 item 用例锁定实际放行序；`toolbuf.rs:7-22` 与 `src/handler/llm/pump/spawn/event_loop.rs:318-379` 代码不改
  - 验证：`grep -n "到达序\|跨槽\|SHALL NOT" openspec/specs/stream-protocol-parity/spec.md` 命中放行序声明
  - 验证：`cargo test -p veil toolbuf_interleaved_parallel_release_order` 通过；实际放行序被锁定

- [x] 7.4（F-11/G-4）门禁措辞降级：`scripts/check_doc_paths.py` docstring、`scripts/gate.sh:8`、`scripts/README.md:29`、r2 归档 `tasks.md:395` 的"行号**语义**校验"改述为"行号**范围**校验（存在性 + 在界内）"；canonical `openspec/specs/docs-test-parity/spec.md` 增补声明"被引行内容与文档语义的一致性由 code review 保证，门禁脚本不校验"，并登记升级触发条件（同类内容漂移再现则改为登记式语义锚点表）；归档失效指针（r2 归档 `tasks.md:36/:37/:103`、`:114`）判定为 apply 期历史快照、**归档目录禁改**、仅注记，**SHALL NOT** 扩展 `PENDING_REFS`/`PENDING_LINE_REFS`（`check_doc_paths.py:154,166-168`）
  - 验证：`grep -rn "行号范围校验\|范围校验" scripts/check_doc_paths.py scripts/gate.sh scripts/README.md` 命中降级措辞
  - 验证：`python3 scripts/check_doc_paths.py` exit 0、0 FAIL；`grep -n "code review 保证\|SHALL NOT 校验被引行" openspec/specs/docs-test-parity/spec.md` 命中声明
  - 验证：`grep -n "ARCHIVED_PREFIX\|归档文档行号引用" scripts/check_doc_paths.py` 命中归档豁免判定与计数打印；`python3 scripts/check_doc_paths.py --self-test` 打印归档判定正确；脚本输出含「归档文档行号引用 N 处未校验」且归档越界计数为 0 FAIL（归档行号冻结快照豁免，与 canonical `docs-test-parity` 新增 Scenario 同源）

- [x] 7.5（G-1）指针与语义修正批：`README.md:408` 指针改符号锚 `src/handler/llm/pump/spawn/event_loop.rs::handle_event`（首插入点 `:353`，`:468/:511` 同符号）；`README.md:726` 与 canonical `openspec/specs/credential-auth-hardening/spec.md:29` 的 `vault_ops.rs:458-464` → `vault_ops.rs:555-561`（`admin_ok` 的 `OBSERVABILITY_ADMIN_TOKEN` 比较）；canonical `openspec/specs/docs-test-parity/spec.md:34,39` 的 `env_parse.rs:469-478` → `env_parse.rs:493`、`main.rs:45` → `main.rs:46`；3 处源码注释（`src/service/audit/verdict.rs:44-45`、`src/service/block_inject.rs:464-465`、`src/service/audit.rs:28`）同步；canonical `openspec/specs/docs-contract-sync/spec.md:47` 的 `env_parse.rs:342-347` → `env_parse.rs:295-296`；canonical `openspec/specs/go-client-interop/spec.md:77` 的 `credential.rs:147-183` → `credential.rs:61-101` / `:190-199`；canonical `openspec/specs/credential-flow-parity/spec.md` 低危偏移（`:10/:34/:58/:223/:247`）与 `:120` PII 缓存描述（校正为无全局 PII 缓存、请求级 `Scope::pii`）；陈旧注释 `src/service/llm_gateway/placeholder.rs:26`、`src/service/metrics/store/tests.rs:107`、`src/handler/llm/pump.rs:1-6`（`pump` 子模块枚举补 `carry`/`decide`）
  - 验证：`grep -n "handle_event\|555-561\|env_parse.rs:493\|main.rs:46\|295-296\|61-101" README.md openspec/specs/docs-test-parity/spec.md openspec/specs/docs-contract-sync/spec.md openspec/specs/go-client-interop/spec.md` 命中修正值
  - 验证：`python3 scripts/check_doc_paths.py` exit 0；旧指针（`:458-464`/`:469-478`/`:45`/`:342-347`/`:147-183`）无残留

- [x] 7.6（G-5）文档完整性缺口：补 `PROXY_URL`/`PROXY_HTTP_TIMEOUT`（`README.md` §5）、`VEIL_APPROVAL_E2E_URL`/`VEIL_APPROVAL_E2E_CALLER`、`scripts/README.md:33-38` 的 `PENDING_LINE_REFS` 说明、`README.md` §7.2 的 `total_tokens` 求和回退语义
  - 验证：`grep -n "PROXY_URL\|PROXY_HTTP_TIMEOUT\|VEIL_APPROVAL_E2E_URL\|total_tokens" README.md` 命中新增说明
  - 验证：`grep -n "PENDING_LINE_REFS" scripts/README.md` 命中说明

- [x] 7.7（G-2）未 enrolled 语义纠正：canonical `openspec/specs/credential-flow-parity/spec.md:311-323` **与** canonical `openspec/specs/credential-api/spec.md:10,20-21` 均改写为"未 enrolled 默认**转审批**（`AUTO_APPROVE=false` 时才 `403`）"，并指向真相源 canonical `openspec/specs/credential-auth-hardening/spec.md:89-101`；同步修正 `credential-flow-parity/spec.md:4` 的 Purpose 措辞；代码锚点 `src/service/credential/auth.rs:262-280`（未 enrolled 且 `Deny` → 403，否则 `approval_dual_mode`）
  - 验证：`grep -n "默认转审批\|AUTO_APPROVE=false" openspec/specs/credential-flow-parity/spec.md openspec/specs/credential-api/spec.md` 命中纠正文本
  - 验证：`grep -n "credential-auth-hardening" openspec/specs/credential-flow-parity/spec.md openspec/specs/credential-api/spec.md` 命中真相源指向

- [x] 7.8（I-D）保留 `responses_failed_frame` 手写 `format!` 信封：`src/service/block_inject/frames.rs:134-159` 不动——`responses_frame` **无条件**写 `sequence_number`，失败帧仅在上游 error 携带序号时写（`:149-151`）；改走 `responses_frame` 会为"序号不可得"情形**新增**字段、违 README §7.2 的 TRN-2 lossy 边界（"可得时写入"）。信封格式在 `frames.rs` 至少 5 处重复（`:58-60`、`:75-81`、`:152`、`:158`、`:452-453`），单点统一不构成收敛，本批不抽取，信封去重（抽 `sse_event`）列为可选后续；在 canonical `openspec/specs/llm-protocol-hardening/spec.md` 显式声明。对照 `src/handler/llm/pump/event.rs:539,577,591,612`、`src/handler/llm/pump/spawn/event_loop.rs:257`
  - 验证：`grep -n "sequence_number.*可得\|lossy\|SHALL NOT" openspec/specs/llm-protocol-hardening/spec.md` 命中保留声明
  - 验证：`grep -n "sequence_number" src/service/block_inject/frames.rs` 命中失败帧条件写入不变

- [x] 7.9（G-3b）为 canonical `llm-proto-closeout`（`openspec/specs/llm-proto-closeout/spec.md:28-40`、`:47-54`）增补 delta（本 change delta 承载：`openspec/changes/veil-audit-r3-remediation/specs/llm-proto-closeout/spec.md`）：MODIFIED「空流三协议语义与差异声明」——三协议真空流**均走最小终止**（Chat 恰一 `[DONE]`、Anthropic 最小 `message_start`+`message_stop`、Responses 恰一 `response.failed`），删除「Chat/Anthropic 保持 open-ended、零合成帧」；MODIFIED「Chat 缺 [DONE] 可观测」——对齐 `clean_close` 例外与上游错误帧语义（干净 EOF 仅补 `[DONE]` 且不记 `open_ended`；带顶层 `error` 帧记 `upstream_error` 而非 `open_ended`；**SHALL NOT** 在 `finish_reason` 非 null 的正常收尾后记 `open_ended`）
  - 验证：`grep -rn "保持 open-ended\|open-ended（零合成帧" openspec/specs/` 归零（归档目录除外）
  - 验证：`cargo test -p veil vacuum_stream_three_protocol_e2e_comparison` 通过；三协议真空流最小终止口径与 `llm-protocol-hardening` 一致

- [x] 7.10（M4 · G-2 补充）`credential-flow-parity` canonical 直改：canonical `openspec/specs/credential-flow-parity/spec.md:4`（Purpose）措辞与 `:223`（紧急吊销网段段）指针具体化——Purpose 中「未 enrolled 兼容放行三项登记契约」改写为「未 enrolled 默认转审批（`AUTO_APPROVE=false` 才 `403`）」口径；`:223` 末尾「（`src/service/credential/` 网络判定）」具体化为 `vault_ops.rs:538`（`is_private_peer` 定义处，IPv4-mapped IPv6 环回判定）
  - 验证：`grep -n "未 enrolled" openspec/specs/credential-flow-parity/spec.md` 命中「默认转审批」新措辞（无「兼容放行」旧措辞）
  - 验证：`grep -c "vault_ops.rs:538" openspec/specs/credential-flow-parity/spec.md` 命中（计数 ≥1）

## 8. 管理面（`D5`/`D6`/门控 404；`observability-admin`）

- [x] 8.1（D5）`src/handler/admin.rs:405-483`（`since` 在 `:454`）改为仅接受 `[dhm]<整数>` 形态（与 `day_key`/`hour_key`/`five_min_key` 产出同形），非法值返回 `400 + E_BAD_REQUEST`（消息列明合法形态），**SHALL NOT** 以 `i64::MIN` 回退为全量无过滤；与既有 `granularity`/`range` 非法即 400 口径一致（`:430-452`）；消费面 `src/service/metrics/aggregate.rs:183-188,412-445` 核对；`README.md` §3 与 canonical `openspec/specs/observability-admin/spec.md` 补注取值形态；epoch/日期形态另立 change；新增 `admin_series_since_invalid_400` 测试
  - 验证：`grep -n "E_BAD_REQUEST\|since\|\[dhm\]" src/handler/admin.rs` 命中非法值 400 分支、无 `i64::MIN` 回退
  - 验证：`grep -n "since" README.md` 命中 §3 的 `[dhm]<整数>` 取值形态说明
  - 验证：`cargo test -p veil admin_series_since_invalid_400` 通过；非法 `since` 返回 400 且消息列明合法形态

- [x] 8.2（D6）`src/service/credential/approval.rs:20-41` 的 `GRACE_NOTIFY_DEDUP` 改 `OnceLock<Mutex<HashMap<String, u64>>>`（value = `expires_at`）；`first_grace_notification(dedup_key, expires_at, now_secs)`：命中返回 false，`len >= GRACE_NOTIFY_DEDUP_MAX(4096)` 时先 `retain(|_, e| *e > now)`，仍满则逐出 `expires_at` 最小者 + warn 再插入；**SHALL NOT** 整表清空；调用点 `:573-584` 已持有 `expires_at`；与 `src/service/credential/ratelimit.rs:19-21,54-75` 的"容量触发清扫 + 硬上限逐出"模式一致；新增 `grace_dedup_ttl_eviction` 测试
  - 验证：`grep -n "expires_at\|retain\|GRACE_NOTIFY_DEDUP_MAX" src/service/credential/approval.rs` 命中 TTL 驱逐与不清表
  - 验证：`cargo test -p veil grace_dedup_ttl_eviction` 通过；达上限先清扫过期、仍满逐出最小 `expires_at`、不清表

- [x] 8.3（门控 404）`src/handler/admin.rs:47` 的 `with_security_headers` 提升为 `pub(crate)`，`src/router.rs:26-33` 的 `observability_gate` 在 `OBSERVABILITY_DISABLE=1` 的 404 分支复用同一函数（`src/router.rs:10` 已 `use handler::{self, admin}`）；**SHALL NOT** 修改 canonical spec 措辞（`openspec/specs/observability-admin/spec.md:140,152` 契约成立）；扩展 `tests/http_e2e_admin_matrix.rs:240-260`，对三个路径的 authed/anon 404 均断言 `cache-control` 含 `no-store`，并确认非 `/_admin` 路径不受影响（`:257-258`）；新增 `admin_gate_404_security_headers` 用例
  - 验证：`grep -n "with_security_headers" src/handler/admin.rs src/router.rs` 命中 `pub(crate)` 与 gate 分支复用
  - 验证：`cargo test -p veil --test http_e2e_admin_matrix admin_gate_404_security_headers` 通过；404 含五项安全头

## 9. 死代码与去重（`DCD-5`/去重抽取；`deadcode-positional-cleanup`）

- [x] 9.1（DCD-5）5 个仅测试引用的 `pub` 项按**引用面**收敛（canonical `deadcode-positional-cleanup` 措辞：仅 lib 内单测引用且无级联者降级，其余登记保留）：
  - `GatewayMetrics::truncated_count`（`src/service/llm_gateway/metrics.rs:114-115`）→ 已降为 `#[cfg(test)] pub(crate)`
  - `hop_filtered_count`（`metrics.rs:125-128`）、`nondialog_passthrough_count`（`metrics.rs:153-155`）→ 被 `tests/http_e2e_nondialog_passthrough.rs:79-80/:117/:155/:307` 集成测试引用（非 `cfg(test)` 构建链接本库，`pub(crate)`/`#[cfg(test)]` 均不可见）→ **保留 `pub`** + 注释登记约束
  - `MatrixApproval::pending_event_ids`（`src/service/matrix/approval.rs:367`）→ 被 `tests/http_e2e_credential.rs:262/:305/:532` 引用 → 同上保留 `pub` + 注释
  - `chunk::scan_builtin`（`src/service/pii/chunk.rs:240`，唯一调用者 `src/service/pii/detector.rs:554` 所在 `scan_spans` 为 `#[cfg(test)]`）→ 收敛会级联致 `detector.rs` 的 `cached_luhn`/`cached_id_ok`/`cached_reserved`（`:472-491`）及其 `use` 面在生产构建死代码告警 → **保留 `pub`** + 注释登记级联约束
  - 验证：`grep -n "cfg(test)\]" src/service/llm_gateway/metrics.rs` 命中 `truncated_count` 降级；`grep -rn "集成测试" src/service/llm_gateway/metrics.rs src/service/matrix/approval.rs` 命中 3 项登记注释（`hop_filtered_count`/`nondialog_passthrough_count`/`pending_event_ids`），`grep -n "死代码告警" src/service/pii/chunk.rs` 命中 `scan_builtin` 级联登记
  - 验证：`cargo test -p veil` 全绿（含 `tests/**` 集成测试编译）；生产面无该 5 项引用

- [x] 9.2（重复 `inner_json_intact` 等）抽取 `src/service/redaction/restore_guard.rs`（零 axum 依赖），暴露 `inner_json_intact(&Value, &Value)` 与 `restore_guard_ok(restored, placeholder, placeholder_parsed: Option<&Value>)`：合并 `src/handler/llm/pump/spawn/frame_feed.rs:80-103` 与 `src/handler/llm/nonstream.rs:534-558`（及 `guard_ok` `:64-76` / `restore_guard_ok` `:522-530`）的**纯逻辑**；`guard_restored_frame_parsed`（metrics/warn 包装）留在 handler `frame_feed`
  - 验证：`grep -n "inner_json_intact\|restore_guard_ok" src/service/redaction/restore_guard.rs src/handler/llm/pump/spawn/frame_feed.rs src/handler/llm/nonstream.rs` 命中单一定义 + 两处共享
  - 验证：`cargo test -p veil restore_guard` 全绿；帧路径与非流路径判定等价

- [x] 9.3（重复 `x-veil-*`/`NORMALIZED_*`/`[DONE]`）抽 `src/service/llm_gateway/mod.rs::strip_veil_internal_headers(&mut HeaderMap)` 替换 `src/handler/llm/mod.rs:47-54`、`src/handler/llm/dispatch.rs:335-342`、`src/handler/llm/nonstream.rs:564-571`；`NORMALIZED_HEADER_NAME`/`NORMALIZED_HEADER_VALUE`（`src/service/redaction/leaf.rs:14,17`，现 `#[cfg(test)]`）提升为生产 `pub(crate) const`，替换 `src/handler/llm/nonstream.rs:230,595`、`src/handler/llm/dispatch.rs:366`、`src/handler/llm/pump/event.rs:46` 字面量；Chat `[DONE]` 两处（`src/service/block_inject/frames.rs:60`、`src/handler/llm/pump/spawn/event_loop.rs:677`）统一走 `chat_done_frame()`（`frames.rs:257`）
  - 验证：`grep -rn "strip_veil_internal_headers\|NORMALIZED_HEADER_NAME\|chat_done_frame" src/` 命中单一定义与全部调用点
  - 验证：`cargo test -p veil` 全绿；剥离/信封字节等价

- [x] 9.4（DCD-5）canonical `openspec/specs/deadcode-positional-cleanup/spec.md` 增补声明：r2 归档 `tasks.md` §8.4 的虚高勾选在本 change 的 design 覆盖表中已显式更正（**归档目录禁改**，仅注记）；确认 r2 已声明的 `ValidationCache`/`x-veil-protocol` 内联保留不在本 change 范围
  - 验证：`grep -n "§8.4\|归档\|注记" openspec/specs/deadcode-positional-cleanup/spec.md` 命中更正注记
  - 验证：`python3 scripts/check_doc_paths.py` exit 0；归档目录未被修改（`git status` 无归档变更）

## 10. Go 客户端（`H-1`/`H-2`/`H-3`/`H-4`/`I-E`；`go-client-interop`）

- [x] 10.1（H-1）`get/internal/approval.go:42` 与 `get/internal/proxy.go:18` 的 `parseDurationEnv` 默认值改为与文档一致的 `300*time.Second`；解析失败回退时 `fmt.Fprintf(os.Stderr, …)` 告警（**非** fail-fast，避免脚本硬失败）、**SHALL NOT** 静默取 30s
  - 验证：`grep -n "300.*time.Second\|Fprintf(os.Stderr" get/internal/approval.go get/internal/proxy.go` 命中默认值与告警
  - 验证：`cd get && go test ./...` 全绿；非法 `PROXY_*_TIMEOUT` 回退 300s 并告警

- [x] 10.2（H-2）`get/cmd/register.go:18`、`get/cmd/revoke.go:16`（及其余子命令）的 `flag.ExitOnError` 改 `flag.ContinueOnError`；`flag.ErrHelp` → 退出 0，其余解析错误 → 打印用法后退出 1；退出码 2 **专用于**「已受理未完成」
  - 验证：`grep -rn "ContinueOnError\|ErrHelp" get/cmd/` 命中全部子命令替换
  - 验证：`cd get && go test ./...` 全绿；用法错误退出 1、`-h` 退出 0、202 待审退出 2

- [x] 10.3（H-3）`get/internal/approval_test.go:180/203` 主用例改用真实 Rust 202 形状（`{"error":{"code":"E_PENDING",…}}`，断言 `regID == ""`）；另留一条 Python 基线（顶层 `reg_id`）用例覆盖 `get/internal/proxy.go:269-274` 的 `reg_id` 回退；回退逻辑**保留**并注明"对 Rust 服务器恒不命中"；`scripts/go_interop_e2e.py` 无 `reg_id` 断言、改动安全
  - 验证：`grep -n "E_PENDING\|reg_id\|regID" get/internal/approval_test.go get/internal/proxy.go` 命中真实形状与回退注释
  - 验证：`cd get && go test ./internal/...` 全绿；两条用例分别覆盖 Rust 与 Python 形状

- [x] 10.4（H-4）重写 `get/internal/approval_test.go:244-259` 的 `TestApprovalPollIntervalClamped`：改为「长超时（如 30s）+ 记录型 `sleepFn`（记录每次休眠参数）+ 两元素脚本响应（先 `202 + E_PENDING`、后终态 200）」；断言 `count()==2`、**恰好一次休眠**、且 `slept[0] == 2s`（`get/internal/approval.go:141` 的钳制下界）；钳制被删则 `slept[0]==0` 而失败；**SHALL NOT** 引入可注入时钟或真实休眠、不改生产代码
  - 验证：`grep -n "sleepFn\|slept\|TestApprovalPollIntervalClamped" get/internal/approval_test.go` 命中记录型休眠与下界断言
  - 验证：`cd get && go test ./internal/ -run TestApprovalPollIntervalClamped` 通过；删去 `approval.go:138-142` 钳制时该用例失败（判别力）

- [x] 10.5（I-E）gate.sh Go 版本声明：`scripts/gate.sh:21-23,28,69-80,90-96` 头注、`README.md` §8.5、`scripts/README.md` 声明"Go 版本由 `get/go.mod`（`go 1.22`）在 `vet`/`test` 阶段强制"；**SHALL NOT** 增加版本字符串比较（Go ≥1.21 的 `GOTOOLCHAIN=auto` 会依 `go.mod` 自动选型/下载；<1.21 时版本指令在 `vet`/`test` 阶段明确报错并非零退出，已 fail-closed）
  - 验证：`grep -n "go.mod\|GOTOOLCHAIN\|版本由" scripts/gate.sh scripts/README.md README.md` 命中声明
  - 验证：`bash scripts/gate.sh` 第 7 步在 `get/` 内 `go vet ./...` + `go test ./...` 全绿

## 11. 覆盖缺口补测

- [x] 11.1（覆盖缺口 · SDK 断言）`scripts/api_conformance.py` 增补非流 Responses 阻断体经真 SDK 解析断言（`output`/`status` 可读、`output_text` 不抛错），并覆盖 A-3 五件套 Anthropic 阻断流经 SDK 累加器解析；与 canonical `openspec/specs/llm-protocol-hardening/spec.md:159-171` 要求对齐
  - 验证：`grep -n "output\|status\|message_start" scripts/api_conformance.py` 命中新增 SDK 断言
  - 验证：`bash scripts/gate.sh` 第 6 步真 SDK conformance 全绿（项数含新增断言）

- [x] 11.2（覆盖缺口 · e2e 多帧）补 A-2 序号游标端到端用例——真空流零帧 `base=0` 维持 0..6、已发多帧后阻断 `base = max_seq + 1` 且严格递增、上游 error 自带序号沿用；覆盖次要帧/被 hold 缓冲帧/被替换 error 帧对游标的影响
  - 验证：`grep -rn "responses_seq_cursor\|base" src/handler/llm/pump/ tests/` 命中多帧 e2e 用例
  - 验证：`cargo test -p veil responses_seq_cursor_e2e_multi_frame` 通过；阻断序列无倒退、真空流行为不变

- [x] 11.3（覆盖缺口 · 多行 data）补 A-5 用例断言出口按 `\n` 拆分为多条 `data:` 前缀行后，解析侧 WHATWG 单 `\n` 连接（`src/service/sse/parser.rs:309`）还原为原载荷（严格互逆），且 `event:`/`id:`/`retry:` 信封不受影响
  - 验证：`grep -rn "multiline\|互逆\|split" src/service/sse.rs src/service/sse/ src/handler/llm/pump/` 命中互逆用例
  - 验证：`cargo test -p veil sse_multiline_data_roundtrip` 通过；出口拆分与解析连接逐字节互逆

- [x] 11.4（覆盖缺口 · 零字节分片洪泛）补 C-3 用例——上游对**同一 index** 持续发零字节 tool 分片，断言 `account_pending_frame` 使 `pending_tool_frames` 条目与字节双维度有界、超限走 `reject_reason="audit-hold-overflow"` fail-closed 阻断臂、被清参数已由终审 `tool_triples`/`responses_pending_triples`（`src/handler/llm/pump/spawn/terminal.rs:115-171`）评估；本任务**复用 5.4 用例** `pending_tool_frames_same_index_zero_byte_flood_bounded`（不新定义用例名）
  - 验证：`grep -n "zero_byte\|同一 index\|audit-hold-overflow" src/service/audit/hold/tests.rs` 命中洪泛用例（与 5.4 同一用例）
  - 验证：`cargo test -p veil pending_tool_frames_same_index_zero_byte_flood_bounded` 通过；内存有界且不静默丢弃

- [x] 11.5（覆盖缺口 · 交错并行 item）补 A-8 用例——构造两个并行 tool 槽交错到达/完成的分片序列，断言放行序为"每槽按到达序取出、由该槽完成事件驱动"，跨槽相对 `sequence_number` 次序不被保证（锁定实际行为）；本任务**复用 7.3 用例** `toolbuf_interleaved_parallel_release_order`（不新定义用例名）
  - 验证：`grep -n "interleaved\|跨槽\|到达序" src/handler/llm/pump/toolbuf.rs` 命中交错用例
  - 验证：`cargo test -p veil toolbuf_interleaved_parallel_release_order` 通过；放行序与声明一致

- [x] 11.6（覆盖缺口 · 双 canonical 对照）断言 canonical `openspec/specs/stream-protocol-parity/spec.md` 无「空流 open-ended」旧条款、与 canonical `openspec/specs/llm-protocol-hardening/spec.md` 真空流最小终止口径一致；三协议真空流最小终止**复用 7.1/7.9 已引用的既有单测** `vacuum_stream_three_protocol_e2e_comparison`（`src/service/block_inject/frames.rs`，不新定义用例名）
  - 验证：`grep -rn "Empty streams stay open-ended" openspec/specs/stream-protocol-parity/spec.md openspec/specs/llm-protocol-hardening/spec.md` 无冲突口径
  - 验证：`cargo test -p veil vacuum_stream_three_protocol_e2e_comparison` 通过；三协议对照一致

## 12. 收口验证

- [x] 12.1（收口）`cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test -p veil` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
  - 验证：clippy 在 `-D warnings` 下 0 warning

- [x] 12.2（收口）`python3 scripts/check_doc_paths.py` 与 `python3 scripts/check_file_sizes.py` 退出 0
  - 验证：两命令输出 OK、无 FAIL 项
  - 验证：源文件 ≤800 行约束保持（新增 `src/service/redaction/restore_guard.rs` 归入 `service/redaction/`）

- [x] 12.3（收口）`openspec validate veil-audit-r3-remediation --strict` 通过
  - 验证：命令输出 `is valid` 且 0 failures
  - 验证：`openspec status --change veil-audit-r3-remediation` artifacts 齐全（proposal/design/tasks/specs）

- [x] 12.4（收口）`bash scripts/gate.sh` 七步全绿（exit 0）
  - 验证：fmt / clippy / test / check_doc_paths / check_file_sizes / api_conformance / go vet+test 七步均绿
  - 验证：真 SDK conformance 全绿、`get/` 内 `go vet ./...` + `go test ./...` 全绿

- [x] 12.5（收口）`README.md` 与 canonical spec 同步终检
  - 验证：`README.md` §3/§5/§7.2/§7.3/§8.5 与对应 canonical spec 口径一致、无旧表述残留
  - 验证：`grep -rn "Empty streams stay open-ended\|458-464\|469-478" README.md openspec/specs/` 无失效/冲突残留

## 已知处置说明

1. **spec 修订工作流口径**：spec 修订以本 change 的 `specs/<capability>/spec.md` delta 为归档晋升载体，**并在 apply 期同步直改 canonical `openspec/specs/**`**（沿用 r2 先例，如 r2 `tasks.md` 4.19 即直改 canonical 并 `grep openspec/specs/...` 验证；归档时 OpenSpec 对同内容为 early-sync no-op）；因此各 spec 任务的 `grep openspec/specs/...` 验证在 apply 期为有效判别，`tasks.md` 正文的 canonical 路径既是真相源也是实施目标。本 change 现有 21 个 capability delta，`openspec validate veil-audit-r3-remediation --strict` 返回 valid。
2. **r2 归档 tasks.md 的失效指针**：按 design G-4 仅为注记（apply 期历史快照、非现行契约），**归档目录禁改**；`check_doc_paths.py` 已扫描归档，`hold.rs` 等引用已登记为 `PENDING`、行号未越界故静默通过，属脚本已声明能力边界，**SHALL NOT** 扩展 `PENDING_REFS`/`PENDING_LINE_REFS`。
3. **行号引用校验范围**：`check_doc_paths.py` 仅做行号**范围**校验（路径存在 + `1 <= start <= end <= 行数`），被引行内容与文档语义的一致性由 code review 保证，门禁脚本不校验；若同类内容漂移再现，升级为登记式语义锚点表（design G-4 升级触发条件）。

## 实施记录（apply）

实施按波次并行推进（波 1 七域并行 / 波 2a 协议单点与覆盖缺口 / 波 2b 记账与去重抽取），64 项任务全部勾选。门禁证据：

- **Rust**：`cargo fmt --check` exit 0；`cargo clippy -p veil --all-targets -- -D warnings` exit 0（No issues）；`cargo test -p veil --no-fail-fast` → **1371 passed / 27 suites / 0 failed**。
- **脚本**：`python3 scripts/check_doc_paths.py` exit 0（2775 处 `src/*.rs` 引用、203 处 spec 引用与 557 处行号引用全通过；归档 change 行号引用按 2131 处计数豁免）；`python3 scripts/check_file_sizes.py` OK（164 个 `src/**/*.rs` ≤800 行）。
- **API 合规**：`scripts/api_conformance.py` 24 项 / 0 失败（含新增非流 Responses 阻断体经真 SDK 解析、Anthropic 五件套经 SDK 累加器断言）。
- **Go 客户端**：`get/` 内 `go vet ./...` + `go test ./...` 全绿。
- **七步 gate**：`bash scripts/gate.sh` **exit 0**（fmt / clippy / test / doc-paths / file-sizes / conformance / go 逐项 ✓）。
- **OpenSpec**：`openspec validate --all --strict` → 92 passed / 0 failed；本 change valid。

**apply 期偏差处置（3 项，均已修正）**：

1. **9.1 符号路径校正**：`GatewayMetrics` 承载文件为 `src/service/llm_gateway/metrics.rs`（非 `mod.rs`）；`truncated_count`（`:114-115`）已降为 `#[cfg(test)] pub(crate)`；`hop_filtered_count`（`:125-128`）、`nondialog_passthrough_count`（`:153-155`）因 `tests/**` 集成测试以非 `cfg(test)` 构建链接本库而**按引用面保留 `pub`** 并注释登记；`chunk::scan_builtin`（`src/service/pii/chunk.rs:240`）因级联致 `detector.rs` 的 `cached_*` 在生产构建死代码告警而保留 `pub` 并注释登记。canonical `deadcode-positional-cleanup` 收敛措辞已同步为「按引用面判定」。
2. **4.2 canonical 直改**：canonical `openspec/specs/redaction-audit-coverage/spec.md:118` 的 Chat 分桶公式已由历史 `ci*64+declared_index` 更新为位域 `(ci << 16) | (idx & 0xFFFF)`（含 `idx >= 64` 碰撞说明与 `ci=0` 等价锚点，与 delta 同口径）。
3. **7.4 验证措辞对齐**：门禁范围声明的 canonical 实际措辞为「SHALL NOT 校验被引行的内容与文档语义；一致性 SHALL 由 code review 保证」（`openspec/specs/docs-test-parity/spec.md:12`），验证串据此对齐。

**测试外迁（红线处置）**：`src/service/audit/hold/tests.rs` 因新增同 index 零字节洪泛用例触 800 行红线，按 `keepalive_tests` 模板外迁为 `src/service/audit/hold/zero_byte_tests.rs`（用例语义不变；`hold.rs` 增 `mod zero_byte_tests;`）。
