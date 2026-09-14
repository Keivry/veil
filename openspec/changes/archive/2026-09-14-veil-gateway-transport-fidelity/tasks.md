## 1. SSE 出口信封保真（`TRN-1`）

- [x] 1.1 `src/handler/llm/pump/spawn.rs:559-563`（JSON 分支）与 `:607-611`（非 JSON 分支）出口信封重建处：在 `event:` 之外补透出 `id:`（`SseEvent.id`）与合法 `retry:`（`SseEvent.retry`，非数字值不透出）；`src/service/sse/parser.rs:227-265 dispatch_block` 对「有 `event`/`id` 无 `data`」的块做跨块暂存（`event` FIFO、`id` 最近值持久化），pump 出口将暂存项与下一含 `data` 块同块重建，不产生孤立 `event:` 块
  - 验证：`cargo test -p veil sse_envelope_id_retry_passthrough` 通过；含 `id: 42`/`retry: 3000` 的上游帧下游收到同名行，非数字 `retry` 不透出
  - 验证：`cargo test -p veil sse_cross_block_event_pairs_with_data` 通过；`event:` 与 `data:` 分块时下游收到同块配对，无空 data 孤立 event 块
  - 验证：`grep -n "ev.id\|ev.retry" src/handler/llm/pump/spawn.rs` 命中出口透出接线
- [x] 1.2 `id:` 直通回归：断言多事件流中 `id` 值逐个透出、`retry` 随所在块透出、顺序与上游一致
  - 验证：`cargo test -p veil sse_id_sequence_passthrough` 通过；`id` 序列与上游投递序列逐一致
  - 验证：`cargo test -p veil --test http_e2e_stream_fidelity`（或既有 e2e）全绿无回退
- [x] 1.3 跨块 `event:`/`id:` 配对回归：断言 `event` FIFO 配对、最近 `id` 对后续无 id 事件持续生效（WHATWG last-event-id）
  - 验证：`cargo test -p veil sse_cross_block_event_fifo` 通过；`event` 按 FIFO 与后续 `data` 配对
  - 验证：`cargo test -p veil sse_last_event_id_persists` 通过；最近 `id` 在后续无 id 事件中持续透出
- [x] 1.4 跨块暂存计数保真：`src/service/sse/parser.rs:263 sse_event_count` 与 `src/handler/llm/pump/spawn.rs:647 metrics.add_sse_event()`/`forwarded` 帧计数，对分块信封流须与同内容非分块流逐一致；暂存 `event`/`id` 仅在出口块重建，不额外增加/吞并事件或转发帧（审计与 metrics 语义不变）
  - 验证：`cargo test -p veil sse_split_envelope_counters_unchanged` 通过；分块 `event:`/`data:` 流与同内容同块流的 `sse_event_count`、`add_sse_event()` 计数、`forwarded` 帧数逐相等
  - 验证：`cargo test -p veil --test http_e2e_stream_fidelity`（或既有 SSE 计数 e2e）全绿无回退

## 2. Anthropic message_start 会话与模型提取（`TRN-7`）

- [x] 2.1 `src/service/llm_gateway/tool.rs:580-620 extract_conv_id` 在既有分支后新增 `data["message"]["id"]`（非空字符串）分支；`src/handler/llm/pump/spawn.rs:198-202` 模型提取改为 `v.get("model")` 优先、回退 `v["message"]["model"]`；提取值接入既有 `conv_id`/`stream_first_id` 与审计/metrics 分桶路径
  - 验证：`cargo test -p veil anthropic_message_start_conv_id` 通过；`message_start.message.id` 被提取为会话标识
  - 验证：`cargo test -p veil anthropic_message_start_model_bucket` 通过；顶层无 `model` 时分桶记录 `message.model`，不记 `unknown_model`
- [x] 2.2 既有顶层形态不回退：Chat `id`/`model`、Responses `response.id` 提取用例保持通过
  - 验证：`cargo test -p veil extract_conv_id_variants` 全绿（顶层/response/data/error 分支无回退）
  - 验证：`cargo test -p veil --test http_e2e_usage_metrics`（或既有分桶 e2e）全绿

## 3. Responses error 双形态与 sequence_number（`TRN-2`）

- [x] 3.1 `src/handler/llm/pump/event.rs:138-161 responses_error_object` 改为合并来源：嵌套 `error` 对象内 `type`/`code`/`param`/`message` 与顶层 `code`/`param`/`message` 合并（缺失才补），复用 `extract_responses_seq` 读取顶层 `sequence_number`；返回值扩展为可携带 `sequence_number`；`spawn.rs` 合成调用点与 `src/service/block_inject/frames.rs:75-82 responses_failed_frame` 把 `sequence_number` 写入合成 `response.failed` 载荷顶层（可得时）
  - 验证：`cargo test -p veil responses_error_official_shape_keeps_code_param` 通过；官方顶层形态下游合成帧保留 `code`/`param` 且带 `sequence_number`
  - 验证：`cargo test -p veil responses_error_nested_shape_still_supported` 通过；既有嵌套形态保留 `code`/`message`
  - 验证：`grep -n "sequence_number" src/service/block_inject/frames.rs src/handler/llm/pump/event.rs` 命中合成接线
- [x] 3.2 缺失字段不产生空噪声：`message` 缺失/error 非对象时维持既有 `{"id","status"}` 回退形态
  - 验证：`cargo test -p veil responses_error_fallback_shape` 通过；无 `error` 字段噪声、不断链
  - 验证：`cargo test -p veil --test http_e2e_truncation`（或既有 Responses error e2e）全绿

## 4. 流式上游错误透传有界读（`TRN-3`）

- [x] 4.1 `src/handler/llm/dispatch.rs:328`：以有界读替换 `up.bytes()` 全量缓冲，**超限 502 仅作用于非错误状态**——先判 `content-length`（`status < 400` 且 `> NONSTREAM_MAX_BYTES` 即 502 `response_too_large`，不读 body）；再以 `up.chunk()` 循环累计至多 `NONSTREAM_MAX_BYTES + 1`；`status < 400` 严格超限即 502，`status >= 400`（4xx/5xx 错误体）**不进入 502 分支**，保持上游状态码与正文字节透传、不改写（有界读/计数仅为内存安全，README §4 口径）；保留现状 `dispatch.rs:329` 的 `status_u16 < 400` 门，上限内维持保状态、保正文字节、hop 过滤与自置 `x-veil-*`
  - 验证：`cargo test -p veil stream_passthrough_oversize_bounded` 通过；非错误超限时返回 502 `response_too_large` 且不转发超限字节
  - 验证：`cargo test -p veil stream_passthrough_error_oversize_passthrough_unchanged` 通过；4xx/5xx 错误体超限时下游状态码与正文字节与上游一致，非 502、不改写
  - 验证：`cargo test -p veil stream_passthrough_within_limit_bytes` 通过；上限内状态与正文字节逐字节一致
  - 验证：`grep -n "bytes().await" src/handler/llm/dispatch.rs` 不再命中 `stream_upstream_passthrough` 内全量读
- [x] 4.2 大 body 不 OOM 回归：构造超过 `NONSTREAM_MAX_BYTES` 的非错误/非 SSE body，断言内存受上限约束且 fail-closed（502）；另构造超过上限的 4xx/5xx 错误体，断言状态码与正文字节仍透传不改写
  - 验证：`cargo test -p veil --test http_e2e_stream_upstream_error` 新增大体用例通过（非错误 502；错误体透传不改写）
  - 验证：`cargo test -p veil stream_passthrough_error_oversize_passthrough_unchanged` 通过；4xx/5xx 超限错误体状态与字节逐一致
  - 验证：`cargo test -p veil --test http_e2e_truncation` 既有用例全绿无回退

## 5. 内部响应头隔离（`TRN-4`）

- [x] 5.1 `src/handler/llm/dispatch.rs:318-326` 拷贝上游响应头时剔除名称以 `x-veil-` 开头（ASCII 大小写不敏感）的头；网关自置的 `x-veil-protocol`/`x-veil-normalized` 在剔除后写入，不被上游同名覆盖
  - 验证：`cargo test -p veil stream_passthrough_strips_internal_headers` 通过；上游注入 `x-veil-debug` 不出现于下游
  - 验证：`grep -n "x-veil-" src/handler/llm/dispatch.rs` 命中内部头剔除逻辑
- [x] 5.2 网关自置头不被覆盖回归：上游回 `x-veil-protocol` 伪值时下游收到网关自置值
  - 验证：`cargo test -p veil stream_passthrough_internal_header_override` 通过；`x-veil-protocol` 为网关值
  - 验证：`cargo test -p veil --test http_e2e_stream_upstream_error` 全绿

## 6. stream_options 三态保留（`TRN-5`）

- [x] 6.1 `src/service/llm_gateway/protocol.rs:138-178`：`should_inject_stream_options` 三态化——缺失 `None`→true、`Some(Value::Null)`→false、对象缺 `include_usage`→true、对象含 `include_usage`→false、非对象非 null（畸形）→true；`inject_stream_options` 仅对「缺失/对象合并/畸形替换」写入，`null` 保留不动
  - 验证：`cargo test -p veil stream_options_three_state_matrix` 通过；缺失注入、`null` 保留、对象按 key 合并、含 `include_usage` 保留（含 `false`）
  - 验证：`cargo test -p veil stream_options_null_preserved` 通过；转发体保留 `"stream_options": null`
- [x] 6.2 畸形形态不回退：`stream_options` 为字符串/数组时维持 warn + 整体替换，不静默丢键
  - 验证：`cargo test -p veil stream_options_malformed_replaced` 通过；替换为 `{"include_usage":true}`
  - 验证：`cargo test -p veil --test http_e2e_stream_rewrite`（或既有 rewrite e2e）全绿

## 7. Anthropic 阻断帧 index 与参数累积清洁（`TRN-6`）

- [x] 7.1 `src/service/block_inject/frames.rs:40-49 anthropic_block_frames` 增 `index` 入参并用于 `content_block_start`/`content_block_stop`；`src/handler/llm/pump/spawn.rs:502-521` 调用点从触发阻断事件解析真实 index（复用 `event.rs outer_event_index`），无法解析才回退 `0`；同步更新 `src/service/block_inject.rs` 既有测试调用与签名
  - 验证：`cargo test -p veil anthropic_block_frame_real_index` 通过；`index:2` 阻断时阻断帧 `index` 为 `2`，未知回退 `0`
  - 验证：`grep -n "anthropic_block_frames(" src/service/block_inject/frames.rs src/handler/llm/pump/spawn.rs` 命中 index 入参接线
- [x] 7.2 `src/handler/llm/pump/fragments.rs:155-174`：Anthropic `content_block_start` 的空占位 `input`（空对象/空串/null）不作为 args_delta 累积；非空完整 `input` 仍可一次性种子；`partial_json` 正常累积
  - 验证：`cargo test -p veil anthropic_empty_input_no_arg_pollution` 通过；`input:{}` + `partial_json` 累积为 `{"cmd":"ls"}`，无 `{}{` 前缀
  - 验证：`cargo test -p veil anthropic_nonempty_input_seed` 通过；非空 `input` 形态仍被完整审计
- [x] 7.3 多 index 回归：多块流中各块 index 独立、阻断帧指向命中块、既有分桶用例不回退
  - 验证：`cargo test -p veil anthropic_multi_index_block_frames` 通过
  - 验证：`cargo test -p veil --test http_e2e_audit_block` 全绿无回退

## 8. README 文档同步（§7.2）

- [x] 8.1 `README.md` §7.2 增补/修订：SSE 出口信封（`id`/`retry` 透出与跨块 `event` 配对）；Responses error 双形态与 `sequence_number`（扩展既有「失败帧诊断字段 lossy 边界」条款）；流式透传有界读与超限 502 `response_too_large`；上游 `x-veil-*` 内部头不泄漏；`stream_options:null` 三态保留
  - 验证：`grep -n "跨块\|last-event-id\|sequence_number\|response_too_large\|x-veil-\|stream_options" README.md` 命中新增/修订条款
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0（引用的 `src/` 路径全部存在）
- [x] 8.2 spec 与 README 互引一致：`specs/gateway-transport-fidelity/spec.md` 各 Requirement 与 README §7.2 对应段落口径一致、无旧表述残留
  - 验证：`grep -n "HOP\|逐跳" README.md` 命中 §7.1 未被本次改动改写；README §7.2 对应段落与 spec 各 Requirement 语义一致
  - 验证：`openspec validate veil-gateway-transport-fidelity --strict` 0 failures

## 9. 门禁与归档准备

- [x] 9.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 9.2 `python3 scripts/check_doc_paths.py` 退出 0（README 与 spec 引用路径全部存在）
  - 验证：命令输出 `OK`，无 FAIL 项
- [x] 9.3 `openspec validate veil-gateway-transport-fidelity --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 9.4 覆盖表终检：proposal 发现覆盖表 7 个 ID 均映射到 task，且每个 ID ≥1 个含文件/符号级修复的 task 与 ≥2 条「验证：」行
  - 验证：`grep -o "TRN-[1-7]" openspec/changes/veil-gateway-transport-fidelity/proposal.md | sort -u | wc -l` 输出 `7`
  - 验证：逐 task 复核「验证：」行计数 ≥2
