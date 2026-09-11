## 1. `N1` Responses 双终止帧守卫

- [x] 1.1 `src/handler/llm/pump/spawn.rs:218-252`：`incomplete/error` 合成分支收敛为 `error` 合成路径，并在分支首行加 `if terminal_sent { continue; }` 守卫（先于 `responses_failed_sent` 判定，已发终端后任何后续帧一律忽略）
  - 验证：`cargo test -p veil responses_completed_then_error` 通过；构造 `response.completed` 后跟 `type:"error"` 的流，断言下游 `response.completed` 恰一、无 `response.failed`、终端后无数据帧
- [x] 1.2 补 `N1` 回归测试：`completed → error` 与 `completed → incomplete` 两序列
  - 验证：`cargo test -p veil n1_single_terminal` 通过；`block_inject::terminal_count(&frames, "responses") == 1` 且 `response.failed` 计数为 0
  - 验证：既有 `cargo test -p veil dedupe_terminal` 全绿无回退

## 2. `N2`（同 `P6`）非 JSON 错误体原样透传

- [x] 2.1 `src/service/llm_gateway/mod.rs:159-175 classify_empty` 与 `src/handler/llm/nonstream.rs:124-145/254-262` 收敛：`status>=400` 且非 JSON（含空体）恒原样透传（保留状态码与正文字节），不再合成 `502 E_EMPTY_BODY`；`status<400` 非 JSON 维持现值；502/401 的 JSON 完整后处理链不变
  - 验证：`cargo test -p veil non_json_error_passthrough` 通过；429 `text/plain` 体断言下游状态码 429 与正文字节逐字节一致
  - 验证：`grep -n "is_error_status" src/handler/llm/nonstream.rs` 命中且判定改为 `status_u16 >= 400`
- [x] 2.2 补 429/500/404 非 JSON 用例（含空体错误）
  - 验证：`cargo test -p veil error_status_non_json` 通过；500 HTML 与 404 非 JSON 体均保留状态与正文，不被替换为 502
- [x] 2.3 README §7.2「非流阻断与错误状态声明」同步：豁免范围由「仅非 JSON 的 502/401 错误体」改为「`status>=400` 的非 JSON 错误体原样透传」
  - 验证：`grep -n "非 JSON" README.md` 命中新表述且不再限定 502/401

## 3. `N3` SSE CRLF 跨块

- [x] 3.1 `src/service/sse/parser.rs:117-160 push_text`：块末孤立 `\r` 不提前消费跨块 `\n`——保持行已终止的同时暂存跨块状态（下一块首字节为 `\n` 时按 `\r\n` 合并吞掉该 `\n`，否则按孤立 `\r` 处理）；块内 `\r\n`、孤立 `\r` 语义不变
  - 验证：`cargo test -p veil crlf_split_across_chunks` 通过；`push_bytes(b"event: x\r")` 后 `push_bytes(b"\ndata: y\r\n\r\n")` 断言恰一个事件且 `event_type=="x"`、`data=="y"`
  - 验证：既有单块 CRLF/`\r` 测试 `whatwg_line_splitting_with_comment_passthrough`（`src/service/sse.rs:26-41`）全绿
- [x] 3.2 补跨块边界测试：`\r` 结尾 + 下一块首字节非 `\n`；`data: z\r` + `\r` 跨块；连续 CRLF 跨块
  - 验证：`cargo test -p veil parser_crlf` 通过；每 case 断言事件计数与 `event`/`data` 归属正确，无提前 `dispatch_block`

## 4. `P1` Chat `[DONE]` 补发

- [x] 4.1 `src/handler/llm/pump/spawn.rs:663-677`：见非 null `finish_reason`（`saw_finish_reason`，`spawn.rs:177`）且流结束时仍未发 `[DONE]`，flush 边界后补发恰一 `data: [DONE]` 并置终端/`mark_terminal`；`finish_reason` 后到达的 usage 尾帧（`choices: []`）照常透传，不提前截断；`truncated_mode=open_ended` 观测保留（复用现有枚举）
  - 验证：`cargo test -p veil chat_finish_reason_without_done` 通过；断言 `[DONE]` 恰一、usage 帧未丢、`truncated_mode==open_ended`
  - 验证：上游已发 `[DONE]` 的正常流不重复补发（`terminal_count==1`）
- [x] 4.2 补 `P1` 回归测试：finish_reason 后断流、finish_reason+usage 尾帧后断流、正常 `[DONE]` 三场景
  - 验证：`cargo test -p veil p1_chat_done` 通过；`cargo test -p veil stream_tests` 全绿
- [x] 4.3 README §7.2「Chat 无 `[DONE]` 收尾处理」段改为「见 `finish_reason` 且流结束缺 `[DONE]` 时补发恰一 `[DONE]`（usage 尾帧保留）」
  - 验证：`grep -n "补发" README.md` 命中该段；`grep -n "不合成.*DONE" README.md` 无旧表述残留

## 5. `P2` 真空流终止帧

- [x] 5.1 `src/service/block_inject/frames.rs:293-297 empty_stream_frames`：Chat 真空流返回恰一 `chat_done_frame()`（`data: [DONE]`）
  - 验证：`cargo test -p veil empty_stream_frames` 通过；`empty_stream_frames("chat", ..)` 恰一帧且为 `data: [DONE]`
- [x] 5.2 同函数：Anthropic 真空流返回最小 `message_start`+`message_stop`（`message.content=[]`、`stop_reason=null`、usage 全 0，不含 `content_block_*`）；并令 Anthropic `type:"error"` 按终端处理（其后不发数据帧，不注入 `message_stop`）
  - 验证：`cargo test -p veil anthropic_vacuum` 通过；断言两帧可解析、`message_stop` 恰一、无 `content_block` 事件
  - 验证：`cargo test -p veil anthropic_error_terminal` 通过；`error` 透传后无 `message_stop`、无后续帧
- [x] 5.3 Responses 真空保持 `response.failed` 全序列不变；`spawn.rs:614-657` 合成守门三协议联测 + README §8.6 更新
  - 验证：`cargo test -p veil vacuum_stream_three_protocol` 通过；Chat 收恰一 `[DONE]`、Anthropic 收最小终止、Responses 收恰一 `response.failed`
  - 验证：`grep -n "8.6" README.md` 段落与 spec 一致（三协议均补终止帧，open-ended 仅余 metrics 观测口径）

## 6. `P4` Responses `incomplete`/`error` 终止语义

- [x] 6.1 `spawn.rs:218-244`：`response.incomplete` 不再进合成分支，原样透传并作为唯一终端（`event.rs:154-167 is_terminal_event` 覆盖 `incomplete` 置位），保留 `incomplete_details`
  - 验证：`cargo test -p veil responses_incomplete_passthrough` 通过；断言 `incomplete` 帧原字节透传、其后无数据帧、无合成 `response.failed`
- [x] 6.2 `type:"error"` 仅合成单帧 `response.failed`（`response.error.message` 携带上游 error message，缺失回退既有合成口径），不注入 `output_index:0` 序列
  - 验证：`cargo test -p veil responses_error_single_failed` 通过；断言总帧数最小、无 `output_item.added` 注入、无重复 `output_index`
- [x] 6.3 全序列收敛：含 `output_index` 的 7 帧 `responses_truncated_frames` 仅 `empty_stream_frames`（真空流）使用；`spawn.rs:541-568` 截断丢弃路径与 `synthesize_truncation` 改单帧 `response.failed`（`response.error.message="truncated"`，保持 failed 语义不伪造完成）
  - 验证：`grep -rn "responses_truncated_frames" src/ --include="*.rs"` 生产调用仅 `frames.rs` 真空路径（其余为测试）
  - 验证：`cargo test -p veil synthesize_truncation`（更新后断言单帧 failed、不伪造完成）通过

## 7. `P7` 脱敏回退 fail-closed

- [x] 7.1 `src/handler/llm/rewrite.rs:62-69`：注入分支重解析失败时回退转发 `redacted_text` 字节（不得回落未脱敏 `body_value`）；`normalized_out` 仅成功重序列化时置位
  - 验证：`cargo test -p veil redaction_fallback_never_emits_unredacted` 通过；构造 `redacted_text` 非法 JSON，断言输出含占位符、不含原文、`x-veil-normalized` 未置位
- [x] 7.2 抽纯函数承载回退决策（输入 `redacted_text`/`original_valid`/`body_value`，输出 `(bytes, normalized_out)`）并补构造性测试
  - 验证：`cargo test -p veil redaction_fallback` 通过；正常注入、重解析失败、`original_valid=false` 三场景行为符合 design D7

## 8. `P9` 工具分桶对齐

- [x] 8.1 `src/handler/llm/pump/fragments.rs:446/452/457/480` 的 Responses `output[]` 桶号由 `i as u32` 对齐为 `item.output_index.unwrap_or(i)`，与非流 `src/service/llm_gateway/tool.rs:462-466` 同键
  - 验证：`cargo test -p veil responses_output_bucket` 通过；`output_index` 存在时两路径同值、缺失时均回退枚举下标
- [x] 8.2 补流/非流交叉一致性测试（`output_index` 存在/缺失两场景，流式分片与非流 `extract_tool_calls` 桶号相同）
  - 验证：`cargo test -p veil tool_bucket_parity` 通过

## 9. `X2` 工具提取共享实现

- [x] 9.1 抽共享内部 helper（字段归一/合成 id/Responses `output[]` 桶号）至 `src/service/llm_gateway/tool.rs`，带 `emit_warn: bool` 参数保持非流 warn、流式静默现值；`extract_tool_calls`（`tool.rs:140`）与 `extract_tool_fragments`（`fragments.rs:14`）两公有入口签名不变
  - 验证：`cargo test -p veil tool_extract_parity` 通过；同一输入（缺参/缺 id/`output_index` 缺省）两入口字段值与桶号一致
  - 验证：`grep -n "tracing::warn" src/handler/llm/pump/fragments.rs` 无新增告警，流式静默语义不变
- [x] 9.2 补流/非流一致锁定测试（Chat 多 choice、Responses `output_index`、缺参缺 id 三组）
  - 验证：`cargo test -p veil fragment_nonstream_parity` 通过

## 10. `P11` 无冒号 `data` 行

- [x] 10.1 `src/service/sse/parser.rs` `dispatch_block`：无冒号的 `data` 行按空值字段处理（push 空串参与多 `data:` 行 `\n` 合并）；其他无冒号行维持忽略
  - 验证：`cargo test -p veil bare_data_line` 通过；`data\ndata: x\n\n` 断言 `data=="\nx"`
- [x] 10.2 补边界测试：裸 `data`、`data:` 空值、裸 `data` 与 `data:` 混合
  - 验证：`cargo test -p veil parser_bare_data` 通过

## 11. 记录项（`P5`/`P3`/`P10`，audited COMPLIANT，无代码改动）

- [x] 11.1 `design.md` D10 记录 `P5`：终端去重常规路径正确（`terminal.rs:23-57`、`spawn.rs:256/458/510`），唯一缺口由 `N1` 收口并指向任务 1.1/1.2
  - 验证：`grep -n "P5" openspec/changes/veil-llm-protocol-hardening/design.md` 命中「audited COMPLIANT, no change」与 N1 指引
- [x] 11.2 `design.md` D10 记录 `P3`/`P10` 证据：`protocol.rs:111-130` + `rewrite.rs:55-69`（`stream_options` 仅 Chat、保留用户 `false`）；`usage.rs:92-103` + `usage.rs:213-217`（五列 `max`、三级回退）
  - 验证：`grep -n "P3\|P10" openspec/changes/veil-llm-protocol-hardening/design.md` 命中两条 COMPLIANT 记录及行号证据

## 12. `P8`（= `X5`）交叉引用（转出，无代码改动）

- [x] 12.1 proposal Non-Goals 与 design D11 记录 `P8` 由 `veil-code-hygiene-closeout` 承接，本 change 不改 `placeholder.rs`
  - 验证：`grep -rn "veil-code-hygiene-closeout" openspec/changes/veil-llm-protocol-hardening/` 命中
  - 验证：apply 阶段 `git diff --name-only` 不含 `placeholder.rs`

## 13. 门禁与回归

- [x] 13.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 13.2 `openspec validate veil-llm-protocol-hardening --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 13.3 `scripts/api_conformance.py` 三协议流式/非流式/阻断用例通过（环境允许本地起服务时执行）
  - 验证：脚本输出三协议用例全通过；缺 `[DONE]`、真空流与 `incomplete` 场景符合新 spec
