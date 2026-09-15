## 1. 嵌套 stringified-JSON 凭据还原（`RED-1`）

- [x] 1.1 `src/service/redaction/scope.rs:194-215` 新增递归 JSON-aware 还原：识别字符串节点（含被字符串化的内层 JSON），对内层字符串节点执行 `loads→walk→dumps` 凭据/PII 还原并按实际 JSON 深度转义写回；`src/handler/llm/pump/spawn/frame_feed.rs:17-28 guard_restored_frame` 守卫扩展为对外层与字符串值内层结构双重校验
  - 验证：`cargo test -p veil nested_stringified_json_restore_inner_valid` 通过；两层嵌套 JSON 参数还原后内层可 `serde_json::from_str` 解析、无非法裸 `"`
  - 验证：`grep -n "restore_response_with_spans_json\|guard_restored_frame" src/service/redaction/scope.rs src/handler/llm/pump/spawn/frame_feed.rs` 命中递归还原入口与内层校验调用点
- [x] 1.2 内层破损 fail-closed：还原后外层合法但内层 stringified JSON 结构破损时，`guard_restored_frame` 回退还原前占位符帧并 `metrics.record_restore_fallback()` 计数
  - 验证：`cargo test -p veil inner_json_broken_fallback` 通过；输出为还原前占位符帧、token 形态保留，`restore_fallback` 计数 +1
  - 验证：`cargo test -p veil outer_valid_inner_broken_no_silent_passthrough` 通过；破损内层不被静默透传
- [x] 1.3 回归：单层帧、双层混合帧与零替换帧无回退
  - 验证：`cargo test -p veil restore_json_aware_regression` 全绿；单层帧逐字节等价、零替换帧不触发 `loads→dumps` 重排
  - 验证：`cargo test -p veil --test mask_engine_diff` 全绿（还原/掩码既有差集不回退）

## 2. 跨缝掩码 JSON 结构保真（`RED-2`）

- [x] 2.1 `src/service/redaction/seam.rs:226-244 mask_span_bytes` 豁免集由 `{ } " [ ]` 扩充至含 `,`/`:` 的结构符集；保持仅非结构位逐字符掩码
  - 验证：`cargo test -p veil mask_span_envelope_roundtrip_valid` 通过；跨缝区间覆盖 `,`/`:` 时掩码后 `serde_json::from_str` 成功
  - 验证：`grep -n "matches!(c," src/service/redaction/seam.rs` 命中新结构符集（含 `,`/`:`）
- [x] 2.2 回归：既有跨缝掩码语义与窗口过滤不变
  - 验证：`cargo test -p veil seam_matrix_cross_seam_zero_window_envelope boundary_hold_envelope_split_masked_same` 全绿（跨缝手机号两侧掩码、窗口 0 直通）
  - 验证：`cargo test -p veil filter_window_ipv6_alpha_group_seam_guard` 全绿（`:` 保留与 IPv6 缝邻保护不变）

## 3. 掩码边缘与 README §7.10 对齐（`RED-3`）

- [x] 3.1 `src/service/pii/detector.rs:242-258` `mask_pii_value` `ipv4` 非 4 段分支按 Python `_pii.py:961-1045` 对齐（`<8` → 首 1/尾 1；`>=8` → 前 4/后 4），`email` 含 `@` 域名无 `.` 分支归 `***@***`
  - 验证：`cargo test -p veil mask_pii_value_ipv4_non4_and_email_nodot_parity` 通过；`12345678`→`1234****5678`、`123456`→`1****6`、`a@b`→`***@***`
  - 验证：`grep -n "len(v) >= 8\|domain.contains\|short" src/service/pii/detector.rs` 显示分支已按 `<8`/`>=8` 重写且 email 无点归并
- [x] 3.2 README §7.10 修正为实际规则并完整登记别名集（`bankcard`/`apikey`/`id_card`）
  - 验证：`grep -n "掩码边缘\|§7.10\|bankcard" README.md` 命中修正段；`python3 scripts/check_doc_paths.py` 退出 0
  - 验证：§7.10 声明与 3.1 实现分支逐字一致，别名集完整无遗漏
- [x] 3.3 回归：§7.10 列举边缘样例
  - 验证：`cargo test -p veil mask_edge_samples_readme_7_10` 通过（6/7 字符非 4 段 IPv4、无点 email、别名 kind）
  - 验证：`cargo test -p veil mask_pii_value_alias_equivalent` 通过；别名与主名输出逐字等值

## 4. Responses 四类工具 delta 审计覆盖（`RED-4`）

- [x] 4.1 `src/service/llm_gateway/tool.rs:419-482` Responses 分支为 `response.code_interpreter_call_code.delta`/`response.shell_call_command.delta`/`response.mcp_call_arguments.delta`/`response.custom_tool_call_input.delta` 建槽并累积参数分片（键按 `output_index`/`item_id`，对齐 Python `_llm.py:783-791`）
  - 验证：`cargo test -p veil responses_four_delta_kinds_accumulate` 通过；四类各产生分片并入对应槽、`tool_triples` 可见
  - 验证：`grep -n "code_interpreter_call_code\|shell_call_command\|mcp_call_arguments\|custom_tool_call_input" src/handler/llm/pump/fragments.rs` 命中四类识别
- [x] 4.2 `src/handler/llm/pump/event.rs:258-266 is_minor_event` 从 Responses 次要集移除 `mcp`/`code_interpreter` 工具 delta，使审计判定可达（`reasoning`/`image_gen` 维持次要）
  - 验证：`cargo test -p veil minor_event_excludes_tool_deltas` 通过；四类 delta 非次要、`reasoning`/`image_gen` 仍次要
  - 验证：`grep -n "reasoning\|mcp\|code_interpreter" src/handler/llm/pump/event.rs` 显示次要集已收窄
- [x] 4.3 回归：四类 delta 危险/良性矩阵
  - 验证：`cargo test -p veil responses_four_delta_block_matrix` 通过；`block` 模式危险参数注入阻断终端且不透传，良性放行
  - 验证：`cargo test -p veil --test http_e2e_audit_approve` 全绿（阻断/放行/审批三臂无回退）

## 5. Chat 审计到期/全局完成分离与终端最终审计（`RED-5`）

- [x] 5.1 `src/service/audit/hold.rs:200-243` 拆分判定：新增审计到期谓词 `is_audit_due_event`——Chat 任意非空 `finish_reason`（顶层、`choices[].finish_reason`、`delta.finish_reason`、`message.finish_reason`，`tool_calls` 在内）触发评估/阻断；`is_complete_event`（全局完成）移除四处 `tool_calls`，仅 `message_stop`/`response.completed`/`response.failed`/`response.incomplete` 触发 `mark_completed`
  - 验证：`cargo test -p veil chat_tool_calls_still_audit_due` 通过；仅 `finish_reason:"tool_calls"` 帧在 `block` 模式危险参数下触发阻断、良性参数下放行
  - 验证：`grep -n "is_audit_due_event\|is_complete_event" src/service/audit/hold.rs` 显示两谓词分离，且 `is_complete_event` 内无 `tool_calls` 分支
- [x] 5.2 `src/handler/llm/pump/spawn/event_loop.rs:315-386` 接线：槽重放 `decide::tool_replay_slot`、评估门（`:410-442`）、释放 `release_audited`（`:484-489`）与缓冲判定 `should_buffer_tool_frame`（`:364`）改用审计到期谓词；`mark_completed`（`:530-531`）改用全局完成谓词，`tool_calls` 后晚到分片不再被 `push_fragment`（`hold.rs:72-78`）短路而照常累积入 `args_by_index`
  - 验证：`cargo test -p veil chat_late_tool_fragment_audited` 通过；`finish_reason:"tool_calls"` 后晚到危险参数被审计且 `block` 模式阻断、不透传
  - 验证：`cargo test -p veil chat_tool_calls_not_global_complete` 通过；仅 `tool_calls` 时 `completed` 未置位、后续分片照常累积
- [x] 5.3 `src/handler/llm/pump/spawn/terminal.rs:52-190` 新增终端最终审计：在清除 `pending_tool_frames`/收尾前，对 `hold.tool_triples()` 执行恰一次幂等 `evaluate_and_record`（`TerminalCtx` 扩展携带 `audit_sink`/`audit_mode`/`audit_policy`/`approval_whitelist`/协议）；`Block` 走既有阻断臂注入终端并丢弃持仓，`Allow`/`NeedApproval` 释放，已判定参数由 `release_audited` 移出持仓或 final-flush 标志保证不重复评估
  - 验证：`cargo test -p veil terminal_flush_audits_unfinished_tool` 通过；截断/未完成且未判定的 tool 参数在终端被审计、`block` 模式阻断，断言不透出参数明文
  - 验证：`cargo test -p veil terminal_flush_audit_idempotent` 通过；已判定参数不重复评估（审计计数/建单数不翻倍）
- [x] 5.4 回归：正常流语义不变、既有截断链无回退
  - 验证：`cargo test -p veil --test http_e2e_truncation` 全绿（正常序列不重复审计、不重复终端）
  - 验证：正常 Chat `tool_calls` 流工具参数照常重放透传、良性与危险矩阵与既有 `block`/`approve` 三臂一致

## 6. Responses 审计字节去重（`RED-6`）

- [x] 6.1 `src/service/audit/hold.rs:111-170 push_responses_fragment/mark_responses_done` 按槽/调用维度去重计数：`seq` 缺失自增键不得对同一调用重复计入 `total_bytes`，`done_args` 不重复累加
  - 验证：`cargo test -p veil responses_done_bytes_dedup` 通过；双计场景 `total_bytes` 只计一次且不超过实际上限
  - 验证：`grep -n "added_bytes\|done_args" src/service/audit/hold.rs` 显示按槽/调用去重逻辑
- [x] 6.2 回归：真实超限仍 fail-closed、审计结论不变
  - 验证：`cargo test -p veil overflow_fail_closed_and_clears_pending` 全绿
  - 验证：`cargo test -p veil responses_dedup_keeps_audit_verdict` 通过；去重不改变 `tool_triples` 参数文本与审计结论

## 7. Chat 审计按声明 index 分桶（`RED-7`）

- [x] 7.1 `src/service/llm_gateway/tool.rs:221-309` Chat 分桶把 `chat_bucket(ci, idx)` 的 `ci` 改为 `ch.get("index")` 声明值（缺省回退枚举位置）；`src/service/llm_gateway/tool.rs:167 chat_bucket` 语义保持 `declared*64+idx`
  - 验证：`cargo test -p veil chat_bucket_declared_index` 通过；`choices[].index` 乱序/跳号（如 2、0、5）各 choice 分片归入各自槽
  - 验证：`grep -n "get(\"index\")" src/handler/llm/pump/fragments.rs` 命中 choice 声明 index 读取
- [x] 7.2 回归：单 choice 分桶键值与旧行为等值
  - 验证：`cargo test -p veil chat_bucket_single_choice_unchanged` 通过；`chat_bucket(0, 0)` 键值与旧实现等值
  - 验证：Chat 审计既有单测与 e2e 全绿

## 8. 截断未完成 tool 落审计（`RED-8`）

- [x] 8.1 `src/handler/llm/pump/spawn/terminal.rs:82-87` 截断收尾在清空 `pending_tool_frames` 前，对未完成 tool 调用产生审计记录/告警（warn 含槽号/分片数，**不含参数明文**），保留 `truncated_tool_dropped` 指标
  - 验证：`cargo test -p veil truncation_unfinished_tool_audited` 通过；截断场景审计/告警记录存在且断言不含参数明文
  - 验证：`grep -n "truncated_tool_dropped" src/handler/llm/pump/spawn/terminal.rs` 命中既有指标与新增审计调用
- [x] 8.2 回归：正常完成不产生截断审计、截断矩阵不回退
  - 验证：`cargo test -p veil normal_complete_no_truncation_audit` 通过；正常完成路径无截断型审计告警
  - 验证：`cargo test -p veil --test http_e2e_truncation_matrix` 全绿

## 9. 门禁与文档同步

- [x] 9.1 README §7.10 与 spec 同批同步（掩码边缘规则、别名集、还原/审计覆盖口径互引）
  - 验证：`grep -n "掩码边缘\|§7.10" README.md` 命中修正段并与 spec 对应 Requirement 互引一致
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0，无 FAIL 项
- [x] 9.2 质量门禁：`cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
  - 验证：`cargo test` 用例数不少于 apply 前基线，无 flaky 复现
- [x] 9.3 `openspec validate veil-redaction-audit-coverage --strict` 0 failures
  - 验证：命令输出 `is valid`（strict 模式无 warning）
  - 验证：spec.md 中 `RED-5` 对应 Requirement 名为「Chat `tool_calls` 审计到期/全局完成分离与终端最终审计」且含 ≥3 个 Scenario（含「tool_calls 仍触发审计到期」「终端最终审计幂等」）
- [x] 9.4 覆盖终检：`RED-1`–`RED-8` 均出现在 proposal「发现覆盖表」并映射到本 tasks，无静默合并/删除
  - 验证：逐 ID 对照 proposal 覆盖表与 tasks 编号，8/8 命中
  - 验证：`openspec status --change veil-redaction-audit-coverage` 显示全部 artifact 完成
