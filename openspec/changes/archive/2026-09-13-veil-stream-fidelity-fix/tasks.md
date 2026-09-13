## 1. 抑制判据与逐帧增量（`S1`/`S8`）

- [x] 1.1 `src/service/audit/hold.rs` 新增 pending 判据 `has_pending_fragments()`（Chat/Anthropic：存在未在完成审计后释放的 `args_by_index` 分片；Responses：存在 `!done_seen` 的槽），并在完成事件审计后提供槽释放入口；`src/handler/llm/pump/decide.rs:108-114 should_suppress_held_output` 改判 `audit_hold_on && has_pending_fragments() && out_data_nonempty && !minor`；`src/handler/llm/pump/spawn.rs:532-538` 调用点接线
  - 验证：`cargo test -p veil suppress_gate_pending_only` 通过；无未完成分片时抑制为 false、默认 `AUDIT_MODE=off` 下抑制恒 false、存在未完成分片时为 true
  - 验证：`grep -n "has_pending_fragments" src/service/audit/hold.rs src/handler/llm/pump/spawn.rs` 命中声明与调用点
- [x] 1.2 逐帧到达回归：mock 上游慢速分片投递多帧文本、下游按帧读取，断言终止帧前已收到内容帧（非单帧拼接）
  - 验证：`cargo test -p veil sse_incremental_default_off` 通过；默认 `AUDIT_MODE=off` 下终止前收到 ≥2 个内容帧，且帧到达顺序与上游投递顺序一致
- [x] 1.3 keepalive 门控统一：`src/handler/llm/pump/spawn.rs:213-216` 的 `_gate` 由 `hold.held()` 改为与 1.1 同判据（仅未完成分片存在时门控）；补触发条件测试
  - 验证：`cargo test -p veil keepalive_gate_pending_only` 通过；无分片时保活帧按周期发送、存在未完成分片时保活被抑制

## 2. Responses 槽级完成与全局完成隔离（`S2`）

- [x] 2.1 `src/service/audit/hold.rs:188-235`：`is_complete_event` 的 `matches!` 集合移除 `response.output_item.done`/`response.function_call_arguments.done`、加入 `response.incomplete`；新增槽级完成判据供 per-item done 使用；`src/handler/llm/pump/spawn.rs:361-363` 改为槽级判据调用 `mark_responses_done` 并对该槽执行审计与清理，`spawn.rs:483-485` 的全局 `mark_completed` 仅由 `completed/failed/incomplete` 触发
  - 验证：`cargo test -p veil responses_slot_isolated` 通过；仅到达 `response.function_call_arguments.done` 时全局完成未置位、后续 item 分片照常累积
  - 验证：`cargo test -p veil responses_complete_events_only` 通过；`completed`/`failed`/`incomplete` 三事件仍触发全局完成
- [x] 2.2 多 item 阻断回归：item0 良性完成后 item1 到达 `exec {"command":"rm -rf /"}`（block 模式），断言阻断帧注入且危险参数不透传
  - 验证：`cargo test -p veil responses_multi_item_block` 通过；下游收到阻断终端，响应体不含 `rm -rf /`
  - 验证：`cargo test -p veil --test http_e2e_audit_approve` 全绿（阻断/放行/审批三臂无回退）

## 3. 合成终端保序（`S3`）

- [x] 3.1 `src/handler/llm/pump/spawn.rs:258-284` 的 `SynthesizeFailed` 分支与 `spawn.rs:620-629` 截断合成路径：发送合成终端前先 `boundary.flush()` 滞留帧并入 `agg` 按序发送，再发送终端帧；阻断路径维持 `agg.clear()/boundary.clear()` 不改
  - 验证：`cargo test -p veil synth_terminal_flush_order` 通过；`type:"error"` 场景下游先收到 delta A 再收到 `response.failed`
  - 验证：`cargo test -p veil truncation_terminal_flush_order` 通过；截断合成前滞留帧按序落下
- [x] 3.2 回归：断言合成终端后无数据帧、终端恰一（`response.failed` 计数为 1）
  - 验证：`cargo test -p veil synth_terminal_single` 通过；terminal 计数恰一且其后无 data 帧
  - 验证：既有 `cargo test -p veil --test http_e2e_truncation_matrix` 全绿无回退

## 4. 跨帧占位符缝合还原（`S4`）

- [x] 4.1 `src/handler/llm/pump/spawn.rs:486-510` 还原路径新增请求级跨帧 carry：帧还原文本尾部为占位符合法前缀残缺形态（`__VG_CRED_`/`__PII_` 及续段）时移入 carry 不落盘，下一帧拼接 carry 后先执行还原再检测新的尾部残片
  - 验证：`cargo test -p veil cross_frame_token_stitch_cred` 通过；两帧 `__VG_CRE` + `D_000001__` 下游收到还原明文、无剥离残片
  - 验证：`cargo test -p veil cross_frame_token_stitch_pii` 通过；PII token 跨帧切分同样还原明文
- [x] 4.2 流末残余清理：正常 EOF、截断、`chunk()` 报错三路径的残余 carry 按既有 `strip_cred_partials`/`strip_pii_partials` 口径剥离，不泄漏原文
  - 验证：`cargo test -p veil cross_frame_residual_strip` 通过；流末未配对前缀被剥离、输出不含 token 原文
- [x] 4.3 既有跨缝/残缺行为不回退：`src/service/redaction/seam.rs:177-197` 掩码保留为第二道防线
  - 验证：`cargo test -p veil --test mask_engine_diff` 与残缺剥离相关单测全绿

## 5. 传输错误观测与断流终端策略（`S5`/`S11`）

- [x] 5.1 `src/handler/llm/pump/spawn.rs:162` 的 `while let Ok(chunk)` 改显式分支：`Err(e)` 记录 warn（含错误与已转发量）并经统一 `set_truncated`/指标置截断观测；`Ok(None)` 维持正常 EOF
  - 验证：`cargo test -p veil stream_transport_error_observed` 通过；mock 上游中途报错时日志含截断告警、观测计数增加
- [x] 5.2 断流终端策略实现：Chat 补恰一 `data: [DONE]` 且记 `open_ended`（与既有 finish_reason 补发合并到同一收尾路径，消除 `truncated_mode_set` 条件竞态）；Anthropic 不合成 `message_stop`、记 `open_ended`；Responses 已发帧合成恰一 `response.failed`、记 `synthesized_failed`，零帧维持真空流最小终止
  - 验证：`cargo test -p veil midstream_truncation_terminal_matrix` 通过；三协议终端恰一、`truncated_mode` 口径与 design D6 一致
- [x] 5.3 断流矩阵回归（mock 上游 mid-stream 断连，含 `chunk()` Err 与异常 EOF 两种形态）
  - 验证：`cargo test -p veil --test http_e2e_truncation_matrix` 通过；既有 tss 用例按新口径更新且无回退（Chat 补 `[DONE]`、Anthropic 无合成终止、Responses 恰一 `failed`）
- [x] 5.4 README §7.2 与 §8.6 同步：中途断流各协议终端与 `truncated_mode` 口径
  - 验证：`grep -n "中途\|断流" README.md` 命中新口径；`python3 scripts/check_doc_paths.py` 退出 0

## 6. 流式上游错误状态透传（`S6`）

- [x] 6.1 `src/handler/llm/dispatch.rs:252-268`：上游 `status>=400` 或响应 `content-type` 非 `text/event-stream` 时读取正文字节并按原状态返回（受 `NONSTREAM_MAX_BYTES` 上限约束），不进入 SSE 泵；仅 `status<400` 且 `text/event-stream` 走 `spawn_stream_pump` + `build_sse_response`
  - 验证：`cargo test -p veil stream_upstream_error_passthrough` 通过；`stream:true` 上游 500 JSON/HTML 时下游状态与正文字节逐字节一致
  - 验证：`cargo test -p veil stream_upstream_non_sse_body` 通过；2xx 非 `text/event-stream` 正文不被改写为 200 SSE 假流
- [x] 6.2 补 500 JSON 与 500 HTML 用例（含空体错误）
  - 验证：`cargo test -p veil --test http_e2e_truncation` 或新增 e2e 全绿；两类错误体保状态保正文
- [x] 6.3 README §7.2 同步流式错误透传口径
  - 验证：`grep -n "text/event-stream" README.md` 命中透传声明段

## 7. 审计 hold 字节按槽回收（`S7`）

- [x] 7.1 `src/service/audit/hold.rs` 按槽记账活跃字节：`clear_index`（`hold.rs:248-252`）、Responses per-item done 槽审计清理、`mark_completed`/`mark_rejected` 归还对应字节；溢出判定基于活跃字节
  - 验证：`cargo test -p veil hold_bytes_reclaim` 通过；长流多工具依次完成清槽后不触发 overflow 拒绝
  - 验证：`cargo test -p veil hold_bytes_active_only` 通过；活跃分片累计口径与单调用上限一致
- [x] 7.2 真实超限仍 fail-closed：单调用分片累计超 `AUDIT_HOLD_MAX_BYTES` 时拒绝并清仓
  - 验证：`cargo test -p veil overflow_fail_closed_and_clears_pending` 全绿（既有）+ 新增长流用例通过

## 8. 截断合成发送成功才置位（`S9`）

- [x] 8.1 `src/handler/llm/pump/spawn.rs:603-630`：仅当合成帧 `send` 成功后置位 `terminal_sent`/`any_frame_sent`/转发计数；全部发送失败时不置位、不掩盖空流守门
  - 验证：`cargo test -p veil truncation_send_failure_guard` 通过；下游早断时不悬挂、不 panic，`PumpOutcome` 如实反映未注入终端
- [x] 8.2 观测回归：截断合成成功路径 `terminal_injected`/metrics 与既有断言一致
  - 验证：`cargo test -p veil --test http_e2e_truncation` 全绿

## 9. 流式审批不挂起记录（`S10`）

- [x] 9.1 design D10 记录 Non-Goal：Python 原仓审批挂起期独立保活（`_llm.py:1948-1969`）不迁移；spec「流式审批不挂起声明」与 README §6.4 互引
  - 验证：`grep -n "S10" openspec/changes/veil-stream-fidelity-fix/design.md` 命中 Non-Goal 段落；`grep -rn "_llm.py:1948" openspec/changes/veil-stream-fidelity-fix/` 命中
- [x] 9.2 approve 模式不挂起 e2e 不回退：危险调用 pending 建单、流不断链、无阻断帧
  - 验证：`cargo test -p veil --test http_e2e_audit_approve approve_branch_keeps_stream_without_block_frame` 通过

## 10. 门禁与归档准备

- [x] 10.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 10.2 `python3 scripts/check_doc_paths.py` 退出 0（README 与 spec 引用路径全部存在）
  - 验证：命令输出 `OK`，无 FAIL 项
- [x] 10.3 `openspec validate veil-stream-fidelity-fix --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 10.4 README §6.4/§7.2/§8.6 与 spec 同批终检（口径一致、无旧表述残留）
  - 验证：`grep -n "全流缓冲\|静默" README.md` 无旧口径残留；spec 与 README 对应段落互引一致
