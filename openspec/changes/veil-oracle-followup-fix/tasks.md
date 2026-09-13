## 1. `F1` Matrix 审批真实 event id 绑定

- [x] 1.1 `src/service/matrix/notify.rs:27-35`：`NotificationSink` trait 新增 `send_text_tracked(&self, text: &str) -> Option<String>`，默认实现回退调用既有 `send_text` 并返回 `None`（保持事件环/spool best-effort 语义不变）
  - 验证：`cargo test -p veil notification_sink_default_tracked` 通过；默认 sink 的 `send_text_tracked` 返回 `None` 且仍完成 `send_text`
- [x] 1.2 `src/service/matrix/notify.rs:32-35`：`impl NotificationSink for MatrixBot` 实现 `send_text_tracked`，返回 `MatrixBot::send_text`（`src/service/matrix/bot.rs:110`）的真实 event_id；发送失败返回 `None`（不 panic）
  - 验证：`cargo test -p veil matrix_bot_tracked_returns_real_id` 通过；断言返回值等于 `bot.rs` 发送返回的真实 id，失败分支为 `None`
- [x] 1.3 `src/service/credential/approval.rs:67-78 submit_pending_with_branch`（及 `submit_pending`、register/revoke/credential/unlock 等所有审批建单路径）：先 `send_text_tracked` await 取真实 id，成功以其为键 `submit_branch(real_id, branch)`；发送失败或 `None` 时 fail-closed（不建单，按拒绝/错误返回）
  - 验证：`cargo test -p veil approval_pending_uses_real_event_id` 通过；建单后 pending 键等于注入 sink 返回的真实 id
  - 验证：`cargo test -p veil approval_send_failure_fail_closed` 通过；发送失败时无 pending 建单且调用方收到错误
- [x] 1.4 audit-hold / audit 审批建单路径同步改用 tracked 发送取真实 id（与 1.3 同口径，避免遗漏并行路径）
  - 验证：`grep -rn "send_text" src/service/matrix/ src/service/credential/ src/service/audit/` 结果逐点标注 best-effort 或 tracked，无审批建单路径仍使用丢弃返回值
  - 验证：`cargo test -p veil audit_hold_approval_real_event_id` 通过
- [x] 1.5 补以注入 sink 返回固定真实 id 的 resolve 回归（`✅`/`❎`/`🔓` + 无回复超时），并在 README 与 design D1 说明 spool（best-effort）与审批（需回执、fail-closed）的路由差异
  - 验证：`cargo test -p veil approval_reaction_three_state_and_timeout` 通过；三态与超时各按预期落定，不依赖合成键
  - 验证：`grep -n "send_text_tracked\|best-effort" README.md` 命中路由差异说明

## 2. `F2` 审计规范化次序

- [x] 2.1 `src/service/audit/rules.rs:439`/`:494`/`:501`：判定次序改为先 `split_chain` 再逐段 `canonicalize_args`（或令 `fold_bin_prefix` 对链节首 `;`/`|`/`&`/`(`/`）` 后的命令起始生效）
  - 验证：`cargo test -p veil chain_segment_alias_fold` 通过；`echo x;/bin/rm -rf tmp` 命中危险命令
- [x] 2.2 补构造性绕过回归：`echo x;/bin/rm -rf tmp`、`echo x|/bin/rm -rf y`、`(/bin/rm -rf z)`
  - 验证：`cargo test -p veil chain_bypass_regression` 通过；三例均命中，返回对应 reason
  - 验证：既有 `cargo test -p veil chain_priority` 与管道/规范化测试全绿无回退
- [x] 2.3 同步 design D4 次序描述为「先拆链再别名折叠」，与实现一致
  - 验证：`grep -n "split_chain\|canonicalize" openspec/changes/veil-oracle-followup-fix/design.md` 命中更正后的次序表述

## 3. `F3` Responses 工具分片先审后放

- [x] 3.1 `src/handler/llm/pump/spawn.rs:324-325`：`should_buffer_tool_frame` 与 `should_suppress_held_output` 对 Responses 协议生效，未完成工具分片先缓冲、不直接下发
  - 验证：`cargo test -p veil responses_tool_delta_buffered` 通过；delta 未在 done 前下发
- [x] 3.2 slot `.done` 完成审计后再决定放行或阻断；block 模式下危险明文不达下游且恰一阻断帧
  - 验证：`cargo test -p veil responses_tool_delta_no_leak_block` 通过；下游无危险明文、阻断帧计数为 1
  - 验证：`cargo test -p veil responses_tool_delta_allow_passthrough` 通过；安全参数按原序放行
- [x] 3.3 补多 item + delta 拆分 E2E（各 item 独立「缓冲 → done 审计 → 放行/阻断」，结论互不串扰）
  - 验证：`cargo test -p veil responses_tool_multi_item_delta_e2e` 通过
- [x] 3.4 确认不改动 Responses 保序/切片与真空终止语义
  - 验证：既有 `vacuum_stream_three_protocol_e2e_comparison`、`proto_closeout_tests` 全绿无回退

## 4. `F4` PII 短名槽变量文档对齐（doc-align）

- [x] 4.1 `README.md:53/55/57`：将 `PII_CUSTOM_RULES`/`PII_CUSTOM_PATTERNS`/`PII_CUSTOM_DICT` 表述改为「**短名槽变量**：与 `*_FILE` 同槽、同文件路径解析、同 fail-closed，列序最低（无 `_FILE` 后缀仅为兼容别名）」，删除「内联/内容语义」表述
  - 验证：`grep -n "内联短名槽" README.md` 无命中；`grep -n "短名槽变量" README.md` 命中三条且含「文件路径」
- [x] 4.2 同步本 change design D4 与 canonical `openspec/specs/pii-parity/spec.md` 的措辞（如涉及），使文档与 `src/config/env_parse.rs:593-613`、`src/config/custom_file.rs:68` 实现字面一致
  - 验证：`grep -rn "内联" openspec/specs/pii-parity/spec.md README.md`（限相关段落）无「内联内容」残留
- [x] 4.3 核对实现未改：`load_custom_file` 仍要求 `path.is_file()` fail-closed（备选真内联不采用）
  - 验证：`grep -n "is_file" src/config/custom_file.rs` 仍命中

## 5. `F5` 危险表词边界匹配

- [x] 5.1 危险表 `"dd "` 改为词边界/命令词首匹配，`add`/`cdd` 不误报、`dd if=... of=/dev/sda` 命中
  - 验证：`cargo test -p veil dangerous_dd_word_boundary` 通过；`echo add` 与 `cdd` 均不判危险
  - 验证：`cargo test -p veil dangerous_dd_real_hit` 通过；`dd if=/dev/zero of=/dev/sda` 命中
- [x] 5.2 同步 design D5 与 canonical 审计规格中「裸词」措辞为「词边界/命令词首」
  - 验证：`grep -n "词边界\|命令词首" openspec/changes/veil-oracle-followup-fix/design.md` 命中

## 6. `F6` 摘要脱敏近似线性

- [x] 6.1 `src/service/audit/log.rs`：`mask_secret_forms` / `email_at` 先按既有 4096/120 截断口径约束输入上限，或一次性预计算小写索引，去除逐位置 `to_lowercase()` 剩余串与逐位 `find('@')`
  - 验证：`cargo test -p veil audit_summary_linear_bound` 通过；大输入（≤1MB）在近似线性时间内完成
- [x] 6.2 补大输入边界测试（含接近 `AUDIT_HOLD_MAX_BYTES` 的 args）
  - 验证：`cargo test -p veil mask_secret_forms_large_input` 通过
- [x] 6.3 输出与原行为逐字一致
  - 验证：既有 `audit_summary_forms`、`zero_plaintext`、`b9_deny_summary_dual_shapes` 全绿无回退

## 7. `F7` TPM 守护结构化

- [x] 7.1 将 TPM 同步子进程守护由白名单整文件化 + 标记探测改为结构化可验证约束（收窄白名单到 `spawn_blocking` 闭包范围，或伪/真分支断言）
  - 验证：`cargo test -p veil tpm_sync_subprocess_guard` 通过；受约束路径通过、越界路径失败
- [x] 7.2 补绕行反例测试（别名/非受约束路径触发同步子进程被拦）
  - 验证：`cargo test -p veil tpm_sync_guard_bypass_rejected` 通过

## 8. `F8` 缓存复用可观测

- [x] 8.1 hardening analyzer 缓存断言加强为可观测命中（命中计数或等价观测），覆盖跨调用复用
  - 验证：`cargo test -p veil hardening_analyzer_cache_reuse` 通过；第二次调用有命中证据
- [x] 8.2 去除「同输入同输出」替代性断言
  - 验证：`grep -n "cache" src/` 相关测试不含仅结果相同的替代断言

## 9. `F9` 清扫任务未启动可观测

- [x] 9.1 `src/service/credential/approval.rs` `init_no_sync_sweeper`：改为可观测断言「清扫任务/后台 spawn 未启动」（任务计数或句柄证据），替代「同步 sweep 不 panic」弱代理
  - 验证：`cargo test -p veil init_no_sync_sweeper_observable` 通过；断言任务未启动证据存在

## 10. `F10` 启动白名单 fail-fast 无副作用

- [x] 10.1 `startup_whitelist_fail_fast`：断言非法 `APPROVAL_WHITELIST` 时无 DB/TPM/网络副作用（数据目录未创建、TPM 未调用、后台任务未启动），去除 tautology
  - 验证：`cargo test -p veil startup_whitelist_fail_fast` 通过；三项副作用可观测为「未发生」

## 11. `F11` web_search 审计全 hold 集成

- [x] 11.1 补 `web_search_call.action.query` 经完整 hold（流式 + 非流式）进入审计的集成测试
  - 验证：`cargo test -p veil web_search_action_audit_hold_stream` 通过；`action.query` 经 hold 按 verdict 处理
  - 验证：`cargo test -p veil web_search_action_audit_hold_nonstream` 通过；与流式同结论

## 12. `F12` 自定义规则跨帧 hold 端到端

- [x] 12.1 补自定义规则经 `feed_output_frame` 跨帧拼接后命中的端到端用例
  - 验证：`cargo test -p veil custom_rule_cross_frame_hold_e2e` 通过

## 13. `F13` fuzzy 还原边界覆盖

- [x] 13.1 补 fuzzy 还原对 response 表 token 与未知 seq「原样保留、不还原」的边界测试
  - 验证：`cargo test -p veil fuzzy_response_table_not_restored` 通过
  - 验证：`cargo test -p veil fuzzy_unknown_seq_not_restored` 通过

## 14. `F14`–`F17` 文档口径收敛

- [x] 14.1 `F14`：统一 T8 表述为「段解析」口径（非跳过段先整体 JSON 解析并 walk，失败回退文本段），登记于本 change design D14 与可写文档；`veil-transport-fidelity-fix` 目录冻结不改
  - 验证：`grep -n "段解析" openspec/changes/veil-oracle-followup-fix/design.md` 命中更正表述
- [x] 14.2 `F15`：核对 README 与 canonical specs 是否引用 `guard.rs`，若存在更正为 `frame_feed.rs`；sibling change 目录冻结，仅登记
  - 验证：`grep -rn "guard\.rs" README.md openspec/specs/` 无命中（或已更正为 `frame_feed.rs`）
- [x] 14.3 `F16`：在 README §4/§8.4 与 design D14 明确「空闲票 60s 回收上限」与「有阻塞等待者凭据类票 300s 阻塞 TTL」两口径并存；canonical 晋升后同步 spec
  - 验证：`grep -n "60s" README.md` 与 `grep -n "300s" README.md` 命中且不互相混用
- [x] 14.4 `F17`：统一 `src/registry/store.rs:291` 注释与 `src/service/credential/vault_ops.rs` 预检说明为「全局 hash 去重已移除；注册判重仍按 `caller_path` 与未吊销 `name`」
  - 验证：`grep -n "hash" src/registry/store.rs` 注释与 `grep -n "预检\|判重" src/service/credential/vault_ops.rs` 表述一致

## 15. 门禁与回归

- [x] 15.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 15.2 `openspec validate veil-oracle-followup-fix --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 15.3 `python3 scripts/check_doc_paths.py` 退出码 0
  - 验证：输出 `OK`，无 FAIL
