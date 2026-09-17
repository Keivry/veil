# Tasks

> 说明：本 change 的 spec 修正经 change-local delta 承载，canonical `openspec/specs/**` 由归档步骤（`openspec archive`）合并；apply 阶段 SHALL NOT 手改 canonical。验收命令中的测试名可在实现时按仓库既有命名微调，但 SHALL 保留同名语义与断言目标（恰一次 / 阻断 / 不双审）。

## 1. R7-01 Responses pending 槽终端最终审计（恰一次）

- [x] 1.1 `src/service/audit/hold.rs`：新增 `pub fn release_pending_audited(&mut self)`——置拒绝态时早返；否则移除全部 `!done_seen` 的 `responses_slots` 并按 `ResponsesSlot::held_bytes()` 以饱和算术归还 `total_bytes`（口径与 `release_audited` 一致，不触碰 done 槽与 `args_by_index`）。验证：`src/service/audit/hold/tests.rs` 新增单测（pending 槽释放后 `total_bytes` 归零/回退、done 槽保留），`cargo test release_pending_audited` 通过。
- [x] 1.2 `src/handler/llm/pump/spawn/event_loop.rs` 全局完成臂（`responses_pending_triples()` 审计循环）：循环结束且 `!state.hold.is_rejected()` 时调用 `state.hold.release_pending_audited()`；`Block` 早退路径不调用（`mark_rejected()` 已清仓）。验证：`cargo test responses_pending` 相关用例通过且新增回归（见 1.4）。
- [x] 1.3 `src/handler/llm/pump/spawn/terminal.rs` 终端最终审计：在既有 `hold.tool_triples()` done 循环之后追加 pending 循环，门控 `protocol.is_responses() && !hold.is_rejected()`；verdict 处置与 done 循环逐字一致（`Block` → `hold.mark_rejected()` + `blocked_index = Some(idx)` + `break`；`NeedApproval` → `audit_pending.insert`；`Allow` → 无动作）；顺序为 done 槽在前、pending 槽在后。验证：`cargo test responses_audit` 通过（含 1.4 新用例）。
- [x] 1.4 `src/handler/llm/pump/responses_audit_tests.rs` 新增两条回归：① 清理完成不双审（危险 pending 槽经全局完成臂审计后流正常收尾，终端 no-op、恰一次审计、阻断终端恰一）；② 截断危险 pending 槽必 `Block`（未发全局完成、危险参数不透出、`blocked_index` 为槽自身 `output_index`）。验证：`cargo test responses_pending_audited_exactly_once` 与 `cargo test responses_pending_blocked_on_truncation` 通过。
- [x] 1.5 既有 Chat/Anthropic 终端最终审计用例（`src/handler/llm/pump/audit_due_tests.rs`、`spawn_tests.rs`）零回退。验证：`cargo test terminal_flush_audit_idempotent` 与既有 `tool_triples` 终端审计用例全绿。

## 2. R7-02 JSON 对象键位脱敏（含碰撞回退）

- [x] 2.1 `src/service/json_walk.rs::json_walk_nested` Object 分支：收集原始键集合后按插入序构造输出 Map；对每个键调用 leaf（键按纯字符串 leaf 处理，MUST NOT 调用 `walk_string_leaf`/stringified-JSON 递归）；替换后键与原键或已选键同名时保留原键（碰撞回退）；值递归口径不变；结果无重复键、插入序保持。验证：`cargo test json_walk` 全绿（含 2.2 新用例）。
- [x] 2.2 `src/service/json_walk.rs` tests 新增单测：`{"13800138000":"x"}` 键位替换且输出可 `jloads`；键位碰撞回退保留原键；键串内嵌敏感子串被子串扫描替换；token 形态键原样保留；键位替换往返（redact→restore）后内容与键集合一致。验证：`cargo test json_walk_key` 通过。
- [x] 2.3 请求侧与响应侧共用入口零旁路核查：`src/service/redaction/scope.rs` 的 `redact_request` 与响应侧新 PII 扫描均经 `json_walk::process_text`，键位覆盖自动生效；还原侧全文扫描无需改动。验证：`cargo test scope` 与 `cargo test cache_fidelity` 全绿，`grep -rn "json_walk_nested" src/` 无其他旁路实现。

## 3. R7-03 Responses error 终端落 `synthesized_failed`

- [x] 3.1 `src/handler/llm/pump/spawn/terminator.rs::plan_responses_error`：`truncated: None` 改为 `truncated: Some(TruncatedMode::SynthesizedFailed)`。验证：`cargo test plan_responses_error`（或既有 Responses error 计划用例）断言计划携带该观测。
- [x] 3.2 `src/handler/llm/pump/spawn/event_loop.rs` Responses error 臂：`TerminalPlan::Frames { kind, frames, .. }` 解构出 `truncated`；`commit` 之后无条件 `set_truncated(&mut state.meta, env.protocol, mode, Some(&env.metrics))`（仅 `Some(mode)` 时；不新增 helper、不以 `terminal_ok` 门控）。验证：`cargo test responses_error` 断言 `truncated_mode == Some(SynthesizedFailed)` 且 metrics `truncated.synthesized_failed` 递增（含下游早断仍落观测的用例）。
- [x] 3.3 既有 `set_truncated` Responses-only 守卫（`src/service/sse/meta.rs`）保持不变，调用点不重复门控。验证：`cargo test set_truncated` 与 `stream-protocol-parity` 相关截断用例全绿。

## 4. R7-04 / R7-08 稳定前缀 `system` 与协议原生键门控

- [x] 4.1 `src/service/redaction/conversation_key.rs::extract_system`：顶层 `system` 读取加 `protocol.is_anthropic()` 门控；Responses 分支（`instructions`）与 `messages` 回退分支不变。验证：`conversation_key_tests.rs` 新增用例——Chat 顶层 `system` 不参与第 3 级（与省略时同键/落第 4 级）；Anthropic 顶层 `system` 参与且命中第 3 级；`cargo test conversation_key_prefix_fields_protocol_whitelist` 全绿。
- [x] 4.2 修正 `src/service/redaction/conversation_key.rs::extract_system` 上方注释（约 :161）为「Anthropic 取原生顶层 `system` 或 `messages` 首条；Chat 仅 `messages`；Responses 取 `instructions`」。验证：`grep -n "Chat/Anthropic 取顶层" src/service/redaction/conversation_key.rs` 零命中。
- [x] 4.3 `README.md` §7.3 稳定前缀字段段改为「Anthropic 取原生顶层 `system` 或 `messages` 首条；Chat 仅 `messages`；Responses 取 `instructions`」。验证：`grep -n "Chat/Anthropic 取 \`messages\`" README.md` 零命中，新措辞命中一次。
- [x] 4.4 `README.md` §7.3 协议原生键段补「协议外原生键静默忽略（不命中第 2 级、不告警、不计数）」声明。验证：`grep -n "静默忽略" README.md` 命中该段；`cargo test conversation_key_native_keys_protocol_whitelist` 全绿（推导结果零变化）。

## 5. R7-05 非流请求遇上游 SSE 的总超时声明

- [x] 5.1 `README.md` §7.2「流式/非流超时口径」段补声明：非流请求（`stream` 未为 `true`）遇上游 `status<400` 的 `text/event-stream` 时经非流 client 总超时转发（复用已取得响应、不重发上游请求；超时按中途断流终端路径收尾），长流须显式 `stream:true`。验证：`grep -n "非流请求" README.md` 命中该声明；`grep -n "text/event-stream" README.md` 命中该段。
- [x] 5.2 零代码变更核查：`src/handler/llm/dispatch.rs` 非流分支（`serve_nonstream`，`state.http_client`）与 `src/handler/llm/nonstream.rs::serve_nonstream` 的 `NonstreamOutcome::Stream` 路径不变。验证：`git diff --stat src/handler/llm/dispatch.rs src/handler/llm/nonstream.rs` 为空；既有非流 SSE 转泵用例全绿。

## 6. R7-07 测试专用终端 helper 收编

- [x] 6.1 `src/service/block_inject/terminal.rs`：`dedupe_terminal_frames` 与 `count_done` 各加 `#[cfg(test)]`（`terminal_count` 已收编）；函数体/语义零改动。验证：`grep -n "pub fn dedupe_terminal_frames\|pub fn count_done" src/service/block_inject/terminal.rs` 的上一行均为 `#[cfg(test)]`。
- [x] 6.2 核查 `src/service/block_inject.rs` 门面重导出：glob `pub use {frames::*, terminal::*}` 随收编自动收窄即可；若存在显式重导出则同加 `#[cfg(test)]`。验证：`cargo build`（非 test 构建）零错误零 unused 告警；`cargo test` 全绿。
- [x] 6.3 生产零调用核查：`rg -n "dedupe_terminal_frames|count_done" src/ --glob '!target'` 的调用点全部位于测试模块（`#[cfg(test)]`/`*_tests.rs`）。验证：上述 grep 逐条判定无生产调用点；`cargo clippy --tests --all-targets -- -D warnings` 通过。

## 7. R7-09 文档精确对齐

- [x] 7.1 `README.md` §7.2 缓存列字段名：`cache_read/cache_creation_input_tokens` 改为精确的 `cache_read_input_tokens`/`cache_creation_input_tokens`（与 `src/service/llm_gateway/usage.rs::cached_columns` 一致）；并同步修正 `src/service/llm_gateway/usage.rs:26` 的 doc comment 简写为该全名（与 `:39`/`:42` 代码一致，避免单侧漂移）。验证：`grep -n "cache_read/cache_creation_input_tokens" README.md src/service/llm_gateway/usage.rs` 零命中；`grep -n "cache_read_input_tokens" README.md` 命中一次。
- [x] 7.2 `README.md` §7.9 逐字符豁免集补齐为 `{ } " [ ] , :`（与 `src/service/redaction/seam.rs::mask_span_bytes` 的 `matches!(c, '{' | '}' | '"' | '[' | ']' | ',' | ':')` 逐一对应）；并同步修正 `src/service/redaction/seam.rs:224` 的 doc comment 旧集 `信封字符（\`{ } " [ ]\`）` 为含 `,`/`:` 的完整集（与 `:226`/`:238` 代码一致，避免单侧漂移）。验证：`grep -n "信封字符（\`{ } \" \[ \]\`）" README.md src/service/redaction/seam.rs` 零命中；新集合命中一次且包含 `,`/`:`。

## 8. 最终验证与复审

- [x] 8.1 `cargo fmt --check` 通过。
- [x] 8.2 `cargo clippy --tests --all-targets -- -D warnings` 全绿（含 1.x/2.x/6.x 新代码）。
- [x] 8.3 `cargo test` 全绿（含 1.4/2.2/3.2/4.1 新用例；记录用例数与新增用例名单）。
- [x] 8.4 `python3 scripts/check_doc_paths.py` 与 `python3 scripts/check_file_sizes.py` 全绿。
- [x] 8.5 `openspec validate veil-audit-r7-remediation --strict` 通过（6 个 delta 合法；MODIFIED 标题与 canonical 逐字一致）。
- [x] 8.6 `bash scripts/gate.sh` 通过；缺 Python venv/SDK 前置时以 `GATE_SKIP_CONFORMANCE=1` 显式跳过并如实登记，缺 Go 工具链时以 `GATE_SKIP_GO=1` 显式跳过（不静默）。
- [x] 8.7 逐发现复核 delta 覆盖：R7-01/R7-02/R7-03/R7-04/R7-05/R7-07/R7-08/R7-09 各至少一条 requirement/scenario 可追溯；R7-06 按 design D10 登记不重开。验证：`grep -rn "R7-0" openspec/changes/veil-audit-r7-remediation/specs/` 逐项命中。
- [x] 8.8 Oracle 复审已实施变更（会话 `ses_f4e6803b3ffe4tI0M9BV4vziJO`）：裁决 **7/7 PASS**（无 Blocking/Major）；2 项 Minor 处置——① 测试强度已加固（approve 路径补 verdict 事件计数断言，防 `PendingApprovals` 同键去重掩盖双审）；② R7-03 下游早断双计按既有 midstream 同型行为登记为已声明边界（design Open Questions），不引额外行为变更。勾选本 tasks 并 commit & push。

## 9. 归档登记（非本 apply 范围，不计入 tasks 勾选）

归档阶段执行 `openspec archive veil-audit-r7-remediation`，由 delta 合并修正 canonical；归档后复核 README 与 canonical 的相关字面量（§7.2 字段名、§7.3 措辞、§7.9 豁免集）零漂移。该步骤属归档阶段，不作为本 apply 的完成前置。
