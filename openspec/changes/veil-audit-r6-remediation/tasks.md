# Tasks

> 说明：本 change 的 spec 修正经 change-local delta 承载，canonical `openspec/specs/**` 由归档步骤（`openspec archive`）合并；apply 阶段 SHALL NOT 手改 canonical（见 design Context 与决策 D1）。

## 1. 文档锚点收敛（AUDIT-01 / AUDIT-02）

- [x] 1.1 `README.md` §4 阈值表行与 §7.2 末句：`src/handler/llm/nonstream.rs:582` 改为符号锚点 `src/handler/llm/nonstream.rs::oversize_response`；验证：`grep -n "nonstream.rs:582" README.md` 零命中、`grep -n "::oversize_response" README.md` 命中两处。
- [x] 1.2 `README.md` §7.2 非流空体正面档：`src/error.rs:86-97` 改为 `src/error.rs::VeilError::code`，`:110` 改为 `src/error.rs::VeilError::status_code`；验证：`grep -n "error.rs:86-97\|error.rs:110" README.md` 零命中。
- [x] 1.3 `README.md` §7.2 超限判序引用 `src/handler/llm/nonstream.rs:130-161` 改为符号锚点 `src/handler/llm/nonstream.rs::serve_nonstream`；验证：`grep -n "nonstream.rs:130-161" README.md` 零命中。
- [x] 1.4 `README.md` §7.5 迁移句：`src/service/credential/vault_ops.rs:555-561` 改为 `src/service/credential/vault_ops.rs::emergency_revoke`；验证：`grep -n "vault_ops.rs:555" README.md` 零命中。
- [x] 1.5 确认 canonical 锚点修正仅由 change-local delta 承载（不手改 `openspec/specs/**`）：验证 `git status --short openspec/specs` 无改动，且 `grep -rn "\.rs:[0-9]" openspec/changes/veil-audit-r6-remediation/specs` 零命中（delta 内定位引用均为符号锚点）。
- [x] 1.6 `python3 scripts/check_doc_paths.py` 全绿（无新增悬空/越界），确认符号锚点不引入路径校验失败。

## 2. 门禁计数（AUDIT-04）

- [x] 2.1 `scripts/gate.sh` 头注第 6 步「23 项」改为「24 项」（与 README §8.5 及 `scripts/api_conformance.py` 的 14+4+5+1 一致）；验证：`grep -n "23 项" scripts/gate.sh` 零命中、`grep -n "24 项" scripts/gate.sh` 命中。

## 3. 上游多值响应头逐值透传（AUDIT-03）

- [x] 3.1 `src/handler/llm/nonstream.rs::clone_upstream_headers` 克隆循环 `resp_headers.insert(n, val)` 改 `resp_headers.append(n, val)`；验证：3.3 新单测（非流路径）通过。
- [x] 3.2 `src/handler/llm/dispatch.rs::stream_upstream_passthrough` 克隆循环 `resp_headers.insert(n, val)` 改 `resp_headers.append(n, val)`；验证：3.3 新单测（流式错误透传路径）通过。
- [x] 3.3 新增多值回归测试（落点：`src/handler/llm/nonstream/tests/headers.rs` 的非流对话路径用例 `nonstream_upstream_multi_value_headers_preserved`；`src/handler/llm/stream_fidelity_tests.rs`（既有 dispatch 流式保真测试模块）的流式错误透传用例 `stream_passthrough_error_preserves_multi_value_headers`）：上游返回两条同名头（`warning: a` 与 `warning: b`），断言下游 `get_all` 得 2 条；验证：`cargo test multi_value` 2 用例通过、既有单值用例不变。
- [x] 3.4 确认网关自置头与后处理语义不变：`with_protocol_header` 仍 `insert` 覆盖、`strip_veil_internal_headers`/`filter_hop_headers_counted` 仍按去重键 `remove`；验证：既有头相关测试全通过。

## 4. 措辞收敛（AUDIT-05 / AUDIT-06）

- [x] 4.1 `src/handler/llm/mod.rs:61` 注释由「网关生成响应统一置 `x-veil-protocol`」改为「非流对话路径 + 流式错误透传路径置该头；SSE 成功路径与 NonDialog 透传不置」；验证：`grep -n "统一置" src/handler/llm/mod.rs` 零命中；README 经核查无「统一」类过宽措辞（无重复修复项）。Oracle 复审补充：`src/handler/llm/nonstream/tests/headers.rs` 模块注释同口径修正（原「统一 `x-veil-protocol`」→ 非流对话路径范围）。
- [x] 4.2 `README.md` §7.2 发送语义段：「`Fast` 攒至标点边界或 `FAST_EMIT_THRESHOLD_BYTES` 字节阈值」改述为「实际边界为 4096 字节阈值；`agg` 恒以帧终止 `\n\n` 结尾，标点分支生产不可达（`is_punct_boundary` 保留为 API）」；验证：`grep -n "攒至标点边界或" README.md` 零命中。Oracle 复审补充：`src/service/sse/emit.rs` 模块注释与 `FAST_EMIT_THRESHOLD_BYTES` 注释对齐同口径（标点分支聚合路径不可达）。
- [x] 4.3 确认 `is_punct_boundary` / `select_emit` / `FAST_EMIT_THRESHOLD_BYTES` 零行为变更（仅文档）；验证：`cargo test` 中 sse/emit 相关用例全通过。

## 5. 验证与复审

- [x] 5.1 `cargo fmt --check` + `cargo clippy --tests --all-targets -- -D warnings` + `cargo test` 全绿（含 3.3 新用例）。
- [x] 5.2 `python3 scripts/check_doc_paths.py` 与 `python3 scripts/check_file_sizes.py` 全绿。
- [x] 5.3 `openspec validate veil-audit-r6-remediation --strict` 通过（6 个 delta 合法，且 delta 内定位引用均为符号锚点——覆盖 delta 文本与实现的对齐核验）。
- [x] 5.4 `bash scripts/gate.sh` 七步通过；第 6 步缺 Python venv/SDK 前置时以 `GATE_SKIP_CONFORMANCE=1` 显式跳过并如实登记（不静默）。
- [x] 5.5 Oracle 复审已实施变更（会话 `ses_f4ea412a3ffeBIpAzqLFUWNhMl`）：裁决 **PASS**（无 Blocking/Major）；3 项 Minor 已修（`nonstream/tests/headers.rs` 与 `emit.rs` 注释措辞对齐、tasks 勾选）。诚实登记：Oracle 未复现的多值头回环在 CI 未单独跑；`check_doc_paths.py` 不校验 `::symbol` 存在性，已登记为后续 change 候选。
- [x] 5.6 勾选本 tasks 全部条目、`openspec status --change veil-audit-r6-remediation` 显示 complete，并 commit & push 到 master（Conventional Commits）。

## 6. 归档登记（非本 apply 范围，不计入 tasks 勾选）

归档阶段执行 `openspec archive veil-audit-r6-remediation`，由 delta 合并修正 canonical 的定位引用；归档后复核上述陈旧行号零命中（`grep` README 与 `openspec/specs/**` 对应字面量）。该步骤属归档阶段，不作为本 apply 的完成前置。
