## 1. 文档 `_llm.py` 行号核验与更正（`DOC-1`）

- [x] 1.1 `README.md:605`：`_llm.py:2936-2944` 更正为 `_llm.py:2936-2946`（覆盖 `metrics_ctx['status'] = 502` 所在行）；`openspec/specs/runtime-parity-limits/spec.md:10` 与 `src/handler/llm/nonstream.rs:150/444`、`src/handler/llm/nonstream/tests/f2.rs:24/59` 五处 `_llm.py:2942` 更正为 `_llm.py:2951-2961`（502 JSON 体构造行）
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0（引用路径存在）
  - 验证：`grep -rn "_llm.py:2942" README.md openspec/specs/ src/` 在非归档语料零命中；`sed -n '2951,2961p' /home/keivry/项目/Python/credential-proxy/_llm.py` 输出含 `response_too_large` 与 `status=502`
- [x] 1.2 核验准确项保持：确认 `README.md:783` 的 `_llm.py:2633`（`async def _ensure_nonempty_stream(`）与 `src/config/env_parse.rs:56` 的 `_llm.py:139`（`NONSTREAM_MAX_BYTES = int(...)`）不改，并在 design D1 表登记
  - 验证：`sed -n '2633p;139p' /home/keivry/项目/Python/credential-proxy/_llm.py` 输出与注释语义一致
  - 验证：`grep -n "_llm.py:2633\|_llm.py:139" README.md src/config/env_parse.rs` 命中且内容未变

## 2. 源码注释指针修正（`DOC-2`）

- [x] 2.1 `src/service/audit/verdict.rs:44`、`src/service/audit.rs:28`、`src/service/block_inject.rs:464`、`src/handler/llm/nonstream.rs:60` 四处注释的 `src/config/env_parse.rs:307-310` 更正为 `src/config/env_parse.rs:469-478`（`validate_approve_whitelist`，实际行号随 `veil-audit-policy-enforcement` 落地下移），并在「显式门禁」语境补 `src/main.rs:45`（`preflight_whitelist`）
  - 验证：`grep -rn "env_parse.rs:307-310" src/` 零命中；`grep -rn "env_parse.rs:469-478" src/` 命中 4 处
  - 验证：`sed -n '469,478p' src/config/env_parse.rs` 输出含 `validate_approve_whitelist` 与 `AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST`；`sed -n '45p' src/main.rs` 为 `preflight_whitelist` 定义
- [x] 2.2 交叉引用回归：确认 `src/service/audit/verdict.rs` 中 approve 空白名单降级测试（`empty_whitelist_downgrades_to_block_with_legacy_env_compat`）仍通过，注释修正不改变行为
  - 验证：`cargo test -p veil empty_whitelist_downgrades_to_block_with_legacy_env_compat` 通过
  - 验证：`cargo fmt --check` 退出 0（注释改动不破坏格式）

## 3. canonical spec 矛盾修订（`DOC-3`）

- [x] 3.1 `openspec/specs/behavior-changes/spec.md`：将「凭据淘汰 FIFO 改 LRU（含 5000/1000 容量分表声明）为 **BREAKING**：迁移 SHALL 说明容量语义」改为「非 BREAKING 容量分表确认」，并补 Python 基线 commit `46f6ff665c869b02c154c10df431c638c2177fd9` 与 `_token.py:231/:523-538`（真 LRU）、`:102/:141`（容量）取证
  - 验证：`grep -n "FIFO 改 LRU" openspec/specs/behavior-changes/spec.md` 命中行标注为「非 BREAKING 容量分表确认 / 不计入 BREAKING 清单」，不再作为 BREAKING 条目；`grep -n "46f6ff66" openspec/specs/behavior-changes/spec.md` 命中
  - 验证：核对后该 Requirement 的凭据淘汰措辞与 `README.md` §6.3 同字（基线 commit、`_token.py` 真 LRU/容量取证一致）
- [x] 3.2 `openspec/specs/docs-contract-sync/spec.md`：将「等价项不列为 BREAKING」Scenario 的「六处」「§6 共 7 小节」更正为「十处」「共 11 小节」（§6.3 非 BREAKING）
  - 验证：`grep -n "六处\|7 小节" openspec/specs/docs-contract-sync/spec.md` 零命中；`grep -n "十处\|11 小节" openspec/specs/docs-contract-sync/spec.md` 命中
  - 验证：`openspec validate --all --strict` 0 failures

## 4. `src/router.rs` 模块文档（`DOC-4`）

- [x] 4.1 `src/router.rs` 首部补 `//!` 模块文档，描述路由装配（凭据 API + LLM 代理 + `/_admin`）与 `observability_gate`/入口模式职责，风格对齐同层模块
  - 验证：`grep -c '^//!' src/router.rs` ≥ 1；`head -5 src/router.rs` 以 `//!` 开头
  - 验证：`cargo build -p veil` 退出 0（注释不破坏编译）

## 5. `GET /registrations` 文档口径更正（`DOC-5`）

- [x] 5.1 `README.md` §5「Go 客户端对接指引」表中 `GET /registrations` 行：更正「原仓无鉴权直读」为「原仓经 `_require_auth` 校验 `GET_BINARY_HASH` + `GET_BINARY_SECRET`（未配置时兼容跳过）」，保留「本仓管理面鉴权（`X-Admin-Token` 或 `X-Get-Binary-Secret`，401）」结论
  - 验证：`grep -n "原仓无鉴权直读" README.md` 零命中；`grep -n "GET /registrations" README.md` 命中且描述含三因子口径
  - 验证：对照 `sed -n '189,191p;103,142p' /home/keivry/项目/Python/credential-proxy/_credential.py` 内容与文档一致
- [x] 5.2 `README.md` §7.5「吊销与注册鉴权声明」bullet 同步同一口径（原仓有鉴权；本仓管理面鉴权 401）
  - 验证：`grep -n "registrations_handler" README.md src/handler/credential.rs` 两处描述互引一致
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0

## 6. 测试断言修复（`TST-1`..`TST-4`）

- [x] 6.1 `TST-1`：`tests/http_e2e_credential.rs:119 t6_register_use_flow_200` 闭环取用（`:156-167`）改用注册/审批同一 caller（`/srv/flow.sh` + `h-flow-1`）；补负例——显式关闭自动放行的 opts 或用未注册 caller 时闭环失败
  - 验证：`cargo test -p veil --test http_e2e_credential t6_register_use_flow_200` 通过；将该用例闭环 caller 改为 `h-flow-2` 时测试失败（临时验证后还原）
  - 验证：`grep -n "flow2.sh\|h-flow-2" tests/http_e2e_credential.rs` 在闭环断言上下文零命中
- [x] 6.2 `TST-2`：`src/service/metrics/store/tests.rs:411 sample_upsert_rollover` 的 `:440-447` 改造为多 distinct 主键（fresh/boundary/expired）用例，断言仅过期行删除（参照同文件 `:452-489 sample_retention`）
  - 验证：`cargo test -p veil sample_upsert_rollover` 通过；断言在「删新鲜行」或「留过期行」的实现变更下失败
  - 验证：`cargo test -p veil --lib metrics::store` 全绿无回退
- [x] 6.3 `TST-3`：`src/service/audit/hold/tests.rs:342 timeout_disconnect_race_window_constants_locked` 改为送 `109/110/130/131`（及 `90`）到 `src/config/validate.rs` 校验入口，断言 `110..=130` 被拒、区间外通过
  - 验证：`cargo test -p veil timeout_disconnect_race_window` 通过；删除 `validate.rs:230` 拒启动分支时测试失败
  - 验证：`grep -n "AUDIT_TIMEOUT_RACE_MIN\|AUDIT_TIMEOUT_RACE_MAX" src/config/validate.rs` 命中真实使用点
- [x] 6.4 `TST-4`：`src/service/block_inject.rs:189`（`truncation_tss01_openended_no_fake_success`）恒真析取 `!contains("message_stop") || contains("truncated")` 改为严格断言（按实际帧语义断言 `message_stop` 存在性，不依赖理由文案）
  - 验证：`cargo test -p veil truncation_tss01_openended_no_fake_success` 通过；删除/新增终端帧时断言失败
  - 验证：`grep -n 'contains("message_stop") ||' src/service/block_inject.rs` 零命中

## 7. 覆盖缺口补缺（`TST-5`..`TST-8`）

- [x] 7.1 `TST-5`：交互式 KeePass 解锁链补 4 例——(a) TPM unseal 失败→解锁失败（不回落软件明文）；(b) 错主密码→500；(c) 并发冷启动经 `tpm_password_provider` 单开（只解封一次）；(d) `lock` 后重解锁需重新解封（缓存已清零）
  - 验证：`cargo test -p veil unlock_chain`（或新增用例名）4 例全绿；对照 `src/keepass.rs`/`src/service/tpm.rs` 既有孤立用例不回退
  - 验证：`cargo test -p veil --lib keepass` 与 `cargo test -p veil --lib tpm` 全绿
- [x] 7.2 `TST-6`：审计 `on_reaction` 补 1 例空白名单落定行为（`APPROVAL_WHITELIST` 为空时的 reaction 处理），与 `veil-audit-policy-enforcement` 的 `POL-5` 决策同源（交叉引用）
  - 验证：`cargo test -p veil --lib matrix::approval` 全绿含新用例；命中/未命中/重复既有用例（`:344/:446/:494/:635`）无回退
  - 验证：`grep -n "POL-5\|空白名单" openspec/changes/veil-docs-test-parity/tasks.md` 记录交叉依赖
- [x] 7.3 `TST-7`：补「请求期动态映射（`detector`/`Scope` 实时生成的 `__PII_*__`）进审计记录/摘要 → 零明文」用例（复用 `audit_summary_zero_plaintext` 断言形态，输入来自动态映射）
  - 验证：`cargo test -p veil audit_dynamic_pii_zero_plaintext`（新增名）通过；断言审计记录不含动态明文
  - 验证：`cargo test -p veil --lib audit::log` 全绿含既有静态零明文用例
- [x] 7.4 `TST-8`：`src/service/metrics/summarize.rs:47 redact_summary` **实施** IPv4/身份证/卡号三项兜底脱敏（与 `sample.rs:142 sample_mask` 同口径），并为三类各补一条测试锁定（断言摘要输出不含对应明文），使实现与 README §7.10 一致
  - 验证：`cargo test -p veil redact_summary` 三项通过；摘要输出不含三类明文
  - 验证：`grep -n "ipv4\|id_card\|bank_card" src/service/metrics/summarize.rs` 命中实现；README §7.10 与最终口径一致

## 8. Anthropic 真 SDK 覆盖扩充（`TST-9`）

- [x] 8.1 `scripts/api_conformance.py` 补 3 项真 SDK 断言——`error` 事件（mock 上游 `:217-250` 增 error/overloaded 分支）、CR-only 分块（绕开 `anth_frame` 的 `\n` 拼接构造 `\r` 帧）、`thinking`（`thinking_delta`/`signature_delta`）；`tool_use` 既有覆盖（`:119-137`、`:491-530`）只回归不重写
  - 验证：`python3 scripts/api_conformance.py` 退出 0，项数由 20 增至 23（或含阻断相调整后计数）；三项新断言均通过
  - 验证：`grep -n "overloaded\|signature_delta\|\\\\r" scripts/api_conformance.py` 命中新增分支
- [x] 8.2 `tests/sentinel_sdk_replay.rs` 提升网关侧 Anthropic 断言精确度（减少单点 `body.contains`），复用既有精确范式（`:262-271`/`:342-355`/`:367-401`/`:404-433`）
  - 验证：`cargo test -p veil --test sentinel_sdk_replay` 全绿；关键断言改为结构性比对
  - 验证：`bash scripts/gate.sh` conformance 步骤通过（若纳入 gate）

## 9. 流式 approve HTTP e2e 核验（`TST-10`）

- [x] 9.1 核验 `tests/http_e2e_audit_approve.rs:155 approve_branch_keeps_stream_without_block_frame` 的 pending 建单/流不断/无阻断帧三要素仍被锁定，记录于 design D10；若发现子场景缺口（多轮 approve、超时后流收尾）再补测
  - 验证：`cargo test -p veil --test http_e2e_audit_approve approve_branch_keeps_stream_without_block_frame` 通过
  - 验证：`cargo test -p veil --test http_e2e_audit_approve`（含 `:193 stream_nonstream_verdict_parity_e2e`）全绿

## 10. 门禁与交付准备

- [x] 10.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
  - 验证：`python3 scripts/check_file_sizes.py` 退出 0（若涉及参数）
- [x] 10.2 文档与引用门禁：`python3 scripts/check_doc_paths.py` 与 `openspec validate --all --strict` 退出 0
  - 验证：两命令输出无 FAIL、0 failures
  - 验证：`grep -rn "env_parse.rs:307-310\|_llm.py:2942\|原仓无鉴权直读" README.md openspec/specs/ src/` 在非归档语料零命中
- [x] 10.3 `openspec validate veil-docs-test-parity --strict` 0 failures，`openspec status --change veil-docs-test-parity` 显示 4/4 done
  - 验证：命令输出 `is valid`
  - 验证：`openspec status --change veil-docs-test-parity --json` 各 artifact status 均完成
- [x] 10.4 README 与 canonical spec 终检（`DOC-3`/`DOC-5` 口径一致、无旧表述残留）
  - 验证：`grep -rn "7 小节\|无鉴权直读" README.md openspec/specs/` 零命中；`grep -rnE "§6[^。]*六处|六处[^。]*§6" README.md openspec/specs/` 零命中（其余「六处」为其它 canonical spec 的无关语境：`arch-docs-cleanup` 六处文档项、`review-arch-docs` 六处调用点、`hygiene-round5` 六处覆盖点，非 §6 计数）
  - 验证：`docs-contract-sync` 与 README §6 对应段落互引一致（§6 引言「十处」、共 11 小节、§6.3 非 BREAKING）；`deadcode-positional-cleanup` 的 §6 首句计数已同步为「十处」
