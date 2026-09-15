## Context

独立六维审查（2026-09-14）在「文档一致 + 测试修复/补缺」维度确认 `DOC-1`..`DOC-5`、`TST-1`..`TST-10` 共 15 项。约束：

- 本 change 只写规划 artifacts，不改 `src/`、`tests/`、`README.md`、`scripts/` 与 canonical specs；不提交 commit。
- 行号来自审查时点，起草时逐项打开源码核验；核验结果与审查计数不一致处，以核验为准并在本 design 记录。
- 归档 `openspec/changes/archive/**` 为冻结语料，不回溯修改。

核验得到的现状证据（均已在本次起草中逐行打开确认）：

- **`DOC-1`**：全仓非归档语料的 `_llm.py:` 引用共 8 处（不含归档与其它 change 目录）：`README.md:605`（`2936-2944`）、`README.md:783`（`2633`）、`openspec/specs/runtime-parity-limits/spec.md:10`（`2942`）、`src/config/env_parse.rs:56`（`139`）、`src/handler/llm/nonstream.rs:150/444`（`2942`）、`src/handler/llm/nonstream/tests/f2.rs:24/59`（`2942`）。Python `_llm.py` 实际：`139` 为 `NONSTREAM_MAX_BYTES = int(...)`；`2633` 为 `async def _ensure_nonempty_stream(`；`2939-2944` 为 warning、`2946` 为 `metrics_ctx['status'] = 502`；`2951-2961` 为 502 JSON 体。审查称「13 处引用 11 处偏移」，核验后为 8 处引用 6 处偏移（详见 D1）。
- **`DOC-2`**：`src/config/env_parse.rs:307-310` 实为 `load_storage` 的返回值列表；白名单门禁在 `env_parse.rs:485-491`（`parse_whitelist` + `audit_mode == Approve && whitelist.is_empty()` 拒启动）与 `src/main.rs:58`（`preflight_whitelist`）。引用错处恰 4 处：`src/service/audit/verdict.rs:44`、`src/service/audit.rs:28`、`src/service/block_inject.rs:464`、`src/handler/llm/nonstream.rs:59`。
- **`DOC-3`**：`openspec/specs/behavior-changes/spec.md` 的 Requirement 文本将「凭据淘汰 FIFO 改 LRU（含 5000/1000 容量分表声明）」列为 **BREAKING**；`README.md` §6.3 已为「容量分表确认（非 BREAKING）」并附 Python 基线 commit `46f6ff665c869b02c154c10df431c638c2177fd9` 与 `_token.py:231/:523-538` 真 LRU、`:102/:141` 容量取证。`openspec/specs/docs-contract-sync/spec.md` 的「等价项不列为 BREAKING」Scenario 称 §6 引言「六处」BREAKING、§6 共 7 小节；`README.md` §6 实为「下述十处」BREAKING、共 11 小节（§6.3 非 BREAKING）。
- **`DOC-4`**：`src/router.rs:1` 为 `use {`，`grep -c '^//!' src/router.rs` = 0。
- **`DOC-5`**：Python `_credential.py:189-191 handle_registrations` 调用 `self._require_auth(_request)`；`_require_auth`（`_credential.py:103-142`）校验 `GET_BINARY_HASH` + `GET_BINARY_SECRET`，两者均未配置时兼容跳过。原仓**有**鉴权，README §5 表与 §7.5 的「原仓无鉴权直读」失真。
- **`TST-1`**：`tests/http_e2e_credential.rs:119 t6_register_use_flow_200` 注册/审批用 `/srv/flow.sh` + `h-flow-1`，闭环（`:156-167`）却用 `/srv/flow2.sh` + `h-flow-2`；`TestOpts::default()` 下 `AUTO_APPROVE=true` 使未 enrolled caller 兼容放行，故 `assert 200` 对错误 caller 亦成立（假绿）。
- **`TST-2`**：`src/service/metrics/store/tests.rs:411 sample_upsert_rollover` 的 `:440-447` 用同 `(day,upstream,kind,hash)` 的老 `last_seen` 覆盖后 purge，只证明「单行可被删空」；同文件 `:452-489 sample_retention` 才是多 PK 真边界。
- **`TST-3`**：`src/service/audit/hold/tests.rs:342 timeout_disconnect_race_window_constants_locked` 仅 `assert_eq!` 常量 110/130/90；真逻辑在 `src/config/validate.rs:230`。
- **`TST-4`**：`src/service/block_inject.rs:189`（函数 `truncation_tss01_openended_no_fake_success`，`:182`）`assert!(!joined_a.contains("message_stop") || joined_a.contains("truncated"))`；`frames.rs:40-48` 的 Anthropic 阻断帧恒含理由文案 `truncated`，故析取恒真。
- **`TST-5`**：解锁链孤立单测在 `src/keepass.rs`、`src/service/tpm.rs`，无「解封→口令→解锁」串联链 4 例。
- **`TST-6`**：`on_reaction` 命中/未命中/重复在 `src/service/matrix/approval.rs:344/:446/:494/:635` 已覆盖；空白名单落定缺口 1 例（交叉 `POL-5`）。
- **`TST-7`**：审计零明文测试（`src/service/audit/log/log_tests.rs:263` 等）均为静态样本，无动态映射输入。
- **`TST-8`**：`src/service/metrics/summarize.rs:47 redact_summary` 无 ipv4/id_card/bank_card 分支；另一引擎 `src/service/metrics/sample.rs:142 sample_mask` 有实现+测试，二者文档化分治（`summarize.rs:42-46`）。
- **`TST-9`**：`scripts/api_conformance.py` 共 20 项；Anthropic 覆盖 `tool_use`（`:119-137`、`:491-530`），缺 `error`、CR-only、`thinking` 三项。`tests/sentinel_sdk_replay.rs` 网关侧重 `body.contains`（substring），精确断言集中于解析/usage/CR 用例（`:262-271`、`:342-355`、`:367-401`、`:404-433`）。
- **`TST-10`**：`tests/http_e2e_audit_approve.rs:155 approve_branch_keeps_stream_without_block_frame` 已断言 pending 非空（`:170-173`）、无阻断帧（`:175-177`）、流不断（`:178`），`:193 stream_nonstream_verdict_parity_e2e` 补充；审查所指缺口经核验**已存在覆盖**。

## Goals / Non-Goals

**Goals：**

- 把 `DOC-1`..`DOC-5`、`TST-1`..`TST-10` 逐项落为文件/符号级修复点与可执行验证命令，使 apply 阶段可独立落地与验证。
- 用已核验的 bad→good 对照替换审查计数中的近似（`DOC-1` 8/6、`TST-9` 3 缺 1 齐、`TST-10` 已覆盖），并保留 ID 不丢。
- 消除四类假守护（假绿、同 PK 覆盖、常量自锁、恒真析取），闭合关键路径覆盖缺口。

**Non-Goals：**

- 不实施 Python 原仓 `llm_test.py` 约 30 处 `assert True`（外部仓问题，仅登记）。
- 不改脱敏 recognizer 集合、采样策略、审计 verdict 判定口径；`TST-8` 只补「摘要防泄漏兜底」最小面（见 D8）。
- 不回溯冻结归档；不改其它 change 目录；不提交 commit。

## Decisions

### D1：`DOC-1` `_llm.py` 行号核验与更正（已核验）

**决策**：按下列 bad→good 表更正（apply 阶段执行）；两处核验准确者保持原样。

| # | 位置 | 现状（bad） | 更正（good） | 核验依据 |
|:--|:-----|:-----------|:-------------|:---------|
| 1 | `README.md:605` | `_llm.py:2936-2944` | `_llm.py:2936-2946` | warning 在 `2939-2944`，`metrics_ctx['status'] = 502` 在 `2946`，原区间未覆盖状态位 |
| 2 | `openspec/specs/runtime-parity-limits/spec.md:10` | `_llm.py:2942` | `_llm.py:2951-2961` | `2942` 为 warning 参数 `NONSTREAM_MAX_BYTES,`；502 JSON 体在 `2951-2961` |
| 3 | `src/handler/llm/nonstream.rs:150` | `_llm.py:2942` | `_llm.py:2951-2961` | 同上 |
| 4 | `src/handler/llm/nonstream.rs:444` | `_llm.py:2942` | `_llm.py:2951-2961` | 同上 |
| 5 | `src/handler/llm/nonstream/tests/f2.rs:24` | `_llm.py:2942` | `_llm.py:2951-2961` | 同上 |
| 6 | `src/handler/llm/nonstream/tests/f2.rs:59` | `_llm.py:2942` | `_llm.py:2951-2961` | 同上 |
| — | `README.md:783` | `_llm.py:2633` | 保持 | `2633` 为 `async def _ensure_nonempty_stream(` |
| — | `src/config/env_parse.rs:56` | `_llm.py:139` | 保持 | `139` 为 `NONSTREAM_MAX_BYTES = int(...)` |

**理由**：引用必须可核验；`2942` 是 warning 调用内的续行参数，非 502 体构造行。审查的「13 处 / 11 处偏移」为近似计数；核验后的权威口径为非归档语料 8 处引用、6 处偏移，另有归档 change 内引用（冻结，不回溯）。

**备选**：统一把非流 502 引用改为 `_llm.py:2938-2966` 覆盖全分支——过宽且含无关 `_is_empty` 判定，不采用。

### D2：`DOC-2` 源码注释指针统一（已核验）

**决策**：将 4 处注释的 `src/config/env_parse.rs:307-310` 统一更正为 `src/config/env_parse.rs:485-491`，并在「显式门禁」语境补 `src/main.rs:58`（`preflight_whitelist`）。4 处落点：`src/service/audit/verdict.rs:44`、`src/service/audit.rs:28`、`src/service/block_inject.rs:464`、`src/handler/llm/nonstream.rs:59`。

**理由**：`307-310` 位于 `Config::from_env` 的 `load_storage` 解构，与白名单门禁无关；`485-491` 才是 `parse_whitelist` + approve 空白名单拒启动，`main.rs:58` 是显式门禁调用点（A15/D14 前移后）。

### D3：`DOC-3` canonical spec 矛盾修订（apply 阶段同步任务）

**决策**：

- `openspec/specs/behavior-changes/spec.md`：把 Requirement「脱敏默认与采样持久与淘汰策略」中「凭据淘汰 FIFO 改 LRU（含 5000/1000 容量分表声明）为 **BREAKING**：迁移 SHALL 说明容量语义」改为「非 BREAKING 容量分表确认」，并补 Python 基线 commit 与真 LRU/容量取证（与 README §6.3 同字）。
- `openspec/specs/docs-contract-sync/spec.md`：把「等价项不列为 BREAKING」Scenario 中「§6 引言同步为「六处」BREAKING（§6 共 7 小节，§6.3 为非 BREAKING 容量分表确认）」改为「十处」「共 11 小节」。
- 修订后重跑 `openspec validate --all --strict`，0 failures。

**理由**：canonical spec 是契约真源，与 README 矛盾会使「文档-契约」可验证性失效；修订属独立同步任务，不作为 MODIFIED delta（与 `veil-stream-fidelity-fix` 归档先例一致：canonical 在归档/同步阶段落定）。

**备选**：在本 change 声明 `behavior-changes`/`docs-contract-sync` 的 MODIFIED delta——会把「文档修订」混入 capability 行为变更，且归档时需人工合并，不采用。

### D4：`DOC-4` `src/router.rs` 模块文档

**决策**：在 `src/router.rs` 首部补 `//!` 模块文档，描述路由装配（凭据 API + LLM 代理 + `/_admin`）与 `observability_gate`/入口模式职责，风格对齐同层模块（如 `src/handler/llm/mod.rs`）。

**理由**：顶层模块缺 `//!` 与仓库其余模块风格不一致，降低可读性与文档完整性。

### D5：`DOC-5` `GET /registrations` 文档口径更正（已核验）

**决策**：更正 README 两处：§5「Go 客户端对接指引」表中 `GET /registrations` 行、§7.5「吊销与注册鉴权声明」bullet。口径改为：原仓 `_credential.py::handle_registrations` 经 `_require_auth` 校验 `GET_BINARY_HASH` + `GET_BINARY_SECRET`（未配置时兼容跳过）；本仓改为管理面鉴权（`X-Admin-Token` 或 `X-Get-Binary-Secret`，两者皆缺/不匹配 401）。

**理由**：Python 原仓**有**鉴权（三因子中的二进制完整性+部署密钥），README「原仓无鉴权直读」为事实错误；Go `get list` 携带部署密钥可用这一结论不变。

### D6：`TST-1`..`TST-4` 假守护修复口径

**决策**：

- `TST-1`：闭环取用改用注册/审批同一 caller（`/srv/flow.sh` + `h-flow-1`）；并补负例——用未注册 caller（或关闭 `AUTO_APPROVE` 的 opts）时闭环断言失败，使测试具备区分度。
- `TST-2`：以 `sample_retention`（`:452-489`）为范式，新建/改造用例写入 fresh/boundary/expired 三个 distinct 主键，断言 purge 后仅过期行删除。
- `TST-3`：改送 `109/110/130/131`（及 `90`）到 `src/config/validate.rs` 的校验入口，断言 `110..=130` 被拒、区间外通过；不再仅比对常量。
- `TST-4`：把恒真析取改为严格断言——对 Anthropic 阻断帧断言终端帧存在性具备区分度（如按设计期望 `assert!(joined_a.contains("message_stop"))` 或明确 `assert!(!joined_a.contains(...))`，以实际帧语义为准），避免 `|| contains("truncated")` 兜底。

**理由**：四类断言的共性是「行为回退时不失败」；修复目标是恢复区分度，不改变被测行为。

### D7：`TST-5`..`TST-7` 覆盖补缺口径

**决策**：

- `TST-5`：补 4 例——(a) TPM unseal 失败→解锁失败（不回落软件明文）；(b) 错主密码→500；(c) 并发冷启动经 `tpm_password_provider` 单开（provider 只解封一次）；(d) `lock` 后重解锁需重新解封（缓存已清零）。
- `TST-6`：补 1 例——`APPROVAL_WHITELIST` 为空时 `on_reaction` 的落定行为，与 `veil-audit-policy-enforcement` 的 `POL-5` 决策同源（若 POL-5 定为「空=不过滤」，则本用例锁定「不忽略」；若定为「空=全忽略」，则锁定忽略）。命中/未命中/重复既有用例不回退。
- `TST-7`：补「请求期动态映射（`detector`/`Scope` 实时生成的 `__PII_*__`）进审计记录/摘要 → 零明文」用例；复用既有 `audit_summary_zero_plaintext` 断言形态但输入来自动态映射。

**理由**：三处缺口均为关键安全/正确性路径，现有静态样本或孤立单测无法覆盖端到端语义。

### D8：`TST-8` metrics 摘要兜底（实现决策，已裁决）

**决策**：`src/service/metrics/summarize.rs:47 redact_summary` **实施** IPv4/身份证/卡号三项兜底脱敏分支（与 `sample.rs:142 sample_mask` 的对应分支同口径），使实现与 README §7.10 的掩码边缘与别名口径一致，并补三项测试逐类锁定。不再保留「声明不覆盖」备选。

**理由**：审计摘要面向管理面展示，三类敏感值若原样出现属明文外泄面；`summarize.rs:42-46` 的引擎分治仅为内部实现细节，不构成对外免责，故按 README §7.10 兜底实现闭环。

**备选**：退化为「文档声明摘要不覆盖三类 + 测试锁定现状」——已否决：与 README §7.10 的掩码兜底口径相悖且留下明文外泄面，不采用。

### D9：`TST-9` Anthropic 真 SDK 覆盖扩充（已核验）

**决策**：`scripts/api_conformance.py` 补 3 项真 SDK 断言：`error` 事件（mock 上游发 Anthropic `error`/`overloaded` 帧，断言 SDK 层正确解析与下游闭合）、CR-only 分块（用 `\r` 分隔的 SSE 帧回放，断言 SDK 解析）、`thinking`（`thinking_delta`/`signature_delta` 帧，断言 SDK 解析与透传）。`tool_use` 已覆盖（`:119-137`、`:491-530`），只需回归。同时提升 `tests/sentinel_sdk_replay.rs` 网关侧断言精确度（可复用既有精确范式 `:262-271`/`:342-355`/`:367-401`/`:404-433`），减少 `body.contains` 单点依赖。

**理由**：核验后缺口为 3 项（非 4 项）；`tool_use` 已有真 SDK 覆盖，登记为已齐避免重复建设。sentinel 的 substring 断言对网关 Anthropic 回放成立，但需补强以降低假绿面。

### D10：`TST-10` 流式 approve HTTP e2e 核验结论

**决策**：审查所指缺口经核验**已存在覆盖**：`tests/http_e2e_audit_approve.rs:155 approve_branch_keeps_stream_without_block_frame` 已断言 pending 建单、流不断链、无阻断帧；`:193 stream_nonstream_verdict_parity_e2e` 补 verdict 一致。本 change 的 task 为**核验闭环**：确认三要素仍被锁定、记录于 tasks；若 apply 阶段发现子场景缺口（如多轮 approve、超时后流收尾）再补测。

**理由**：不虚增重复任务；保留 ID 但如实登记为已覆盖，符合「无 ID 静默删除、需在覆盖表说明」的要求。

### D11：Python 仓空断言 Non-Goal

**决策**：Python 原仓 `llm_test.py` 约 30 处 `assert True` 属外部仓测试质量，本 change 仅登记，不在 veil 内实施。恢复/修复需 Python 仓另立任务。

## Risks / Trade-offs

- [`DOC-1` 行号后续再漂移] → 依赖人工核对非长期机制；apply 阶段以「打开行号确认语义」为验证步骤，后续可考虑在 `scripts/check_doc_paths.py` 增加 `_llm.py` 行号语义抽检（本 change 不强制）。
- [`DOC-3` canonical 修订与归档时序] → 直接改 canonical 需在归档前完成并重跑 `validate --all --strict`；若有并行 change 同时改同一 spec，需以最后落定者为准（本 change tasks 记为同步任务）。
- [`TST-1` 负例可能受 `AUTO_APPROVE` 默认值影响] → 负例需显式构造关闭自动放行的 opts，避免再次落入兼容放行而失去区分度。
- [`TST-8` 实现] → `redact_summary` 行为变化（补 IPv4/身份证/卡号三类兜底），需同步 README §7.10/注释；测试逐类锁定，避免退化为未防护而无声。
- [`TST-6` 依赖 `POL-5` 决策] → 若 `POL-5` 决策未定，本用例口径悬空；tasks 标注交叉依赖，`POL-5` 落定后再锁定。
- [`TST-9` mock 上游需支持 error/CR/thinking] → 需扩 `MockUpstream::do_POST` 分支（`:217-250`），CR-only 需绕开 `anth_frame` 的 `\n` 拼接；属测试设施扩展，不改生产路径。

## Migration Plan

1. 按 tasks 顺序落地：先文档类（`DOC-1`/`DOC-2`/`DOC-4`/`DOC-5`），再 canonical 同步（`DOC-3`），再测试修复（`TST-1`..`TST-4`），再覆盖补缺（`TST-5`..`TST-8`），再协议 SDK（`TST-9`），最后核验（`TST-10`）。
2. 文档类改动以 `python3 scripts/check_doc_paths.py` 与行号抽查验证；canonical 改动以 `openspec validate --all --strict` 验证；测试改动以对应 `cargo test` / `python3 scripts/api_conformance.py` 验证。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；文档口径更正（`DOC-5`）与 canonical 修订（`DOC-3`）为文本面变化，行为不变。

## Open Questions

- 无阻塞项。`TST-6` 口径依赖 `veil-audit-policy-enforcement` 的 `POL-5` 决策，已在 tasks 标注交叉引用；`TST-8` 已裁决为实现 IPv4/身份证/卡号三类兜底（见 D8），无开放项。
