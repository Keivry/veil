## Why

独立六维审查（2026-09-14）在「文档一致 + 测试修复/补缺」维度确认 15 项偏差（`DOC-1`..`DOC-5`、`TST-1`..`TST-10`）。其中多数为**可验证的文档失真与测试假守护**：文档引用的 Python `_llm.py` 行号已偏移、Rust 源码注释指向错误位置、canonical spec 与 README 互相矛盾；测试侧存在「换 caller 仍通过」「同 PK 覆盖冒充边界删除」「常量自锁」「恒真析取」四类假绿/空断言，以及 KeePass 解锁链、审计 `on_reaction` 空白名单、动态 PII 零明文、metrics 摘要兜底、Anthropic 真 SDK 覆盖等缺口。

这些问题不会让现有测试变红，却使「文档即契约」「测试即守护」的可信度下降：读者按文档引用的行号取到的是无关代码，回归测试无法在行为回退时失败。本 change 逐项核证后固化修复口径，为 apply 阶段提供文件/符号级落点与可验证命令。

真相源为审查基准 `/tmp/opencode/audit-inventory.md` 的 `C7` 段、Rust 源码与测试、`README.md`、`openspec/specs/` 下 canonical specs，以及 Python 对照仓 `/home/keivry/项目/Python/credential-proxy`（基线 `df1b523`）。本 change 只交付规划 artifacts（proposal/design/spec/tasks），不改 `src/`、`tests/`、`README.md`、`scripts/` 与 canonical specs；实现与文档同步留待 apply 阶段。

## What Changes

- **`DOC-1` `_llm.py` 行号偏移修正**：逐处比对当前 Python 仓行号与引用语义，修正 `README.md:605`（`_llm.py:2936-2944` → `2936-2946`）与 5 处 `_llm.py:2942`（非流 502 JSON 体，实际 `2951-2961`）。`README.md:783`（`_llm.py:2633`）与 `src/config/env_parse.rs:56`（`_llm.py:139`）经核验准确，不改。
- **`DOC-2` 源码注释指针修正**：4 处注释引 `src/config/env_parse.rs:307-310`（该处实为 `load_storage` 返回值列表），实际白名单门禁在 `env_parse.rs:485-491`（`parse_whitelist` + approve 空白名单拒启动）与 `main.rs:58`（`preflight_whitelist` 显式门禁）；统一更正。
- **`DOC-3` canonical spec 矛盾修订**：`openspec/specs/behavior-changes/spec.md` 将「凭据淘汰 FIFO 改 LRU」误列 **BREAKING**（README §6.3 已修正为非 BREAKING 容量分表确认）；`openspec/specs/docs-contract-sync/spec.md` 的 Scenario 称 §6 引言「六处」/「共 7 小节」（实际「十处」/共 11 小节）。给出修订清单并重跑 `openspec validate --all --strict`。
- **`DOC-4` `src/router.rs` 补模块文档**：文件首行为 `use {`，无 `//!` 模块级文档；补与其它模块一致的 `//!` 头。
- **`DOC-5` `GET /registrations` 文档修正**：Python `_credential.py:189-191 handle_registrations` 实际调用 `self._require_auth(_request)`（`_credential.py:103-142` 校验 `GET_BINARY_HASH` + `GET_BINARY_SECRET`，未配置时兼容跳过），README §5 表与 §7.5 的「原仓无鉴权直读」失真；更正为原仓三因子鉴权、本仓管理面鉴权。
- **`TST-1` 注册闭环真守护**：`tests/http_e2e_credential.rs:119 t6_register_use_flow_200` 的闭环断言换用无关 caller（`h-flow-2`），断言恒 200 无区分度；改为同一 caller（`h-flow-1`）闭环并补「换 caller 即失败」负例。
- **`TST-2` metrics 边界删除真用例**：`src/service/metrics/store/tests.rs:411 sample_upsert_rollover` 的 `:440-447` 用同 PK 覆盖冒充边界删除；改为多 distinct PK（fresh/boundary/expired）断言「过期删、新鲜留」。
- **`TST-3` 审计常量断言改行为覆盖**：`src/service/audit/hold/tests.rs:342 timeout_disconnect_race_window_constants_locked` 仅比对常量；改送 `109/110/130/131` 边界值验证 `validate` 拒启动分支。
- **`TST-4` 恒真析取改有效断言**：`src/service/block_inject.rs:189`（`truncation_tss01_openended_no_fake_success`）`!contains("message_stop") || contains("truncated")` 恒真；改为严格断言。
- **`TST-5` 交互式 KeePass 解锁链 4 例**：补 unseal 失败→解锁失败、错口令→500、并发冷启动经 TPM provider 单开、lock 后重解锁需重解封。
- **`TST-6` 审计 `on_reaction` 矩阵补 1 例**：白名单命中/未命中/重复已有，补「空白名单」落定用例（与 `veil-audit-policy-enforcement` 的 `POL-5` 交叉引用）。
- **`TST-7` 动态 PII 零明文锁定**：补「请求期动态映射（`__PII_*__`）进审计记录」的零明文不变量用例。
- **`TST-8` metrics 摘要兜底**：`src/service/metrics/summarize.rs:47 redact_summary` 实施 ipv4/id_card/bank_card 三项兜底脱敏并逐类补测试，使实现与 README §7.10 一致。
- **`TST-9` Anthropic 真 SDK 覆盖扩充**：`scripts/api_conformance.py` 补 `error` / CR-only / `thinking` 三项真 SDK 断言（`tool_use` 已覆盖），并提升 `tests/sentinel_sdk_replay.rs` 网关侧断言的精确度。
- **`TST-10` 流式 approve HTTP e2e 核验**：既有 `tests/http_e2e_audit_approve.rs:155` 已覆盖 pending 建单/流不断/无阻断帧三要素；本 change 仅核验闭环，若发现子场景缺口再补。

## Capabilities

### New Capabilities

- `docs-test-parity`：文档-契约-测试三者一致的可验证契约——文档行号引用与上游取证一致、Rust 源码注释指针准确、canonical spec 与 README 口径同源、模块文档齐备、端点文档与实现同源；测试断言有区分度（禁止假绿/常量自锁/恒真），覆盖缺口闭合（解锁链、审计 reaction、动态 PII 零明文、metrics 兜底、Anthropic 真 SDK、流式 approve e2e）。

### Modified Capabilities

- 无。`DOC-3` 涉及的 canonical spec（`behavior-changes`、`docs-contract-sync`）修订在 apply 阶段作为独立同步任务执行并在归档时落定，本 change 只给出修订清单与口径，不新增 MODIFIED delta（与 `veil-stream-fidelity-fix` 归档先例一致）。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `DOC-1` | P2 | `_llm.py` 行号逐处核验更正（`2936-2944`→`2936-2946`；5 处 `2942`→`2951-2961`）；`2633`/`139` 核验不改 | 1.1、1.2 |
| `DOC-2` | P2 | 4 处注释指针 `env_parse.rs:307-310` → `485-491`（+ `main.rs:58` 显式门禁） | 2.1、2.2 |
| `DOC-3` | P2 | `behavior-changes` spec 去 FIFO→LRU BREAKING 误标；`docs-contract-sync:62` 「六处」→「十处」、「7 小节」→「11 小节」；重跑 validate | 3.1、3.2 |
| `DOC-4` | P3 | `src/router.rs` 补 `//!` 模块文档 | 4.1 |
| `DOC-5` | P2 | README §5 表与 §7.5 更正 `GET /registrations` 原仓鉴权口径（原仓有三因子鉴权，非无鉴权直读） | 5.1、5.2 |
| `TST-1` | P2 | 注册闭环同一 caller + 负例，消除假绿 | 6.1 |
| `TST-2` | P2 | metrics 边界删除多 PK 用例替代同 PK 覆盖 | 6.2 |
| `TST-3` | P2 | 审计竞态常量改送边界值验证拒启动分支 | 6.3 |
| `TST-4` | P2 | 恒真析取改严格断言 | 6.4 |
| `TST-5` | P2 | 交互式 KeePass 解锁链补 4 例 | 7.1 |
| `TST-6` | P2 | `on_reaction` 空白名单补 1 例（交叉 `POL-5`） | 7.2 |
| `TST-7` | P2 | 动态 PII 映射零明文补锁定用例 | 7.3 |
| `TST-8` | P2 | metrics 摘要 ipv4/id_card/bank_card 兜底 + 测试 | 7.4 |
| `TST-9` | P1 | `api_conformance.py` 补 error/CR-only/thinking 3 项真 SDK；提升 sentinel 断言强度 | 8.1、8.2 |
| `TST-10` | P2 | 流式 approve HTTP e2e 核验（既有 `http_e2e_audit_approve.rs:155` 已覆盖），缺口则补 | 9.1 |

## Non-Goals（显式）

- **规划-only**：本 change 只交付 `openspec/changes/veil-docs-test-parity/` 下四个 artifacts；不改 `src/`、`tests/`、`README.md`、`scripts/`，不改其它 change 目录，不提交 commit。实现与文档同步留待 apply 阶段。
- **Python 原仓空断言不在本仓实施**：Python 仓 `llm_test.py` 约 30 处 `assert True` 属**外部仓**测试质量问题，审计已记录；本 change 仅登记，实施落点归 Python 仓，不在 veil 内交付。
- **不改行为契约本身**：`TST-8` 实施 `redact_summary` 兜底脱敏，只补「防泄漏兜底」这一最小面，不改脱敏 recognizer 集合、采样策略、审计 verdict 判定口径。
- **不改冻结归档**：`openspec/changes/archive/**` 内的历史引用（含 `_llm.py:1948-1969`、`2936-2944` 等）为冻结语料，不回溯修改。

## Impact

- **新增文件**：`openspec/changes/veil-docs-test-parity/proposal.md`、`design.md`、`specs/docs-test-parity/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`README.md` §5/§6/§7.5、`openspec/specs/behavior-changes/spec.md`、`openspec/specs/docs-contract-sync/spec.md`、`src/router.rs`、`src/config/env_parse.rs` 相关注释、`src/service/audit/{verdict.rs,audit.rs,hold/tests.rs}`、`src/handler/llm/nonstream.rs`、`src/service/block_inject.rs`、`src/service/metrics/store/tests.rs`、`src/service/metrics/summarize.rs`、`src/service/matrix/approval.rs`、`src/service/audit/log.rs` 相关测试、`tests/http_e2e_credential.rs`、`tests/sentinel_sdk_replay.rs`、`scripts/api_conformance.py`。
- **影响系统**：文档可信度（引用可核验）、canonical spec 与 README 同源、测试守护有效性（假绿消除）、关键路径覆盖（解锁链/审计/metrics/协议 SDK）。
- **依赖**：无新依赖；仅既有 cargo/pytest/pytest 脚本与 `openspec` CLI。
