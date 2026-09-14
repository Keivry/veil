# docs-contract-sync Specification

## Purpose
把「文档-契约-仓库状态」收敛为可验证的单一事实源：README 的每个 spec 引用可解析、阈值表可追溯、环境变量表完整、重写基线陈述与上游取证一致、OpenSpec 归档卫生可核验。

## Requirements

### Requirement: 文档引用可解析且无悬空 spec 名

README SHALL 使每个 spec 引用可解析：canonical 引用 SHALL 指向 `openspec/specs/<capability>/spec.md`；指向未归档 change 的引用 SHALL 显式给出完整路径 `openspec/changes/<change>/specs/<capability>/spec.md` 并标注「未归档」；仓库 SHALL NOT 出现裸 spec 名引用（如 `arch-docs`）。

#### Scenario: canonical 引用可解析

- **WHEN** 归档把 `credential-api`/`observability-admin` 晋升为 canonical 后核对 README:87/160/408
- **THEN** 引用均可定位到 `openspec/specs/` 下实际存在的目录（`test -f openspec/specs/<capability>/spec.md` 成立）

#### Scenario: 未归档引用显式标注

- **WHEN** README 引用仍留在唯一未归档 change `veil-hardening` 的 `admin-ratelimit-contract`（README:5/200）
- **THEN** 引用为完整 change-local 路径并标注「未归档」，而非裸 spec 名

#### Scenario: 错误名引用消除

- **WHEN** 全文检索 README 的 spec 引用
- **THEN** 不再出现裸名 `arch-docs`；README:427 的 D9 互引指向 `arch-docs-cleanup`（或完整 `veil-arch-docs-cleanup` 路径）且可解析

### Requirement: 阈值表与 spec 同字且可追溯

README §4 阈值表 SHALL 与 `admin-ratelimit-contract` spec 同字；每行 SHALL 可追溯到 spec 需求与 enforcement 点；阈值变更 SHALL 在同一 change 内同步 README 与 spec，SHALL NOT 单侧漂移。

#### Scenario: 逐行同字

- **WHEN** 逐行比对 README §4 与 `admin-ratelimit-contract` spec 的限流/上限取值与超限行为
- **THEN** 通用 admin `10/min` + `429` + `Retry-After`、SSE `5/IP`、通用体 `10MB` + `413`、审计类 `8MB` ceiling 锚点逐项一致

#### Scenario: 变更同源

- **WHEN** 未来调整任一阈值
- **THEN** 同一 change 同时修改 README 与 spec（diff 同源），不出现单侧漂移

### Requirement: 环境变量表完整

二进制读取的每个环境变量 SHALL 在 README 环境变量表有可检索的行；新增读取 SHALL 同 change 补行；README:26 的「未列出的变量二进制不读取」断言 SHALL 在补录完成后为真。

#### Scenario: 隐藏开关被补录

- **WHEN** 核查 `OBSERVABILITY_DISABLE`（`src/config/env_parse.rs:426-429`、`src/router.rs:19-28`）
- **THEN** README 变量表含该行，语义为精确 `=1`（去空白）时 `/_admin*` 全 404 且与 token 有效性无关（`tests/http_e2e_admin_matrix.rs:271`）

#### Scenario: 完整性断言可复核

- **WHEN** 用 grep 从 `src/config/env_parse.rs` 提取 `get("...")` 变量名，与 README 环境变量表的反引号变量名做差集
- **THEN** 差集为空（表外无二进制读取变量）

### Requirement: 重写基线陈述经上游取证

README 相对原仓（Python `credential-proxy`）的差异陈述 SHALL 以锁定的基线 commit 取证；经核实为等价的项 SHALL NOT 列为 BREAKING；逐跳头等对照 SHALL 给出双侧精确项数与文件行号来源。

#### Scenario: 等价项不列为 BREAKING

- **WHEN** 核查凭据/PII 淘汰策略
- **THEN** README §6.3 为「容量分表确认（非 BREAKING）」并附 Python 基线 commit 与 `_token.py` 真 LRU（`:231`、`:523-538`）、容量（`:102`、`:141`）证据；§6 引言同步为「十处」BREAKING（§6 共 11 小节，§6.3 为非 BREAKING 容量分表确认）

#### Scenario: HOP 对照精确

- **WHEN** 查阅 README §7.1 原仓对照
- **THEN** 表述为「原仓显式 7 项 HOP（含 `host`，`_sse.py:16-26`）→ 本仓 8 项 + `Connection` 动态项（`hop.rs:7-16`），`host` 由 `forward_headers` 单独剥（`handler/llm/mod.rs:34-46`）」

### Requirement: OpenSpec 归档卫生

任务 100% 完成的 change SHALL 在验证通过后归档，canonical specs SHALL 反映已完成的 delta；归档 SHALL 以 tasks 全勾为前置，SHALL 以 `openspec validate --archived` 与 `openspec validate <name> --strict` 零失败为门槛；未完成 change SHALL 保持打开并登记承接项。

#### Scenario: 完成 change 已归档

- **WHEN** 归档执行后运行 `openspec list --json`
- **THEN** 冻结名单内 19 个完成 change 均移入 `openspec/changes/archive/` 且活跃列表不再包含它们；`openspec/specs/` 含全部晋升能力

#### Scenario: 归档前置校验

- **WHEN** 对任一候选 change 执行归档
- **THEN** 其 `status=complete`（tasks 全勾）且 `openspec validate <name> --strict` 零失败，`openspec validate --archived` 全绿后方执行 `openspec archive <name> --yes`

#### Scenario: 半成品保持打开

- **WHEN** `veil-hardening` 仍有 5.1–5.3 未勾
- **THEN** 该 change 保持活跃不归档，其 `admin-ratelimit-contract` 等 spec 以 change-local 路径可见
