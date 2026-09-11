## Why

docs/OpenSpec 一致性审计确认 6 项「文档/仓库状态 vs 代码/契约」漂移（D2–D5/D8/D9），全部为陈述性缺陷，无 `src/` 行为缺陷，但会误导部署者与后续 change：

- **D2（MED）OpenSpec 卫生**：审计基线时 20 个活跃 change 中 19 个任务 100% 完成却未归档（仅 `veil-hardening` 13/16，5.1–5.3 Go 端到端延后，原因已记于 `tasks.md:28-30`）；`openspec/specs/` 只有 11 个 canonical，落后于 change 内已完成的 spec delta，读者按 README「以 spec 为准」找不到 canonical。规划期快照（2026-09-11）活跃 change 增至 22（并行 change `veil-config-legacy-compat` 0/12、`veil-code-hygiene-closeout` no-tasks 不计入归档范围）。
- **D3（MED）README spec 引用悬空**：README:5/87/160/200/408 引用的 `admin-ratelimit-contract`/`observability-admin`/`credential-api` 均只在未归档 change 内，`openspec/specs/` 无同名 canonical 目录。
- **D4（LOW）README 变量表漏项**：`OBSERVABILITY_DISABLE` 被二进制读取（`src/config/env_parse.rs:426-429`、`src/router.rs:19-28`，测试 `tests/http_e2e_admin_matrix.rs:271`）却不在 README 变量表，使 README:26「未列出的变量二进制不读取」为假。
- **D5（LOW）§6.3 基线陈述错误**：称「FIFO→LRU」为 BREAKING，但 Python `_token.py` 自 v0.9.6 起凭据与 PII 均已是真 LRU（`:231`、`:523-538`），容量凭据 5000（`:102`）/PII 1000（`:141`）亦一致，不构成漂移。
- **D8（LOW）§7.1 措辞低估原仓**：称「原仓 Python 侧仅透传常用头」，实际 Python 有显式 7 项 HOP 过滤（含 `host`，`_sse.py:16-26`）。
- **D9（LOW）引用名不可解析**：README:427 引 `arch-docs`，实际 change 为 `veil-arch-docs-cleanup`（spec 目录 `arch-docs-cleanup`）。

本 change 只交付规划 artifacts：不改 `src/`、规划期不改 README、不动 git 状态；归档与文档修改留待 apply 阶段按 tasks 执行。

## What Changes

- **D2 归档 19 个完成 change（晋升 canonical）**：冻结 19 名名单与固定顺序，逐个以「tasks 全勾（`status=complete`）+ `openspec validate <name> --strict` 零失败 + `openspec validate --archived` 全绿」为前置执行 `openspec archive <name> --yes`；`veil-hardening` 保持打开；归档后复核活跃列表仅剩进行中 change。
- **D3 引用口径对齐**：归档完成后 `credential-api`/`observability-admin` 晋升 canonical，README 对应引用可解析；仍留在 `veil-hardening` 内的 `admin-ratelimit-contract` 改为完整 change-local 路径并标注「未归档」。
- **D4 §1 变量表补行**：新增 `OBSERVABILITY_DISABLE` 行，语义为精确 `=1`（去空白）时 `/_admin*` 全 404（与 token 有效性无关），其余值不触发（生产不推荐）。
- **D5 §6.3 去 BREAKING 化**：标题与正文改为「容量分表确认（非 BREAKING）」，附录锁定 Python 基线 commit 与 `_token.py` 证据；§6 引言「六处」改「五处」。
- **D8 §7.1 措辞精确化**：改为「原仓显式 7 项 HOP（含 `host`，`_sse.py:16-26`）→ 本仓 8 项 RFC 9110 §7.6.1 全集 + `Connection` 动态项（`hop.rs:7-16`），`host` 由 `forward_headers` 单独剥（`handler/llm/mod.rs:34-46`）」。
- **D9 引用改名**：README:427 裸名 `arch-docs` → `arch-docs-cleanup`（canonical 后）或完整 `veil-arch-docs-cleanup` 路径（兜底）。

## Capabilities

### New Capabilities

- `docs-contract-sync`：文档-契约-仓库状态单一事实源、spec 引用可解析、阈值表同字可追溯、环境变量表完整、重写基线陈述经上游取证、OpenSpec 归档卫生的锁定场景。

### Modified Capabilities

- 无。本 change 不新增/修改任何既有 spec 需求；D2 归档由 OpenSpec `archive` 机制将既有 change 的 delta 合并进 `openspec/specs/`，属仓库卫生操作而非需求语义变更。

## Findings 覆盖表

| ID | 严重度 | 修复要点 | 任务 |
|:---|:-------|:---------|:-----|
| D2 | MED | 19 个完成 change 按序归档晋升 canonical；逐个 tasks 全勾 + strict/archived 前置；保留 `veil-hardening` | 1.1–1.5 |
| D3 | MED | 归档后 README 引用解析到 canonical；`veil-hardening` 内引用显式 change-local 路径 | 2.1–2.3 |
| D4 | LOW | §1 变量表补 `OBSERVABILITY_DISABLE` 行（`=1` 全 404 语义） | 3.1–3.2 |
| D5 | LOW | §6.3 去 BREAKING 化（容量分表确认）+ 锁 Python 基线 commit；§6 引言六→五 | 4.1–4.3 |
| D8 | LOW | §7.1 精确为「原仓 7 项 → 本仓 8 项 + `host` 单独剥」 | 5.1–5.2 |
| D9 | LOW | README:427 `arch-docs` → `arch-docs-cleanup` 可解析引用 | 6.1–6.2 |

## Non-Goals（显式）

- 不改 `src/` 任何实现；不改 `README.md`（本 change 只规划，README 修改留 apply 阶段且仅限上表条目）。
- 不修改其他 change 目录；不手改 `openspec/specs/` 内容（D2 归档由 CLI 合并，非手写）。
- 不处理本表之外审计发现（`X1`/`F1`/`F2`/`F3`/`NEW-*` 归 `veil-config-legacy-compat` 等并行 change）。
- 不在规划阶段执行归档、不提交 commit、不动 git 状态。

## Impact

- **新增文件**：仅 `openspec/changes/veil-docs-contract-sync/` 下 proposal.md、design.md、specs/docs-contract-sync/spec.md、tasks.md、.openspec.yaml。
- **apply 阶段文件**：`README.md`（D3/D4/D5/D8/D9 条目）；`openspec/changes/<19 change>` → `openspec/changes/archive/`（CLI 移动）；`openspec/specs/`（CLI 合并 delta，新增 canonical）。
- **README 修改边界（与并行 change 互斥）**：本 change 只负责 D2–D5/D8/D9 对应的 README 行——§1 环境变量全表（含 `OBSERVABILITY_DISABLE` 行与 README:26 完整性断言）、§1 管理控制台段（README:87）、§2 语义补充（README:160）、§3/§4 阈值表与 spec 引用（README:200）、§6 引言与 §6.3、§7.1、§7.5（README:408）、README:5 与 README:427 的 spec 引用。以下四个并行 change 的 README 条目由各自承担，本 change 不重复、不覆盖：
  - `veil-config-legacy-compat`：`AUDIT_ENABLED` 变量表行、§7.4 遗留变量表、`CREDENTIAL_BLOCK_WAIT` 真值集合措辞；
  - `veil-llm-protocol-hardening`：其协议合规条目（不属本表）；
  - `veil-parity-gap-closeout`：其对等缺口条目（不属本表）；
  - `veil-code-hygiene-closeout`：其代码卫生条目（不属本表）。
  同文件冲突处理：串行合入，后到者 rebase 对齐，禁止互相覆盖；若同一行同时被两 change 修改，以先合入者立基线并在后到 change 的 tasks 中复核。
- **影响系统**：OpenSpec 仓库卫生（canonical 保鲜）、文档可信度（引用可解析）、部署可观测性（隐藏开关可见）、迁移陈述准确性。
- **依赖**：`openspec` CLI（`archive`/`validate`）、`scripts/check_doc_paths.py`、Python 原仓只读取证（`git log`、`_token.py`、`_sse.py`）。
