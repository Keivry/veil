# docs-contract-sync Design

## Context

来源：docs/OpenSpec 一致性审计的固定发现清单（D2/D3/D4/D5/D8/D9）。约束：本 change 只规划——不改 `src/`、规划期不改 README、不动 git 状态；归档与 README 修改留 apply 阶段。

规划期事实快照（2026-09-11，只读核对）：

- 活跃 change 22：19 个 `status=complete`（任务 100%）；`veil-hardening` 13/16（Go 5.1–5.3 延后，原因见其 `tasks.md:28-30`）；`veil-config-legacy-compat` 0/12；`veil-code-hygiene-closeout` no-tasks。`openspec/specs/` 11 个 canonical；`openspec/changes/archive/` 11 个已归档。
- 19 个候选 change 的 spec delta 全部为 `## ADDED Requirements`（无 MODIFIED/REMOVED），与既有 canonical 无同名冲突 → 归档无 delta 合并冲突，固定顺序只为可复现与审计。
- `openspec validate --archived` 是归档目录全局 lint（当前 11 条全绿），不接收 change 名；变更级门槛用 `openspec validate <name> --strict` + `openspec list --json` 的 `status=complete`。
- Python 原仓 HEAD 快照：`46f6ff665c869b02c154c10df431c638c2177fd9`（2026-09-07 v0.9.47），仅作规划参照，apply 时重跑锁定。

## Decisions

### 决策 1（D2）：全量归档 19 个完成 change，`veil-hardening` 保持打开

**决策**：冻结 19 名归档名单（快照），以 `rust-rewrite-veil` 优先、其余按创建时序为固定顺序，逐个前置校验后 `openspec archive <name> --yes`；`veil-hardening` 与 2026-09-11 后新建的进行中 change 明确排除。

**理由**：canonical 是 README「以 spec 为准」的落点；19 个 delta 全部 ADDED-only，归档即无损晋升，且能一次性消除 D3 的悬空引用主因。增量归档（只归档 README 引用到的 3 个能力）会留下 16 个已完成 change 继续陈旧，D2 的核心诉求（canonical 与 change 状态同步）不成立。

**备选**：

- 只归档被 README 引用的 change：治标不治本，canonical 继续落后，不采用。
- 全部保持 change-local、不归档：D2 维持原样、D3 只能全改措辞；canonical 永远滞后于已完成工作，不采用（见决策 2）。
- 手改 `openspec/specs/` 内容：绕过 CLI 的 delta 合并与校验，有漂移与不可追溯风险，不采用。

### 决策 2（D3）：归档晋升为主路径，change-local 显式路径为兜底

**决策**：`credential-api`/`observability-admin` 经归档晋升 canonical，README:87/160/408 引用 canonical；`admin-ratelimit-contract` 因 `veil-hardening` 保持打开，README:5/200 改为完整路径 `openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md` 并标注「未归档（5.1–5.3 完成后晋升）」。若归档因外部原因未执行，README 全部引用退回完整 change-local 路径（本 change 的 tasks 3.x 已内置该兜底判定）。

**理由**：两选项并非全仓二选一——能晋升的晋升（canonical 保鲜），不能晋升的显式路径（读者可解析）。混用但格式统一（canonical 用 spec 名、未归档用完整路径 + 标注），消除「裸名找不到」的歧义。

**备选**：

- 全部改 change-local 措辞不归档：D2 卫生问题保留，canonical 继续陈旧，不采用。
- 全部等归档后再改：`veil-hardening` 未完成期间 README:5/200 仍悬空，不采用。

### 决策 3（D5）：§6.3 去 BREAKING 化，改容量分表确认

**决策**：§6 引言由「六处」改「五处」；§6.3 标题「凭据淘汰 FIFO 改 LRU（含容量分表声明）」改为「容量分表确认（非 BREAKING）」，正文改为锁定原仓 v0.9.6 起真 LRU（`_token.py:231`、`:523-538`）与容量凭据 5000（`:102`）/PII 1000（`:141`）与本仓一致，并列 apply 时锁定的基线 commit。

**理由**：BREAKING 列表是迁移者的行动清单，等价项留在其中会制造无效迁移动作并侵蚀清单可信度（原仓与 `veil-review-arch-docs` design D9 的「五 BREAKING」口径也互相矛盾）。容量数字本身仍值得保留为迁移复核锚点，故不删除条目而是降级定性。

**备选**：

- 保留 §6.3 但补一句「实际早已是 LRU」：BREAKING 定性仍在，迁移者仍被误导，不采用。
- 删除 §6.3：容量分表锚点丢失，不采用。

### 决策 4（D8/D9）：措辞精确化与引用改名，不新增实现条目

**决策**：D8 的 §7.1 改写为双侧精确项数（原仓 7 项含 `host`，本仓 8 项 + 动态项，`host` 在 `forward_headers` 单独剥）；D9 的 README:427 由裸名 `arch-docs` 改为可解析的 `arch-docs-cleanup`（兜底为完整 `veil-arch-docs-cleanup` 路径）。

**理由**：「仅透传常用头」与「引 arch-docs」都是不可核验陈述，违背 README 唯一事实源定位；改后每个断言都有文件行号来源。

**备选**：

- 保留概述措辞：审计发现复现，不采用。

## Safe Archive Procedure（决策 1 操作程序，apply 阶段执行）

**前置条件（每个候选 change 必须同时满足）**：

1. `openspec list --json` 中该 change `status=complete`（tasks 全勾，含 `veil-hardening` 之外的 19 名名单）。
2. `openspec validate <name> --strict` 零失败。
3. `openspec validate --archived` 全绿（归档目录历史条目无漂移）。
4. 工作区干净（`git status --porcelain` 为空），保证整目录可回滚。

**执行顺序**：`rust-rewrite-veil` 固定第一（canonical 基础：`credential-api`/`llm-gateway`/`observability-admin`/`redaction`/`audit-tpm-matrix`/`protocol-compliance-fix`）；其余按 `.openspec.yaml created` 升序，缺失该字段者按 `openspec list --json` 的 `lastModified` 升序。全部 delta 为 ADDED-only，顺序不影响结果，固定顺序只为可复现。

**19 名冻结名单（快照，执行时以 `openspec list --json` 复核）**：

`rust-rewrite-veil`、`veil-conformance-fix`、`veil-keepass-real`、`veil-approval-pii-hold`、`veil-gateway-p0-fix`、`veil-gateway-protocol-fix`、`veil-test-closure-round2`、`veil-test-parity-close`、`veil-full-parity-fix`、`veil-review-remediation`、`veil-review-llm-critical`、`veil-review-llm-edge`、`veil-review-test-fill`、`veil-review-arch-docs`、`veil-arch-docs-cleanup`、`veil-arch-hygiene-round3`、`veil-review-followup-llm-fix`、`veil-review-followup-test-gap`、`veil-review-followup-arch-hygiene`。

**逐步执行**（每个 change 重复）：

1. `openspec validate <name> --strict`（失败即停，不归档）。
2. `openspec archive <name> --yes`（CLI 自动校验并把 delta 合并进 `openspec/specs/`，change 目录移入 `openspec/changes/archive/<date>-<name>/`）。
3. 复核：`openspec validate --archived` 零失败 + `ls openspec/specs/` 新增预期 canonical。

**结束条件**：`openspec list --json` 活跃列表不再包含名单内 19 个；`openspec/specs/` 含 `credential-api`、`observability-admin`、`llm-gateway`、`redaction` 等晋升能力；`veil-hardening` 仍为 `in-progress`。

**回滚**：归档是文件移动 + canon 合并，失败即 `git restore --worktree openspec/`（或 `git checkout -- openspec/`）回到归档前，再复用标准删除本次新建的 archive 子目录；不得用 `--no-validate`。

**显式排除**：`veil-hardening`（13/16，等待 5.1–5.3）；`veil-config-legacy-compat`（0/12）；`veil-code-hygiene-closeout`（no-tasks）；任何规划快照后新建且未完成的 change。

## Risks / Trade-offs

- [归档中途失败 → canon 半合并] → 每个归档独立前置校验 + 每步后 `--archived` lint + 失败整目录回滚。
- [README 引用在归档窗口悬空] → 读者找不到 spec → README 引用任务（2.x）排在归档任务（1.x）之后；未归档项一律完整 change-local 路径兜底。
- [与并行 change 同时改 README] → 互相覆盖 → proposal Impact 的边界声明 + 串行合入、后到者 rebase。
- [Python 基线 commit 漂移 → §6.3 证据失效] → apply 时重跑 `git log -1` 锁定 hash 并写入 README 脚注；规划快照 `46f6ff6` 仅作参照。
- [`veil-hardening` 长期不归档 → `admin-ratelimit-contract` 长期 change-local] → 5.1–5.3 完成后按同一程序补归档并晋升，届时 README:5/200 再改为 canonical。

## Migration Plan

1. 先归档（tasks 1.x），再对齐 README 引用（2.x），最后 D4/D5/D8/D9 文本修改（3.x–6.x）。
2. 每步独立可回滚；README 修改集中一次编辑窗口，避免与并行 change 交叠。
3. 收口：`openspec validate veil-docs-contract-sync --strict` + `python3 scripts/check_doc_paths.py` + tasks 7.3 的 grep 断言集。

## Open Questions

- 无。D3 两选项已按「归档晋升 + change-local 兜底」定案；若归档阻塞，退回全 change-local 措辞（决策 2 备选与 tasks 兜底已覆盖）。
