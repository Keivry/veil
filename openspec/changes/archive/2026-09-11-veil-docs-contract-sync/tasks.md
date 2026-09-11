> 本 change 为规划交付：以下任务在 apply 阶段执行，规划期不执行归档、不改 README、不提交 commit。

## 1. D2：OpenSpec 归档（19 个完成 change 晋升 canonical，保留 veil-hardening）

- [x] 1.1 冻结归档范围：运行 `openspec list --json`，筛选 `status=complete` 且在本 change 19 名冻结名单内者（规划快照 2026-09-11：19 个）；明确排除 `veil-hardening`（13/16）、`veil-config-legacy-compat`（0/12）、`veil-code-hygiene-closeout`（no-tasks）及之后新建的进行中 change。
  验证：`openspec list --json | grep -c '"status": "complete"'` 输出 ≥19 且逐名与快照名单一致；`openspec list --json | grep -E 'veil-hardening|veil-config-legacy-compat|veil-code-hygiene-closeout'` 三项均非 complete
- [x] 1.2 全局前置 lint 与工作区冻结：`openspec validate --archived` 零失败（当前 11 条归档条目全绿）；`git status --porcelain` 为空（保证可整目录回滚）。
  验证：两条命令退出码 0；`git status --porcelain | wc -l` 输出 `0`
- [x] 1.3 按序逐个归档：`rust-rewrite-veil` 固定第一，其余按 `.openspec.yaml created` 升序（缺失者按 `openspec list --json` 的 `lastModified` 升序）；每个 change 先 `openspec validate <name> --strict` 零失败，再 `openspec archive <name> --yes`，逐步后跑 `openspec validate --archived`。
  验证：`for c in $CHANGES; do openspec validate "$c" --strict && openspec archive "$c" --yes && openspec validate --archived || exit 1; done` 退出码 0（`$CHANGES` 为 19 名冻结名单；禁止 `--no-validate`）
- [x] 1.4 归档后复核：`openspec list --json` 活跃列表不再含 19 名名单；`openspec/specs/` 新增 `credential-api`/`llm-gateway`/`observability-admin`/`redaction`/`audit-tpm-matrix`/`protocol-compliance-fix` 等 canonical；19 个 change 目录已移入 `openspec/changes/archive/`。
  验证：`for s in credential-api llm-gateway observability-admin redaction; do test -f "openspec/specs/$s/spec.md" || exit 1; done` 退出码 0；`openspec list --json | grep -c '"status": "complete"'` 输出 `0`（快照名单内完成项清零）
- [x] 1.5 保留 `veil-hardening` 打开的登记：确认 `tasks.md:28-30` 的 5.1–5.3 延后记录仍在，且 `openspec list --json` 中该 change 仍为 `in-progress`；登记「5.1–5.3 完成后按 design 安全归档程序补归档并晋升 `admin-ratelimit-contract`」。
  验证：`grep -nE '^- \[ \] 5\.[123]' openspec/changes/veil-hardening/tasks.md` 命中三行；`openspec list --json | grep -A2 '"name": "veil-hardening"'` 显示 `"status": "in-progress"`

## 2. D3：README spec 引用口径对齐（归档晋升 + change-local 兜底）

- [x] 2.1 归档完成后对齐 canonical 引用：README:87/408（`observability-admin`）、README:160（`credential-api`）保持可解析到 `openspec/specs/<capability>/spec.md`；如需改路径，全仓统一为 spec 名（canonical 场景）。
  验证：`for s in observability-admin credential-api; do test -f "openspec/specs/$s/spec.md" || exit 1; done` 退出码 0；`grep -n 'observability-admin\|credential-api' README.md` 命中行均可解析
- [x] 2.2 `veil-hardening` 引用显式化：README:5 与 README:200 的 `admin-ratelimit-contract` 改为完整路径 `openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md`，并标注「未归档（`veil-hardening` 5.1–5.3 完成后晋升）」；保留「如有出入以 spec 为准」语义。
  验证：`grep -n 'admin-ratelimit-contract' README.md` 两处均含 `openspec/changes/veil-hardening/specs/` 完整路径且带「未归档」标注，无裸名-only 引用
- [x] 2.3 悬空引用清零复核：对 README 全部 spec 引用（`credential-api`/`observability-admin`/`admin-ratelimit-contract`/`arch-docs`/`arch-docs-cleanup` 等）逐项 `test -e` 解析；归档未执行时的兜底：全部改为完整 change-local 路径。
  验证：逐行 `test -e <解析路径>` 全成立；`grep -n '`arch-docs`' README.md` 零命中

## 3. D4：README 环境变量表补 `OBSERVABILITY_DISABLE`

- [x] 3.1 README §1 环境变量全表新增行：`| 入口 | OBSERVABILITY_DISABLE | 空（启用） | 精确 =1（去空白）时 /_admin* 全 404，且与 token 有效性无关；其余值不触发；生产不推荐 |`（分组/列序与相邻行一致）。
  验证：`grep -n 'OBSERVABILITY_DISABLE' README.md` 命中表行；语义与 `src/config/env_parse.rs:426-429`、`src/router.rs:19-28`、`tests/http_e2e_admin_matrix.rs:271` 一致
- [x] 3.2 完整性断言复核：从 `src/config/env_parse.rs` 提取 `get("...")` 变量名与 README 表行做差集，确认 README:26「未列出的变量二进制不读取」为真；差集非空则同 change 补行。
  验证：`grep -ohE 'get\("[A-Z_0-9]+"\)' src/config/env_parse.rs | sort -u > /tmp/opencode/veil-env-code.txt` 与 README 表反引号变量提取结果比对，差集为空（`comm -23` 输出空）

## 4. D5：§6.3 去 BREAKING 化（容量分表确认）

- [x] 4.1 锁定 Python 重写基线：`git -C /home/keivry/项目/Python/credential-proxy log -1 --format='%H %ad %s' --date=short`，输出记入 README §6.3 脚注（规划快照 `46f6ff665c869b02c154c10df431c638c2177fd9`，2026-09-07 v0.9.47）。
  验证：命令输出与 README §6.3 脚注 hash 一致；`git -C /home/keivry/项目/Python/credential-proxy log -1 --format=%H` 非空
- [x] 4.2 改写 README §6.3：标题改「容量分表确认（非 BREAKING）」；正文改为「原仓自 v0.9.6 起凭据与 PII 均已是真 LRU（`_token.py:231`、`:523-538`），容量凭据 `MAX_TOKEN_ENTRIES=5000`（`:102`）/PII `PII_MAX_ENTRIES=1000`（`:141`）与本仓一致，非行为漂移」；§6 引言「六处」改「五处」并注明 §6.3 为基线确认。
  验证：`grep -n 'FIFO 改 LRU' README.md` 零命中；`grep -n '容量分表确认\|五处' README.md` 命中；`grep -nE 'MAX_TOKEN_ENTRIES|PII_MAX_ENTRIES|真 LRU' /home/keivry/项目/Python/credential-proxy/_token.py` 命中 `:102`/`:141`/`:231`
- [x] 4.3 迁移段复核：§6.3 迁移指引由「无配置项需改；如依赖旧 FIFO 逐出顺序请按容量重估」改为容量复核指引，不主张默认值/行为变化。
  验证：§6.3 全文无「由 FIFO 改为 LRU」「淘汰策略变更」类漂移声明；`grep -n 'FIFO' README.md` 命中仅限历史语境（或零命中）

## 5. D8：§7.1 HOP 头措辞精确化

- [x] 5.1 改写 README §7.1 原仓差异句：「原仓 Python 侧仅透传常用头」→「原仓显式剥 7 项 HOP（`host`/`transfer-encoding`/`content-length`/`content-encoding`/`connection`/`keep-alive`/`te`，`_sse.py:16-26`）；本仓为 RFC 9110 §7.6.1 全集 8 项 + `Connection` 动态项（`hop.rs:7-16`），其中 `host` 由 `forward_headers` 单独剥（`handler/llm/mod.rs:34-46`）」。
  验证：`grep -n '仅透传常用头' README.md` 零命中；`grep -n '7 项\|8 项' README.md` 命中 §7.1；`test -f` 三个来源文件均存在且 `grep -n 'HOP_HEADERS' src/service/llm_gateway/hop.rs`、`grep -n 'header::HOST' src/handler/llm/mod.rs` 命中
- [x] 5.2 与 spec 对照复核：改后文本与 `docs-contract-sync` spec「重写基线陈述经上游取证 > HOP 对照精确」场景同字；`python3 scripts/check_doc_paths.py` 通过。
  验证：`python3 scripts/check_doc_paths.py` 退出码 0；`grep -n '_sse.py:16-26\|hop.rs:7-16\|mod.rs:34-46' README.md` 命中

## 6. D9：README:427 `arch-docs` 引用改名

- [x] 6.1 归档已完成（1.x 后）：README:427「D9 互引见 `arch-docs` spec」改为「D9 互引见 `arch-docs-cleanup` spec（canonical，自 `veil-arch-docs-cleanup` 归档晋升）」；归档未完成的兜底：改为完整路径 `openspec/changes/veil-arch-docs-cleanup/specs/arch-docs-cleanup/spec.md`。
  验证：`grep -n 'arch-docs' README.md` 不再出现裸 `arch-docs`；`test -d openspec/specs/arch-docs-cleanup`（归档路径）或 `test -d openspec/changes/veil-arch-docs-cleanup`（兜底路径）成立
- [x] 6.2 交叉核对改名后语义不变：确认 `arch-docs-cleanup` spec 中与 README:427 相关的需求（README 唯一入口/与 spec 同字）仍存在，引用指向可解释。
  验证：`test -f openspec/specs/arch-docs-cleanup/spec.md`（或兜底 change 内 spec）且 `grep -n 'README' <spec 路径>` 命中相关需求

## 7. 收口门禁

- [x] 7.1 `openspec validate veil-docs-contract-sync --strict` 零失败；全部 tasks 勾选后重跑并记录。
  验证：命令输出 `0 failures`（或等价全绿）
- [x] 7.2 `python3 scripts/check_doc_paths.py` 通过（README 引用的 `src/...` 全部解析）。
  验证：退出码 0
- [x] 7.3 最终断言集（覆盖全部发现 ID）：D2 快照名单内完成项清零；D3 全部 spec 引用可解析；D4 `OBSERVABILITY_DISABLE` 表行存在；D5 无「FIFO 改 LRU」BREAKING 断言；D8 无「仅透传常用头」；D9 无裸 `arch-docs`。
  验证：`openspec list --json | grep -c '"status": "complete"'` 输出 `0`；`grep -n 'OBSERVABILITY_DISABLE' README.md` 非空；`grep -n 'FIFO 改 LRU\|仅透传常用头' README.md` 零命中；`grep -n '`arch-docs`' README.md` 零命中；7 条断言逐条记入变更记录

- [x] 7.4 canonical specs 的 `## Purpose` 补足 ≥50 字，`openspec validate --specs --strict` 57/0 全绿
  验证：`openspec validate --specs --strict` 输出 `0 failed`

> 验证记录（2026-09-11，apply 执行，只读证据）：
> - **D2**：19/19 归档成功（每步 `validate <name> --strict` → `archive --yes` → `validate --archived`，归档 lint 12→30 全绿）；活跃列表 19 名清零；canonical `openspec/specs/` 11→57（新增 46，含 `credential-api`/`llm-gateway`/`observability-admin`/`redaction`/`audit-tpm-matrix`/`protocol-compliance-fix`）；`veil-hardening` 保持 13/16 `in-progress`，5.1–5.3 未勾。
> - **D3**：README:5/202 → `openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md`（未归档标注）；:89/162/438 canonical 可解析；:320 `veil-full-parity-fix` → canonical `metrics-admin-parity`；:512 `llm-protocol-hardening` → change-local 完整路径（未归档）；裸 `arch-docs` 零命中；全部 spec 引用逐项 `test -e` 成立。
> - **D4**：README §1 新增 `OBSERVABILITY_DISABLE` 行（精确 `=1` 去空白后 `/_admin*` 全 404、与 token 有效性无关；`env_parse.rs:340`、`router.rs:20`、`tests/http_e2e_admin_matrix.rs:272`）；`get("...")` 19 名与扩展 49 名（含 `parse_*` 助手与 `env.get`）对 README 表差集均空。
> - **D5**：§6.3 改「容量分表确认（非 BREAKING）」；锁基线 `46f6ff665c869b02c154c10df431c638c2177fd9`（2026-09-07 v0.9.47）；`FIFO 改 LRU`/`FIFO` 零命中；§6 引言按「七处 − §6.3 = 六处」（保留 C3 §6.7；规划文「五处」为快照偏差）。
> - **D8**：§7.1 改双侧 7/8 项 + `host` 单独剥；`仅透传常用头` 零命中；`_sse.py` 锁定 HEAD 实际块为 `:19-28`（规划文 `:16-26` 偏差，README 取实际行号）。
> - **D9**：README:464 → `arch-docs-cleanup`（canonical）；spec 内 README 唯一入口需求在位（`arch-docs-cleanup/spec.md:37`）。
> - **门禁**：`openspec validate veil-docs-contract-sync --strict` 全绿；`check_doc_paths.py` 414 处引用存在（exit 0）；`openspec validate --archived` 30/30。
> - **偏差登记**：apply 工作区含 C1–C4 未提交改动（受 no-commit 约束），1.2「工作区干净」前置以全量快照替代（`/tmp/opencode/veil-dcs/openspec-pre-archive.tar.gz`、stash `b7e1827`）；C1–C4 保持活跃 complete（4 项），待 Oracle 复核后随 C5 一并补归档。
