# Tasks

## 1. 脚本实现

- [x] 1.1 `scripts/check_doc_paths.py`：新增符号引用正则与解析函数（末段标识符匹配 + 门面同名目录子树回退），接入 `main()` 扫描、计数与 FAIL 列表；验证：`python3 scripts/check_doc_paths.py --self-test` 通过、全量运行 0 失败。
- [x] 1.2 归档豁免与计数：`is_archived_doc(rel)` 命中的符号引用只计数不判定，打印「归档文档符号引用 N 处未校验」；验证：全量运行输出 `归档 change 文档符号引用 199 处未校验（符号冻结快照）`。
- [x] 1.3 更新脚本模块 docstring 的校验范围声明为「路径存在性 + 行号在界 + 符号末段标识符存在性」并写明启发式与豁免口径；验证：docstring 与实现一致，零残留「仅路径存在性」旧措辞（`grep -n "SHALL NOT 校验" scripts/check_doc_paths.py` 复核改写后文本）。
- [x] 1.4 `--self-test` 扩展：缺失符号检出、门面子树放行、缺文件不重复报错等断言；验证：`--self-test` 退出码 0 且打印新增断言结论。

## 2. 负向与正向验证

- [x] 2.1 负向实测：临时向 `scripts/README.md` 注入一行 `src/error.rs::NoSuchSymbolForTest`（末段不存在），运行脚本须非零退出并打印该项；随后还原并复跑通过；验证：记录两次运行输出。<!-- doc-paths-ignore -->
- [x] 2.2 正向实测：确认 `src/service/block_inject.rs::protocol_block_frames_modeled`（canonical `architecture-cleanup` 中的引用）通过门面子树解析；验证：全量运行 0 失败且符号计数包含该处。

## 3. 文档同步

- [x] 3.1 `scripts/README.md` 的 `check_doc_paths.py` 段补「`::symbol` 末段标识符存在性校验（含门面子树回退）与归档豁免」描述；验证：grep 命中新措辞。
- [x] 3.2 `scripts/gate.sh` 第 4 步头注补「+ `::symbol` 存在性」；验证：头注与脚本能力一致、`bash scripts/gate.sh` 步骤 4 通过。

## 4. 验证与收口

- [x] 4.1 `python3 scripts/check_doc_paths.py` 全绿（新计数 > 0、FAIL 0）与 `--self-test` OK。
- [x] 4.2 `openspec validate veil-doc-symbol-anchor-guard --strict` 通过。
- [x] 4.3 `bash scripts/gate.sh` 7/7 全绿（第 6 步以 `VEIL_CONFORMANCE_PYTHON=/tmp/opencode/veil-conformance-venv/bin/python` 实跑 `共 24 项，失败 0 项`；1-5、7 步全通过，`== gate 全绿（exit 0）==`）。
- [x] 4.4 Oracle 复审已实施变更（会话 `ses_f4e90f28dffeif09wX7NEB93yk`）裁决 **PASS**（无 Blocking/Major）；5 项 Minor 已修：`symbol_refs_in_file` 补 `...` 占位符守卫（占位写法不再计入符号计数）、design 登记「注释/字符串同名标识符」假阴性、proposal/tasks 计数与证据校正、脚本 docstring 补通道计数语义说明。
- [ ] 4.5 归档本 change（delta 合并 canonical `docs-contract-sync`）并 commit & push 到 master。

## 5. 证据登记

- 全量运行（Oracle Minor 修复后复跑）：`OK: 3817 处 src/*.rs 引用、256 处 spec 引用、116 处行号引用与 200 处符号引用全部通过`（FAIL 0）；`归档 change 文档符号引用 199 处未校验（符号冻结快照）`。
- 负向实测：注入 `src/error.rs::NoSuchSymbolForTest` → `FAIL: 1 个符号引用不存在` + exit 1；还原后 exit 0、注入文本零残留。<!-- doc-paths-ignore -->
- 正向实测：`src/service/block_inject.rs::protocol_block_frames_modeled`（门面子树）解析通过。
- `--self-test` OK；`openspec validate veil-doc-symbol-anchor-guard --strict` valid。
