# scripts

- `api_conformance.py` — 8.2 真实 SDK 对照。用原仓 `.venv` python 运行：
  `/home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/api_conformance.py`
- SDK pin：`openai==3.5.0`、`anthropic==1.1.0`（与原仓 `.venv` 锁定版本一致）。
- mock 上游监听 `:0` 随机端口；veil 二进制固定 `127.0.0.1:8877`。
- `gate.sh` — 发布/CI 统一门禁（`veil-test-coverage-fill` T3）：串联
  `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、
  `check_doc_paths.py`、`check_file_sizes.py`、`api_conformance.py`；任一子步骤失败整体非零退出。
  用法：`bash scripts/gate.sh`（仓库根目录执行）。
  前置条件（第 6 步）：Python venv（默认路径同 `api_conformance.py`，可用
  `VEIL_CONFORMANCE_PYTHON=<python>` 覆盖）内含 SDK pin `openai==3.5.0`/`anthropic==1.1.0`
  与 `pykeepass`；Mock TPM 回退由 `api_conformance.py` 内建（`VEIL_ALLOW_MOCK_TPM=1`，仅开发/CI）。
  跳过语义：缺 venv/SDK 默认显式报错并非零退出；`GATE_SKIP_CONFORMANCE=1` 为显式跳过第 6 步
  并打印跳过理由（不静默）。文档口径见 README §8.5。
- `check_doc_paths.py` — 文档源码路径校验（`veil-docs-contract-fix` 1.3）：扫描 `README.md` +
  `openspec/**/*.md` + `scripts/*.md` 的 `src/...rs` 引用并断言存在，缺失即非零退出；
  勘误注内旧路径与 `<!-- doc-paths-ignore -->` 行自动跳过。门禁调用：
  `python3 scripts/check_doc_paths.py`（仓库根目录执行，无额外依赖）。
- `check_file_sizes.py` — 全仓单文件 800 行上限校验（`veil-arch-file-size-closeout` S2.1）：
  扫描 `src/**/*.rs`，任一文件总行（含测试与注释）超过 800 即非零退出并列出文件与行数，
  无白名单（全仓强制）；口径与 `hygiene-round4` 真源及就地 `file_len_under_800_or_split`
  守护单测一致。门禁调用：`python3 scripts/check_file_sizes.py`（仓库根目录执行，无额外依赖）。
