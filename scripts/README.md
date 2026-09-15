# scripts

- `api_conformance.py` — 8.2 真实 SDK 对照。用原仓 `.venv` python 运行：
  `/home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/api_conformance.py`
- SDK pin：`openai==3.5.0`、`anthropic==1.1.0`（与原仓 `.venv` 锁定版本一致）。
- mock 上游监听 `:0` 随机端口；veil 二进制固定 `127.0.0.1:8877`。
- `go_interop_e2e.py` — `veil-hardening` 5.1–5.3「Go 对接验证」端到端 runner，共 14 项
  （5.1 Go 直连取用全链路 4 项、5.2 三因子齐全/缺失 6 项、5.3 Go 消费阻断流终止 3 项、
  5.2 `caller_hash` 冒用 `GET_BINARY_HASH` 1 项）；失败非零退出，前置不可得显式报错不静默跳过。
  用法（仓库根目录，复用 `api_conformance.py` 设施，须含 `pykeepass`）：
  `/home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/go_interop_e2e.py`。
  Go 客户端自 `veil-audit-r2-remediation` 起内置本仓 `get/`（不再取兄弟仓 `credential-proxy/get`）：
  脚本按自身位置解析 `get/` 绝对路径（不依赖 cwd）并打印所用目录，执行 `make -C get build`
  产出 `get/get-credential-linux-amd64`，缺失时显式报错不静默跳过；兄弟仓 `.venv` 仅作 Python 解释器。
  前置：上述 venv、Go 工具链、`cargo build --bin veil`；无 TPM 硬件时脚本内建 Mock TPM 回退
  （`VEIL_ALLOW_MOCK_TPM=1`，仅开发/CI）。
- `gate.sh` — 发布/CI 统一门禁（`veil-test-coverage-fill` T3）：串联
  `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、
  `check_doc_paths.py`、`check_file_sizes.py`、`api_conformance.py` 与 `get/` 内
  `go vet ./...`/`go test ./...` 共七步；任一子步骤失败整体非零退出。
  用法：`bash scripts/gate.sh`（仓库根目录执行）。
  前置条件（第 6 步）：Python venv（默认路径同 `api_conformance.py`，可用
  `VEIL_CONFORMANCE_PYTHON=<python>` 覆盖）内含 SDK pin `openai==3.5.0`/`anthropic==1.1.0`
  与 `pykeepass`；Mock TPM 回退由 `api_conformance.py` 内建（`VEIL_ALLOW_MOCK_TPM=1`，仅开发/CI）。
  前置条件（第 7 步）：本机 Go 工具链（`get/go.mod` 要求 go 1.22），在 `get/` 目录内执行。
  跳过语义：缺 venv/SDK/Go 默认显式报错并非零退出；`GATE_SKIP_CONFORMANCE=1`（第 6 步）与
  `GATE_SKIP_GO=1`（第 7 步）为显式跳过并打印跳过理由（不静默）。文档口径见 README §8.5。
- `check_doc_paths.py` — 文档源码/spec 路径与行号校验（`veil-docs-contract-fix` 1.3；
  `veil-docs-contract-resync` 3.1 扩展 spec 引用；`veil-audit-r2-remediation` 9.10 扩展行号语义）：
  扫描 `README.md` + `openspec/**/*.md` + `scripts/*.md` 的 `src/...rs` 与 spec 完整路径引用并断言
  存在，另解析 `path:line` / `path:start-end` 引用并校验行号落在目标文件实际行数内，任一缺失/越界即非零退出；
  勘误注内旧路径与 `<!-- doc-paths-ignore -->` 行自动跳过。
  `PENDING_REFS` 例外机制：仅登记**历史/情景性悬空引用**（其他 change 目录、已归档 change、
  canonical 中的旧 change-local 路径），键为精确「源文件相对路径 + 引用原文」组合并附登记理由；
  命中即打印 `PENDING` 且**不算失败**（可复核的例外名单，脚本内 `PENDING_REFS` 即权威来源）。
  **`README.md` 的引用永不登记**：归档迁移致其悬空时必须 `FAIL`，防止静默通过；
  其余未登记组合一律 `FAIL`。门禁调用：
  `python3 scripts/check_doc_paths.py`（仓库根目录执行，无额外依赖）。
- `check_file_sizes.py` — 全仓单文件 800 行上限校验（`veil-arch-file-size-closeout` S2.1）：
  扫描 `src/**/*.rs`，任一文件总行（含测试与注释）超过 800 即非零退出并列出文件与行数，
  无白名单（全仓强制）；口径与 `hygiene-round4` 真源及就地 `file_len_under_800_or_split`
  守护单测一致。注意：`file_len_under_800_or_split` 为文件大小守护、非行为覆盖
  （不验证业务语义，仅防超线）。门禁调用：`python3 scripts/check_file_sizes.py`（仓库根目录执行，无额外依赖）。
