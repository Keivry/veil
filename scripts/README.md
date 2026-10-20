# scripts

- `api_conformance.py` — 8.2 真实 SDK 对照。用本仓 `.venv` python 运行：
  `.venv/bin/python scripts/api_conformance.py`（仓库根目录执行）
- SDK pin：`openai==3.5.0`、`anthropic==1.1.0`、`pykeepass==4.1.1.post1`（pin 见 `scripts/requirements-conformance.txt`）。
- mock 上游监听 `:0` 随机端口；veil 二进制固定 `127.0.0.1:8877`。
- `go_interop_e2e.py` — 5.1–5.3「Go 对接验证」端到端 runner，共 14 项
  （5.1 Go 直连取用全链路 4 项、5.2 三因子齐全/缺失 6 项、5.3 Go 消费阻断流终止 3 项、
  5.2 `caller_hash` 冒用 `VEILCTL_BINARY_HASH` 1 项）；失败非零退出，前置不可得显式报错不静默跳过。
  用法（仓库根目录，复用 `api_conformance.py` 设施，须含 `pykeepass`）：
  `.venv/bin/python scripts/go_interop_e2e.py`。
  Go 客户端内置本仓 `veilctl/`：
  脚本按自身位置解析 `veilctl/` 绝对路径（不依赖 cwd）并打印所用目录，执行 `make -C veilctl build`
  产出 `veilctl/veilctl-linux-amd64`，缺失时显式报错不静默跳过；本仓 `.venv` 仅作 Python 解释器。
  前置：上述 venv、Go 工具链、`cargo build --bin veil`；无 TPM 硬件时脚本内建 Mock TPM 回退
  （`VEIL_ALLOW_MOCK_TPM=1`，仅开发/CI）。
  就地依赖两项（无需外部服务）：脚本内置**本地 Matrix stub**（`whoami`/`sync`/发送三端点，
  随机回环端口）并把临时 TOML 的 `[auth].homeserver` 指过去，使转审 `202 + E_PENDING` 建单路径
  可端到端验证；另按 Go wrapper 的**真实 sha256** 预置调用方注册表（取用相须命中已启用调用方，
  未 enrolled 会转审批而非直接返凭据；注册表完整性 `sha256` 按 `BTreeMap` 键序重建）。
- `gate.sh` — 发布/CI 统一门禁：串联
  `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、
  `check_doc_paths.py`、`check_file_sizes.py`、`api_conformance.py` 与 `veilctl/` 内
  `go vet ./...`/`go test ./...` 共七步；任一子步骤失败整体非零退出。
  用法：`bash scripts/gate.sh`（仓库根目录执行）。
  前置条件（第 6 步）：Python venv（默认 `<仓库根>/.venv`，依赖 pin 见
  `scripts/requirements-conformance.txt`，可用 `VEIL_CONFORMANCE_PYTHON=<python>` 覆盖）内含
  SDK pin `openai==3.5.0`/`anthropic==1.1.0`
  与 `pykeepass`；Mock TPM 回退由 `api_conformance.py` 内建（`VEIL_ALLOW_MOCK_TPM=1`，仅开发/CI）。
  前置条件（第 7 步）：本机 Go 工具链，在 `veilctl/` 目录内执行；Go 版本由 `veilctl/go.mod`（`go 1.26`）
  在 `vet`/`test` 阶段强制（Go ≥1.21 的 `GOTOOLCHAIN=auto` 依 `go.mod` 自动选型/下载；<1.21 时
  版本指令明确报错并非零退出，fail-closed），脚本 **SHALL NOT** 增加版本字符串比较。
  跳过语义：缺 venv/SDK/Go 默认显式报错并非零退出；`GATE_SKIP_CONFORMANCE=1`（第 6 步）与
  `GATE_SKIP_GO=1`（第 7 步）为显式跳过并打印跳过理由（不静默）。文档口径见 README §8.5。
- `check_doc_paths.py` — 文档源码路径、行号与符号校验（行号范围校验为存在性 + 在界内，
  `::symbol` 校验末段标识符存在性；被引行内容、符号可见性/签名与文档语义的一致性
  由 code review 保证，脚本不校验，只做结构校验）：
  扫描 `README.md` + `scripts/**/*.md` + `docs/**/*.md` 的 `src/...rs` 路径引用并断言
  存在，解析 `path:line` / `path:start-end` 引用并校验行号落在目标文件实际行数内，另解析
  `文件::符号` 引用并校验末段标识符在目标文件或门面模块子树（`X.rs` 与 `X/` 目录并存时取 `X/**/*.rs`）
  内出现，任一缺失/越界/符号不存在即非零退出；勘误注内旧路径与 `<!-- doc-paths-ignore -->` 行自动跳过。
  `docs/**/*.md` 一并扫描：工程契约载体 `docs/engineering-reference.md`（冻结 §1–§8 编号）
  为 README 前缀 § 引用的解析目标。
  README 前缀 § 章节引用通道（词法范围仅 `README` / `README.md` 后接 `§N` / `§N.M`，含
  `-` / `/` / `、` 等续接的同前缀令牌：`README §6-§7` 展开校验 6 与 7；
  `README §7.1-7.2` 因第二令牌无 `§` 仅校验 7.1）；单独 `§N`（无 README 前缀，如
  `RFC 9110 §7.6.1`）不匹配。每个编号 SHALL 解析为 `docs/engineering-reference.md` 的同编号
  标题（`## N.` / `### N.M`，按编号令牌匹配、不看标题文本）；勘误剥离与
  `<!-- doc-paths-ignore -->` 跳过与其他通道同口径。载体缺失时
  **fail-closed** 非零退出（绝不静默跳过）；编号悬空时非零退出并列文件、行号与引用原文。
  自测：`python3 scripts/check_doc_paths.py --self-test`（临时语料断言正例/悬空/勘误剥离/
  忽略标记/范围/载体缺失 fail-closed 各分支；零依赖、不触网）。门禁调用：
  `python3 scripts/check_doc_paths.py`（仓库根目录执行，无额外依赖）。
- `check_file_sizes.py` — 全仓单文件行数上限校验（budget rule v2，按文件类别分线）：
  扫描 `src/**/*.rs` 与 `src/**/*.html`；生产文件（非测试 `.rs`）限 800 行，
  测试文件（末段 `tests.rs` / `*_tests.rs`，或任一路径段名为 `tests`）限 1200 行，
  HTML 限 1600 行；类别为纯路径判定（零解析），任一文件总行（含测试与注释）超过本类
  红线即非零退出并列出文件、类别、行数与红线，无白名单（全仓强制）；
  口径与就地 `file_len_under_800_or_split` 守护单测一致（测试套件外置到同级
  `tests.rs` / `tests/` 后给 1200 行预算，生产文件维持 800 行）。注意：
  `file_len_under_800_or_split` 为文件大小守护、非行为覆盖
  （不验证业务语义，仅防超线）。门禁调用：`python3 scripts/check_file_sizes.py`（仓库根目录执行，无额外依赖）。
