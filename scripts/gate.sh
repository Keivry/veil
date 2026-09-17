#!/usr/bin/env bash
# scripts/gate.sh — 发布/CI 统一门禁（veil-test-coverage-fill T3/D3）。
#
# 串联七步（任一失败整体非零退出）：
#   1) cargo fmt --check
#   2) cargo clippy --tests --all-targets -- -D warnings
#   3) cargo test
#   4) python3 scripts/check_doc_paths.py（文档路径 + `path:line` 行号范围校验（存在性 + 在界内）+
#      `文件::符号` 末段标识符存在性校验（门面模块子树回退）；归档 change 目录行号/符号免校验并按处数
#      打印），9.10；内容语义一致性由 code review 保证，脚本不校验
#   5) python3 scripts/check_file_sizes.py
#   6) scripts/api_conformance.py（真 SDK 一致性，24 项）
#   7) get/ 内 go vet ./... + go test ./...（内置 Go 客户端静态检查与单测）
#
# 前置条件（第 6 步）：
#   - Python venv：默认按仓库相对定位 `<veil 仓库>/../../Python/credential-proxy/.venv/bin/python`
#     （即原仓 Python credential-proxy venv），可用 `VEIL_CONFORMANCE_PYTHON=<python>` 覆盖。
#   - SDK pin：`openai==3.5.0`、`anthropic==1.1.0`，另需 `pykeepass`（取用相建临时库）；
#     api_conformance.py 自身断言版本 pin。
#   - Mock TPM 回退：无 TPM 硬件时脚本内建 `VEIL_ALLOW_MOCK_TPM=1` 重试（仅开发/CI，
#     生产必须接 TPM 2.0 硬件）。
#
# 前置条件（第 7 步）：
#   - Go 工具链：`go vet`/`go test` 需本机 Go 可执行文件，在 `get/` 目录内执行；
#     缺失且未显式跳过时 fail-fast 非零退出。
#   - Go 版本由 `get/go.mod`（`go 1.22`）在 `vet`/`test` 阶段强制：Go ≥1.21 的
#     `GOTOOLCHAIN=auto` 会依 `go.mod` 自动选型/下载；<1.21 时版本指令在 `vet`/`test`
#     阶段明确报错并非零退出（fail-closed）。本脚本 SHALL NOT 增加版本字符串比较
#     （会把本可成功的环境误判失败）。
#
# 跳过语义（不静默）：
#   - `GATE_SKIP_CONFORMANCE=1`：显式跳过第 6 步并在输出打印跳过理由与文档位置；
#   - `GATE_SKIP_GO=1`：显式跳过第 7 步并在输出打印跳过理由与文档位置；
#   - 缺 venv/SDK/Go 且未显式跳过：前置条件检查在长步骤前 fail-fast，打印修复指引后非零退出。
#
# 文档：README §8.5（测试口径注明）、scripts/README.md（脚本用法与 SDK pin）。

set -euo pipefail

VEIL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$VEIL_ROOT" || exit 1

CONFORMANCE_PY="${VEIL_CONFORMANCE_PYTHON:-$VEIL_ROOT/../../Python/credential-proxy/.venv/bin/python}"
SKIP_CONFORMANCE="${GATE_SKIP_CONFORMANCE:-0}"
GO_DIR="$VEIL_ROOT/get"
SKIP_GO="${GATE_SKIP_GO:-0}"

run_step() {
  local name="$1"
  shift
  echo "==> [$name] $*"
  if ! "$@"; then
    echo "!! gate 失败于步骤：$name（退出码非零）" >&2
    exit 1
  fi
  echo "✓ $name"
}

run_conformance_precheck() {
  if [ ! -x "$CONFORMANCE_PY" ]; then
    echo "!! 前置条件缺失（第 6 步 api_conformance）：未找到可执行 Python venv：$CONFORMANCE_PY" >&2
    echo "   安装 SDK pin openai==3.5.0 / anthropic==1.1.0 / pykeepass，或用" >&2
    echo "   VEIL_CONFORMANCE_PYTHON=<python> 指定；详见 README §8.5 与 scripts/README.md。" >&2
    echo "   若为有意跳过，请显式设置 GATE_SKIP_CONFORMANCE=1（会打印跳过理由）。" >&2
    exit 1
  fi
  if ! "$CONFORMANCE_PY" -c 'import openai, anthropic, pykeepass' 2>/dev/null; then
    echo "!! 前置条件缺失（第 6 步 api_conformance）：$CONFORMANCE_PY 缺 openai/anthropic/pykeepass" >&2
    echo "   SDK pin：openai==3.5.0 / anthropic==1.1.0；详见 README §8.5 与 scripts/README.md。" >&2
    echo "   若为有意跳过，请显式设置 GATE_SKIP_CONFORMANCE=1（会打印跳过理由）。" >&2
    exit 1
  fi
}

run_go_precheck() {
  if ! command -v go >/dev/null 2>&1; then
    echo "!! 前置条件缺失（第 7 步 go）：未找到 Go 工具链（go 可执行文件不在 PATH）" >&2
    echo "   安装 Go 1.22+（版本要求见 get/go.mod）后重试；详见 README §8.5 与 scripts/README.md。" >&2
    echo "   若为有意跳过，请显式设置 GATE_SKIP_GO=1（会打印跳过理由）。" >&2
    exit 1
  fi
}

run_go_checks() {
  (cd "$GO_DIR" && go vet ./... && go test ./...)
}

echo "== veil gate：$VEIL_ROOT =="
if [ "$SKIP_CONFORMANCE" = "1" ]; then
  echo "==> [6/7 conformance] 显式跳过（GATE_SKIP_CONFORMANCE=1）"
  echo "    跳过理由：真 SDK 一致性需 Python venv 与 SDK pin（openai==3.5.0/anthropic==1.1.0），"
  echo "    本环境未声明具备或有意跳过；口径与前置条件见 README §8.5 与 scripts/README.md。"
else
  run_conformance_precheck
fi
if [ "$SKIP_GO" = "1" ]; then
  echo "==> [7/7 go] 显式跳过（GATE_SKIP_GO=1）"
  echo "    跳过理由：Go 客户端 vet/test 需本机 Go 工具链（get/go.mod 要求 go 1.22），"
  echo "    本环境未声明具备或有意跳过；口径与前置条件见 README §8.5 与 scripts/README.md。"
else
  run_go_precheck
fi

run_step "1/7 fmt" cargo fmt --check
run_step "2/7 clippy" cargo clippy --tests --all-targets -- -D warnings
run_step "3/7 test" cargo test
run_step "4/7 doc-paths" python3 scripts/check_doc_paths.py
run_step "5/7 file-sizes" python3 scripts/check_file_sizes.py

if [ "$SKIP_CONFORMANCE" = "1" ]; then
  echo "==> [6/7 conformance] 已按 GATE_SKIP_CONFORMANCE=1 跳过（见上方理由）"
else
  run_step "6/7 conformance" "$CONFORMANCE_PY" scripts/api_conformance.py
fi

if [ "$SKIP_GO" = "1" ]; then
  echo "==> [7/7 go] 已按 GATE_SKIP_GO=1 跳过（见上方理由）"
else
  run_step "7/7 go" run_go_checks
fi

echo "== gate 全绿（exit 0）=="
