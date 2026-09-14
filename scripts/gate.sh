#!/usr/bin/env bash
# scripts/gate.sh — 发布/CI 统一门禁（veil-test-coverage-fill T3/D3）。
#
# 串联六步（任一失败整体非零退出）：
#   1) cargo fmt --check
#   2) cargo clippy --tests --all-targets -- -D warnings
#   3) cargo test
#   4) python3 scripts/check_doc_paths.py
#   5) python3 scripts/check_file_sizes.py
#   6) scripts/api_conformance.py（真 SDK 一致性，23 项）
#
# 前置条件（第 6 步）：
#   - Python venv：默认按仓库相对定位 `<veil 仓库>/../../Python/credential-proxy/.venv/bin/python`
#     （即原仓 Python credential-proxy venv），可用 `VEIL_CONFORMANCE_PYTHON=<python>` 覆盖。
#   - SDK pin：`openai==3.5.0`、`anthropic==1.1.0`，另需 `pykeepass`（取用相建临时库）；
#     api_conformance.py 自身断言版本 pin。
#   - Mock TPM 回退：无 TPM 硬件时脚本内建 `VEIL_ALLOW_MOCK_TPM=1` 重试（仅开发/CI，
#     生产必须接 TPM 2.0 硬件）。
#
# 跳过语义（不静默）：
#   - `GATE_SKIP_CONFORMANCE=1`：显式跳过第 6 步并在输出打印跳过理由与文档位置；
#   - 缺 venv/SDK 且未显式跳过：前置条件检查在长步骤前 fail-fast，打印修复指引后非零退出。
#
# 文档：README §8.5（测试口径注明）、scripts/README.md（脚本用法与 SDK pin）。

set -euo pipefail

VEIL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$VEIL_ROOT" || exit 1

CONFORMANCE_PY="${VEIL_CONFORMANCE_PYTHON:-$VEIL_ROOT/../../Python/credential-proxy/.venv/bin/python}"
SKIP_CONFORMANCE="${GATE_SKIP_CONFORMANCE:-0}"

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

echo "== veil gate：$VEIL_ROOT =="
if [ "$SKIP_CONFORMANCE" = "1" ]; then
  echo "==> [6/6 conformance] 显式跳过（GATE_SKIP_CONFORMANCE=1）"
  echo "    跳过理由：真 SDK 一致性需 Python venv 与 SDK pin（openai==3.5.0/anthropic==1.1.0），"
  echo "    本环境未声明具备或有意跳过；口径与前置条件见 README §8.5 与 scripts/README.md。"
else
  run_conformance_precheck
fi

run_step "1/6 fmt" cargo fmt --check
run_step "2/6 clippy" cargo clippy --tests --all-targets -- -D warnings
run_step "3/6 test" cargo test
run_step "4/6 doc-paths" python3 scripts/check_doc_paths.py
run_step "5/6 file-sizes" python3 scripts/check_file_sizes.py

if [ "$SKIP_CONFORMANCE" = "1" ]; then
  echo "==> [6/6 conformance] 已按 GATE_SKIP_CONFORMANCE=1 跳过（见上方理由）"
else
  run_step "6/6 conformance" "$CONFORMANCE_PY" scripts/api_conformance.py
fi

echo "== gate 全绿（exit 0）=="
