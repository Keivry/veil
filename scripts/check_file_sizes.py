#!/usr/bin/env python3
"""全仓单文件行数上限校验（budget rule v2，按文件类别分线）。

按文件类别施加不同红线，类别判定纯走路径（零解析、无白名单）：

- 生产文件（`src/**/*.rs` 中的非测试文件）：限 800 行；
- 测试文件（`src/**/*.rs` 中满足以下任一者）：限 1200 行：
  - 末段名为 `tests.rs`；
  - 末段名以 `_tests.rs` 结尾；
  - 任一路径段名等于 `tests`。
- 前端资产（`src/**/*.html` 与 `src/**/*.js`）：限 1600 行（静态资产按片段拆分后共享同一预算）。

分线理由：测试套件外置到同级 `tests.rs` / `tests/` 后仍计入文件总行，测试文件里
更长的编排与断言代码并不代表生产复杂度，故给出 1200 行预算；生产文件维持 800 行
以持续抑制膨胀。

任一文件总行（含测试与注释）超过其类别红线即非零退出，并列出文件、类别、行数与
红线。口径与就地 `file_len_under_800_or_split` 守卫一致。

用法：`python3 scripts/check_file_sizes.py`（仓库根目录执行，无额外依赖）。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
PROD_LIMIT = 800
TEST_LIMIT = 1200
ASSET_LIMIT = 1600
ASSET_GLOBS = ("*.html", "*.js")


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def is_test_file(path: Path) -> bool:
    """纯路径分类：末段 `tests.rs` / `*_tests.rs`，或任一路径段名为 `tests`。"""
    name = path.name
    if name == "tests.rs" or name.endswith("_tests.rs"):
        return True
    return any(part == "tests" for part in path.parts)


def budget_limit(path: Path) -> int:
    return TEST_LIMIT if is_test_file(path) else PROD_LIMIT


def class_label(path: Path) -> str:
    return "测试文件" if is_test_file(path) else "生产文件"


def main() -> int:
    rs_offenders: list[tuple[str, int, str, int]] = []
    rs_checked = 0
    for path in sorted(SRC.rglob("*.rs")):
        rs_checked += 1
        lines = line_count(path)
        limit = budget_limit(path)
        if lines > limit:
            rs_offenders.append((str(path.relative_to(ROOT)), lines, class_label(path), limit))

    asset_offenders: dict[str, list[tuple[str, int]]] = {}
    asset_checked: dict[str, int] = {}
    for pattern in ASSET_GLOBS:
        offenders: list[tuple[str, int]] = []
        checked = 0
        for path in sorted(SRC.rglob(pattern)):
            checked += 1
            lines = line_count(path)
            if lines > ASSET_LIMIT:
                offenders.append((str(path.relative_to(ROOT)), lines))
        asset_offenders[pattern] = offenders
        asset_checked[pattern] = checked

    if rs_offenders or any(asset_offenders.values()):
        if rs_offenders:
            print(
                f"FAIL: {len(rs_offenders)} 个 .rs 文件超过本类红线"
                f"（生产文件 {PROD_LIMIT} / 测试文件 {TEST_LIMIT}；共扫描 {rs_checked} 个）："
            )
            for rel, lines, label, limit in rs_offenders:
                print(f"  {rel}: {lines} 行（{label}，红线 {limit}）")
        for pattern in ASSET_GLOBS:
            offenders = asset_offenders[pattern]
            if not offenders:
                continue
            suffix = pattern.lstrip("*")
            print(
                f"FAIL: {len(offenders)} 个 {suffix} 文件超过 {ASSET_LIMIT} 行"
                f"（共扫描 {asset_checked[pattern]} 个）："
            )
            for rel, lines in offenders:
                print(f"  {rel}: {lines} 行（{suffix.upper().lstrip('.')}，红线 {ASSET_LIMIT}）")
        return 1
    print(
        f"OK: {rs_checked} 个 src/**/*.rs 文件均 ≤ 本类红线"
        f"（生产文件 {PROD_LIMIT} / 测试文件 {TEST_LIMIT}），"
        f"{asset_checked['*.html']} 个 src/**/*.html 与 "
        f"{asset_checked['*.js']} 个 src/**/*.js 文件均 ≤{ASSET_LIMIT} 行。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
