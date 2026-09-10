#!/usr/bin/env python3
"""全仓单文件 800 行上限校验（veil-arch-file-size-closeout S2.1）。

扫描 `src/**/*.rs`，任一文件总行（含测试与注释）超过 800 即非零退出，
并列出全部超线文件与行数；无白名单（全仓强制）。
口径与 `hygiene-round4` 真源及就地 `file_len_under_800_or_split` 守卫一致。

用法：`python3 scripts/check_file_sizes.py`（仓库根目录执行，无额外依赖）。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
LIMIT = 800


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def main() -> int:
    offenders: list[tuple[str, int]] = []
    checked = 0
    for path in sorted(SRC.rglob("*.rs")):
        checked += 1
        lines = line_count(path)
        if lines > LIMIT:
            offenders.append((str(path.relative_to(ROOT)), lines))
    if offenders:
        print(f"FAIL: {len(offenders)} 个文件超过 {LIMIT} 行（共扫描 {checked} 个）：")
        for rel, lines in offenders:
            print(f"  {rel}: {lines} 行")
        return 1
    print(f"OK: {checked} 个 src/**/*.rs 文件均 ≤{LIMIT} 行。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
