#!/usr/bin/env python3
"""文档源码路径校验（veil-docs-contract-fix 1.3）。

扫描 README.md + openspec/**/*.md + scripts/*.md 中的 `src/...rs`
引用，断言每个引用对应磁盘上真实存在的文件；缺失即非零退出。

规则：
- 先剔除 `（勘误：...）` 片段：勘误注内引用的原文旧路径是历史快照，
  不参与存在性断言。
- 含 `<!-- doc-paths-ignore -->` 的行整行跳过：用于故意举例过期路径
  的行（如本 change spec 中 stale-path 反例）。
- 只校验 `src/` 开头且以 `.rs` 结尾的引用；`::Symbol` / `:行号` 后缀自动剥离。
- 大括号展开式（如 `handler/llm/{mod,pump}.rs`）不匹配 `src/` 前缀，天然跳过。

用法：`python3 scripts/check_doc_paths.py`（仓库根目录执行）。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = [ROOT / "README.md", ROOT / "openspec", ROOT / "scripts"]

REF_RE = re.compile(r"src/[A-Za-z0-9_./-]+\.rs")
ERRATUM_RE = re.compile(r"（勘误：.*?）")
IGNORE_MARKER = "<!-- doc-paths-ignore -->"


def refs_in_file(path: Path) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        line = ERRATUM_RE.sub("", line)
        for m in REF_RE.finditer(line):
            ref = m.group(0)
            if "..." in ref:  # 占位省略写法（如 `src/...rs`），非真实引用
                continue
            out.append((lineno, ref))
    return out


def main() -> int:
    targets: list[Path] = []
    for entry in SCAN_DIRS:
        if entry.is_file() and entry.suffix == ".md":
            targets.append(entry)
        elif entry.is_dir():
            targets.extend(sorted(entry.rglob("*.md")))
    missing: list[str] = []
    checked = 0
    for path in targets:
        for lineno, ref in refs_in_file(path):
            checked += 1
            if not (ROOT / ref).is_file():
                missing.append(f"{path.relative_to(ROOT)}:{lineno}: {ref}")
    if missing:
        print(f"FAIL: {len(missing)} 个文档路径不存在（共校验 {checked} 处）：")
        for item in missing:
            print(f"  {item}")
        return 1
    print(f"OK: {checked} 处 src/*.rs 引用全部存在。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
