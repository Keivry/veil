#!/usr/bin/env python3
"""文档源码/spec 路径校验（veil-docs-contract-fix 1.3；veil-docs-contract-resync 3.1 扩展）。

扫描 README.md + openspec/**/*.md + scripts/*.md 中的 `src/...rs` 与 spec 路径
引用，断言每个引用对应磁盘上真实存在的文件；缺失即非零退出。

规则：
- 先剔除 `（勘误：...）` 片段：勘误注内引用的原文旧路径是历史快照，
  不参与存在性断言。
- 含 `<!-- doc-paths-ignore -->` 的行整行跳过：用于故意举例过期路径
  的行（如 change spec 中 stale-path 反例）。
- `src/` 引用：匹配 `src/...rs`；`::Symbol` / `:行号` 后缀自动剥离。
- spec 引用：匹配 canonical `openspec/specs/<capability>/spec.md` 与
  change-local `openspec/changes/<change>/specs/<capability>/spec.md`
  两种完整路径形态，输出报告各自校验计数。
- 大括号展开式（如 `handler/llm/{mod,pump}.rs`）不匹配 `src/` 前缀，天然跳过。
- PENDING_REFS：本 change apply 禁改的其他 change 目录中，规划期已登记的未来
  新建/拆分目标与未来 canonical / 历史归档路径；仅对「源文件 + 引用」精确组合
  豁免并显式打印 PENDING，未登记组合一律 FAIL。README.md 的引用永不登记，
  保证 `veil-hardening` 归档后其 change-local 引用悬空时门禁强制失败
  （veil-docs-contract-resync spec「归档迁移触发更新」）。

用法：`python3 scripts/check_doc_paths.py`（仓库根目录执行）。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = [ROOT / "README.md", ROOT / "openspec", ROOT / "scripts"]

SRC_REF_RE = re.compile(r"src/[A-Za-z0-9_./-]+\.rs")
SPEC_REF_RE = re.compile(
    r"openspec/(?:changes/[A-Za-z0-9_.-]+/specs/[A-Za-z0-9_.-]+|specs/[A-Za-z0-9_.-]+)/spec\.md"
)
ERRATUM_RE = re.compile(r"（勘误：.*?）")
IGNORE_MARKER = "<!-- doc-paths-ignore -->"

_FUTURE_SPLIT = "未来新建/拆分目标（该 change apply 时创建），其他 change 目录禁改"
_FUTURE_CANONICAL = "未来 canonical 登记（该 change 尚未归档），归档后按 canonical 复核"
_ARCHIVED_HISTORY = "目标 change 已归档（canonical 在位），历史记录，其他 change 目录禁改"

# 已知悬空引用登记表，键为（引用所在文件相对路径，引用原文）。
# 仅登记本 change apply 禁改的其他 change 目录内的未来/历史路径；打印 PENDING
# 但不算失败。其余悬空引用（含 README.md 全部引用）一律 FAIL。
PENDING_REFS: dict[tuple[str, str], str] = {
    (
        "openspec/changes/veil-hygiene-round5/proposal.md",
        "src/registry/migrate.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-hygiene-round5/tasks.md",
        "src/registry/migrate.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-runtime-robustness/tasks.md",
        "src/registry/entry.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-runtime-robustness/tasks.md",
        "src/registry/acl.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-runtime-robustness/tasks.md",
        "src/registry/store.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-runtime-robustness/tasks.md",
        "src/registry/migrate.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-test-coverage-fill/design.md",
        "src/handler/llm/pump/decide.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-test-coverage-fill/design.md",
        "src/handler/llm/pump/spawn_tests.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-test-coverage-fill/proposal.md",
        "src/handler/llm/pump/decide.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-test-coverage-fill/proposal.md",
        "src/handler/llm/pump/spawn_tests.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-test-coverage-fill/tasks.md",
        "src/handler/llm/pump/decide.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-test-coverage-fill/tasks.md",
        "src/handler/llm/pump/spawn_tests.rs",
    ): _FUTURE_SPLIT,
    (
        "openspec/changes/veil-config-legacy-compat/tasks.md",
        "openspec/changes/veil-full-parity-fix/specs/audit-parity/spec.md",
    ): _ARCHIVED_HISTORY,
    (
        "openspec/changes/veil-docs-contract-sync/tasks.md",
        "openspec/changes/veil-arch-docs-cleanup/specs/arch-docs-cleanup/spec.md",
    ): "归档兜底路径（canonical arch-docs-cleanup 在位）；历史记录，其他 change 目录禁改",
    (
        "openspec/changes/veil-test-coverage-fill/design.md",
        "openspec/specs/test-coverage-fill/spec.md",
    ): "未来 canonical 登记（该 change 尚未归档），其他 change 目录禁改",
    (
        "openspec/changes/veil-docs-contract-resync/tasks.md",
        "openspec/specs/admin-ratelimit-contract/spec.md",
    ): _FUTURE_CANONICAL,
}


def refs_in_file(path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        line = ERRATUM_RE.sub("", line)
        for m in pattern.finditer(line):
            ref = m.group(0)
            if "..." in ref:  # 占位省略写法（如 `src/...rs`），非真实引用
                continue
            out.append((lineno, ref))
    return out


def collect_missing(rel: str, lineno: int, ref: str, missing: list[str], pending: list[str]) -> None:
    if (ROOT / ref).is_file():
        return
    reason = PENDING_REFS.get((rel, ref))
    if reason:
        pending.append(f"{rel}:{lineno}: {ref}（登记：{reason}）")
    else:
        missing.append(f"{rel}:{lineno}: {ref}")


def main() -> int:
    targets: list[Path] = []
    for entry in SCAN_DIRS:
        if entry.is_file() and entry.suffix == ".md":
            targets.append(entry)
        elif entry.is_dir():
            targets.extend(sorted(entry.rglob("*.md")))
    missing: list[str] = []
    pending: list[str] = []
    src_checked = 0
    spec_checked = 0
    for path in targets:
        rel = path.relative_to(ROOT).as_posix()
        for lineno, ref in refs_in_file(path, SRC_REF_RE):
            src_checked += 1
            collect_missing(rel, lineno, ref, missing, pending)
        for lineno, ref in refs_in_file(path, SPEC_REF_RE):
            spec_checked += 1
            collect_missing(rel, lineno, ref, missing, pending)
    print(
        f"计数：src/*.rs 引用 {src_checked} 处；spec 引用 {spec_checked} 处"
        f"（其中登记 PENDING {len(pending)} 处）。"
    )
    for item in pending:
        print(f"PENDING: {item}")
    if missing:
        print(f"FAIL: {len(missing)} 个文档路径不存在：")
        for item in missing:
            print(f"  {item}")
        return 1
    print(f"OK: {src_checked} 处 src/*.rs 引用与 {spec_checked} 处 spec 引用全部存在。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
