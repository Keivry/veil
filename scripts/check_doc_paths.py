#!/usr/bin/env python3
"""文档源码路径、行号与符号校验。

扫描 README.md + scripts/**/*.md + docs/**/*.md 中的 `src/...rs`、
`path:line`、`文件::符号` 与 README 前缀 § 章节引用，断言每个路径引用对应磁盘上真实
存在的文件、每个行号落在目标文件实际行数内、每个符号引用的末段标识符在目标文件
（或门面模块子树）内出现、每个 README 前缀 § 编号解析到工程契约载体的同编号标题；
缺失/越界/符号不存在/编号悬空即非零退出。

校验范围声明：本脚本做**结构**校验（路径存在 + `1 <= start <= end <= 行数` + 符号末段
标识符存在），SHALL NOT 校验被引行内容、符号可见性/签名或文档叙述语义；被引内容与
文档语义的一致性由 code review 保证。符号解析为启发式：目标为门面模块（`X.rs` 与
`X/` 目录并存）时在模块子树 `X/**/*.rs` 内解析，以覆盖 `pub use <子模块>::*` 重导出。
升级触发条件：若同类内容漂移再现，改为登记式语义锚点表（`(源文件, 引用原文) → 期望正则`，
仅登记关键锚点）。

规则：
- 先剔除 `（勘误：...）` 片段：勘误注内引用的原文旧路径是历史快照，
  不参与存在性断言。
- 含 `<!-- doc-paths-ignore -->` 的行整行跳过：用于故意举例过期路径
  的行（如 stale-path 反例）。
- `src/` 引用：匹配 `src/...rs`；`::Symbol` / `:行号` 后缀自动剥离（符号与行号各走
  独立通道校验，见下条；符号引用的路径部分同时计入本通道计数）。
- `文件::符号` 引用：取末段标识符在目标文件内做标识符存在性断言；目标为门面模块
  （`X.rs` 与 `X/` 并存）时回退到模块子树 `X/**/*.rs`；解析失败非零退出。
- `path:line` / `path:start-end` 引用：解析后校验行号落在目标文件实际行数内
  （`1 <= start <= end <= 文件行数`）；目标文件不存在时本通道跳过，存在性交由
  `src/*.rs` 路径通道判定（其余外部文件引用不另行判定）。越界非零退出并打印文档与行。
- 大括号展开式（如 `handler/llm/{mod,pump}.rs`）不匹配 `src/` 前缀，天然跳过。
- README 前缀 § 章节引用：词法范围仅 `README`（可带 `.md`）后接
  `§N` / `§N.M`，含 `-` / `/` / `、` 等续接的同前缀令牌（`README §6-§7` 展开校验 6 与 7；
  `README §1.3-1.4` 因第二令牌无 `§` 仅校验 1.3）；单独 `§N`（无 README 前缀，如
  `RFC 9110 §7.6.1`）不匹配。每个编号 SHALL 解析为 `docs/engineering-reference.md` 的同编号
  ATX 标题（`## N.` / `### N.M`，仅比编号令牌、不看标题文本）。勘误剥离与
  `<!-- doc-paths-ignore -->` 跳过同其他通道；载体缺失时 fail-closed 非零退出
  （禁止静默跳过）；编号悬空非零退出并列出文件、行号与引用原文。

用法：`python3 scripts/check_doc_paths.py`（仓库根目录执行）。
自测：`python3 scripts/check_doc_paths.py --self-test`（校验越界行号、缺失符号、
勘误剥离/忽略标记跳过与 README § 引用的解析/悬空/范围/载体缺失 fail-closed 可被检出）。
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = [ROOT / "README.md", ROOT / "scripts", ROOT / "docs"]

SRC_REF_RE = re.compile(r"src/[A-Za-z0-9_./-]+\.rs")
SYMBOL_REF_RE = re.compile(
    r"(src/[A-Za-z0-9_./-]+\.rs)::([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)"
)
LINE_REF_RE = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:rs|md|toml|sh|py|ya?ml|json)):(\d+)(?:-(\d+))?"
)
ERRATUM_RE = re.compile(r"（勘误：.*?）")
IGNORE_MARKER = "<!-- doc-paths-ignore -->"

# 工程契约载体：README 前缀 § 引用的编号解析目标。
ENGINEERING_REFERENCE_REL = "docs/engineering-reference.md"
# README 前缀 § 章节引用：仅匹配 README 前缀（`README`/`README.md` + § + 编号），
# 续接令牌须自带 `§`（故 `README §1.3-1.4` 只校验 `1.3`）；单独 `§N` 不匹配。
README_SECTION_REF_RE = re.compile(
    r"README(?:\.md)?\s*§\s*\d+(?:\.\d+)?"
    r"(?:\s*[-–—/~、,，]\s*§\s*\d+(?:\.\d+)?)*"
)
README_SECTION_NUM_RE = re.compile(r"§\s*(\d+(?:\.\d+)?)")
# 标题编号令牌：`## N. 标题` / `### N.M 标题`；仅比编号、不看标题文本。
HEADING_NUM_RE = re.compile(r"^#{1,6}\s+(\d+(?:\.\d+)?)(?:[.\s]|$)")


def preprocessed_lines(path: Path) -> list[tuple[int, str]]:
    """公共行预处理：`<!-- doc-paths-ignore -->` 行整行跳过，`（勘误：...）` 片段剥离。"""
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        out.append((lineno, ERRATUM_RE.sub("", line)))
    return out


def refs_in_file(path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for lineno, line in preprocessed_lines(path):
        for m in pattern.finditer(line):
            ref = m.group(0)
            if "..." in ref:  # 占位省略写法（如 `src/...rs`），非真实引用
                continue
            out.append((lineno, ref))
    return out


def line_refs_in_file(path: Path) -> list[tuple[int, str, int, int]]:
    out: list[tuple[int, str, int, int]] = []
    for lineno, line in preprocessed_lines(path):
        for m in LINE_REF_RE.finditer(line):
            start = int(m.group(2))
            end = int(m.group(3)) if m.group(3) else start
            out.append((lineno, m.group(1), start, end))
    return out


def symbol_refs_in_file(path: Path) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for lineno, line in preprocessed_lines(path):
        for m in SYMBOL_REF_RE.finditer(line):
            if "..." in m.group(1):  # 占位省略写法（如 `src/...rs::Sym`），非真实引用
                continue
            out.append((lineno, m.group(1), m.group(2)))
    return out


def readme_section_refs_in_file(path: Path) -> list[tuple[int, str, list[str]]]:
    """README 前缀 § 引用（`README §7.2`、`README.md §6-§7` 等）及编号令牌列表。

    词法范围仅限 README 前缀：单独 `§N`（如 `RFC 9110 §7.6.1`）不匹配；
    续接令牌须自带 `§`，故 `README §1.3-1.4` 仅产出编号 `1.3`。
    """
    out: list[tuple[int, str, list[str]]] = []
    for lineno, line in preprocessed_lines(path):
        for m in README_SECTION_REF_RE.finditer(line):
            citation = m.group(0)
            out.append((lineno, citation, README_SECTION_NUM_RE.findall(citation)))
    return out


def heading_numbers(path: Path) -> set[str]:
    """收集 Markdown ATX 标题的编号令牌（跳过围栏代码块；仅比编号、不看标题文本）。"""
    numbers: set[str] = set()
    in_fence = False
    fence = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence = True, marker
            elif stripped.startswith(fence):
                in_fence, fence = False, ""
            continue
        if in_fence:
            continue
        m = HEADING_NUM_RE.match(stripped)
        if m:
            numbers.add(m.group(1))
    return numbers


def check_readme_sections(targets: list[Path], base: Path) -> tuple[int, list[str], list[str], int]:
    """README 前缀 § 引用检查（扫描 + 编号解析）。

    返回 `(rc, 违规列表, fail-closed 说明列表, 校验处数)`；
    rc 非零即存在编号悬空或工程契约载体缺失（fail-closed）。
    """
    refs: list[tuple[str, int, str, list[str]]] = []
    for path in targets:
        rel = path.relative_to(base).as_posix()
        for lineno, citation, numbers in readme_section_refs_in_file(path):
            refs.append((rel, lineno, citation, numbers))
    if not refs:
        return 0, [], [], 0
    reference = base / ENGINEERING_REFERENCE_REL
    if not reference.is_file():
        return (
            1,
            [],
            [
                f"{ENGINEERING_REFERENCE_REL} 缺失，但存在 {len(refs)} 处 README § 引用"
                f"（fail-closed：禁止静默跳过，请恢复工程契约载体或移除引用）"
            ],
            len(refs),
        )
    headings = heading_numbers(reference)
    violations: list[str] = []
    for rel, lineno, citation, numbers in refs:
        for num in numbers:
            if num not in headings:
                violations.append(f"{rel}:{lineno}: {citation}（编号 {num} 无对应标题）")
    return (1 if violations else 0), violations, [], len(refs)


def symbol_exists(target_path: Path, symbol: str) -> bool:
    """末段标识符在目标文件内出现，或在门面模块子树（同名目录 `**/*.rs`）内出现。"""
    ident = symbol.split("::")[-1]
    pattern = re.compile(r"\b" + re.escape(ident) + r"\b")
    if pattern.search(target_path.read_text(encoding="utf-8")):
        return True
    module_dir = target_path.with_suffix("")
    if module_dir.is_dir():
        for sub in sorted(module_dir.rglob("*.rs")):
            if pattern.search(sub.read_text(encoding="utf-8")):
                return True
    return False


def collect_symbol_violations(
    rel: str,
    lineno: int,
    target: str,
    symbol: str,
    violations: list[str],
    base: Path = ROOT,
) -> None:
    """校验 `target::symbol` 末段标识符存在性；目标文件缺失时交由路径校验处理。"""
    target_path = base / target
    if not target_path.is_file():
        return
    if symbol_exists(target_path, symbol):
        return
    violations.append(f"{rel}:{lineno}: {target}::{symbol}")


def collect_missing(rel: str, lineno: int, ref: str, missing: list[str]) -> None:
    if (ROOT / ref).is_file():
        return
    missing.append(f"{rel}:{lineno}: {ref}")


def collect_line_violations(
    rel: str,
    lineno: int,
    target: str,
    start: int,
    end: int,
    violations: list[str],
    base: Path = ROOT,
) -> None:
    """校验 `target:start-end` 落在目标文件实际行数内；目标缺失时交由路径校验处理。"""
    target_path = base / target
    if not target_path.is_file():
        return
    total = len(target_path.read_text(encoding="utf-8").splitlines())
    if 1 <= start <= end <= total:
        return
    label = f"{rel}:{lineno}: {target}:{start}" + (f"-{end}" if end != start else "")
    violations.append(f"{label}（目标仅 {total} 行）")


def main() -> int:
    targets: list[Path] = []
    for entry in SCAN_DIRS:
        if entry.is_file() and entry.suffix == ".md":
            targets.append(entry)
        elif entry.is_dir():
            targets.extend(sorted(entry.rglob("*.md")))
    missing: list[str] = []
    line_violations: list[str] = []
    symbol_violations: list[str] = []
    src_checked = 0
    line_checked = 0
    symbol_checked = 0
    for path in targets:
        rel = path.relative_to(ROOT).as_posix()
        for lineno, ref in refs_in_file(path, SRC_REF_RE):
            src_checked += 1
            collect_missing(rel, lineno, ref, missing)
        for lineno, target, start, end in line_refs_in_file(path):
            line_checked += 1
            collect_line_violations(rel, lineno, target, start, end, line_violations)
        for lineno, target, symbol in symbol_refs_in_file(path):
            symbol_checked += 1
            collect_symbol_violations(rel, lineno, target, symbol, symbol_violations)
    (
        section_rc,
        section_violations,
        section_fail_closed,
        section_checked,
    ) = check_readme_sections(targets, ROOT)
    print(
        f"计数：src/*.rs 引用 {src_checked} 处；行号引用 {line_checked} 处；"
        f"符号引用 {symbol_checked} 处。"
    )
    print(f"README § 引用 {section_checked} 处（解析目标 {ENGINEERING_REFERENCE_REL} 标题编号）。")
    if missing or line_violations or symbol_violations or section_rc:
        if missing:
            print(f"FAIL: {len(missing)} 个文档路径不存在：")
            for item in missing:
                print(f"  {item}")
        if line_violations:
            print(f"FAIL: {len(line_violations)} 个行号引用越界：")
            for item in line_violations:
                print(f"  {item}")
        if symbol_violations:
            print(f"FAIL: {len(symbol_violations)} 个符号引用不存在：")
            for item in symbol_violations:
                print(f"  {item}")
        if section_fail_closed:
            print("FAIL: README § 引用 fail-closed：")
            for item in section_fail_closed:
                print(f"  {item}")
        if section_violations:
            print(f"FAIL: {len(section_violations)} 处 README § 引用编号无对应标题：")
            for item in section_violations:
                print(f"  {item}")
        return 1
    print(
        f"OK: {src_checked} 处 src/*.rs 引用、{line_checked} 处行号引用与 "
        f"{symbol_checked} 处符号引用全部通过。"
    )
    print(
        f"OK: {section_checked} 处 README § 引用全部解析到 "
        f"{ENGINEERING_REFERENCE_REL} 对应编号标题。"
    )
    return 0


def self_test() -> int:
    """结构校验自测：行号越界、符号存在性与 README § 引用全分支。"""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "a.rs").write_text("l1\nl2\n", encoding="utf-8")
        violations: list[str] = []
        collect_line_violations("doc.md", 1, "a.rs", 3, 3, violations, base=base)
        if len(violations) != 1:
            print("self-test FAIL：越界行号未被检出")
            return 1
        violations_ok: list[str] = []
        collect_line_violations("doc.md", 1, "a.rs", 1, 2, violations_ok, base=base)
        if violations_ok:
            print("self-test FAIL：合法行号被误报")
            return 1
        violations_rev: list[str] = []
        collect_line_violations("doc.md", 1, "a.rs", 2, 1, violations_rev, base=base)
        if len(violations_rev) != 1:
            print("self-test FAIL：逆序区间未被检出")
            return 1
        ignore_case = base / "ignore_case.md"
        ignore_case.write_text(
            "src/live.rs\nsrc/gone.rs <!-- doc-paths-ignore -->\n", encoding="utf-8"
        )
        if refs_in_file(ignore_case, SRC_REF_RE) != [(1, "src/live.rs")]:
            print("self-test FAIL：`<!-- doc-paths-ignore -->` 行未被整行跳过")
            return 1
        erratum_case = base / "erratum_case.md"
        erratum_case.write_text("src/live.rs\n（勘误：src/old.rs）\n", encoding="utf-8")
        if refs_in_file(erratum_case, SRC_REF_RE) != [(1, "src/live.rs")]:
            print("self-test FAIL：勘误注 `（勘误：…）` 内旧路径未被剥离")
            return 1
        (base / "f.rs").write_text("pub use inner_mod::*;\n", encoding="utf-8")
        (base / "f").mkdir(exist_ok=True)
        (base / "f" / "inner_mod.rs").write_text("pub fn routed() {}\n", encoding="utf-8")
        sym_direct: list[str] = []
        collect_symbol_violations("doc.md", 1, "f.rs", "inner_mod", sym_direct, base=base)
        if sym_direct:
            print("self-test FAIL：门面文件内符号被误报")
            return 1
        sym_routed: list[str] = []
        collect_symbol_violations("doc.md", 1, "f.rs", "routed", sym_routed, base=base)
        if sym_routed:
            print("self-test FAIL：门面子树符号被误报")
            return 1
        sym_missing: list[str] = []
        collect_symbol_violations("doc.md", 1, "f.rs", "missing_sym", sym_missing, base=base)
        if len(sym_missing) != 1:
            print("self-test FAIL：缺失符号未被检出")
            return 1
        sym_absent_file: list[str] = []
        collect_symbol_violations("doc.md", 1, "nope.rs", "x", sym_absent_file, base=base)
        if sym_absent_file:
            print("self-test FAIL：缺失文件应由路径通道处理，符号通道不得重复报错")
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        reference = base / "docs" / "engineering-reference.md"
        reference.parent.mkdir()
        readme = base / "README.md"
        readme.write_text(
            "README §7.2 通过；README §1.3-1.4 仅校验 §1.3；"
            "RFC 9110 §7.6.1 忽略；§1.3-1.4 忽略。\n",
            encoding="utf-8",
        )
        reference.write_text(
            "## 7. 传输与兼容声明\n\n### 7.2 usage 口径\n\n### 1.3 子节\n",
            encoding="utf-8",
        )
        targets = [readme]
        rc, violations, fail_closed, checked = check_readme_sections(targets, base)
        if rc != 0 or violations or fail_closed or checked != 2:
            print("self-test FAIL：README § 正例/忽略规则行为错误")
            return 1
        readme.write_text("README §9.9 悬空。\n", encoding="utf-8")
        rc, violations, fail_closed, checked = check_readme_sections(targets, base)
        if rc != 1 or len(violations) != 1 or "README §9.9" not in violations[0]:
            print("self-test FAIL：悬空 README § 引用未被检出")
            return 1
        reference.write_text("## 6. 行为变更\n## 7. 传输与兼容声明\n", encoding="utf-8")
        readme.write_text("README §6-§7 范围引用。\n", encoding="utf-8")
        rc, violations, fail_closed, checked = check_readme_sections(targets, base)
        if rc != 0 or violations or checked != 1:
            print("self-test FAIL：README §6-§7 范围引用未按两令牌校验")
            return 1
        reference.write_text("## 6. 行为变更\n", encoding="utf-8")
        rc, violations, fail_closed, checked = check_readme_sections(targets, base)
        if rc != 1 or len(violations) != 1:
            print("self-test FAIL：README §6-§7 中缺失的 §7 未被检出")
            return 1
        reference.unlink()
        rc, violations, fail_closed, checked = check_readme_sections(targets, base)
        if rc != 1 or violations or len(fail_closed) != 1:
            print("self-test FAIL：工程契约载体缺失未 fail-closed")
            return 1
    print(
        "self-test OK：越界/逆序行号与缺失符号可检出，合法区间与门面符号放行；"
        "勘误剥离/忽略标记跳过与 README § 引用解析/悬空/范围/载体缺失 fail-closed 正确"
    )
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
