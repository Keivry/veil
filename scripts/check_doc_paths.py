#!/usr/bin/env python3
"""文档源码/spec 路径与行号校验（veil-docs-contract-fix 1.3；veil-docs-contract-resync 3.1 扩展；
veil-audit-r2-remediation 9.10 扩展行号语义）。

扫描 README.md + openspec/**/*.md + scripts/*.md 中的 `src/...rs`、spec 路径与
`path:line` 引用，断言每个路径引用对应磁盘上真实存在的文件、每个行号落在目标文件
实际行数内；缺失/越界即非零退出。

规则：
- 先剔除 `（勘误：...）` 片段：勘误注内引用的原文旧路径是历史快照，
  不参与存在性断言。
- 含 `<!-- doc-paths-ignore -->` 的行整行跳过：用于故意举例过期路径
  的行（如 change spec 中 stale-path 反例）。
- `src/` 引用：匹配 `src/...rs`；`::Symbol` / `:行号` 后缀自动剥离。
- spec 引用：匹配 canonical `openspec/specs/<capability>/spec.md` 与
  change-local `openspec/changes/<change>/specs/<capability>/spec.md`
  两种完整路径形态，输出报告各自校验计数。
- `path:line` / `path:start-end` 引用：解析后校验行号落在目标文件实际行数内
  （`1 <= start <= end <= 文件行数`）；目标文件不存在时交由路径校验处理或按外部
  引用跳过（如原仓 `_llm.py`/`_credential.py`）。越界非零退出并打印文档与行。
- 大括号展开式（如 `handler/llm/{mod,pump}.rs`）不匹配 `src/` 前缀，天然跳过。
- PENDING_REFS：本 change apply 禁改的其他 change 目录中，规划期已登记的未来
  新建/拆分目标与未来 canonical / 历史归档路径；仅对「源文件 + 引用」精确组合
  豁免并显式打印 PENDING，未登记组合一律 FAIL。README.md 的引用永不登记，
  保证 `veil-hardening` 归档后其 change-local 引用悬空时门禁强制失败
  （veil-docs-contract-resync spec「归档迁移触发更新」）。
- PENDING_LINE_REFS：非本 change 范围（规划快照 / canonical 历史行号）的行号越界，
  按「源文件 + 目标文件」精确登记并打印 PENDING，其余越界一律 FAIL。

用法：`python3 scripts/check_doc_paths.py`（仓库根目录执行）。
自测：`python3 scripts/check_doc_paths.py --self-test`（校验越界行号可被检出）。
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = [ROOT / "README.md", ROOT / "openspec", ROOT / "scripts"]

SRC_REF_RE = re.compile(r"src/[A-Za-z0-9_./-]+\.rs")
SPEC_REF_RE = re.compile(
    r"openspec/(?:changes/[A-Za-z0-9_.-]+/specs/[A-Za-z0-9_.-]+|specs/[A-Za-z0-9_.-]+)/spec\.md"
)
LINE_REF_RE = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:rs|md|toml|sh|py|ya?ml|json)):(\d+)(?:-(\d+))?"
)
ERRATUM_RE = re.compile(r"（勘误：.*?）")
IGNORE_MARKER = "<!-- doc-paths-ignore -->"

_ARCHIVED_HISTORY = "目标 change 已归档（canonical 在位），历史记录，其他 change 目录禁改"
_ARCHIVED_HARDENING_REF = "veil-hardening 归档后其 change-local admin-ratelimit-contract spec 引用（历史/情景文本），canonical 已在位"
_ARCHIVED_SELF_REF = "2026-09-13 归档后其 change-local spec 引用（历史/情景文本），canonical 已在位"
_ARCHIVED_SELF_REF_0914 = "2026-09-14 归档后其 change-local spec 引用（历史/情景文本），canonical 已在位"
_PLANNING_TARGET = (
    "本 change 规划期目标路径（apply 后实际落点/命名为实现真相），规划快照，"
    "apply 期不改其正文，其他任务所有者负责"
)

# 已知悬空引用登记表，键为（引用所在文件相对路径，引用原文）。
# 仅登记历史/情景性悬空引用（其他 change 目录、归档 change、canonical 中的旧 change-local 路径）；打印 PENDING
# 但不算失败。其余悬空引用（含 README.md 全部引用）一律 FAIL。
PENDING_REFS: dict[tuple[str, str], str] = {
    (
        "openspec/changes/archive/2026-09-11-veil-config-legacy-compat/tasks.md",
        "openspec/changes/veil-full-parity-fix/specs/audit-parity/spec.md",
    ): _ARCHIVED_HISTORY,
    (
        "openspec/changes/archive/2026-09-11-veil-docs-contract-sync/tasks.md",
        "openspec/changes/veil-arch-docs-cleanup/specs/arch-docs-cleanup/spec.md",
    ): "归档兜底路径（canonical arch-docs-cleanup 在位）；历史记录，其他 change 目录禁改",
    (
        "openspec/changes/archive/2026-09-11-veil-docs-contract-resync/design.md",
        "openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md",
    ): _ARCHIVED_HARDENING_REF,
    (
        "openspec/changes/archive/2026-09-11-veil-docs-contract-resync/proposal.md",
        "openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md",
    ): _ARCHIVED_HARDENING_REF,
    (
        "openspec/changes/archive/2026-09-11-veil-docs-contract-resync/specs/docs-contract-resync/spec.md",
        "openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md",
    ): _ARCHIVED_HARDENING_REF,
    (
        "openspec/changes/archive/2026-09-11-veil-docs-contract-sync/design.md",
        "openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md",
    ): _ARCHIVED_HARDENING_REF,
    (
        "openspec/changes/archive/2026-09-11-veil-docs-contract-sync/tasks.md",
        "openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md",
    ): _ARCHIVED_HARDENING_REF,
    (
        "openspec/specs/docs-contract-resync/spec.md",
        "openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md",
    ): _ARCHIVED_HARDENING_REF,
    (
        "openspec/changes/archive/2026-09-13-veil-pii-parity-closeout/tasks.md",
        "openspec/changes/veil-pii-parity-closeout/specs/pii-parity-closeout/spec.md",
    ): _ARCHIVED_SELF_REF,
    (
        "openspec/changes/archive/2026-09-13-veil-reverify-fix/tasks.md",
        "openspec/changes/veil-reverify-fix/specs/reverify-fix/spec.md",
    ): _ARCHIVED_SELF_REF,
    (
        "openspec/changes/archive/2026-09-13-veil-stream-fidelity-fix/proposal.md",
        "openspec/changes/veil-stream-fidelity-fix/specs/stream-fidelity-fix/spec.md",
    ): _ARCHIVED_SELF_REF,
    (
        "openspec/changes/archive/2026-09-14-veil-audit-policy-enforcement/tasks.md",
        "openspec/changes/veil-audit-policy-enforcement/specs/audit-policy-enforcement/spec.md",
    ): _ARCHIVED_SELF_REF_0914,
    (
        "openspec/changes/archive/2026-09-14-veil-credential-auth-hardening/proposal.md",
        "openspec/changes/veil-credential-auth-hardening/specs/credential-auth-hardening/spec.md",
    ): _ARCHIVED_SELF_REF_0914,
    (
        "openspec/changes/archive/2026-09-14-veil-credential-auth-hardening/tasks.md",
        "openspec/changes/veil-credential-auth-hardening/specs/credential-auth-hardening/spec.md",
    ): _ARCHIVED_SELF_REF_0914,
    (
        "openspec/changes/archive/2026-09-14-veil-gateway-transport-fidelity/proposal.md",
        "openspec/changes/veil-gateway-transport-fidelity/specs/gateway-transport-fidelity/spec.md",
    ): _ARCHIVED_SELF_REF_0914,
    (
        "openspec/changes/archive/2026-09-14-veil-redaction-audit-coverage/proposal.md",
        "openspec/changes/veil-redaction-audit-coverage/specs/redaction-audit-coverage/spec.md",
    ): _ARCHIVED_SELF_REF_0914,
}

# 本 change（veil-audit-r2-remediation）为在途规划 artifact：其 design/spec/tasks 引用的
# 源码路径是规划期目标（apply 后以实现落点为准），apply 期不由本任务改写其正文，
# 故按「源文件 + 引用」精确登记为 PENDING（规划快照，非契约）。
_PLANNING_CHANGE = "openspec/changes/veil-audit-r2-remediation/"
_PLANNING_REFS: list[tuple[str, str]] = [
    ("design.md", "src/handler/credential/mod.rs"),
    ("design.md", "src/handler/llm/pump/event_loop.rs"),
    ("design.md", "src/handler/llm/pump/frame_feed.rs"),
    ("design.md", "src/handler/llm/pump/hold.rs"),
    ("design.md", "src/handler/llm/pump/hold/tests.rs"),
    ("design.md", "src/handler/llm/pump/terminal.rs"),
    ("design.md", "src/service/matrix/validate.rs"),
    ("design.md", "src/service/pii/rewrite.rs"),
    ("proposal.md", "src/service/registry/store.rs"),
    ("specs/architecture-cleanup/spec.md", "src/handler/llm/pump/event_loop.rs"),
    ("specs/architecture-cleanup/spec.md", "src/handler/llm/pump/frame_feed.rs"),
    ("specs/credential-flow-parity/spec.md", "src/service/registry/store.rs"),
    ("specs/go-client-interop/spec.md", "src/handler/credential/mod.rs"),
    ("tasks.md", "src/handler/credential/mod.rs"),
    ("tasks.md", "src/handler/credential/vault_ops.rs"),
    ("tasks.md", "src/handler/llm/pump/event_loop.rs"),
    ("tasks.md", "src/handler/llm/pump/frame_feed.rs"),
    ("tasks.md", "src/handler/llm/pump/hold.rs"),
    ("tasks.md", "src/handler/llm/pump/hold/tests.rs"),
    ("tasks.md", "src/handler/llm/pump/terminal.rs"),
    ("tasks.md", "src/service/block_inject/tool.rs"),
    ("tasks.md", "src/service/matrix/validate.rs"),
    ("tasks.md", "src/service/pii/emit.rs"),
    ("tasks.md", "src/service/registry/store.rs"),
]
# 2026-09-15 归档后其规划快照随 change 迁入 archive/（键须同步；规划正文不改写）。
_ARCHIVED_PLANNING_CHANGE = (
    "openspec/changes/archive/2026-09-15-veil-audit-r2-remediation/"
)
for _base in (_PLANNING_CHANGE, _ARCHIVED_PLANNING_CHANGE):
    for _file, _ref in _PLANNING_REFS:
        PENDING_REFS[(_base + _file, _ref)] = _PLANNING_TARGET

# 行号越界例外登记，键为（引用所在文件相对路径，目标文件相对路径）。
# 仅登记非本 change 范围的历史/规划快照（canonical 旧行号、在途 change 规划快照）；
# 其余越界一律 FAIL。对应文档正文不由本任务改写。
PENDING_LINE_REFS: dict[tuple[str, str], str] = {
    (
        "openspec/specs/hygiene-round5/spec.md",
        "src/registry.rs",
    ): "canonical 历史行号（registry.rs 已 façade 拆分），本 change 不改 canonical",
}

# 本 change 规划快照的行号越界（归档后随 changes 目录迁移，两种落点键均登记）。
_PLANNING_LINE_REFS: list[tuple[str, str]] = [
    ("design.md", "src/service/pii/scope.rs"),
    ("specs/nonstream-audit-align/spec.md", "src/handler/llm/mod.rs"),
    ("tasks.md", "src/service/pii/scope.rs"),
    ("tasks.md", "src/handler/llm/mod.rs"),
]
for _base in (_PLANNING_CHANGE, _ARCHIVED_PLANNING_CHANGE):
    for _file, _target in _PLANNING_LINE_REFS:
        PENDING_LINE_REFS[(_base + _file, _target)] = _PLANNING_TARGET


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


def line_refs_in_file(path: Path) -> list[tuple[int, str, int, int]]:
    out: list[tuple[int, str, int, int]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        line = ERRATUM_RE.sub("", line)
        for m in LINE_REF_RE.finditer(line):
            start = int(m.group(2))
            end = int(m.group(3)) if m.group(3) else start
            out.append((lineno, m.group(1), start, end))
    return out


def collect_missing(rel: str, lineno: int, ref: str, missing: list[str], pending: list[str]) -> None:
    if (ROOT / ref).is_file():
        return
    reason = PENDING_REFS.get((rel, ref))
    if reason:
        pending.append(f"{rel}:{lineno}: {ref}（登记：{reason}）")
    else:
        missing.append(f"{rel}:{lineno}: {ref}")


def collect_line_violations(
    rel: str,
    lineno: int,
    target: str,
    start: int,
    end: int,
    violations: list[str],
    pending: list[str],
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
    reason = PENDING_LINE_REFS.get((rel, target))
    if reason:
        pending.append(f"{label}（登记：{reason}；目标 {total} 行）")
    else:
        violations.append(f"{label}（目标仅 {total} 行）")


def main() -> int:
    targets: list[Path] = []
    for entry in SCAN_DIRS:
        if entry.is_file() and entry.suffix == ".md":
            targets.append(entry)
        elif entry.is_dir():
            targets.extend(sorted(entry.rglob("*.md")))
    missing: list[str] = []
    pending: list[str] = []
    line_violations: list[str] = []
    line_pending: list[str] = []
    src_checked = 0
    spec_checked = 0
    line_checked = 0
    for path in targets:
        rel = path.relative_to(ROOT).as_posix()
        for lineno, ref in refs_in_file(path, SRC_REF_RE):
            src_checked += 1
            collect_missing(rel, lineno, ref, missing, pending)
        for lineno, ref in refs_in_file(path, SPEC_REF_RE):
            spec_checked += 1
            collect_missing(rel, lineno, ref, missing, pending)
        for lineno, target, start, end in line_refs_in_file(path):
            line_checked += 1
            collect_line_violations(
                rel, lineno, target, start, end, line_violations, line_pending
            )
    print(
        f"计数：src/*.rs 引用 {src_checked} 处；spec 引用 {spec_checked} 处；"
        f"行号引用 {line_checked} 处"
        f"（其中登记 PENDING {len(pending) + len(line_pending)} 处："
        f"路径 {len(pending)}、行号 {len(line_pending)}）。"
    )
    for item in pending:
        print(f"PENDING: {item}")
    for item in line_pending:
        print(f"PENDING(line): {item}")
    if missing or line_violations:
        if missing:
            print(f"FAIL: {len(missing)} 个文档路径不存在：")
            for item in missing:
                print(f"  {item}")
        if line_violations:
            print(f"FAIL: {len(line_violations)} 个行号引用越界：")
            for item in line_violations:
                print(f"  {item}")
        return 1
    print(
        f"OK: {src_checked} 处 src/*.rs 引用、{spec_checked} 处 spec 引用与 "
        f"{line_checked} 处行号引用全部通过。"
    )
    return 0


def self_test() -> int:
    """行号校验自测：越界检出、合法放行（含 start-end 形态）。"""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "a.rs").write_text("l1\nl2\n", encoding="utf-8")
        violations: list[str] = []
        pending: list[str] = []
        collect_line_violations("doc.md", 1, "a.rs", 3, 3, violations, pending, base=base)
        if len(violations) != 1:
            print("self-test FAIL：越界行号未被检出")
            return 1
        violations_ok: list[str] = []
        pending_ok: list[str] = []
        collect_line_violations("doc.md", 1, "a.rs", 1, 2, violations_ok, pending_ok, base=base)
        if violations_ok:
            print("self-test FAIL：合法行号被误报")
            return 1
        violations_rev: list[str] = []
        pending_rev: list[str] = []
        collect_line_violations("doc.md", 1, "a.rs", 2, 1, violations_rev, pending_rev, base=base)
        if len(violations_rev) != 1:
            print("self-test FAIL：逆序区间未被检出")
            return 1
    print("self-test OK：越界/逆序行号可检出，合法区间放行")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
