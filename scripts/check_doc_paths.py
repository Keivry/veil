#!/usr/bin/env python3
"""文档源码/spec 路径、行号与符号校验（veil-docs-contract-fix 1.3；veil-docs-contract-resync 3.1 扩展；
veil-audit-r2-remediation 9.10 扩展行号引用；veil-audit-r3-remediation 7.4 降级措辞为行号范围校验；
veil-doc-symbol-anchor-guard 扩展 `::symbol` 末段标识符存在性校验）。

扫描 README.md + openspec/**/*.md + scripts/*.md 中的 `src/...rs`、spec 路径、
`path:line` 与 `文件::符号` 引用，断言每个路径引用对应磁盘上真实存在的文件、每个行号
落在目标文件实际行数内、每个符号引用的末段标识符在目标文件（或门面模块子树）内出现；
缺失/越界/符号不存在即非零退出。

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
  的行（如 change spec 中 stale-path 反例）。
- `src/` 引用：匹配 `src/...rs`；`::Symbol` / `:行号` 后缀自动剥离（符号与行号各走
  独立通道校验，见下条；符号引用的路径部分同时计入本通道计数）。
- `文件::符号` 引用：取末段标识符在目标文件内做标识符存在性断言；目标为门面模块
  （`X.rs` 与 `X/` 并存）时回退到模块子树 `X/**/*.rs`；解析失败非零退出。
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
- 归档 change 目录（`openspec/changes/archive/**`）：行号是归档时刻的冻结快照，
  对现行源码做在界断言无判定意义（canonical docs-test-parity「指向冻结归档语料的
  引用 SHALL NOT 被回改」），故整体豁免行号在界断言并按处数打印
  「归档文档行号引用 N 处未校验」；其 `src/...rs` 路径存在性仍照常校验
  （悬空引用须按 PENDING_REFS 逐项登记）。`::Symbol` 引用同为冻结快照，
  整体豁免存在性断言并按处数打印「归档文档符号引用 N 处未校验」。

用法：`python3 scripts/check_doc_paths.py`（仓库根目录执行）。
自测：`python3 scripts/check_doc_paths.py --self-test`（校验越界行号与缺失符号可被检出）。
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = [ROOT / "README.md", ROOT / "openspec", ROOT / "scripts"]

SRC_REF_RE = re.compile(r"src/[A-Za-z0-9_./-]+\.rs")
SYMBOL_REF_RE = re.compile(
    r"(src/[A-Za-z0-9_./-]+\.rs)::([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)"
)
SPEC_REF_RE = re.compile(
    r"openspec/(?:changes/[A-Za-z0-9_.-]+/specs/[A-Za-z0-9_.-]+|specs/[A-Za-z0-9_.-]+)/spec\.md"
)
LINE_REF_RE = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:rs|md|toml|sh|py|ya?ml|json)):(\d+)(?:-(\d+))?"
)
ERRATUM_RE = re.compile(r"（勘误：.*?）")
IGNORE_MARKER = "<!-- doc-paths-ignore -->"

# 归档 change 目录内的文档：其 `path:line` 是归档时刻的冻结快照，行号随源码演进
# 必然漂移，对现行源码做在界断言无判定意义（canonical docs-test-parity「指向冻结
# 归档语料的引用 SHALL NOT 被回改」），故整体豁免**行号在界**断言；路径存在性仍由
# SRC_REF_RE 通道 + PENDING_REFS 逐项治理。
ARCHIVED_PREFIX = "openspec/changes/archive/"


def is_archived_doc(rel: str) -> bool:
    """归档 change 文档判定（行号冻结快照，免在界断言）。"""
    return rel.startswith(ARCHIVED_PREFIX)

_ARCHIVED_HISTORY = "目标 change 已归档（canonical 在位），历史记录，其他 change 目录禁改"
_ARCHIVED_HARDENING_REF = "veil-hardening 归档后其 change-local admin-ratelimit-contract spec 引用（历史/情景文本），canonical 已在位"
_ARCHIVED_SELF_REF = "2026-09-13 归档后其 change-local spec 引用（历史/情景文本），canonical 已在位"
_ARCHIVED_SELF_REF_0914 = "2026-09-14 归档后其 change-local spec 引用（历史/情景文本），canonical 已在位"
_ARCHIVED_SELF_REF_0916 = "2026-09-16 归档后其 change-local spec delta 引用（历史/验证串文本），canonical 已在位"
_ARCHIVED_XREF_0917 = (
    "2026-09-17 起：归档 r4 change 对后续 change veil-pii-conversation-cache 的 "
    "change-local spec delta 交叉引用（历史/验证串文本）；该后续 change 已于 2026-09-17 归档，"
    "对应 requirement 已晋升 canonical openspec/specs/llm-gateway/spec.md"
)
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
    (
        "openspec/changes/archive/2026-09-16-veil-audit-r3-remediation/tasks.md",
        "openspec/changes/veil-audit-r3-remediation/specs/llm-gateway/spec.md",
    ): _ARCHIVED_SELF_REF_0916,
    (
        "openspec/changes/archive/2026-09-16-veil-audit-r3-remediation/tasks.md",
        "openspec/changes/veil-audit-r3-remediation/specs/llm-proto-closeout/spec.md",
    ): _ARCHIVED_SELF_REF_0916,
    (
        "openspec/changes/archive/2026-09-16-veil-audit-r3-remediation/tasks.md",
        "openspec/changes/veil-audit-r3-remediation/specs/observability-admin/spec.md",
    ): _ARCHIVED_SELF_REF_0916,
    (
        "openspec/changes/archive/2026-09-16-veil-audit-r4-remediation/design.md",
        "openspec/changes/veil-pii-conversation-cache/specs/llm-gateway/spec.md",
    ): _ARCHIVED_XREF_0917,
    (
        "openspec/changes/archive/2026-09-16-veil-audit-r4-remediation/tasks.md",
        "openspec/changes/veil-pii-conversation-cache/specs/llm-gateway/spec.md",
    ): _ARCHIVED_XREF_0917,
    (
        "openspec/changes/archive/2026-09-16-veil-audit-r4-remediation/specs/llm-protocol-hardening/spec.md",
        "openspec/changes/veil-pii-conversation-cache/specs/llm-gateway/spec.md",
    ): _ARCHIVED_XREF_0917,
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


def symbol_refs_in_file(path: Path) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        line = ERRATUM_RE.sub("", line)
        for m in SYMBOL_REF_RE.finditer(line):
            if "..." in m.group(1):  # 占位省略写法（如 `src/...rs::Sym`），非真实引用
                continue
            out.append((lineno, m.group(1), m.group(2)))
    return out


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
    symbol_violations: list[str] = []
    src_checked = 0
    spec_checked = 0
    line_checked = 0
    symbol_checked = 0
    archived_line_refs = 0
    archived_symbol_refs = 0
    for path in targets:
        rel = path.relative_to(ROOT).as_posix()
        for lineno, ref in refs_in_file(path, SRC_REF_RE):
            src_checked += 1
            collect_missing(rel, lineno, ref, missing, pending)
        for lineno, ref in refs_in_file(path, SPEC_REF_RE):
            spec_checked += 1
            collect_missing(rel, lineno, ref, missing, pending)
        for lineno, target, start, end in line_refs_in_file(path):
            if is_archived_doc(rel):
                archived_line_refs += 1
                continue
            line_checked += 1
            collect_line_violations(
                rel, lineno, target, start, end, line_violations, line_pending
            )
        for lineno, target, symbol in symbol_refs_in_file(path):
            if is_archived_doc(rel):
                archived_symbol_refs += 1
                continue
            symbol_checked += 1
            collect_symbol_violations(rel, lineno, target, symbol, symbol_violations)
    print(
        f"计数：src/*.rs 引用 {src_checked} 处；spec 引用 {spec_checked} 处；"
        f"行号引用 {line_checked} 处；符号引用 {symbol_checked} 处"
        f"（其中登记 PENDING {len(pending) + len(line_pending)} 处："
        f"路径 {len(pending)}、行号 {len(line_pending)}）。"
    )
    print(
        f"归档 change 文档行号引用 {archived_line_refs} 处未校验"
        f"（行号冻结快照，路径存在性仍校验）；"
        f"归档 change 文档符号引用 {archived_symbol_refs} 处未校验（符号冻结快照）。"
    )
    for item in pending:
        print(f"PENDING: {item}")
    for item in line_pending:
        print(f"PENDING(line): {item}")
    if missing or line_violations or symbol_violations:
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
        return 1
    print(
        f"OK: {src_checked} 处 src/*.rs 引用、{spec_checked} 处 spec 引用、"
        f"{line_checked} 处行号引用与 {symbol_checked} 处符号引用全部通过。"
    )
    return 0


def self_test() -> int:
    """结构校验自测：行号越界检出、符号存在性（直接/门面子树/缺失/缺文件）、归档目录判定。"""
    if is_archived_doc("openspec/changes/veil-audit-r3-remediation/tasks.md") or not is_archived_doc(
        "openspec/changes/archive/2026-09-11-x/tasks.md"
    ):
        print("self-test FAIL：归档目录判定错误")
        return 1
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
    print(
        "self-test OK：越界/逆序行号与缺失符号可检出，合法区间与门面符号放行，"
        "归档目录判定正确"
    )
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
