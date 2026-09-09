## Context

See proposal.md Why. Current: `README.md:295` 引用不存在的 `src/service/llm_gateway.rs::HOP_HEADERS`；`veil-gateway-protocol-fix/proposal:32`、`veil-full-parity-fix/proposal:42`、`veil-review-remediation/proposal:39`、`veil-conformance-fix/proposal:31`、`rust-rewrite-veil/tasks:103/106/109/118-119` 同类过期；`config.rs:210-213` 两配置无文档；`rewrite.rs:58-67` 注入行为无头声明文档；`usage.rs:57-66` max 口径迁移须知在 README 7.2 但缺旧大盘对照；NonDialog/落盘/Go/入口无集中决策记录。<!-- doc-paths-ignore -->

## Goals / Non-Goals

**Goals:**

- 文档引用路径 100% 存在（脚本可验）；env 全表与二进制读取一致；遗留决策有记录可追溯。

**Non-Goals:**

- 业务代码修改（去留决策执行归 hygiene/P0/protocol-parity，本 change 只落文档 + 勘误 + 脚本）。

## Decisions

- 历史 proposal 路径勘误：直接改原文路径字样并附 `(勘误：路径已拆分，语义不变)` 注，不另立勘误 change。
- 隐藏配置：默认删除派（hygiene 执行删代码）；若保留则本 change 补 env 全表行（默认值/语义/示例）。两条件分支在本 change tasks 写明。
- 路径校验脚本：`scripts/check_doc_paths.py` 扫描 README + proposals 的 `src/...rs` 引用并断言存在，CI 运行。
- 决策记录位置：README 第 7 节后加第 8 节“遗留决策记录”（NonDialog/落盘/Go/入口四条），specs 加 `contract-docs/spec.md` 锁定。

## Risks / Trade-offs

- [Risk] 改历史 proposal 被误读为改结论 → Mitigation：仅路径字样 + 勘误注，不碰 Why/Decisions 结论。
- [Risk] 脚本误报（代码块示例路径）→ Mitigation：只校验 `src/` 开头且以 `.rs` 结尾的引用，示例路径加 `ignore` 标记。

## Migration Plan

- 按 tasks 落地，跑脚本 + 全文 grep 复核；回滚 revert 本 change（脚本删除即可）。
