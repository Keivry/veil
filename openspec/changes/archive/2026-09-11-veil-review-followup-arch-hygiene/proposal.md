## Why

深度审查 §3-5 结论：架构拆分方向正确但 2 文件仍超限且验收失实、3 文件逼近红线、4 组垫片未收敛、文档 800 断言与实测矛盾。立项时 `sse.rs 884`、`block_inject.rs 831` 超 800 可维护约线（`veil-review-arch-docs` D2 验收仅覆盖 pump/audit 等五组拆分，不含此二文件）；`env_parse 758`、`registry 742`、`custom_file 704` 逼近红线；`auth/approval/audit_hold/credential_vault` 四组立面+实体双层易误用（H3.1 核查：仅 `audit_hold` 为真垫片，其余三组为职责正交实体）；`check_doc_paths` 全绿须保持（H4.1 实测 183 处，立项时 177）。本 change 只做拆分、收敛与文档修正，不碰网关语义。

## What Changes

- **拆 A-D2（sse/block_inject 超限）**：`sse.rs` 按常量/切行/keepalive 三切（H1.1 落定：门面 516/`parser` 312/`meta` 46/`emit` 43，均 ≤800），`block_inject.rs` 按三协议帧/去重两切（H1.2 落定：门面 498/`frames` 295/`terminal` 77，均 ≤800），对外路径不变；拆分路径已锁定，无需 900 改线。
- **看护 A-NEAR（逼近红线三文件）**：`src/config/env_parse.rs`/`src/registry.rs`/`src/config/custom_file.rs` 加长度断言或拆分预案，超 800 即触发拆分任务。
- **收敛 A-SHIM（四组垫片）**：`src/auth.rs` vs `src/service/credential/auth.rs`、`src/approval.rs` vs `src/service/credential/approval.rs`、`src/service/audit_hold.rs` vs `src/service/audit/hold.rs`、`src/service/credential_vault.rs` vs `src/service/credential/vault_ops.rs` 明确 owner 与旧路径废弃计划，重导出保留兼容，grep 旧字面收敛。
- **修正 D-800（文档夸大）**：arch-docs“均不超 800”改为实测值或拆后值，与 `check_doc_paths` 互锁。
- **验证 Z（零死代码/重复/引用）**：`allow(dead_code)/unimplemented!/todo!` 零命中、`pub fn` 无重名、`KeepaliveTracker` 零接线（仅删除注记残留2处，历史注释说明除外）、`check_doc_paths` 全绿（H4.1 实测 183 处）作为 Verify 常驻项。

## Capabilities

### New Capabilities

- `arch-hygiene-followup`：拆分、收敛与文档修正的可验证场景。

### Modified Capabilities

- 无。不改网关语义与阈值；`GATEWAY_BODY_LIMIT` 归属与 HOP 全集保持不动。

## Non-Goals（显式）

- 不改用量/审计/PII/限流语义，不改单监听与选路。
- 不改既有 change 文件；不提交 commit。

## Impact

- **新增文件**：本目录 proposal/design/specs/tasks；apply 拆 `sse.rs`/`block_inject.rs`（或其子模块）、收敛四垫片、改 README/arch-docs 表述。
- **影响系统**：可维护性与文档真实性，无行为变更。
- **依赖**：`cargo test` 全绿 + `scripts/check_doc_paths.py` + `scripts/api_conformance.py`。
