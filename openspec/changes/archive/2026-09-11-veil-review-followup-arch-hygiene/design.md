## Context

现状：立项时 `sse.rs 884`/`block_inject.rs 831` 超 800 可维护约线；三文件逼近红线（H2.1 落定：`src/config/env_parse.rs` 770/`src/registry.rs` 754/`src/config/custom_file.rs` 716，看护 active）；四组垫片双层（H3.1 落定：仅 `audit_hold` 为真垫片）；`check_doc_paths` 全绿须保持（H4.1 实测 183 处）。约束：只拆分收敛改文档，不碰语义阈值。

## Goals / Non-Goals

Goals：单文件均 ≤800（或书面修正线）且路径不变，文档与实测一致。
Non-Goals：不改网关语义、不改阈值、不输出逐行 diff。

## Decisions

### D1：sse 按三切、block 按两切（A-D2）

决策：`sse.rs` 拆常量/切行+截断/keepalive（H1.1 落定：门面 516/`parser` 312/`meta` 46/`emit` 43），`block_inject.rs` 拆三协议帧合成/去重终结（H1.2 落定：门面 498/`frames` 295/`terminal` 77）；重导出不变。拆分路径已由实测锁定（均 ≤800），900 改线备选不再启用。
理由：800 是可维护性约线，884/831 已超且含测试，继续膨胀风险高。
备选：维持现状只改文档数字，不采用（治标不治本，首选仍是拆）。

### D2：逼近红线看护（A-NEAR）

决策：`src/config/env_parse.rs`/`src/registry.rs`/`src/config/custom_file.rs` 加 `#[test] file_len_under_800` 长度断言或拆分预案注释，超限即触发拆分任务。
理由：758/742/704 距线不足 100 行，无看护下一次合入即超。
备选：立即全拆，不采用（改动过大，当前只看护）。

### D3：四垫片收敛（A-SHIM）

决策：明确 owner 为 `service/*` 实体，根 `auth/approval/audit_hold/credential_vault` 缩为重导出垫片并加废弃指引注释；grep 旧字面收敛到重导出与测试。
理由：双层易误用，新代码须走实体路径。
备选：删除垫片，不采用（破坏外部路径兼容）。

### D4：文档 800 断言修正（D-800）+ 常驻验证（Z）

决策：arch-docs“均不超 800”改为拆后实测值（H4.1：2.1 五组全 ≤800；2.2 仅 `nonstream.rs` 804 超 4 行已备案）；`check_doc_paths` 全绿（H4.1 实测 183 处）、零死代码/重复、`KeepaliveTracker` 零接线（仅删除注记残留2处）作为每任务 Verify 常驻项。
理由：文档须与实测同字，否则验收失信。

## Risks / Trade-offs

- [拆分后路径断裂] → 重导出 + 全量测试 → conformance 全绿为准。
- [长度断言误伤注释行] → 断言按非测试代码行 → tasks 注明口径。

## Migration Plan

1. 先 D4 文档修正立实测基线，再 D1 拆分，最后 D2/D3。
2. 每拆一步跑 `cargo test` + `check_doc_paths` + conformance。

## Open Questions

- 无。800 vs 900 以拆后实测为准锁定其一。
