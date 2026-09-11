## H1. A-D2 超限拆分或改线（D1）

- [x] H1.1 `sse.rs` 按三切拆且路径不变（H4.1 实测：门面 516/`parser` 312/`meta` 46/`emit` 43，均 ≤800）
  - Verify：拆后单文件均 ≤800（或改线 900 同步文档），`cargo test` + conformance + `check_doc_paths` 全绿（H4.1 实测 183 处）
  - Verify：对外 `crate::service::sse::*` 引用编译通过
- [x] H1.2 `block_inject.rs` 按两切拆且路径不变（H4.1 实测：门面 498/`frames` 295/`terminal` 77，均 ≤800）
  - Verify：同上全绿；三协议帧形态快照不变

## H2. A-NEAR 红线看护（D2）

- [x] H2.1 三文件加长度断言或预案注释（H4.1 实测：`src/config/env_parse.rs` 770/`src/registry.rs` 754/`src/config/custom_file.rs` 716，均 ≤800，看护 active）
  - Verify：`src/config/env_parse.rs`/`src/registry.rs`/`src/config/custom_file.rs` 任一超 800 即单测失败指向拆分任务
  - Verify：`cargo test` 通过

## H3. A-SHIM 四垫片收敛（D3）

- [x] H3.1 明确 owner 并缩为重导出加废弃指引（H4.1 落定：`audit_hold` 为唯一真垫片已收敛；`auth/approval/credential_vault` 三组经核查为职责正交实体、互不垫片，改落 owner 声明）
  - Verify：生产引用指向 `service/*` 实体，根仅重导出；grep 旧字面收敛
  - Verify：`cargo test` 通过，语义无变更

## H4. D-800 文档修正与 Z 常驻（D4）

- [x] H4.1 修正 800 断言为实测值（H4.1 实测：`nonstream.rs` 804 超 4 行已在 arch-docs 2.2 备案；`check_doc_paths` 183 处全绿，立项时 177）
  - Verify：文档数字与实测行数一致，`grep -n "800"` 逐项核对
  - Verify：`allow(dead_code)/unimplemented!/todo!` 零命中、`pub fn` 无重名、`KeepaliveTracker` 零接线（仅删除注记残留2处）、`check_doc_paths` 全绿
