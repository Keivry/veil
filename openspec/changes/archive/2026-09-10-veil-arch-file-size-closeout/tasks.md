## S1. 测试外迁（8 文件双 ≤800）

- [x] S1.1 `src/service/llm_gateway/placeholder.rs`（1011）测试迁出至 `placeholder/tests.rs`，主文件留 `#[cfg(test)] mod tests;`
  - Verify：两文件各 ≤800 行；`cargo test placeholder` 全绿
- [x] S1.2 `src/service/metrics/store.rs`（929）→ `store/tests.rs`
  - Verify：两文件各 ≤800 行；`cargo test store` 全绿
- [x] S1.3 `src/service/llm_gateway/tool.rs`（879）→ `tool/tests.rs`
  - Verify：两文件各 ≤800 行；`cargo test tool` 全绿
- [x] S1.4 `src/service/pii/detector.rs`（849）→ `detector/tests.rs`（与既有 `pii/` 子模块目录共存，即 `src/service/pii/` 下新建 `detector/` 目录）
  - Verify：两文件各 ≤800 行；`cargo test detector` 全绿
- [x] S1.5 `src/service/metrics/aggregate.rs`（833）→ `aggregate/tests.rs`
  - Verify：两文件各 ≤800 行；`cargo test aggregate` 全绿
- [x] S1.6 `src/service/pii/chunk.rs`（806）→ `chunk/tests.rs`
  - Verify：两文件各 ≤800 行；`cargo test chunk` 全绿
- [x] S1.7 `src/service/metrics/sample.rs`（806）→ `sample/tests.rs`
  - Verify：两文件各 ≤800 行；`cargo test sample` 全绿
- [x] S1.8 `src/handler/llm/nonstream.rs`（804）→ `nonstream/tests.rs`（与 `veil-nonstream-audit-align` 同触该文件：本步先行，逻辑改动后随）
  - Verify：两文件各 ≤800 行；`cargo test nonstream` 全绿

## S2. 全仓守卫

- [x] S2.1 新增 `scripts/check_file_sizes.py`：扫描 `src/**/*.rs`，>800 非零退出并列出文件与行数，无白名单
  - Verify：当前全仓运行退出码 0
- [x] S2.2 八文件补 `file_len_under_800_or_split` 守卫（主文件 + tests.rs 双断言，`include_str!` 相对路径按 D3）
  - Verify：`cargo test file_len_under_800` 11 处全过（3 存量 + 8 新增）
- [x] S2.3 存量三守卫复核保持（env_parse / registry / custom_file），不改写
  - Verify：单测通过且 diff 不含这三处
- [x] S2.4 `scripts/README.md` 增 `check_file_sizes.py` 条目（用途 + 门禁调用命令）
  - Verify：条目存在且含 `python3 scripts/check_file_sizes.py`

## S3. 收口验证

- [x] S3.1 四门禁：`cargo test` + `cargo clippy --all --all-targets -- -D warnings` + `python3 scripts/check_file_sizes.py` + `python3 scripts/check_doc_paths.py`
  - Verify：四门禁全部退出码 0
- [x] S3.2 design 附录补拆前/拆后实测表（8 文件）
  - Verify：表格数值与 `check_file_sizes.py` 输出一致
