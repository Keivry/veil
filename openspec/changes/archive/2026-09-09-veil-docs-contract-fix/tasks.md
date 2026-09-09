## 1. 路径勘误（DOC1）

- [x] 1.1 README 路径批量替换（DOC1）：`llm_gateway.rs::HOP_HEADERS`→`llm_gateway/hop.rs:7`（经重导出 `mod.rs:189` 亦可用）、`handler.rs`→`handler/llm/mod.rs` 等，全文 grep 复核零残留<!-- doc-paths-ignore -->
- [x] 1.2 5 个历史 proposal + `rust-rewrite-veil/tasks` 同类替换并附勘误注（DOC1，语义不变）
- [x] 1.3 新增 `scripts/check_doc_paths.py`（扫描 `src/...rs` 引用并断言存在）+ CI 接入<!-- doc-paths-ignore -->

## 2. env 与声明（DOC2/L15/L18）

- [x] 2.1 隐藏配置去留（DOC2/D1/D2）：`CREDENTIAL_BLOCK_WAIT`/`PII_GLOBAL_PERSIST`：hygiene 删除则本 change 只做校验；保留则 env 全表补行（默认/语义/示例）
- [x] 2.2 补声明（L15/L18）：`x-veil-normalized` 语义、`file_search` 口径、usage max 旧大盘对照（与 protocol-parity 联动）
- [x] 2.3 阈值表零漂移校验（README 第 4 节 vs `admin-ratelimit-contract` spec 同字断言）

## 3. 遗留决策记录（F1-F4）

- [x] 3.1 README 新增第 8 节（F1/F2/F3/F4）：NonDialog 透传语义+计数（F1，与 P0 联动）、调试落盘缺失与代替指引（F2）、Go 未闭环清单与 `veil-hardening 5.x` 承接（F3）、入口三态语义（F4）
- [x] 3.2 `contract-docs/spec.md` 锁定上述记录为需求（防后续静默漂移）
