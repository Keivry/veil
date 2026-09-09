## 1. 解耦与拆分（A1/A2/A3/A4）

- [x] 1.1 解耦 `state ↔ service`（A1）：state 下沉纯类型+构造，新建 `service/credential.rs` 承接凭据/限流/审批业务，trait 注入；`decide_via_gateway` 移 `audit.rs`
- [x] 1.2 按 `llm_gateway` 模板拆 `config`/`pii`/`metrics`/`admin` 为子模块 + `mod.rs` 重导出（A2：旧路径兼容，单文件 <800 行）
- [x] 1.3 阈值配置化或注释硬编码理由（A3：`RETRY_DELAYS_MS` 等逐项）
- [x] 1.4 闭环 `TODO(metrics)`（A4）：命中率量化数据或书面不测声明并关 TODO

## 2. 死代码清理（D1/D2/D3/D4/D5/D6）

- [x] 2.1 隐藏配置与重复入口（D1/D2/D3）：`credential_block_wait`（`config.rs:210`）补文档或删；`pii_global_persist`（`:213`）接线或删；`resolve_upstream_with_ingress`（`:293`）合并删除
- [x] 2.2 测试独占与双保活（D4/D5/D6）：`admin.rs:145/155/165` 降 `#[cfg(test)]`；`RequestKeepalive` vs `KeepaliveTracker` 二选一删除；`Utf8ByteBuffer` 未接线方法清理（含 `cargo test` 确认）

## 3. 去重合并（R1/R2/R3/R4/R5/R6/R7）

- [x] 3.1 BOM 单一来源（R1）：删 `sse::strip_sse_bom`，全改 `json_walk::strip_bom`（`pump.rs:23/166/206/255` + `sse.rs` 内）
- [x] 3.2 `SCAN_INPUT_LIMIT` 单一来源（R2）：删 `pii.rs:41`，复用 `json_walk.rs:13`
- [x] 3.3 脱敏/截断/判定收敛（R3/R4/R5）：脱敏统一 `audit::sanitize_for_log`；截断二选一或注释差异；审计判定收敛（block_inject 只合成帧，hold 只累积）
- [x] 3.4 span/还原单函数化（R6/R7）：`apply_spans` 单函数化（`with_dedup` 参数）；`restore_response` 内联/改名
- [x] 3.5 全量门禁 `fmt/clippy/test` 全绿 + 旧路径兼容 grep（`use crate::service::X` 仍编译）
