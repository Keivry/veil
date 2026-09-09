## Why

架构审查（78/100）发现结构性问题：`state ↔ service` 双向依赖（`state.rs:60-70` vs `service/mod.rs:1-15`）违反单向依赖；`approval ↔ matrix` 经 `audit_hold.rs:20-29` 桥接泄漏；4 个超大文件（`config` 1844/`service/mod` 1754/`pii` 2157/`metrics` 1703/`admin` 1436行） narrative 可维护性差；阈值硬编码过多；`TODO(metrics)` 命中率量化超两版本未闭环。同时 6 组重复（BOM/常量/脱敏/截断/审计判定/span/还原双入口，已复核实锤 2 组）与 6 项死代码（2 隐藏配置 + 测试独占 pub + 双保活二选一）需清理。

## What Changes

- 解耦 `state ↔ service`：state 下沉为纯类型+构造，凭据/限流/审批业务上移到 `service/credential.rs` 等新模块，经 trait 注入打破循环；`decide_via_gateway` 从 `audit_hold.rs:20` 移到 `audit.rs`。
- 按 `llm_gateway` 模板拆 4 胖文件为子模块 + `mod.rs` 重导出（路径兼容）：`config/*`、`service/credential.rs`（凭据业务抽离 `service/mod.rs`）、`pii/*`、`metrics/*`、`admin/*`。
- 阈值配置化或显式注释硬编码理由（`RETRY_DELAYS_MS` 等）。
- 闭环 `TODO(metrics)`：量化请求隔离 vs 全局复用的 prompt-cache 命中率，或显式声明不测+理由。
- 删除/降级死代码：`credential_block_wait` 补文档或删；`pii_global_persist` 接线或删；`resolve_upstream_with_ingress` 合并；`admin` 三函数降 `#[cfg(test)]`；`RequestKeepalive` vs `KeepaliveTracker` 二选一；`Utf8ByteBuffer` 未接线方法清理。
- 合并 7 组重复：BOM→`json_walk::strip_bom` 单一来源；`SCAN_INPUT_LIMIT` 单一来源；日志脱敏统一 `audit::sanitize_for_log`；截断语义合并或显式注释差异；审计判定收敛为 `is_dangerous+evaluate_with_whitelist`（block_inject 只合成帧，hold 只累积字节）；span/还原单函数化。

## Capabilities

### New Capabilities

- `hygiene-round4`: 循环解耦 + 胖文件拆分 + 死代码清理 + 7 组去重 + 命中率量化。

### Modified Capabilities

- 无（纯内构重构，对外路径经重导出保持不变）。

## Impact

- 影响 `state.rs`、`service/mod.rs`（新建 `credential.rs`）、`config.rs`、`pii.rs`、`metrics.rs`、`admin.rs`、`audit*.rs`、`sse.rs`、`json_walk.rs`、`redaction.rs`、`block_inject.rs`。
- **兼容**：全部经 `mod.rs` 重导出保持 `crate::...` 路径不变，调用方零改。
- 与 P0/P1/sampler 联动：BOM/`SCAN_INPUT_LIMIT` 合并后两 change 复用单一来源；`record_chat` 签名变更（model 参数）与 protocol-parity C13 同步。
