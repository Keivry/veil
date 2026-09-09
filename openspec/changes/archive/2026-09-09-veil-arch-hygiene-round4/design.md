## Context

See proposal.md Why. Current code: `state.rs:60-70` 聚合 `AdminState/MatrixApproval/RateTable/GatewayMetrics/vault/pii`，`service/mod.rs:1-15` 反向引用 `state::AppState`；`audit_hold.rs:20-29` 桥接 `NoopApproval/MatrixApproval`；`service/mod.rs:344-502` 凭据业务塞 mod；`pii.rs:1006-1404/metrics.rs:163-1108/admin.rs:184-850` 业务+测试巨石；`llm_gateway/mod.rs:25 RETRY_DELAYS_MS` 硬编码；`metrics.rs:12 TODO`；死代码与重复见 proposal 清单（BOM/常量已复核函数体相同）。

## Goals / Non-Goals

**Goals:**

- 依赖单向无环；文件均 <800 行；零死代码；零重复实现；命中率有数或有声明。

**Non-Goals:**

- 业务语义变更（判定/口径/终止形态归 P0/P1/sampler）。
- 对外路径变更（必须重导出兼容）。

## Decisions

- 解耦：`state.rs` 只留 `AppState` 类型 + `new()` 构造；`RateTable`/凭据查询/注册吊销审批移 `service/credential.rs`；`service` 经 `AppStateParts` trait 读态。备选“保留循环（可编译）”违反分层不采用。
- 拆分模板（照抄 `llm_gateway`）：`config/{mod,env_parse,custom_file,validate}.rs`、`pii/{detector,scope,chunk,custom}.rs`、`metrics/{store,aggregate,sample,summarize}.rs`、`admin/{state,ratelimit,sse,events}.rs`，各 `mod.rs` 重导出旧路径。备选“大爆炸重写”风险高不采用。
- 死代码：`credential_block_wait` 留则 README 补行（转 docs change），否则删除；`pii_global_persist` 删除（无读取方）；`resolve_upstream_with_ingress` 删除（生产只用 `llm_gateway::resolve_upstream`）；`admin` 三函数加 `#[cfg(test)]`；保活二选一：保留 `sse::KeepaliveTracker`（pump 已接线），删除 `RequestKeepalive`；`Utf8ByteBuffer` 未用方法删除（先核对 pump 接线）。
- 去重：删 `sse::strip_sse_bom` 全改为 `json_walk::strip_bom`；删 `pii::SCAN_INPUT_LIMIT` 改复用 `json_walk::SCAN_INPUT_LIMIT`；删 `metrics::redact_summary` 脱敏段只留截断，调用方改 `audit::sanitize_for_log`；`AUDIT_SUMMARY_TRUNCATE_CHARS` vs `SUMMARY_MAX_CHARS` 二选一或注释差异；`audit` 只留 `is_dangerous+evaluate_with_whitelist`；`apply_spans_dedup` 并入 `apply_spans(with_dedup: bool)`；`restore_response` 改名 `restore_response_internal` 或内联。
- 命中率：跑采样对比（隔离 vs 全局复用）给出百分点，或书面声明不测（隐私优先，接受未知代价）并关闭 TODO。

## Risks / Trade-offs

- [Risk] 拆分导致 `git blame` 断裂 → Mitigation：`git mv` 保留历史 + 重导出兼容。
- [Risk] trait 注入改构造链 → Mitigation：`AppState::new` 签名不变，内部组装调整。

## Migration Plan

- 按 tasks 顺序，每组 `cargo test` + 路径兼容 `grep`（旧路径仍可 `use`）；与 protocol-parity 联动 `record_chat(model)` 签名；回滚 revert 本 change。
