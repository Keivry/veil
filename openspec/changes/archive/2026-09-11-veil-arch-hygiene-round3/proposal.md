## Why

审查确认依赖方向健康无循环（`router→handler→service→state→config` 单向），但架构债与卫生问题未立项：`src/handler/llm/mod.rs`（勘误：原文单文件 `src/handler/llm.rs` 2237 行，`forward_headers/request_rewrite/serve_nonstream/spawn_stream_pump/gateway_serve` 五职责混居，现已拆为 `handler/llm/{mod,rewrite,nonstream,pump}.rs`）与 `src/service/llm_gateway/mod.rs`（勘误：原文单文件 `src/service/llm_gateway.rs` 2028 行，现已拆为 `llm_gateway/{mod,protocol,usage,hop,placeholder,tool}.rs`，行号为当时快照，语义不变）仍是全仓最大两文件，`GATEWAY_BODY_LIMIT/AUDIT_SUBLIMIT_CEILING` 常量误置入口文件；`chmod 0600` 三拷贝（`state.rs:186`、`metrics.rs:809`、`registry.rs:481`）+ WAL 初始化两套（`state.rs:167` 与 `metrics.rs:496`）；`state.rs:47 Arc<std::sync::Mutex<RateTable>>` 在 `async handle_credential:455` 内阻塞 executor；`PiiValueSampler::sample:1057` 同步直写 sqlite 与文件头“写库一律 `spawn_blocking`”矛盾，高频采样卡转发路径；`mask_pii_value(pii.rs:204)` 与 `mask_value(metrics.rs:979)` 同名易误用；`admin.rs:125` 自研 HMAC 比较未复用 `auth.rs::secret_eq`；死代码 `handler/credential.rs:362 CredentialRequestBody`（与 `service CredentialBody` 全同零引用）、`admin.rs:365 SseGuard.released #[allow(dead_code)]` 只写不读、`metrics.rs:360 flush_to_sqlite_blocking` 无生产调用；文档 5 处过时（README §7.5 `src/handler/mod.rs` 路径（勘误：原文 `src/handler.rs`，路径已拆分，语义不变）、`metrics.rs:15` TODO 已接线、`config.rs:240,247` 注释旧路径、`veil-arch-docs-cleanup` design 通篇旧路径、`error.rs` 限值位置未注）；遗留三变量静默忽略无告警；PII 请求隔离 vs 凭据跨请求复用双口径未量化注释。本 change 一次收敛，不碰网关语义与测试门限。

## What Changes

- **二次拆分**：`handler/llm/mod.rs` 按 `rewrite/nonstream/pump` 拆三文件（勘误：原文 `handler/llm.rs`，拆分已落地，语义不变），`llm_gateway/mod.rs` 按 `protocol/usage/hop/placeholder/tool` 拆子模块（勘误：原文 `llm_gateway.rs`，拆分已落地，语义不变），限值常量下沉 `config.rs`。
- **合一与锁**：新建 `src/fs_perm.rs`（`ensure_0600 + open_wal`）统一三拷贝两初始化；`RateTable` 锁换 `tokio::sync::Mutex`（或 `parking_lot`）并注释临界区禁 `.await`；采样改 `mpsc+后台 flush` 或头注释禁热路径直调 + `mask_value` 改名 `sample_mask` + 同步镜像降级 `#[cfg(test)]`。
- **死代码清理**：删重复请求体、去死字段（或 `Drop` 自动释放）、`admin` 复用 `secret_eq`、双实现/`resolve_upstream`/终止计数三处对齐注释。
- **文档与兼容**：5 处路径/注释修复；遗留三变量启动期 warn（沿用旧名不再静默）；双口径权衡注释量化；`Mock TPM` 非 `1` 值门禁已正确仅文档重申。

## Capabilities

### New Capabilities

- `arch-hygiene-round3`：二次拆分、权限合一、锁与采样修正、死代码清理、文档一致性修复。

### Modified Capabilities

- 无既有 spec 需求变更；纯结构与卫生收敛（legacy warn 为新增可观测行为，属 patch 级）。

## Non-Goals（显式）

- 不改网关阻断/审计语义（见 `veil-gateway-protocol-fix`）。
- 不加测试门限（见 `veil-test-parity-close`）。
- 不引入新运行时依赖（`parking_lot` 若用须评审，此处默认 `tokio::sync::Mutex` 零新依赖）。
- 不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-arch-hygiene-round3/` 下 proposal/design/specs/tasks；apply 阶段拆分 2 文件、新建 `fs_perm.rs`、改锁/采样/注释/README。
- **影响系统**：可维护性与长跑稳定性；行为零变更（拆分 conformance 回归）。
- **依赖**：无新依赖（默认方案）。
