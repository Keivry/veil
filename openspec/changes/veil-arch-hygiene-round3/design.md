## Context

现状：功能正确，债集中在文件体量、重复权限、锁选型、采样路径、死代码、文档漂移六处。约束：拆分行为一致（conformance 回归）；无新依赖（默认）；legacy warn 只读环境不改行为。

## Goals / Non-Goals

**Goals：**

- 给出拆分边界与常量归属，使 apply 可机械执行。
- 给出合一/锁/采样的最小改法。
- 给出死代码与文档的精确位置与改后形态。

**Non-Goals：**

- 不重排 `service/` 内网关管线语义。
- 不改限流阈值与采样表结构。

## Decisions

### D1：`handler/llm.rs` 按三单元拆分，`llm_gateway.rs` 按协议拆模块

**决策**：`handler/llm.rs` → `handler/llm/{mod.rs,rewrite.rs,nonstream.rs,pump.rs}`（`mod.rs` 仅 re-export + `protocol_header_value/empty_body_response/should_pump_stream` 谓词留守）；`service/llm_gateway.rs` → `service/llm_gateway/{mod.rs,protocol.rs,usage.rs,hop.rs,placeholder.rs,tool.rs}`（`mod.rs` 重导出既有公开符号，对外路径不变）；`GATEWAY_BODY_LIMIT_BYTES` 与 `AUDIT_SUBLIMIT_CEILING_BYTES` 移 `config.rs`，原位 `pub use` 转发（防外部引用断裂）。

**理由**：`gateway-pipeline-units`（rewrite/nonstream/pump）初衷未竟，五职责混居致单测须全量 `AppState`；按协议拆后 tool/usage 可独立单测。

**备选**：维持双大文件——可维护性持续恶化，不采用。

### D2：新建 `fs_perm.rs` 合一权限与 WAL

**决策**：新建 `src/fs_perm.rs::ensure_0600(db_path)`（含 `-wal/-shm` 同权）+ `open_wal(db_path)->Connection`（`WAL+busy_timeout5000+synchronous NORMAL+0600`），替换 `state.rs:186-203`、`metrics.rs:496-507,809-822`、`registry.rs:481` 三拷贝两初始化。`lib.rs` 注册模块。

**理由**：三拷贝语义同为 `0600 + -wal/-shm`，漂移即漏洞；WAL 参数双源必合一。

### D3：锁换异步友好 + 采样移出热路径

**决策**：`state.rs:47` 两表 `Arc<std Mutex>` 换 `Arc<tokio::sync::Mutex>`，`handle_credential:455` 临界区注释“禁 `.await`，仅查改时间戳”；`PiiValueSampler::sample` 改 `mpsc(512)+后台 flush`（队列满丢最老计 `dropped`，与指标环同语义），若工作量超则退守头注释“仅后台任务调用，禁转发热路径直调”；`mask_value:979` 改名 `sample_mask`；`flush_to_sqlite_blocking:360` 降级 `#[cfg(test)]`。

**理由**：同步锁阻塞 executor 在高并发凭据 burst 下放大尾延迟；同步直写 sqlite 卡转发路径与文件头契约矛盾。

**备选**：`parking_lot::Mutex`——临界区极短亦可，但引入新依赖，默认不采用。

### D4：死代码与复用清理

**决策**：删 `handler/credential.rs:362 CredentialRequestBody`（统一 `service::CredentialBody`）；`admin.rs:365 SseGuard.released` 删字段并实现 `Drop::drop{release_sse_for(ip)}`（去 `#[allow(dead_code)]`，替代手动释放）；`admin.rs:125` 自研 HMAC 比较复用 `auth::secret_eq`（删 5 行）；`audit_hold.rs:303 reject_new_dangerous_during_hold` 保留但标注“预留：泵未接线，接线见 gateway change”；`error.rs:1` 注释加“413 入口直接构造，限值见 `config.rs`（由 `handler/llm.rs:16` 下沉）”。

### D5：文档 5 处 + legacy warn + 双口径注释

**决策**：README §7.5 路径改 `handler/credential.rs`；`metrics.rs:15` TODO 改“已接线 `handler/llm.rs:965`”；`config.rs:240,247` 注释改 `handler/llm.rs`；`veil-arch-docs-cleanup/design.md:22,58` 加“截至 bcc6c4e 已为目录形态”；启动期对 `CREDENTIAL_MASTER_PASSWORD/CREDENTIAL_PORT/CREDENTIAL_PROXY_DEBUG_DIR` 三遗留变量若检出则 warn“二进制不读取，改用见 README §7.4”（只读 env，不改行为）；PII 隔离 vs 凭据复用在 README §7.3 追加“跨请求 prompt-cache 命中下降属有意权衡”已存在则补量化占位（hit 率待测标注 `TODO(metrics)`，不阻塞）。

## Risks / Trade-offs

- [拆分引入循环依赖] → `handler/llm/mod.rs` 只 re-export，共享类型不动 → 先编过再删旧文件。
- [锁替换致死锁语义变] → 临界区禁 `.await` 注释 + 既有限流单测全绿 → 全量测试回归。
- [采样异步化丢数] → 满队列丢最老 + `dropped` 计数可查 → 与指标环同语义可接受。

## Migration Plan

1. 先 D4+D5 零风险清理与文档（含 legacy warn），再 D2 合一，再 D3 锁/采样，最后 D1 拆分（conformance 回归）。
2. 拆分未合入前不删旧文件；合入后单 PR 删旧。
3. 回滚：各决策独立 revert。

## Open Questions

- 无。
