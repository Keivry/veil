## 1. 零风险清理（D4/D5 先行）

- [x] 1.1 删 `CredentialRequestBody` + `SseGuard.released` 改 `Drop` + `secret_eq` 复用
  - Verify: `handler/credential.rs` 无 `CredentialRequestBody` 定义且编译通过
  - Verify: 全仓 grep `allow(dead_code)` 零生产命中，`release_sse_for` 由 `Drop` 自动触发（断连不泄漏单测）
  - Verify: `admin.rs` HMAC 比较调用 `auth::secret_eq`，自研实现已删
- [x] 1.2 文档 5 处修复（README §7.5、`metrics` TODO、`config` 注释、旧 design 注、限值注）
  - Verify: 5 处逐项改后文案正确（逐项列出文件行号比对）
  - Verify: 文档评审确认零漂移
- [x] 1.3 遗留三变量启动 warn + 双口径注释 + `reject_*` 预留标注
  - Verify: 含旧变量启动时日志出现 warn 且行为仍为不读取
  - Verify: `audit_hold.rs:303` 头注释含预留说明

## 2. 合一与锁采样（D2/D3）

- [x] 2.1 新建 `fs_perm.rs` 并替换三拷贝两初始化
  - Verify: `src/fs_perm.rs` 存在且导出 `ensure_0600 + open_wal`
  - Verify: `state.rs/metrics.rs/registry.rs` 旧拷贝已删，语义单源
  - Verify: sqlite 0600 + WAL 参数单测通过
- [x] 2.2 锁换 `tokio::sync::Mutex` + 临界区注释
  - Verify: `state.rs` 无 `std::sync::Mutex` 用于 `RateTable`
  - Verify: 临界区注释“禁 `.await`”且限流边界单测全绿
- [x] 2.3 采样异步化（或禁热路径声明）+ 改名 + 同步镜像降级
  - Verify: 转发热路径无同步 sqlite 写（代码审查确认）或 `mpsc` 后台 flush 生效且满队列丢最老可查
  - Verify: `mask_value` 已改名 `sample_mask`，`flush_to_sqlite_blocking` 仅 `#[cfg(test)]`
  - Verify: 全量 `cargo test` 通过

## 3. 二次拆分（D1，最后）

- [x] 3.1 `handler/llm/` 三单元拆分 + 对外路径不变
  - Verify: `handler/llm/{mod,rewrite,nonstream,pump}.rs` 存在且旧单文件已删
  - Verify: `router.rs` 无需改动，对外 `handler::*` 不变
- [x] 3.2 `llm_gateway/` 按协议拆模块 + 常量下沉 `config.rs`
  - Verify: `service/llm_gateway/{mod,protocol,usage,hop,placeholder,tool}.rs` 存在且重导出符号不变
  - Verify: 限值常量归属 `config.rs`，原位转发不断裂
  - Verify: conformance 20/20 + 全量 `cargo test` 通过
