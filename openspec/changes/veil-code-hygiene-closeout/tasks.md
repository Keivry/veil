## 1. A1 层声明落地（D1）

- [x] 1.1 新建 `src/handler/admin.rs`（或 `handler/admin/`），把实现 `State<AppState>` 的 handler（`src/service/admin/sse.rs:172-176` `admin_events_stream`、`src/service/admin/events.rs:180/211/240/303/379` 五个 handler）搬入，`src/service/admin/{sse,events}.rs` 仅留响应构造与纯逻辑
  - 验证：`router.rs` 七路由经 `handler::admin::*` 注册，路径与状态码不变，`cargo test` 全绿
- [x] 1.2 `PeerIp` 提取器（`src/service/admin/sse.rs:106-122` 与 `src/handler/credential.rs:297-315` 统一后）移入 handler 层公共模块，`service` 侧零 `use axum`
  - 验证：`grep -rn "use crate::state" src/service/` 零命中，`grep -rn "use axum" src/service/` 仅剩纯数据依赖（`llm_gateway/hop.rs`/`llm_gateway/mod.rs` 的 `HeaderMap`），逐项声明例外
- [x] 1.3 使 `src/service/mod.rs:3-5` 声明与实现同字并锁定
  - 验证：`cargo build` 通过；grep 证实 `service` 不再命名 `crate::state::AppState`，声明可被 grep 直接证实

## 2. A2 配置按域拆分（行为保持）

- [x] 2.1 把 `src/config/env_parse.rs:256-473` 的 `load_from` 拆为私有 `load_auth`/`load_storage`/`load_redaction`/`load_audit`/`load_llm`
  - 验证：默认值、错误顺序与错误消息逐项不变，既有 `load_from` 测试断言零修改且 `cargo test` 全绿
- [x] 2.2 拆分后 `src/config/env_parse.rs` 保持 ≤800 行、`file_len_under_800_or_split`（:506-515）保持 active
  - 验证：`cargo test file_len_under_800_or_split` 通过，`wc -l src/config/env_parse.rs` ≤800
- [x] 2.3 确认拆分后无行为漂移（auth/storage/redaction/audit/LLM 逐域默认与 fail-closed 口径）
  - 验证：`cargo test` 全绿 + `scripts/api_conformance.py` 全绿，缺必填仍拒启动

## 3. A3 spawn 语义显式化（D2）

- [x] 3.1 在 `src/handler/llm/dispatch.rs:43-52` spawn 处补注释，显式声明 panic→`JoinError`→500 兜底与断连续跑两语义
  - 验证：注释覆盖两语义，`cargo build` 通过
- [x] 3.2 补 panic 兜底测试（注入 panic 的测试 handler，断言 500 而非连接中断）
  - 验证：`cargo test` 新增 panic 兜底用例通过，正常路径行为不变

## 4. A4 日志级别纪律

- [x] 4.1 改 `src/error.rs:153` 的 `IntoResponse for VeilError`：4xx→`tracing::warn!`、5xx→`tracing::error!`，保留 code 字段
  - 验证：`cargo test` 全绿；4xx 响应仍返回原状态码与错误体
- [x] 4.2 补日志级别断言测试（404/400→warn，500→error）
  - 验证：级别断言测试可重复通过，`grep tracing::error` 不再覆盖 4xx 分支

## 5. X3 热路径 restore 复杂度（D4）

- [x] 5.1 `src/service/credential_vault.rs` 新增 `restore_one(token: &str) -> Option<String>`：同锁一次直查，不克隆全表、不建 alternation 正则
  - 验证：`cargo test` 全绿，单 token 结果与全量 `restore` 同 token 子串一致
- [x] 5.2 `src/service/redaction/scope.rs:120-158` 的 `restore_response_with_spans` 逐 token 回查改走 `restore_one`；全量 `restore`/`snapshot_t2p`（:122-128）/`redact_with_map` 路径不变
  - 验证：`cargo test` 全绿，spans 输出与改造前一致
- [x] 5.3 补正确性 + 复杂度回归测试（逐 token 回查不再触发全表克隆/正则重建）
  - 验证：复杂度回归测试通过；`snapshot_t2p` 调用计数在逐 token 路径为零

## 6. X4 死码逐项删除（D3）

- [x] 6.1 删除 `decide_via_gateway`（`src/service/audit/verdict.rs:36`，测试仅 `hold.rs:344,506,519,539`）并迁移 `audit_hold.rs:9` 重导出
  - 验证：该项单独 `cargo build`+`cargo test` 通过，`grep -rn decide_via_gateway src/` 零命中
- [x] 6.2 删除 `is_unlocked_by_password`（`src/keepass.rs:234`，测试仅 `:591/596/603`）并处理测试引用
  - 验证：该项单独 `cargo build`+`cargo test` 通过，`grep -rn is_unlocked_by_password src/` 零命中
- [x] 6.3 删除 `SSE_SNAPSHOT_SECS`/`SSE_DELTA_SECS`（`src/service/admin/sse.rs:37/39`，测试仅 `:277/278`）
  - 验证：该项单独 `cargo build`+`cargo test` 通过，`grep -rn "SSE_SNAPSHOT_SECS\|SSE_DELTA_SECS" src/` 零命中
- [x] 6.4 删除 `SqliteOutcome.memory_only`（`src/state.rs:164`）并同步全部构造点（`state.rs:189,199`、`router.rs:93`、`handler/credential.rs:398` 等）
  - 验证：该项单独 `cargo build`+`cargo test` 通过，`grep -rn "memory_only" src/` 零命中
- [x] 6.5 死码零容忍规则落地：pub 项显式审计（lint 盲区补偿）
  - 验证：四项全部删除后整体 `cargo clippy`+`cargo test` 全绿；`src/lib.rs` pub 模块面复查无其他生产零引用项（记录结论）
  - 结论：pub 面全量文本扫描（392 fn / 79 const / 68 struct / 18 enum / 4 type / 4 trait，含 tests/）零生产零引用项；补审另清理 7 项同类死码（`AuditVerdict::is_allow`、`policy_path_from_env`、`CallerRegistry::set_entries`、`MockKeePass::set_unlocked`、`truncated_line_dropped_bytes_count`、`DAILY_RETENTION_DAYS`、`HOURLY_RETENTION_DAYS`），逐项无测试/文档引用
- [x] 6.6 补审（Oracle 残留观察①）：`PiiScope::next_available_index` 降为 `#[cfg(test)]` 测试专用（移除非测试构建可见性），消除 pub 面 lint 盲区残留
  - 验证：`cargo clippy --all-targets -- -D warnings` 零问题；`grep -rn "pub fn next_available_index" src/` 零命中；`cargo test -p veil pii` 全绿

> 说明：`X4` 每项 MUST 单独编译验证（lint 对 `pub` 项不告警，批量删除会掩盖重导出/构造点断裂）。

## 7. X5 删不可达分支（=`P8`）

- [x] 7.1 删除 `src/service/llm_gateway/placeholder.rs:175-189` 第二个 `if protocol == Anthropic` 块（`:141` 已 return、`:159` 已对 Responses return，恒不可达）
  - 验证：`cargo build` 通过；`placeholder_inject_obj` 对 Anthropic/Responses/其他三协议输出不变
- [x] 7.2 补协议矩阵测试（Anthropic system 存在/缺失/非法形态 + Responses input/instructions + 其他协议）
  - 验证：协议矩阵测试全绿，防回归

## 8. X6 PeerIp 提取器统一

- [x] 8.1 抽公共 `PeerIp` 提取器（单一模块、统一返回类型、同禁代理头），替换 `src/handler/credential.rs:297-315`（`Option<String>`）与 `src/service/admin/sse.rs:106-122`（`IpAddr`）两处
  - 验证：两调用方（`emergency_revoke_handler`、admin handlers）行为不变，`cargo test` 全绿
- [x] 8.2 反伪造测试保持：携带 `X-Forwarded-For` 等代理头不影响判定
  - 验证：`forged_proxy_headers_do_not_bypass_revoke_check` 与 `peer_ip_uses_direct_connection_ignores_proxy_headers` 通过
  - 注：统一实现见 `src/handler/peer_ip.rs:18`（`Option<IpAddr>`）；admin 侧回退回环、紧急吊销保持 fail-closed `None`，两调用方语义与 1.2 搬移前一致

## 9. X7 map 替换抽取

- [x] 9.1 抽 `replace_all_by_map(text, map)`，`src/service/credential_vault.rs:131-150`（restore）与 `:176-194`（redact_with_map）共用，方向差异由入参承载
  - 验证：`cargo test` 全绿，两函数输出逐字节不变
- [x] 9.2 保留 `J1` 三处 restore 的不同安全语义，不合并
  - 验证：`credential_vault.rs:131`/`pii/scope.rs:132`/`redaction/scope.rs:108` 三层调用链不变，各自单测通过

## 10. X8 usage 回退链共享

- [x] 10.1 抽共享三级回退 helper，`src/service/llm_gateway/usage.rs:105-151`（非流）与 `:159-208`（流式）共用，保留 delta 层差异
  - 验证：`cargo test` 全绿，三协议 usage/cached 列取值逐项不变
- [x] 10.2 保留流式三处差异（快路径门、`usage_in` 统一、Anthropic delta 层）
  - 验证：`scripts/api_conformance.py` 全绿，usage 口径与 README §7.2 同字

## 11. X9 垫片收敛

- [x] 11.1 `src/handler/llm/pump/spawn.rs:28` 改引 `crate::service::audit::{AuditHold, RequestKeepalive}`（`AuditHold`/`RequestKeepalive` 符号保留，见 `J4`）
  - 验证：`cargo test` 全绿，spawn 泵行为不变
- [x] 11.2 `src/service/audit_hold.rs` 收敛为仅重导出加废弃指引；grep 生产引用经 `service::audit::*`
  - 验证：`grep -rn "audit_hold::" src/` 仅剩垫片与兼容重导出，新代码零 `audit_hold` 字面
