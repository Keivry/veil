## Purpose

锁定代码卫生收口的可验证行为：层声明与实现同字、配置模块尺寸红线与 `load_from` 拆分、日志级别纪律、热路径 `restore` 复杂度上界、死码零容忍（pub 项显式审计），以及不可达分支/重复实现/垫片的收敛。全部为行为保持型重构与清理，不放宽 fail-closed 语义。

## ADDED Requirements

### Requirement: 层声明与实现同字

`src/service/mod.rs` 声称「本层业务经 `AppStateParts` trait 读态，不再命名 `crate::state`（`service -> state` 边已断）」SHALL 与实现同字：`src/service/` 下 SHALL NOT 命名 `crate::state::AppState`，实现 `State<AppState>` 的 admin handler 与 web 提取器 SHALL 归属 handler 层；`service` 层 SHALL NOT 顶层 `use axum`（纯数据依赖的 `HeaderMap` 例外 SHALL 显式声明）。

#### Scenario: service 零 state 命名

- **WHEN** grep `use crate::state` / `crate::state::AppState` in `src/service/`
- **THEN** 零命中，且 `src/service/mod.rs` 的声明可由 grep 直接证实

#### Scenario: 七路由路径与状态码不变

- **WHEN** admin handler 搬移至 `handler/admin.rs` 并经 `router.rs` 注册
- **THEN** 七条 `/_admin*` 路由路径与状态码（含 429/404/401）不变，`cargo test` 全绿

### Requirement: 配置模块尺寸红线与 load_from 拆分

`src/config/env_parse.rs` SHALL 保持 ≤800 行且红线自检测试保持 active；`load_from` SHALL 按域拆为 `load_auth`/`load_storage`/`load_redaction`/`load_audit`/`load_llm` 私有函数并保持按序编排，行为保持（默认值、错误顺序、错误消息与 fail-closed 口径不变）。

#### Scenario: 红线看护 active

- **WHEN** 任一改动使 `env_parse.rs` 超过 800 行
- **THEN** `file_len_under_800_or_split` 测试失败并指向拆分任务

#### Scenario: 拆分行为保持

- **WHEN** `load_from` 拆分后以原测试集与 `api_conformance.py` 验证
- **THEN** 默认值、错误顺序与错误消息逐项不变，缺必填仍拒启动

### Requirement: 日志级别纪律

`VeilError` 的响应日志 SHALL 按状态码分级：4xx SHALL 记 `tracing::warn!`，5xx SHALL 记 `tracing::error!`，并保留错误 `code` 字段；SHALL NOT 对预期 4xx（如 404/400）一律记 `error`。

#### Scenario: 4xx 降为 warn

- **WHEN** 请求触发 404 或 400
- **THEN** 仅产生 warn 级日志，响应状态码与错误体不变

#### Scenario: 5xx 仍为 error

- **WHEN** 请求触发 5xx
- **THEN** 记 error 级日志，可被告警规则捕获

### Requirement: 热路径 restore 复杂度上界

`CredentialVault` SHALL 提供 `restore_one(token)` 单 token 直查（同一把锁一次读、不克隆全表、不重建 alternation 正则）；`restore_response_with_spans` 的逐 token 回查 SHALL 走 `restore_one`；全量 `restore`/`snapshot_t2p`/`redact_with_map` 路径 SHALL 保持不变。逐 token 回查 SHALL NOT 触发全表克隆或全量正则重建。

#### Scenario: 单 token 与全量一致

- **WHEN** 对已注册 token 调用 `restore_one` 并与全量 `restore` 的同 token 子串比对
- **THEN** 结果一致，spans 输出与改造前一致

#### Scenario: 复杂度回归有界

- **WHEN** SSE 每事件对 K 个 token 逐 token 回查
- **THEN** 不再触发 `snapshot_t2p` 全表克隆（调用计数为零），复杂度由 O(K×N) 降为 O(K+N)

### Requirement: 死码零容忍（pub 项显式审计）

系统 SHALL NOT 保留生产零引用的 pub 符号：`decide_via_gateway`（`src/service/audit/verdict.rs:36`）、`is_unlocked_by_password`（`src/keepass.rs:234`）、`SSE_SNAPSHOT_SECS`/`SSE_DELTA_SECS`（`src/service/admin/sse.rs:37/39`）、`SqliteOutcome.memory_only`（`src/state.rs:164`）SHALL 被删除；重导出与测试引用 SHALL 同步迁移。因 `src/lib.rs` 以 `pub mod` 暴露全部模块致 rustc `dead_code` lint 盲区，每项删除 SHALL 单独编译验证，SHALL NOT 以 `#[allow(dead_code)]` 或批量删除替代。

#### Scenario: 四项零残留

- **WHEN** grep 上述四个符号名 in `src/`
- **THEN** 零命中，且每项删除后单独 `cargo build`+`cargo test` 通过

#### Scenario: lint 盲区补偿

- **WHEN** 清理完成后执行 `cargo clippy`
- **THEN** 全绿，且 pub 模块面经显式审计记录无其他生产零引用项

### Requirement: 不可达分支清除

`placeholder_inject_obj` SHALL NOT 含生产不可达的第二个 `if protocol == Anthropic` 块（`src/service/llm_gateway/placeholder.rs:175-189`，`:141`/`:159` 已全路径 return）。

#### Scenario: 协议矩阵防回归

- **WHEN** 以 Anthropic system 存在/缺失/非法形态、Responses input/instructions 及非对话协议执行矩阵测试
- **THEN** 注入结果与删除前一致，不可达块不再存在

### Requirement: 重复实现单一来源

重复实现 SHALL 收敛为单一来源：`PeerIp` 提取器 SHALL 统一（同读 `ConnectInfo`、同禁代理头）；`credential_vault.rs` 的 restore/redact map 替换 SHALL 共用 `replace_all_by_map`；`usage.rs` 非流/流式三级回退链 SHALL 共用 helper 并保留 delta 层差异。`J1` 三处 restore 的不同安全语义 SHALL NOT 合并。

#### Scenario: PeerIp 反伪造保持

- **WHEN** 请求携带 `X-Forwarded-For` 等代理头
- **THEN** 判定仍按 TCP 远端地址，反伪造测试通过

#### Scenario: map 替换逐字节不变

- **WHEN** restore 与 redact_with_map 经共享 `replace_all_by_map` 执行
- **THEN** 输出逐字节不变，三层 restore 语义各自保持

#### Scenario: usage 口径不变

- **WHEN** 三协议 usage/cached 列取数经共享回退 helper
- **THEN** 取值逐项不变，流式三处差异（快路径门、`usage_in`、Anthropic delta 层）保留

### Requirement: spawn 语义声明与垫片收敛

`src/handler/llm/dispatch.rs` 的 `tokio::spawn(...).await` SHALL 以注释显式声明 panic→`JoinError`→500 兜底与客户端断连续跑两语义，并有 panic 兜底测试；`src/service/audit_hold.rs` SHALL 收敛为仅重导出加废弃指引，`spawn.rs` 生产引用 SHALL 经 `service::audit::*`，且 `AuditHold`/`RequestKeepalive` 符号 SHALL 保留（非死码）。

#### Scenario: panic 兜底可测

- **WHEN** 注入 panic 的测试 handler 处理请求
- **THEN** 返回 500 而非连接中断，正常路径行为不变

#### Scenario: 垫片仅重导出

- **WHEN** grep `audit_hold::` in `src/`
- **THEN** 仅剩垫片重导出与兼容引用，新代码零 `audit_hold` 字面，`AuditHold`/`RequestKeepalive` 仍在
