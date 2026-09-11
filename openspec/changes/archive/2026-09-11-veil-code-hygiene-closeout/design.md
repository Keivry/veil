## Context

现状（见 proposal.md Why）：行为面缺口已由既有变更承接，结构性债仍有 11 项（`A1`-`A4`、`X3`-`X9`）待收口，全部为行为保持型重构/清理。关键约束：`src/lib.rs` 以 `pub mod` 暴露全部模块，rustc `dead_code` lint 对 pub 可达项不告警，故死码清理（`X4`/`X5`）不可依赖 lint，必须逐项删除后单独编译验证。

约束：本 change 只写规划 artifacts，不改 `src/`；不放宽 fail-closed；≤800 行红线保持；`J1`-`J8` 裁定为非问题不动。新 change 名固定 `veil-code-hygiene-closeout`。

## Goals / Non-Goals

**Goals：**

- 使层声明与实现同字：`service` 不再命名 `crate::state::AppState`，声明可被 grep 证伪/证实。
- 使配置模块尺寸与职责可维护：`load_from` 按域拆分、红线测试保持 active。
- 使热路径 `restore` 复杂度有上界（每 token O(1) 直查，不重建全量 alternation 正则）。
- 使死码从 lint 盲区转为显式审计：四项逐项删除、逐项编译验证。
- 使重复实现（`PeerIp`/map 替换/usage 回退）收敛为单一来源。

**Non-Goals：**

- 不实现协议问题（`P1` `[DONE]`、`N2` 非 JSON 错误体），只登记 `J6`/`J8` 归属。
- 不设计任何网关语义/阈值变更；不合并 `J1` 三处 restore。
- 不输出 `src/` 级逐行 diff，只定决策、边界与验证口径。

## Decisions

### D1：`A1` 选「搬移 admin handler 到 `handler/admin.rs`」，不选「修正声明」

**决策**：新建 `src/handler/admin.rs`（或 `handler/admin/`），把实现 `State<AppState>` 的 handler 与 `PeerIp` 提取器从 `src/service/admin/{sse,events}.rs` 搬入；`router.rs` 改经 `handler::admin::*` 注册七路由（路径与状态码不变）。`service/admin/{ratelimit,sse,events,state}` 留守响应构造、限流表、SSE 帧与查询纯逻辑，不再命名 `crate::state::AppState`。完成后 `src/service/mod.rs:3-5` 的「本层业务经 `AppStateParts` trait 读态，不再命名 `crate::state`」与实现同字，可用 grep 验证。

**理由**：web 层提取器（`State`/`HeaderMap`/`Query`）与响应构造属 handler 职责；`service` 持有它们正是声明失真的根因。搬移后 `service` 零 `crate::state` 命名，声明无需改字即成立，避免「声明降级为兼容表述」掩盖分层退化。`router.rs` 已是唯一装配点，改动面可控。

**备选：**

- 修正声明为「service 仅 admin/credential 响应构造耦合」：改动最小但承认分层退化，且 `service` 仍多文件 import axum，声明与依赖图持续漂移，不采用。
- 仅把 `AppState` 换成泛型 trait bound 而不搬移：改动面更大且 `axum` 提取器仍需 `State` 具体类型，不采用。

### D2：`A3` 选「保留 spawn 并显式声明」，不选「去掉 spawn」

**决策**：保留 `src/handler/llm/dispatch.rs:43-52` 的 `tokio::spawn(...).await`，补注释显式声明两语义——(1) panic→`JoinError`→500 兜底；(2) 客户端断连时任务脱离请求 future 续跑（不在中途取消），并补 panic 兜底测试（注入 panic 的测试 handler，断言 500 而非连接中断）。去掉 spawn 使任务随请求 future 取消，属行为变更，另立 change。

**理由**：spawn 后立即 await 在正常路径确无并发收益，但其 panic 隔离与断连续跑是有意语义。当前代码无注释，审查易误判为冗余；显式化即可，不改变行为。

**备选：**

- 去掉 spawn，恢复随断连取消：简化调用栈但变更取消语义（长流在客户端断连时由「续跑」变「取消」），且可能影响审计/用量落库完整性，需独立论证，不采用。
- 保持现状不加注释：语义继续隐式，审查反复误报，不采用。

### D3：`X4` 对四个死码项选「逐项删除」，测试引用随之迁移

**决策**：对 `decide_via_gateway`（`src/service/audit/verdict.rs:36`）、`is_unlocked_by_password`（`src/keepass.rs:234`）、`SSE_SNAPSHOT_SECS`/`SSE_DELTA_SECS`（`src/service/admin/sse.rs:37/39`）、`SqliteOutcome.memory_only`（`src/state.rs:164`）逐项删除；每项的测试引用迁移为对内联断言或删除过时断言（如 SSE 常量测试改断言硬编码值，`memory_only` 构造点同步删字段），重导出（`audit_hold.rs:9` 等）与构造点同步更新。每删除一项即单独 `cargo build`+`cargo test` 验证，禁止批量删除后一次性编译。

**理由**：这些符号生产零引用（`decide_via_gateway` grep 仅定义/重导出/`hold.rs:344,506,519,539` 测试；`is_unlocked_by_password` 仅同文件 `:591/596/603`；SSE 常量仅 `:277/278`；`memory_only` 生产只写不读）。逐项删除可精确暴露重导出/构造点断裂；逐项编译验证是 lint 盲区下的唯一可靠捕获手段。

**备选：**

- 统一加 `#[allow(dead_code)]` 或 `#[cfg(test)]` 收编：会掩盖真实死码、违背零容忍规则，不采用。
- 保留并标注「计划移除」：死码长期留存，不采用。

### D4：`X3` 选「`restore_one(token)` 单 token 直查」，全量路径不变

**决策**：`CredentialVault` 新增 `restore_one(token: &str) -> Option<String>`——同一把锁一次读、按 token 直查 `token_to_pwd`，不克隆全表、不建 alternation 正则。`src/service/redaction/scope.rs:120-158` 的 `restore_response_with_spans` 逐 token 回查改用 `restore_one`（替换现 `restore_response(vault, &token)` 全量路径）；`restore`/`snapshot_t2p`/`redact_with_map` 全量路径不变。补正确性测试（单 token 结果与全量 restore 同 token 子串一致）与复杂度回归测试（逐 token 回查不再触发全表克隆/正则重建，可用计数或基准断言）。

**理由**：现路径每个 token 调一次全量 `restore`（`snapshot_t2p` 克隆全表 5000 凭据 + 1000 PII 并重建 alternation 正则），SSE 每事件触发 → O(K×N)；单 token 直查把每 token 降到 O(1) 锁内查表，总量 O(K+N)。全量路径不变可零风险保持既有行为。

**备选：**

- 缓存最近一次 snapshot 与编译后正则：需处理失效与并发，复杂度高，不采用。
- 改 `snapshot_t2p` 返回引用：生命周期与锁粒度难控，不采用。

## Risks / Trade-offs

- [A1 搬移后 `service` 仍可能残留 axum 限定引用] → 以「`service` 零顶层 `use axum`」为完成线，`llm_gateway/hop.rs` 的 `HeaderMap` 如属纯数据可保留并按需声明例外；grep 验证。
- [X4 删除触发重导出/构造点断裂] → 逐项删除、逐项编译，禁止批量；重导出同步更新。
- [X3 单 token 直查语义与全量 restore 有细微差异（如 strip_hallucinated/fuzzy）] → 正确性测试以「全量结果的 token 子串」为基准，差异项在 design 记录并加断言；`J1` 三层语义不被合并。
- [A4 日志级别变更影响既有告警规则] → 4xx 由 error 降 warn 属信噪比修正；在 spec 声明并在 README 不新增 BREAKING（不属行为漂移，属可观测性修正）。
- [A2 拆分导致错误顺序/消息漂移] → 拆分保持按序编排与同名错误消息，既有 `load_from` 测试不改断言。

## Migration Plan

1. 先做无行为风险的收敛（`X5` 删不可达、`X6`/`X7`/`X8` 抽公共、`X9` 迁引用），每步 `cargo test` 全绿。
2. 再做 `X4` 死码逐项删除，每项单独编译验证。
3. 再做 `A4` 日志分级、`A3` 注释+测试。
4. 再做 `A2` `load_from` 拆分（行为保持）。
5. 最后做 `A1` handler 搬移（改动面最大），`router.rs` 与测试同步。
6. 每步失败只回滚该步；全程 ≤800 红线与 `check_doc_paths` 保持。

## Open Questions

- 无。`A1` 两路线已选定搬移；`A3` 已选定保留+声明；`X4` 已选定逐项删除；`X3` 已选定单 token 直查。若 apply 阶段发现 `restore_one` 与全量 restore 存在无法容忍的语义差，回退为「缓存 snapshot + 编译正则」方案并提后续 change。
