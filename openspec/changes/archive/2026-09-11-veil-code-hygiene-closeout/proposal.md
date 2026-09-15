## Why

六维审查（架构/死码/重复/文档/协议/测试对等）收口后，行为面缺口已由既有变更承接，但结构性债仍有 11 项（`A1`-`A4`、`X3`-`X9`）未进入任何 change，全部为行为保持型重构/清理：

- `A1`（MED）层声明不成立：`src/service/mod.rs:3-5` 声称「本层业务经 `credential::AppStateParts` trait 读态，不再命名 `crate::state`（`service -> state` 边已断）」，但 `src/service/admin/sse.rs:10,173` 与 `src/service/admin/events.rs:5,180/211/240/303/379` 直接 `use crate::state::AppState` 并实现 `State<AppState>` handler，`service` 层多文件 import axum。
- `A2`（MED）配置巨石：`src/config/env_parse.rs` 770/800 行（自检测试 `:506-515`），`load_from` 220 行串行巨石（`:256-473`，auth/storage/redaction/audit/LLM 逐域内联）。
- `A3`（LOW）spawn 语义未声明：`src/handler/llm/dispatch.rs:43-52` 为 `tokio::spawn(...).await`（spawn 后立即 await），正常路径无收益；实际作用是 panic→`JoinError`→500 与客户端断连时任务脱离续跑，代码无注释声明。
- `A4`（LOW）日志级别失当：`src/error.rs:153` 对全部错误（含预期 4xx 404/400）一律 `tracing::error!`，稀释真告警。
- `X3`（LOW 性能）热路径 O(K×N)：`src/service/redaction/scope.rs:120-158` 的 `restore_response_with_spans` 先全量 restore，再对 `scan_token_forms` 每个 token 循环调 `restore_response`；`src/service/credential_vault.rs:131-150` 的 `restore` 每次经 `snapshot_t2p()`（:122-128）全表克隆并按全部 token（上限 5000 凭据 + 1000 PII）重建 alternation 正则；调用点 `src/handler/llm/pump/spawn/event_loop.rs:571-599/483/595` 为每 SSE 事件。
- `X4`（LOW 死码，lint 盲区）四组生产零引用符号：`decide_via_gateway`（`src/service/audit/verdict.rs:36`，仅测试 `hold.rs:506/519/539` 用；README §6.4 已声明流式审批不再同步阻塞）、`is_unlocked_by_password`（`src/keepass.rs:234`，仅测试 `:591/596/603` 用；生产走 `is_unlocked()` `:257`）、`SSE_SNAPSHOT_SECS`/`SSE_DELTA_SECS`（`src/service/admin/sse.rs:37/39`，仅测试 `:277/278` 用）、`SqliteOutcome.memory_only`（`src/state.rs:164`，生产只写不读）。
- `X5`（=`P8`，LOW）不可达分支：`src/service/llm_gateway/placeholder.rs:175-189` 第二个 `if protocol == Anthropic` 恒不可达（`:141` 已 return；`:159` 已对 Responses return）。
- `X6`（LOW）重复提取器：`PeerIp` 双实现——`src/handler/credential.rs:297-315`（`Option<String>`）vs `src/service/admin/sse.rs:106-122`（`IpAddr`），同读 `ConnectInfo` 同禁代理头。
- `X7`（LOW）重复算法：`src/service/credential_vault.rs:131-150`（restore）与 `:176-194`（redact_with_map）算法全同（长度降序 + escape + alternation + 按 map 替换），仅方向相反。
- `X8`（LOW）重复回退链：`src/service/llm_gateway/usage.rs:105-148` vs `:159-205` 三级回退链重复（Responses 三级 + Anthropic 回退）。
- `X9`（LOW）垫片未收敛：`src/service/audit_hold.rs:1-8` 自述「新代码应走 `service::audit::*`」，但 `src/handler/llm/pump/spawn.rs:28` 仍引 `audit_hold::{AuditHold, RequestKeepalive}`。

**关键事实（死码逃逸根因）**：`src/lib.rs:1-11` 将全部顶层模块以 `pub mod` 暴露，rustc `dead_code` lint 对 pub 可达项按公开 API 处理、不产生告警，故 `cargo clippy` 全绿与「存在生产零引用 pub 项」并存（`X4`/`X5` 即此类）。因此本 change 的死码清理 MUST NOT 依赖 lint，必须逐项删除后单独编译验证，并同步处理重导出与测试 import。

## What Changes

- **`A1`（MED）层声明落地（design D1）**：把实现 `State<AppState>` 的 admin handler 与 `PeerIp` 提取器搬移至新建 `src/handler/admin.rs`（或 `handler/admin/`），`router.rs` 改经 `handler::admin::*` 注册，七路由路径与状态码不变；`service/admin/{ratelimit,sse,events,state}` 留守响应构造与纯逻辑，`service` 不再命名 `crate::state::AppState`，`service/mod.rs` 声明与实现同字。拒绝「修正声明为 service 仅 admin/credential 响应构造耦合」路径，理由见 design D1。
- **`A2`（MED）配置按域拆分**：`src/config/env_parse.rs` 的 `load_from` 拆为 `load_auth`/`load_storage`/`load_redaction`/`load_audit`/`load_llm` 私有函数并保留按序编排，行为保持（默认值、错误顺序与错误消息不变）；≤800 行红线与自检测试保持 active。
- **`A3`（LOW）spawn 语义显式化（design D2）**：保留 `tokio::spawn(...).await` 作为 panic 兜底（panic→`JoinError`→500、断连续跑），补注释显式声明两语义与 panic 兜底测试；去掉 spawn 的「断连取消」路线不采用（取消语义变更另立 change）。
- **`A4`（LOW）日志级别纪律**：`src/error.rs` 按状态码分级——4xx→`tracing::warn!`、5xx→`tracing::error!`；补可重复的日志级别断言测试。
- **`X3`（LOW 性能）restore 单 token 直查（design D4）**：`CredentialVault::restore_one(token)` 同锁一次直查、不建 alternation、不克隆全表；`restore_response_with_spans` 的逐 token 回查改走它；全量 `restore`/`snapshot_t2p` 路径不变；补正确性 + 复杂度回归测试。
- **`X4`（LOW 死码）四项逐项删除（design D3）**：`decide_via_gateway`、`is_unlocked_by_password`、`SSE_SNAPSHOT_SECS`/`SSE_DELTA_SECS`、`SqliteOutcome.memory_only` 逐项删除并单独编译验证，测试引用迁移（非删除断言）、重导出与构造点同步更新。
- **`X5`（=`P8`，LOW）删不可达分支**：删除 `placeholder.rs:175-189`，补协议矩阵测试防回归。
- **`X6`（LOW）`PeerIp` 统一**：抽公共提取器（单一模块、统一返回类型、同禁代理头），替换两处实现。
- **`X7`（LOW）`replace_all_by_map` 抽取**：restore 与 redact_with_map 共用同一 map 替换函数，方向差异由入参承载。
- **`X8`（LOW）usage 回退链共享**：抽共享三级回退 helper，保留 delta 层差异。
- **`X9`（LOW）垫片收敛**：`spawn.rs:28` 改引 `crate::service::audit::{AuditHold, RequestKeepalive}`，`audit_hold` 收敛为仅重导出加废弃指引。

## Capabilities

### New Capabilities

- `code-quality-cleanup`：代码卫生收口契约——层声明与实现同字、配置模块尺寸红线与 `load_from` 拆分、日志级别纪律、热路径 `restore` 复杂度上界、死码零容忍（pub 项显式审计）、重复实现单一来源。

### Modified Capabilities

- 无。本 change 不修改任何既有 spec 需求；行为、阈值与 fail-closed 口径保持不动，`openspec/specs/` 现有能力契约不受影响。

## Findings 覆盖表

| ID | 严重度 | 修复要点 | task 编号 |
|:---|:-------|:---------|:----------|
| `A1` | MED | admin handler 搬移至 `handler/admin.rs`，`service` 零 `crate::state` 命名，声明与实现同字（design D1） | 1.1-1.3 |
| `A2` | MED | `load_from` 拆 `load_auth/load_storage/load_redaction/load_audit/load_llm`，行为保持，≤800 红线保持 | 2.1-2.3 |
| `A3` | LOW | 保留 spawn 并注释声明 panic 兜底与断连续跑语义，补 panic 测试（design D2） | 3.1-3.2 |
| `A4` | LOW | 4xx→warn、5xx→error，补级别断言测试 | 4.1-4.2 |
| `X3` | LOW（性能） | `restore_one` 单 token 直查，逐 token 回查走它，补正确性+复杂度回归（design D4） | 5.1-5.3 |
| `X4` | LOW（死码） | 四项逐项删除，测试引用迁移，单独编译验证（design D3） | 6.1-6.5 |
| `X5` | LOW（=`P8`） | 删 `placeholder.rs:175-189` 不可达段，补协议矩阵测试 | 7.1-7.2 |
| `X6` | LOW | `PeerIp` 提取器抽公共模块统一 | 8.1-8.2 |
| `X7` | LOW | 抽 `replace_all_by_map` 共用 | 9.1-9.2 |
| `X8` | LOW | 抽 usage 三级回退共享 helper，保留 delta 差异 | 10.1-10.2 |
| `X9` | LOW | `spawn.rs` 迁引 `service::audit::*`，垫片收敛 | 11.1-11.2 |

## 裁定为非问题清单（不改动）

以下 8 项经复核裁定为非问题，本 change 不改动，仅登记结论与理由（`J6`/`J8` 的问题面归 `veil-llm-protocol-hardening` 的 `N2`/`P1` 承接）：

| ID | 裁定理由 | 处置 |
|:---|:---------|:-----|
| `J1` | 三处 restore（`credential_vault.rs:131`/`pii/scope.rs:132`/`redaction/scope.rs:108`）是凭据/PII/组合三层不同安全语义，合并会混淆安全边界 | 不改动（保持） |
| `J2` | `legacy_ignored_detected`、admin `compat_granularity_for_range`/`normalize_verdict_compat` 均已接线（`load_from:258`、`events.rs:332/400`），非死码 | 不改动（保留） |
| `J3` | Responses 不注入 `stream_options` 是修正 Python 违规（Responses 仅接受 `include_obfuscation`），符合官方规范 | 不改动（保持） |
| `J4` | `AuditHold`/`RequestKeepalive` 已接线于 `pump/spawn.rs`，非死码（`X9` 只迁引用路径，不删符号） | 不改动（保留） |
| `J5` | HOP 8 项超集 + `host` 在 `forward_headers` 单独剥，为有意设计 | 不改动（保持） |
| `J6` | 非流 2xx 阻断体与非 2xx JSON 走完整链（README §7.2 声明）为有意行为；非 JSON 错误体问题归 `veil-llm-protocol-hardening` 的 `N2` | 不改动（保持，归属另案） |
| `J7` | usage 未记录 `reasoning_tokens`：仅影响指标、非合规问题 | 不改动（记录不改） |
| `J8` | openai-python 在 EOF 亦结束、非严格阻塞；`[DONE]` 问题归 `veil-llm-protocol-hardening` 的 `P1` | 不改动（保持，归属另案） |

## Non-Goals（显式）

- 不实现 `veil-llm-protocol-hardening` 承接的协议问题（`P1` `[DONE]`、`N2` 非 JSON 错误体）；本 change 仅登记 `J6`/`J8` 裁定与归属，不碰协议处理。
- 不放宽任何 fail-closed 语义；不改审计/脱敏/限流/用量口径与阈值；不合并 `J1` 三处 restore。
- 不改 `src/` 下任何实现代码、不改 `README.md`、不改其他 change 文件、不提交 commit；本 change 只交付规划 artifacts，实现留待 apply 阶段。
- 不追求全局 `service` 零 axum import 之外的额外分层改造（如 trait 全量泛化）；`A1` 以「service 零 `crate::state` 命名 + 声明同字」为完成线。

## Impact

- **新增文件**：`openspec/changes/veil-code-hygiene-closeout/` 下 proposal.md、design.md、specs/code-quality-cleanup/spec.md、tasks.md；apply 阶段才改 `src/`（新增 `src/handler/admin.rs` 或 `handler/admin/`、`src/config/env_parse.rs` 内部拆分、`src/service/credential_vault.rs`、`src/service/redaction/scope.rs`、`src/error.rs`、`src/service/llm_gateway/{placeholder,usage}.rs`、`src/service/audit_hold.rs`、`src/handler/llm/pump/spawn.rs`、`src/router.rs` 等）。
- **影响系统**：可维护性与架构声明真实性（分层）、热路径性能（SSE 每事件还原复杂度 O(K×N)→O(K)）、日志信噪比（4xx 不再按 error 告警）、死码面（lint 盲区显式清零）。
- **依赖**：`cargo fmt`/`cargo clippy`/`cargo test` + `scripts/check_doc_paths.py` + `scripts/api_conformance.py`；无新外部依赖。
