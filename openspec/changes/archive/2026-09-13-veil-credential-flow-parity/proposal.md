## Why

2026-09-13 凭据流水线六段（注册 → 审批 → 取用 → 哈希变更 → 吊销 → 锁定）独立审查确认 18 项相对原仓（Python `credential-proxy`）的缺失、缺陷与故意差异。其中两项审批链断链与三项并发/清理缺陷为功能性缺口：

- **审批链断链（高）**：注册/吊销直接落盘返回，不经 Matrix 审批（`C1`/`C2`，已复核 `src/service/credential/vault_ops.rs:181-237`）。注册条目 `enabled=false` 且无激活路径 → 条目长期 `disabled` 无人激活；吊销无需确认即可执行。
- **状态机缺口（中）**：哈希变更无三态落定（`C3`）；`POST /revoke {name}` 无 `name` 解析、重名不 409（`C5`）；Matrix `lock/forget` 只清审批单，口令缓存/KeePass 会话/token 映射无接线（`C6`）。
- **并发与清理缺陷（高/中）**：300s 阻塞审批票被 60s 孤儿清扫删除，批准在 60s 后无效（`C7`）；双 pending 表超时清理不对称致 `GET /health pending` 虚高（`C8`）；TPM 解封固定 `veil-tpm-PID` 目录，并发互覆中间对象（`C9`）。
- **迁移与语义漂移（中/低）**：生产 `load_from` 不接 Python 旧格式迁移（`C4`）；审批消息过度脱敏致审批人看不到批什么（`C10`）；限流维度、紧急吊销网段、注册表存储语义、`caller_path` 双必填四项需裁决（`C11`/`C13`/`C14`/`C16`）；旧哈希宽限为 Rust 正向修正需登记（`C12`）。
- **记录项（已合规）**：`/credential` 信封（`C15`）、时序安全比较（`C17`）、未 enrolled 兼容放行（`C18`）审计确认合规，本 change 核验测试并登记，不改行为。

真相源：`src/service/credential/vault_ops.rs`、`src/service/credential/approval.rs`、`src/service/credential/auth.rs`、`src/service/matrix/approval.rs`、`src/service/matrix/bot.rs`、`src/service/matrix/branch.rs`、`src/registry/store.rs`、`src/registry/migrate.rs`、`src/registry/entry.rs`、`src/handler/credential.rs`、`src/service/tpm.rs`、`src/approval.rs`、`src/auth.rs`、`src/config/custom_file.rs`。本 change 只规划（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 README。

引用契约：canonical `openspec/specs/credential-api/spec.md`（三因子/未 enrolled 放行）、`credential-approval-dual-mode`（202/300s 双模）、`approval-hold-parity`（挂起与审批语义）、`registry-parity`、`matrix-approval-closure`；`C1`/`C2`/`C11`/`C13`/`C14`/`C16` 的裁决依据见 design.md 对应 Decision。

## What Changes

- **`C1` 注册审批链恢复**：`register_caller_extended` 注册后建 Matrix 审批单（`MatrixBranch::Register`，携带 `reg_id`），复用既有双模（默认 `202` 抛单、`CREDENTIAL_BLOCK_WAIT=1` 时 300s 阻塞等 reaction）；三态落定：🔓 保持 `disabled` / ✅ `enabled=true` / ❎ 与超时按吊销（`revoked=true`，fail-closed）；补三态与超时测试。
- **`C2` 吊销审批确认恢复**：常规 `revoke_caller` 建审批单，✅ 后执行吊销；❎/超时保持现状不吊销（吊销为破坏性操作，避免被滥用为 DoS）；紧急吊销旁路（管理 token/文件在位/内网）保留并文档化。
- **`C3` 哈希变更三态与 handler 契约**：`approve_hash_change` 落定语义补三态（🔓 保持自动 / ✅ 降级人工 `manual` / ❎ 禁用），三态均写 `old_hash` 宽限；`approve_hash_change_handler` 接受 `reg_id`/`reaction` 入参（缺省回退既有 `caller_path`/`new_hash` 语义）；补三态测试。
- **`C4` 生产旧格式迁移接入**：`CallerRegistry::load_from` 接入 Python 旧格式（`version/callers/allowed_entries`）一次性迁移，成功后写回新格式并保留 `.bak`；`migrate_python_registry` 由生产路径引用；补旧格式样例测试。
- **`C5` 按名吊销/重名 409**：注册判重补 `name`（非空且与现有条目重名 → `Conflict`）；`RevokeBody` 增 `name` 字段并纳入定位顺序；补重名 409 与按名吊销测试。
- **`C6` lock/forget 清理接线**：Matrix 文本指令处理接入网关侧清理——`lock` 清口令缓存 + KeePass 会话（`_kp=None` 对等）+ pending + PII scope；`forget` 清 token 映射并回传真实条数；补「lock 后取不到凭据」测试。
- **`C7` 审批票 TTL 统一**：孤儿清扫不再删除存在阻塞等待者的未决票（按分支 TTL 保留，`Register`/`Credential` 300s）；补「建单 60s 后仍可决」测试。
- **`C8` 双 pending 表原子清理**：超时/拒绝/落定路径同一函数清理内存侧与矩阵侧 pending，`GET /health pending` 计数即时一致；补计数一致性测试。
- **`C9` TPM 并发隔离**：`unseal` 每次调用唯一临时目录（pid + 时间戳 + 随机），成功/失败均清理；补并发解封隔离测试。
- **`C10` 审批消息可读上下文**：审批摘要补条目/字段/调用方元数据（敏感值仍脱敏、不落消息）；补消息内容测试。
- **`C11` 限流维度裁决（保留 + 文档化）**：维持按调用方（`caller_path:caller_hash`）2s 与注册按 `source` 1s，登记为相对 Python 全局单桶的有意差异，补跨调用方隔离测试；备选回退条款记 design D11。
- **`C12` 旧哈希宽限修正登记**：文档化 Rust 真实宽限（`old_hash_expires_at = now + 3600`）为对 Python 死码的修正；补宽限内可用/超时失效边界测试。
- **`C13` 紧急吊销网段裁决（保留 + 文档化）**：维持回环/IPv6/链路本地/ULA/CGNAT + `file_present` 放行，README §7.5 列明网段清单；补各网段测试。
- **`C14` 注册表存储语义裁决（推荐组合）**：损坏 fail-closed 拒加载（不回落空表）；`write_atomic` 补 fsync；`BTreeMap` 稳定排序与「排序取末位 `.kdbx` + 仅同名 `.key`」文档化；补完整性/落盘/顺序测试。
- **`C15`/`C16`/`C17`/`C18` 登记与核验**：`/credential` 信封、`caller_path`+`caller_hash` 双必填（维持 + 有意收紧登记）、`ct_eq`/`secret_eq` 时序安全、未 enrolled 兼容放行——核验测试在位并登记；`C16` 补缺 `path` 403 测试。
- **文档同步（apply 阶段）**：README §3/§4（限流维度）、§5（name 吊销/409）、§6.7（注册审批）、§7.5（吊销/网段/消息/双必填）随行为同批更新。

## Capabilities

### New Capabilities

- `credential-flow-parity`：凭据流水线六段的目标契约——注册/吊销/哈希变更审批链与三态语义、生产旧格式迁移、按名吊销与重名冲突、lock/forget 清理接线、审批票 TTL 与双 pending 原子清理、TPM 并发隔离、审批消息可读上下文、限流维度、旧哈希宽限、紧急吊销网段、注册表存储语义，以及四项已合规登记项。

### Modified Capabilities

- 无。本 change 新增 capability；canonical `credential-api`/`credential-approval-dual-mode`/`approval-hold-parity` 等既有条款不删不改，本 spec 仅补齐其未覆盖的审批落定/清理/并发面；README 随 apply 阶段同步。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `C1` | HIGH（缺失/裁决） | 注册接入审批链，三态 🔓保持 `disabled`/✅启用/❎吊销，超时按吊销；复用双模 `202`/300s；`reg_id` 落定契约 | 1.1、1.2、1.3 |
| `C2` | HIGH（缺失/裁决） | 常规吊销恢复 Matrix 确认，✅执行/❎·超时保持；紧急吊销旁路保留 | 2.1、2.2 |
| `C3` | MED（缺失） | 哈希变更三态（保持自动/降级 manual/禁用）+ `reg_id`/`reaction` handler 契约 | 3.1、3.2、3.3 |
| `C4` | MED（缺失） | `load_from` 接旧格式一次性迁移 + `.bak` + 写回新格式；旧样例测试 | 4.1、4.2 |
| `C5` | MED（缺失） | `name` 非空重名 409 + `POST /revoke {name}` 定位 | 5.1、5.2 |
| `C6` | MED（缺失） | lock/forget 网关侧清理接线（口令缓存/`_kp`/pending/PII scope/token 映射） | 6.1、6.2 |
| `C7` | HIGH（bug） | 清扫保留阻塞票（按分支 TTL），300s 阻塞 60s 后仍可决 | 7.1、7.2 |
| `C8` | MED（bug） | 双 pending 表终态原子清理，`/health pending` 即时一致 | 8.1、8.2 |
| `C9` | HIGH（bug） | TPM 每次调用唯一临时目录（或等价隔离），并发不互覆 | 9.1、9.2 |
| `C10` | MED（divergent） | 审批消息补条目/字段/调用方上下文；敏感值不落消息 | 10.1、10.2 |
| `C11` | MED（裁决） | 裁决：保留按调用方维度并文档化为有意差异；备选回退全局单桶 | 11.1、11.2 |
| `C12` | LOW（divergent） | 登记宽限修正（真实 `now+3600`），补边界测试 | 12.1、12.2 |
| `C13` | MED（裁决） | 裁决：保留扩展内网网段 + `file_present`，README §7.5 列清单 | 13.1、13.2 |
| `C14` | MED（裁决） | 裁决：fail-closed + fsync + 稳定排序 + 仅同名 `.key`；逐项登记与测试 | 14.1、14.2 |
| `C15` | 记录（COMPLIANT） | `/credential` 信封 `{ok,credential}` 已在 README §5；核验测试并登记 | 15.1 |
| `C16` | 记录（裁决） | 裁决：维持双必填并登记为有意收紧；补缺 `path` 403 测试 | 15.2 |
| `C17` | 记录（COMPLIANT） | `ct_eq`/`secret_eq` 时序安全优于 Python 明文比较；登记正向差异 | 15.3 |
| `C18` | 记录（COMPLIANT） | 未 enrolled 兼容放行且 Secret 仍校验；核验登记 | 15.3 |

## Non-Goals（显式）

- **不改 `src/`、`tests/` 与 README**：本 change 只交付规划 artifacts（proposal/design/spec/tasks），实现与文档改动留待 apply 阶段；不改 `openspec/` 下其他 change 与 canonical specs；不提交 commit。
- **不做 `C1`/`C2` 的 BREAKING Non-Goal 方案**：裁决为恢复审批链（见 design D1/D2），不以「文档化直接生效」替代；直接生效语义与 parity 目标冲突且注册条目无激活路径。
- **不回退 `C11`/`C13` 的现状到 Python 原样**：裁决保留现有更安全/更可用的维度与网段，仅文档化为有意差异；若运维要求严格 parity 另立 change。
- **不引入新依赖、不改 wire 枚举**：`AutoApprove` 的 `true/false/none` 三值不变（manual 映射 `Pending`/`none`）；`/register-caller` 既有字段只增不删；双必填维持。
- **不碰审批审计口径**：`AUDIT_TIMEOUT` 90s 与凭据 300s 分表不变；不合并两类审批分支；不改 `APPROVAL_WHITELIST` 语义。
- **不处理窗口外发现**：审查未列的其他漂移不在本 change 范围；`C15`/`C17`/`C18` 仅登记不改行为。

## Impact

- **新增文件**：`openspec/changes/veil-credential-flow-parity/` 下 `proposal.md`、`design.md`、`specs/credential-flow-parity/spec.md`、`tasks.md`（`.openspec.yaml` 已就位）。
- **apply 阶段改动面**：`src/service/credential/vault_ops.rs`、`src/service/credential/approval.rs`、`src/service/credential/auth.rs`、`src/service/matrix/approval.rs`、`src/service/matrix/bot.rs`、`src/service/matrix/branch.rs`、`src/registry/store.rs`、`src/registry/migrate.rs`、`src/registry/entry.rs`、`src/handler/credential.rs`、`src/service/tpm.rs`、`src/approval.rs`、`src/handler/mod.rs`（如 health 计数清理接线）、对应单测与 `README.md` §3/§4/§5/§6.7/§7.5。
- **影响系统**：凭据注册/吊销/哈希变更的审批落定与激活语义；审批票生命周期与 health 计数；TPM 并发解封正确性；注册表旧格式升级路径；凭据限流与紧急吊销豁免面。
- **依赖**：无新依赖；复用既有 Matrix 审批网关、注册表与 TPM 设施。
