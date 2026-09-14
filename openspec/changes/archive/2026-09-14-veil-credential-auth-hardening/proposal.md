## Why

独立六维审计（2026-09-14，凭据/认证/生命周期面）确认 10 项鉴权与生命周期偏差（`AUTH-1`–`AUTH-10`），其中 2 项 P0（无鉴权写端点、客户端自证放行）、3 项 P1，违反既有 canonical spec 声明或 Python 原仓契约：

- **`AUTH-1`（P0）`/approve-hash-change` 无任何鉴权**：`src/handler/credential.rs:238-255` 的 handler 签名无 `HeaderMap`、无鉴权调用；`src/service/credential/vault_ops.rs:461-515` 仅校验 `entry_mode` 与 `key/new_hash` 非空；`src/router.rs:49-52` 唯一路由层中间件 `observability_gate` 只覆盖 `/_admin`。未鉴权请求可直接改写注册表哈希（注册劫持）。Python 对照 `_credential.py:738` 先走 `_require_auth`（三因子）。
- **`AUTH-2`（P0）`/revoke/emergency` 的 `file_present` 为客户端自证**：`src/handler/credential.rs:193` 该字段直接取自请求体，`:220` 原样下传；`src/service/credential/vault_ops.rs:440` `if admin_ok || file_present || net_ok` 据此直接吊销；全仓无服务端文件探测。伪造 `{"file_present":true}` 即可绕过审批。Python `_credential.py:549` 先 `_require_auth`，紧急通道为 `admin_token` 或内网（`:578`），无 `file_present` 概念。
- **`AUTH-3`（P1）`/register-caller`、`/revoke` 无三因子鉴权**：`src/handler/credential.rs:100-148` 的注册 handler 仅用 `HeaderMap` 取 `x-source`、`:174-180` 的吊销 handler 签名连 `HeaderMap` 都无。Python `_credential.py:626`/`:468` 均有 `_require_auth`。
- **`AUTH-4`（P1）未 enrolled 调用方默认 `AUTO_APPROVE=true` 直接放行**：`src/service/credential/auth.rs:184-186` 未匹配任何注册条目时 `Some(state.config().auto_approve)`，默认配置即放行。Python `_registry.py:221` 未注册返回 `None` → 转审批。
- **`AUTH-5`（P1）`lock` 不清 TPM 派生主密码缓存**：`src/state.rs:189-195` 的 `lock_cleanup` 调 `keepass.clear_cache()`，但 `src/keepass.rs:250-254` 的 `clear_cache` 只清 KeePass `Database` 缓存；TPM 派生主密码缓存在 `src/keepass.rs:110-133` 的闭包 `Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>` 中，`lock` 后仍命中，unlock 无需重新 TPM 解封。Python `_matrix.py:94-96` lock 时置 `master_password=None`。
- **`AUTH-6`（P1）注册审批发送失败留孤儿条目**：`src/service/credential/vault_ops.rs:277` 先落条目、`:285` 再建单，`:293` 的 `?` 在发送失败时直接冒泡且不回滚，注册表残留 `disabled` 孤儿。Python `_credential.py:674-676` 发送失败即 `_revoke_caller(reg_id)` 回滚。
- **`AUTH-7`（P2）已吊销 `caller_path` 不可复用**：`src/registry/store.rs:293-297` 对 `entries.contains_key(caller_path)`（含已吊销）一律 `Conflict 409`，而已吊销条目的 `name` 已释放可复用（`:299`），两键语义不一致。需对照 Python 行为决策后固化。
- **`AUTH-8`（P2）KeePass 路径 500 回传内部细节**：`src/error.rs:77-79` 的 `KeePass` 变体映射 500（`:118`），且 `public_message`（`:141`）原样回传 `message`，KDBX 路径/解密失败等内部细节进入响应体。
- **`AUTH-9`（P2）`PendingApprovals` 内存清扫恒 60s 与 README §8.4（凭据阻塞票 300s）矛盾**：`src/approval.rs:52` `PENDING_TTL_SECS=60`，`:84-98` 的 `sweep_expired` 不区分 waiter 一律回收超 60s 记录；`src/service/credential/approval.rs:152-171` 的 `DecisionTable` 仅 `Decided` 条目受 60s TTL、`InFlight` 不受清扫。README §8.4 声明「有阻塞等待者凭据类票在其自身 300s 阻塞超时前不被回收」，与 `PendingApprovals` 的实际清扫行为不一致。
- **`AUTH-10`（P2）Go `get register --auto` 静默失效**：`src/config/env_parse.rs:96-109` 的 `AutoApprove::from_str` 只接受 `true/1/yes`、`false/0/no`、`none/pending/matrix`，不接受 Go 客户端发送的 `auto`/`manual`；`src/service/credential/register_map.rs:121-125` 解析失败后静默回退 `auto` 布尔或 `None`。Python `_credential.py:651,672` 以 `manual` 为默认、`auto` 触发 `🔓/✅/❎` 三反应。

真相源为上述 `src/` 文件、Python 原仓对应文件与 `README.md` §2/§5/§7.5/§8.4。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/`、`README.md`、`scripts/`；实现与文档同步留待 apply 阶段。

引用规范：`openspec/specs/credential-api/spec.md`（三因子任一缺失/不一致 SHALL 返回 403）、`openspec/specs/credential-flow-parity/spec.md`（注册/吊销/哈希变更审批链与紧急吊销三通道）、`openspec/specs/three-factor-decoupling/spec.md`（三因子独立校验）、`openspec/specs/residual-closeout/spec.md`（紧急吊销转审批闭环）。

## What Changes

- **`AUTH-1` 哈希变更接入三因子**：`approve_hash_change_handler` 增加 `HeaderMap` 抽取并按 `/credential` 同链路核验三因子（`X-Get-Binary-Hash` + `X-Get-Binary-Secret`/`body.secret` + `body.auth.caller_hash`/`caller_path`）；未鉴权返回 401/403 且不执行哈希变更；修正 `src/router.rs:193-202` 无鉴权头断言 200 的错误期望为拒绝；保留 `KeepAuto`/三态落定语义不变。
- **`AUTH-2` 移除 `file_present` 自证通道**：删除 `EmergencyRevokeBody.file_present` 与服务端 `file_present` 判据（或改为服务端文件探测），保留 admin token / 内网来源两通道；伪造 `{"file_present":true}` 不再放行。同步 README §7.5 三通道表述与相关 canonical spec 引用。
- **`AUTH-3` 注册/吊销接入三因子**：`register_caller_handler`/`revoke_handler` 增加三因子核验，未鉴权拒绝；保留 Matrix 审批语义（`Register` 分支、`202`/阻塞双模）不变。
- **`AUTH-4` 未 enrolled 默认转审批**：`src/service/credential/auth.rs` 未匹配分支置 `unenrolled` 标记（`:239-243`），限流后由前置检查（`:257-274`）统一接管——`AUTO_APPROVE=Deny` 拒绝，其余（含默认 `Allow`）一律转审批；自动放行仅对已注册条目的 `decision` 分支生效。
- **`AUTH-5` lock 清除并零化主密码缓存**：`lock` 链路在清 KeePass 会话的同时清除 TPM 派生主密码缓存（`Zeroizing` 零化），unlock 需重新经 TPM 解封；补回归测试。
- **`AUTH-6` 注册审批发送失败回滚**：`register_caller_with_approval` 在建单/发送失败时回滚已落条目（删除或置吊销），`caller_path` 保持可重试；补失败注入回归测试。
- **`AUTH-7` 吊销后 `caller_path` 复用语义固化**：按 Python 行为与一致性原则决策（允许复用重新注册，或保留 409 但文档与错误信息明示），决策写入 design，行为与文档同批落地。
- **`AUTH-8` KeePass 500 脱敏**：`VeilError::KeePass` 对外只返回通用错误（如 `内部错误`/`E_KEEPASS` 固定文案），内部细节仅进日志；补响应体不含内部实现信息的断言。
- **`AUTH-9` 审批票 TTL 口径统一**：按 README §8.4/§4 统一（凭据/注册/哈希变更类阻塞票 300s、空闲/审计/解锁类 60s）或按语义拆分并明确单一来源；同步 README §4/§8.4 与 canonical spec 引用；补票存活时长与文档一致的回归。
- **`AUTH-10` `allow_mode` 接受 `auto`/`manual`**：`register_map::parse_register_allow_mode` 映射 `auto`→放行、`manual`→人工审批（或对未知值显式报错而非静默回退）；与 Go `get register --auto` 契约同步；补映射回归。
- **`AUTH-11` 写端点部署密钥强制 fail-closed（P0，Oracle 复核补充）**：`verify_three_factor` 在 `get_binary_hash`/`credential_secret` 均未配置的 compat 默认下只核验调用方可自报字段，三写端点仍实质未鉴权；新增 `verify_three_factor_write` 使 `/approve-hash-change`、`/register-caller`、`/revoke` 在未配置部署密钥时 `403 E_AUTH` 且动作前失败，已配置时行为不变；`/credential` 读路径保持 Python 兼容。
- **文档同步**：README §2（未 enrolled 兼容放行口径 + 写端点 fail-closed）、§5（Go 对接表 `allow_mode`/鉴权列与写端点前置）、§7.5（紧急吊销 `file_present` 表述 + 写端点鉴权前置）、§8.4（lock 清理与审批票 TTL）与修复后行为同批更新。

## Capabilities

### New Capabilities

- `credential-auth-hardening`：凭据面鉴权与生命周期契约——无鉴权写端点接入三因子、紧急吊销仅认 admin token/内网、未 enrolled 默认转审批、lock 清除 TPM 主密码缓存、注册审批发送失败原子回滚、吊销后 `caller_path` 复用语义、KeePass 500 脱敏、审批票 TTL 口径单一来源、`allow_mode` 的 `auto`/`manual` 兼容。

### Modified Capabilities

- 无（本 change 新增 capability）。既有 `openspec/specs/credential-flow-parity/spec.md`「吊销审批确认 / 紧急吊销旁路」、`openspec/specs/residual-closeout/spec.md`「紧急吊销转审批」三通道表述与 README §7.5 中与本 spec 冲突的 `file_present` 旧口径，在 apply/归档阶段按 `openspec/changes/veil-credential-auth-hardening/specs/credential-auth-hardening/spec.md` 为准同步并随 canonical 修订，不作为本 change 的 MODIFIED delta。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `AUTH-1` | P0 | `approve_hash_change_handler` 接入三因子；未鉴权 401/403 不落变更；修正 router 测试期望 | 1.1、1.2、1.3 |
| `AUTH-2` | P0 | 移除 `file_present` 客户端自证通道（或改服务端探测）；保留 admin/内网；伪造不放行 | 2.1、2.2、2.3 |
| `AUTH-3` | P1 | `register_caller_handler`/`revoke_handler` 接入三因子，未鉴权拒绝，保留审批语义 | 1.2 |
| `AUTH-4` | P1 | 未 enrolled 默认转审批/拒绝；显式配置且已注册才自动放行 | 3.1、3.2 |
| `AUTH-5` | P1 | lock 清除并零化 TPM 派生主密码缓存；unlock 重新解封 | 4.1、4.2、4.3 |
| `AUTH-6` | P1 | 注册审批建单/发送失败回滚条目；`caller_path` 可重试 | 5.1、5.2 |
| `AUTH-7` | P2 | design 固化吊销后 `caller_path` 复用语义；行为+文档一致 | 6.1、6.2 |
| `AUTH-8` | P2 | KeePass 500 对外通用错误，细节仅日志 | 7.1、7.2 |
| `AUTH-9` | P2 | 审批票 TTL 口径单一来源（60s/300s 语义拆分或统一）；README §4/§8.4 同步 | 8.1、8.2、8.3 |
| `AUTH-10` | P2 | `allow_mode` 接受 `auto`/`manual`（或显式报错）；Go 契约同步 | 9.1、9.2 |
| `AUTH-11` | P0（Oracle 复核补充） | 三写端点三因子守卫 fail-closed：未配置部署密钥 `403 E_AUTH` 且无动作；读路径不变；BREAKING + 迁移 | 11.1、11.2、11.3、11.4、11.5、11.6 |

## Non-Goals（显式）

- **不改三因子核验算法本身**：沿用既有 HMAC 等长比较与 `X-Get-Binary-Hash`/`X-Get-Binary-Secret`/`body.auth.caller_hash`/`caller_path` 字段口径，不新增认证因子。
- **不改 Matrix 审批三态语义**：注册/吊销/哈希变更的 `🔓/✅/❎` 落定与 `202`/阻塞双模口径保持；`AUTH-5` 仅加清理，不改 unlock 交互。
- **不迁移 Python 回环免 token 语义**：`AUTH-4` 只把未 enrolled 默认由放行改为审批/拒绝，不引入新的免鉴权逃生口（README §6.6 声明不变）。
- **不改 `src/`、`tests/`、`README.md`、`scripts/` 与任何其它 `openspec/changes/*` 目录**：本 change 只交付规划 artifacts，实现与文档改动留待 apply 阶段；不提交 commit。
- **不虚构清单外发现**：仅覆盖 `AUTH-1`–`AUTH-10`，不并入 `POL/TRN/RED/RUN/ARC/DOC/TST` 段发现。

## Impact

- **新增文件**：`openspec/changes/veil-credential-auth-hardening/proposal.md`、`design.md`、`specs/credential-auth-hardening/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`src/handler/credential.rs`（三因子接线、`file_present` 移除、`auth` 抽取）、`src/service/credential/vault_ops.rs`（注册回滚、紧急吊销口径、哈希变更核验）、`src/service/credential/auth.rs`（未 enrolled 默认）、`src/service/credential/register_map.rs` 与 `src/config/env_parse.rs`（`allow_mode` 映射）、`src/state.rs` 与 `src/keepass.rs`（lock 缓存清理）、`src/approval.rs` 与 `src/service/credential/approval.rs`（TTL 口径）、`src/error.rs`（KeePass 脱敏）、`src/registry/store.rs`（`caller_path` 复用语义）、`src/router.rs`（测试期望）、对应单测与 e2e、`README.md` §2/§5/§7.5/§8.4。
- **影响系统**：凭据面写端点鉴权、紧急吊销旁路可信度、未注册调用方默认行为、lock/unlock 主密码生命周期、注册审批原子性、审批票内存有界与文档一致性、Go 客户端互操作。
- **依赖**：无新依赖；仅既有 `axum`、`serde`、`zeroize`、`tokio` 与测试设施。
