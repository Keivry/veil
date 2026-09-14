## Context

独立六维审计（2026-09-14）在凭据/认证/生命周期面确认 10 项偏差（`AUTH-1`–`AUTH-10`，见 proposal.md「Why」与覆盖表）。现状真相源：

- 写端点缺鉴权：`src/handler/credential.rs:238-255`（`/approve-hash-change` 无 `HeaderMap`）、`:174-180`（`/revoke` 无 `HeaderMap`）、`:100-148`（`/register-caller` 仅取 `x-source`）；`src/router.rs:49-52` 路由层仅有 `observability_gate`（只覆盖 `/_admin`），`:193-202` 测试断言无鉴权头返回 200。
- 紧急吊销客户端自证：`src/handler/credential.rs:193` `file_present` 取自请求体，`:220` 下传；`src/service/credential/vault_ops.rs:440` `if admin_ok || file_present || net_ok` 直接吊销。
- 未 enrolled 默认放行：`src/service/credential/auth.rs` 未匹配分支曾直接取 `Some(state.config().auto_approve)`（默认 `Allow`）；apply 后由 `unenrolled` 前置检查（`:257-274`，标记置位于 `:239-243`）接管——`AUTO_APPROVE=Deny` 才拒绝，其余一律转审批。
- 主密码缓存未清：`src/state.rs:189-195` `lock_cleanup` 仅 `keepass.clear_cache()`；`src/keepass.rs:250-254` 的 `clear_cache` 只清 `Database`；TPM 派生主密码缓存于 `src/keepass.rs:110-133` 闭包内的 `Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>`。
- 注册非原子：`src/service/credential/vault_ops.rs:277` 先落条目、`:285` 建单、`:293` `?` 失败不回滚。
- 吊销路径不可复用：`src/registry/store.rs:293-297` 对任何已存在 `caller_path`（含已吊销）返回 `Conflict 409`，而 `:299` 已释放已吊销条目的 `name`。
- KeePass 500 泄漏：`src/error.rs:77-79` 变体、`:118` 映射 500、`:141` `public_message` 原样回传 `message`。
- TTL 矛盾：`src/approval.rs:52` `PENDING_TTL_SECS=60` 且 `:84-98` 的 `sweep_expired` 无 waiter 感知；`src/service/credential/approval.rs:152-171` 的 `DecisionTable` 仅 `Decided` 受 60s TTL、`InFlight` 不清扫。
- `allow_mode` 静默失效：`src/config/env_parse.rs:96-109` 的 `AutoApprove::from_str` 不接受 `auto`/`manual`；`src/service/credential/register_map.rs:121-125` 解析失败静默回退。

Python 对照：`_credential.py:468/549/626/738` 四个写端点均先 `_require_auth`；紧急通道为 `req_token == admin_token or is_internal`（`:578`）；`_credential.py:674-676` 发送失败回滚注册；`_matrix.py:94-96` lock 置 `master_password=None`；`_registry.py:221` 未注册返回 `None` → 审批；`_credential.py:651,672` `allow_mode` 默认 `manual`、`auto` 触发三反应。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/`、`README.md`、`scripts/` 与其它 change 目录；不新增依赖；不虚构清单外发现。

## Goals / Non-Goals

**Goals：**

- 给出 `AUTH-1`–`AUTH-10` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「写端点三因子」「紧急吊销只认 admin/内网」「未 enrolled 默认审批」「lock 清主密码缓存」「注册原子回滚」「吊销路径复用语义」「KeePass 脱敏」「审批票 TTL 单一来源」「`allow_mode` auto/manual」收敛为 spec 契约，README §2/§5/§7.5/§8.4 与行为同批同步。
- 固化 `AUTH-7` 语义与 `AUTH-9` 时长口径，消除「文档声明与实现不符」与「静默失效」类缺陷。

**Non-Goals：**

- 不改三因子核验算法与字段口径，不新增认证因子；不改 Matrix 三态审批语义与 `202`/阻塞双模。
- 不引入回环免 token 逃生口（README §6.6 声明不变）。
- 不改本 change 之外的 `POL/TRN/RED/RUN/ARC/DOC/TST` 段发现；不改 Python 原仓。
- 不交付实现与文档改动（本 change 只规划）；不提交 commit。

## Decisions

### D1：抽出可复用三因子核验守卫，统一接线写端点（`AUTH-1`/`AUTH-3`）

**决策**：在凭据面抽出与 `credential_handler` 同源的异步三因子核验（`X-Get-Binary-Hash` + `X-Get-Binary-Secret`/`body.secret` + `body.auth.caller_hash`/`caller_path`），`/approve-hash-change`、`/register-caller`、`/revoke` 三处复用同一守卫；守卫在业务动作前执行，失败返回 `401`（缺失）/`403`（不一致）且不触碰注册表。`/approve-hash-change` 的 `ApproveHashChangeBody` 需补充 `auth` 字段（或从统一 `CredentialBody` 形态解析）。同步把 `src/router.rs:193-202` 的 200 断言改为鉴权拒绝断言。

**理由**：三处核验逻辑与 `/credential` 完全同源，复制会再次产生口径漂移；统一守卫保证「任一因子缺失/不一致 → 403」的 canonical `credential-api` 契约一致。业务动作与鉴权解耦，动作前失败即无副作用。

**备选**：每 handler 内联核验——重复且易漏，不采用；把鉴权下沉到路由层中间件——`/*` 通配会误伤 LLM 透传与无鉴权的 `GET /registrations`/`/health`，需按路径白名单，复杂度更高，不采用。

### D2：删除 `file_present` 自证通道（`AUTH-2`）

**决策**：删除 `EmergencyRevokeBody.file_present` 与 `emergency_revoke` 的 `file_present` 判据，紧急吊销只保留「有效管理 token」与「内网来源（TCP 远端判定）」两通道；未命中转常规审批。同步修订 README §7.5 与 canonical `credential-flow-parity`/`residual-closeout` 中「文件在位」表述。

**理由**：`file_present` 由客户端在请求体自证，服务端无任何探测，等价于「自报即可吊销」，是纯旁路缺陷；Python 原仓从无此概念（仅 token/内网）。最小改法是删除而非新增服务端探测——探测只会引入新的文件系统依赖与竞态，且「文件在位」本身不构成授权依据。

**备选**：改为服务端探测文件存在——「文件在位」不是可信授权信号，且需定义探测路径与权限，收益低、面更大，不采用。

### D3：未 enrolled 默认转审批；自动放行须显式配置且已注册（`AUTH-4`）

**决策**：`src/service/credential/auth.rs` 未匹配任何条目时置位 `unenrolled` 标记（`:239-243`），限流通过后由前置检查（`:257-274`）统一接管：`AUTO_APPROVE=Deny` 时拒绝，其余取值（含默认 `Allow`）一律走 `approval_dual_mode(..., "unenrolled_default_pending")` 转审批。未注册调用方不因全局 `AUTO_APPROVE` 默认值而放行；自动放行仅对已注册条目的 `decision` 分支生效。此为相对 README §2「未 enrolled 兼容放行」的**行为变更（BREAKING）**，随 README §2 同批声明。

**理由**：`AUTO_APPROVE` 默认 `Allow` 会让所有未注册调用方直接取得凭据，违背注册表白名单的防护意图；Python `_registry.py:221` 未注册即返回 `None` → 审批。自动放行的语义前提是「已注册且放行」，对未注册主体不应生效。

**备选**：仅改 `AUTO_APPROVE` 默认值为 `Pending`——会一并改变已注册但未显式配置条目的行为，面过大，不采用；未 enrolled 直接 `Deny`——比原仓更严且无审批补救通道，不采用。

### D4：lock 清除并零化 TPM 派生主密码缓存（`AUTH-5`）

**决策**：为 TPM 主密码缓存引入可清理句柄（如 `tpm_password_provider` 返回「provider + clear 句柄」，或把缓存移入 `RealKeePass` 可 `clear_cache` 触及的位置）；`lock` 链路在清 KeePass 会话之外调用该清理，`Zeroizing` 保证零化；`unlock` 走既有重新 TPM 解封路径。

**理由**：`lock` 的语义是「回到未解锁态」，主密码缓存残留使 `lock` 后无需 TPM 即可再次解锁，违背 TPM 密封的安全承诺；Python `_matrix.py:94-96` lock 即置 `master_password=None`。缓存当前被闭包捕获、外部不可达，必须引入清理点才能实现。

**备选**：不缓存主密码（每次取用都 TPM 解封）——TPM 单步超时 30s，性能不可接受，不采用；`lock` 时重建 provider——持有者是 `Arc<dyn Fn>`，无法替换，不采用。

### D5：注册审批发送失败原子回滚（`AUTH-6`）

**决策**：`register_caller_with_approval` 在 `submit_pending_with_branch` 失败（发送失败/取不到真实 `event_id`）时回滚刚落的条目，使注册表无孤儿且 `caller_path` 可重试。回滚方式与 D6 的复用语义对齐：优先「删除该条目」（`caller_path` 立即可重试）；若沿用软吊销回滚，则依赖 D6 允许已吊销路径复用。

**理由**：先落盘后建单的两步操作若无补偿，发送失败即留下 `disabled` 孤儿条目，占用 `caller_path` 且不可决；Python `_credential.py:674-676` 失败即 `_revoke_caller(reg_id)` 回滚。

**备选**：登记失败条目供后台清理——延迟且仍占键，不采用；先建单后落盘——send 需要 `reg_id`/条目信息，且失败时应无任何落盘更符合原子性，但改动面更大，留作 apply 时按实现最小化权衡。

### D6：吊销后 `caller_path` 允许复用（`AUTH-7` 语义固化）

**决策**：**允许**已吊销条目的 `caller_path` 重新注册（重新走注册审批），与已吊销 `name` 释放复用的既有语义（`src/registry/store.rs:299`）保持一致；重注册时条目按全新条目初始化（`enabled=false`、`revoked=false`、`old_hash` 宽限清空），不得继承已吊销条目的哈希/宽限。`src/registry/store.rs:293-297` 的判重改为仅对**未吊销**条目拒绝，已吊销路径放行。

**理由**：吊销是终态，但标识符（脚本路径）会被正常复用（脚本修复后重新注册）；永久封禁路径会与 `AUTH-6` 要求「回滚后 `caller_path` 可重试」直接冲突，并造成不可恢复的标识符耗尽。复用仍需 Matrix 审批，安全面不降低。

**备选**：保留 `409` 拒绝并文档化——与 `AUTH-6` 重试要求及 `name` 释放语义不一致，且无补救手段，不采用。

**安全权衡**：允许复用意味着曾吊销的恶意脚本路径可再次申请注册；但注册必经人工审批，且旧哈希宽限被清空，不构成自动放行回退面。

### D7：KeePass 内部错误对外脱敏（`AUTH-8`）

**决策**：`VeilError::KeePass` 的 `public_message` 改为固定通用文案（如「服务不可用」或「内部错误」），保留错误码 `E_KEEPASS`（或归并为 `E_INTERNAL`）供下游判别；完整 `message` 继续经 `tracing::error!` 落日志。响应体不得包含 KDBX 路径、解密异常等细节。

**理由**：`src/error.rs` 的既定口径是「500 系统一脱敏，不泄漏内部细节」（`:7`/`:17`/`:129`），`KeePass` 变体是唯一把 500 细节原样回传的例外，属口径破例；对内保留日志即可排障。

**备选**：把 KeePass 映射为 503 `Unavailable`——状态码语义变化影响下游，本次仅做文案脱敏，不采用。

### D8：审批票 TTL 口径单一来源（`AUTH-9` 时长决策）

**决策**：按「记录类别 + 是否有 waiter」区分，统一以一处常量为准：
- 凭据/注册/哈希变更类**存在阻塞等待者**的未决票：保留至阻塞超时 `300s`（`CREDENTIAL_APPROVAL_TIMEOUT_SECS`），SHALL NOT 被 60s 空闲清扫回收；
- 空闲/审计/解锁类**无等待者**的孤儿票：按 `60s` 上限清扫。

实现上令 `PendingApprovals` 的清扫对「有活跃 waiter / 凭据阻塞类」记录豁免 60s 回收（或让凭据类 pending 记录不再进入 60s 清扫表、改由 `DecisionTable` 的 `InFlight` 生命周期承载）。README §4/§8.4 的 60s/300s 两口径与实现对齐，`GET /health pending` 计数口径同步。

**理由**：README §4/§8.4 已声明「空闲票 60s、有阻塞等待者凭据类 300s 两口径并存」，但 `src/approval.rs:84-98` 的清扫对全部记录一律 60s，导致声明与实现矛盾；单一来源消除歧义。

**备选**：全局改 `300s`——空闲/审计/解锁孤儿票内存滞留变长，且偏离既有声明，不采用；全局保留 `60s` 并改文档为 60s——会让阻塞等待的凭据票在 60s 被回收，破坏 `300s` 阻塞语义，不采用。

### D9：`allow_mode` 接受 `auto`/`manual`（`AUTH-10`）

**决策**：`register_map::parse_register_allow_mode` 在既有三态别名之外接受 `auto` → `Allow`、`manual` → `Pending`；未知非空值保持既有「回退 `auto` 布尔」的兼容行为并补 `warn` 日志（或按 spec 显式返回 `400`）。与 Go `get register --auto`（发送 `allow_mode:"auto"`）及 Python 默认 `manual` 契约同步。

**理由**：Go 客户端与 Python 原仓均以 `auto`/`manual` 为一等值，Rust 侧静默丢弃是互操作缺陷；映射到既有三态语义即可，无需新枚举。未知值当前静默回退，补 warn 使失效可观测。

**备选**：新增 `Auto`/`Manual` 枚举变体——与既有三态重复，不采用；未知值一律 `400`——可能破坏历史调用方，故保留兼容回退但补告警。

### D10：文档同步清单（跨 `AUTH-2/4/5/9/10`）

**决策**：apply 阶段与行为同批更新：README §2（未 enrolled 兼容放行 → 默认审批，`AUTH-4`）、§5（Go 对接表 `allow_mode`/鉴权列，`AUTH-10`）、§7.5（紧急吊销 `file_present` 三通道 → admin/内网两通道，`AUTH-2`）、§8.4（lock 清理含主密码缓存 `AUTH-5`、审批票 TTL 两口径 `AUTH-9`）。canonical `credential-flow-parity`/`residual-closeout` 的冲突表述随归档同步。

**理由**：README 是部署与行为唯一入口（README 首段自述），行为变更不同批同步即产生文档-实现漂移；canonical spec 为本 change 之外文件，按项目惯例在归档时随 canonical 修订。

### D11：写端点部署密钥强制 fail-closed（`AUTH-11`）

**决策**：`/approve-hash-change`、`/register-caller`、`/revoke` 三处写端点使用的三因子守卫，在部署未配置部署密钥（`GET_BINARY_SECRET`/`CREDENTIAL_SECRET` 均为空）时 SHALL 直接 fail-closed：返回 `403`（`E_AUTH`）且不执行任何业务动作。实现上在 `src/service/credential/auth.rs` 新增 `verify_three_factor_write`（先校验部署密钥已配置，再委派既有 `verify_three_factor`），`src/handler/credential.rs::require_three_factor` 改委派该守卫。已配置部署密钥时行为与既有 `verify_three_factor` 完全一致。`POST /credential` 读路径不经该守卫，保持 Python 兼容语义。

**理由**：Oracle 复核确认 `verify_three_factor`（`auth.rs:83-122`）仅在 `get_binary_hash` 已配置时校验哈希、仅在 `credential_secret` 已配置时校验密钥；compat 默认（两者均空）下只核验攻击者可自报的 `body.auth.caller_hash`/`caller_path`，故三写端点仍实质未鉴权可调（P0 未闭环）。写操作可改配置、删条目、重定向哈希，必须 fail-closed；读路径按既定决策维持兼容。

**BREAKING / 迁移**：相对 Python 原仓对特权写端点为**有意偏离**（Python 四写端点均先 `_require_auth`，但 compat 部署下 Secret 因子同样可空跳过，故本仓更严）。compat 部署升级后若未配置 `GET_BINARY_SECRET` 或 `CREDENTIAL_SECRET`，三写端点将恒返 `403`；迁移须配置非空部署密钥，并与客户端 `X-Get-Binary-Secret`（或 `body.secret`）取值对齐。`/credential` 读路径不受影响。

**备选**：把强制逻辑并入 `verify_three_factor` 本体——会使 `/credential` 读路径一并变严，违反「读路径保持 Python 兼容」的既定决策，不采用；以 `GET_BINARY_HASH` 作为替代强制因子——哈希同样可被调用方自报且语义不同（完整性 vs 部署密钥），不采用。

## Risks / Trade-offs

- [`AUTH-1`/`AUTH-3` 鉴权收紧破坏既有测试与调用方] → `src/router.rs:193-202` 期望改为拒绝；三因子是既有 canonical 契约，README §5 已声明三因子，属修正而非新约束；补「无鉴权→拒绝」回归。
- [`AUTH-2` 移除 `file_present` 为 BREAKING] → 依赖该字段的旧调用方将转审批；README §7.5 与 canonical 同批声明；无服务端语义可保留，属安全修正。
- [`AUTH-4` 未 enrolled 默认由放行改审批为 BREAKING] → 旧部署若依赖兼容放行将转审批（更严，非更松）；README §2 显式声明迁移；需确认不影响已注册调用方。
- [`AUTH-5` lock 后重解锁需 TPM 解封] → 重解锁延迟增加（TPM 单步超时 30s），属安全/性能权衡；`unlock` 路径不变。
- [`AUTH-6` 回滚与 `AUTH-7` 复用语义耦合] → 若回滚用软吊销而 `AUTH-7` 不允许复用则回滚后仍不可重试；D5/D6 已对齐（允许复用），apply 时须同批验证。
- [`AUTH-7` 允许吊销路径复用] → 恶意路径可重申请，但必经人工审批且清空宽限；记录于 D6 安全权衡。
- [`AUTH-8` 500 文案脱敏] → 排障依赖日志；保留 `tracing::error!` 完整错误，不降低可观测性。
- [`AUTH-9` 凭据阻塞票 300s 内存滞留] → `DecisionTable` 已有 `DECISION_TABLE_MAX_ENTRIES=4096` 上界，内存有界；60s 空闲票照常回收。
- [`AUTH-10` 未知 `allow_mode` 兼容回退] → 补 warn 使静默失效可观测；若 spec 选择显式 `400` 需评估历史调用方。
- [`AUTH-11` compat 部署写端点恒 403（BREAKING）] → 迁移须配置 `GET_BINARY_SECRET`/`CREDENTIAL_SECRET`；读路径 `/credential` 不受影响；README §2/§5/§7.5 与 spec 同批声明。

## Migration Plan

1. 按 tasks 顺序落地：先鉴权（`AUTH-1`/`AUTH-3`/`AUTH-2`），再默认与生命周期（`AUTH-4`/`AUTH-5`/`AUTH-6`/`AUTH-7`），再脱敏与口径（`AUTH-8`/`AUTH-9`/`AUTH-10`），最后文档同步。
2. 每组独立 `cargo test`；README §2/§5/§7.5/§8.4 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：`AUTH-2`（移除 `file_present`）、`AUTH-4`（未 enrolled 默认转审批）与 `AUTH-11`（写端点部署密钥 fail-closed）为 BREAKING，由 README 声明；其余为安全修正或口径对齐。

## Open Questions

- 无。`AUTH-1`–`AUTH-10` 均已裁定（含 `AUTH-7` 复用语义与 `AUTH-9` 时长口径）。Go 客户端为外部仓，本 change 仅保证 Rust 侧接受 `auto`/`manual`；若 Go 侧另有发送值需扩展，在 apply 阶段按 spec「`allow_mode` 兼容 `auto` 与 `manual`」Scenario 补充并回记本 design。
