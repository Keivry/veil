## Context

2026-09-13 凭据流水线六段独立审查确认 18 项偏差（`C1`–`C18`，见 proposal 覆盖表）。现状真相源与证据：

- **审批链断链**：`register_caller_extended`（`src/service/credential/vault_ops.rs:181-224`）与 `revoke_caller`（`:226-237`）直接内存改 + 落盘返回，零 Matrix 交互；注册条目 `enabled=false`（`src/registry/store.rs:251-264`），全仓无「注册后启用」调用路径（`set_enabled` 仅测试与 `approve_hash_change` 调用）→ 条目长期 `disabled`（`C1`）。Python `_credential.py:617-721` 注册后等待 Matrix 300s 三态（🔓保持 disabled/✅启用/❎吊销，超时自动吊销）；`_credential.py:459-534` 吊销需 Matrix 确认（`C2`）。
- **哈希变更三态缺失**：`approve_hash_change_with_script_sha256`（`src/registry/store.rs:292-313`）仅更新 hash/宽限/`enabled=true`，不改 `allow_mode`；`approve_hash_change_handler`（`src/handler/credential.rs:294`）仅收 `caller_path`/`new_hash`。Python `_registry.py:283-312`（🔓保持自动/✅降级 manual/❎禁用）+ handler 契约（`_credential.py:725-774`，`reg_id`/`reaction`）（`C3`）。
- **迁移未接线**：`load_from`（`src/registry/store.rs:167-185`）按新 `RegistryFile` 直接 `Err`；`migrate_python_registry`（`src/registry/migrate.rs:21-122`）模块级 `#[cfg(test)]` gating，生产零引用（`C4`）。
- **name 语义缺失**：注册判重仅 path（`src/registry/store.rs:244-250`），`RevokeBody` 无 `name`（`src/handler/credential.rs:280-299`）→ `POST /revoke {name}` 404、重名不 409（`C5`）。
- **lock/forget 未接线**：`handle_text_command_full`（`src/service/matrix/bot.rs:170-201`）只清审批单，注释明示网关侧须清口令缓存 + KeePass 会话 + PII scope / token 映射（`:162-169`），生产零调用（`C6`）。
- **审批票冲突**：阻塞等 300s（`src/service/credential/approval.rs:76-77`）vs 孤儿清扫 60s 删未决单（`src/service/matrix/approval.rs:233-240`，`ORPHAN_SWEEP_SECS=60`）→ 60s 后批准无效（`C7`）；双 pending 表（内存 `PendingApprovals` + 矩阵 `MatrixApproval::pending`）超时仅删矩阵侧（`matrix/approval.rs:217`），内存侧等 60s sweep（`src/approval.rs:83-97`）→ `GET /health pending`（`src/handler/mod.rs:26`）虚高（`C8`）。
- **TPM 并发互覆**：`unseal` 固定 `veil-tpm-{pid}` + 固定 `primary.ctx`/`sealed.ctx`（`src/service/tpm.rs:173-201`）→ 并发解封互覆；Python `_tpm.py:33-58` 每调用唯一临时目录（`C9`）。
- **消息/限流/宽限/网段/存储漂移**：审批消息仅 `reason::key`（`src/service/credential/approval.rs:42`）vs Python 含条目/字段/调用方（`C10`）；Rust 按 `caller_path:caller_hash` 2s（`src/service/credential/auth.rs:192-197`）+ 注册按 `source` 1s（`src/service/credential/vault_ops.rs:201-206`）vs Python 全局单桶 2s（`C11`）；Rust 真置 `now+3600`（`src/registry/store.rs:304-306`，`src/registry/entry.rs:40`）vs Python 宽限死码（`C12`）；`is_private_ip`（`src/auth.rs:44-68`）含回环/链路本地/CGNAT/IPv6 + `file_present`（`vault_ops.rs:239-258`）vs Python 三前缀（`C13`）；损坏 fail-closed（`store.rs:177-181`）、缺 fsync（`store.rs:115-140`）、`BTreeMap` 排序、仅同名 `.key`（`src/config/custom_file.rs:14-42`）vs Python fail-open/插入序/首个 `.key`（`C14`）。
- **已合规登记**：`/credential` 信封（`src/handler/credential.rs:32-39`，README §5）（`C15`）；`caller_path`+`caller_hash` 双必填（`src/service/credential/auth.rs:89`，canonical `credential-api` 已锁）（`C16`）；`ct_eq`/`secret_eq`（`src/auth.rs:11-37`）（`C17`）；未 enrolled 兼容放行（`src/service/credential/auth.rs:184-186`，README §2）（`C18`）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/`、README；裁决项（`C1`/`C2`/`C11`/`C13`/`C14`/`C16`）须给出推荐决策 + 理由 + 备选。

## Goals / Non-Goals

**Goals：**

- 给出 `C1`–`C18` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证；每个 ID 在 spec 有行为契约（记录项为登记契约）、在 tasks 有 ≥1 任务。
- 恢复注册/吊销/哈希变更审批链与三态落定，使「已注册但未审批」不再是终态死角；修复审批票 TTL、双表清理、TPM 并发三类缺陷。
- 把 `C11`/`C13`/`C14`/`C16` 的裁决结论固化进 design 与 spec/README（有意的差异也要可追溯），避免后续 change 静默漂移。

**Non-Goals：**

- 不实现 BREAKING Non-Goal 方案（`C1`/`C2` 不选「文档化直接生效」）；不改 `AutoApprove` wire 三值；不改 `/register-caller` 既有字段。
- 不改三因子校验原语与未 enrolled 放行（`C17`/`C18` 仅登记）；不改审计 90s / 凭据 300s 分表；不引入新依赖。
- 不处理窗口外发现；`C15`/`C17`/`C18` 不改行为，仅核验测试与登记。

## Decisions

### D1：`C1` 注册审批链恢复 + 三态超时口径（裁决）

**决策**：恢复审批链。`register_caller_extended` 成功写内存+落盘后，建 `MatrixBranch::Register` 审批单（带 `reg_id`：注册条目稳定标识），复用既有双模：默认 `202` 抛单（与 §6.7 已声明口径一致），`CREDENTIAL_BLOCK_WAIT=1` 时阻塞等待 300s。三态映射 `ReactionOutcome::Applied { approved, auto }`（`src/service/matrix/branch.rs:154-174`）：

- `🔓` = `(true, true)` → 保持 `disabled`（不激活）；
- `✅` = `(true, false)` → `set_enabled(true)`；
- `❎` = `(false, _)` 与等待超时 → `revoked=true`（fail-closed，Python「超时自动吊销」等价）。

**理由**：不恢复则注册条目永远 `disabled` 且无支持路径可激活（只能手改注册表文件），违反 parity 目标；Python 的审批链是「未审注册不得生效」的安全门。复用双模而非严格阻塞，是为与既有 `CREDENTIAL_BLOCK_WAIT` 声明（README §6.7）保持一致，避免为注册单独引入第三种模式。三态中缺省（🔓）保持最小暴露面，❎/超时吊销保证未决注册不会悬挂为可用状态。

**备选**：① 文档化 BREAKING Non-Goal（保留直接生效）——把功能死角写成契约，运维无恢复手段，与 change 主题冲突，不采用；② 严格复刻 Python 同步阻塞 300s（忽略双模）——回退既有公开声明且拖死长连接，不采用；③ 三态中 `❎` 仅保持 disabled 不吊销——注册条目可能永久驻留 `disabled` 垃圾，且在途注册无人处置，不采用。

### D2：`C2` 吊销审批确认（裁决）

**决策**：常规 `revoke_caller` 改为经 Matrix 确认：建单（`reg_id`/`caller_path`，复用 `MatrixBranch::Register` 的三态映射），`✅` 后执行 `revoked=true`；`❎` 与超时 **不吊销、保持现状**。紧急吊销旁路（管理 token / 文件在位 / 内网）不变。`MatrixBranch::from_reason` 补「吊销/revoke」到 `Register` 分支的映射（否则 reason 不含既有关键词会落 `Unknown` 被忽略）。

**理由**：吊销是破坏性动作；若无人确认时自动执行，任意调用方可用伪造吊销请求对他人做 DoS（Python 注册超时自动吊销的前提是「新注册尚未激活」，与吊销活跃条目风险不对称）。保留紧急吊销旁路，运维仍有即时止损通道。

**备选**：① 超时自动吊销（照搬注册超时口径）——DoS 面扩大，不采用；② 文档化 BREAKING「吊销无需审批」——与 parity 目标冲突且审批链断裂无补偿，不采用；③ 新增 `MatrixBranch::Revoke` 分支——与 `Register` 三态完全同形，零收益，不采用。

### D3：`C3` 哈希变更三态映射与 handler 契约

**决策**：`approve_hash_change` 落定语义按 `(approved, auto)` 映射为三态：`🔓 (true, true)` 保持现有 `allow_mode`（自动放行延续）；`✅ (true, false)` 降级人工——`allow_mode = Some(AutoApprove::Pending)`（wire `none`，后续取用走审批）；`❎ (false, _)` 与超时 `enabled=false`（禁用）。三态均照旧写 `old_hash`/`old_hash_expires_at` 宽限并更新 `script_sha256`。`approve_hash_change_handler` 增 `reg_id`/`reaction` 可选入参：`reg_id` 缺省回退 `caller_path`，`reaction` 缺省按既有批准语义（保持自动）。

**理由**：`reaction_to_decision` 对 `HashChange` 分支的三表情已就绪（`(true,true)/(true,false)/(false,false)`），映射无需新增枚举；Python 三态语义中「降级 manual」用 `AutoApprove::Pending` 表达最贴切（与全局 `auto_approve` 解耦，且 wire 值 `none` 不破坏既有 Schema）。缺省回退保证 Go 旧客户端不带 `reg_id`/`reaction` 时行为不变。

**备选**：① 维持二元 approve/reject——丢 Python 三态（🔓/✅ 都落 `enabled=true` 时无法区分保持自动与降级），不采用；② 扩展 `AutoApprove` 增加 `manual` wire 值——破坏三值 Schema（README §2 与 spec 均锁 `true/false/none`），不采用。

### D4：`C4` 生产加载期一次性迁移

**决策**：`load_from` 内接入旧格式识别：新格式解析+完整性校验成功则直读；失败且含 `version/callers` 旧形态则走 `migrate_python_registry`（备份 `.bak` fail-closed → 写回新格式 → 返回内存态）；两者皆不匹配仍 `Err`（fail-closed）。`migrate_python_registry` 去掉 `#[cfg(test)]` 生产零引用状态，作为内部函数由 `load_from` 调用。

**理由**：`load_from` 是生产唯一加载入口，接入即可无缝升级旧部署；Python `_registry.py:317-365` 同为加载期迁移。`.bak` 在覆盖写前生成（既有实现已 fail-closed），迁移结果具备完整性校验。独立命令方案要求运维显式执行，遗漏则启动直接失败，对现有部署不友好。

**备选**：① 独立迁移命令（`veil migrate-registry`）——多一步运维且易漏，不采用；② 旧格式直接拒绝并给出改用手工迁移的报错——等同现状，不满足 `C4`，不采用。

### D5：`C5` name 判重与按名吊销

**决策**：注册判重扩展为 `path 已存在 OR name 非空且与现有条目重名`（含已吊销条目？否——已吊销条目的 name 释放，允许复用；实现上仅对 `!revoked` 条目判重）→ `VeilError::Conflict`（409）。`RevokeBody` 增 `name` 字段，`revoke_key` 解析顺序 `key → caller_path → caller_hash → name`；`CallerRegistry` 增按 name 定位（未吊销优先；因注册已拒重名，未吊销集合内至多一条）。

**理由**：Python `_registry.py:66-80` 按 name 查/判重；Go CLI `get revoke --name` 依赖按名定位（README §5 已示例 `get revoke --name "check-mail"`）。未吊销集合判重避免阻塞历史名复用，同时保证定位无歧义。

**备选**：① 仅补按名吊销不判重——重名条目产生定位歧义，不采用；② 对所有条目（含吊销）判重——历史名永久不可复用，运营负担，不采用。

### D6：`C6` lock/forget 清理接线

**决策**：`handle_text_command_full` 改为经网关侧回调（AppState 可及）执行完整清理：`lock` → 清 vault 口令缓存 + KeePass 会话（`_kp=None` 对等）+ 内存 pending（`PendingApprovals::clear_all`，已就绪）+ 矩阵 pending（`lock_reject_all`/`lock_clear_all`，已就绪）+ PII scope；`forget` → 清 token 映射并以真实清理条数回执（不再固定 0）。`unlocked/secrets` 参数改由网关侧实时状态填充。

**理由**：注释已把清理义务登记给网关接线人（`bot.rs:162-169`），但生产零调用；「锁定后取不到凭据」是 lock 指令的安全语义核心，未接线即语义不成立。Python `_matrix.py:94-122` 为对等实现。

**备选**：① 保留只清审批单——锁定后凭据仍可取用，语义缺陷，不采用；② 在 Matrix 层直接持有 AppState 引用——层次倒置（matrix 服务不依赖全局状态），用回调/trait 注入更干净，不采用。

### D7：`C7` 审批票 TTL 与清扫语义统一

**决策**：孤儿清扫保留「存在阻塞等待者」的未决票。实现推荐按分支 TTL：清扫阈值 = `max(ORPHAN_SWEEP_SECS, 分支超时)`——`Register`/`HashChange`/`Credential` 分支取 300s（`CREDENTIAL_TIMEOUT_SECS`），`Audit`/`Unlock` 维持 60s；或等价地给 `PendingEntry` 加 `waiting: bool`（`ask` 进入/退出时置位）并在清扫时跳过 `waiting` 票。

**理由**：`ask` 阻塞等待 300s（`credential_approval_timeout_secs`，`service/credential/approval.rs:76-77`），60s 清扫删票使批准永远无法被 `ask` 观测（`matrix/approval.rs:217` 只在 `ask` 自身超时时删）。按分支 TTL 方案零新状态字段、与分表超时同源，优先采用；`waiting` 标记方案更精确但引入状态机维护。

**备选**：① 全局清扫阈值提到 300s——审计类低风险票滞留变长，内存虽小但语义粗糙，备选；② 阻塞票不参与清扫、只由 `ask` 超时删除——`ask` 崩溃/任务丢弃时票永久驻留，不作首选。

### D8：`C8` 双 pending 表原子清理

**决策**：抽统一终态清理函数：`approval_dual_mode` 在 `ask` 返回 `Some(false)`/`None` 时同时调用 `state.pending().remove(key)` 与矩阵侧 `remove(event_id)`；`✅` 落定后同样清理内存侧（矩阵侧由 `ask` 返回前保留至读取，落定后清理）。注册/吊销/哈希变更的一条性落定路径同样在终态后清理两侧。`GET /health pending`（`src/handler/mod.rs:26`）计数即时归零。

**理由**：内存侧 `PendingApprovals` 与矩阵侧 `MatrixApproval::pending` 是同一审批的两个视图，键空间不同（`pending_key` vs `event_id`），当前仅在矩阵侧终态清理，内存侧等 60s sweep，导致 health 计数虚高最长 60s，误导运维判断（「仍在等待审批」）。

**备选**：① 让 health 直接读矩阵侧计数——`PendingApprovals` 还被其它路径使用（审计挂起），单点替换影响面大，且矩阵侧同样有过期票，不采用；② 只在 sweep 时同步两侧——仍有时延，不满足「即时一致」，不采用。

### D9：`C9` TPM 解封唯一临时目录

**决策**：`unseal` 的 workdir 由 `veil-tpm-{pid}` 改为每次调用唯一：`veil-tpm-{pid}-{unix_nanos}-{seq}`（`seq` 为进程内原子计数器，防同纳秒碰撞）；`Guard`（已存在）继续负责成功/失败清理。不引入跨调用串行化。

**理由**：Python 每调用唯一目录；固定目录下两个并发 `unseal` 的 `createprimary`/`load` 会互相覆盖 `primary.ctx`/`sealed.ctx`，可能解封到错误上下文或直接失败。唯一目录保持并发吞吐且零锁竞争；`seq` 计数器补足时钟回拨/同刻碰撞。

**备选**：① 进程级 `Mutex` 串行化——解封是启动期低频操作，串行可接受但无谓限制并发且 panic 时需 poison 处理，不采用；② `tempfile::TempDir` 依赖——引入新依赖违反 Non-Goals，不采用。

### D10：`C10` 审批消息可读上下文

**决策**：`submit_pending` 摘要由 `{reason} :: {key}` 扩展为携带条目/字段/调用方元数据（如 `hash_mismatch :: /s/job.sh :: 网易/授权码`，reason 保持机器可读前缀）；`approval_dual_mode` 把 `entry`/`field` 传入 `submit_pending`（签名扩展）。敏感值（凭据明文/Secret）继续不进入消息；`key` 为 `caller_path:caller_hash`，hash 按现有口径呈现（非明文凭据）。

**理由**：审批人当前只看到 reason+key，无法判断批什么（Python 消息含条目/字段/调用方）。补充的是调用元数据而非敏感值，安全面不扩大。

**备选**：① 消息附完整请求体——凭据相关载荷进聊天室，泄漏面扩大，不采用；② 保持现状仅 reason/key——审批质量缺陷保留，不采用。

### D11：`C11` 限流维度保留 + 文档化（裁决）

**决策**：保留 Rust 维度——凭据取用按 `caller_path:caller_hash` 独立 2s 桶（`CREDENTIAL_RATE_WINDOW_SECS`），注册按 `source` 1s 桶（`REGISTER_RATE_WINDOW_SECS`），并在 README §3/§4 与 design 本条登记为相对 Python 全局单桶的有意差异；补跨调用方隔离测试（同调用方窗口内第二次 429、另一调用方不受影响）。

**理由**：按调用方分桶提供故障隔离——Python 全局单桶下任一调用方高频请求会阻塞所有调用方（跨方 DoS 面）；注册按 source 分桶与调用方身份解耦，防止未注册方抢占他人桶。维度拆分不降低单调用方的防滥用强度（每调用方仍 2s 一次），且 `RateTable` 有界（4096 项 + 60s 清扫），无内存放大。差异是行为可见的（并发能力提高），必须文档化而非静默。

**备选**：① 恢复 Python 全局单桶——严格 parity，但引入跨调用方干扰与 DoS 面，作为回退条款记录（若运维要求可另立 change）；② 全局桶 + 按调用方桶双层——实现复杂度与误伤面上升，无明确需求支撑，不采用。

### D12：`C12` 旧哈希宽限修正登记

**决策**：登记 Rust 语义为修正：`approve_hash_change` 真置 `old_hash = 旧 hash` 且 `old_hash_expires_at = now + OLD_HASH_GRACE_SECS`（3600s，`src/registry/entry.rs:40`），宽限内旧 hash 可用（`matches_old_hash`，`src/registry/entry.rs:53-62`）、超时失效。Python `_resolve` 置 `hash_change_at = 0.0` 致宽限成为死码，属原仓缺陷，本仓不复刻。补边界测试（`now+3600-1` 可用、`now+3600+1` 失效）。

**理由**：宽限窗口是轮换期间的可用性保障（脚本更新有部署时差）；复刻死码会回归可用性缺陷。README §4.1 已列 `OLD_HASH_GRACE_SECS=3600`，本 change 仅补行为声明与边界测试。

**备选**：复刻 Python 死码——无理由让已知缺陷回归，不采用。

### D13：`C13` 紧急吊销网段保留 + 文档化（裁决）

**决策**：保留 `is_private_ip` 现有全部范围（`localhost`/`::1`/`127.0.0.0/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`100.64/10`、`fd00::/8`、`fe80::/10`）与 `file_present` 放行，README §7.5 列明网段清单；补各网段测试（放行组/拒绝组）。内网判定继续只认 TCP 远端 `ConnectInfo`，不采信代理头。

**理由**：紧急吊销是防御性操作（目标是把可疑调用方停下来），放宽本地来源降低止损门槛；Python 三前缀遗漏回环，导致同机操作反而走审批，属原仓疏漏。`169.254/100.64` 属链路本地/CGNAT 内网段，与私网同类；`file_present` 是文件在位标记，能置位者已具备本地文件系统权限。真正的安全边界在于「是否只认 TCP 远端」，该点保持不变。

**备选**：① 回退 Python 三前缀——同机紧急吊销被挡，运维风险，不采用；② 去掉 `file_present`——契约已声明（README §7.5），删除是 BREAKING 且无安全收益，不采用。

### D14：`C14` 注册表存储语义裁决（裁决，逐项）

**决策**（逐项）：

1. **损坏 → fail-closed**（保留现状）：解析失败/完整性失配 `Err` 拒加载，不回落空表。Python fail-open 回空表会让全部调用方变「未 enrolled」而兼容放行，属安全缺陷，不复刻。
2. **落盘补 fsync**：`write_atomic`（`src/registry/store.rs:115-140`）tmp 写完 `sync_all`，rename 后对父目录 fsync，保证掉电后已确认的注册不丢失。
3. **稳定排序**：条目按 `BTreeMap` 键排序序列化，完整性 sha256 与 diff 稳定；文档化为相对 Python 插入序的有意差异（不承诺插入序）。
4. **多库/密钥选择**：`DB_DIR` 扫描排序取末位 `.kdbx`，仅当存在同名 `.key` 才配对（`src/config/custom_file.rs:14-42`）；不采用 Python「取首个 `.key`」（可能配错库）。README §1 已声明，补配对测试。

**理由**：fail-closed 与 fsync 是把「已注册状态」当作安全资产对待；排序确定性使完整性校验可复现；同名配对避免错配密钥导致打不开库或打开错误库。四项均已在实现或 README 中有基础，本 change 补 fsync、测试与声明。

**备选**：① 逐项回退 Python（fail-open/无 fsync/insertion order/首个 .key）——安全与可靠性倒退，不采用；② 排序改为持久化 `IndexMap` 保持插入序——引入依赖且完整性计算复杂化，不采用。

### D15：`C15`/`C17`/`C18` 记录项登记（audited COMPLIANT, no change）

- **`C15` `/credential` 信封**：成功响应 `{"ok":true,"credential":{...}}`（`src/handler/credential.rs:32-39`）已记载于 README §5，与 Go 客户端解析契约一致；apply 阶段核验/补信封测试并登记，不改行为。
- **`C17` 时序安全比较**：`ct_eq`（等长哈希恒时，`src/auth.rs:11-18`）与 `secret_eq`（HMAC 域分隔后 32 字节恒时 tag，`:26-37`）优于 Python 明文比较；无需改动，登记为正向差异。
- **`C18` 未 enrolled 兼容放行**：未配置期望哈希时跳过哈希比对但 Secret 仍校验（`src/service/credential/auth.rs:184-186`，README §2 已声明）；核验测试并在 design 登记。

**理由**：三项均为已合规的既有契约，重复实现或「顺手重构」会扩大改动面并可能引入回归；登记即可防止后续 change 误改。

### D16：`C16` 双必填口径维持 + 有意收紧登记（裁决）

**决策**：维持 `caller_hash` 与 `caller_path` 双必填，缺任一返回鉴权失败（403/`Auth`）；在 README 与 design 登记为相对 Python「仅强制 hash」的有意收紧（canonical `credential-api` 已锁「三因子任一缺失或不一致 SHALL 返回 403」）；补缺 `path` 403 测试。

**理由**：`caller_path` 是注册表 ACL 与吊销定位的主键，且 `pending_key` 由 `caller_path:caller_hash` 构成；放宽为 hash-only 会使审批建单/吊销定位/审计关联退化，并与 canonical spec 冲突。Go 客户端（README §5）实发双因子齐全，无存量兼容问题。

**备选**：① 放宽为 hash-only 兼容老客户端——需同步修订 canonical spec 且削弱主键语义，不作推荐（如后续确有老客户端需求另立 change）；② 缺 path 时合成占位路径——审计与 ACL 语义模糊，不采用。

### D17：apply 落地顺序与回滚

**决策**：按 tasks 顺序分四批落地——① 审批链与状态机（`C1`–`C3`）；② 迁移/name/清理（`C4`–`C6`）；③ TTL/并发/消息（`C7`–`C10`）；④ 裁决与登记（`C11`–`C18`）；最后门禁。每组独立 `cargo test -p veil <组>` + README 同批更新；回滚按组 revert，无 schema/依赖/部署形态变化。审批链恢复有行为可见变化（注册/吊销默认 `202` 建单），README §6.7/§7.5 同批声明。

## Risks / Trade-offs

- [`C1` 注册审批链恢复改变既有「注册即成功」行为] → 默认 `202` 建单使旧调用方需轮询（与 §6.7 相同迁移路径）；README §6.7/§7.5 显式声明，Go 客户端已有 `202` 容忍先例。
- [`C1`/`C2` 超时未决票被吊销/保持] → 注册超时吊销可能误伤慢审批（人工未及处理）→ 保持「fail-closed」并给足 300s；运维可用重新注册恢复，紧急吊销通道亦可即时处置。
- [`C2` 吊销不再即时] → 正常吊销需人工确认，应急处置依赖紧急吊销旁路；README §7.5 明示两条路径的分工。
- [`C3` 降级 manual 映射 `AutoApprove::Pending`] → 与全局 `auto_approve` 的交互需测试覆盖（条目级优先）；apply 补三态测试锁定优先级。
- [`C4` 加载期迁移写文件] → 首次启动对只读挂载会备份失败并拒绝覆盖（fail-closed）→ 报错信息指明 `.bak` 失败原因；运维改挂载权限后重启即可，不会损坏旧文件。
- [`C5` 未吊销集合判重] → 吊销后同名可复用，审计上可能出现同名两代条目 → 以 `reg_id`/`caller_path` 区分，符合 Python 语义。
- [`C7` 按分支 TTL 清扫] → 审计类仍 60s、凭据类 300s，未决票内存驻留变长 → 票结构小（key/reason/时间戳/分支），内存有界可接受。
- [`C8` 终态统一清理] → 需保证 `Some(true)` 路径也清理内存侧，避免「批准后 health 仍有票」→ 测试覆盖批准/拒绝/超时三终态。
- [`C9` 唯一目录] → 极端情况下临时目录残留（进程被 kill）→ 使用系统临时目录 + 启动期不做主动清理（避免误删他人文件）；残留可由 tmpwatch/运维处理，风险可接受。
- [`C13` 网段保留] → 内网面扩大（含 CGNAT/链路本地）→ 内网判定只认 TCP 远端，伪造头无效；README §7.5 列清单，便于审计。
- [`C14` fail-closed 拒加载] → 注册表损坏时启动失败（可用性下降）→ 以 `.bak` 与原子写降低损坏概率；fail-open 会把安全资产静默清零，两害相权取 fail-closed。
- [`C16` 维持双必填] → 极老客户端（仅 hash）收 403 → README 声明收紧并提供迁移指引（补 `caller_path`）。

## Open Questions

- 无。`C1`/`C2`/`C11`/`C13`/`C14`/`C16` 已给出推荐裁决与备选；若 apply 阶段实测发现双模对注册场景不适用（如 Go 客户端注册流程不接受 `202`），以 spec「注册审批链三态落定」Scenario 为准回补 design 记录差异，不静默改行为。
