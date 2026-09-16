## RENAMED Requirements

- FROM: `### Requirement: 未 enrolled 兼容放行`
- TO: `### Requirement: 未 enrolled 默认转审批`

## MODIFIED Requirements

### Requirement: 注册审批链三态落定

系统 SHALL 在注册成功后创建 Matrix 审批单（`MatrixBranch::Register`，携带 `reg_id`），并按既有双模口径等待落定：默认模式 SHALL 返回 `202` 抛单，`CREDENTIAL_BLOCK_WAIT=1` 时 SHALL 阻塞等待至 `300s` 审批超时。落定 SHALL 支持三态：`🔓` 保持 `disabled`（不激活）、`✅` 置 `enabled=true`、`❎` 置 `revoked=true`；等待超时 SHALL 按吊销落定（fail-closed）。系统 SHALL NOT 在未获 `✅` 时激活注册条目，SHALL NOT 因落定失败回滚注册表内存态。对同一未决注册请求的重试 SHALL 幂等：SHALL 返回同一 pending（`202 + E_PENDING`），SHALL NOT 重复建单、SHALL NOT 对该待审 `caller_path` 返回 `409`；落定为终态后重试 SHALL 返回终态结果（`✅` 放行、`❎`/超时按 `403` 拒绝），与 README 声明的轮询语义一致（`src/service/credential/vault_ops.rs:314`）。

#### Scenario: 注册等待 ✅ 后启用

- **WHEN** 注册成功且审批人回复 `✅`
- **THEN** 条目 `enabled=true`、`revoked=false`，后续取用按授权条目放行

#### Scenario: 注册 🔓 保持未激活

- **WHEN** 注册成功且审批人回复 `🔓`
- **THEN** 条目保持 `disabled`，取用仍被拒绝，注册记录保留

#### Scenario: 注册 ❎ 与超时按吊销

- **WHEN** 注册成功且审批人回复 `❎`，或等待超过 `300s` 无人落定
- **THEN** 条目 `revoked=true`，后续取用被拒绝

#### Scenario: 未决注册重试返回同一 pending

- **WHEN** 默认模式下同一注册请求（同一 `caller_path`）在未决期间再次发起
- **THEN** 返回 `202 + E_PENDING`（同一 pending），不重复建单、不返回 `409`，条目仍为未激活

### Requirement: 吊销审批确认

系统 SHALL 使常规吊销请求经 Matrix 审批确认后执行：`✅` 后条目置 `revoked=true` 且 `enabled=false`；`❎` 与等待超时 SHALL NOT 改变条目状态。系统 SHALL 保留紧急吊销豁免通道（管理 token / 文件在位 / 内网来源任一），且紧急通道 SHALL NOT 要求审批。对同一未决吊销请求的重试 SHALL 幂等：SHALL 返回同一 pending（`202 + E_PENDING`）且 SHALL NOT 重复建单；终态后重试 SHALL 返回终态（批准后条目保持 `revoked=true`/`enabled=false`，拒绝/超时保持原状），与 README 声明的轮询语义一致（`src/service/credential/vault_ops.rs:420`）。

#### Scenario: 批准后吊销生效

- **WHEN** 吊销请求已建单且审批人回复 `✅`
- **THEN** 目标条目 `revoked=true`，后续取用被拒绝

#### Scenario: 拒绝或超时保持现状

- **WHEN** 吊销请求已建单且审批人回复 `❎` 或等待超时
- **THEN** 条目状态不变，仍按原状态取用或拒绝

#### Scenario: 紧急吊销旁路

- **WHEN** 请求携带有效管理 token、或声明文件在位、或来源为内网
- **THEN** 吊销直接执行，不建审批单

#### Scenario: 未决吊销重试不重复建单

- **WHEN** 默认模式下同一吊销请求在未决期间再次发起
- **THEN** 返回 `202 + E_PENDING`（同一 pending），不重复建单，条目状态不变

### Requirement: 哈希变更三态与落定契约

哈希变更落定后系统 SHALL 按三态处理：`🔓` 保持现有 `allow_mode`（自动放行延续）；`✅` 降级为人工审批模式（后续取用进入审批）；`❎` 与超时置 `enabled=false`。三态 SHALL 均写入旧哈希宽限（`old_hash` + `old_hash_expires_at = now + 3600s`）并更新 `script_sha256`。落定入口 SHALL 接受 `reg_id` 与 `reaction` 入参（`reg_id` 缺省回退 `caller_path`，`reaction` 缺省按保持自动语义），且 SHALL NOT 因入参缺省返回 `400`。落定 SHALL NOT 写入 `revoked=false` 或 `enabled=true`——`🔓` 与 `✅` 分支均 SHALL NOT 复活或解吊销既有条目，仅更新 `script_sha256` 与旧哈希宽限字段，与 Python 语义对齐（`src/registry/store.rs:371-393`；Python `_registry.py:294-306`）。

#### Scenario: ✅ 降级人工

- **WHEN** 哈希变更落定为 `✅`
- **THEN** 条目 `allow_mode` 为人工审批语义，后续取用进入审批而非自动放行

#### Scenario: ❎ 禁用

- **WHEN** 哈希变更落定为 `❎` 或等待超时
- **THEN** 条目 `enabled=false`，取用被拒绝

#### Scenario: reg_id/reaction 缺省兼容

- **WHEN** 落定入口未携带 `reg_id`/`reaction`
- **THEN** 系统按 `caller_path` 定位并按保持自动语义落定，返回成功而非 `400`

#### Scenario: 已吊销条目不因哈希变更复活

- **WHEN** 对已 `revoked=true` 的条目执行哈希变更落定（`🔓` 或 `✅`）
- **THEN** 条目保持 `revoked=true`，不被写入 `revoked=false`/`enabled=true`，仅 `script_sha256` 与旧哈希宽限字段更新

### Requirement: 注册表存储语义

系统 SHALL 对注册表加载采用 fail-closed：解析失败或完整性失配 SHALL 拒绝加载，SHALL NOT 回落空表放行。落盘 SHALL 原子（tmp + rename）并在确认前同步落盘（fsync）；条目序列化 SHALL 采用稳定排序（`BTreeMap` 键序）。数据库选择 SHALL 排序取末位 `.kdbx`，仅当存在同名 `.key` 时配对，SHALL NOT 取任意首个 `.key`。上述语义 SHALL 登记（含与原仓差异）。启动加载路径 SHALL 传播加载错误并拒绝启动（fail-fast），同时记 `error` 日志；SHALL NOT 以 `.unwrap_or_default()` 等静默回落为空表（C14；`src/state.rs:76`，`src/registry/store.rs:206-221`）。注册表临时文件 SHALL 在创建时即以 `0600` 权限打开（`OpenOptionsExt::mode`），SHALL NOT 存在先创建后 `chmod` 的宽权限窗口；重写产物权限口径一致（`src/registry/store.rs`）。

#### Scenario: 损坏注册表拒绝加载

- **WHEN** 注册表文件内容损坏或 sha256 失配
- **THEN** 加载返回错误，不启动、不以空表放行

#### Scenario: 落盘持久化

- **WHEN** 注册/吊销/哈希变更写入注册表
- **THEN** 文件经原子替换与 fsync 后生效，序列化顺序稳定可复现

#### Scenario: 多库与同名密钥

- **WHEN** `DB_DIR` 存在多个 `.kdbx` 与多个 `.key`
- **THEN** 选中排序末位 `.kdbx`，仅在同名 `.key` 存在时配对，否则不带密钥文件

#### Scenario: 启动加载失败拒绝启动并记日志

- **WHEN** 启动加载路径遇注册表损坏、不可读或 sha256 失配
- **THEN** 进程拒绝启动并记 `error` 日志，不以静默空表继续运行

#### Scenario: 临时文件创建即 0600

- **WHEN** 注册表落盘创建临时文件
- **THEN** 该文件自创建起权限即为 `0600`，无宽权限窗口

### Requirement: lock/forget 清理接线

系统 SHALL 在 Matrix `lock` 指令执行时清理：口令缓存、KeePass 会话、TPM 派生主密码缓存、未决审批（内存 pending + 矩阵 pending 按拒绝落定）与请求级 PII 作用域（`Scope::pii`）。系统 SHALL NOT 宣称或依赖「全局 PII 缓存」——PII 映射为请求级容器（随请求销毁，跨请求不互见），`lock` 清理不触及任何全局 PII 映射。清理后凭据取用 SHALL 失败直至重新解锁。系统 SHALL 在 `forget` 指令执行时清理已决审批单与 token 映射，并在回执中报告真实清理条数。

#### Scenario: lock 后取不到凭据

- **WHEN** 已解锁状态下执行 `lock`
- **THEN** 未决审批清零，凭据取用失败（会话/缓存已清）

#### Scenario: lock 不依赖全局 PII 缓存

- **WHEN** 核查 `lock` 清理范围
- **THEN** 清理对象为请求级 PII 作用域（`Scope::pii`）而非全局缓存；不存在全局 PII 映射被清空或跨请求共享

#### Scenario: forget 清理映射并计数

- **WHEN** 存在已决审批单与 token 映射时执行 `forget`
- **THEN** 已决单与映射被清理，回执条数与实际清理数一致

### Requirement: 未 enrolled 默认转审批

当服务端未配置调用方期望哈希（未 enrolled）时，系统 SHALL 默认转入 Matrix 审批（`202 + E_PENDING`）；仅当 `AUTO_APPROVE=false` 时 SHALL 返回 `403`。系统 SHALL NOT 因未注册而直接自动放行。Secret 校验 SHALL 在转审批/拒绝判定前继续执行；Secret 失败 SHALL 返回 `403`。行为真相源 SHALL 为 canonical `openspec/specs/credential-auth-hardening/spec.md`「未注册调用方默认转审批」。代码锚点：`src/service/credential/auth.rs:262-280`（未 enrolled 且 `Deny` → 403，否则 `approval_dual_mode`）。

#### Scenario: 未 enrolled 放行且 Secret 仍校验

- **WHEN** 调用方无期望哈希配置且 Secret 正确
- **THEN** 默认转入 Matrix 审批（`202 + E_PENDING`），不返回凭据明文、不直接放行（`AUTO_APPROVE=false` 时为 `403`）

#### Scenario: AUTO_APPROVE=false 时 403

- **WHEN** 调用方无期望哈希配置、Secret 正确，且 `AUTO_APPROVE=false`
- **THEN** 返回 `403`，不转审批、不返回凭据

#### Scenario: Secret 错误仍拒绝

- **WHEN** 调用方无期望哈希配置但 Secret 缺失或不匹配
- **THEN** 返回 `403`，不接触凭据

