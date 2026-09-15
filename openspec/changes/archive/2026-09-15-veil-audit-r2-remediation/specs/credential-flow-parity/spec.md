## MODIFIED Requirements

### Requirement: 注册审批链三态落定

系统 SHALL 在注册成功后创建 Matrix 审批单（`MatrixBranch::Register`，携带 `reg_id`），并按既有双模口径等待落定：默认模式 SHALL 返回 `202` 抛单，`CREDENTIAL_BLOCK_WAIT=1` 时 SHALL 阻塞等待至 `300s` 审批超时。落定 SHALL 支持三态：`🔓` 保持 `disabled`（不激活）、`✅` 置 `enabled=true`、`❎` 置 `revoked=true`；等待超时 SHALL 按吊销落定（fail-closed）。系统 SHALL NOT 在未获 `✅` 时激活注册条目，SHALL NOT 因落定失败回滚注册表内存态。对同一未决注册请求的重试 SHALL 幂等：SHALL 返回同一 pending（`202 + E_PENDING`），SHALL NOT 重复建单、SHALL NOT 对该待审 `caller_path` 返回 `409`；落定为终态后重试 SHALL 返回终态结果（`✅` 放行、`❎`/超时按 `403` 拒绝），与 README 声明的轮询语义一致（`src/service/credential/vault_ops.rs:297`）。

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

系统 SHALL 使常规吊销请求经 Matrix 审批确认后执行：`✅` 后条目置 `revoked=true` 且 `enabled=false`；`❎` 与等待超时 SHALL NOT 改变条目状态。系统 SHALL 保留紧急吊销豁免通道（管理 token / 文件在位 / 内网来源任一），且紧急通道 SHALL NOT 要求审批。对同一未决吊销请求的重试 SHALL 幂等：SHALL 返回同一 pending（`202 + E_PENDING`）且 SHALL NOT 重复建单；终态后重试 SHALL 返回终态（批准后条目保持 `revoked=true`/`enabled=false`，拒绝/超时保持原状），与 README 声明的轮询语义一致（`src/service/credential/vault_ops.rs:389`）。

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

哈希变更落定后系统 SHALL 按三态处理：`🔓` 保持现有 `allow_mode`（自动放行延续）；`✅` 降级为人工审批模式（后续取用进入审批）；`❎` 与超时置 `enabled=false`。三态 SHALL 均写入旧哈希宽限（`old_hash` + `old_hash_expires_at = now + 3600s`）并更新 `script_sha256`。落定入口 SHALL 接受 `reg_id` 与 `reaction` 入参（`reg_id` 缺省回退 `caller_path`，`reaction` 缺省按保持自动语义），且 SHALL NOT 因入参缺省返回 `400`。落定 SHALL NOT 写入 `revoked=false` 或 `enabled=true`——`🔓` 与 `✅` 分支均 SHALL NOT 复活或解吊销既有条目，仅更新 `script_sha256` 与旧哈希宽限字段，与 Python 语义对齐（`src/service/registry/store.rs:381-393`；Python `_registry.py:294-306`）。

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

### Requirement: 生产加载旧格式迁移

系统 SHALL 在生产加载路径识别 Python 旧格式注册表（`version`/`callers`/`allowed_entries` 形态）并一次性迁移：迁移前 SHALL 生成 `.bak` 备份（备份失败 SHALL 拒绝覆盖写），迁移后 SHALL 以新格式写回并可直接加载。新格式文件 SHALL 直读不触发迁移。系统 SHALL NOT 因旧格式存在而拒绝启动。迁移 SHALL 保留旧格式条目的 `old_hash_expires_at`、`allow_mode`、`reg_id` 字段（字段缺省时以明确默认值补齐），SHALL NOT 静默丢弃；迁移后条目的宽限与放行模式语义 SHALL 与迁移前一致（`src/service/registry/store.rs` 迁移路径）。

#### Scenario: 旧格式样例迁移

- **WHEN** `CALLER_REGISTRY_PATH` 指向 Python 旧格式文件
- **THEN** 加载成功、条目字段（hash/enabled/授权条目）保留、`.bak` 备份存在、文件已写回新格式

#### Scenario: 新格式不重复迁移

- **WHEN** 注册表已是新格式
- **THEN** 直接加载成功，不生成新 `.bak`、不改写文件

#### Scenario: 迁移保留宽限与模式字段

- **WHEN** 旧格式条目携带 `old_hash_expires_at`/`allow_mode`/`reg_id`
- **THEN** 迁移后新格式条目保留三者原值（或按明确默认补齐），宽限与放行模式语义不丢失

### Requirement: 旧哈希宽限窗口

哈希变更后系统 SHALL 保留旧哈希在 `3600s` 宽限内可用（`old_hash` + `old_hash_expires_at`），宽限内以其取用 SHALL 放行并记录通知；超过宽限 SHALL 失效。该语义为本仓对原仓宽限死码的修正，SHALL 登记。宽限通知 SHALL 按条目与宽限窗口去重：同一 `old_hash` 在同一宽限窗口内多次取用 SHALL NOT 重复发送相同通知（`src/service/credential/` 通知路径）。

#### Scenario: 宽限内旧哈希可用

- **WHEN** 哈希变更生效后 `3600s` 内旧哈希发起取用
- **THEN** 请求按授权条目正常放行（含宽限通知）

#### Scenario: 超时旧哈希失效

- **WHEN** 哈希变更生效超过 `3600s` 后旧哈希发起取用
- **THEN** 旧哈希不再被接受，按哈希失配处理

#### Scenario: 宽限通知去重

- **WHEN** 同一旧哈希在宽限窗口内多次发起取用
- **THEN** 通知按条目与窗口去重，同窗口仅记录一次，不重复发送

### Requirement: 紧急吊销豁免网段

紧急吊销 SHALL 在管理 token、文件在位标记、内网来源三者任一命中时直接执行。内网判定 SHALL 覆盖：`localhost`/`::1`/`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、`100.64.0.0/10`、`fd00::/8`、`fe80::/10`；SHALL 仅采信 TCP 远端地址（`ConnectInfo`），SHALL NOT 采信代理头。公网来源 SHALL 转常规审批。网段清单 SHALL 在 README 声明。内网判定 SHALL 同时覆盖 IPv4-mapped IPv6 环回形（如 `::ffff:127.0.0.1`，等价 `127.0.0.0/8`；`src/service/credential/` 网络判定）。

#### Scenario: 回环紧急吊销放行

- **WHEN** 来源为 `127.0.0.1` 或 `::1` 的紧急吊销请求
- **THEN** 直接吊销，不建审批单

#### Scenario: 公网来源转审批

- **WHEN** 来源为公网地址（如 `203.0.113.9`）且无管理 token、无文件在位标记
- **THEN** 请求转常规审批，不直接吊销

#### Scenario: 代理头不可伪造豁免

- **WHEN** 公网来源携带伪造内网 `X-Forwarded-For`
- **THEN** 内网判定不命中，仍转审批

#### Scenario: IPv4-mapped IPv6 环回识别

- **WHEN** 来源为 `::ffff:127.0.0.1` 等 IPv4-mapped IPv6 环回地址
- **THEN** 内网判定命中，紧急吊销直接执行，不建审批单

### Requirement: 注册表存储语义

系统 SHALL 对注册表加载采用 fail-closed：解析失败或完整性失配 SHALL 拒绝加载，SHALL NOT 回落空表放行。落盘 SHALL 原子（tmp + rename）并在确认前同步落盘（fsync）；条目序列化 SHALL 采用稳定排序（`BTreeMap` 键序）。数据库选择 SHALL 排序取末位 `.kdbx`，仅当存在同名 `.key` 时配对，SHALL NOT 取任意首个 `.key`。上述语义 SHALL 登记（含与原仓差异）。启动加载路径 SHALL 传播加载错误并拒绝启动（fail-fast），同时记 `error` 日志；SHALL NOT 以 `.unwrap_or_default()` 等静默回落为空表（C14；`src/state.rs:76`，`store.rs:193-208`）。注册表临时文件 SHALL 在创建时即以 `0600` 权限打开（`OpenOptionsExt::mode`），SHALL NOT 存在先创建后 `chmod` 的宽权限窗口；重写产物权限口径一致（`src/service/registry/store.rs`）。

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

### Requirement: 敏感比较时序安全

系统 SHALL 使用恒时比较处理敏感值：定长哈希比较 SHALL 使用等长恒时比较（`ct_eq`），变长 Secret 比较 SHALL 使用域分隔后压缩为等长 tag 的恒时比较（`secret_eq`），SHALL NOT 使用明文早退比较。管理面 token（`X-Admin-Token`/Cookie/SSE query）比较 SHALL 恒时且长度不可分辨——SHALL 经域分隔压缩为等长 tag 后恒时比较，SHALL NOT 以长度可分辨的方式提前失败（Rust 管理面鉴权）。

#### Scenario: 等长/变长比较语义

- **WHEN** 比较哈希或 Secret
- **THEN** 长度不等立即判定失败但不泄漏内容；等长按恒时比较，无内容相关早退

#### Scenario: 管理 token 比较长度不可分辨

- **WHEN** 以不同长度的候选 token 请求管理面
- **THEN** 比较按恒时口径执行，不因长度不等而可分辨地提前返回，鉴权结果正确

## ADDED Requirements

### Requirement: 哈希查找活跃优先

系统 SHALL 在按哈希查找注册条目时优先返回活跃（未吊销）条目；当同一哈希同时存在活跃条目与已吊销/废弃条目时，SHALL NOT 返回已吊销/废弃条目。仅当无活跃条目时才按明确且稳定的回退顺序处理，不误判为活跃语义（`src/service/registry/store.rs`）。

#### Scenario: 活跃条目优先于废弃条目

- **WHEN** 同一哈希存在一条活跃条目与一条已吊销条目
- **THEN** 哈希查找返回活跃条目，取用按其授权条目处理

#### Scenario: 无活跃条目时才回退

- **WHEN** 同一哈希仅存在已吊销条目
- **THEN** 查找按明确回退顺序返回该已吊销条目并按已吊销语义处理（或被拒），不误判为活跃
