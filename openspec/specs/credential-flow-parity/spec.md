# credential-flow-parity Specification

## Purpose
锁定凭据流水线六段（注册 → 审批 → 取用 → 哈希变更 → 吊销 → 锁定）的目标契约：注册/吊销/哈希变更审批链与三态落定、生产旧格式迁移、按名吊销与重名冲突、lock/forget 清理接线、审批票 TTL 与双 pending 原子清理、TPM 并发隔离、审批消息可读上下文、限流维度、旧哈希宽限、紧急吊销网段、注册表存储语义，以及 `/credential` 信封、时序安全比较、未 enrolled 默认转审批（`AUTO_APPROVE=false` 才 `403`）三项登记契约。行为真相源为 `src/service/credential/`、`src/service/matrix/`、`src/registry/`、`src/handler/credential.rs`、`src/service/tpm.rs`、`src/approval.rs`、`src/auth.rs`。

## Requirements

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

### Requirement: 生产加载旧格式迁移

系统 SHALL 在生产加载路径识别 Python 旧格式注册表（`version`/`callers`/`allowed_entries` 形态）并一次性迁移：迁移前 SHALL 生成 `.bak` 备份（备份失败 SHALL 拒绝覆盖写），迁移后 SHALL 以新格式写回并可直接加载。新格式文件 SHALL 直读不触发迁移。系统 SHALL NOT 因旧格式存在而拒绝启动。迁移 SHALL 保留旧格式条目的 `old_hash_expires_at`、`allow_mode`、`reg_id` 字段（字段缺省时以明确默认值补齐），SHALL NOT 静默丢弃；迁移后条目的宽限与放行模式语义 SHALL 与迁移前一致（`src/registry/store.rs` 迁移路径）。

#### Scenario: 旧格式样例迁移

- **WHEN** `CALLER_REGISTRY_PATH` 指向 Python 旧格式文件
- **THEN** 加载成功、条目字段（hash/enabled/授权条目）保留、`.bak` 备份存在、文件已写回新格式

#### Scenario: 新格式不重复迁移

- **WHEN** 注册表已是新格式
- **THEN** 直接加载成功，不生成新 `.bak`、不改写文件

#### Scenario: 迁移保留宽限与模式字段

- **WHEN** 旧格式条目携带 `old_hash_expires_at`/`allow_mode`/`reg_id`
- **THEN** 迁移后新格式条目保留三者原值（或按明确默认补齐），宽限与放行模式语义不丢失

### Requirement: 按名吊销与重名冲突

系统 SHALL 在注册时对非空 `name` 判重：与任一未吊销条目重名 SHALL 返回 `409 Conflict`。系统 SHALL 支持按 `name` 定位并吊销条目（`POST /revoke` 请求体的 `key`/`caller_path`/`caller_hash`/`name` 任一可定位）。已吊销条目的 `name` SHALL 可被新注册复用。

#### Scenario: 重名注册 409

- **WHEN** 已存在未吊销条目 `name="check-mail"` 时再次注册同名条目
- **THEN** 返回 `409`，原条目不变

#### Scenario: 按名吊销

- **WHEN** `POST /revoke` 携带 `{"name":"check-mail"}` 且该条目存在
- **THEN** 定位到对应条目并执行吊销（经审批链），不返回 `404`

#### Scenario: 吊销后名字复用

- **WHEN** 原同名条目已吊销后注册同 `name` 新条目
- **THEN** 注册成功，不与已吊销条目冲突

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

### Requirement: 审批票 TTL 与清扫语义一致

系统 SHALL 使孤儿清扫与审批超时语义一致：对存在阻塞等待者的未决票，清扫 SHALL NOT 在阻塞超时（`300s`）前删除；等价地，凭据类分支待审票 TTL SHALL 不小于其阻塞超时。系统 SHALL 继续回收无等待者的孤儿票（空闲票 60s 上限语义保留）。

#### Scenario: 阻塞 60s 后仍可决

- **WHEN** `CREDENTIAL_BLOCK_WAIT=1` 下建单并等待超过一个清扫周期（60s）
- **THEN** 审批人回复 `✅` 仍能解除阻塞并返回凭据

#### Scenario: 无等待者孤儿票回收

- **WHEN** 某未决票创建后无人等待且超过其 TTL
- **THEN** 清扫回收该票，内存有界

### Requirement: 双 pending 表原子清理

系统 SHALL 在审批终态（批准、拒绝、超时）同步清理内存侧与矩阵侧 pending 记录；`GET /health` 的 `pending` 计数 SHALL 在终态清理后即时反映真实值，SHALL NOT 依赖 60s 清扫延迟。

#### Scenario: 超时后两侧清零

- **WHEN** 阻塞等待超时且 `ask` 返回 `None`
- **THEN** 矩阵侧与内存侧均无该票，重新查询返回 pending 计数 `0`

#### Scenario: 批准后计数即时归零

- **WHEN** 审批被批准且同请求返回凭据
- **THEN** `pending` 计数即时归零，不再显示该单

### Requirement: TPM 解封并发隔离

系统 SHALL 使每次 TPM 解封使用独立临时工作目录（或等价隔离），并发解封 SHALL NOT 互覆 `primary.ctx`/`sealed.ctx` 等中间对象；临时目录 SHALL 在成功与失败路径均清理，SHALL NOT 以轮询或全局锁退化为串行解封为唯一手段。

#### Scenario: 并发解封互不干扰

- **WHEN** 同一进程并发发起多次 `unseal`
- **THEN** 各次调用使用不同工作目录，全部成功且结果一致，无中间对象覆盖

#### Scenario: 临时目录清理

- **WHEN** 一次 `unseal` 成功或失败返回
- **THEN** 其临时工作目录已被清理

### Requirement: 审批消息可读上下文

系统 SHALL 使审批消息携带可读上下文：至少包含原因、目标调用方路径，以及凭据场景下的条目与字段元数据；敏感值（凭据明文、部署 Secret）SHALL NOT 出现在消息中。

#### Scenario: 消息含条目与字段

- **WHEN** `hash_mismatch` 审批建单（涉及条目 `网易`、字段 `授权码`）
- **THEN** 审批消息包含 `网易`/`授权码` 与调用方路径，审批人可判断批什么

#### Scenario: 消息不含敏感明文

- **WHEN** 任意审批消息发送
- **THEN** 消息不含凭据明文或部署 Secret

### Requirement: 凭据限流维度

凭据取用限流 SHALL 按调用方维度独立计数（`caller_path:caller_hash`，窗口 `2s`）；注册限流 SHALL 按 `source` 维度计数（窗口 `1s`）。同一调用方在窗口内重复请求 SHALL 返回 `429`；其他调用方 SHALL NOT 因该调用方被限流而受影响。该维度相对原仓全局单桶属有意差异，SHALL 在 README 声明。

#### Scenario: 同调用方连续请求 429

- **WHEN** 同一 `caller_path:caller_hash` 在 `2s` 内发起第二次凭据请求
- **THEN** 返回 `429`，不进入凭据查询

#### Scenario: 跨调用方隔离

- **WHEN** 调用方 A 被限流的同时调用方 B 发起请求
- **THEN** 调用方 B 正常处理，不受 A 的限流影响

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

紧急吊销 SHALL 在管理 token、文件在位标记、内网来源三者任一命中时直接执行。内网判定 SHALL 覆盖：`localhost`/`::1`/`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、`100.64.0.0/10`、`fd00::/8`、`fe80::/10`；SHALL 仅采信 TCP 远端地址（`ConnectInfo`），SHALL NOT 采信代理头。公网来源 SHALL 转常规审批。网段清单 SHALL 在 README 声明。内网判定 SHALL 同时覆盖 IPv4-mapped IPv6 环回形（如 `::ffff:127.0.0.1`，等价 `127.0.0.0/8`；`src/service/credential/vault_ops.rs:538` 的 `is_private_peer` 判定）。

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

### Requirement: /credential 成功信封

`POST /credential` 成功响应 SHALL 为 `{"ok":true,"credential":{...}}` 信封，凭据载荷位于 `credential` 字段；该行为 SHALL 保持并登记（与 Go 客户端解析契约一致）。

#### Scenario: 成功响应信封

- **WHEN** 三因子核验通过并按授权取用凭据
- **THEN** 响应体含 `ok=true` 与 `credential` 字段，凭据载荷在 `credential` 内

### Requirement: 三因子双必填口径

系统 SHALL 要求请求体同时携带 `body.auth.caller_hash` 与 `body.auth.caller_path`，任一缺失 SHALL 返回 `403`（鉴权失败）；该口径 SHALL 维持并登记为相对原仓「仅强制 hash」的有意收紧。

#### Scenario: 缺 caller_path 拒绝

- **WHEN** 请求体仅有 `caller_hash` 而无 `caller_path`
- **THEN** 返回 `403`，不进入凭据查询

#### Scenario: 缺 caller_hash 拒绝

- **WHEN** 请求体仅有 `caller_path` 而无 `caller_hash`
- **THEN** 返回 `403`，不进入凭据查询

### Requirement: 敏感比较时序安全

系统 SHALL 使用恒时比较处理敏感值：定长哈希比较 SHALL 使用等长恒时比较（`ct_eq`），变长 Secret 比较 SHALL 使用域分隔后压缩为等长 tag 的恒时比较（`secret_eq`），SHALL NOT 使用明文早退比较。管理面 token（`X-Admin-Token`/Cookie/SSE query）比较 SHALL 恒时且长度不可分辨——SHALL 经域分隔压缩为等长 tag 后恒时比较，SHALL NOT 以长度可分辨的方式提前失败（Rust 管理面鉴权）。

#### Scenario: 等长/变长比较语义

- **WHEN** 比较哈希或 Secret
- **THEN** 长度不等立即判定失败但不泄漏内容；等长按恒时比较，无内容相关早退

#### Scenario: 管理 token 比较长度不可分辨

- **WHEN** 以不同长度的候选 token 请求管理面
- **THEN** 比较按恒时口径执行，不因长度不等而可分辨地提前返回，鉴权结果正确

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

### Requirement: 哈希查找活跃优先

系统 SHALL 在按哈希查找注册条目时优先返回活跃（未吊销）条目；当同一哈希同时存在活跃条目与已吊销/废弃条目时，SHALL NOT 返回已吊销/废弃条目。仅当无活跃条目时才按明确且稳定的回退顺序处理，不误判为活跃语义（`src/registry/store.rs`）。

#### Scenario: 活跃条目优先于废弃条目

- **WHEN** 同一哈希存在一条活跃条目与一条已吊销条目
- **THEN** 哈希查找返回活跃条目，取用按其授权条目处理

#### Scenario: 无活跃条目时才回退

- **WHEN** 同一哈希仅存在已吊销条目
- **THEN** 查找按明确回退顺序返回该已吊销条目并按已吊销语义处理（或被拒），不误判为活跃
