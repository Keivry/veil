# credential-flow-parity Specification

## Purpose
锁定凭据流水线六段（注册 → 审批 → 取用 → 哈希变更 → 吊销 → 锁定）的目标契约：注册/吊销/哈希变更审批链与三态落定、生产旧格式迁移、按名吊销与重名冲突、lock/forget 清理接线、审批票 TTL 与双 pending 原子清理、TPM 并发隔离、审批消息可读上下文、限流维度、旧哈希宽限、紧急吊销网段、注册表存储语义，以及 `/credential` 信封、时序安全比较、未 enrolled 兼容放行三项登记契约。行为真相源为 `src/service/credential/`、`src/service/matrix/`、`src/registry/`、`src/handler/credential.rs`、`src/service/tpm.rs`、`src/approval.rs`、`src/auth.rs`。

## Requirements

### Requirement: 注册审批链三态落定

系统 SHALL 在注册成功后创建 Matrix 审批单（`MatrixBranch::Register`，携带 `reg_id`），并按既有双模口径等待落定：默认模式 SHALL 返回 `202` 抛单，`CREDENTIAL_BLOCK_WAIT=1` 时 SHALL 阻塞等待至 `300s` 审批超时。落定 SHALL 支持三态：`🔓` 保持 `disabled`（不激活）、`✅` 置 `enabled=true`、`❎` 置 `revoked=true`；等待超时 SHALL 按吊销落定（fail-closed）。系统 SHALL NOT 在未获 `✅` 时激活注册条目，SHALL NOT 因落定失败回滚注册表内存态。

#### Scenario: 注册等待 ✅ 后启用

- **WHEN** 注册成功且审批人回复 `✅`
- **THEN** 条目 `enabled=true`、`revoked=false`，后续取用按授权条目放行

#### Scenario: 注册 🔓 保持未激活

- **WHEN** 注册成功且审批人回复 `🔓`
- **THEN** 条目保持 `disabled`，取用仍被拒绝，注册记录保留

#### Scenario: 注册 ❎ 与超时按吊销

- **WHEN** 注册成功且审批人回复 `❎`，或等待超过 `300s` 无人落定
- **THEN** 条目 `revoked=true`，后续取用被拒绝

### Requirement: 吊销审批确认

系统 SHALL 使常规吊销请求经 Matrix 审批确认后执行：`✅` 后条目置 `revoked=true` 且 `enabled=false`；`❎` 与等待超时 SHALL NOT 改变条目状态。系统 SHALL 保留紧急吊销豁免通道（管理 token / 文件在位 / 内网来源任一），且紧急通道 SHALL NOT 要求审批。

#### Scenario: 批准后吊销生效

- **WHEN** 吊销请求已建单且审批人回复 `✅`
- **THEN** 目标条目 `revoked=true`，后续取用被拒绝

#### Scenario: 拒绝或超时保持现状

- **WHEN** 吊销请求已建单且审批人回复 `❎` 或等待超时
- **THEN** 条目状态不变，仍按原状态取用或拒绝

#### Scenario: 紧急吊销旁路

- **WHEN** 请求携带有效管理 token、或声明文件在位、或来源为内网
- **THEN** 吊销直接执行，不建审批单

### Requirement: 哈希变更三态与落定契约

哈希变更落定后系统 SHALL 按三态处理：`🔓` 保持现有 `allow_mode`（自动放行延续）；`✅` 降级为人工审批模式（后续取用进入审批）；`❎` 与超时置 `enabled=false`。三态 SHALL 均写入旧哈希宽限（`old_hash` + `old_hash_expires_at = now + 3600s`）并更新 `script_sha256`。落定入口 SHALL 接受 `reg_id` 与 `reaction` 入参（`reg_id` 缺省回退 `caller_path`，`reaction` 缺省按保持自动语义），且 SHALL NOT 因入参缺省返回 `400`。

#### Scenario: ✅ 降级人工

- **WHEN** 哈希变更落定为 `✅`
- **THEN** 条目 `allow_mode` 为人工审批语义，后续取用进入审批而非自动放行

#### Scenario: ❎ 禁用

- **WHEN** 哈希变更落定为 `❎` 或等待超时
- **THEN** 条目 `enabled=false`，取用被拒绝

#### Scenario: reg_id/reaction 缺省兼容

- **WHEN** 落定入口未携带 `reg_id`/`reaction`
- **THEN** 系统按 `caller_path` 定位并按保持自动语义落定，返回成功而非 `400`

### Requirement: 生产加载旧格式迁移

系统 SHALL 在生产加载路径识别 Python 旧格式注册表（`version`/`callers`/`allowed_entries` 形态）并一次性迁移：迁移前 SHALL 生成 `.bak` 备份（备份失败 SHALL 拒绝覆盖写），迁移后 SHALL 以新格式写回并可直接加载。新格式文件 SHALL 直读不触发迁移。系统 SHALL NOT 因旧格式存在而拒绝启动。

#### Scenario: 旧格式样例迁移

- **WHEN** `CALLER_REGISTRY_PATH` 指向 Python 旧格式文件
- **THEN** 加载成功、条目字段（hash/enabled/授权条目）保留、`.bak` 备份存在、文件已写回新格式

#### Scenario: 新格式不重复迁移

- **WHEN** 注册表已是新格式
- **THEN** 直接加载成功，不生成新 `.bak`、不改写文件

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

系统 SHALL 在 Matrix `lock` 指令执行时清理：口令缓存、KeePass 会话、未决审批（内存 pending + 矩阵 pending 按拒绝落定）与 PII scope 缓存；清理后凭据取用 SHALL 失败直至重新解锁。系统 SHALL 在 `forget` 指令执行时清理已决审批单与 token 映射，并在回执中报告真实清理条数。

#### Scenario: lock 后取不到凭据

- **WHEN** 已解锁状态下执行 `lock`
- **THEN** 未决审批清零，凭据取用失败（会话/缓存已清）

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

哈希变更后系统 SHALL 保留旧哈希在 `3600s` 宽限内可用（`old_hash` + `old_hash_expires_at`），宽限内以其取用 SHALL 放行并记录通知；超过宽限 SHALL 失效。该语义为本仓对原仓宽限死码的修正，SHALL 登记。

#### Scenario: 宽限内旧哈希可用

- **WHEN** 哈希变更生效后 `3600s` 内旧哈希发起取用
- **THEN** 请求按授权条目正常放行（含宽限通知）

#### Scenario: 超时旧哈希失效

- **WHEN** 哈希变更生效超过 `3600s` 后旧哈希发起取用
- **THEN** 旧哈希不再被接受，按哈希失配处理

### Requirement: 紧急吊销豁免网段

紧急吊销 SHALL 在管理 token、文件在位标记、内网来源三者任一命中时直接执行。内网判定 SHALL 覆盖：`localhost`/`::1`/`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、`100.64.0.0/10`、`fd00::/8`、`fe80::/10`；SHALL 仅采信 TCP 远端地址（`ConnectInfo`），SHALL NOT 采信代理头。公网来源 SHALL 转常规审批。网段清单 SHALL 在 README 声明。

#### Scenario: 回环紧急吊销放行

- **WHEN** 来源为 `127.0.0.1` 或 `::1` 的紧急吊销请求
- **THEN** 直接吊销，不建审批单

#### Scenario: 公网来源转审批

- **WHEN** 来源为公网地址（如 `203.0.113.9`）且无管理 token、无文件在位标记
- **THEN** 请求转常规审批，不直接吊销

#### Scenario: 代理头不可伪造豁免

- **WHEN** 公网来源携带伪造内网 `X-Forwarded-For`
- **THEN** 内网判定不命中，仍转审批

### Requirement: 注册表存储语义

系统 SHALL 对注册表加载采用 fail-closed：解析失败或完整性失配 SHALL 拒绝加载，SHALL NOT 回落空表放行。落盘 SHALL 原子（tmp + rename）并在确认前同步落盘（fsync）；条目序列化 SHALL 采用稳定排序（`BTreeMap` 键序）。数据库选择 SHALL 排序取末位 `.kdbx`，仅当存在同名 `.key` 时配对，SHALL NOT 取任意首个 `.key`。上述语义 SHALL 登记（含与原仓差异）。

#### Scenario: 损坏注册表拒绝加载

- **WHEN** 注册表文件内容损坏或 sha256 失配
- **THEN** 加载返回错误，不启动、不以空表放行

#### Scenario: 落盘持久化

- **WHEN** 注册/吊销/哈希变更写入注册表
- **THEN** 文件经原子替换与 fsync 后生效，序列化顺序稳定可复现

#### Scenario: 多库与同名密钥

- **WHEN** `DB_DIR` 存在多个 `.kdbx` 与多个 `.key`
- **THEN** 选中排序末位 `.kdbx`，仅在同名 `.key` 存在时配对，否则不带密钥文件

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

系统 SHALL 使用恒时比较处理敏感值：定长哈希比较 SHALL 使用等长恒时比较（`ct_eq`），变长 Secret 比较 SHALL 使用域分隔后压缩为等长 tag 的恒时比较（`secret_eq`），SHALL NOT 使用明文早退比较。

#### Scenario: 等长/变长比较语义

- **WHEN** 比较哈希或 Secret
- **THEN** 长度不等立即判定失败但不泄漏内容；等长按恒时比较，无内容相关早退

### Requirement: 未 enrolled 兼容放行

当服务端未配置调用方期望哈希（未 enrolled）时，系统 SHALL 跳过哈希比对并兼容放行，但 Secret 校验 SHALL 继续执行；Secret 失败 SHALL 返回 `403`。

#### Scenario: 未 enrolled 放行且 Secret 仍校验

- **WHEN** 调用方无期望哈希配置且 Secret 正确
- **THEN** 请求放行并按自动放行三态处理

#### Scenario: Secret 错误仍拒绝

- **WHEN** 调用方无期望哈希配置但 Secret 缺失或不匹配
- **THEN** 返回 `403`，不接触凭据
