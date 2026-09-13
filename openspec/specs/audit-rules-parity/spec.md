# audit-rules-parity Specification

## Purpose
锁定审计规则面的等价契约与已声明差异：审计 JSONL 真实接线（canonical `audit-tpm-matrix` 的落盘条款由「规格在位、生产零调用」收敛为实际生效）、摘要脱敏十形态、危险规则语义等价、规范化管线等价类、内外网判定偏严声明、开关真值集与非法值 fail-closed、策略文件对象形兼容、写失败双层语义、审计事件可查询、SSE metrics 周期快照，以及 MXID 校验、`find` 预检、启动顺序、Cookie https 判定四项缺陷收敛。判定与策略真相源为 `src/service/audit/rules.rs`、`src/service/audit/normalize.rs`、`src/service/audit/policy.rs`、`src/service/audit/verdict.rs`、`src/service/audit/log.rs`。

## Requirements

### Requirement: 审计日志落盘接线

系统 SHALL 将 `AuditLogger`（`src/service/audit/log.rs`）接线到审计判定路径：流式（`src/handler/llm/pump/spawn.rs`）与非流（`src/handler/llm/nonstream.rs`）的 verdict 命中/放行事件 SHALL 以 `spawn_blocking` 写入 `DATA_DIR/audit.log`；SHALL NOT 保留仅单测引用的零调用形态（`src/service/audit.rs` 模块文档与 canonical spec 要求落盘生效）。落盘 SHALL 为 JSONL、先脱敏后截断、剥 `\x00-\x1f`、权限 0600、单文件 10MB 保留 5 份。

#### Scenario: 审计命中实际落盘

- **WHEN** 审计判定命中且流式/非流式请求结束
- **THEN** `DATA_DIR/audit.log` 出现对应 JSONL 行（脱敏摘要），且写盘经 `spawn_blocking` 不阻塞异步流

#### Scenario: 轮转与权限

- **WHEN** `audit.log` 达到 10MB
- **THEN** 轮转为 `audit.log.1`、旧文件按 5 份保留且文件权限为 0600

#### Scenario: 无死码形态

- **WHEN** apply 后扫描生产代码中的 `AuditLogger` 引用
- **THEN** 存在非 `src/service/audit/log.rs` 自身/非其单测的调用点，模块文档与实际接线一致

### Requirement: 审计摘要脱敏形态对齐

系统 SHALL 在审计摘要（`sanitize_for_log`，`src/service/audit/log.rs`）覆盖 Python `_audit.py` 的敏感形态全集：`sk-` 形密钥、`ghp_`/`gho_`/`ghs_`/`ghu_`/`glpat-`/`xox[baprs]-` 形 token、`password`/`passwd`/`secret`/`token`/`pwd`/`access_key`/`auth_key`/`secret_key`/`private_key` 键值对、`Bearer`（含 JWT 实参）、私钥 PEM 块、身份证号（17 位 + 校验位）、手机号、邮箱。脱敏 SHALL 先于截断执行，截断 SHALL 为 UTF-8 安全（不切多字节字符）；手机号、身份证号、邮箱、`Bearer`/JWT、私钥样本 SHALL NOT 以明文进入 `audit.log`。`AUDIT_SUMMARY_TRUNCATE_CHARS`（4096）与 Python 摘要 120 字的差异 SHALL 在 design.md 显式登记（R4 既有裁决，不在本 change 重开）。

#### Scenario: 联系方式零明文

- **WHEN** 审计摘要输入含手机号、身份证号、邮箱
- **THEN** 落盘摘要中三者均被替换为 `[REDACTED:<type>]` 且不含明文原文

#### Scenario: Bearer/JWT 与私钥零明文

- **WHEN** 摘要输入含 `Authorization: Bearer <jwt>` 或 `-----BEGIN ... PRIVATE KEY-----` 块
- **THEN** 对应明文段被替换为脱敏标签，私钥块不残留 `BEGIN` 段主体

#### Scenario: 先脱敏后截断 UTF-8 安全

- **WHEN** 摘要为含多字节字符的超长串且前段含敏感值
- **THEN** 输出长度不超过截断上限、边界不切坏 UTF-8 字符、敏感值不因截断而复活明文

### Requirement: 危险规则集语义等价

系统 SHALL 使内建危险规则覆盖 Python `_audit.py` 九条 dangerous 规则的语义面：`rm -rf` 词形删除、`mkfs`、`dd if=... of=/dev|sd|hd` 块设备写入、`shutdown`/`reboot`/`poweroff`、`chmod`/`chown` 系统目录形态、敏感路径写入、网络传输（`curl`/`wget`/`nc`/`ncat`/`telnet`/`ssh`，`network=true` 走外部 host 复核）、`base64`/`openssl` 解码外传包装。实现 SHALL 维持 O(n) 子串/词形判定（禁正则回溯），与 Python 正则的近似差异（如 `dd ` 裸词偏严）SHALL 在 design.md 登记；每条规则 SHALL 有独立命中样本测试。

#### Scenario: 关机重启规则命中

- **WHEN** 工具参数含 `shutdown -h now`、`reboot` 或 `poweroff`
- **THEN** 判定命中并给出关机/重启原因

#### Scenario: 解码外传包装命中

- **WHEN** 参数含 `base64 -d`、`openssl ... decrypt` 形态
- **THEN** 判定命中并给出解码传输原因

#### Scenario: telnet/ssh 网络传输命中

- **WHEN** 参数含 `telnet <host>` 或 `ssh <host> <cmd>` 且目标为外部 host
- **THEN** 判定命中网络传输；目标命中内网豁免时不命中

#### Scenario: rm -rf 任意目标命中

- **WHEN** 参数含 `rm -rf /tmp/x`（不限于根目录）
- **THEN** 判定命中危险删除（对齐 Python `rm\s+-rf` 语义面）

### Requirement: 规范化管线等价

系统 SHALL 使参数规范化管线（`src/service/audit/normalize.rs`）在拆链前完成单层变量展开，并挖掘参数文本内的赋值形（`CMD=rm;$CMD -rf` 中 `CMD=rm` 的值可被同名引用展开）；SHALL 支持别名折叠 `/bin/` 前缀与 `find -delete` → `rm -rf` 形态；SHALL 对全管线做 `..` 词法归一（O(n) 栈式，不触文件系统）。构造性绕过样本（文本赋值引用、`/bin/` 别名、`find -delete`）SHALL 全部命中危险规则。

#### Scenario: 文本赋值绕过失败

- **WHEN** 参数为 `CMD=rm;$CMD -rf /tmp`
- **THEN** 规范化后 `rm -rf` 可见，判定命中危险删除

#### Scenario: /bin 别名折叠命中

- **WHEN** 参数为 `/bin/rm -rf /etc/x`
- **THEN** 别名折叠后可命中 `rm -rf` 规则

#### Scenario: find -delete 别名命中

- **WHEN** 参数为 `find /tmp -delete`
- **THEN** 判定命中批量删除（语义等价 `rm -rf`）

#### Scenario: .. 全管线归一

- **WHEN** 参数为 `cat /tmp/../etc/passwd`
- **THEN** `..` 归一后命中敏感路径

### Requirement: 内外网判定偏严声明

系统 SHALL 在审计网络外传判定中把 IP 字面量（含 RFC1918 `10.`/`172.16-31.`/`192.168.`、环回 `127.`/`::1`、链路本地 `169.254.`/`fe80::`）一律视为非内网（可能外传），仅 `localhost`、`.local`/`.internal` 启发式与策略 `internal_suffixes` 显式清单可豁免；无法提取 host（空/`None`）SHALL 视为非内网。该偏严语义与原仓 Python `is_external_host` 豁免 RFC1918/环回/链路本地不同，SHALL 在 README §6 显式登记为有意差异（BREAKING 声明）。

#### Scenario: RFC1918 目标拦截

- **WHEN** 参数以 `--data` 向 `http://10.x` 或 `http://192.168.x` 外发
- **THEN** 判定命中网络外传（不因 RFC1918 豁免）

#### Scenario: 环回与链路本地字面量拦截

- **WHEN** 参数向 `http://127.0.0.1` 或 `http://169.254.x` 外发
- **THEN** 判定命中网络外传；仅 `localhost` 字面量按内网豁免

#### Scenario: internal_suffixes 显式豁免

- **WHEN** 目标 host 命中策略 `internal_suffixes` 或 `.local`/`.internal`
- **THEN** 网络外传规则不拦截

#### Scenario: 空 host 不豁免

- **WHEN** 网络类命中但无法提取 host（空/`None`）
- **THEN** 按非内网处理（fail-closed 拦截）

### Requirement: 审计开关真值集与非法值 fail-closed

系统 SHALL 以真值集合 `1`/`true`/`yes`/`on`（trim + 大小写不敏感）识别遗留 `AUDIT_ENABLED`；显式非空 `AUDIT_MODE` SHALL 优先，空白 `AUDIT_MODE` SHALL 走 `AUDIT_ENABLED` 回退并映射 `block`。`AUDIT_TIMEOUT`（须 ≥1 且避 110-130 竞态区间）与 `AUDIT_HOLD_MAX_BYTES`（须 ≥1 正整数）取值非法时 SHALL 拒启动（fail-closed）。真值集宽于原仓（原仓 `1/true/True/yes` 且无 trim/`on`）与非法值拒启动（原仓静默保默认）的差异 SHALL 在 README §6 显式登记（BREAKING）。

#### Scenario: 真值集表驱动

- **WHEN** `AUDIT_MODE` 为空/空白且 `AUDIT_ENABLED` 取 `1`/`true`/`yes`/`on`（含大小写与首尾空白变体）
- **THEN** 审计模式为 `block`；取 `0`/`false`/`no`/`off`/乱值时不启用

#### Scenario: 显式 AUDIT_MODE 优先

- **WHEN** `AUDIT_MODE` 显式非空（含 `off`）且 `AUDIT_ENABLED=1`
- **THEN** 以 `AUDIT_MODE` 为准，回退不生效

#### Scenario: 非法值拒启动

- **WHEN** `AUDIT_TIMEOUT` 为 `0`/负/110-130，或 `AUDIT_HOLD_MAX_BYTES` 为 `0`/非整数
- **THEN** 启动报错退出（不静默回落默认值）

### Requirement: 审计策略文件兼容

系统 SHALL 保留策略文件 fail-closed 语义：`AUDIT_POLICY_FILE` 不可读、含未知键、孤立列表项或非法 `mode` 时 SHALL 拒启动。`dangerous:` 段 SHALL 同时接受字符串形（`pattern` 或 `pattern => reason`，后缀 `[network]`）与对象形（`pattern`/`reason`/`network` 三字段，YAML mapping 与 JSON 对象），使原仓 Python 策略文件可直接加载或经最小迁移加载；对象形 `network=true` 的命中 SHALL 走外部 host 复核。与原仓「非法策略文件 → 禁用审计并继续」的差异 SHALL 在 README §6 登记。

#### Scenario: 对象形加载

- **WHEN** 策略文件 `dangerous:` 项为 `{pattern, reason, network: true}`
- **THEN** 解析为 `DangerRule` 且命中时执行外部 host 复核

#### Scenario: 旧策略文件迁移

- **WHEN** 加载原仓 Python 形态策略文件（含对象形 dangerous 与既有键）
- **THEN** 加载成功且规则按 `pattern`/`reason`/`network` 生效

#### Scenario: fail-closed 保持

- **WHEN** 策略文件不可读、含未知键、孤儿项或非法 mode
- **THEN** 启动报错退出，不降级为禁用审计

### Requirement: 审计写失败双层语义

系统 SHALL 区分审计落盘失败的路径语义：`Block`/`NeedApproval` 命中路径写失败 SHALL 保持既有阻断/审批结论不变并记 error 告警；`Allow` 路径写失败 SHALL NOT 阻断主请求，SHALL 递增连续失败计数，连续失败达 10 次 SHALL 升级 critical 告警并重置计数。故障注入测试 SHALL 覆盖两条路径与熔断计数行为。

#### Scenario: allow 写失败不阻断

- **WHEN** 放行事件审计写失败
- **THEN** 主请求正常放行，连续失败计数 +1

#### Scenario: deny 写失败结论不变

- **WHEN** 阻断命中事件审计写失败
- **THEN** 下游仍收阻断（结论不因写失败改变），并记 error 告警

#### Scenario: 连续失败升级告警

- **WHEN** 放行路径连续 10 次写失败
- **THEN** 触发 critical 熔断告警且连续失败计数重置

### Requirement: 审计事件内存环可查询

系统 SHALL 使审计事件在进程内环可查询：复用 `AdminState` 事件环（`src/service/admin/state.rs`，`EVENT_RING_CAP` 512、FIFO 淘汰、`query_events` 过滤、SSE 回放），审计命中/放行事件 SHALL 以 `kind="audit"` 推入；SHALL NOT 另建并行的 100 条专用审计环。环容量 SHALL ≥ Python 原仓 100 条，顺序 SHALL 为 FIFO 且可经 `query_events(kind="audit")` 与 `/_admin/events/stream` 回放查询。

#### Scenario: 容量与 FIFO 顺序

- **WHEN** 推入超过环容量的事件
- **THEN** 淘汰最旧事件、保留最新至多 512 条，查询结果按时间序返回

#### Scenario: 审计事件可查询

- **WHEN** 审计命中产生事件
- **THEN** `query_events(kind="audit")` 可见该事件，SSE 建连回放包含该事件

### Requirement: SSE metrics 周期快照

系统 SHALL 在 `GET /_admin/events/stream` 流内每 15s 推送一次 `event: metrics` 快照，data SHALL 为 `{range, model, upstream, metrics, series, health}`：`metrics`/`series`/`health` 口径 SHALL 与 `/_admin/metrics`、`/_admin/series`、`/_admin/health` 一致，`model`/`upstream`/`range` SHALL 与建连过滤维度一致；取数失败 SHALL 降级为对应 `*_unavailable` 错误对象，SHALL NOT 中断事件推送与 60s ping。

#### Scenario: 15s 快照形状

- **WHEN** SSE 建连后 15s 到达
- **THEN** 下游收到 `event: metrics`，data JSON 含 `range`/`model`/`upstream`/`metrics`/`series`/`health` 六键

#### Scenario: 取数失败降级

- **WHEN** metrics/series/health 取数抛错
- **THEN** 对应字段为 `{error: "*_unavailable"}`，流不中断、后续事件与 ping 照常

#### Scenario: 过滤维度一致

- **WHEN** 建连带 `model`/`upstream` 过滤
- **THEN** 快照内的该两字段与过滤值一致

### Requirement: MXID 校验拒绝多点 @

系统 SHALL 校验审批白名单 MXID 为 `@localpart:domain`：三段非空、`user` 与 `server` 不含空白，且 `@` 后（`localpart` 与 `domain` 整体）SHALL NOT 再出现 `@`；`@a@b:c` SHALL 判非法并拒启动。边界样本 SHALL 表驱动覆盖。

#### Scenario: 多点 @ 拒绝

- **WHEN** 白名单成员为 `@a@b:c`
- **THEN** 校验失败并拒启动

#### Scenario: 合法 MXID 通过

- **WHEN** 白名单成员为 `@admin:example.com`
- **THEN** 校验通过

#### Scenario: 空白与缺段拒绝

- **WHEN** 成员含空白、缺 `@`、缺 `:` 或 localpart/domain 为空
- **THEN** 校验失败并拒启动

### Requirement: deny 名单优先级

系统 SHALL 保证策略 `deny` 名单精确匹配为终判：命中后 SHALL 直接拒绝且 SHALL NOT 进入危险内容判定、SHALL NOT 被 `allow` 同名豁免，拒绝原因 SHALL 为 deny 名单原因；`allow` 名单 SHALL 仅在无危险内容时放行。`src/service/audit/rules.rs` 中 deny/allow 相关注释 SHALL 与上述语义一致，不得产生「名单命中绕过内容判定」的误导。

#### Scenario: deny 与 allow 同名

- **WHEN** 同一 tool 名同时在 `deny` 与 `allow` 名单
- **THEN** 判定为拒绝，原因为 deny 名单精确匹配

#### Scenario: deny 命中不进入内容判定

- **WHEN** deny 名单 tool 的参数含危险内容
- **THEN** 拒绝原因仍为 deny 名单原因（内容判定不改变结论）

#### Scenario: allow 不豁免危险内容

- **WHEN** allow 名单 tool 的参数含危险内容
- **THEN** 判定命中危险内容（allow 仅在无危险时放行）

### Requirement: find 预检覆盖

系统 SHALL 使审计预检（`audit_precheck`，`src/service/audit/rules.rs`）覆盖 `find` 危险形态：tool 名为 `find`，或参数前缀含 `find ` 且带 `-exec`/`-delete`/`--delete` 时 SHALL 返回 true（暂停 flush 等待完整判定）。`find /etc -exec rm` SHALL NOT 因预检漏判而在判定前放行帧。

#### Scenario: find -exec 预检命中

- **WHEN** 参数前缀为 `find /etc -exec rm`
- **THEN** `audit_precheck` 返回 true

#### Scenario: find -delete 预检命中

- **WHEN** 参数前缀含 `find ... -delete` 或 `--delete`
- **THEN** `audit_precheck` 返回 true

#### Scenario: 普通命令不误报

- **WHEN** tool 名与参数均不含危险前缀/形态（如 `echo ok`）
- **THEN** `audit_precheck` 返回 false

### Requirement: 启动校验顺序

系统 SHALL 在启动时先完成审批白名单校验（`APPROVAL_WHITELIST` MXID 校验），先于 TPM 门禁、sqlite 初始化、KeePass 装载、审批清扫任务与指标回填；白名单非法 SHALL 拒启动且 SHALL NOT 产生磁盘/网络副作用（不创建数据目录、不触 TPM、不起后台任务）。

#### Scenario: 非法白名单 fail-fast

- **WHEN** `APPROVAL_WHITELIST` 含非法 MXID
- **THEN** 启动在 TPM/sqlite/KeePass/清扫/回填之前报错退出，无落盘与网络访问副作用

#### Scenario: 合法白名单顺序不回归

- **WHEN** 白名单合法
- **THEN** 启动按校验先行后继续原初始化序列，行为与现网一致

### Requirement: Cookie https 双判据

系统 SHALL 以双判据判定管理 Cookie 安全属性：`X-Forwarded-Proto: https` 或 RFC 7239 `Forwarded` 头内 `proto=https`（大小写不敏感）任一命中时 SHALL 签发 `__Host-admin_token`（`Secure` + `Path=/`），两者皆无或非 https 时 SHALL 退回 http 兼容 `admin_token`（无 `Secure`）。README SHALL 声明反代部署必须透传协议头，否则 https Cookie 降级。

#### Scenario: X-Forwarded-Proto 判据

- **WHEN** 请求头 `X-Forwarded-Proto: https`
- **THEN** 响应 `Set-Cookie` 为 `__Host-admin_token` 且含 `Secure`

#### Scenario: RFC 7239 Forwarded 判据

- **WHEN** 请求头 `Forwarded: for=...;proto=https`
- **THEN** 响应 `Set-Cookie` 为 `__Host-admin_token` 且含 `Secure`

#### Scenario: 无协议头降级

- **WHEN** 两个协议头皆缺失或均非 https
- **THEN** 签发 http 兼容 `admin_token`（无 `Secure`），README 声明反代透传要求
