## Context

独立审计（2026-09-13）对照原仓 Python `credential-proxy` 在审计规则面确认 17 项发现（`A1`-`A17`，见 proposal 覆盖表）。现状真相源（行号为本仓/原仓当前快照）：

- **`A1` 死码与规格悬空**：`AuditLogger`/`log_event`（`src/service/audit/log.rs:169-245`）全仓引用仅本文件与其单测；`src/service/audit.rs:10` 模块文档与 canonical `openspec/specs/audit-tpm-matrix/spec.md` 的 JSONL 10MB×5 + 0600 + 写失败 fail-closed 条款因此未实际生效。`log_event` 含同步文件 IO 与 `std::thread::sleep(50ms)`（`log.rs:195-206`）。
- **`A3` 脱敏形态缩水**：`sanitize_for_log`/`mask_secret_forms`（`log.rs:42-158`）仅覆盖 `sk-`/`sk_or_`/`ghp_`/`gho_`/`xoxb-`/`xoxp-`/`AKIA`/`__VG_CRED_` 前缀与 `password`/`passwd`/`secret`/`token`/`api_key`/`apikey` 键；对照 Python `_SECRET_PATTERNS`（`_audit.py:993-1074`）缺 Bearer/JWT、私钥 PEM、身份证、手机、邮箱、`pwd`、`*_key` 形态。
- **`A4` 规则面收窄**：`classify_segment`（`rules.rs:36-88`）子串表缺 `shutdown`/`reboot`/`poweroff`、`base64`/`openssl` 解码、`telnet`/`ssh` 网络传输；`rm -rf` 仅根部形（`rules.rs:45`）；`chmod`/`chown` 仅 `chmod 777 /` 两形（`rules.rs:43-44`）。对照 Python 九条 dangerous（`_audit.py:502-530`）。
- **`A5` 规范化不等价**：`canonicalize_args`（`normalize.rs:249-254`）顺序为转义→变量（空 env + `std::env::var` 回退）→别名（仅 `ls` 族）→空白；无文本赋值挖掘、无 `/bin/` 折叠、无 `find -delete` → `rm -rf`；`..` 仅敏感路径局部归一（`rules.rs:102-121`）。对照 Python 管线（`_audit.py:242-268`、`_expand_vars`/`_expand_aliases`）。
- **`A6` 内外网默认相反**：`is_internal_host`（`rules.rs:204-226`）仅 `localhost`/`.local`/`.internal`/`internal_suffixes` 豁免，IP 字面量一律非内网；Python `is_external_host`（`_audit.py:439-470`）对 RFC1918/环回/链路本地返回内网、空 host 返回 `None`（非外网）。
- **`A7` 开关口径**：真值集 `1/true/yes/on`（trim + 大小写不敏感，`validate.rs:62-67`）宽于 Python（`1/true/True/yes`，无 trim/`on`，`_audit.py:1118-1124`）；空白 `AUDIT_MODE` 走回退（`verdict.rs:31-39`）；非法 `AUDIT_TIMEOUT`/`AUDIT_HOLD_MAX_BYTES` 拒启动（`validate.rs:217-240`），Python 静默保默认。
- **`A8` 策略文件语义**：`AuditPolicy::load_from_file`/`parse_minimal_yaml`（`policy.rs:38-166`）不可读/未知键/孤儿项拒启动、仅 6 键，`dangerous` 仅字符串形；Python（`_audit.py:705-722`）缺文件/解析失败禁用审计继续，支持对象形 `{pattern,reason,network}`。
- **`A9` 写失败不对等**：`log_event`（`log.rs:189-206`）统一重试 50ms 后返回 `Storage`（文档要求调用方拒主请求）；Python（`_audit.py:909-926`）deny 写失败仍阻断、allow 写失败不阻断 + 连续失败熔断计数。
- **`A10` 环缺失与既有环闲置**：Python 进程内 `_audit_log_ring` 100 条（`_audit.py:585-599`）；Rust 无审计环，但 `AdminState` 已有事件环 `EVENT_RING_CAP=512`（`src/service/admin/state.rs:19`）含 `query_events`（`:113-130`）与 SSE 回放，`push_event` 生产零调用（`state.rs:81-82` 注释自认待接线）。
- **`A11` SSE 快照缺失**：Python `event: metrics` 15s 全量快照（`_admin.py:535-580`）；Rust `/_admin/events/stream`（`src/handler/admin.rs:438-508`）仅事件广播 + 60s ping。
- **`A12` MXID 校验**：`src/config/validate.rs:267-276` 与 `src/service/matrix/branch.rs:67-76` 两处同构校验仅查三段非空，`@a@b:c` 可通过；Python `_audit.py:1089-1094` 额外要求 `s[1:].count('@') == 0`。
- **`A13` 注释误导**：deny 早返实现在 `rules.rs:278-282` 正确；易误导注释位于 `rules.rs:276-277`（findings 标注 `verdict.rs`，以实际代码为准）。
- **`A14` `find` 预检缝隙**：`audit_precheck`（`rules.rs:230-274`）前缀表含 `rm`/`shutdown` 等但无 `find`，`find /etc -exec rm` 参数前缀不触发暂停。
- **`A15` 启动顺序**：`Config::from_env` 已在配置加载期做白名单成员校验（`env_parse.rs:485-491` → `parse_whitelist`），但 `main.rs:117` 的显式门禁位于 TPM/sqlite/KeePass/清扫/回填之后（`main.rs:62-115`）；审计要求校验先行且不触盘/网。
- **`A16` Cookie 判据**：`admin.rs:135-148` 仅信 `X-Forwarded-Proto`；Python 用 `request.scheme`（`_admin.py:324-354`）。
- **`A2`/`A17` 记录**：PII 锁中毒 panic（`src/service/pii/custom.rs`）由 `veil-pii-parity-closeout` P14 承接；既有非目标与分歧见 D16/D17。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/`、README；不重开已裁决项（R4 截断、§6.4 流式审批、§8.4 入口、§3 限流、§7.1 HOP）。

## Goals / Non-Goals

**Goals：**

- 给出 `A1`/`A3`-`A16` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证；`A2`/`A17` 仅登记交叉引用。
- 把「审计日志真实落盘」「脱敏零明文」「规则/规范化等价类」「写失败双层语义」「事件可查询」「SSE 快照」收敛为 spec 契约，README §4/§6 与行为同批同步。
- 对无法完全等价的分歧（内外网偏严、开关真值集、非法值拒启动、策略文件 fail-closed、截断长度）以显式 BREAKING 声明对齐，不静默漂移。

**Non-Goals：**

- 不修 `A2`（PII 锁中毒，转出 `veil-pii-parity-closeout` P14）。
- 不重开 R4 截断裁决（audit 4096 / metrics 1000 / Python 120 差异维持有意声明）。
- 不放松安全口径（D5/D6/D7/D8 均为保留偏严 + 文档声明）。
- 不改流式审批同步阻塞（§6.4）、管理静态页、入口模式（§8.4）、限流（§3）、HOP（§7.1）。
- 不改 `src/`、`tests/`、README；不提交 commit。

## Decisions

### D1：`A1` 裁决 = 接线（非删死码），接线必须 `spawn_blocking`

**决策**：保留 `AuditLogger` 并将其接入流式/非流式审计判定路径：verdict 事件（命中与放行）经 `spawn_blocking` 调用 `log_event` 写 `DATA_DIR/audit.log`；同步推送 `AdminState` 事件环（D9）。启动期构造单例（`AppState` 持有 `Arc<AuditLogger>`），不保留零调用形态。

**理由**：canonical spec 与模块文档已要求落盘，删除死码需反向修订规格且失去合规审计证据；接线符合「先实现契约再谈删减」。`log_event` 含同步 fs + `std::thread::sleep(50ms)`，直接调用会阻塞 tokio worker，必须 `spawn_blocking`。

**备选**：修订 spec + 删 `AuditLogger`——与 canonical 冲突且审计证据缺失，不采用；仅保留函数不动——审计缺陷保留，不采用。

### D2：`A3` 脱敏形态对齐、截断维持 R4 有意差异

**决策**：`sanitize_for_log` 补齐 Python `_SECRET_PATTERNS` 形态面：① `sk-` 密钥；② `gh[pousu]_`/`glpat-`/`xox[baprs]-` token；③ 键值对 `password`/`passwd`/`secret`/`token`/`pwd`/`access_key`/`auth_key`/`secret_key`/`private_key`（引号与裸键两形，值不跨 JSON 字段贪吃）；④ `Bearer <token>`（含 JWT）；⑤ PEM 私钥块；⑥ 身份证（17 位 + `X`）；⑦ 手机（`1[3-9]` + 9 位，前后不粘数字）；⑧ 邮箱。保持「先脱敏后截断」与 UTF-8 安全边界；`AUDIT_SUMMARY_TRUNCATE_CHARS`（4096）与 Python 摘要 120 字的长度差异登记为 R4 既有裁决、本 change 不重开。

**理由**：手机/身份证/邮箱明文入 `audit.log` 是实际泄漏面；形态补齐后零明文可样本断言。截断长度已由 R4 双声明裁决（audit 4096 行预算 vs metrics 1000），重开会引入无谓震荡。

**备选**：连截断一起对齐 120——推翻已归档裁决且改变审计行预算，不采用；仅补关键词不补正则形态——遗漏号码/邮箱类，不采用。

### D3：`A4` 规则补齐采用 O(n) 子串/词形近似，逐规则测试

**决策**：补齐规则面：`shutdown`/`reboot`/`poweroff`；`base64`/`openssl` 的 `-d`/`decode`/`decrypt` 组合；`telnet`/`ssh` 网络传输（并入 `is_exfiltration`）；`rm -rf` 由根部形放宽为词形（任意目标）；`chmod`/`chown` 系统目录形态（`chmod [0-7]{3,4} /{etc,usr,bin,var}`、`chown <user> /{etc,usr,bin}` 子串近似）；敏感路径补 `/boot/`。实现维持 O(n) 无回溯（禁全文正则），与 Python 正则的近似差异（如 `dd ` 裸词偏严、`chmod` 组合近似）在 design 登记并逐规则测试。

**理由**：子串近似是既有性能决策（模块文档 `audit.rs:6` 明示「禁全文正则回溯」）；等价面以语义命中为准，逐规则测试锁定覆盖。

**备选**：改用正则——回溯风险与既有裁决冲突，不采用；仅补文档不改规则——漏拦保留，不采用。

### D4：`A5` 规范化管线重排为 Python 等价顺序，去除宿主 env 回退

**决策**：`canonicalize_args` 对齐 Python 顺序：转义 → 空白合并 → `..` 归一 → 单层变量展开（**仅参数文本内赋值挖掘** + 显式注入 env，去除 `std::env::var` 隐式回退）→ 拆链（`;`/`&&`/`||`/`|`/换行）→ 别名折叠（`/bin/<cmd>` → `<cmd>`、`find -delete` → `rm -rf`）。`find -delete` 定位用「先找 `-delete` 再向前找 `find`」O(n) 算法；`..` 归一全管线执行（栈式，不触文件系统）。

**理由**：`CMD=rm;$CMD -rf` 类绕过根因是赋值-引用关系在拆链后丢失；宿主 env 回退使判定随部署环境漂移（不可复现），Python 无此行为，去除后判定确定。

**备选**：保留 env 回退——环境污染与不可复现，不采用；只补 `/bin/` 不补赋值挖掘——绕过保留，不采用。

### D5：`A6` 裁决 = 保留偏严内外网语义 + README §6 BREAKING 声明

**决策**：保留 `is_internal_host` 现行偏严语义：IP 字面量（RFC1918/环回/链路本地）一律非内网，空/无法提取 host 不豁免；仅 `localhost`/`.local`/`.internal` 与 `internal_suffixes` 显式清单豁免。README §6 新增条目声明与原仓 `is_external_host` 差异（原仓放行 `curl 10.x --data`，本仓拦截）及豁免手段（`internal_suffixes`）。

**理由**：安全侧不放松——内网目标同样可能是外传/横向移动跳板；对齐 Python 会静默放宽线上拦截面。项目既有模式（§6.1-§6.7）支持「有意偏严 + 显式声明」。

**备选**：对齐 Python 豁免 RFC1918——放宽拦截面且无安全收益，不采用；不改也不声明——静默漂移，不采用。

### D6：`A7` 裁决 = fail-closed 保留 + 真值集锁步声明

**决策**：真值集恒为 `1`/`true`/`yes`/`on`（trim + 大小写不敏感），显式非空 `AUDIT_MODE` 优先，空白 `AUDIT_MODE` 走 `AUDIT_ENABLED` 回退映射 `block`；非法 `AUDIT_TIMEOUT`（含 110-130 禁区）与 `AUDIT_HOLD_MAX_BYTES` 保持拒启动。README §6 登记两处与原仓差异（真值集更宽、非法值拒启动 vs 静默默认）。

**理由**：审计总开关非法时静默保默认（默认 `off`）等于静默关闭审计，属 fail-open；拒启动是安全正确解。真值集更宽属兼容增强，锁步文档即可。

**备选**：对齐 Python 静默默认——fail-open，不采用；收窄真值集去掉 `on`——破坏既有 README 承诺，不采用。

### D7：`A8` 裁决 = fail-closed 保留 + `dangerous` 对象形兼容 + 旧文件迁移

**决策**：策略文件不可读/未知键/孤儿项/非法 `mode` 保持拒启动；`dangerous:` 段增加对象形 `{pattern, reason, network}`（YAML mapping 与 JSON 对象；`network` 缺省 `false`），与字符串形（`pattern`/`pattern => reason`/`[network]` 后缀）并存；原仓风格文件（`allow`/`deny`/`dangerous`/`internal_suffixes` 四键 + 对象形 dangerous）可直接加载。README §6 登记与原仓「解析失败禁用审计继续」的差异。

**理由**：静默禁用审计是降级攻击面；对象形是原仓文件的实际形态，不支持则迁移须重写文件，成本与出错率更高。

**备选**：对齐 Python 禁用继续——fail-open，不采用；仅支持字符串形——旧文件不可迁移，不采用。

### D8：`A9` 写失败双层语义按 verdict 路径区分

**决策**：`log_event` 保留重试与计数，但失败语义由调用方按路径处置：`Block`/`NeedApproval` 命中路径写失败 → 保持既有阻断/审批结论（不因写失败改判）+ error 告警 + 计数 +1；`Allow` 路径写失败 → 不阻断主请求 + 计数 +1，连续失败达 10 次 → critical 熔断告警并重置计数。故障注入测试覆盖两条路径与计数阈值。

**理由**：写失败不应把可用性风险放大到放行路径（Python 语义）；deny 路径结论本已决定，写失败只影响证据留存，降级为告警即可。

**备选**：统一 fail-closed 拒主请求（现值）——放行路径被审计盘故障拖垮，不采用；统一不阻断——deny 证据丢失无告警，不采用。

### D9：`A10` 裁决 = 复用 `AdminState` 事件环，不新增专用环

**决策**：审计事件以 `kind="audit"` 推入既有 `AdminState` 事件环（`EVENT_RING_CAP=512`、FIFO、`query_events`、SSE 回放）；不新增 100 条专用环。D1 接线时同步调用 `push_event`，`push_event` 生产接线随本 change 补齐（现为零调用）。

**理由**：功能重叠（Python 环目的即告警通道不可用时事件不无痕），既有环容量 512 > 100 且查询/回放接口齐备；双环会引入容量与顺序不一致的观测分叉。

**备选**：新增 100 条专用环——冗余存储与两套查询面，不采用；仅落盘不推环——内存可观测性缺失，不采用。

### D10：`A11` 裁决 = 补 15s `event: metrics` 快照

**决策**：`/_admin/events/stream` 流内每 15s 推一次 `event: metrics`，data 为 `{range, model, upstream, metrics, series, health}`：三份取数复用既有服务函数（`/_admin/metrics`、`/_admin/series`、`/_admin/health` 口径），`model`/`upstream`/`range` 与建连过滤一致；取数失败降级对应 `{error: "*_unavailable"}`，不中断事件推送与 60s ping。

**理由**：对齐原仓大盘契约，浏览器/SSE 客户端无需另开轮询；失败降级保证流可用性。

**备选**：声明 Non-Goal 并文档化轮询替代——下游前端需改造，不采用；另起独立 SSE 通道——重复连接与限流占用，不采用。

### D11：`A12` MXID 校验增加「无额外 @」并收敛两处实现

**决策**：`@` 前缀后部分（localpart + domain）SHALL NOT 再含 `@`（等价 Python `s[1:].count('@') == 0`）；`src/config/validate.rs::is_valid_mxid` 与 `src/service/matrix/branch.rs::is_valid_mxid` 两处同步修复并保持语义一致（可抽共享 helper），边界样本表驱动测试（`@a@b:c`、`@admin:example.com`、缺段、空白）。

**理由**：`@a@b:c` 形源于占位符误写（Python 注释），放过会在审批链静默失配；两处实现是同一校验的副本，必须同步否则出现「配置放行、链路拒绝」分叉。

**备选**：只修配置侧——链路侧仍放过，不采用；删链路侧只留配置侧——丢失显式门禁与单测锚点，不采用（保留双点但收敛语义）。

### D12：`A13` deny 终判注释修正 + 优先级锁定

**决策**：修正 `src/service/audit/rules.rs:276-277` 注释，明确「deny 精确匹配即终判、不再进入危险内容判定；allow 免责仅在无危险内容时成立」；补锁定测试：同一 tool 名同时在 deny 与 allow 时 deny 胜且原因为名单原因、deny 命中不因参数含危险内容改判、allow 名单内危险内容仍拦截。

**理由**：行为已正确（`rules.rs:278-282` 早返优先于内容判定），仅注释易被读成「名单内工具的内容判定结果可覆盖名单」；锁定测试防后续重构调整优先级。

**备选**：只改注释不补测试——语义无回归锚点，不采用；调整实现顺序——现值已正确，无改动必要。

### D13：`A14` 预检补齐 `find` 形态

**决策**：`audit_precheck` 前缀表补 `find`（tool 名精确与 `find ` 起始），参数前缀含 `-exec`/`-delete`/`--delete` 时同样返回 true（含 JSON 包装形）。

**理由**：预检唯一职责是「暂停 flush 等完整判定」；`find /etc -exec rm` 完整参数到达前若已放行帧，终判命中时无法回收已发字节。

**备选**：预检加全量规则镜像——维护双份规则且成本高，不采用；仅补 tool 名——参数形仍漏，不采用。

### D14：`A15` 启动校验先行与真源收敛

**决策**：校验先行以 `Config::from_env`（`env_parse.rs:485-491`）为第一真源（A12 修复后覆盖多点 `@`）；`main.rs:117` 的显式门禁前移至 TPM 门禁之前，保证「校验失败不触盘/网」。无副作用测试断言非法白名单下不创建数据目录、不触 TPM、不起后台任务。

**理由**：审计发现的门禁滞后（TPM/sqlite/KeePass 之后）会在失败场景留下 TPM 访问与目录副作用；前移成本极低且保持显式复核。复核确认配置加载期已有同等校验（`branch.rs:54` 注释自认），两者语义必须一致。

**备选**：删除 `main.rs:117` 冗余调用——可行但丢失显式门禁锚点，不采用；仅依赖配置加载不改 main——findings 要求的顺序显式性不满足，不采用。

### D15：`A16` Cookie https 双判据

**决策**：`X-Forwarded-Proto: https` 或 RFC 7239 `Forwarded` 中 `proto=https`（大小写不敏感）任一命中 → `__Host-admin_token; Secure`；否则 http 兼容 `admin_token`。README 声明反代必须透传协议头（否则 Secure Cookie 降级为 http Cookie）。

**理由**：反代实现不一（Nginx `X-Forwarded-Proto`、通用 `Forwarded`）；双判据覆盖主流部署且不依赖 TLS 终结位置。`__Host-` 前缀要求 Secure + Path=/，判据错误会导致 Cookie 被浏览器拒收或降级。

**备选**：只文档化不补判据——通用反代仍降级，不采用；改读连接 scheme——本仓无 TLS 监听，不可用。

### D16：`A2` PII 锁中毒转出交叉引用

**决策**：`src/service/pii/custom.rs` 的 `.expect("检测器锁无毒")` panic 由 change `veil-pii-parity-closeout` P14 负责；本 change 不修改 `src/service/pii/`，仅在 proposal 覆盖表、Non-Goals 与本条交叉引用（含 `src/service/pii/scope.rs::recover_mutex` 替代实现指引）。

**理由**：避免双 change 重复修复与合并冲突；锁中毒属 PII 面归口。

### D17：`A17` 既有非目标与已声明分歧登记

**决策**：以下项不重复修复，仅在覆盖表与本条登记：管理静态页 Non-Goal（README 管理控制台段）、流式审批同步阻塞未迁移（README §6.4）、轻量入口语义（§8.4）、管理限流 `10/min`（§3）、HOP 头 8 项（§7.1）；`AUDIT_MODE` 非法值拒启动随 A7 决策在 README §6 落档 BREAKING。

**理由**：均为已归档 change 的显式声明或有意设计，重复修复会静默推翻既有契约。

### D18：`A18` metrics 时序口径等价映射登记

Rust 时序（`src/service/admin/events.rs:6`）为 `five_min`/`hourly`/`daily` 三档，Python 原仓为 `1h 分钟级 60 点`/`24h`/`7d`/`30d` 四档；12 桶边界与 `RING_CAP=10000` 一致，`cached_read`/`cached_write`/`model` 分桶只加不改（README §7.2 一致），非对话 `is_passthrough` 丢弃与 Python v0.9.35+ 一致。

**裁决**：保留 Rust 三档口径，登记 `1h→five_min` 等映射等价表并补回归测试锁定数值等价；旧 key 兼容由 `/_admin/series` 映射层承担。
**备选**：改用 Python 四档命名 —— 破坏既有 admin API 契约且收益为零，拒绝。

### D19：`A19` events 过滤扩展登记

Rust（`src/handler/admin.rs:392-431`）过滤为 `kind`/`since`/`limit`，`verdict` 归一后仅命中环内 kind 才过滤，`model`/`upstream` 仅回显；Python（`_admin.py:461-478`）为 `limit(1-200)`/`kind`/`upstream`/`model`，`verdict` 忽略仅标注。

**裁决**：`since` 与 `verdict` 归一为新增/加法语义，登记并补 `limit` 1/200 边界与组合过滤回归；不回收既有 query 参数。
**备选**：移除 `since` 回归 Python —— 删除已发布能力，拒绝。

## Risks / Trade-offs

- [`A1` 接线引入阻塞 IO] → `spawn_blocking` + 单例 `Arc`；写失败按 D8 区分路径，压测验证流式时延无回退。
- [`A3` 邮箱/手机正则误伤] → 值形态限定（前后不粘数字、值不跨 JSON 字段）；样本测试锁定精确替换，README §4 声明摘要脱敏范围扩大。
- [`A4`/`A5` 补齐后误报上升] → 逐规则测试 + 既有用例全绿；误报优于漏审（与 §6.5 检索口径同原则），README 审计表同步。
- [`A6` 偏严拦截内部自动化] → README §6 BREAKING + `internal_suffixes` 显式豁免指引；上线后监控网络外传拦截量。
- [`A7` 非法值拒启动影响旧部署] → README §6 登记 + 启动错误信息给出合法区间；迁移指引明确。
- [`A8` 对象形解析分叉] → YAML mapping 与 JSON 对象统一走同一 `DangerRule` 构造；旧文件样本回归。
- [`A9` allow 失败不阻断削弱审计保证] → 熔断计数 + critical 告警 + SSE/环观测；README §4 声明写失败双层语义。
- [`A10` 环复用后审计事件容量感知] → 512 容量与 FIFO 测试；文档声明审计事件与业务事件共享环。
- [`A11` 15s 快照增加流负载] → 复用服务函数（不 HTTP 自调用）+ 失败降级；快照与 ping 正交不互相阻塞。
- [`A12` 收紧校验拒绝既有合法形态] → 仅拒绝 localpart/domain 含 `@`；`@admin:example.com` 等常规形态回归测试。
- [`A14` 预检过宽误暂停] → 仅对 `find ` + `-exec`/`-delete` 组合命中；普通 `find /tmp -name` 不误报测试。
- [`A15` 前移门禁改变失败优先级] → 白名单错误现在先于 TPM/sqlite 报错；测试锁定错误顺序与无副作用。
- [`A16` `Forwarded` 头解析复杂] → 仅取 `proto` 参数（分号/逗号分隔容错，大小写不敏感）；两判据测试 + 缺失降级测试。

## Migration Plan

1. 按 tasks 顺序落地：先 `A1`/`A9`/`A10` 落盘与可观测接线，再 `A3`/`A4`/`A5` 规则与脱敏主体，再 `A6`/`A7`/`A8` 决策类对齐，再 `A11`-`A16` 缺陷收敛，最后 `A17` 登记与门禁。
2. 每组独立 `cargo test -p veil <组>`；README §4/§6 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：新增 BREAKING 声明 4 处（`A6`/`A7`/`A8`/`A16` 的偏严与 fail-closed 差异）+ 行为增强（脱敏形态、规则覆盖、SSE 快照、Cookie 判据）；`A9` 写失败语义放宽属可用性修复并在 §4 声明。

## Open Questions

- `A11` 快照内 `range` 默认值与 `series` 新旧口径映射（`1h`/`24h`/`7d`/`30d` 兼容表）需在 apply 阶段与 `/_admin/series` 现值对齐后锁定；若默认口径有歧义，以 `/_admin/series` 无参默认为准并在此回填。
- `A6` 偏严语义上线后若出现内部自动化误拦（`internal_suffixes` 未配置场景），是否放宽 RFC1918 豁免需以运行观测另立 change，不在本 change 预设。
- `A3` 邮箱/手机正则的误伤率无线上真值，apply 阶段以样本测试 + 审计摘要抽查为准；如需更严边界（TLD 白名单）另立 change。
