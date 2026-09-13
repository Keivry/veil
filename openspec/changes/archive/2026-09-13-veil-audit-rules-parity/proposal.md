## Why

独立审计（2026-09-13）在审计规则面对照原仓 Python `credential-proxy` 确认 19 项发现（`A1`-`A19`），其中多项违反既有契约或声明：

- **落盘未接线（`A1`，high）**：`AuditLogger`/`log_event`（`src/service/audit/log.rs:169-245`）全仓仅本文件与其单测引用，生产零调用；而 `src/service/audit.rs:10` 模块文档与 canonical `openspec/specs/audit-tpm-matrix/spec.md` 均要求 `DATA_DIR/audit.log` JSONL 10MB×5 + 0600 + 写失败 fail-closed 真实生效。
- **分歧类（`A3`-`A9`）**：摘要脱敏形态缩水（手机/身份证/邮箱可能明文入 `audit.log`）；危险规则由正则改子串且规则面收窄；规范化管线不等价（`CMD=rm;$CMD -rf` 类可漏拦）；内外网判定默认相反；`AUDIT_ENABLED` 真值集与非法值容忍度不同；策略文件语义相反（不可读拒启动 vs 禁用继续、缺对象形）；写失败语义不对等（allow 路径被放大为拒主请求）。
- **缺失类（`A10`-`A11`）**：进程内审计事件环不可查询（Python 保留 100 条）；SSE 缺少 15s 全量 metrics 快照。
- **缺陷类（`A12`-`A15`）**：MXID 校验放过 `@a@b:c`；deny 早返注释误导；`find` 预检缝隙（`find /etc -exec rm` 可能预检放行）；启动顺序白名单校验滞后（先触 TPM/sqlite/keepass）。
- **低危与记录（`A16`/`A2`/`A17`）**：Cookie https 判定依赖 `X-Forwarded-Proto` 单判据；PII 锁中毒 panic 由 `veil-pii-parity-closeout` P14 承接；既有非目标与已声明分歧登记不重复修复。
- **等价性与加法记录（`A18`/`A19`）**：metrics 时序口径等价性依赖映射（Rust `five_min/hourly/daily` ↔ Python `1h 分钟级 60 点/24h/7d/30d`）；events 过滤新增 `since`、`verdict` 归一过滤、`model`/`upstream` 仅回显——登记并补回归。

本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 README。真相源：`src/service/audit/{log,rules,normalize,policy,verdict,hold}.rs`、`src/config/{validate,env_parse}.rs`、`src/main.rs`、`src/handler/admin.rs`、`src/service/admin/state.rs`；对照基线：原仓 `_audit.py`（`242-268`、`502-530`、`705-722`、`909-926`、`993-1074`、`1089`、`1118-1124`）、`_admin.py`（`318-360`、`535-580`）、`proxy.py:100-107`。

## What Changes

- **`A1` 审计落盘接线（推荐接线，不删死码）**：将 `AuditLogger` 接入流式（`src/handler/llm/pump/spawn.rs`）与非流（`src/handler/llm/nonstream.rs`）判定路径；写盘经 `spawn_blocking`（`log_event` 含同步 fs + `std::thread::sleep(50ms)`）；事件同步推 `AdminState` 事件环（`kind="audit"`，联动 `A10`）；测试落盘/轮转/权限/失败语义。
- **`A2` PII 锁中毒交叉引用（记录）**：由 `veil-pii-parity-closeout` P14 负责，本 change 不修改 `src/service/pii/`，仅在覆盖表与 Non-Goals 登记。
- **`A3` 摘要脱敏形态补齐**：对齐 Python `_SECRET_PATTERNS` 全形态（`sk-`/`gh*`/`glpat-`/`xox*` token、`password`/`pwd`/`*key`/`secret`/`token` 键值对、`Bearer`（含 JWT）、私钥 PEM、身份证、手机、邮箱）；先脱敏后截断与 UTF-8 安全保持；截断 4096 vs Python 120 差异在 design 登记（R4 既有裁决不重开）；样本测试断言零明文。
- **`A4` 危险规则补齐**：补 `shutdown`/`reboot`/`poweroff`、`base64`/`openssl -d|decode|decrypt`、`telnet`/`ssh` 网络传输、`rm -rf` 任意目标词形、`chmod`/`chown` 系统目录形态；维持 O(n) 无回溯子串实现，逐规则测试。
- **`A5` 规范化管线对齐**：拆链前单层变量展开并挖掘文本赋值（`CMD=rm;$CMD -rf`）；别名折叠 `/bin/` 与 `find -delete` → `rm -rf`；全管线 `..` 归一；构造性绕过测试。
- **`A6` 内外网判定裁决**：保留 Rust 偏严语义（IP 字面量一律非内网，含 RFC1918/环回/链路本地；空 host 不豁免），README §6 显式 BREAKING 登记与原仓差异；四类目标测试。
- **`A7` 开关口径裁决**：真值集锁步 `1/true/yes/on`（trim + 大小写不敏感）+ 显式 `AUDIT_MODE` 优先 + 空白回退；非法 `AUDIT_TIMEOUT`/`AUDIT_HOLD_MAX_BYTES` 保持 fail-closed 拒启动；README §6 BREAKING 登记；表驱动测试。
- **`A8` 策略文件兼容**：保留 fail-closed（不可读/未知键/孤儿项拒启动），`dangerous:` 增加对象形 `{pattern,reason,network}`（YAML/JSON）并支持旧 Python 文件迁移；测试旧策略文件。
- **`A9` 写失败双层语义**：`deny`/`approve` 命中写失败保持结论 + error 告警；`allow` 写失败不阻断主请求 + 连续失败计数（10 次 critical 熔断告警）；故障注入测试。
- **`A10` 内存环裁决（复用既有环）**：不新增 100 条专用环，审计事件推入 `AdminState` 事件环（`EVENT_RING_CAP=512` + `query_events` + SSE 回放）；容量/FIFO/查询测试。
- **`A11` SSE metrics 快照**：`/_admin/events/stream` 每 15s 推 `event: metrics`，data 为 `{range,model,upstream,metrics,series,health}`（复用 `/_admin/{metrics,series,health}` 口径；失败降级 `*_unavailable`；不中断事件与 ping）；消息形状测试。
- **`A12` MXID 校验对齐**：`@a@b:c` 拒（localpart/domain 不得再含 `@`）；边界测试。
- **`A13` deny 注释与锁定**：修正 `rules.rs:276-282` 误导注释（deny 终判不进入内容判定、allow 免责仅无危险内容）；deny 优先级锁定测试。
- **`A14` `find` 预检补齐**：预检覆盖 tool 名 `find` 与 `find `/`-exec`/`-delete`/`--delete`；`find /etc -exec rm` 测试。
- **`A15` 启动顺序重排**：白名单校验前置到 TPM/sqlite/KeePass/清扫/回填之前，fail-fast 且无磁盘/网络副作用；无副作用测试。
- **`A16` Cookie https 双判据**：`X-Forwarded-Proto` 或 RFC 7239 `Forwarded: proto=https` 任一命中签发 `__Host-` Secure Cookie；README 声明反代透传要求；测试两判据。
- **`A17` 既有分歧登记**：管理静态页 Non-Goal、流式审批同步阻塞 §6.4、轻量入口 §8.4、管理限流 10/min §3、HOP 8 项 §7.1、`AUDIT_MODE` 非法值拒启动（A7 决策后 BREAKING 落档）仅在 design 与覆盖表登记，不重复修复。
- **`A18`/`A19` 等价性与加法登记**：design D18/D19 登记 metrics 时序映射等价表（`src/service/admin/events.rs:6`）与 events 过滤扩展（`src/handler/admin.rs:392-431`）；补桶边界/时序映射与过滤语义回归测试。
- **文档同步（apply 阶段）**：README §6 新增 BREAKING 条目（`A6`/`A7`/`A8`/`A16`）、§4 审计日志轮转/权限表述与实际接线一致、管理面反代指引更新。

## Capabilities

### New Capabilities

- `audit-rules-parity`：审计规则面修复后的行为契约——日志落盘真实接线、摘要十形态脱敏、危险规则语义等价、规范化管线等价、内外网偏严声明、开关真值集与非法值 fail-closed、策略文件对象形兼容、写失败双层语义、审计事件可查询、SSE metrics 周期快照，以及 MXID/预检/启动顺序/Cookie 判定收敛。

### Modified Capabilities

- 无。canonical `openspec/specs/` 既有契约（`audit-tpm-matrix`、`audit-parity` 等）行为不动；本 change 新增 capability，apply 阶段 README §6 增补 BREAKING 条目。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `A1` | high | `AuditLogger` 接线流/非流判定路径（`spawn_blocking`），落盘/轮转/0600/失败语义测试；联动 `A10` 推环 | 1.1、1.2、1.3、1.4 |
| `A2` | record | PII 锁中毒 panic 由 `veil-pii-parity-closeout` P14 承接，本 change 仅覆盖表/Non-Goals 交叉引用 | 2.1 |
| `A3` | divergent | 补齐 Python 十形态（Bearer/JWT/私钥/身份证/手机/邮箱/键值对）；截断差异登记；零明文样本测试 | 3.1、3.2、3.3 |
| `A4` | divergent | 补 shutdown/reboot/poweroff、base64/openssl 解码、telnet/ssh、`rm -rf` 词形、chmod/chown 形态；逐规则测试 | 4.1、4.2 |
| `A5` | divergent | 文本赋值挖掘 + `/bin/` 与 `find -delete` 别名 + 全管线 `..`；构造性绕过测试 | 5.1、5.2 |
| `A6` | divergent | 保留偏严（IP 字面量非内网、空 host 不豁免）并 README §6 BREAKING 登记；RFC1918/环回/链路本地/None 测试 | 6.1、6.2 |
| `A7` | divergent | 真值集锁步 + 显式 `AUDIT_MODE` 优先 + 非法值拒启动；表驱动测试 + BREAKING 落档 | 7.1、7.2、7.3 |
| `A8` | divergent | 保留 fail-closed + `dangerous` 对象形/字符串形双向兼容 + 旧文件迁移；旧策略测试 | 8.1、8.2、8.3 |
| `A9` | divergent | deny 保持结论、allow 不阻断 + 10 次熔断计数；故障注入测试 | 9.1、9.2（联合 1.3） |
| `A10` | missing | 复用 `AdminState` 事件环（512/FIFO/查询/SSE 回放），不新建专用环；容量/顺序测试 | 10.1、10.2（接线 1.4） |
| `A11` | missing | SSE 15s `event: metrics` 快照（六键、失败降级、过滤一致）；消息形状测试 | 11.1、11.2 |
| `A12` | bug | `@a@b:c` 拒（localpart/domain 不再含 `@`）；边界测试 | 12.1 |
| `A13` | bug | 修正 deny 早返注释；deny 优先级锁定测试 | 13.1、13.2 |
| `A14` | bug | 预检补 `find` tool 名与 `-exec`/`-delete`/`--delete`；`find /etc -exec rm` 测试 | 14.1、14.2 |
| `A15` | bug | 白名单校验前置（TPM/sqlite/KeePass/清扫/回填之前）；无副作用测试 | 15.1、15.2 |
| `A16` | low | Cookie 双判据（XFP 或 `Forwarded: proto=https`）+ README 反代声明；两判据测试 | 16.1、16.2 |
| `A17` | record | 既有非目标与分歧登记（静态页/流式审批 §6.4/轻量入口 §8.4/限流 §3/HOP §7.1/A7 BREAKING 落档），不重复修复 | 17.1、17.2 |
| `A18` | record | metrics 时序口径等价映射登记（`five_min/hourly/daily` ↔ Python `1h/24h/7d/30d`）；桶边界与映射回归 | 17.3 |
| `A19` | record | events 过滤扩展登记（新增 `since`；`verdict` 归一过滤、`model`/`upstream` 仅回显）；过滤语义回归 | 17.4 |

## Non-Goals（显式）

- **`A2` 不处理**：PII 检测器锁中毒 panic 由 change `veil-pii-parity-closeout` P14 负责，本 change 不触碰 `src/service/pii/`。
- **不重开 R4 截断裁决**：`AUDIT_SUMMARY_TRUNCATE_CHARS`（4096）与 metrics `SUMMARY_MAX_CHARS`（1000）及 Python 120 的差异维持既有有意声明，仅在 design 登记（`A3` 只对齐脱敏形态）。
- **不放松安全侧口径**：`A6` 保留偏严内外网判定、`A7` 保留非法值拒启动、`A8` 保留策略文件 fail-closed、`A9` 保留 deny 路径 fail-closed，均以 README §6 BREAKING 声明对齐而非降级。
- **不改流式审批同步阻塞语义（§6.4）、管理静态页 Non-Goal、入口模式 §8.4、管理限流 §3、HOP 8 项 §7.1**：`A17` 仅登记。
- **不改 `src/`、`tests/` 与 README**：本 change 只交付规划 artifacts；实现与 README 改动留待 apply 阶段；不改 `openspec/changes/` 内任何既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-audit-rules-parity/` 下 `proposal.md`、`design.md`、`specs/audit-rules-parity/spec.md`、`tasks.md`（`.openspec.yaml` 已就位）。
- **apply 阶段改动面**：`src/service/audit/log.rs`、`src/service/audit/rules.rs`、`src/service/audit/normalize.rs`、`src/service/audit/policy.rs`、`src/service/audit/verdict.rs`、`src/config/validate.rs`、`src/config/env_parse.rs`、`src/main.rs`、`src/handler/admin.rs`、`src/handler/llm/nonstream.rs`、`src/handler/llm/pump/spawn.rs`、`src/service/admin/state.rs`（接线/复用）及对应单测与 `README.md` §4/§6。
- **影响系统**：审计落盘与可观测性、危险规则覆盖与误报面、参数规范化对抗性、审计开关与策略加载启动语义、管理 SSE 消息面、审批白名单校验与启动顺序、管理 Cookie 安全属性。
- **依赖**：无新依赖；仅既有 `tokio`（`spawn_blocking`）、`axum`、`serde_json` 与测试设施。
