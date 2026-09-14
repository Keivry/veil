## Context

独立六维审查（2026-09-14，审计策略与规则面）确认 9 项偏差（`POL-1`–`POL-9`，见 proposal 发现覆盖表）。现状真相源：

- **策略加载 fail-open**：`src/service/audit/policy.rs:42-52` 的 `load_for_runtime` 以 `match ... Err => warn + default_policy()` 吞掉 `load_from_file` 的 `VeilError::Config`；该 Config 分支（`policy.rs:63-75,133-211`）在启动序列中从未经过——`src/main.rs`（1-201 行）只做 `Config::from_env`、白名单门禁、TPM、sqlite 与后台任务，无策略加载；请求期 `spawn.rs:99`、`nonstream.rs:174` 各自 `load_for_runtime` 一次，即每请求读盘 + 每请求 `capture_process_env`（`policy.rs:56-59`）。
- **`mode` 只校验不生效**：`policy.rs:187-198` 校验 `mode` 取值，但 `AuditPolicy`（`policy.rs:10-27`）无 `mode` 字段，运行模式只来自 `AUDIT_MODE`（`src/config/env_parse.rs`）。
- **自定义文件无上限**：`src/config/custom_file.rs:42-90` 的 `load_custom_file` 直接 `read_to_string`，无大小门禁；Python `_pii.py:120-121` 以 `st.st_size > 1_048_576` 拒绝。
- **日志权限窗**：`src/service/audit/log.rs:466-472` 先 `OpenOptions::create(true).append(true).open()` 写入，再 `set_permissions(0o600)`。
- **白名单空语义**：`src/service/matrix/branch.rs:54-56` 的 `is_mxid_allowed` 为 `whitelist.iter().any(|m| m == mxid)`，空白名单恒 false；调用点 `src/service/matrix/approval.rs:110-113,173-176`。Python `_matrix.py:235,254` 为 `if self.approval_whitelist and sender not in self.approval_whitelist`（空＝不过滤）。
- **规则缺口与误报**：`src/service/audit/rules.rs:54-55,66-75`（`curl`/`wget` 仅管道/`--data` 命中）、`:291-303`（`is_exfiltration`）、`:300`（`lower.contains("nc ")` 命中 `sync`/`async`）、`:114-117,248-267`（`touches_sensitive_path` 不区分读写）。Python 规则见 `_audit.py:516-520`（写入口集合）与 `:522-526`（网络外传，含裸 `curl|wget|nc|ncat|telnet|ssh` + URL/输出重定向）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/`、`README.md`、`scripts/`；不做热重载；不引入新依赖（`std::os::unix::fs::OpenOptionsExt`/`PermissionsExt` 为既有 std）；不碰 verdict 单核结构与脱敏 recognizer。

## Goals / Non-Goals

**Goals：**

- 给出 `POL-1`–`POL-9` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「启动期 fail-fast 加载 + 共享注入」「策略 `mode` 生效」「生效模式口径的空白名单门禁（含文件来源 `approve`）」「自定义文件 1MB 上限」「日志创建即 0600」「空白名单语义」「裸 `curl`/`wget` 外传」「命令词边界」「敏感路径读写分流」收敛为 spec 契约。
- 固化 `POL-1` 错误分类、`POL-5` 空语义与 `POL-9` 生效模式门禁三类关键决策，README §6.11 与 spec 口径同批同步。

**Non-Goals：**

- 本 change 只交付规划（proposal/design/spec/tasks）；不改实现、测试、README、脚本；不提交 commit；实现与文档同步留待 apply 阶段。
- 不做策略热重载（维持「改配置重启生效」，`src/service/audit.rs` 模块声明）。
- 不恢复 Python 的「解析失败禁用审计继续」fail-open 路径；`POL-1` 只向 fail-closed 收紧。
- 不改审计 verdict 判定内核、hold 容量记账、脱敏 recognizer 集合与采样策略。
- 不引入新依赖。

## Decisions

### D1：启动期 fail-fast 加载 + 共享注入（`POL-1`）

**决策**：

- 新增 fail-fast 入口（如 `AuditPolicy::load_startup(path) -> Result<Self>`）：直接返回 `load_from_file` 的 `Result`，成功时调用一次 `capture_process_env`，失败时把 `VeilError::Config` 原样上抛。
- `src/main.rs` 在 `Config::from_env` 与白名单门禁之后、`startup_tpm_in`/`init_sqlite`/`spawn_sweeper` 等副作用点之前调用该入口；失败即 `eprintln! + ExitCode::from(1)`（与既有启动失败风格一致）。
- 成功加载的 `AuditPolicy` 经 `AppState` 共享（`Arc<AuditPolicy>` 或克隆存储），`spawn.rs:99`、`nonstream.rs:174` 改为读取注入实例，删除请求期 `load_for_runtime` 调用。
- **错误分类（error taxonomy）**全部映射为启动期 `VeilError::Config` 并带定位信息，SHALL 覆盖：① 文件不可读（`policy.rs:70-73` 已有）；② 未知键（`:199-204`）；③ 孤立列表项（`:142-150`）；④ 非法 `mode`（`:187-198`）；⑤ 行无法解析（`:208-211`）；⑥ 列表段形态错误（`:176-184`）。这些分支已存在，本 change 的实质是**让它们真正到达启动边界**，不再被 `warn + default_policy()` 吞掉。
- `load_for_runtime` 若保留，仅可用于 `#[cfg(test)]` 或显式「允许默认回退」的调用点，SHALL NOT 出现在生产启动/请求路径。

**理由**：契约（README §6.11、`audit-rules-parity/spec.md:139,151-154`）要求配置错误显式拒启动；每请求读盘 + 全量 env 快照既浪费又使策略在运行中可能被替换（TOCTOU）。启动期一次性加载注入是最小且可审计的收敛点。

**备选**：保留 `load_for_runtime` 只在 `main` 多做一次校验（不改请求期调用）——请求期仍每请求读盘/env 快照，且两处实例可能不一致，不采用；引入 `OnceLock` 全局策略——与既有 `AppState` 注入风格不符且不利测试隔离，不采用。

### D2：策略 `mode` 生效与优先级（`POL-2`）

**决策**：

- `AuditPolicy` 新增 `mode: Option<AuditMode>`，在解析 `mode` 键（合法取值）时写入。
- **生效模式计算**：先判定「env 是否显式设置了审计模式」。**env 显式**的定义是 `Config::from_env`（`env_parse.rs::load_audit:466-483`）解析出的 `audit_mode` **来自 env 来源**——即 `AUDIT_MODE` 非空，**或** `AUDIT_MODE` 缺失/空白时由 `AUDIT_ENABLED` 真值回退推导出的 `block`；只有两者都未给出审计模式（`audit_mode` 落到默认 `Off`）才算「env 未设置」。据此优先级为：**env 显式（含 `AUDIT_ENABLED` 回退）> 策略文件 `mode` > 默认 `off`**；文件 `mode` 仅当 env 未给出审计模式时才生效，SHALL NOT 静默覆盖 env 来源的值。env 与文件同时显式且不一致时记 `tracing::warn!` 说明以 env 为准（不静默）。空/缺省文件 `mode` 不改变既有 env 优先级。
- **生效模式注入运行时配置**：计算出的生效模式 SHALL 在启动期写回运行时配置（`Config.audit_mode` / `AppState.config.audit_mode`），因为请求路径读取该字段判定审计行为（`src/handler/llm/dispatch.rs:165` 的 `let audit_mode = state.config.audit_mode;`）。若只在策略对象上计算而不回写配置，文件来源的 `mode: approve/block` 将永不生效——这正是 `POL-2`「只校验不生效」的根因，故注入与优先级同为必要接线。

**理由**：`mode` 目前被校验却不生效，属「静默失效陷阱」；两选一（删除键 or 生效）中，删除会与 canonical `audit-rules-parity` 的「非法 mode 拒启动」条款冲突并需 MODIFIED delta，故选择生效。优先级把 operator 显式 env（含遗留 `AUDIT_ENABLED` 回退）放在最高，符合「显式配置覆盖文件」直觉并避免文件意外关闭审计；`AUDIT_ENABLED` 本身即 fail-closed 回退（真值→`block`），将其计入「env 显式」可确保文件 `mode` 不会静默反转该回退。生效模式若不注入运行时配置，则「`mode` 生效」只停留在解析层，故注入是同一决策的必要组成。

**备选**：文件 `mode` 覆盖 env——策略文件可静默关闭审计，风险更高，不采用；两者不一致直接拒启动——更严但可能破坏既有部署且 Python 无语义，不采用（改为 warn）；`AUDIT_ENABLED` 回退不算 env 显式、允许文件 `mode` 覆盖——会使 fail-closed 的遗留回退被文件静默反转，不采用。

### D3：自定义文件 1MB 上限（`POL-3`）

**决策**：`load_custom_file` 在 `read_to_string` 前先 `std::fs::metadata(&path)`，`len() > 1_048_576` 时以 `config_error(var, ...)` 拒绝并报告实际字节；恰 `== 1_048_576` 放行。保持既有「空文件仅 warn、形态非法拒启动」语义不变。

**理由**：超大文件读取会放大内存并被 ReDoS/解析放大攻击利用；Python 已有同值上限（`_pii.py:120-121`），对齐即 parity。`metadata` 预检避免先读后判。

**备选**：读取后判 `text.len()`——已产生内存放大，不采用；用 `take(cap+1)` 流式判长——可行但改动更大，元数据预检等价且更简。

### D4：审计日志创建即 0600（`POL-4`）

**决策**：`AuditLogger::append_line` 的 `OpenOptions` 增加 `use std::os::unix::fs::OpenOptionsExt; .mode(0o600)`，删除后续 `set_permissions(0o600)`。`mode` 为「创建时权限位」，与进程 umask 相与后不超过 `0600`（umask 非零只会更严），满足「创建瞬间不宽于 0600」。既有已存在文件的追加与轮转维持 `0600`。

**理由**：先创建后 chmod 存在可被同机其他用户读取/竞态的窗口；创建时即定权限是原子收口。`OpenOptionsExt::mode` 为 std 既有 API，零新依赖。

**备选**：进程启动设 `umask(0o077)`——全局副作用、影响其它文件，不采用；临时改 umask 包裹 open——竞态且需 unsafe，不采用。

### D5：审批白名单空语义＝不过滤（`POL-5`）

**决策**：`is_mxid_allowed` 改为 `whitelist.is_empty() || whitelist.iter().any(|m| m == mxid)`。`AUDIT_MODE=approve` 下空白的 `APPROVAL_WHITELIST` 仍由 `env_parse.rs:484-489` 的启动门禁拒绝，故审计 approve 面不因本改动放松。`resolve`/`on_reaction` 的其它过滤层（房间/自反应/时间戳/分支/表情/event id）不变。

**理由**：Python `_matrix.py:235,254` 语义即空白名单不过滤；Rust 现行为使凭据/注册审批在未配白名单时全部 reaction 被忽略，票只能等超时（可用性回归）。审计面由启动门禁兜底，不存在「任意人审批审计」的新面。

**备选**：维持空＝全忽略（拒绝所有）——与 Python 背离且使凭据审批链在未配白名单时不可用，不采用；空名单时改为直接拒绝而非忽略——语义更差，不采用。

### D6：内建规则补裸 `curl`/`wget` 外传（`POL-6`）

**决策**：在 `rules.rs` 危险规则中新增外传形态：当命令词为 `curl`/`wget`（词边界，复用 `is_command_word`/`word_after_command`）且其后出现远程目标形态（`http(s)://`、`ftp://`，或 `-o`/`--output`/`>`/`>>` 输出重定向）时，判为网络外传。该判定纳入 `is_exfiltration`（或等价的网络外传分支），命中外部 host 时拦截，命中 `internal_suffixes` 时按既有「网络外传 + internal_target」豁免口径放行。管道进解释器与 `--data`/`-d`/`--post-data` 的既有更高危判定保持优先。

**理由**：Python 第 8 条（`_audit.py:522-526`）覆盖 `(curl|wget|nc|ncat|telnet|ssh)` + URL/输出重定向，`network: true` 走外部 host 复核；本仓漏了裸 GET 外传面。用命令词边界 + 目标形态限定误报。

**备选**：只用 `lower.contains("curl")` 判定——`echo "curl"`/文件名误报，不采用；把 `curl`/`wget` 加入无条件 DANGEROUS 子串——同样误报且丢失内网豁免，不采用。

### D7：外传判定命令词边界（`POL-7`）

**决策**：`is_exfiltration` 中 `lower.contains("nc ")`/`lower.contains("ncat ")` 改为命令词判定：复用 `is_command_word(lower, "nc")`/`is_command_word(lower, "ncat")`。为使绝对/带路径调用（`/bin/nc`、`/usr/bin/ncat`）仍命中，SHALL 扩展 `word_after_command`（`rules.rs:129-157`）的左边界集合 `pre_ok` 增补 `/`——否则 `/bin/nc evil 4444` 因 `nc` 前的 `/` 不在边界集而漏判，相对现状 `contains("nc ")` 构成**覆盖回退**。`/dev/tcp/` 与 `nc -l` 等真实用法识别 SHALL 保留；`post_ok` 已含空白，`/bin/nc -l`、`/bin/nc host port` 均命中。`scp `/`rsync `/`sftp `/`ftp ` 等带尾随空格的分支一并复核是否应统一为词边界（至少不因单词内子串误报）。

**理由**：`"nc "` 是裸子串，`sync ` / `async ` 内含 `nc ` 被误报；命令词边界是既有 `word_after_command`（`rules.rs:129-157`）已用于 `ssh`/`telnet`/`shutdown` 的成熟口径。但 `pre_ok` 现不含 `/`，直接切换会在绝对路径调用上产生**误报转漏报的回归**（`/bin/nc` 是真实外传命令的常见写法），故边界集必须含 `/` 才满足「不降低真实命中」。

**备选**：正则 `\bnc\b`——引入正则回溯面，与「禁全文正则回溯」模块约束冲突，不采用；仅对 `nc`/`ncat` 保留 `lower.contains("nc ")` 子串兜底——可命中绝对路径但重新引入 `sync`/`async` 误报，不采用（改为扩边界集）。

### D8：敏感路径读写分流（`POL-8`）

**决策**：把「敏感路径」与「写入意图」解耦。写入口判定集合对照 Python `_audit.py:518` 逐字取用：`write_file`/`patch`/`echo`/`cat`/`tee`/`cp`/`mv`（含本仓既有 `edit`/`write`/`apply_patch`/`save_file` 工具名写入口），并叠加输出重定向（`>`/`>>` 指向敏感前缀）。仅当存在写入意图且路径触及 `SENSITIVE_PATHS`/`extra_sensitive_paths` 时判「敏感路径写入」；无写入意图的只读命令（如 `ls`/`grep`）触及敏感前缀不再拦截。

**理由**：现行为对任何触及敏感前缀的路径 token 一律拦截，`ls /etc/passwd` 被误拦；Python 以写入口集合限定，本仓应对齐。`cat` 保留在写入口集合内为**有意对齐 Python**（`cat` 可配合重定向/here-doc 写入），故 `cat /etc/passwd` 仍拦截——这是 parity 而非误报。

**备选**：维护「只读命令白名单」——白名单永远不全且随命令演化漏判写入，不采用；完全不分读写但仅对 `>` 重定向判写——漏 `cp`/`tee` 等写命令，不采用。

### D9：生效模式口径的空白名单门禁（`POL-9`，`POL-2`×`POL-5` 交互）

**决策**：

- 启动期空白名单门禁的判据从「env `AUDIT_MODE` 值」升级为「`POL-2` 定义的**最终生效模式**」。实现上把 `env_parse.rs:485-491` 的 `audit_mode == Approve && approval_whitelist.is_empty()` 检查抽为可复用入口（如 `validate_approve_whitelist(mode: AuditMode, whitelist: &[String]) -> Result<()>`），由启动序列在 `POL-1` 完成策略加载、`POL-2` 完成生效模式解析（D2 口径：env 显式——含 `AUDIT_ENABLED` 回退——> 文件 `mode` > 默认 `off`）之后、`startup_tpm_in`/`init_sqlite`/`spawn_sweeper` 等副作用点之前调用；命中即 `VeilError::Config` 拒启动。门禁 SHALL 使用合并后的生效模式，SHALL NOT 以未经文件 `mode` 合并的裸 env `audit_mode` 为判据。
- 环境变量来源的 `approve` 仍由 `Config::from_env`（`env_parse.rs:486-491`）既有检查保证不回归；新增调用点覆盖文件来源及未来任何非 env 来源。
- 生效模式解析与空白名单门禁置于同一阶段，消除「先按 env 校验、随后被文件 `mode` 覆盖」的时序缝；`main.rs:58` 的 `preflight_whitelist` 仅校验 MXID 形态，不承担空名单门禁。

**理由**：`POL-5` 确立「空白名单＝不过滤」，其安全性前提正是「审计 approve 空名单由启动门禁拒绝」。若生效模式可由策略文件置为 `approve` 而门禁只认 env，则该前提被击穿，审计 approve 面退化为「任意 reaction 可批准审计决策」，与 README §6.11 的 fail-closed 精神冲突。把门禁锚定在「最终生效模式」是唯一不产生绕过面的收口点，且复用既有检查、不新增语义。

**备选**：

- **完全禁止文件来源的 `approve`（仅允许 env 启用 `approve`）**——不采用：与 `D2` 已裁定的「文件 `mode` 生效（env 显式含 `AUDIT_ENABLED` 回退 > 文件 > off）」直接冲突，会使合法部署（文件 `mode: approve` + 非空白名单）被无谓拒绝；更关键的是它只堵当前文件来源，未来任何非 env 来源仍会重现缺口，属治标。
- **在 `Config::from_env` 之后、策略加载之前预读文件 `mode` 再校验**——不采用：造成策略文件二次解析与 TOCTOU，且与 `POL-1` 的「启动期单次加载注入」冲突。
- **env 与文件 `mode` 不一致直接拒启动**——不采用：与 `D2` 的 warn 口径冲突，且 `POL-9` 关注空白名单安全面而非优先级冲突本身。

## Risks / Trade-offs

- [启动期 fail-fast 改变既有可容忍行为] → 这是契约要求的收紧；README §6.11 与本 spec 声明，迁移只需修正策略文件语法/键名/`mode`；错误消息带行号便于定位。生产升级前应先用 `AUDIT_POLICY_FILE` 校验（任务含启动失败/成功双向回归）。
- [显式 `AUDIT_MODE` 覆盖文件 `mode` 造成预期外] → 冲突记 warn 并保持 env 优先，不静默；design D2 声明优先级。
- [`POL-6` 新增外传检测抬高误报] → 命令词 + 远程目标形态双条件，且 `internal_suffixes` 豁免内网；回归覆盖 `curl http://evil` 命中与良性文本不命中。
- [`POL-8` 写入口集合过窄导致漏拦写入] → 采用 Python 逐字集合 + 输出重定向 + 工具名写入口三重覆盖；回归矩阵覆盖只读放行、`cp`/`tee`/重定向/写类工具拦截。
- [`POL-5` 空白名单＝不过滤削弱凭据审批管控] → 与 Python parity，且审计 approve 空名单由启动门禁拒绝；README/运维指引应声明生产必须配置白名单（apply 阶段核对文档）。
- [`POL-9` 门禁从 env 口径改为生效模式口径遗漏时序] → 门禁调用点固定于「策略加载（`POL-1`）+ 模式解析（`POL-2`）之后、副作用点之前」，同一阶段完成；env 路径既有检查保留以不改旧行为，回归覆盖 env 与文件两来源。
- [`POL-4` `OpenOptionsExt::mode` 与 umask 关系] → `mode` 为创建位，umask 只会进一步收紧，不会导致宽于 `0600`；回归直接断言新建文件 `0o600`。
- [`POL-3` 1MB 上限影响既有超限文件] → 既有超限文件本不该被容忍（内存风险）；错误带变量名与实际字节，迁移即裁剪文件。

## Migration Plan

1. 按 tasks 顺序落地：先 `POL-1` 启动加载与注入（含错误分类与请求期去重），再规则层 `POL-6`/`POL-7`/`POL-8`，再 `POL-5`，再 `POL-9` 生效模式空白名单门禁，最后 `POL-2`/`POL-3`/`POL-4`。
2. 每组独立 `cargo test`；README §6.11 与 spec 口径同批核对；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：`POL-1` 是相对现状的行为收紧（配置错误拒启动），由 README §6.11 声明；其余为规则/权限/语义修复，无新增 BREAKING 配置项。

## Open Questions

- 无。`POL-1` 错误分类与 `POL-5` 空语义已裁定；`POL-2` 优先级已裁定。若 apply 阶段实测发现策略 `mode` 生效与既有 env 解析存在冲突路径，以 design D2 优先级为准并回记差异。
