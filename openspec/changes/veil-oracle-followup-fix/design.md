## Context

2026-09-13 独立 Oracle 复核在 7 个变更全部落地（`cargo test` 1050 passed、`openspec validate --all --strict` 79/0）之后，对 transport / PII / credential / audit / stream / arch+docs 六个维度逐项对照源码与测试夹具，确认 17 项未被现有门禁捕获的缺口（`F1`–`F17`）。现状真相源与行级证据：

- **审批绑定失效**：`approval_event_id`（`src/service/credential/approval.rs:16-27`）生成合成键 `$veil-{nanos}-{hash:08x}`，`:77-78` 以其建 pending；`NotificationSink::send_text`（`src/service/matrix/notify.rs:29`）返回 `()`，`impl NotificationSink for MatrixBot`（`:32-35`）丢弃 `MatrixBot::send_text`（`src/service/matrix/bot.rs:110`，实为 `Result<String>`）的真实 event_id；反应回调（`src/service/matrix/approval.rs:145-163`）用真实 `input.target_event_id` 查 pending → 永不匹配（`F1`）。
- **规范化顺序绕过**：`check_args`（`src/service/audit/rules.rs:439`）先 `canonicalize_args`，`:494`/`:501` 再 `split_chain`；`normalize.rs:240-266 fold_bin_prefix` 仅空白算 word-start；`rules.rs:126-154 word_after_command` 的 `pre_ok` 不含 `/` → `echo x;/bin/rm -rf tmp` 绕过（`F2`）。
- **Responses 工具 delta 先泄后审**：`spawn.rs:324-325` `audit_hold_on = !Off && matches!(protocol, Chat | Anthropic)`，Responses 工具 delta 不缓冲直接下发；slot `.done` 才审计（`F3`）。
- **PII 短名槽名实不符**：`README.md:53/55/57` 称 `PII_CUSTOM_*` 为「内联短名槽变量」；`src/config/env_parse.rs:593-613` 将其与 `*_FILE` 同列传入 `load_custom_file`，后者 `src/config/custom_file.rs:68 if !path.is_file()` → 实为文件路径别名（`F4`）。
- **危险表子串误报**：危险表裸子串 `"dd "` → `echo add`（含 `add `）误判危险（`F5`）。
- **摘要脱敏 O(n²)**：`src/service/audit/log.rs` `mask_secret_forms`（`:48` 调用）逐位置 `to_lowercase()` 剩余串、`email_at`（`:84` 调用）逐位 `find('@')`，大 args（≤1MB）可致严重耗时（`F6`）。
- **守护弱项**：`F7` TPM 同步子进程守护白名单整文件化 + `RealTpm`/`tpm2_` 标记探测可绕；`F8` analyzer 缓存复用仅同输入同输出；`F9` `init_no_sync_sweeper` 仅断言同步 sweep 不 panic；`F10` `startup_whitelist_fail_fast` 未验顺序（tautology）；`F11` `web_search_action_audit_both_paths` 仅提取单测、非 hold 集成；`F12` 自定义规则跨帧 hold 无 `feed_output_frame` 端到端；`F13` fuzzy 还原未覆盖 response 表/未知 seq。
- **文档漂移**：`F14` T8 design D8 表述与实现「段解析」不符；`F15` `guard.rs`→`frame_feed.rs` 命名漂移；`F16` 「空闲票 60s 上限」与 300s 阻塞 TTL 两口径需明确；`F17` `src/registry/store.rs:291` 注释「全局 hash 唯一拒绝已删除」与 `vault_ops` 预检说明不一致。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 README；不改 `openspec/changes/` 内其他 change 目录与 canonical specs；不提交 commit。`F14`/`F15`/`F16` 涉及的 sibling change 目录（`veil-transport-fidelity-fix`、`veil-arch-hygiene-closeout`、`veil-credential-flow-parity`）冻结，仅在可写面登记。

## Goals / Non-Goals

**Goals：**

- 给出 `F1`–`F17` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证；每个 ID 在覆盖表有行、在 tasks 有 ≥1 任务，行为项在 spec 有契约。
- 修复三项高危功能缺陷（审批恒超时、审计链节绕过的漏拦、Responses 工具参数先泄后审），并把「真实回执为键」「链节起始折叠」「工具分片先审后放」收敛为 spec 契约。
- 把弱守护/弱断言升级为可观测证据（缓存命中、清扫未 spawn、启动无副作用），并把文档/注释漂移收敛。

**Non-Goals：**

- 不改 `src/`、`tests/`、README（规划期）；不实现 `F4` 的真内联语义（裁决 doc-align）。
- 不改三因子校验原语、脱敏 recognizer 集合与采样策略、usage `max` 口径、Responses 保序/切片与真空终止、审计 verdict 判定口径。
- 不引入新依赖、不改 wire 枚举与配置默认值；不重开已复核 COMPLIANT 的面。

## Decisions

### D1：`F1` 以真实 event id 为 pending 键，发送失败 fail-closed（裁决）

**决策**：`NotificationSink` 新增 `send_text_tracked(&self, text: &str) -> Option<String>`，默认实现回退既有 `send_text`（返回 `None`，兼容事件环/spool 的 best-effort 语义）；`impl NotificationSink for MatrixBot` 返回 `MatrixBot::send_text`（`bot.rs:110`）的真实 event_id（发送失败返回 `None`）。所有审批建单路径（`submit_pending_with_branch` 及 register/revoke/credential/unlock/audit-hold）改为：先 `send_text_tracked` await 取真实 id，成功以其为键 `submit_branch(real_id, branch)`，失败或 `None` 即 fail-closed（不建不可决单，按拒绝/错误返回）。

**理由**：pending 键的唯一消费者是反应回调（`matrix/approval.rs:148/163`），其输入为真实 `target_event_id`；合成键与真实 id 无映射关系，除测试直接 resolve 合成键外在生产无任何命中路径，导致阻塞恒 300s 超时。真实 id 是「消息已发出且可被反应」的唯一凭据，以它为键即把「能发送」与「能落定」绑定。发送失败时建单必然不可决，fail-closed 避免制造超时黑洞。

**备选**：维护合成键→真实 id 的映射表——引入双源状态与清理负担，且发送失败仍难处理，不采用；把真实 id 由 `MatrixBot::send_text` 通过 sink trait 返回值透传（即本决策方案），最小改动，采用。

**路由差异**：事件环/spool 走 best-effort（不需回执，`send_text` 返回值可丢）；审批走 tracked（需回执，fail-closed）。二者共用 `MatrixBot`，差异在调用点选择的 sink 方法，文档化于 spec 与 README。

### D2：`F2` 先拆链再逐段规范化（裁决，落实既有 design D4 次序）

**决策（已落地）**：审计判定次序为**先 `split_chain` 再逐段 `canonicalize_args`**（链节首别名折叠），并令 `fold_bin_prefix` 对链节分隔符/括号 `;`/`|`/`&`/`(`/`）` 后的命令起始同样视为 word-start；二者协同确保链节首 `/bin/<cmd>` 折叠生效。整命令预检（`curl|sh` 管道、敏感路径、`extra_dangerous`）仍在原始整段 canon 上先行。

**理由**：`fold_bin_prefix` 的语义是「命令词首可省略路径前缀」，而 `split_chain` 之后每个链节的起始才是命令词首；现有次序在 `canonicalize_args` 时尚未拆链，整段只认空白为 word-start，故 `;`/`|`/`(` 后接 `/bin/rm` 不被折叠、不被危险表命中。先拆链使每段成为独立命令上下文，规范化语义与 `word_after_command` 一致。

**备选**：仅在 `pre_ok` 加 `/`——会让 `a/b` 之类非命令起始的 `/` 也被当 word-start，产生新误报面，不采用；改危险表直接匹配 `/bin/rm` 绝对路径——漏掉其他别名形态且与别名折叠设计冲突，不采用。

### D3：`F3` Responses 工具分片纳入审计 hold（裁决）

**决策**：`should_buffer_tool_frame` 与 `should_suppress_held_output` 对 Responses 生效（`spawn.rs:324-325` 的 `matches!(protocol, Chat | Anthropic)` 收敛为含 Responses，或以工具帧判定为准）；未完成工具分片先缓冲，slot `.done` 完成审计后再放行/阻断。

**理由**：Responses 工具参数以 `response.function_call_arguments.delta` 增量下发，若 delta 直通则危险明文先于 done 帧到达下游，构成先泄后审；缓冲到 done 后审计是「先审后放」的唯一正确时序。Responses 保序/切片与真空终止语义不在本决策范围，保持不变。

**备选**：仅在 delta 上做流式预扫——需另建跨 delta 重组与审计通道，复杂度高且与既有 slot 审计重复，不采用；只改 E2E 夹具不改实现——掩盖缺陷，不采用。

### D4：`F4` PII 短名槽变量 = 文件路径兼容别名（裁决，推荐 doc-align）

**决策**：`PII_CUSTOM_RULES` / `PII_CUSTOM_PATTERNS` / `PII_CUSTOM_DICT` 的契约措辞统一为「**短名槽变量**：与对应 `*_FILE` 同槽合并、同文件路径解析、同 fail-closed 校验，列序优先级最低；无 `_FILE` 后缀仅为兼容别名」，删除 README/design/spec 中的「内联/内容语义」表述。

**理由**：实现真相为 `env_parse.rs:593-613` 将其与 `*_FILE` 同列传入 `load_custom_file`，后者 `custom_file.rs:68` 要求 `path.is_file()`，即值语义是路径而非内容；文档称「内联」属名实不符，会误导运维把规则内容直接写入变量导致 fail-closed 拒启动。doc-align 与实现零改动、零风险。

**备选**：实现真内联（`custom_file` 支持「值非存在的文件即按内容解析」）——改变 fail-closed 语义与安全面（内容变量绕过文件校验），需重估审计/ReDoS 守卫，超出本 follow-up 范围，不采用（若确需另立 change）。

### D5：`F5` 危险表词边界匹配（裁决）

**决策**：危险表 `"dd "` 改为词边界/命令词首匹配（复用 `word_after_command` 或等价边界判定），使 `add`/`cdd` 不误报、`dd if=... of=/dev/sda` 命中。

**理由**：旧裸子串 `"dd "` 会命中任何含该子串的普通词（`add`、`cdd`），与危险表应有的「词边界/命令词首」口径名实不符，产生误报噪声并可能掩盖真实命中。词边界匹配把语义收敛为「命令词 `dd`」。

**备选**：正则 `\bdd\b`——需在危险表逐条改写且部分条目非单词形态，改动面大，不采用；仅加空格前后约束——仍无法区分 `add`，不采用。

### D6：`F6` 摘要脱敏输入上限 + 一次性预计算（裁决）

**决策**：`mask_secret_forms` / `email_at`（`src/service/audit/log.rs`）先按既有 4096/120 截断口径约束输入上限，或一次性预计算小写索引，使处理近似线性；SHALL NOT 对每个位置重复 `to_lowercase()` 剩余串或逐位 `find('@')`。

**理由**：现有实现对每个位置构造剩余子串并 `to_lowercase`，整体 O(n²)；审计 hold 上限 `AUDIT_HOLD_MAX_BYTES`（默认 1MB）下最坏可致严重耗时，属可用性风险。一次性预计算或先截断保持输出逐字一致，风险最低。

**备选**：仅文档化「大输入慢」——不消除可利用的耗时面，不采用；改脱敏算法语义——可能改变输出，不采用。

### D7：`F7` TPM 守护结构化可验证（裁决）

**决策**：把 TPM 同步子进程守护由「白名单整文件化 + `RealTpm`/`tpm2_` 标记探测」改为结构化约束：白名单收窄到受约束范围（如 `spawn_blocking` 闭包），或以伪/真分支断言替代标记探测；补绕行反例测试。

**理由**：整文件白名单使文件内任何调用（含别名绕过）都被放行，守护不产生真实约束力；结构化约束 + 反例测试能证明「越界即失败」。

**备选**：保持现状仅加注释——弱守护问题保留，不采用。

### D8：`F8` 缓存复用可观测（裁决）

**决策**：hardening analyzer 缓存断言加强为可观测命中证据（命中计数或等价观测），覆盖跨调用复用。

**理由**：同输入同输出不能区分「命中缓存」与「重新计算」，断言力不足；可观测命中才锁定缓存行为。

**备选**：以耗时阈值间接判断——不稳定，不采用。

### D9：`F9` 清扫任务未启动可观测（裁决）

**决策**：`init_no_sync_sweeper`（`src/service/credential/approval.rs`）改以可观测证据断言清扫任务/后台 spawn 未启动，替代「同步 sweep 不 panic」的弱代理。

**理由**：不 panic 不等于未启动；需直接观测任务计数/句柄缺失。

### D10：`F10` 启动白名单 fail-fast 无副作用（裁决）

**决策**：`startup_whitelist_fail_fast` 断言非法白名单时无 DB/TPM/网络副作用（数据目录未创建、TPM 未调用、后台任务未启动），去除当前 tautology 断言。

**理由**：顺序保证的价值在于「失败前不触盘/触网」；不观测副作用则断言为空。真源对照见 `src/main.rs` 启动顺序与 `src/config/env_parse.rs` 白名单校验。

### D11：`F11` web_search 审计全 hold 集成（裁决）

**决策**：补 `action.query` 经完整 hold（流式 + 非流式）进入审计的集成测试，替代仅参数提取单测。

**理由**：提取正确不等于经 hold 进入审计；需端到端锁定流/非流同结论。

### D12：`F12` 自定义规则跨帧 hold 端到端（裁决）

**决策**：补自定义规则经 `feed_output_frame` 跨帧拼接后命中的端到端用例。

**理由**：跨帧 hold 是 PII/审计的核心时序；缺端到端则不覆盖真实调用形态。

### D13：`F13` fuzzy 还原边界覆盖（裁决）

**决策**：补 fuzzy 还原对 response 表 token 与未知序号「原样保留、不还原」的边界测试。

**理由**：`PII_FUZZY_RESTORE` 为有意超集，边界锁定在「仅请求表可还原」；未覆盖即可能误还原响应侧 token。

### D14：`F14`–`F17` 文档/注释口径收敛（裁决）

**决策**：

- `F14`：T8 表述统一为「**段解析**」口径（非跳过段先尝试整体 JSON 解析并 walk，失败回退文本段），sibling change `veil-transport-fidelity-fix` 目录冻结，不在 `openspec/changes/` 其他目录内改动；在本 change design 与可写文档（README/canonical 晋升后）登记更正表述。
- `F15`：核对 README 与 canonical specs 是否引用 `guard.rs`；若存在一律更正为 `frame_feed.rs`（`veil-arch-hygiene-closeout` H5 实际产物）。该写法当前仅存在于 sibling change 的 design/tasks，冻结不改，登记于本 design 与 README（如引用）。
- `F16`：明确两个并存口径——**空闲票 60s 回收上限**（无阻塞等待者的孤儿票清扫）与**有阻塞等待者凭据类票 300s 阻塞 TTL**（不得在阻塞超时前删）；`veil-credential-flow-parity` spec 冻结，随其归档晋升 canonical 后再同步措辞，本 change 先在 README §4/§8.4 与 design 登记。
- `F17`：`src/registry/store.rs:291` 注释与 `src/service/credential/vault_ops.rs` 预检说明统一为「全局 hash 去重已移除（内容相同双脚本可各自注册）；注册判重仍按 `caller_path` 与未吊销 `name`」。

**理由**：四项均为表述/注释层漂移，不改变行为；在不改冻结目录的前提下，把更正落到可写面并保留可追溯登记，避免后续 change 误读。

**备选**：改动 sibling change 目录内的 design/spec——违反「不改其他 change 目录」约束，不采用；不处理——漂移持续，不采用。

## Risks / Trade-offs

- [`F1` tracked 发送失败 fail-closed 降低可用性] → 审批链在 Matrix 短暂故障时不再建单。缓解：fail-closed 是安全优先的有意选择（不可决单比拒绝更危险）；失败返回明确错误，调用方可重试。
- [`F1` 全路径改造面大] → register/revoke/credential/unlock/audit-hold 均需改。缓解：统一经 `submit_pending_with_branch`，逐路径回归；注入 sink 固定真实 id 锁定。
- [`F2` 顺序调整影响既有审计结论] → 可能新增命中（更严）。缓解：属「误报优于漏审」的既有口径；管线优先级测试锁定不误报。
- [`F3` 缓冲 Responses 工具分片改变下游时序] → 分片延迟到 done 才放行，可能影响流式实时性。缓解：仅工具分片缓冲，非工具帧不动；保序/切片语义测试锁定。
- [`F4` doc-align 后运维仍可能误解] → 文档已明确路径语义与 fail-closed。缓解：README 表格措辞与实现字面一致。
- [`F6` 输入上限约束可能截断超长 args 的脱敏覆盖] → 截断口径与既有 4096/120 一致，非新增行为。缓解：输出逐字一致性测试锁定。
- [`F7`–`F10` 守护加强可能暴露既有实现偏差] → 属预期（守护目的）。缓解：反例测试明确失败面，偏差按 follow-up 修复。
- [`F14`–`F16` 冻结目录无法即时更正] → canonical 晋升前文档仍有漂移。缓解：本 change design/README 登记，归档晋升时同步 canonical。

## Migration Plan

1. 按 tasks 顺序落地：先高危 `F1`/`F2`/`F3`，再中危 `F4`/`F5`/`F6`，再低危守护 `F7`–`F13`，最后文档 `F14`–`F17` 与门禁。
2. 每组独立 `cargo test -p veil <组>`；README 相关段落与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：`F1` fail-closed 行为（发送失败不建单）与 `F3` Responses 工具分片延迟放行属下游可感知变化，由 spec 与 README 声明；其余为内部修复与测试/文档强度提升。

## Open Questions

- `F1` tracked 发送是否需对既有 `send_text` 调用点做统一迁移清单：apply 阶段以 `grep -rn "send_text" src/service/matrix/` 枚举并逐点标注（best-effort vs tracked），结论回写本 design D1。
- `F7` 结构化约束的具体形态（收窄白名单 vs 伪/真分支断言）：apply 阶段视 `src/service/tpm.rs` 与 `src/main.rs` 现状择一，锁定后回写 D7。
- `F14`/`F15`/`F16` 的 canonical 同步时机：待对应 sibling change 归档晋升后随文档同步，本 change 仅登记；如归档流程允许同批修订则并入。
