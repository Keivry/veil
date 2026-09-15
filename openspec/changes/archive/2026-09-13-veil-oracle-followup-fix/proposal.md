## Why

2026-09-13 在 7 个变更全部落地（`cargo test` 1050 passed、`openspec validate --all --strict` 79/0 全绿）之后，对 transport / PII / credential / audit / stream / arch+docs 六个后台任务做独立 Oracle 复核，逐项对照源码与测试夹具，确认仍存在 17 项实质缺口（`F1`–`F17`）。其中 3 项高危为功能性缺陷，现有测试因夹具掩盖（直接 resolve 合成键、done-only 夹具、`/` 目标样例）而全绿：

- **`F1`（critical）Matrix 审批反应绑定失效**：`src/service/credential/approval.rs:16-27` 的 `approval_event_id` 生成合成键 `$veil-{nanos}-{hash:08x}`，`:77` 用它建 pending；`src/service/matrix/notify.rs:29` 的 `NotificationSink::send_text` 返回 `()`（`bot.rs:110` 实为 `Result<String>` 却被丢弃），真实 Matrix event_id 未透传；`src/service/matrix/approval.rs:145-163` 却用反应回调的真实 `input.target_event_id` 查 pending → 永不匹配。后果：阻塞审批恒 300s 超时，注册→自动吊销、吊销→不执行、凭据→被拒绝等 202 异步任务恒超时；测试直接 resolve 合成 id 故全绿。
- **`F2`（high）A5 规范化顺序绕过（审计漏拦）**：`src/service/audit/rules.rs:439` 先 `canonicalize_args`（含 `fold_bin_prefix`）再 `:494`/`:501` `split_chain`；`src/service/audit/normalize.rs:240-266` 仅空白算 word-start；`rules.rs:126-154` `word_after_command` 的 `pre_ok` 不含 `/` → `echo x;/bin/rm -rf tmp`（`;` + `/bin/rm` + 非 `/` 目标）绕过命中。
- **`F3`（high）S2 Responses 工具参数先泄后审**：`src/handler/llm/pump/spawn/event_loop.rs:308-312` `audit_hold_on` 仅 `!Off && matches!(protocol, Chat | Anthropic)` → Responses 工具 delta 不缓冲、直接下发；审计在 slot `.done` 才发生 → `response.function_call_arguments.delta` 携带的危险参数先于阻断帧透传，E2E 用 done-only 夹具掩盖。

其余为中低危：`F4` PII 短名槽变量名实不符（README 称「内联」、实为文件路径别名）；`F5` 危险表裸子串 `"dd "` 使 `echo add` 误报；`F6` `mask_secret_forms` 摘要脱敏 O(n²)；`F7` TPM 同步子进程守护白名单整文件化可绕；`F8` hardening analyzer 缓存复用断言弱；`F9` `init_no_sync_sweeper` 未真验「无 spawn」；`F10` `startup_whitelist_fail_fast` 未验顺序（tautology）；`F11` `web_search_action_audit_both_paths` 仅提取单测、非 hold 集成；`F12` 自定义规则跨帧 hold 无 `feed_output_frame` 端到端；`F13` fuzzy 还原未覆盖 response 表/未知 seq；`F14`–`F17` 设计/注释/规格措辞漂移。

真相源：`src/service/credential/approval.rs`、`src/service/matrix/notify.rs`、`src/service/matrix/bot.rs`、`src/service/matrix/approval.rs`、`src/service/audit/rules.rs`、`src/service/audit/normalize.rs`、`src/service/audit/log.rs`、`src/handler/llm/pump/spawn.rs`、`src/config/env_parse.rs`、`src/config/custom_file.rs`、`src/service/tpm.rs`、`src/registry/store.rs`。本 change 只规划（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 README。

引用契约：canonical `openspec/specs/credential-api/spec.md`（三因子）、`credential-approval-dual-mode`（202/300s 双模）、`approval-hold-parity`（挂起与审批语义）、`matrix-approval-closure`、`audit-parity`、`pii-parity`、`llm-protocol-hardening`；`F1`/`F2`/`F3`/`F4`/`F5` 的裁决依据见 design.md 对应 Decision。

## What Changes

- **`F1` Matrix 审批以真实 event id 为 pending 键**：`NotificationSink` 新增 tracked 发送能力（`send_text_tracked -> Option<String>`，默认实现回退 `send_text` 返回 `None`；`MatrixBot` 实现返回 `bot.rs:110` 的真实 event_id）；`submit_pending_with_branch`（`src/service/credential/approval.rs:67-78`）及 register/revoke/credential/unlock 等所有审批建单路径**先 await 发送取真实 id 再 `submit_branch(real_id, branch)`**；发送失败或返回 `None` 时 fail-closed（不建不可决单，直接按拒绝/错误返回）；同步修复 audit-hold / audit 审批路径。补以注入 sink 返回固定真实 id 的 resolve 回归（`✅`/`❎`/`🔓` + 超时），并说明 spool（best-effort、不需回执）与审批（需回执、fail-closed）的路由差异。
- **`F2` 审计规范化次序修正**：按 design D4 次序**先 `split_chain` 再逐段 `canonicalize_args`**，或使别名折叠对链节首（`;`/`|`/`&`/`(`/`）` 后的命令起始）生效；保证 `echo x;/bin/rm -rf tmp`、`echo x|/bin/rm -rf y`、`(/bin/rm -rf z)` 均命中；补构造性绕过回归且不破坏既有管线/管道优先级测试；同步 design D4 次序描述。
- **`F3` Responses 工具分片先审后放**：使 `should_buffer_tool_frame` / `should_suppress_held_output` 对 Responses 生效，未完成工具分片先缓冲；slot `.done` 审计后再放行或阻断；block 模式下危险参数经 delta 分片时下游不得出现危险明文且收到恰一阻断帧；补多 item + delta 拆分 E2E；确认不改动 Responses 保序/切片与真空终止语义。
- **`F4` PII 短名槽变量文档对齐（推荐 doc-align）**：README/design/spec 措辞改为「短名槽变量：与 `*_FILE` 同槽、同文件路径解析、同 fail-closed，列序最低（无 `_FILE` 后缀仅为兼容别名）」，删除「内联/内容语义」表述；不实现真内联（备选见 design D4）。
- **`F5` 危险表词边界匹配**：危险表 `"dd "` 改为词边界/命令词首匹配，使 `echo add`/`cdd` 不误报而 `dd if=... of=/dev/sda` 命中；补正反测试；同步 design D3 措辞。
- **`F6` 摘要脱敏近似线性**：`src/service/audit/log.rs` 的 `mask_secret_forms` / `email_at` 改为先按既有 4096/120 截断口径约束输入上限，或一次性预计算小写索引，保证近似线性；补大输入边界测试；输出与原行为逐字一致（`audit_summary_forms`/`zero_plaintext`/`b9_deny_summary_dual_shapes` 保绿）。
- **`F7` TPM 守护结构化**：把 TPM 同步子进程守护由白名单整文件化 + 标记探测改为结构化可验证约束（收窄白名单范围或伪/真分支断言）+ 绕行反例测试。
- **`F8` 缓存复用可观测**：hardening analyzer 缓存断言加强为可观测缓存命中（跨调用复用证据），非仅同输入同输出。
- **`F9` 清扫任务无 spawn 可观测**：`init_no_sync_sweeper` 改为可观测断言（清扫任务未启动的证据/计数）。
- **`F10` 启动白名单 fail-fast 无副作用**：断言非法白名单时**无** DB/TPM/网络副作用（可观测证据），去除 tautology。
- **`F11` web_search 审计全 hold 集成**：补 `action.query` 经完整 hold（流式 + 非流）进入审计的集成测试。
- **`F12` 自定义规则跨帧 hold 端到端**：补 `feed_output_frame` 跨帧端到端用例。
- **`F13` fuzzy 还原边界覆盖**：补 response 表 token 与未知 seq 的 fuzzy 还原边界覆盖。
- **`F14` T8 design D8 表述与实现「段解析」对齐**：在无法修改的 sibling change 目录外，于本 change design 与本 change 可写文档给出更正后的「段解析」表述，随归档晋升 canonical 时同步。
- **`F15` H5 命名漂移更正**：核对并更正 `guard.rs` → `frame_feed.rs` 的 README/文档引用（若存在）；sibling change 目录冻结不改，登记于本 change design。
- **`F16` C7 两 TTL 口径明确**：明确「空闲票 60s 回收上限」与「有阻塞等待者凭据类票 300s 阻塞 TTL」两口径并存，避免歧义。
- **`F17` C5 hash 唯一性注释统一**：统一 `src/registry/store.rs` 注释与 `vault_ops` 预检口径说明（移除的是全局 hash 去重，注册判重仍按 path/name）。

## Capabilities

### New Capabilities

- `oracle-followup-fix`：独立 Oracle 复核后 17 项缺口的修复契约——审批建单以真实回执为键、审计链节起始别名折叠、Responses 工具分片先审后放、PII 短名槽变量语义、危险命令词边界匹配、摘要脱敏近似线性、TPM 守护结构化、缓存/清扫/启动副作用可观测、web_search 与自定义规则审计路径覆盖、fuzzy 还原边界，以及文档口径一致。

### Modified Capabilities

- 无。canonical `openspec/specs/` 既有契约（`credential-api`、`credential-approval-dual-mode`、`approval-hold-parity`、`matrix-approval-closure`、`audit-parity`、`pii-parity`、`llm-protocol-hardening` 等）的行为不动；本 change 新增 capability，相关 README 段落随行为同步更新。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `F1` | CRITICAL | `NotificationSink::send_text_tracked` 返回真实 event_id；全审批建单路径先发送取真实 id 再 `submit_branch`；发送失败 fail-closed；注入 sink 固定 id 回归（三态+超时）；spool 与审批路由差异文档化 | 1.1、1.2、1.3、1.4、1.5 |
| `F2` | HIGH | 先 `split_chain` 再逐段 `canonicalize_args`（或别名折叠覆盖链节首）；`;`/`|`/`(` 构造性绕过命中；管线优先级测试不回退；design D4 次序同步 | 2.1、2.2、2.3 |
| `F3` | HIGH | Responses 工具分片纳入 `should_buffer_tool_frame`/`should_suppress_held_output`；slot done 审计后再放行/阻断；危险明文不达下游且恰一阻断帧；多 item + delta 拆分 E2E | 3.1、3.2、3.3、3.4 |
| `F4` | MED | doc-align：README/design/spec 改为「短名槽变量＝文件路径别名、同槽同解析同 fail-closed、列序最低」；删「内联」表述；备选真内联不采用 | 4.1、4.2、4.3 |
| `F5` | MED | 危险表 `"dd "` 改词边界/命令词首；`add`/`cdd` 不误报、`dd if=...` 命中；design D3 措辞同步 | 5.1、5.2 |
| `F6` | MED | `mask_secret_forms`/`email_at` 输入上限约束或一次性小写预计算，近似线性；大输入边界测试；输出逐字不变 | 6.1、6.2、6.3 |
| `F7` | LOW | TPM 同步子进程守护改结构化可验证（收窄白名单/伪真分支断言）+ 绕行反例 | 7.1、7.2 |
| `F8` | LOW | analyzer 缓存加强为可观测跨调用复用证据 | 8.1、8.2 |
| `F9` | LOW | `init_no_sync_sweeper` 改可观测「清扫任务未启动」断言 | 9.1 |
| `F10` | LOW | `startup_whitelist_fail_fast` 断言非法白名单无 DB/TPM/网络副作用，去 tautology | 10.1 |
| `F11` | LOW | 补 `action.query` 经完整 hold（流式+非流）进审计的集成测试 | 11.1 |
| `F12` | LOW | 补自定义规则 `feed_output_frame` 跨帧端到端用例 | 12.1 |
| `F13` | LOW | 补 fuzzy 还原 response 表 token 与未知 seq 边界覆盖 | 13.1 |
| `F14` | LOW | T8 design D8 表述更正为「段解析」口径（sibling 冻结，登记+可写面同步） | 14.1 |
| `F15` | LOW | `guard.rs`→`frame_feed.rs` 命名引用更正（若存在）；sibling 冻结登记 | 14.2 |
| `F16` | LOW | 明确空闲票 60s 上限与阻塞票 300s TTL 两口径 | 14.3 |
| `F17` | LOW | 统一 `store.rs` hash 唯一性注释与 `vault_ops` 预检说明 | 14.4 |

## Non-Goals（显式）

- **不改 `src/`、`tests/` 与 README**：本 change 只交付规划 artifacts（proposal/design/spec/tasks），实现与文档改动留待 apply 阶段；不改 `openspec/changes/` 内其他 change 目录与 canonical specs；不提交 commit。
- **`F4` 不实现真内联语义**：裁决为 doc-align（见 design D4），不改 `src/config/custom_file.rs` 的 `path.is_file()` fail-closed；若需真内联须另立 change。
- **不重开已复核通过的面**：不碰三因子校验原语、不碰脱敏 recognizer 集合与采样策略、不改 usage `max` 口径、不改 Responses 保序/切片与真空终止、不改审计 verdict 判定口径。
- **不引入新依赖、不改 wire 枚举**：复用既有 Matrix 发送与审计设施；不改 `AutoApprove` 三值与任何配置项默认值。
- **窗口外发现不处理**：复核未列的其他漂移不在本 change 范围；`F14`/`F15`/`F16` 涉及冻结 change 目录的内容仅在可写面（本 change design/README）登记，不改 sibling 文件。

## Impact

- **新增文件**：`openspec/changes/veil-oracle-followup-fix/` 下 `proposal.md`、`design.md`、`specs/oracle-followup-fix/spec.md`、`tasks.md`（`.openspec.yaml` 已就位）。
- **apply 阶段改动面**：`src/service/matrix/notify.rs`、`src/service/matrix/bot.rs`、`src/service/credential/approval.rs`、`src/service/matrix/approval.rs`、`src/service/audit/rules.rs`、`src/service/audit/normalize.rs`、`src/service/audit/log.rs`、`src/handler/llm/pump/spawn.rs`、`src/config/env_parse.rs`、`src/service/tpm.rs`、`src/registry/store.rs`、对应单测与 `README.md` 相关段落。
- **影响系统**：Matrix 审批链可用性（阻塞/异步均恢复可决）；审计命令规范化拦截完整性；Responses 工具参数审计前置；PII 自定义规则文档语义；审计摘要性能；TPM/缓存/清扫/启动守护测试强度；web_search 与自定义规则审计覆盖。
- **依赖**：无新依赖；复用既有 Matrix 审批网关、审计管线与测试设施。
