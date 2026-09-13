## Purpose

锁定独立 Oracle 复核（2026-09-13）所确认 17 项缺口（`F1`–`F17`）的修复契约：Matrix 审批建单以真实回执为 pending 键、审计链节起始别名折叠、Responses 工具分片先审后放、PII 短名槽变量文件路径别名语义、危险命令词边界匹配、审计摘要脱敏近似线性、TPM 同步子进程约束可验证守护、缓存/清扫/启动副作用可观测、web_search 与自定义规则审计路径覆盖、fuzzy 还原边界，以及遗留文档口径一致。行为真相源为 `src/service/credential/approval.rs`、`src/service/matrix/notify.rs`、`src/service/matrix/bot.rs`、`src/service/matrix/approval.rs`、`src/service/audit/rules.rs`、`src/service/audit/normalize.rs`、`src/service/audit/log.rs`、`src/handler/llm/pump/spawn.rs`、`src/config/env_parse.rs`、`src/service/tpm.rs`、`src/registry/store.rs`。

## ADDED Requirements

### Requirement: Matrix 审批建单以真实回执为键

系统 SHALL 在创建 Matrix 审批单时以 Bot 发送返回的**真实 Matrix event id** 作为 pending 键，SHALL NOT 使用按时间戳/哈希合成的键。系统 SHALL 提供 tracked 发送能力（`NotificationSink::send_text_tracked -> Option<String>`，`MatrixBot` 实现返回真实 event_id）；所有审批建单路径（凭据、注册、吊销、哈希变更、解锁、audit-hold）SHALL 先 await 发送取得真实 id 再 `submit_branch(real_id, branch)`。系统 SHALL 在发送失败或未取得真实 id 时 fail-closed（不建不可决单，按拒绝/错误返回），SHALL NOT 静默建单后恒超时。用于事件环/spool 的 best-effort 发送 SHALL 保持不依赖回执。

#### Scenario: 反应按真实 id 命中 pending

- **WHEN** 审批单经 tracked 发送建立，审批人随后对同一消息回复 `✅`/`❎`/`🔓`
- **THEN** 反应回调以真实 `target_event_id` 命中 pending 并落定，不出现 300s 恒超时

#### Scenario: 发送失败 fail-closed

- **WHEN** tracked 发送失败或返回 `None`
- **THEN** 不建立审批单，调用方按拒绝/错误返回，不产生不可决 pending

#### Scenario: 注入 sink 固定真实 id 回归

- **WHEN** 注入返回固定真实 id 的测试 sink 并分别回复 `✅`/`❎`/`🔓`，以及无回复至超时
- **THEN** 三态与超时各按预期落定，验证不依赖合成键

### Requirement: 审计链节起始别名折叠

系统 SHALL 使命令别名折叠（`fold_bin_prefix`）对链节首（`;`/`|`/`&`/`(`/`）` 后的命令起始）生效；等价地，审计判定 SHALL 先 `split_chain` 再逐段规范化。系统 SHALL 使 `echo x;/bin/rm -rf tmp`、`echo x|/bin/rm -rf y`、`(/bin/rm -rf z)` 均命中危险命令判定，且 SHALL NOT 破坏既有管线/管道优先级与既有规范化测试。

#### Scenario: 分号后绝对路径命令命中

- **WHEN** 命令为 `echo x;/bin/rm -rf tmp`
- **THEN** 审计判定命中危险命令，返回对应 reason

#### Scenario: 管道后绝对路径命令命中

- **WHEN** 命令为 `echo x|/bin/rm -rf y`
- **THEN** 审计判定命中危险命令

#### Scenario: 子 shell 内绝对路径命令命中

- **WHEN** 命令为 `(/bin/rm -rf z)`
- **THEN** 审计判定命中危险命令

### Requirement: Responses 工具分片先审后放

系统 SHALL 对 Responses 协议缓冲未完成的工具分片（`should_buffer_tool_frame` 与 `should_suppress_held_output` 对 Responses 生效），SHALL NOT 在审计完成前把 `response.function_call_arguments.delta` 携带的参数直接下发。系统 SHALL 在 slot `.done` 完成审计后再决定放行或阻断。block 模式下，危险参数经 delta 分片时下游 SHALL NOT 出现危险明文，且 SHALL 收到恰一阻断帧。系统 SHALL NOT 改变 Responses 的保序/切片与真空终止语义。

#### Scenario: 危险参数经 delta 不泄漏

- **WHEN** Responses 工具调用参数以多个 `response.function_call_arguments.delta` 分片下发且含危险明文，`AUDIT_MODE=block`
- **THEN** 下游不出现危险明文，收到恰一阻断帧

#### Scenario: 安全参数正常放行

- **WHEN** Responses 工具调用参数分片下发且审计判定允许
- **THEN** 分片按原顺序放行，保序与切片语义不变

#### Scenario: 多 item 与 delta 拆分 E2E

- **WHEN** 单个响应含多个工具 item 且各自参数被拆分为多个 delta
- **THEN** 各 item 独立完成「缓冲 → done 审计 → 放行/阻断」，结论互不串扰

### Requirement: PII 短名槽变量为文件路径别名

系统 SHALL 将无 `_FILE` 后缀的 `PII_CUSTOM_RULES` / `PII_CUSTOM_PATTERNS` / `PII_CUSTOM_DICT` 定义为与对应 `*_FILE` 变量同槽的**文件路径兼容别名**：同槽合并、同文件路径解析、同 fail-closed 校验，列序优先级最低。系统 SHALL NOT 将其解释为内联内容或内容语义。相关 README/design/spec 措辞 SHALL 与实现字面一致。

#### Scenario: 短名槽解析为文件路径

- **WHEN** 仅设置 `PII_CUSTOM_RULES` 且其值为一个不存在的路径
- **THEN** 启动按 fail-closed 拒绝，与设置不存在的 `PII_CUSTOM_RULES_FILE` 行为一致

#### Scenario: 与 _FILE 同槽叠加

- **WHEN** 同时设置 `PII_CUSTOM_RULES_FILE` 与 `PII_CUSTOM_RULES`
- **THEN** 两者按列序合并加载，短名槽优先级最低，均按文件路径解析

### Requirement: 危险命令词边界匹配

系统 SHALL 以词边界/命令词首口径匹配危险命令表，SHALL NOT 以裸子串匹配导致误报。系统 SHALL 使 `echo add`、`cdd` 不判为危险，使 `dd if=... of=/dev/sda` 命中危险。

#### Scenario: 子串误报消除

- **WHEN** 命令为 `echo add`
- **THEN** 审计判定不因 `"dd "` 子串而误报危险

#### Scenario: 真实 dd 命中

- **WHEN** 命令为 `dd if=/dev/zero of=/dev/sda`
- **THEN** 审计判定命中危险命令

### Requirement: 审计摘要脱敏近似线性

系统 SHALL 使审计摘要脱敏（`mask_secret_forms` 与 `email_at`）在处理大输入时保持近似线性时间；SHALL 先按既有 4096/120 截断口径约束输入上限，或一次性预计算小写索引，SHALL NOT 对每个位置重复扫描/转换剩余串。系统 SHALL 保持脱敏输出与原行为逐字一致。

#### Scenario: 大输入边界不退化

- **WHEN** 审计摘要输入接近既有上限（如 ≤1MB 的 args）
- **THEN** 脱敏在近似线性时间内完成，不出现 O(n²) 级别耗时

#### Scenario: 输出逐字一致

- **WHEN** 对既有样例执行脱敏
- **THEN** 输出与修复前逐字相同（`audit_summary_forms`/`zero_plaintext`/`b9_deny_summary_dual_shapes` 保绿）

### Requirement: TPM 同步子进程约束可验证守护

系统 SHALL 以结构化可验证方式守护「TPM 操作仅经同步子进程/`spawn_blocking` 约束」：守护白名单 SHALL 收窄到约束范围（如 `spawn_blocking` 闭包），或以伪/真分支断言替代整文件标记探测；系统 SHALL 提供绕行反例测试证明别名等绕过会被拦。

#### Scenario: 白名单内调用通过

- **WHEN** TPM 同步调用位于受约束的 `spawn_blocking` 闭包内
- **THEN** 守护测试通过

#### Scenario: 绕行反例被拦

- **WHEN** 经由别名或非受约束路径触发同步 TPM 子进程
- **THEN** 守护测试失败/命中拦截，证明约束非整文件标记可绕

### Requirement: 分析器缓存可观测复用

系统 SHALL 使 hardening analyzer 的缓存复用具备可观测断言：跨调用复用 SHALL 有证据（命中计数或等价观测），SHALL NOT 仅以同输入同输出替代缓存命中验证。

#### Scenario: 跨调用复用命中

- **WHEN** 连续两次以相同输入调用 analyzer
- **THEN** 第二次命中既有缓存，有可观测命中证据而非仅结果相同

### Requirement: 审计清扫任务未启动可观测

系统 SHALL 使 `init_no_sync_sweeper` 的「不启动同步清扫」具备可观测断言（清扫任务未启动的证据/计数），SHALL NOT 仅以「同步 sweep 不 panic」作为弱代理。

#### Scenario: 无清扫任务启动

- **WHEN** 初始化 `no_sync_sweeper`
- **THEN** 有可观测证据表明清扫任务/后台 spawn 未启动

### Requirement: 启动白名单 fail-fast 无副作用

系统 SHALL 在校验非法 `APPROVAL_WHITELIST` fail-fast 时保证无 DB/TPM/网络副作用，并以可观测证据断言（数据目录未创建、TPM 未调用、后台任务未启动），SHALL NOT 使用不验证顺序的 tautology。

#### Scenario: 非法白名单无副作用

- **WHEN** 启动时 `APPROVAL_WHITELIST` 非法
- **THEN** 进程 fail-fast，且数据目录未创建、TPM 未调用、无网络/后台任务副作用

### Requirement: web_search 审计全 hold 路径

系统 SHALL 使 Responses `web_search_call` 的 `action.query` 经完整审计 hold 路径（流式与非流式）进入审计判定，并以集成测试锁定，SHALL NOT 仅以参数提取单测替代 hold 集成。

#### Scenario: 流式 hold 审计

- **WHEN** 流式响应含 `web_search_call` 且 `action.query` 命中危险/审计规则
- **THEN** 该查询经 hold 进入审计并按 verdict 处理

#### Scenario: 非流 hold 审计

- **WHEN** 非流式响应含 `web_search_call` 且 `action.query`
- **THEN** 该查询经 hold 进入审计，与流式同结论

### Requirement: 自定义规则跨帧 hold 端到端

系统 SHALL 提供自定义规则经 `feed_output_frame` 跨帧 hold 的端到端用例，覆盖跨帧拼接后命中审计的场景。

#### Scenario: 跨帧拼接命中

- **WHEN** 危险内容被拆分到多个输出帧经 `feed_output_frame` 依次送入
- **THEN** 跨帧拼接后命中自定义规则并进入审计处置

### Requirement: fuzzy 还原边界覆盖

系统 SHALL 覆盖 `PII_FUZZY_RESTORE` 的边界：response 表 token 与未知序号 SHALL 原样保留、不还原；并补对应测试。

#### Scenario: response 表 token 不还原

- **WHEN** 开启 fuzzy 还原且占位符序号来自 response 表
- **THEN** 该 token 原样保留，不回查请求表还原

#### Scenario: 未知序号不还原

- **WHEN** 占位符序号在任何已注册表中均不存在
- **THEN** 原样保留，不发生误还原

### Requirement: 遗留文档口径一致

系统 SHALL 使 `F14`–`F17` 的文档/注释与实现一致：`T8` design 表述 SHALL 采用「段解析」口径；命名引用 SHALL 使用 `frame_feed.rs`（若存在漂移则更正）；空闲票 `60s` 回收上限与有阻塞等待者凭据类 `300s` 阻塞 TTL SHALL 明确为两个并存口径；`store.rs` 的 hash 唯一性注释 SHALL 与 `vault_ops` 预检说明一致（移除仅指全局 hash 去重，注册判重仍按 path/name）。对已冻结的其他 change 目录 SHALL 仅在可写面登记，不改其内容。

#### Scenario: 两 TTL 口径无歧义

- **WHEN** 文档描述审批票回收
- **THEN** 同时明确「空闲票 60s 上限」与「有阻塞等待者凭据类票 300s 保留」两个口径，不混用

#### Scenario: hash 注释与预检一致

- **WHEN** 阅读 `store.rs` 注释与 `vault_ops` 预检说明
- **THEN** 二者对「全局 hash 去重已移除而注册判重仍按 path/name」表述一致
