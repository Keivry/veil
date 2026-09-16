## MODIFIED Requirements

### Requirement: 并发 Scope 内 PII 隔离 + 全局凭据 LRU

PII 映射 SHALL 隔离在请求级 `Scope` 内，请求结束即销毁，跨请求 MUST NOT 互见；**当且仅当** `PII_SCOPE_MODE=conversation` 且成功推导出会话键时，PII 映射 SHALL 提升为会话级共享作用域（同一会话键的多个请求互见；跨会话键、跨租户 MUST NOT 互见）。默认 `PII_SCOPE_MODE=request` 时行为 SHALL 与既有请求级隔离逐项一致。凭据明文到 token 映射 SHALL 走全局有界凭据 LRU（moka）；PII 还原 SHALL 只查本 `Scope`（请求级或会话级），MUST NOT 触达全局凭据 LRU；多请求并发脱敏/还原 SHALL 原子执行，MUST NOT 出现占位符串扰或映射撕裂。

#### Scenario: 并发请求不串扰

- **WHEN** 多请求并发执行脱敏与还原
- **THEN** 各作用域 PII 映射彼此隔离，凭据热路径走全局 LRU，结果正确

#### Scenario: 跨请求不可还原他方 PII

- **WHEN** 请求 B 在非同一会话键下持有请求 A 的 PII 占位符
- **THEN** 还原失败并原样保留，记审计计数

#### Scenario: 默认模式行为逐项不变

- **WHEN** `PII_SCOPE_MODE` 未设或为 `request`
- **THEN** 每请求独立 `Scope`，跨请求 PII 不可见，行为与既有实现逐项一致

#### Scenario: 会话模式跨轮互见

- **WHEN** `PII_SCOPE_MODE=conversation` 且同一会话键的两轮请求依次到达
- **THEN** 第二轮复用第一轮已注册 PII 的同一 token；不同会话键互不可见

### Requirement: Vault 稳态与 rand8 OsRng

占位符随机段 SHALL 使用 `OsRng` 生成 8 位十六进制串（rand8）；Vault 映射 SHALL 稳态存储占位符与原文映射，同一原文在同一请求内 SHALL 复用同一占位符；`PII_SCOPE_MODE=conversation` 下同一会话键内同一原文 SHALL 复用同一占位符（含同一 rand8），不同会话键 SHALL NOT 复用。跨轮复用 SHALL 不改变 rand8 的 CSPRNG 来源与不可预测性。

#### Scenario: 同值复用同一占位符

- **WHEN** 同一作用域内同一原文多次出现
- **THEN** 每次替换为同一占位符（含同一 rand8）

#### Scenario: 随机段不可预测

- **WHEN** 攻击者观察占位符序列
- **THEN** rand8 仍不可预测（`OsRng` 熵源）

#### Scenario: 会话内跨轮同值同 token

- **WHEN** 同一会话键的两轮请求含同一 PII 明文
- **THEN** 两轮产出同一 `__PII_<seq>_<rand8>__` token

#### Scenario: 会话间不复用

- **WHEN** 两个不同会话键的请求含同一 PII 明文
- **THEN** 各自独立分配 token，互不可见

## ADDED Requirements

### Requirement: 会话级 PII 作用域与作用域模式开关

系统 SHALL 提供会话级 PII 作用域模式，经 env 开关控制：`PII_SCOPE_MODE` 取值 `request`（默认）/`conversation`；`PII_SCOPE_TTL_SECS`（默认 `1800`，空闲 TTL）；`PII_SCOPE_MAX_CONVERSATIONS`（默认 `1024`，会话数上限）；`PII_SCOPE_KEY_HEADER`（默认 `x-veil-conversation-id`）。`request` 模式 SHALL 保持既有请求级 `Scope` 行为（零行为变化，默认即现行为，非 BREAKING）；`conversation` 模式 SHALL 将 PII 注册/还原落在会话级共享 `PiiScope` 上。会话数上限与空闲 TTL SHALL 触发 LRU/到期淘汰。淘汰或进程重启 SHALL 仅导致缓存失配（重新铸造 token），MUST NOT 影响正确性——未知/未授权 token 按既有语义原样保留或剥离。

#### Scenario: 默认模式零行为变化

- **WHEN** `PII_SCOPE_MODE` 未设
- **THEN** 每请求独立作用域，行为与既有实现逐项一致（非 BREAKING）

#### Scenario: 会话模式生效

- **WHEN** `PII_SCOPE_MODE=conversation` 且同一会话键跨轮到达
- **THEN** PII token 在轮间稳定复用

#### Scenario: 淘汰或重启仅缓存失配

- **WHEN** 会话条目因 TTL/容量淘汰或进程重启后相同会话再次到达
- **THEN** 重新铸造 token；响应侧按未知 token 语义处理（不误还原、不报错）

#### Scenario: 非法开关值拒启动

- **WHEN** `PII_SCOPE_MODE` 取值非 `request`/`conversation`
- **THEN** 启动期拒绝（fail-closed），不静默回退

### Requirement: 会话键分层推导与租户命名空间

系统 SHALL 按以下优先级（首个命中者胜）推导会话键：① 客户端显式头 `PII_SCOPE_KEY_HEADER`（默认 `x-veil-conversation-id`）之值，**长度 SHALL ≤256 字节**且经合法性校验（非空、无控制字符）；② 协议原生键——Chat/Responses 请求体的 `prompt_cache_key`（存在时），Responses 的 `previous_response_id` 经进程内响应 id→会话键映射解析（**该映射 SHALL 按租户指纹分域**：映射键 = `HMAC(secret, tenant_fingerprint || previous_response_id)`，故某租户铸造的 `previous_response_id` 在其他租户 MUST NOT 解析）；③ 稳定前缀 HMAC——对**脱敏前**规范化的 `tools + system + 首个 user turn 为止的前导 messages` 前缀做 HMAC；④ 回退请求级作用域。系统 SHALL NOT 使用 OpenAI `user` 字段作会话键（其为用户 id 而非会话 id，存在跨会话关联风险）。

推导 SHALL 为**条件性**：会话级稳定**当且仅当**第 1–3 级之一命中时成立——第 3 级要求请求同时具备 `tools` + `system` + 首个 user turn 三者，第 1/2 级依赖客户端配合（显式头 / `prompt_cache_key` / `previous_response_id`）。**纯多轮 `messages` 请求（无工具、无会话键头、无协议原生键）即便 `PII_SCOPE_MODE=conversation` SHALL 落第 4 级逐请求**，不获得跨轮 token 稳定，属预期降级（MUST NOT 报错或伪造键）。

会话键 SHALL 经 `HMAC(secret, tenant_fingerprint || conversation_id)` 派生。`tenant_fingerprint` SHALL 由**派生键之前即可得、且跨轮稳定**的信号派生（MUST NOT 事后回取「本请求命中的 vault 键集合」——vault 为全局明文→token 快照、按值匹配，不存在每请求「注入了哪个凭据」的选择点，事后预扫描会随轮次改变指纹而自败），口径固定：`tenant_fingerprint = HMAC(secret, 完整上游基址 || 分隔符 || 客户端凭据头归一化)`。

- **主判别项** SHALL 取**完整 `upstream_base`（含 path/query）**（`resolve_upstream` 产物，取自 `src/handler/llm/dispatch.rs:145`）；**MUST NOT 仅用上游主机**——`resolve_upstream` 按入口端口选上游，端口经（可伪造的）Host 头解析，不同端口可共享同一主机，仅用主机会把不同租户折叠进同一命名空间。
- **可选次判别项** SHALL 取客户端 Authorization/api-key 请求头的 HMAC（请求头，键推导前可得、跨轮稳定）；启用时并入指纹。
- **分隔符** SHALL 为固定单一字面量，界定各分量的拼接边界。
- **零/多凭据归一化** SHALL 为确定性函数：对客户端提供的凭据头，零个归一为**固定字面量（空串分量，非示例）**，多个去重后按字节序排序、以固定子分隔符 join，再并入 HMAC；全程 MUST NOT 含凭据原文。

客户端原始提供值 MUST NOT 直接作键。跨租户隔离 SHALL 由租户命名空间保证，但**仅为层内（in-layer）保证**：同一完整上游基址且客户端凭据头不可区分者 SHALL 落入同一命名空间（本层隔离不构成跨调用方保证；该残余限制显式登记于本要求与 `credential-vault-singleton` 的相关条款）。

第 3 级（稳定前缀）SHALL 为**确定性**推导：规范化 SHALL 对前缀 JSON 对象递归按键名升序排序、对 `tools` 数组按工具名稳定排序、其余数组保序；同一逻辑前缀的任意键序/工具序扰动 SHALL 归一到同一字节序列，**同输入恒得同键**。无法规范化（非 JSON 容器，或缺 `tools`/`system`/首个 user turn）时第 3 级 SHALL 不可命中并落第 4 级，MUST NOT 产生含糊键。第 3 级的**规范化规则已定**（即上句的确定性函数，SHALL NOT 因测试补充而改变）；**多模态内容块等边界由 apply 期补测试**（`conversation_key_stable_prefix_deterministic` 锁定同输入恒同键与键序/工具序扰动不变），规则文本与本条一致、须与 `design.md` 同口径（MUST NOT 表述为「规则待定」）。

会话键头 SHALL 由网关消费：其名与值 MUST NOT 出现在转发上游的请求头或任一日志行；默认头名位于 `x-veil-*` 内部命名空间，由 `src/handler/llm/mod.rs:45-46` 于转发前统一剔除；自定义头名 MUST 同样在转发前剔除。`previous_response_id` 映射的写入点 SHALL **仅限 `Protocol::Responses` 的响应完成处**（流式 `src/handler/llm/pump/spawn/event_loop.rs:205-210`；非流 `src/handler/llm/nonstream.rs:205-213`）；上述两处实现为协议无关（Chat 亦产出 `chatcmpl-*`、Anthropic 产出 `msg_*`），故写入 SHALL 先判 `Protocol::Responses`，**Chat/Anthropic 的响应 id MUST NOT 进入该映射**。上游 `response.id` SHALL **值级不变**（客户端下一轮 `previous_response_id` 可解析）：该 id 非 PII 匹配面，零替换帧逐字节透传、含新 PII 帧经 `loads→walk→dumps` 重序列化时其值仍不变——论断按值级成立，MUST NOT 表述为「字节级透传保证」。键推导 SHALL 为纯函数，MUST NOT 发起网络 I/O。

#### Scenario: 显式头优先

- **WHEN** 请求携带合法 `x-veil-conversation-id`
- **THEN** 以其（经租户命名空间 + HMAC）为键，忽略协议原生与稳定前缀来源

#### Scenario: prompt_cache_key 次之

- **WHEN** 无显式头且请求体含 `prompt_cache_key`
- **THEN** 以其为会话键来源（仍经租户命名空间 + HMAC）

#### Scenario: previous_response_id 解析

- **WHEN** 无显式头与 `prompt_cache_key`，Responses 请求携带 `previous_response_id`
- **THEN** 经进程内映射解析为既有会话键；未命中则继续下一优先级

#### Scenario: 稳定前缀兜底（条件性命中）

- **WHEN** 前两级均不可用，且请求同时具备 `tools` + `system` + 首个 user turn
- **THEN** 以脱敏前 `tools + system + 首个 user turn` 前缀的 HMAC 为键；三者缺一即不命中第 3 级

#### Scenario: 无工具纯多轮落第 4 级

- **WHEN** `PII_SCOPE_MODE=conversation` 且请求为纯多轮 `messages`（无 `tools`、无会话键头、无 `prompt_cache_key`/`previous_response_id`）
- **THEN** 第 3 级不命中（缺 `tools`），SHALL 落第 4 级逐请求；MUST NOT 报错或伪造会话键，跨轮 token 稳定不成立属预期降级

#### Scenario: 不可推导回退请求级

- **WHEN** 全部层级均无法得出键
- **THEN** 回退请求级作用域（缓存失配），MUST NOT 报错或伪造键

#### Scenario: user 字段不作键

- **WHEN** 请求体仅含 OpenAI `user` 字段而无其他可用来源
- **THEN** SHALL NOT 以其作会话键，按回退请求级处理

#### Scenario: 跨租户不可见

- **WHEN** 两个租户（不同完整上游基址，或相同基址但客户端凭据头可区分）提交相同客户端会话 id
- **THEN** 派生键因租户命名空间不同而隔离，互不可见

#### Scenario: 跨租户 previous_response_id 不可解析

- **WHEN** 租户 A 的响应铸造 `response.id` 并写入其映射，同一 `previous_response_id` 出现在租户 B 的请求
- **THEN** 映射因租户指纹分域而未命中，SHALL NOT 解析为租户 A 的会话键（继续下一优先级）

#### Scenario: 仅主机不足以防折叠

- **WHEN** 不同入口端口经（可伪造的）Host 头选中共享同一主机但路径/query 不同的上游基址
- **THEN** 指纹因取**完整 `upstream_base`（含 path/query）**而不同，SHALL NOT 折叠进同一命名空间（仅用主机不足以区分）

#### Scenario: 零凭据归一定义租户指纹

- **WHEN** 客户端未提供任何凭据头
- **THEN** 凭据分量归一为**固定字面量**（空串分量，非示例），`tenant_fingerprint` 恒有定义且非空；相同完整上游基址下稳定，不同完整上游基址间隔离

#### Scenario: 多凭据归一确定性

- **WHEN** 客户端提供多个凭据头（或同一值的重复项）
- **THEN** 去重后按字节序排序、以固定子分隔符 join 再并入 HMAC，同集合恒得同指纹（顺序扰动不变）

#### Scenario: 同基址不可区分者共享命名空间（层内保证）

- **WHEN** 两个调用方共享同一完整上游基址且客户端凭据头不可区分
- **THEN** 派生键落入同一租户命名空间（会话键隔离仅为**层内（in-layer）**保证，MUST NOT 被理解为跨调用方保证）；该残余限制显式登记于本要求

#### Scenario: 稳定前缀确定性

- **WHEN** 同一逻辑前缀（同 `tools`/`system`/首 user turn）以不同键序或不同工具序提交两次
- **THEN** 规范化归一到同一字节序列，两次得**同一**会话键

#### Scenario: 会话键头超长拒绝

- **WHEN** `PII_SCOPE_KEY_HEADER` 头值超过 256 字节（或含控制字符）
- **THEN** 该来源不命中（按优先级继续下一级），SHALL NOT 以截断/哈希原始超长值作键

#### Scenario: 会话键头不转发不入日志

- **WHEN** 请求携带会话键头
- **THEN** 头名/头值 MUST NOT 出现在转发上游的请求头或任一日志行（`x-veil-*` 由 `src/handler/llm/mod.rs:45-46` 剔除，自定义头名同样剔除）

### Requirement: 会话作用域存储有界与并发收敛

系统 SHALL 以进程内存 LRU + TTL 存储 `ConversationScopeStore` 承载会话作用域，键为会话键（HMAC 派生），并 SHALL 挂 `AppState`（`src/state.rs:37-71`，启动装配 `src/state.rs:88-163`）以跨请求共享。存储 SHALL 满足：会话数上限 `PII_SCOPE_MAX_CONVERSATIONS`（默认 1024）；单会话条目上限沿用既有 `PII_MAX_ENTRIES`（1000）；空闲 TTL `PII_SCOPE_TTL_SECS`（默认 1800 秒）。存储 SHALL 同时受**聚合上界**约束：单会话 `PiiScope` 含**两张表**——请求表与响应表，各自在 `>= PII_MAX_ENTRIES` 时淘汰（`src/service/pii/scope.rs:169`、`:181`），故条目总数 SHALL ≤ `PII_SCOPE_MAX_CONVERSATIONS` × `PII_MAX_ENTRIES` × 2（默认 1024 × 1000 × 2 = 2,048,000），单值长度受请求体上限（10MB）约束；`previous_response_id` 映射条目数 SHALL 同受 `PII_SCOPE_MAX_CONVERSATIONS` 约束。get-or-insert SHALL 原子化并返回共享 `Arc<PiiScope>`，使同会话键的并发在途请求收敛到同一 token（同值复用经 `PiiScope` 内部 Mutex 原子执行）。淘汰策略 SHALL 确定性且可测。存储 SHALL 经 `lock_or_recover` 语义承载，锁中毒时 fail-closed（不静默降级为错误结果）。跨租户 LRU 干扰（客户端经第 1 级头铸造无限会话键挤出他租户条目）SHALL 仅致缓存失配/重新铸造，MUST NOT 影响正确性、MUST NOT 破坏跨租户隔离；该风险 SHALL 显式登记为**已接受风险**（本层不限速，隔离不变量优先）。

#### Scenario: 同会话并发收敛

- **WHEN** 同会话键的多个请求并发在途且含同一明文
- **THEN** 收敛到同一 token，不出现同明文多 token

#### Scenario: 会话数有界

- **WHEN** 活跃会话数超过 `PII_SCOPE_MAX_CONVERSATIONS`
- **THEN** 按 LRU 淘汰至上限内；淘汰仅致缓存失配

#### Scenario: 单会话条目有界

- **WHEN** 单会话注册值超过 `PII_MAX_ENTRIES`
- **THEN** 沿用既有 LRU 淘汰语义，条目数有界

#### Scenario: 空闲 TTL 驱逐

- **WHEN** 会话在 `PII_SCOPE_TTL_SECS` 内无访问
- **THEN** 被驱逐；再次到达时重新铸造 token

#### Scenario: 淘汰确定性可测

- **WHEN** 注入容量/TTL 并触发淘汰
- **THEN** 被淘汰者确定且可断言

#### Scenario: 聚合上界

- **WHEN** 多会话注册值（会话数 ≤ 上限且单会话各表条目 ≤ 上限）
- **THEN** 存储条目总数 ≤ `PII_SCOPE_MAX_CONVERSATIONS` × `PII_MAX_ENTRIES` × 2（请求表 + 响应表各 1000，默认 2,048,000），不无界增长

#### Scenario: 恶意键 churn 仅致失配

- **WHEN** 客户端滥用第 1 级头铸造无限会话键以挤出他租户条目
- **THEN** 仅致被挤出会话的缓存失配/重新铸造（未知 token 按既有语义原样保留/剥离），正确性与跨租户隔离不变（已接受风险）

### Requirement: PII 会话级与凭据请求级授权域不对称

授权域 SHALL 显式不对称：PII token 为**会话级**——同一会话键下早期轮次铸造的 PII token 在后续轮次 MAY 还原（多轮正确性所需）；凭据 token 保持**请求级**（B3 不变）——响应侧凭据还原 SHALL 仅授权「本请求脱敏实际产出」的 token（minted-set），未授权凭据 token SHALL 按幻觉剥离。系统 MUST NOT 因会话级 PII 作用域而放宽凭据授权域（SHALL NOT 使凭据 token 进入会话级作用域）。非本会话/非本请求铸造的 token 之还原 SHALL 不可能。

#### Scenario: 会话内 PII 跨轮还原

- **WHEN** 会话键 K 的第 1 轮铸造 PII token，第 2 轮响应含该 token
- **THEN** 第 2 轮可还原该 PII

#### Scenario: 跨会话 PII 不可还原

- **WHEN** 会话键 K1 铸造的 PII token 出现在会话键 K2 的响应
- **THEN** 不可还原，按未知 token 原样保留/剥离

#### Scenario: B3 凭据请求级不变

- **WHEN** 上一轮请求铸造的凭据 token 出现在本轮响应
- **THEN** 未授权，按幻觉剥离；仅本请求 minted-set 内凭据 token 可还原

#### Scenario: 凭据不进会话作用域

- **WHEN** 检查会话级作用域承载内容
- **THEN** 仅含 PII 映射，凭据映射仍由进程单例 vault + 请求级 minted-set 承载

### Requirement: 会话作用域隐私增量与 MUST NOT 承诺清单

本模式的隐私增量 SHALL 显式声明：启用 `conversation` 后明文在 TTL 窗口内常驻内存（相对「请求结束即销毁」属回归）；会话内关联可接受（上游 provider 本就关联同一上下文的轮次）；跨会话隔离 SHALL 保持。系统 SHALL NOT 承诺：provider 缓存命中率可测量的提升（命中率为上游计费指标，本地不测量，wont-measure 保持）、跨会话 token 稳定性、凭据占位符稳定性、零明文常驻、网关重启后 token 稳定、键推导含糊时的任何行为。不可泄露约束 SHALL 覆盖**日志层**：会话键、头值、明文与 token MUST NOT 出现在任一日志行（含 `tracing` debug 级），强度与 `/_admin/metrics` 不泄露约束一致。

#### Scenario: 隐私增量显式登记

- **WHEN** 查阅本能力文档与 spec
- **THEN** 明文 TTL 常驻、会话内关联可接受、跨会话隔离保持均显式列出

#### Scenario: MUST NOT 承诺清单完备

- **WHEN** 检查对外承诺
- **THEN** 不含缓存命中率提升、跨会话 token 稳定、凭据占位符稳定、零明文常驻、重启稳定、含糊键行为等承诺

#### Scenario: 未启用时不增加常驻

- **WHEN** `PII_SCOPE_MODE=request`（默认）
- **THEN** 不引入会话级明文常驻（与既有请求级销毁语义一致）

#### Scenario: 日志不泄露键/明文/token

- **WHEN** 在 `conversation` 模式下产生请求处理日志（含 debug 级）
- **THEN** 日志行不含会话键、头值、明文或 token 原值
