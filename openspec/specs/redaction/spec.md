# redaction Specification

## Purpose
请求与响应双侧脱敏：凭据 token 与 PII 占位符在转发前替换、响应中还原，语义等价改写保证 JSON 结构与业务含义不变，并发安全，残缺占位符不泄漏。本 spec 为 json-aware 与 FIX-5 字节契约的权威定义，protocol-compliance-fix spec FIX-5 只引用本 spec。

## Requirements

### Requirement: 凭据 token 与 PII 双侧脱敏

系统 SHALL 在请求侧将凭据明文与 PII 替换为占位符，在响应侧将占位符还原为原文；请求侧未注册的值在响应中出现 SHALL 按响应侧新检出处理，不自动还原。

#### Scenario: 请求侧替换响应侧还原
- **WHEN** 请求正文含已注册凭据或 PII
- **THEN** 转发上游时为占位符，返回客户端时还原为原文

#### Scenario: 响应新检出不还原
- **WHEN** 响应中出现请求期未注册的新 PII
- **THEN** 系统以新占位符呈现，不还原为明文

### Requirement: 7 recognizer + 联合正则 + 中文边界

系统 SHALL 内置 7 recognizer：手机号、身份证、银行卡、邮箱、IPv4、IPv6、API 密钥；7 recognizer SHALL 联合为单一联合正则一次扫描；中文与 CJK 边界 SHALL 用 lookaround 表达，MUST NOT 用 `\b`（`\b` 对 CJK 无效）；含 `\b` 的自定义正则 SHALL 拒绝加载。内置 recognizer 名单长度 SHALL 恒为 7（`email/phone/id_card/bank_card/ipv4/ipv6/api_key`），与实现/Python 一致。

#### Scenario: 六类命中

- **WHEN** 正文含上述七类之一
- **THEN** 联合正则一次扫描即命中对应 recognizer

#### Scenario: \b 正则拒绝加载

- **WHEN** 自定义正则含 `\b`
- **THEN** 系统拒绝加载并报错

#### Scenario: CJK 边界正确

- **WHEN** 敏感值紧贴中文字符
- **THEN** lookaround 边界正确判定，不误报不断句

#### Scenario: 内置计数为 7

- **WHEN** 检查内置 recognizer 名单
- **THEN** 其长度为 7（含 `ipv6`），与实现/Python 一致

### Requirement: Luhn 与 GB 校验位 + 保留豁免清单

银行卡 SHALL 过 Luhn 校验，身份证 SHALL 过 GB 校验位；未过校验 SHALL NOT 替换；保留豁免清单（含示例号码、文档占位值、测试号段）命中的 SHALL 豁免不替换。保留豁免清单 SHALL 同时覆盖 IPv4 保留网段，至少包含 `192.88.99.0/24`（6to4 中继任播网段），命中该网段的 IPv4 值 SHALL 豁免不替换，避免过度脱敏。

#### Scenario: 校验位拦截误报

- **WHEN** 数字串形似卡号但 Luhn / GB 校验失败
- **THEN** 系统不替换

#### Scenario: 豁免清单放行

- **WHEN** 命中值在保留豁免清单内
- **THEN** 系统不替换

#### Scenario: IPv4 保留网段豁免

- **WHEN** IPv4 值落在保留网段（如 `192.88.99.x`）
- **THEN** 系统豁免不替换，不因过度脱敏改写明文

### Requirement: 自定义正则 ReDoS 100ms 与字典独立扫描

自定义正则 SHALL 跑独立线程池执行，单次超时 SHALL 为 100ms；同一模式连续 3 次超时 SHALL 停用该模式并告警；字典 SHALL 独立扫描（不并入联合正则），逐词精确匹配。

#### Scenario: 恶意模式 100ms 拦截
- **WHEN** 自定义正则为 `^(a+)+$` 类灾难回溯模式
- **THEN** 100ms 内被独立池拦截，本次扫描跳过该模式

#### Scenario: 连续 3 次超时停用
- **WHEN** 同一自定义模式连续 3 次超时
- **THEN** 系统停用该模式并告警，后续扫描不再加载

#### Scenario: 字典独立扫描
- **WHEN** 正文含字典词
- **THEN** 字典扫描独立命中，不干扰联合正则

### Requirement: json-aware 语义等价改写（FIX-5 权威定义）

脱敏改写 SHALL 为 json-aware：仅替换 JSON 字符串值语义，不改变键名、结构、数字与布尔类型；默认 SHALL 仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`。改写前后 JSON 语义 SHALL 等价（除占位符替换外）。同一明文跨多个 JSON 深度出现时，转义 SHALL 按各 span 实际所在深度逐出现点判定，MUST NOT 以该明文的全局最大深度统一聚合转义；深度分析 SHALL 计入对象 key（键名所在深度），使深键位与浅值位的转义互不误伤。

#### Scenario: 结构与类型不变

- **WHEN** 请求体为 JSON 且含需脱敏的字符串值
- **THEN** 改写后键名、层级、非字符串类型均不变，仅目标值变为占位符

#### Scenario: 非字符串值不碰

- **WHEN** 数字、布尔、null 字段的值与敏感值文本相同
- **THEN** 系统不替换这些非字符串字段

#### Scenario: 默认不重排仅开启重写

- **WHEN** `normalize_json_whitespace` 未开启
- **THEN** 不做 `dumps` 重写；开启为 `1` 时才重写并带 `x-veil-normalized:json-whitespace`

#### Scenario: 同明文跨深度逐点转义

- **WHEN** 同一明文分别出现在浅层值位与深层值位
- **THEN** 各 span 按自身所在深度转义，浅层不被过度转义（内容不损坏）

#### Scenario: 对象键位计入深度

- **WHEN** 敏感值出现在对象 key 位置
- **THEN** 深度分析计入键位深度，转义判定与值位同口径，不因漏算而欠转义

### Requirement: 凭据优先于 PII

同一文本同时命中凭据与 PII 规则 SHALL 优先按凭据处理，PII 规则 SHALL NOT 覆盖凭据占位符。

#### Scenario: 凭据优先
- **WHEN** 某值同时匹配凭据与 PII 模式
- **THEN** 系统生成凭据占位符，PII 规则跳过该区间

### Requirement: Vault 稳态与 rand8 OsRng

占位符随机段 SHALL 使用 `OsRng` 生成 8 位十六进制串（rand8）；Vault 映射 SHALL 稳态存储占位符与原文映射，同一原文在同一请求内 SHALL 复用同一占位符；`PII_SCOPE_MODE=conversation` 下同一会话键内同一原文 SHALL 复用同一占位符（含同一 rand8），不同会话键 SHALL NOT 复用。跨轮复用 SHALL 不改变 rand8 的 CSPRNG 来源与不可预测性。

PII 值注册（`PiiScope::register`）失败 SHALL 区分两类处置，MUST NOT 共用同一错误分支：(1) **token 形态拒绝**——待注册值本身即命中内部 token 形态或保留前缀（`__PII_`/`__VG_CRED_` 等），SHALL 静默跳过该值（不替换、不改写请求、不失败）；(2) **熵源/内部故障**——rand8 的 `OsRng` 熵源不可用等，SHALL **fail-closed**：记 `warn!`（MUST NOT 含明文、token、会话键、头值）并计入指标，且请求 MUST NOT 以未脱敏正文转发上游，以下游可观测的网关级不可用错误收敛（HTTP `502` + 错误码 `E_PII_UNAVAILABLE`，错误体形态与既有网关错误一致）。

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

#### Scenario: token 形态值静默跳过

- **WHEN** 待注册值本身即 `__PII_*`/`__VG_CRED_*` token 形态或含保留前缀
- **THEN** 静默跳过该值（不替换、不改写请求、不失败），与既有语义一致

#### Scenario: 熵源故障 fail-closed

- **WHEN** rand8 的 `OsRng` 熵源或内部生成不可用
- **THEN** 记不含明文/token/键/头值的 `warn!` 与指标，请求以 `502` + `E_PII_UNAVAILABLE` 收敛，MUST NOT 转发未脱敏正文

### Requirement: 并发 Scope 内 PII 隔离 + 全局凭据 LRU

PII 映射 SHALL 隔离在请求级 `Scope` 内，请求结束即销毁，跨请求 MUST NOT 互见；**当且仅当** `PII_SCOPE_MODE=conversation` 且成功推导出会话键时，PII 映射 SHALL 提升为会话级共享作用域（同一会话键的多个请求互见；跨会话键、跨租户 MUST NOT 互见）。默认 `PII_SCOPE_MODE=request` 时行为 SHALL 与既有请求级隔离逐项一致。凭据明文到 token 映射 SHALL 走全局有界凭据 LRU（moka）；PII 还原 SHALL 只查本 `Scope`（请求级或会话级），MUST NOT 触达全局凭据 LRU；多请求并发脱敏/还原 SHALL 原子执行，MUST NOT 出现占位符串扰或映射撕裂。

单 `PiiScope` 内请求表与响应表 SHALL 各自维护**独立的序号空间与分配游标**，并在**各表内**满足可观测不变量**「一个在用条目 ↔ 一个序号」**（同一表内不出现重复序号；数值相同的序号可同时存在于两表，属两套独立序号空间的正常现象，另有等价实现须显式登记）。某表在用序号集覆盖 `1..=PII_MAX_ENTRIES` 时，该表下一次分配 SHALL 返回饱和哨兵 `PII_MAX_ENTRIES + 1`（同一表内至多一个在用条目持有该哨兵），紧随其后的 LRU 淘汰 SHALL 释放一个空洞供后续分配复用；饱和 SHALL NOT 使**同一表内**多 token 共享同一序号。按序号回查的 `fuzzy` 还原 SHALL **仅查询请求表**（`restore_with_fuzzy` 的序号→明文映射仅由请求表构建），故响应表在数值上相同的序号 SHALL NOT 被解析到响应表明文——跨表误解析结构性不可能。序号分配 SHALL 保持均摊有界，MUST NOT 在饱和时每次全量扫描。序号值非对外契约，不可预测性由 rand8（CSPRNG）承担。

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

#### Scenario: 请求/响应表序号空间独立

- **WHEN** 单 `PiiScope` 的请求表与响应表各自注册至并超过 `PII_MAX_ENTRIES`
- **THEN** 两表序号空间独立；**各表内**「一个在用条目 ↔ 一个序号」成立（含饱和哨兵 `PII_MAX_ENTRIES + 1` 在单表内至多被一个在用条目持有）；数值相同的序号可同时存在于两表，属两套独立序号空间，不构成同表重复

#### Scenario: 饱和不产生跨表错值

- **WHEN** 两表各自达到饱和并继续注册（触发饱和哨兵与 LRU 空洞释放）
- **THEN** 同表内 SHALL NOT 出现两个在用 token 共享同一序号（含哨兵 `PII_MAX_ENTRIES + 1`）；`fuzzy` 还原仅查请求表，SHALL NOT 将截断形态 token 解析到响应表的明文

### Requirement: 残缺占位符清理

流式分片切断导致的残缺占位符 SHALL 被累积补全后处理；补全失败或孤立残缺 SHALL 清理为原样文本或告警，MUST NOT 向任一侧泄漏半截占位符。

#### Scenario: 切断占位符补全
- **WHEN** 占位符被 SSE 分片切断
- **THEN** 系统累积后续分片补全后再替换或还原

#### Scenario: 孤立残缺清理
- **WHEN** 流结束仍有无法补全的残缺占位符
- **THEN** 系统原样保留并记审计事件，不输出半截占位符

### Requirement: 检测窗口字符边界安全

系统 SHALL 使 `bank_card` 等 recognizer 的上下文窗口切片（前后窗）使用字符边界安全切片，MUST NOT 对多字节 UTF-8 执行裸字节切片而 panic；窗口长度语义 SHALL 保持不变（对齐仅用于消除非法切片，不放宽也不收紧窗口）。当卡号前缀（如 `62`/`60`/`34`/`35` 开头）与多字节字符（CJK/emoji 等）紧邻或跨越窗口边界时，扫描 SHALL 正常返回命中或未命中结论，MUST NOT 中断异步请求热路径。

#### Scenario: 多字节值跨界不 panic

- **WHEN** `bank_card` 候选值（含 `62`/`60`/`34`/`35` 前缀）与多字节字符紧邻且落入上下文窗口边界
- **THEN** 扫描正常返回结论，进程不 panic、请求不中断

#### Scenario: 窗口语义不变

- **WHEN** 上下文窗口边界因字符对齐而位移
- **THEN** 命中判定与既有窗口语义一致，不因对齐而漏判或误判

### Requirement: 还原 span 逐出现点定位

系统 SHALL 以逐出现点（per-occurrence）映射定位还原 span，MUST NOT 以明文子串全量查找后整段跳过（skip 集）定位；当同一明文在响应侧作为独立明文出现（非占位符还原点）时，系统 SHALL 仍按响应侧新检出对该独立明文掩码，SHALL NOT 因 skip 集过度覆盖而放行。

#### Scenario: 同值独立明文仍被掩码

- **WHEN** 响应同时含一处由占位符还原的同值点与一处独立同值明文
- **THEN** 独立明文按响应侧新检出被掩码，不因 skip 集漏放

#### Scenario: 逐出现点不误伤

- **WHEN** 同一明文在单个响应内多处出现且仅部分为还原点
- **THEN** 各出现点按自身语义分别处理，互不整段覆盖

### Requirement: 残余帧 JSON 转义还原

系统 SHALL 对残余帧（流末未被正常路径处理、但载荷为完整 JSON 的半帧）使用 JSON-aware 的按深度转义还原（`restore_response_with_spans_json`），与正常帧同一口径；SHALL NOT 使用逐字插入变体（`restore_response_with_spans`）。当还原明文含 `"`、`\` 或控制字符时，输出 SHALL 仍为合法 JSON。

系统 SHALL 使残余帧还原与正常帧还原**共用单一发送 helper** `emit_restored_json_frame`（handler 层，含 metrics/warn）：该 helper SHALL 恒执行 `guard_restored_frame_parsed`（还原后 JSON 可解析 + 内层 `inner_json_intact`），守卫**失败时 SHALL 回退占位符帧**（SHALL NOT 落非法 JSON、SHALL NOT 直接 `feed_output_frame`）；仅守卫成功才输出还原帧。残余路径（`terminal.rs`）与正常帧路径（`event_loop.rs` 的 opaque 臂与普通臂）SHALL 均经该 helper，SHALL NOT 各自内联直通。`service::redaction::restore_guard` SHALL 保持零 axum 依赖边界。

#### Scenario: 明文含引号仍为合法 JSON

- **WHEN** 残余帧为完整 JSON 且还原出的明文含双引号或反斜杠
- **THEN** 明文按 JSON 深度转义写入，残余帧解析后仍为合法 JSON

#### Scenario: 控制字符不破坏结构

- **WHEN** 还原明文含换行等控制字符
- **THEN** 按深度转义输出，JSON 结构保持完整可解析

#### Scenario: 残余帧守卫失败回退占位符帧

- **WHEN** 残余帧还原后 JSON 校验失败（外层破损或内层 stringified JSON 破损）
- **THEN** 输出回退为占位符帧并记录 metrics/warn，不输出非法 JSON，与正常帧守卫失败语义一致

#### Scenario: 残余与正常帧共用 helper

- **WHEN** 检查残余帧路径与正常帧路径的还原发送点
- **THEN** 两者均调用 `emit_restored_json_frame`，无内联直通 `feed_output_frame`，守卫与回退口径一致

### Requirement: 未闭合 JSON 片段深度计

系统 SHALL 在已知工具参数载体帧下，对**未闭合**的 JSON 片段按「外层字符串 + 内层容器」计 `depth+1`。载体判据 SHALL 限定为：帧 `type == "response.function_call_arguments.delta"`；或 `type == "content_block_delta"` 且 `delta.type == "input_json_delta"`；或子树键名为 `partial_json` / `arguments`。完整可解析容器的既有分支优先级 SHALL 不变；载体以外的普通字符串（如 `delta.text`）SHALL NOT 应用加一，SHALL NOT 无差别加一。

若实现中载体判定被证实不可靠，系统 SHALL 降级为「声明该限制 + 锁定回归用例」；SHALL NOT 采用无差别加一（会使纯文本被过度转义）。

#### Scenario: 未闭合片段按内层深度转义

- **WHEN** 工具参数载体帧携带以 `{`/`[` 开头但整体不可解析的 JSON 片段，其中含凭据 token
- **THEN** 该 token 按 `depth+1` 转义写入，片段拼接进内层 JSON 后结构有效

#### Scenario: delta.text 不受影响

- **WHEN** 普通字符串字段（如 `delta.text`）含 token 而非 JSON 容器
- **THEN** SHALL NOT 应用加一，还原转义与既有口径一致

#### Scenario: 完整容器行为不变

- **WHEN** 载体帧携带完整可解析的 JSON 容器
- **THEN** 走既有完整容器分支，深度与转义结果不变

### Requirement: 会话级 PII 作用域与作用域模式开关

系统 SHALL 提供会话级 PII 作用域模式，经 env 开关控制：`PII_SCOPE_MODE` 取值 `request`（默认）/`conversation`；`PII_SCOPE_TTL_SECS`（默认 `1800`，空闲 TTL）；`PII_SCOPE_MAX_CONVERSATIONS`（默认 `1024`，会话数上限）；`PII_SCOPE_KEY_HEADER`（默认 `x-veil-conversation-id`）。`request` 模式 SHALL 保持既有请求级 `Scope` 行为（零行为变化，默认即现行为，非 BREAKING）；`conversation` 模式 SHALL 将 PII 注册/还原落在会话级共享 `PiiScope` 上。会话数上限与空闲 TTL SHALL 触发 LRU/到期淘汰。淘汰或进程重启 SHALL 仅导致缓存失配（重新铸造 token），MUST NOT 影响正确性——未知/未授权 token 按既有语义原样保留或剥离。

会话级 token 跨轮稳定 SHALL 为**条件性**：**当且仅当**会话键成功推导（见「会话键分层推导与租户命名空间」第 1–3 级之一命中）时成立；键不可推导的请求形态 SHALL 落逐请求作用域，不获跨轮 token 稳定，属**预期降级**（MUST NOT 报错、MUST NOT 伪造会话键）。该条件性对全部协议与请求形态一视同仁，包括 Responses **标量 `input`** 简写形态（其第 3 级不可命中，见「会话键分层推导与租户命名空间」）。

#### Scenario: 默认模式零行为变化

- **WHEN** `PII_SCOPE_MODE` 未设
- **THEN** 每请求独立作用域，行为与既有实现逐项一致（非 BREAKING）

#### Scenario: 会话模式生效

- **WHEN** `PII_SCOPE_MODE=conversation` 且同一会话键跨轮到达
- **THEN** PII token 在轮间稳定复用

#### Scenario: 会话级稳定条件性（不可推导即降级）

- **WHEN** `PII_SCOPE_MODE=conversation` 且请求形态无法推导会话键（如 Responses 标量 `input` 简写）
- **THEN** 落逐请求作用域，token 不跨轮稳定，MUST NOT 报错或伪造会话键，属预期降级

#### Scenario: 淘汰或重启仅缓存失配

- **WHEN** 会话条目因 TTL/容量淘汰或进程重启后相同会话再次到达
- **THEN** 重新铸造 token；响应侧按未知 token 语义处理（不误还原、不报错）

#### Scenario: 非法开关值拒启动

- **WHEN** `PII_SCOPE_MODE` 取值非 `request`/`conversation`
- **THEN** 启动期拒绝（fail-closed），不静默回退

### Requirement: 会话键分层推导与租户命名空间

系统 SHALL 按以下优先级（首个命中者胜）推导会话键：① 客户端显式头 `PII_SCOPE_KEY_HEADER`（默认 `x-veil-conversation-id`）之值，**长度 SHALL ≤256 字节**且经合法性校验（非空、无控制字符）；② 协议原生键（**按协议白名单，MUST NOT 跨协议接受**）——仅 Chat 与 Responses 请求体的 `prompt_cache_key`（存在时）、仅 Responses 的 `previous_response_id` 经进程内响应 id→会话键映射解析（**该映射 SHALL 按租户指纹分域**：映射键 = `HMAC(secret, tenant_fingerprint || previous_response_id)`，故某租户铸造的 `previous_response_id` 在其他租户 MUST NOT 解析）；Anthropic MUST NOT 接受任一原生键，Chat MUST NOT 接受 `previous_response_id`（协议不匹配的原生字段 MUST NOT 命中第 2 级，按优先级继续下一级）；③ 稳定前缀 HMAC——对**脱敏前**规范化的 `tools + system + 首个 user turn 为止的前导 messages` 前缀做 HMAC；④ 回退请求级作用域。系统 SHALL NOT 使用 OpenAI `user` 字段作会话键（其为用户 id 而非会话 id，存在跨会话关联风险）。

推导 SHALL 为**条件性**：会话级稳定**当且仅当**第 1–3 级之一命中时成立——第 3 级要求请求同时具备 `tools` + `system` + 首个 user turn 三者，第 1/2 级依赖客户端配合（显式头 / `prompt_cache_key` / `previous_response_id`）。**纯多轮 `messages` 请求（无工具、无会话键头、无协议原生键）即便 `PII_SCOPE_MODE=conversation` SHALL 落第 4 级逐请求**，不获得跨轮 token 稳定，属预期降级（MUST NOT 报错或伪造键）。

第 3 级的 turn 锚点 SHALL 为**可确定**的前缀字段，且字段提取 SHALL 按协议白名单：Chat/Anthropic 取 `messages` 数组（system 提示取消息中 `system`/`developer` 首条，Anthropic MAY 另取顶层 `system`）、Responses 取**数组形** `input` 与 `instructions`。**标量（字符串）形 `input` MUST NOT 参与第 3 级**（其内容随轮次增长，无法作为稳定 turn 锚点）；协议外字段 MUST NOT 越界参与（Chat 请求体的 `instructions` MUST NOT 被当作 `system`，Responses 请求体的 `messages` MUST NOT 被当作首个 user turn）。Responses 标量 `input` 简写形态下第 3 级 SHALL 不可命中并落第 4 级逐请求，由既有 `record_request_fallback()` 计入观测，MUST NOT 报错。

会话键 SHALL 经 `HMAC(secret, tenant_fingerprint || conversation_id)` 派生。`tenant_fingerprint` SHALL 由**派生键之前即可得、且跨轮稳定**的信号派生（MUST NOT 事后回取「本请求命中的 vault 键集合」——vault 为全局明文→token 快照、按值匹配，不存在每请求「注入了哪个凭据」的选择点，事后预扫描会随轮次改变指纹而自败），口径固定：`tenant_fingerprint = HMAC(secret, 完整上游基址 || 分隔符 || 客户端凭据头归一化)`。

- **主判别项** SHALL 取**完整 `upstream_base`（含 path/query）**（`src/service/llm_gateway/mod.rs::resolve_upstream` 产物，由 `src/handler/llm/dispatch.rs::gateway_serve` 的入口调用取得）；**MUST NOT 仅用上游主机**——`resolve_upstream` 按入口端口选上游，端口经（可伪造的）Host 头解析，不同端口可共享同一主机，仅用主机会把不同租户折叠进同一命名空间。
- **可选次判别项** SHALL 取客户端 Authorization/api-key 请求头的 HMAC（请求头，键推导前可得、跨轮稳定）；启用时并入指纹。
- **分隔符** SHALL 为固定单一字面量，界定各分量的拼接边界。
- **零/多凭据归一化** SHALL 为确定性函数：对客户端提供的凭据头，零个归一为**固定字面量（空串分量，非示例）**，多个去重后按字节序排序、以固定子分隔符 join，再并入 HMAC；全程 MUST NOT 含凭据原文。

因 `tenant_fingerprint` 纳入**完整上游基址（含 path/query）**与归一化客户端凭据头，**切换上游基址或轮换客户端凭据** SHALL 改变租户命名空间，使此前铸造的会话键不可解析（表现为缓存失配/重新铸造，MUST NOT 报错）——会话级稳定仅在相同完整上游基址且相同凭据归一化下成立（已登记现实约束）。

客户端原始提供值 MUST NOT 直接作键。跨租户隔离 SHALL 由租户命名空间保证，但**仅为层内（in-layer）保证**：同一完整上游基址且客户端凭据头不可区分者 SHALL 落入同一命名空间（本层隔离不构成跨调用方保证；该残余限制显式登记于本要求与 `credential-vault-singleton` 的相关条款）。

第 3 级（稳定前缀）SHALL 为**确定性**推导：规范化 SHALL 对前缀 JSON 对象递归按键名升序排序、对 `tools` 数组按工具名稳定排序、其余数组保序；同一逻辑前缀的任意键序/工具序扰动 SHALL 归一到同一字节序列，**同输入恒得同键**。无法规范化（非 JSON 容器，或缺 `tools`/`system`/首个 user turn）时第 3 级 SHALL 不可命中并落第 4 级，MUST NOT 产生含糊键。第 3 级命中依赖 `tools` + `system` + 首个 user turn **三者内容跨轮冻结**：任一后续轮次改写该三者的**内容**（键序/工具序扰动已由规范化归一，不在此列）SHALL 改变稳定前缀并因而改变会话键（跨轮 token 稳定不成立，属已登记边界，MUST NOT 视为缺陷）。第 3 级的**规范化规则已定**（即上句的确定性函数，SHALL NOT 因测试补充而改变）；**多模态内容块等边界由 apply 期补测试**（`conversation_key_stable_prefix_deterministic` 锁定同输入恒同键与键序/工具序扰动不变），规则文本与本条一致、须与 `design.md` 同口径（MUST NOT 表述为「规则待定」）。

会话键头 SHALL 由网关消费：其名与值 MUST NOT 出现在转发上游的请求头或任一日志行。会话键头的剔除 SHALL 为**无条件**（独立于 `PII_SCOPE_MODE`；默认 `request` 模式下同样剔除），并 SHALL 覆盖**任意自定义头名**——`PII_SCOPE_KEY_HEADER` MAY 取非 `x-veil-*` 名称，其名与值仍 MUST NOT 转发上游或入日志。自定义/默认会话键头的剔除由 `src/handler/llm/dispatch.rs::strip_conversation_header` 在转发前对转发头执行；通用 `x-veil-*` 内部头剔除另由 `src/handler/llm/mod.rs::forward_headers`（经 `strip_veil_internal_headers`）承担，二者为不同剔除以覆盖不同命名空间。`previous_response_id` 映射的写入点 SHALL **仅限 `Protocol::Responses` 的响应完成处**（流式见 `src/handler/llm/pump/spawn/event_loop.rs` 的 `record_response_id` 调用点，非流见 `src/handler/llm/nonstream.rs` 的同名调用点；协议门控在 `src/service/redaction/conversation_key.rs::record_response_id`）；上述两处实现为协议无关（Chat 亦产出 `chatcmpl-*`、Anthropic 产出 `msg_*`），故写入 SHALL 先判 `Protocol::Responses`，**Chat/Anthropic 的响应 id MUST NOT 进入该映射**。上游 `response.id` SHALL **值级不变**（客户端下一轮 `previous_response_id` 可解析）：该 id 非 PII 匹配面，零替换帧逐字节透传、含新 PII 帧经 `loads→walk→dumps` 重序列化时其值仍不变——论断按值级成立，MUST NOT 表述为「字节级透传保证」。键推导 SHALL 为纯函数，MUST NOT 发起网络 I/O。

`PII_SCOPE_KEY_HEADER` SHALL 在启动期做**保留名校验**（fail-closed）：其取值 MUST NOT 与真实鉴权/传输头名冲突——大小写不敏感地命中 `authorization`、`x-api-key`、`api-key`、HOP 头集（`src/service/llm_gateway/hop.rs::HOP_HEADERS`，即 `connection`/`keep-alive`/`proxy-authenticate`/`proxy-authorization`/`te`/`trailer`/`transfer-encoding`/`upgrade`）、`host`、`content-length`、`content-encoding`、`accept-encoding` 之一时 SHALL 拒启动；除保留名外的任意自定义头名（含非 `x-veil-*` 前缀）SHALL 被接受。该校验与「无条件剔除」并存而非二选一：因会话键头的剔除为**无条件**（独立于 `PII_SCOPE_MODE`，见上段），若允许保留名作会话键头，默认 `request` 模式下亦会删除真实鉴权头转发上游而静默断链，故必须在启动期拦截；自定义名的安全性由**无条件剔除**保证——配置的会话键头在所有模式下均于转发前剥离，其名与值不入上游请求头与日志，故无需额外 allow-list。

缓存稳定性边界（已成立但 MUST NOT 作为稳定承诺的登记项）：(a) 第 3 级要求 `tools` + `system` + 首个 user turn 的内容跨轮冻结，改写其内容即换键；(b) `tenant_fingerprint` 纳入完整上游基址与归一化凭据头，切换上游/轮换凭据即换命名空间；(c) 占位符说明注入的**文案文本**（`PII_PLACEHOLDER_PROMPT_TEXT`）属发往上游的前缀字节，会话期间修改该配置（或切换注入开关）SHALL 改变后续轮次前缀字节，会话进行中应冻结该配置；(d) `src/service/json_walk.rs::SCAN_INPUT_LIMIT`（1 MiB）、`::CONTAINER_NEST_LIMIT`（128 层）、`::DEPTH_LIMIT`（5 层 stringified JSON）为回退阈值，超限正文回退 plain/原样处理，可能改变该请求的序列化形状——对超大/超深正文的字节稳定性不承诺。以上边界均不改变 token 还原正确性。

#### Scenario: 显式头优先

- **WHEN** 请求携带合法 `x-veil-conversation-id`
- **THEN** 以其（经租户命名空间 + HMAC）为键，忽略协议原生与稳定前缀来源

#### Scenario: prompt_cache_key 次之

- **WHEN** 无显式头且请求体含 `prompt_cache_key`
- **THEN** 以其为会话键来源（仍经租户命名空间 + HMAC）

#### Scenario: previous_response_id 解析

- **WHEN** 无显式头与 `prompt_cache_key`，Responses 请求携带 `previous_response_id`
- **THEN** 经进程内映射解析为既有会话键；未命中则继续下一优先级

#### Scenario: 原生键按协议白名单（正例 + 反例）

- **WHEN** Chat 请求体携带 `previous_response_id`，或 Anthropic 请求体携带 `prompt_cache_key`
- **THEN** 该原生字段 MUST NOT 命中第 2 级，按优先级继续下一级；仅 Chat/Responses 的 `prompt_cache_key` 与仅 Responses 的 `previous_response_id` 可命中

#### Scenario: 稳定前缀兜底（条件性命中）

- **WHEN** 前两级均不可用，且请求同时具备 `tools` + `system` + 首个 user turn
- **THEN** 以脱敏前 `tools + system + 首个 user turn` 前缀的 HMAC 为键；三者缺一即不命中第 3 级

#### Scenario: 第 3 级字段按协议白名单

- **WHEN** Chat 体携带 `instructions`，或 Responses 体携带 `messages`
- **THEN** 协议外字段 MUST NOT 参与第 3 级（Chat 的 `instructions` 不作 system，Responses 的 `messages` 不作首个 user turn）

#### Scenario: Responses 标量 input 不参与第 3 级

- **WHEN** Responses 请求为标量（字符串）`input` 且带 `instructions` 与 `tools`
- **THEN** 第 3 级不可命中（标量 `input` 不作 turn 锚点），落第 4 级逐请求，由 `record_request_fallback()` 计入观测，MUST NOT 报错

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

#### Scenario: 保留名会话键头拒启动

- **WHEN** `PII_SCOPE_KEY_HEADER` 取值为真实鉴权/传输头名（`authorization`/`x-api-key`/`api-key`/HOP 头集/`host`/`content-length`/`content-encoding`/`accept-encoding` 之一，大小写不敏感）
- **THEN** 启动期拒启动（fail-closed），错误信息指明与保留头名冲突（因剔除无条件，保留名会令 `request` 模式亦删真实鉴权头）；除保留名外的任意自定义名 SHALL 被接受，并在所有模式下由 `src/handler/llm/dispatch.rs::strip_conversation_header` 无条件剔除、不转发上游、不入日志

#### Scenario: 会话键头不转发不入日志

- **WHEN** 请求携带会话键头（`x-veil-*` 默认名或自定义非 `x-veil-` 名）
- **THEN** 头名/头值 MUST NOT 出现在转发上游的请求头或任一日志行；剔除为**无条件**（`request` 模式同样剔除），自定义头名亦由 `src/handler/llm/dispatch.rs::strip_conversation_header` 剔除，通用 `x-veil-*` 由 `src/handler/llm/mod.rs::forward_headers` 剔除

#### Scenario: 稳定前缀冻结边界

- **WHEN** 同一会话的后续轮次改写了首个 user turn、system 或 `tools` 的内容
- **THEN** 稳定前缀改变，会话键随之改变（跨轮 token 稳定不成立，属已登记边界，非缺陷）

#### Scenario: 上游/凭据轮换换命名空间

- **WHEN** 会话进行中切换完整上游基址或轮换客户端凭据头
- **THEN** `tenant_fingerprint` 改变，此前铸造的会话键不可解析（缓存失配/重新铸造，MUST NOT 报错）

#### Scenario: 配置文案变更破前缀字节

- **WHEN** 会话进行中修改 `PII_PLACEHOLDER_PROMPT_TEXT`（或切换注入开关）
- **THEN** 后续轮次发往上游的前缀字节改变（会话期间应冻结该配置；属已登记边界）

#### Scenario: 超大/超深正文回退

- **WHEN** 请求正文超过 1 MiB、裸容器嵌套超过 128 层或 stringified JSON 递归超过 5 层
- **THEN** `json_walk` 回退 plain/原样处理，该请求序列化形状可能改变（对超大/超深正文的字节稳定性不承诺；还原正确性不受影响）

### Requirement: 会话作用域存储有界与并发收敛

系统 SHALL 以进程内存 LRU + TTL 存储 `ConversationScopeStore` 承载会话作用域，键为会话键（HMAC 派生），并 SHALL 挂 `AppState`（`src/state.rs::AppState`，启动装配 `src/state.rs::try_new`）以跨请求共享。存储 SHALL 满足：会话数上限 `PII_SCOPE_MAX_CONVERSATIONS`（默认 1024）；单会话条目上限沿用既有 `PII_MAX_ENTRIES`（1000）；空闲 TTL `PII_SCOPE_TTL_SECS`（默认 1800 秒）。存储 SHALL 同时受**聚合上界**约束：单会话 `PiiScope` 含**两张表**——请求表与响应表，各自在 `>= PII_MAX_ENTRIES` 时由 `src/service/pii/scope.rs::PiiScope::register` LRU 淘汰，且两表使用**各自独立的序号空间**（各表内在用条目与序号一一对应；某表在用序号集覆盖 `1..=PII_MAX_ENTRIES` 时下一次分配返回饱和哨兵 `PII_MAX_ENTRIES + 1`，紧随的 LRU 淘汰释放空洞；数值相同的序号可同时存在于两表，`fuzzy` 还原仅查请求表故无跨表误解析），故条目总数 SHALL ≤ `PII_SCOPE_MAX_CONVERSATIONS` × `PII_MAX_ENTRIES` × 2（默认 1024 × 1000 × 2 = 2,048,000），单值长度受请求体上限（10MB）约束；`previous_response_id` 映射条目数 SHALL 受 `PII_PREV_ID_MAX_ENTRIES` 约束；该变量未设置时回退到 `PII_SCOPE_MAX_CONVERSATIONS` 的**生效值**（配置相关默认），以保证任意配置下零行为变化。get-or-insert SHALL 原子化并返回共享 `Arc<PiiScope>`，使同会话键的并发在途请求收敛到同一 token（同值复用经 `PiiScope` 内部 Mutex 原子执行）。淘汰策略 SHALL 确定性且可测。存储 SHALL 经 `lock_or_recover` 语义承载，锁中毒时 fail-closed（不静默降级为错误结果）。跨租户 LRU 干扰（客户端经第 1 级头铸造无限会话键挤出他租户条目）SHALL 仅致缓存失配/重新铸造，MUST NOT 影响正确性、MUST NOT 破坏跨租户隔离；该风险 SHALL 显式登记为**已接受风险**（本层不限速，隔离不变量优先）。

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

- **WHEN** 多会话注册值（会话数 ≤ 上限且单会话各表条目 ≤ 上限，各表可含饱和哨兵 `PII_MAX_ENTRIES + 1`）
- **THEN** 存储条目总数 ≤ `PII_SCOPE_MAX_CONVERSATIONS` × `PII_MAX_ENTRIES` × 2（请求表 + 响应表各 1000，默认 2,048,000），不无界增长

#### Scenario: 两表序号空间独立且聚合上界不变

- **WHEN** 单会话的请求表与响应表各自注册至并超过 `PII_MAX_ENTRIES`
- **THEN** 两表序号空间独立且**各表内**「一个在用条目 ↔ 一个序号」成立（饱和哨兵 `PII_MAX_ENTRIES + 1` 在单表内至多一个在用条目持有，LRU 淘汰释放空洞）；数值相同的序号跨表并存不构成同表重复；条目总数仍 ≤ `PII_SCOPE_MAX_CONVERSATIONS` × `PII_MAX_ENTRIES` × 2

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

本模式的隐私增量 SHALL 显式声明：启用 `conversation` 后明文在 TTL 窗口内常驻内存（相对「请求结束即销毁」属回归）；会话内关联可接受（上游 provider 本就关联同一上下文的轮次）；跨会话隔离 SHALL 保持。系统 SHALL NOT 承诺：provider 缓存命中率可测量的提升（命中率为上游计费指标，本地不测量，wont-measure 保持）、跨会话 token 稳定性、**Responses 标量 `input` 形态的会话级 token 稳定**（见「会话键分层推导与租户命名空间」）、**序号空间饱和后的 `fuzzy` 还原确定性**（见「并发 Scope 内 PII 隔离 + 全局凭据 LRU」）、凭据占位符稳定性、零明文常驻、网关重启后 token 稳定、键推导含糊时的任何行为。不可泄露约束 SHALL 覆盖**日志层**：会话键、头值、明文与 token MUST NOT 出现在任一日志行（含 `tracing` debug 级），强度与 `/_admin/metrics` 不泄露约束一致。

#### Scenario: 隐私增量显式登记

- **WHEN** 查阅本能力文档与 spec
- **THEN** 明文 TTL 常驻、会话内关联可接受、跨会话隔离保持均显式列出

#### Scenario: MUST NOT 承诺清单完备

- **WHEN** 检查对外承诺
- **THEN** 不含缓存命中率提升、跨会话 token 稳定、Responses 标量 `input` 形态的会话级稳定、序号空间饱和后的 `fuzzy` 还原确定性、凭据占位符稳定、零明文常驻、重启稳定、含糊键行为等承诺

#### Scenario: 未启用时不增加常驻

- **WHEN** `PII_SCOPE_MODE=request`（默认）
- **THEN** 不引入会话级明文常驻（与既有请求级销毁语义一致）

#### Scenario: 日志不泄露键/明文/token

- **WHEN** 在 `conversation` 模式下产生请求处理日志（含 debug 级）
- **THEN** 日志行不含会话键、头值、明文或 token 原值

#### Scenario: 标量 input 与饱和歧义不承诺

- **WHEN** 请求为 Responses 标量 `input` 简写形态，或请求/响应表序号空间饱和
- **THEN** 系统 SHALL NOT 承诺会话级 token 稳定或 `fuzzy` 还原确定性（分别落逐请求降级、按未知/不确定处理）
