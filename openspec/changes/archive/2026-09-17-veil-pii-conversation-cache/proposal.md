# veil-pii-conversation-cache

## Why

PII 脱敏当前是**逐网关请求**作用域：`Scope` 每请求构造（`src/handler/llm/dispatch.rs:160`），`PiiScope` 随请求销毁（`src/service/redaction/scope.rs:42-51`），token 形如 `__PII_<seq>_<rand8>__`，其中 `seq` 与 `rand8` 均为请求期生成（`src/service/pii/scope.rs:27-29`、`:165-167`）。`src/service/redaction/scope.rs:43` 明确「跨请求 MUST NOT 互见」。

后果：同一会话的每一轮都会重新铸造不同的 PII token，**发往上游的字节因此不同**，上游 prompt-cache 的字节级前缀必然失配。README §7.3（`README.md:706-713`）已把该差异登记为有意权衡（wont-measure）。与此同时，r3 安全修复 B3 把响应侧凭据还原收紧为请求级 minted-set 授权（`src/service/redaction/scope.rs:20-40`、`:420-446`；`src/service/credential_vault.rs:335-351`），该安全属性**必须保持不被削弱**。

用户要求：在**至少会话级**达到缓存友好（**当且仅当**会话键成功推导时成立，见下文四级优先级），同时不削弱 B3。本 change 仅交付提案与计划（artifacts-only），不修改 `src/**`；剩余审计发现由 `veil-audit-r4-remediation` 承载。

## What Changes

### 一、会话键推导（分层优先级，首个命中者胜）

1. 客户端显式头 `x-veil-conversation-id`（**长度有界：≤256 字节** + 合法性校验；**MUST** 经租户命名空间 + HMAC，原始值绝不作键；该头由网关消费，**MUST NOT** 转发上游或写入日志——默认头名位于 `x-veil-*` 内部命名空间，转发前由 `src/handler/llm/mod.rs:45-46` 统一剔除）；
2. 协议原生：Chat/Responses 的 `prompt_cache_key`；Responses 的 `previous_response_id` 经进程内响应 id→会话键映射解析，**该映射按租户指纹分域**（`previous_response_id` 跨租户 MUST NOT 解析）；
3. 稳定前缀 HMAC：对**脱敏前**规范化（对象键递归升序、`tools` 按工具名稳定排序、其余数组保序）的 `tools + system + 首个 user turn 为止的前导 messages` 前缀做 HMAC（跨轮稳定且**确定**：同输入恒同键、键序/工具序扰动不变）；
4. 回退：逐请求作用域（当前行为）。

**条件性声明（不得过度承诺）**：会话级缓存友好**当且仅当**会话键成功推导（命中第 1–3 级之一）时才成立；级别 1/2 依赖客户端配合（显式头 / `prompt_cache_key` / `previous_response_id`），级别 3 要求请求同时含 `tools` + `system` + 首个 user turn。故**纯多轮 `messages` 请求（无工具、无会话键头、无 `prompt_cache_key`/`previous_response_id`）即便 `PII_SCOPE_MODE=conversation` 亦落第 4 级逐请求**，不获得跨轮 token 稳定，属预期降级（不报错、不伪造键）。

**SHALL NOT** 使用 OpenAI `user` 字段作会话键（其为用户 id 而非会话 id，存在跨会话关联风险）。

### 二、会话作用域存储（`ConversationScopeStore`）

进程内 LRU + TTL 存储，键为 `HMAC(secret, tenant_fingerprint || conversation_id)`；`tenant_fingerprint` **派生口径固定为「键推导前即可得且跨轮稳定」的信号**（MUST NOT 事后回取「本请求命中的 vault 键集合」——vault 为全局明文→token 快照、按值匹配，不存在每请求「注入了哪个凭据」的选择点，事后预扫描会随轮次改变指纹而自败）：`tenant_fingerprint = HMAC(secret, 完整上游基址 || 分隔符 || 客户端凭据头归一化)`。**主判别项**取**完整 `upstream_base`（含 path/query）**（`resolve_upstream` 产物，`src/handler/llm/dispatch.rs:145`）——**MUST NOT 仅用上游主机**：`resolve_upstream` 按入口端口选上游，而端口经（可伪造的）Host 头解析，不同端口可共享同一主机，仅用主机会把不同租户折叠进同一命名空间。**可选次判别项**取客户端 Authorization/api-key 请求头的 HMAC（键推导前可得、跨轮稳定）。**分隔符**为固定单一字面量；**零/多凭据归一化**：对客户端提供的凭据头做确定性归一化——零个归一为空串分量（**固定字面量，非示例**），多个去重后按字节序排序、以固定子分隔符 join，再并入 HMAC；全程不含凭据原文。跨租户隔离是强制项，但**仅为层内（in-layer）保证**：同上游基址且客户端凭据头不可区分者落入同一命名空间（残余限制显式登记于 spec）。上限：会话数默认 `1024`（`PII_SCOPE_MAX_CONVERSATIONS`）；单会话条目沿用既有 `PII_MAX_ENTRIES`（1000，`src/service/pii/detector.rs:36`）；**聚合上界** = 会话数 × 单会话条目 × 2 张表（请求表 + 响应表，各自在 `>= PII_MAX_ENTRIES` 淘汰，`src/service/pii/scope.rs:169`、`:181`；默认 1024 × 1000 × 2 = 2,048,000），单值长度另受请求体上限（10MB）约束；空闲 TTL 默认 `1800s`（`PII_SCOPE_TTL_SECS`）。存储与 `previous_response_id` 映射挂 `AppState`（`src/state.rs:37-71`，启动装配 `src/state.rs:88-163`）以跨请求共享。原子 get-or-insert 返回共享 `Arc<PiiScope>`，使同会话并发在途请求收敛到**同一明文一个 token**（同值复用经 `PiiScope` 内部 Mutex 原子执行）。恶意键 churn（客户端滥用第 1 级头铸造无限会话键）仅致缓存失配/重新铸造（不损正确性与隔离），登记为**已接受风险**。淘汰/重启仅致缓存失配（重新铸造 token），已登记。

### 三、授权域不对称（B3 保持）

**PII → 会话级**：同一会话键内早期轮次铸造的 PII token 在后续轮次可还原（多轮正确性所需）。**凭据 → 保持请求级 B3 不变**：仅本请求脱敏实际产出的 token 可还原，未授权者按幻觉剥离。系统 MUST NOT 因 PII 会话级而放宽凭据授权域；凭据 token MUST NOT 进入会话级作用域。跨会话/跨请求的非本域 token 还原 SHALL 不可能。

### 四、隐私增量声明（不得隐藏）

启用 `conversation` 后明文在 TTL 窗口内常驻内存（相对「请求结束即销毁」属回归）；会话内关联可接受（上游 provider 本就关联同一上下文轮次）；跨会话隔离保持。

### 五、MUST NOT 承诺清单

不得承诺：provider 缓存命中率可测量的提升（命中率为上游计费指标，本地不可见真值，wont-measure 保持）、跨会话 token 稳定性、凭据占位符稳定性、零明文常驻、网关重启后 token 稳定、键推导含糊时的任何行为。

### 六、分阶段上线与回滚

`PII_SCOPE_MODE=request|conversation`（默认 `request` = 零行为变化，非 BREAKING）；`PII_SCOPE_TTL_SECS`（1800）；`PII_SCOPE_MAX_CONVERSATIONS`（1024）；`PII_SCOPE_KEY_HEADER`（`x-veil-conversation-id`）。四个 `PII_SCOPE_*` 变量 MUST 登记进 README §1 环境变量全表（README 声明「未列出的变量二进制不读取」，漏登记即静默不生效）。README/BREAKING 章节仅在默认值变更时才更新。

### 七、占位符说明注入位置

**保持头部注入**（`messages[0]` / `system` / `input|instructions`，`src/service/llm_gateway/placeholder.rs:138-188`、`:244-317`）——token 跨轮稳定后注入文本逐轮字节一致；移至尾部会改变提示语义并削弱指令遵循。新增验收测试断言同一会话两轮注入前缀字节一致。

### 八、上游 prompt cache 前缀保真（Q9）

脱敏 MUST NOT 丢弃/位移/改写客户端 `cache_control` 断点；`prompt_cache_key` / `metadata` 请求体字段 MUST 原样转发。新增断言：断点在改写后数量/位置/取值逐项存活（字节表示受既有已声明偏离约束）。

### 九、thinking 连续性（Q5，条件性收益）

会话级作用域使同明文同 token，是 Anthropic thinking `signature` 连续性的**必要条件**（非充分，MUST NOT 据此声称连续性已实现或已验证）；文档须列残余限制：无签名校验、淘汰、响应侧新 PII 占位符、其他 provider 的签名 thinking。本声明与 canonical `llm-protocol-hardening` 的 requirement「Anthropic 扩展思考签名连续性限制声明」**显式互引**（按 requirement 名互指，两处 MUST NOT 漂移）；该 canonical 要求为真相源。**跨 change 排序（已满足，2026-09-16）**：该 canonical 条款由 `veil-audit-r4-remediation` 引入并已随其归档晋升至 `openspec/specs/llm-protocol-hardening/spec.md`，故本互引**已生效**（预设条件已满足，不再有待生效标注）。

### 十、观测

新增 `/_admin/metrics` 只读项：作用域模式 + 会话复用/淘汰/回退计数；既有指标键不变；不泄露键/明文/token。该不泄露约束**同覆盖 `tracing` 日志层**——会话键/头值/明文/token MUST NOT 进入任一日志行。

## Capabilities

### New Capabilities

无（本 change 只修改既有 capability）。

### Modified Capabilities

- `redaction`: 新增会话级 PII 作用域与作用域模式开关、会话键分层推导与租户命名空间、`ConversationScopeStore` 有界与并发收敛、PII 会话级 / 凭据请求级授权域不对称、隐私增量与 MUST NOT 承诺清单；修订「并发 Scope 内 PII 隔离 + 全局凭据 LRU」与「Vault 稳态与 rand8 OsRng」以纳入会话模式（默认 `request` 行为不变）。
- `llm-gateway`: 新增上游 prompt cache 前缀保真（`cache_control` / `prompt_cache_key` / `metadata`）、占位符说明头部注入跨轮字节恒定、Anthropic thinking 连续性条件性收益与残余限制。
- `observability-admin`: 新增 PII 作用域模式与复用/淘汰计数只读观测。
- `credential-vault-singleton`: 将既有「请求级隔离为 PII 唯一映射模型」「SHALL NOT 持有全局 PII 注册表」两处条款**收窄为有界例外**——`PII_SCOPE_MODE=conversation` 显式启用且会话键推导成功时，允许**进程内、有界、租户+会话作用域、非持久**的 `ConversationScopeStore`（默认 `request` 行为逐项不变）；并登记 canonical Purpose 内部张力（`credential-vault-singleton:3` 仍称 PII 跨请求稳定）与对齐口径（apply/归档期手工对齐 canonical Purpose，因 delta Purpose 对既有 spec 不生效）。
- `docs-contract-resync`: 将「README §7.3 与 `src/service/metrics.rs:7-12` 同字、请求隔离为隐私硬要求」条款收窄为允许「默认请求级 + 有界、非持久会话级例外」的同字表述，要求两侧**同批锁步更新**（same wording），MUST NOT 单侧漂移。

## Non-goals

- 不做全局跨会话确定性（globally keyed-HMAC 稳定 token 非推荐终态，见 design 备选）。
- 不测量 provider 缓存命中率（wont-measure 保持）。
- 不做 Anthropic/其他 provider 的签名校验，不承诺 thinking 连续性已实现。
- 不把凭据作用域改为会话级（B3 请求级授权 SHALL 不变）。
- 不改变任何默认行为（`PII_SCOPE_MODE` 默认 `request`）。
- 不作为 BREAKING 变更；仅在默认值变更时才需 README/BREAKING 更新。
- 不新增 crate 依赖（`hmac`/`sha2` 已是直接依赖，见 `Cargo.toml:22-23`）。
