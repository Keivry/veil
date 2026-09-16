# Design — veil-pii-conversation-cache

## Context

PII 脱敏为逐网关请求作用域：`Scope::with_opts` 每请求构造（`src/handler/llm/dispatch.rs:160`），`PiiScope` 随请求销毁（`src/service/redaction/scope.rs:42-51`）。PII token 为 `__PII_<seq>_<rand8>__`，`seq` 来自请求期分配游标、`rand8` 为请求期 CSPRNG（`src/service/pii/scope.rs:27-29`、`:79-88`、`:165-167`）。`src/service/redaction/scope.rs:43` 声明「跨请求 MUST NOT 互见」。

因此同一会话每轮重新铸造 token，上游字节随之变化，prompt-cache 前缀失配；README §7.3（`README.md:706-713`）把该差异登记为有意权衡（命中率 wont-measure）。与之正交的 B3（r3 安全修复）把响应侧凭据还原收紧为请求级 minted-set 授权（`src/service/redaction/scope.rs:20-40`、`:420-446`；`src/service/credential_vault.rs:335-351`），必须在本次改造中保持。

凭据 token `__VG_CRED_%06d__` 为进程全局稳定（`src/service/credential_vault.rs:32`、`:238`），本身已缓存友好；但 B3 使还原授权为请求级，`make_cred_token` 形态与全局映射语义均不变。

决策来源：Q1/Q5/Q9 三组 oracle 裁决（见「Decisions」）。设计原则沿用仓库既有哲学：spec 即真相源；接受的偏离必须显式声明并锁测试；fail-closed 优先；不引入新依赖；默认值即现行为、非 BREAKING。

## Goals

1. 使 PII 脱敏**在会话键成功推导时**达到会话级缓存友好（**当且仅当**命中第 1–3 级之一；第 3 级要求 `tools`+`system`+首个 user turn 齐备，第 1/2 级依赖客户端配合）：同一会话键内同一明文跨轮铸造同一 token。纯多轮 `messages`（无工具、无会话键头、无协议原生键）在 `conversation` 模式仍落第 4 级逐请求，不获得跨轮稳定（预期降级，非缺陷）。
2. 保持 B3 授权域不变：凭据仍为请求级 minted-set 授权，未授权 token 按幻觉剥离。
3. 隐私与安全边界显式声明：租户命名空间 + HMAC、跨会话隔离、隐私增量、MUST NOT 承诺清单齐全。
4. 分阶段上线：默认 `request` 零行为变化，可经 env 开关启用与回滚。
5. 端到端可验证：会话键稳定性、注入前缀字节恒定、`cache_control` 存活、观测计数均有可执行验收。

## Non-Goals

- 全局跨会话确定性 token（非推荐终态，见备选与否决理由）。
- provider 缓存命中率测量（wont-measure 保持）。
- Anthropic/其他 provider 签名校验；不承诺 thinking 连续性已实现。
- 凭据作用域会话级化（B3 请求级授权 SHALL 不变）。
- 任何默认行为变更；本 change 非 BREAKING。
- 新增 crate 依赖（`hmac`/`sha2` 已在 `Cargo.toml:22-23`）。

## Decisions

### D1 · 会话键分层推导与优先级（Q1）

**决策**：按以下优先级，**首个可命中者胜**：

| 优先级 | 来源 | 约束 |
|:--|:--|:--|
| 1 | 客户端显式头 `PII_SCOPE_KEY_HEADER`（默认 `x-veil-conversation-id`） | **≤256 字节** + 合法性校验；**MUST** 命名空间 + HMAC，原始值绝不直接作键；头名/值 MUST NOT 转发上游或入日志（默认头名属 `x-veil-*` 内部命名空间，转发前由 `src/handler/llm/mod.rs:45-46` 剔除） |
| 2 | 协议原生：Chat/Responses `prompt_cache_key`；Responses `previous_response_id` 经进程内响应 id→会话键映射 | `previous_response_id` 未命中则继续下一级；**映射按租户指纹分域**（`previous_response_id` 跨租户 MUST NOT 解析）；写入点为 Responses 响应完成处（`src/handler/llm/pump/spawn/event_loop.rs:205-210`；非流 `src/handler/llm/nonstream.rs:205-213`），读点为请求推导 |
| 3 | 稳定前缀 HMAC：脱敏前**规范化**的 `tools + system + 首个 user turn 为止的前导 messages` | 跨轮稳定（不含后续消息）；对**脱敏前**原文计算；规范化为**确定性函数**：对象键递归升序、`tools` 按工具名稳定排序、其余数组保序 → 同输入恒同键（键序/工具序扰动不变） |
| 4 | 回退逐请求作用域（当前行为） | 缓存失配，不报错、不伪造键 |

**MUST NOT** 使用 OpenAI `user` 作会话键：`user` 是用户 id 而非会话 id，跨会话聚合会引入关联风险。

**理由**：显式头是最可控来源；协议原生键直接对齐 provider 缓存语义；稳定前缀在不依赖客户端配合时仍可跨轮稳定；回退保证不可推导时行为不变。

**锚点**：请求体解析点 `src/handler/llm/dispatch.rs:196-204`；改写入口 `src/handler/llm/rewrite.rs:32-58`；对话标识提取 `src/service/llm_gateway/tool.rs:709`（`extract_conv_id`）；响应 id **捕获/写入点** `src/handler/llm/pump/spawn/event_loop.rs:205-210`（流式）与非流 `src/handler/llm/nonstream.rs:205-213`。**值级不变论证（非字节级透传）**：上游 `response.id` 的**值**在响应侧还原中不变——`response.id` 非 PII 匹配面（非 PII 形态，`json_walk` 仅替换字符串值语义），故它是客户端下一轮 `previous_response_id` 得以解析的前提。零替换帧（README §7.7 H1）逐字节透传，其值显然不变；**含新 PII 的帧**走 `loads→walk→dumps` 重序列化（键序保持原序、空白/数字表示可能规整），但 `id` 值仍不变。论断按**值级不变**成立，MUST NOT 表述为「由零替换帧字节透传语义保证、其值恒不变」（H1 以零替换为前提，不覆盖含新 PII 帧）。**协议门控**：写入点实现为协议无关，SHALL 先判 `Protocol::Responses`；Chat（`chatcmpl-*`）/Anthropic（`msg_*`）的 id MUST NOT 进入映射（见 spec 与任务 1.4 的负向断言）。

**回滚**：回退层即现行为，移除 1-3 级即回到逐请求作用域。

### D2 · 租户命名空间与 HMAC

**决策**：会话键 = `HMAC(secret, tenant_fingerprint || conversation_id)`。`tenant_fingerprint` SHALL 由**派生键之前即可得、且跨轮稳定**的信号派生（MUST NOT 事后回取「本请求命中的 vault 键集合」：vault 为全局明文→token 快照、按值匹配，`src/service/credential_vault.rs:64-101`、`src/service/redaction/scope.rs:107`，不存在每请求「注入了哪个凭据」的选择点；事后预扫描须先于 `src/handler/llm/dispatch.rs:160` 的作用域选择运行，且会随轮次改变指纹而自败，多凭据/零凭据下亦无定义）。口径固定：`tenant_fingerprint = HMAC(secret, 完整上游基址 || 分隔符 || 客户端凭据头归一化)`：

- **主判别项**：**完整 `upstream_base`（含 path/query）**（`resolve_upstream` 产物，取自 `src/handler/llm/dispatch.rs:145`）——配置派生、键推导前可得、跨轮稳定。**MUST NOT 仅用上游主机**：`resolve_upstream`（`src/service/llm_gateway/mod.rs:107-129`）按入口端口选上游，而端口来自（可伪造的）Host 头，不同端口可共享同一主机，仅用主机会令不同租户折叠进同一命名空间。
- **可选次判别项**：客户端 Authorization/api-key 请求头的 HMAC（请求头，键推导前可得、跨轮稳定）；启用时并入指纹，提高对「同基址多调用方」的区分度。
- **分隔符**：固定单一字面量（界定各分量拼接边界，避免歧义）。
- **零/多凭据归一化**：对**客户端提供的**凭据头做确定性归一化——零个归一为固定字面量（空串分量，非示例）；多个去重后按字节序排序、以固定子分隔符 join 再 HMAC；全程不含凭据原文。

**残余限制（层内保证，非跨调用方保证）**：同一完整上游基址且客户端凭据头不可区分者落入**同一**租户命名空间；会话键隔离是**层内（in-layer）**保证，MUST NOT 被理解为跨调用方保证。跨租户隔离仍为强制项：不同完整上游基址或可区分凭据头即使提交相同客户端会话 id 亦互不可见。`previous_response_id` → 会话键映射的键亦须嵌入 `tenant_fingerprint`，杜绝跨租户解析。

**理由**：HMAC 使进程内键不可由客户端预测/枚举；租户命名空间阻止跨租户碰撞与越权复用。`hmac`/`sha2` 已是直接依赖，零新依赖。

**实现口径**：复用既有 HMAC-SHA256 用法模式（`src/service/metrics/sample.rs:250-253`）。

**回滚**：不适用（随模式开关整体回滚）。

### D3 · `ConversationScopeStore` 结构（LRU + TTL + 上限 + 并发收敛）

**决策**：进程内存存储，键为 D2 派生键，值为共享 `Arc<PiiScope>`：

- 位置：`ConversationScopeStore` 与 `previous_response_id` → 会话键映射挂 `AppState`（`src/state.rs:37-71`，启动装配 `src/state.rs:88-163`），跨请求共享；`PII_SCOPE_MODE=request` 时不构造/不使用。
- 容量：会话数上限 `PII_SCOPE_MAX_CONVERSATIONS`（默认 1024）；单会话条目上限沿用 `PII_MAX_ENTRIES`（1000，`src/service/pii/detector.rs:36`）。
- **聚合上界**：会话数 × 单会话条目 × 2 张表（请求表 + 响应表，各自在 `>= PII_MAX_ENTRIES` 淘汰，`src/service/pii/scope.rs:169`、`:181`；默认 1024 × 1000 × 2 = 2,048,000 条），单值长度另受请求体上限（10MB）约束；`previous_response_id` 映射条目数同受会话数上限约束。
- 时间：空闲 TTL `PII_SCOPE_TTL_SECS`（默认 1800s）。
- 并发：get-or-insert **原子化**并返回 `Arc<PiiScope>`；同会话并发在途请求收敛到**同一明文一个 token**（同值复用由 `PiiScope` 内部 Mutex 原子保证，见 `src/service/pii/scope.rs:142-194`）。
- 淘汰：LRU / 到期，确定性且可测；淘汰/重启仅致缓存失配（重新铸造 token）。
- 跨租户 LRU 干扰：客户端经第 1 级头铸造无限会话键可挤出他租户条目，**仅致缓存失配/重新铸造**（未知 token 按既有语义原样保留/剥离），**不影响正确性与跨租户隔离**；登记为**已接受风险**（本层不限速；理由：隔离不变量优先，churn 的可用性代价由 LRU/TTL 与观测计数吸收）。
- 锁恢复：沿用 `lock_or_recover`（`src/service/lock_recover.rs:26`），锁中毒 fail-closed，不静默降级为错误结果。

**理由**：`Arc` 共享使并发请求看到同一映射；有界容量防无界增长；TTL 限定明文常驻窗口。

**回滚**：`PII_SCOPE_MODE=request` 时不构造/不使用该存储。

### D4 · 授权域不对称：PII 会话级 vs 凭据请求级（B3 保持）

**决策**：

- **PII → 会话级**：会话键内早期轮次铸造的 PII token 在后续轮次可还原（多轮正确性所需）。
- **凭据 → 请求级（B3 不变）**：响应侧凭据还原仅授权本请求 minted-set（`src/service/redaction/scope.rs:20-40`、`:154-167`、`:420-446`；`src/service/credential_vault.rs:335-351`）。未授权凭据 token 按幻觉剥离。
- **MUST NOT** 因 PII 会话级而放宽凭据授权域；凭据 token MUST NOT 进入会话级作用域。
- 非本会话/非本请求铸造的 token 还原 SHALL 不可能。

**理由**：B3 修补的是「跨请求凭据明文泄露」；会话化 PII 是为多轮正确性与缓存友好，与凭据授权域正交，不得混同。

**回滚**：凭据侧代码不动。

### D5 · 隐私增量声明

**决策**：显式登记——启用 `conversation` 后明文在 TTL 窗口内常驻内存（相对「请求结束即销毁」属回归）；会话内关联可接受（上游 provider 本就关联同一上下文轮次）；跨会话隔离保持。会话键/头值/明文/token MUST NOT 进入任一日志行（含 `tracing` debug 级）。

**理由**：把「接受的风险」写进 spec/README，避免静默偏离。

### D6 · MUST NOT 承诺清单

**决策**：对外承诺**不含**：provider 缓存命中率可测量的提升、跨会话 token 稳定性、凭据占位符稳定性、零明文常驻、网关重启后 token 稳定、键推导含糊时的任何行为。命中率 wont-measure 保持（`README.md:706-713`）。

**理由**：命中率是上游计费指标，网关侧不可见真值；过度承诺会制造不可验证的契约。

### D7 · env 开关与回滚

**决策**：`PII_SCOPE_MODE=request|conversation`（默认 `request`）；`PII_SCOPE_TTL_SECS`（默认 1800）；`PII_SCOPE_MAX_CONVERSATIONS`（默认 1024）；`PII_SCOPE_KEY_HEADER`（默认 `x-veil-conversation-id`）。非法值拒启动（fail-closed，不静默回退）。字段落在 `Config`（`src/config/env_parse.rs:171-239`，脱敏相关字段区 `:199-205`）。README/BREAKING 仅在默认值变更时才更新——本 change 非 BREAKING。

**理由**：默认即现行为，运维可灰度启用与即时回滚。

### D8 · 失败模式

**决策**：

- 键推导含糊/全级不可用 → 回退逐请求作用域（缓存失配），不报错、不伪造键。
- 会话条目淘汰/进程重启 → 重新铸造 token；响应侧未知 token 按既有语义原样保留/剥离，正确性不受影响。
- 存储锁中毒 → `lock_or_recover` fail-closed。
- 会话数/条目超限 → LRU 淘汰，仅致失配。

### D9 · 占位符说明注入位置保持头部

**决策**：**保持头部注入**（Chat `messages[0]` / Anthropic `system` / Responses `input|instructions`，`src/service/llm_gateway/placeholder.rs:138-188`、`:244-317`）。token 跨轮稳定后注入文本逐轮字节一致；移至尾部会改变提示语义、削弱指令遵循。新增验收测试：同一会话两轮的注入前缀**字节一致**。

**理由**：缓存前缀保真依赖「首部稳定」；位置稳定与 token 稳定共同构成必要条件。

### D10 · 上游 prompt cache 前缀保真（Q9）

**决策**：脱敏 MUST NOT 丢弃/位移/改写客户端 `cache_control` 断点；`prompt_cache_key` / `metadata` MUST 原样转发（不增删改）。改写后断点语义/取值/数量/位置不变；字节级规整属既有已声明偏离。**SHALL NOT** 自行注入客户端未提供的 `cache_control`。

**理由**：`json_walk` 仅替换字符串值语义（`src/service/json_walk.rs:137`），断点对象应存活；须显式测试锁定，防未来重序列化误删。字段透传经改写链：`src/handler/llm/rewrite.rs:32-58`（`redact_request_with_report`）与 `src/service/redaction/scope.rs:101-131`。

### D11 · Anthropic thinking 连续性（Q5，条件性收益）

**决策**：会话级 token 稳定是 thinking `signature` 连续性的**必要条件**（非充分），文档声明，**不**声称已实现/已验证。残余限制显式列出：无签名校验、会话条目淘汰、响应侧新 PII 仍产生新 token、其他 provider 的签名 thinking 不在范围内。本声明与 canonical `llm-protocol-hardening` 的 requirement「Anthropic 扩展思考签名连续性限制声明」**显式互引**（按 requirement 名互指）；该 canonical 要求为真相源，本处 MUST NOT 与其漂移。**跨 change 排序（已满足，2026-09-16）**：该条款由 `veil-audit-r4-remediation` 引入并已随其归档晋升 canonical（`openspec/specs/llm-protocol-hardening/spec.md` 现存该 requirement），故该互引**已生效**，canonical 为真相源。

**理由**：token 稳定解决了「同一明文同 token」这一已知阻塞项，但签名校验/淘汰/响应侧新 PII 等仍会打断；诚实收窄声明。

### D12 · 观测计数

**决策**：`/_admin/metrics` 新增只读项——当前作用域模式 + 会话复用/淘汰/回退计数；沿用 `GatewayMetrics` / `KeyedCounters` 固定键原子风格（`src/service/llm_gateway/metrics.rs:9-51`、`:66-105`），快照装配点 `src/handler/admin.rs:110-148`。既有指标键不变；缺失/锁不可用降级为 `0`；不暴露键/明文/token。该「不暴露」约束**同覆盖 `tracing` 日志层**：会话键/头值/明文/token MUST NOT 出现在任一日志行（含 debug 级）。

**理由**：模式切换与淘汰行为须可观测；与既有指标只加不改。

## 显式列出的备选与否决理由

### A1 · 全局 keyed-HMAC 稳定 token（**否决为终态**）

方案：对明文做全局 keyed-HMAC 生成跨请求稳定 token。否决理由：跨会话可关联 + 跨租户还原泄露风险；若坚持须配 per-tenant secret 与 per-tenant store——本 change **登记为非目标**，不作为推荐终态。

### A2 · OpenAI `user` 作会话键（**否决**）

方案：直接以 `user` 作会话键。否决理由：`user` 是用户 id 而非会话 id，会把同一用户的多个会话聚合成一个作用域，引入跨会话关联与还原越权面。

### A3 · 尾部注入占位符说明（**否决**）

方案：把说明注入到 messages 尾部/末尾以便「前缀不含变量」。否决理由：改变提示语义、削弱指令遵循；头部注入在 token 稳定后已逐轮字节一致，无需牺牲语义。

### A4 · 凭据作用域会话级化（**否决**）

方案：把凭据 token 也提升为会话级以兼顾缓存。否决理由：直接削弱 B3（跨请求凭据明文泄露）。凭据保持请求级；凭据 token 形态 `%06d` 本身已全局稳定，缓存收益有限而安全代价高。

### A5 · 会话键直接用客户端原始值（**否决**）

方案：直接以 `x-veil-conversation-id` 原始字符串作键。否决理由：可被枚举/碰撞，且无租户隔离。改为 HMAC + 租户命名空间。

### A6 · 依赖 provider 端不返回签名/不校验（**不采纳为承诺**）

思考连续性不做校验、不承诺，仅作条件性收益声明（D11）。

## 影响与门禁

- **代码改动面（apply 期）**：`src/config/env_parse.rs`（4 字段 + 校验）、`src/service/redaction/`（会话作用域接线 + 存储 + 键推导）、`src/state.rs`（`AppState` 新增 `ConversationScopeStore` 与 `previous_response_id` 映射字段 + 启动装配）、`src/handler/llm/dispatch.rs`（作用域选择接线）、`src/handler/llm/rewrite.rs`（键推导接线）、`src/handler/llm/mod.rs`（会话键头读取与转发剔除）、`src/handler/llm/pump/spawn/event_loop.rs` + `src/handler/llm/nonstream.rs`（响应 id 捕获写入）、`src/service/llm_gateway/metrics.rs` + `src/handler/admin.rs`（观测）、`README.md` §1 环境变量表（4 个 `PII_SCOPE_*` 行）+ §7.3 增补说明（不新增 BREAKING）、**`src/service/metrics.rs` 模块文档（`:7-12`）与 README §7.3 同批锁步更新**（`docs-contract-resync` 要求 same wording，见任务 6.1/6.3）。
- **门禁**：沿用 `scripts/gate.sh` 七步（fmt / clippy `-D warnings` / tests / `check_doc_paths.py` / `check_file_sizes.py` / 真 SDK conformance / go vet+test）；本 change 为 artifacts-only，apply 后须全绿。
- **新增测试**：会话键稳定性、会话键稳定前缀**确定性**（同输入恒同键、键序/工具序扰动不变）、租户指纹零凭据归一仍定义、`previous_response_id` 跨租户不解析、响应 id **值级不变**、协议门控（仅 `Protocol::Responses` 写入，Chat/Anthropic id 不入映射）、同会话并发收敛、会话数/TTL 淘汰、聚合上界（×2 表）与恶意键 churn 仅致失配、会话键头超长拒绝、跨会话不可还原、B3 凭据请求级不变、注入前缀跨轮字节一致、`cache_control` 存活、`prompt_cache_key`/`metadata` 透传、模式/计数观测、日志层不泄露键/明文/token。
- **默认行为**：`request` 模式零行为变化；非 BREAKING。

## 可选后续（本 change 范围外，仅登记）

1. 全局 keyed-HMAC 稳定 token 的 per-tenant secret + per-tenant store 方案（若未来确需跨会话稳定，须另立 change 并评估关联风险）。
2. 会话键推导第 3 级的「规范化前缀」：**规则已定**（确定性函数——键递归升序、`tools` 按名稳定排序、其余数组保序；无法规范化的输入（非 JSON 容器/缺 `tools`/`system`/首 user turn）跳过第 3 级落第 4 级，不产生含糊键）；**多模态内容块边界在 apply 期补测试**（以 `conversation_key_stable_prefix_deterministic` 锁定同输入恒同键与扰动不变），规则文本不因补测试而改变。
3. provider 缓存命中率的可观测代理指标（如上游响应中的 cached token 列）已由 `cached_read`/`cached_write` 现有列承载，本 change 不新增承诺。
