## ADDED Requirements

### Requirement: 上游 prompt cache 前缀保真

系统 SHALL 在脱敏改写中保留客户端提供的 `cache_control` 断点（MUST NOT 丢弃、位移或改写其内容），并 SHALL 原样转发 `prompt_cache_key` 与 `metadata` 请求体字段（MUST NOT 新增、删除或改写）。改写（含 json-aware 重序列化）后 `cache_control` 断点对象 SHALL 存活且语义等价；字节级表示可能因既有 JSON 重序列化规整而改变（既有已声明偏离），但断点数量、位置与取值 SHALL 不变。系统 SHALL NOT 自行注入客户端未提供的 `cache_control` 断点。

#### Scenario: cache_control 断点存活

- **WHEN** Chat/Anthropic 请求体在 `tools`/`system`/`messages` 内携带 `cache_control` 断点且请求发生脱敏替换
- **THEN** 改写后输出的 `cache_control` 断点数量、位置与取值逐项存活（语义等价；字节表示受既有已声明偏离约束）

#### Scenario: prompt_cache_key/metadata 透传

- **WHEN** 请求体含 `prompt_cache_key` 或 `metadata`
- **THEN** 改写后转发体保留原值，不新增、不删除、不改写

#### Scenario: 无 cache_control 不新增

- **WHEN** 请求体不含 `cache_control`
- **THEN** 系统 SHALL NOT 自行注入 `cache_control` 断点

#### Scenario: 非对话路径不受影响

- **WHEN** 请求为非对话尾透传路径
- **THEN** 该要求不改变既有字节透传语义（无改写、无字段增删）

### Requirement: 占位符说明头部注入跨轮字节恒定

占位符说明注入 SHALL 保持头部位置（Chat `messages[0]` / Anthropic `system` / Responses `input|instructions`），MUST NOT 改为尾部注入（尾部注入会改变提示语义并削弱指令遵循）。当 `PII_SCOPE_MODE=conversation` 且会话键稳定时，同一会话两轮的注入前缀 SHALL 字节一致（依赖 token 跨轮稳定 + 注入位置稳定）。既有幂等守卫（已含说明不重复前插，返回原字节）SHALL 不变。

#### Scenario: 头部注入位置不变

- **WHEN** 占位符说明被注入
- **THEN** 位置为头部（`messages[0]`/`system`/`input|instructions`），非尾部

#### Scenario: 会话内注入前缀字节一致

- **WHEN** 同一会话键的两轮请求含需注入的 token
- **THEN** 两轮注入前缀字节一致（逐字节相等）

#### Scenario: 幂等不重复前插

- **WHEN** 目标位置已含说明
- **THEN** 不再重复前插，返回原字节（既有幂等语义不变）

### Requirement: Anthropic thinking 签名连续性（条件性收益与残余限制）

会话级作用域使同一明文铸造同一 token，SHALL 被文档声明为 Anthropic thinking `signature` 连续性的**必要条件**（非充分条件），MUST NOT 声称签名连续性已实现或已验证。残余限制 SHALL 显式列出：无签名校验、会话条目淘汰、响应侧新 PII 仍产生新 token、其他 provider 的签名 thinking 不在范围内。本要求 SHALL 与 canonical `llm-protocol-hardening` 的 requirement「Anthropic 扩展思考签名连续性限制声明」**显式互引**（按 requirement 名互指，两处 MUST NOT 漂移）；该 canonical 要求为真相源，本处声明 MUST NOT 与其漂移。**跨 change 排序（已满足，2026-09-16）**：该条款由 `veil-audit-r4-remediation` 引入并已随其归档晋升 canonical（`openspec/specs/llm-protocol-hardening/spec.md` 现存该 requirement），故本互引**已生效**（预设条件已由 r4 归档满足，无需再等待）。

#### Scenario: 声明为必要条件

- **WHEN** 查阅 thinking 连续性文档
- **THEN** 会话级 token 稳定被声明为必要条件而非充分条件，且无实现/验证声明

#### Scenario: 残余限制登记

- **WHEN** 检查残余限制清单
- **THEN** 含无签名校验、淘汰、响应侧新 PII、其他 provider 四项

#### Scenario: 与 canonical llm-protocol-hardening 互引不漂移

- **WHEN** 对照本要求与 canonical `llm-protocol-hardening` 的「Anthropic 扩展思考签名连续性限制声明」
- **THEN** 两处均声明「必要条件非充分」「不校验签名」「不承诺无条件连续」，措辞互引且无冲突

#### Scenario: 跨 change 排序：r4 已归档、互引已生效

- **WHEN** 检查互引成立条件（`veil-audit-r4-remediation` 已于 2026-09-16 归档）
- **THEN** canonical `llm-protocol-hardening` 含 requirement「Anthropic 扩展思考签名连续性限制声明」，本互引标注为已生效，以该 canonical requirement（按 requirement 名互指）为真相源

#### Scenario: 不改变请求体语义

- **WHEN** 启用 `conversation` 模式处理含 thinking 的请求
- **THEN** 请求体除既有占位符替换与说明注入外，语义不变
