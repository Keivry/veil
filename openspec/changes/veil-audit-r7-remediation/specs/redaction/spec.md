# Spec Delta

## MODIFIED Requirements

### Requirement: json-aware 语义等价改写（FIX-5 权威定义）

脱敏改写 SHALL 为 json-aware（`R7-02`）：JSON 字符串值位与**对象键位** SHALL 同 leaf 口径参与脱敏替换（键位与值位语义等价），结构、数字与布尔类型 SHALL NOT 改变；未命中的键名 SHALL 保持原样。对象键位替换 SHALL 以**原始键集合**做碰撞回退：替换后的键若与任一原始键或已选键同名，SHALL 保留原键，SHALL NOT 合并成员或丢键；键位 SHALL 按**纯字符串 leaf** 处理（MUST NOT 对键串做 stringified-JSON 递归展开），键串内嵌的敏感子串 SHALL 仍被子串扫描覆盖；本身即内部 token 形态/保留前缀的键 SHALL 按注册侧 token 形态守卫跳过并原样保留。键位替换 SHALL 与值位替换同口径置位 `x-veil-normalized`（实际重序列化时）。默认 SHALL 仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`。改写前后 JSON 语义 SHALL 等价（除占位符替换外）。同一明文跨多个 JSON 深度出现时，转义 SHALL 按各 span 实际所在深度逐出现点判定，MUST NOT 以该明文的全局最大深度统一聚合转义；深度分析 SHALL 计入对象 key（键名所在深度），使深键位与浅值位的转义互不误伤。响应侧新 PII 掩码 SHALL 与请求侧同口径覆盖键位；响应侧还原沿用全文扫描（键位无需新增还原路径）。

#### Scenario: 结构与类型不变

- **WHEN** 请求体为 JSON 且含需脱敏的字符串值或键名
- **THEN** 改写后层级、非字符串类型均不变；未命中的键名原样保留，命中的键名与目标值变为占位符/掩码

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

#### Scenario: 键位 PII 被脱敏

- **WHEN** 请求体为 `{"13800138000":"x"}` 且该号码命中 PII 规则
- **THEN** 键位替换为占位符/掩码，值 `"x"` 不变，输出仍可解析为合法 JSON

#### Scenario: 键位碰撞回退

- **WHEN** 键位脱敏后的键与请求中既有的原始键（或已选定的替换键）同名
- **THEN** 该键位保留原键，两个成员均存在，SHALL NOT 合并成员或丢键

#### Scenario: 键串内嵌敏感子串扫描

- **WHEN** 键名本身是含敏感子串的字符串（如以 JSON 文本形态承载的值）
- **THEN** 键串按纯字符串 leaf 做子串扫描替换（不做 stringified-JSON 递归展开），输出仍可解析

#### Scenario: token 形态键原样保留

- **WHEN** 键名本身即内部 token 形态/保留前缀（如 `__PII_*`/`__VG_CRED_*`）
- **THEN** 该键跳过替换、原样保留，不触发注册失败

#### Scenario: 响应侧键位掩码同口径

- **WHEN** 响应侧新 PII 命中出现在对象键位
- **THEN** 键位与值位同口径掩码；还原侧全文扫描覆盖键位，无需新增还原路径

## ADDED Requirements

### Requirement: 稳定前缀 `system` 提取与协议原生键的协议门控

稳定前缀（会话键第 3 级）的 system 来源提取 SHALL 按协议白名单（`R7-04`）：**Chat SHALL NOT 读取顶层 `system`**，SHALL 仅从 `messages` 首条 `system`/`developer` 提取；Anthropic MAY 取**原生顶层 `system`**（存在且非 null 时优先）或 `messages` 首条 `system`/`developer`；Responses SHALL 仅取 `instructions`（既有语义不变）。请求体同时携带顶层 `system` 与 `messages` 时，Chat 的稳定前缀提取结果 SHALL NOT 受顶层 `system` 影响（与会话体省略该字段时同键）。

会话键第 2 级的协议原生键白名单 SHALL 沿用「会话键分层推导与租户命名空间」既有 requirement（`Anthropic MUST NOT 接受任一原生键`、`Chat MUST NOT 接受 previous_response_id`），本 requirement SHALL NOT 重复定义该白名单；本节新增收敛仅限可观测口径（`R7-08`）：协议不匹配的原生字段 SHALL 被**静默忽略**——SHALL NOT 命中第 2 级、SHALL NOT 改变第 3/4 级推导结果、SHALL NOT 告警、SHALL NOT 计数。**就第 2 级协议原生键白名单而言**，任何协议在本 change 前后的派生会话键 SHALL 逐位一致（白名单判定结果不变）；第 3 级因 R7-04 的 `system` 门控产生的变化不在此不变量范围。README §7.3 SHALL 与本节口径同字（Anthropic 取原生顶层 `system` 或 `messages` 首条；Chat 仅 `messages`；Responses 取 `instructions`；协议外原生键静默忽略）。

#### Scenario: Chat 顶层 system 不参与

- **WHEN** Chat 请求含顶层 `system`、`tools` 与仅含 user 的 `messages`
- **THEN** 第 3 级不命中（落第 4 级逐请求），且与省略顶层 `system` 时同键；仅当 `messages` 首条为 `system`/`developer` 时才命中

#### Scenario: Anthropic 原生 system 可命中

- **WHEN** Anthropic 请求含顶层 `system`、`tools` 与首个 user turn
- **THEN** 第 3 级命中，稳定前缀使用原生 `system` 内容

#### Scenario: 协议外原生键静默忽略

- **WHEN** Anthropic 请求体携带 `prompt_cache_key`（或 Chat 请求体携带 `previous_response_id`）且无显式会话键头
- **THEN** 该字段不命中第 2 级、不告警、不计数，按第 3/4 级继续推导

#### Scenario: README §7.3 同口径

- **WHEN** 核查 README §7.3 的稳定前缀与协议原生键段
- **THEN** 与实现一致声明「Anthropic 取原生顶层 `system` 或 `messages` 首条；Chat 仅 `messages`；Responses 取 `instructions`」与「协议外原生键静默忽略」
