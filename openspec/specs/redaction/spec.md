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

### Requirement: 6 recognizer + 联合正则 + 中文边界

系统 SHALL 内置 6 recognizer：手机号、身份证、银行卡、邮箱、IP 地址、API 密钥；6 recognizer SHALL 联合为单一联合正则一次扫描；中文与 CJK 边界 SHALL 用 lookaround 表达，MUST NOT 用 `\b`（`\b` 对 CJK 无效）；含 `\b` 的自定义正则 SHALL 拒绝加载。

#### Scenario: 六类命中
- **WHEN** 正文含上述六类之一
- **THEN** 联合正则一次扫描即命中对应 recognizer

#### Scenario: \b 正则拒绝加载
- **WHEN** 自定义正则含 `\b`
- **THEN** 系统拒绝加载并报错

#### Scenario: CJK 边界正确
- **WHEN** 敏感值紧贴中文字符
- **THEN** lookaround 边界正确判定，不误报不断句

### Requirement: Luhn 与 GB 校验位 + 保留豁免清单

银行卡 SHALL 过 Luhn 校验，身份证 SHALL 过 GB 校验位；未过校验 SHALL NOT 替换；保留豁免清单（含示例号码、文档占位值、测试号段）命中的 SHALL 豁免不替换。

#### Scenario: 校验位拦截误报
- **WHEN** 数字串形似卡号但 Luhn / GB 校验失败
- **THEN** 系统不替换

#### Scenario: 豁免清单放行
- **WHEN** 命中值在保留豁免清单内
- **THEN** 系统不替换

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

脱敏改写 SHALL 为 json-aware：仅替换 JSON 字符串值语义，不改变键名、结构、数字与布尔类型；默认 SHALL 仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`。改写前后 JSON 语义 SHALL 等价（除占位符替换外）。

#### Scenario: 结构与类型不变
- **WHEN** 请求体为 JSON 且含需脱敏的字符串值
- **THEN** 改写后键名、层级、非字符串类型均不变，仅目标值变为占位符

#### Scenario: 非字符串值不碰
- **WHEN** 数字、布尔、null 字段的值与敏感值文本相同
- **THEN** 系统不替换这些非字符串字段

#### Scenario: 默认不重排仅开启重写
- **WHEN** `normalize_json_whitespace` 未开启
- **THEN** 不做 `dumps` 重写；开启为 `1` 时才重写并带 `x-veil-normalized:json-whitespace`

### Requirement: 凭据优先于 PII

同一文本同时命中凭据与 PII 规则 SHALL 优先按凭据处理，PII 规则 SHALL NOT 覆盖凭据占位符。

#### Scenario: 凭据优先
- **WHEN** 某值同时匹配凭据与 PII 模式
- **THEN** 系统生成凭据占位符，PII 规则跳过该区间

### Requirement: Vault 稳态与 rand8 OsRng

占位符随机段 SHALL 使用 `OsRng` 生成 8 位十六进制串（rand8）；Vault 映射 SHALL 稳态存储占位符与原文映射，同一原文在同一请求内 SHALL 复用同一占位符。

#### Scenario: 同值复用同一占位符
- **WHEN** 同一请求内同一原文多次出现
- **THEN** 每次替换为同一占位符（含同一 rand8）

#### Scenario: 随机段不可预测
- **WHEN** 攻击者观察占位符序列
- **THEN** rand8 仍不可预测（`OsRng` 熵源）

### Requirement: 并发 Scope 内 PII 隔离 + 全局凭据 LRU

PII 映射 SHALL 隔离在请求级 `Scope` 内，请求结束即销毁，跨请求 MUST NOT 互见；凭据明文到 token 映射 SHALL 走全局有界凭据 LRU（moka）；PII 还原 SHALL 只查本 `Scope`，MUST NOT 触达全局凭据 LRU；多请求并发脱敏/还原 SHALL 原子执行，MUST NOT 出现占位符串扰或映射撕裂。

#### Scenario: 并发请求不串扰
- **WHEN** 多请求并发执行脱敏与还原
- **THEN** 各请求 PII 映射彼此隔离，凭据热路径走全局 LRU，结果正确

#### Scenario: 跨请求不可还原他方 PII
- **WHEN** 请求 B 持有请求 A 的 PII 占位符
- **THEN** 还原失败并原样保留，记审计计数

### Requirement: 残缺占位符清理

流式分片切断导致的残缺占位符 SHALL 被累积补全后处理；补全失败或孤立残缺 SHALL 清理为原样文本或告警，MUST NOT 向任一侧泄漏半截占位符。

#### Scenario: 切断占位符补全
- **WHEN** 占位符被 SSE 分片切断
- **THEN** 系统累积后续分片补全后再替换或还原

#### Scenario: 孤立残缺清理
- **WHEN** 流结束仍有无法补全的残缺占位符
- **THEN** 系统原样保留并记审计事件，不输出半截占位符
