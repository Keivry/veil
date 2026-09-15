# redaction Specification — delta

## ADDED Requirements

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

## MODIFIED Requirements

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

## RENAMED Requirements

- FROM: `### Requirement: 6 recognizer + 联合正则 + 中文边界`
- TO: `### Requirement: 7 recognizer + 联合正则 + 中文边界`
