## Purpose

Rust 重写过程中的 6 项协议合规修正：逐项收敛与原 Python 网关的语义偏差，每项独立可验，修正前后行为以 AS-IS / TO-BE 双 Scenario 锁定。本 spec 为 FIX-1 至 FIX-6 的权威定义，llm-gateway spec 的终止、尾判定、字节契约只引用本 spec 同字口径；FIX-5 的 json-aware 语义以 redaction spec 为权威，本 spec 只做引用。

## ADDED Requirements

### Requirement: FIX-1 hop 头全集与编码开关配对

逐跳（hop-by-hop）头 SHALL 按 RFC 9110 全集剥离（`connection`、`keep-alive`、`proxy-authenticate`、`proxy-authorization`、`te`、`trailer`、`transfer-encoding`、`upgrade` + `Connection` 头内列名的动态项），大小写不敏感，双向过滤；`reqwest` 编解码开关 SHALL 配对（自动解码开启则对外统一 `identity`，关闭则原样透传编码），剥离 SHALL 在编码改写之前执行；过滤动作 SHALL 记 `hop_filtered_total{dir}`。

#### Scenario: AS-IS 修正前（hop 头残留与顺序错）
- **WHEN** 上游响应含 `Connection: X-Custom-Hop` 且 `X-Custom-Hop` 为逐跳头
- **THEN**（修正前）网关仅剥离固定 hop 头集合，`X-Custom-Hop` 被透传给客户端，且编码改写先于剥离导致长度口径错乱

#### Scenario: TO-BE 修正后（全集剥离与开关配对）
- **WHEN** 同样响应到达网关
- **THEN**（修正后）网关解析 `Connection` 全集并全部剥离，`reqwest` 编解码开关配对，客户端收到的头部与长度一致，`hop_filtered_total{dir}` 递增

### Requirement: FIX-2 三协议终止闭合

chat 阻断/空流恒以 `data:[DONE]` 恰 1 个收尾；Anthropic 补 `content_block_stop` + `message_delta` + `message_stop`；responses 阻断补 `response.completed`、截断补 `response.failed`；合成块必须带 `event:` 行。终止后到达的滞后分片 SHALL 被丢弃；重复终止标记 SHALL 去重。

#### Scenario: AS-IS 修正前（终止未闭合）
- **WHEN** 上游流缺失终止标记且连接半开，或审计阻断注入后无统一收尾
- **THEN**（修正前）网关无限等待或收尾形态不定，下游 Hermes 把阻断流误判为截断而重试或挂起

#### Scenario: TO-BE 修正后（三协议闭合）
- **WHEN** 同样半开流超时或阻断注入
- **THEN**（修正后）chat 恒以 `data:[DONE]` 恰 1 个收尾，Anthropic 补三件套，responses 阻断补 `response.completed`、截断补 `response.failed`，合成块带 `event:` 行，`stream_meta.terminal_injected=true`

### Requirement: FIX-3 tool 三元组与 legacy 兼容

tool 调用 SHALL 统一抽为 `(id, name, args)` 三元组；缺 `id` 时 SHALL 合成 `call_stable_<index>` 并标记 `id_synth=true`；SHALL 兼容 `message.function_call` / `delta.function_call` legacy 形态并归一为标准 tool_calls；SHALL 兼容 `custom_tool_call` 方言。非 string `args` SHALL 规范化为 JSON 串（dict SHALL `dumps` 序列化，缺失 SHALL 记告警不断链），MUST NOT 静默置空透传。三元组缺失 SHALL 告警并暂缓审计放行。

#### Scenario: AS-IS 修正前（三元组缺失与形态裸奔）
- **WHEN** 上游以增量分片发送 tool `arguments` 或以 legacy `function_call` 发送
- **THEN**（修正前）网关逐分片裸转或不识别 legacy，审计侧收到碎片 JSON 或漏检，三元组缺 `id` 时仍放行

#### Scenario: TO-BE 修正后（三元组补齐与形态归一）
- **WHEN** 同样增量分片或 legacy 形态到达
- **THEN**（修正后）网关累积补全 `arguments` 为合法 JSON，缺 `id` 合成 `call_stable_<index>` 标 `id_synth=true`，legacy 归一为标准 tool_calls 后进审计

#### Scenario: 非 string args 规范化不置空
- **WHEN** tool `args` 为 dict 等非 string 形态或缺失
- **THEN** 网关以 `dumps` 规范化为 JSON 串，缺失记告警不断链，不得静默置空透传

### Requirement: FIX-4 尾判定唯一与宽容可观测

`is_chat_tail` SHALL 为全协议唯一判定，禁内联 `endswith`（B1 审计旁路）；SHALL 保留一层后缀宽容，每次宽容命中 SHALL 记 `chat_tail_lenient_total{tail}` 并写 debug 日志；严格匹配三对话尾全路径段，子串包含 SHALL NOT 判真。

#### Scenario: AS-IS 修正前（子串误判与黑盒）
- **WHEN** 请求路径为 `/v1/fake-chat/completions-extra`
- **THEN**（修正前）子串匹配误判为对话尾，走注入分支污染透传流量，且无判定日志与计数可查

#### Scenario: TO-BE 修正后（唯一判定与可观测宽容）
- **WHEN** 同样路径或一层容忍后缀路径到达
- **THEN**（修正后）子串路径判定为假走透传；容忍后缀命中判真并记 `chat_tail_lenient_total{tail}` 与 debug 日志；业务分支无内联 `endswith`

### Requirement: FIX-5 字节契约（引用 redaction）

网关 SHALL 遵循与 redaction spec json-aware 定义同字的字节契约：默认仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`。语义细节以 redaction spec 为准，本 spec 只做引用。

#### Scenario: AS-IS 修正前（静默压缩空白）
- **WHEN** 网关改写 JSON 请求体
- **THEN**（修正前）静默压缩空白与明文化转义，字节不等价且无声明，下游签名或缓存键断裂

#### Scenario: TO-BE 修正后（显式字节契约）
- **WHEN** 同样改写场景
- **THEN**（修正后）默认仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才 `dumps` 重写并带 `x-veil-normalized:json-whitespace`

### Requirement: FIX-6 conv_id 提取覆盖与豁免

`conv_id` 提取 SHALL 覆盖 `incomplete` / `failed` / `error` 事件的单双层 `id`（含 `data.response.id` 单层与双层回退）；提取失败 SHALL 记 `conv_id_missing_total{reason}` 并按 `unknown_<hash8>` 归档不断链；header 注入与 body 字节等价冲突 SHALL 显式豁免（header 注入优先不断链，不视为 FIX-5 违例）。

#### Scenario: AS-IS 修正前（conv_id 缺失）
- **WHEN** 上游以 `response.incomplete` / `response.failed` / `error` 事件返回
- **THEN**（修正前）网关只认成功形态，会话 id 丢失，落盘与审计关联断链

#### Scenario: TO-BE 修正后（全覆盖与豁免）
- **WHEN** 同样事件到达
- **THEN**（修正后）提取器覆盖单双层 `id`，失败记 `conv_id_missing_total{reason}` 并按 `unknown_<hash8>` 归档；header 注入与 body 字节等价冲突显式豁免
