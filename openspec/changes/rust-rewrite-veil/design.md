## Context

现状（见 proposal.md）：Python `proxy.py` + `_credential` + `_registry` + `_token` + `_pii` + `_llm` 约 8676 行 + `_sse` + `_matrix` + `_tpm` + `_audit` + `_metrics` + `_admin` + `utils/json_walk` 构成 credential-proxy 全量行为。Go `get` 客户端保持不动，`admin.html` 原样复用，本 change 只在 veil 新仓写 Rust 实现，不碰原仓。

技术基线：
- Python 侧为每端口一个 `AppRunner`，`asyncio.Lock` / `Event` 做并发控制，`ContextVar` 做请求级上下文，`threading` 锁加队列做 metrics 写库
- 转发链路含 7 凭据路由加通配 `/{tail:.*}`，加 6 admin 路由，`/_admin` 须优先匹配
- 脱敏管线为凭据占位符加 PII 占位符加 `json-walk`，SSE 为 WHATWG 切行加三层缓冲，审计含 hold 缓冲与截断三态
- 三协议（OpenAI Chat、Anthropic Messages、Responses）各有合规坑，Rust 重写须逐项修正落设计，不留隐式行为
- 参考风格对齐原项目 `openspec/changes/llm-privacy-gateway/design.md` 的 D1/D2 分节写法，中文撰写

## Goals / Non-Goals

**Goals：**
- 用 Rust tokio 加 axum 完整重写 Python 网关行为，路由、并发语义、脱敏、SSE、审计、存储、配置逐项等价
- 三协议合规 6 项修正全部进设计决策，每项给出判定点与输出形态
- 存储与配置 fail closed 语义与原仓 README 继承一致
- Go `get` 客户端与 `admin.html` 零改动可直接对接

**Non-Goals：**
- 不改 Go `get` 客户端协议与参数
- 不改 `admin.html` 结构与接口字段，原样复用
- 不引入 Presidio 等重依赖，不做语义级危险文本检测（延续原 D1 Non-Goals 边界）
- 不做多租户隔离，不改 Hermes 端 custom provider 配置
- 不碰原仓任何文件，只写 veil 新文件

## Decisions

### D1：路由分层，单 axum serve 多 SocketAddr

**决策**：只起一个 axum `Router`，单 `serve` 同时绑定多个 `SocketAddr`，替代 Python 每端口一个 `AppRunner`。路由按三层组织：`/_admin` 优先层，凭据业务层，通配兜底层。

**理由**：多 `AppRunner` 是 Python 历史形态，多端口共享同一 handler 表时徒增任务数与端口漂移风险。单 `serve` 让路由表唯一，行为可审计，启动失败 fail closed。

**路由表（硬性）**：
- `/_admin` 相关 6 路由优先注册，精确匹配先于通配，防 `/{tail:.*}` 吞没。唯一表：`/_admin/`、`/_admin/health`、`/_admin/metrics`、`/_admin/series`、`/_admin/events`、`/_admin/events/stream`。顺序约定：admin 精确路由先注册，通配最后注册，单测断言 `/_admin/...` 不进通配 handler。
- admin 鉴权与 spec 同字：`X-Admin-Token` 请求头 > `__Host-admin_token` Cookie > `?access_token`（仅 SSE `/_admin/events/stream`）；非 SSE 带 query 恒 401；HMAC 等长比较；限流按 TCP `remote` 计数不读 XFF；SSE 5/IP 并发；通用管理接口 10/min/IP 429 + `Retry-After`。token 名映射：服务端环境变量 `OBSERVABILITY_ADMIN_TOKEN`，客户端请求头 `X-Admin-Token`。
- 凭据业务 7 路由：对齐 Python 现有 7 凭据路由（注册、取用、审批回调、LLM 转发三协议入口、健康检查等），方法加路径精确匹配。凭据吊销类路由口径归 credential-api spec，D1 不复写。
- 通配 `/{tail:.*}` 仅一处，作为 LLM 上游透传兜底，不得再新增第二个通配。尾判定一律调用 `is_chat_tail`（全协议唯一判定，禁内联 `endswith`）。

**备选**：
- 多 `serve`（每端口一实例）：与 Python 对齐但运维复杂，端口间路由漂移难发现，不采用
- 单端口多路复用：与现有多 SocketAddr 部署不兼容，不采用

### D2：并发与状态，tokio 原语替代 asyncio

**决策**：并发原语一一映射，不自创语义。

| Python 现状 | Rust 决策 |
|---|---|
| `asyncio.Lock`（注册表、token 映射） | `tokio::sync::RwLock`（读多写少处）与 `tokio::sync::Mutex`（写密集临界区） |
| KeePass 串行访问锁 | `tokio::sync::Semaphore(1)`，许可数为 1，全局单例，超时即 fail closed 返回 503 |
| `asyncio.Event`（审批等待） | `tokio::sync::broadcast` 审批事件通道，审批结果广播给挂起任务，滞后订阅者按过期拒绝处理 |
| `ContextVar` 请求上下文 | 每请求 `Scope` 结构体，经 axum `Extension` 或显式参数传递，禁止全局可变静态量跨请求共享 |
| `threading` 锁加队列写 metrics | `tokio::mpsc(512)` 有界通道加 `spawn_blocking(rusqlite WAL)` 写库任务 |

**理由**：`RwLock` 适配注册表读多写少，`Mutex` 适配 token 计数器等短临界区，`Semaphore(1)` 把 KeePass 不可重入约束显式化。`broadcast` 对审批一对多唤醒语义最贴合，且天然支持滞后者检测。`Scope` 让请求级映射生命周期可析构，避免 `ContextVar` 隐式传递在 Rust 中不可表达。

**细节（硬性）**：
- `Semaphore(1)` 只包 KeePass 进程调用段，锁外做网络 I/O，沿用 Python 锁外网络约束。
- `broadcast` 通道容量按审批并发配额设定，满时新审批请求直接拒绝，不阻塞转发主路径。
- 每请求 `Scope` 含请求级 PII 映射、SSE 缓冲、审计 hold 句柄，请求结束即 drop，见 D3 隔离。
- metrics 路径：转发主路径只做 `try_send` 进 `mpsc(512)`，满则计数器 `dropped` 加一并告警，不阻塞。写库端 `spawn_blocking` 内跑 `rusqlite` WAL 模式，批量提交。

**备选**：
- 全 `Mutex`：简单但读并发塌缩，不采用
- `watch` 替代 `broadcast`：只保留最新值，审批多 pending 会丢事件，不采用
- 无界 `mpsc`：内存不可控，metrics 洪水可拖垮进程，不采用

### D3：脱敏管线，长度降序加 json walk 加 roundtrip

**决策**：脱敏分四步：凭据替换，PII 替换，json walk 全量扫描，roundtrip 校验。

**占位符形态（硬性）**：
- 凭据：`__VG_CRED_%06d__`，零填充 6 位序号，全局递增。替换按明文长度降序，避免短值先替换切断长值。
- PII：`__PII_<seq>_<rand8>__`，`seq` 为请求内递增序号，`rand8` 为 8 位十六进制随机段。Python 侧 `secrets` 对应 Rust 侧 `rand::rngs::OsRng`，禁止 `StdRng` 时间种子。`_restore` 只还原本请求 `Scope` 内存在的 token，越界或形态不符原样保留并记审计计数。

**json walk（硬性）**：`depth=5`，流程为 `loads` 解析，`walk` 递归替换，`dumps` 回写。解析失败走 text 级兜底，不丢请求。字节契约与 FIX-5 同字：默认仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`。回写后做 roundtrip 校验：再 parse 一次确认 JSON 合法且占位符无破损，失败则拒绝转发并记审计。json-aware 语义细节以 redaction spec 为准。

**优先级与隔离（硬性）**：
- 凭据优先跳过：同一明文既命中凭据注册表又命中 PII 模式，一律走凭据路径，PII 检测跳过该区间。占位符区间重叠排除：任何与 `__VG_CRED_*__` 或 `__PII_*__` 区间重叠的匹配整体跳过。
- 全局 LRU 用 `moka` 缓存已注册凭据明文到 token 映射热路径，容量有界加版本计数，配置重载即失效。请求级 PII 映射只活在 `Scope` 内，永不写入全局 LRU 与全局注册表，请求结束清理。单测断言跨请求不可还原他方 PII token。

**备选**：
- `dashmap` 替代 `moka`：见 Risks，`dashmap` 无界增长需手写淘汰，不采用为主路径
- 正则直扫 body 字符串：会误伤占位符与 base64 图像，且中文边界误报高，不采用

### D4：SSE 与审计，WHATWG 切行加三层缓冲

**决策**：SSE 解析严格按 WHATWG 切行，缓冲分三层，慢快语义对齐，审计 hold 独立。

**切行与缓冲（硬性）**：
- WHATWG 切行：按 `\n` 组装事件，`\r\n` 不拆开，不在 JSON 引号中间解析。行缓冲上限 1M，事件缓冲上限 16K，空闲超时 30s，keepalive 注释每 10s 下发一次冒号注释行。跨分片字节按字节缓冲 + IncrementalDecoder（`utf8-chunk`）组装，MUST NOT 逐 chunk `replace` 解码（半字符等待后续字节补齐）。
- slow/fast 语义对齐：slow 路径逐事件 flush 保序，fast 路径允许合并 flush 提吞吐，两者完成事件语义一致，审计触发点同为完成事件。
- 审计 hold：上限 1M， verdict 未出前暂停可疑 tool call 后续事件 flush，继续读上游防 TCP 背压断连。超限按 fail closed 拒绝并注入拒绝消息。

**截断三态（硬性）**：唯一值 `silent_discard` / `open_ended` / `synthesized_failed`（`synthesized_failed` 仅 Responses 协议可用，合成失败终止事件，避免客户端 tool 块 dangling。Chat 与 Anthropic 不得合成该形态，各自走原生终止）。网关在 `stream_meta.truncated_mode` 记录该值并落 metrics（按 mode 分标签）。

**理由**：三层缓冲把行组装、事件累积、审计挂起解耦，超限各自 fail closed。截断三态把协议差异显式化，`synthesized_failed` 限定 Responses 是因其 `completed` 与 `failed` 状态机最严格。

**备选**：
- 单层大缓冲：行与事件超限混同，超限定位难，不采用
- 挂起整个流：延迟大且破坏流式体验，不采用

### D5：三协议合规修正设计，6 项逐条决策

以下 6 项每项均为硬性设计决策，实现与测试一一对应。

**修正 1，hop 头与编码**：hop 头按 RFC 9110 全集剥离（`connection`、`keep-alive`、`proxy-authenticate`、`proxy-authorization`、`te`、`trailer`、`transfer-encoding`、`upgrade` + `Connection` 头内列名的动态项），大小写不敏感，双向过滤。`reqwest` 编解码开关配对（自动解码开启则对外统一 `identity`）。剥离在编码改写之前执行，过滤动作记 `hop_filtered_total{dir}`。理由：hop 头透传会污染上下游连接复用，未解码即检测会漏检 gzip 包体。

**修正 2，终止语义**：chat 阻断/空流恒以 `data:[DONE]` 恰 1 个收尾；Anthropic 补 `content_block_stop` + `message_delta`（含 `stop_reason`）+ `message_stop`；responses 阻断补 `response.completed`、截断补 `response.failed`，两者不得互换；合成块必须带 `event:` 行。终止后滞后分片丢弃，重复终止去重，`stream_meta.terminal_injected=true`。理由：客户端按终止形态推进状态机，形态错乱即 dangling。

**修正 3，tool 三元组**：tool 调用统一抽为 `(id, name, args)` 三元组。三协议映射：Chat 取 `tool_calls[].id/function.name/function.arguments`；Anthropic 取 `tool_use` 块；Responses 取 `output[]`。缺 `id` 合成 `call_stable_<index>` 并标 `id_synth=true`。兼容 `message.function_call` / `delta.function_call` legacy 与 `custom_tool_call`，归一为三元组后进审计。理由：审计只认三元组，不认协议方言。

**修正 4，尾部判定**：`is_chat_tail` 为全协议唯一判定，禁内联 `endswith`（B1 审计旁路）。保留一层后缀宽容，每次宽容命中记 `chat_tail_lenient_total{tail}` 并写 debug 日志。子串包含不得判真。理由：子串匹配曾把 content 中的 done 字样误判为流结束。

**修正 5，改写语义**：与 FIX-5 同字：默认仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带响应头 `x-veil-normalized:json-whitespace`。json-aware 细节引用 redaction spec。`stream` 探测用协议字段判定（如 `stream:true` 与 SSE `content-type`），禁止用 body 字符串含 `stream` 字样判定。理由：字符串误命中曾把非流式包体送进流式分支。

**修正 6，会话标识**：`conv_id` 提取覆盖 `incomplete` / `failed` / `error` 事件的单双层 `id`（含 `data.response.id` 回退）；失败记 `conv_id_missing_total{reason}` 并按 `unknown_<hash8>` 归档不断链；header 注入与 body 字节等价冲突显式豁免。理由：无标识的审计条目不可关联，复盘断链。

### D6：存储与配置，WAL 加轮转加完整性

**决策**：三类文件各有归宿与权限。

- `metrics.sqlite`：WAL 模式，文件权限 0600。内存环 10k + `daily` 表保留 30 天 + `hourly` 表保留 7 天 + `5min` 表覆盖式 UPSERT 只留最新窗口；仅对话端点计数（`is_chat_tail` 为真）；延迟 12 桶 p95 近似；`is_precise` 为真表示精确计数可直接对账，为假表示近似仅趋势参考。写路径走 D2 的 `mpsc(512)` 加 `spawn_blocking`，读路径只读快照。
- `audit.log`：JSON Lines，10MB 单文件轮转，保留 5 份，文件权限 0600。先脱敏后截断再落盘，控制字符 `\x00-\x1f` 剥离，写失败双层 fail-closed（先重试缓冲，仍失败则拒绝主请求）并记熔断计数。
- `caller_registry.json`：调用方注册表，附 `sha256` 完整性字段，启动加载即校验，失配拒绝启动。重载走原子写（临时文件加 rename）。

**TPM（硬性）**：TPM 强制硬件，TPM 不可用 SHALL 启动失败，MUST NOT 软件回退。CI 用 mock TPM 实现 trait，不验收软件回退路径。

**配置（硬性）**：环境变量 fail-closed 表继承原仓 README（fail closed：缺失必填即拒绝启动，未启用脱敏或审计即显式告警保护未生效）。`OBSERVABILITY_ADMIN_TOKEN` 必填且独立，不得复用业务 token 或 admin 业务 token，缺失或弱值拒绝启动，鉴权失败只记计数不回显 token。

**备选**：
- JSON 文件替代 sqlite：并发写与聚合查询退化，不采用
- 明文审计全参数落盘：泄漏风险，不采用，只记脱敏摘要

## Risks / Trade-offs

- **单 serve 多 SocketAddr vs 多 serve**：风险为单 Router 故障域集中，一处 panic 影响全端口。备选多 serve 隔离性好但路由漂移难察。决策单 serve，缓解为启动时逐地址绑定校验，任一失败整体拒绝启动。
- **moka vs dashmap**：`moka` 有界 LRU 加 TTL 开箱即用，风险为引入额外依赖与异步失效语义。`dashmap` 轻量但无界，需手写淘汰与版本失效。决策主路径 `moka`，备选 `dashmap` 加手写 LRU 仅在依赖受限时启用。
- **RwLock 读饿死**：高并发读加偶发写可饿死写者。缓解为 token 计数器等写密集处改 `Mutex`，注册表重载走写优先。
- **Semaphore(1) KeePass 串行**：吞吐瓶颈，超时即 503。备选连接池不可行（KeePass 进程不可重入），接受串行并配超时告警。
- **broadcast 滞后订阅丢事件**：审批结果广播时掉线者按过期拒绝，可能误伤。缓解为挂起任务先查 pending 表再订阅，终态幂等。
- **mpsc(512) 满则丢 metrics**：洪水时可观测性降级。备选阻塞主路径会放大为全网关 DoS，宁可丢并计数告警。
- **json walk depth=5 截断**：超深嵌套走 text 兜底，可能漏检。备选调大深度会放大 CPU，维持 5 并显式记计数。
- **roundtrip 校验误伤**：上游非标准 JSON 被拒。缓解为仅对网关改写过的包体强校验，透传包体放行。
- **审计 hold 1M fail closed**：大 tool 参数被拒。备选放宽上限会放大内存，维持 1M 并记截断三态。
- **`synthesized_failed` 仅 Responses**：他协议客户端行为不一致。已在 D5 限定，跨协议测试覆盖。
- **OsRng 熵枯竭**：高并发随机段生成阻塞。备选批量预生成会扩大复用窗口，不采用，实测 OsRng 在目标并发下足够。
- **0600 权限与容器 umask 冲突**：挂载卷权限被覆盖。缓解为启动时 chmod 自检，不合即告警并拒绝写敏感文件。
- **sha256 注册表完整性 vs 可运维性**：手改注册表即失配。备选宽松告警不阻断会留篡改窗口，维持失配拒启动，提供离线重签名工具。

## Migration Plan

1. 先落 D1 路由表与 D2 并发骨架，单测断言 admin 优先与 Scope 隔离
2. 再落 D3 脱敏管线（含 roundtrip）与 D4 SSE 缓冲，加协议级集成测试
3. 再落 D5 六项修正逐项测试，最后落 D6 存储与配置 fail closed 表
4. Go `get` 与 `admin.html` 做端到端联调，原仓不动，只改 veil 侧
5. 回滚即切回 Python 进程，veil 与原仓数据文件互不共享，无迁移脚本

## Open Questions

- 多 SocketAddr 在 systemd socket 激活下是否仍由 veil 自绑，待部署侧确认
- `moka` 全局 LRU 容量与 metrics `mpsc(512)` 背压阈值是否需按 KeePass 实测延迟再调，待压测后定值
- `chat_tail_lenient_total{tail}` 告警阈值（计数）与 `conv_id` 归因口径待真实流量校准
