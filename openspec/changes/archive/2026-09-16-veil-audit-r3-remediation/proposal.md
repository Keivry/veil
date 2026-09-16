## Why

本 change 承载 2026-09-16 第三轮独立六维审查（r3）的修复规划：对上一批已归档变更 `veil-audit-r2-remediation`（审查基线 `2785974`，13 提交 / 251 文件 / +14752−2286）做只读审查后，登记 **P1×2、P2×13、P3×24**，覆盖协议合成帧合规、请求/响应保真、资源上限、跨请求还原授权、架构声明与实现背离、死代码收敛、文档指针与门禁口径七个方向。

审查基线门禁全绿（`gate.sh` 7/7、真 SDK conformance 23/23、`check_file_sizes` 159 文件 ≤800 行、`openspec validate --all --strict`），故这些是现有门禁未捕获的二阶缺陷：**热路径无界增长（上游可控 OOM）、跨请求凭据明文泄露（token 序号可枚举）、规范真相源自相矛盾、注释/规格声明强于实现、文档指针漂移**——而非已知失败回归。

其中 3 项为深度复核后的**纠偏结论**（已由 oracle 咨询确认，本 change 采纳）：

- **B3 严重度由 P2 上调 P1**：响应侧凭据还原为全局查表且 token 序号可枚举，构成跨请求凭据明文泄露；修法必须以"本请求脱敏实际产出的 token"为白名单，**SHALL NOT** 以"请求体中出现过的 token"为白名单（调用方自带字面量会保留漏洞）。
- **D1 的审计修法无效**：真实无界路径为"同一 index 零字节 tool 分片"（不增条目、不增字节，`push_fragment` 的上限恒不触发），须以 `pending_tool_frames` 自身记账 + fail-closed 封堵，而非 hold 状态门控。
- **ARH-9/10/11 应显式收窄 canonical spec 文本**而非继续收敛代码：剩余 `match protocol` 集中于逐协议**差异产物构造**，不属重复分派；`UpstreamStatus` 强制范围应为网关边界；不变量守护只能覆盖已枚举项。

## What Changes

### 一、跨请求还原授权与审批容量（`CRD-R3`）

- **B3（P1）响应侧凭据还原改为请求级授权**：`Scope` 新增请求级 minted-set（随请求销毁），由请求侧脱敏**实际产生替换**处记录本请求产出的凭据 token；响应还原（`restore_response_one` / `restore_cred_tokens`）仅在 token ∈ minted-set 时还原，未命中者按幻觉 token 剥离（`strip_hallucinated` 增 allowed 过滤）。`CredentialVault` 保持进程单例、`make_cred_token` 六位零填充、`token_re` `\d{4,}`、placeholder 门控 `\d{6,}`、prompt-cache 关联语义**均不变**。
- **D4（P2）`DecisionTable::begin` 施软上限**：`begin` 先 `sweep` → 循环驱逐终态 `Decided`（`created` 升序、key 字典序 tie-break）→ 满表且仅余 `InFlight` 时新增 `BeginOutcome::Saturated` → `VeilError::RateLimited{retry_after_secs: 60}`（`429 + Retry-After`）。**SHALL NOT** 驱逐 `InFlight`，**SHALL NOT** 对新键伪造 `202 + E_PENDING`。同键在途仍 `202 + E_PENDING`。同步修订 `architecture-cleanup` spec 的「InFlight 由 Matrix 并发度天然约束」backstop 条款（该理由不成立）。

### 二、协议合成帧合规（`RSP`/`CHC`/`ANTH`）

- **F-01（P1）非流 Responses 阻断体补齐必需字段**：与流式 `responses_failed_frame` 同形——`object`/`created_at`/`model`/`output`/`status` 齐备，`status` 恒 `failed`、`output` 恒空数组；`model` 优先回显上游归一值、缺失回退 `unknown_model`；`id` 优先上游、其次会话 id；`error` 仅保留 `message`（不合成 `code`/`param`），与流式逐字段对齐。
- **F-02/F-03（P2）Responses 合成帧序号游标**：泵内维护"已见上游序号上界"游标（仅 Responses 且帧可解析时更新，取 max、缺失不更新、回退忽略、不因断序升级为错误）。阻断 7 帧与截断单帧以 `cursor.map_or(0, |c| c + 1)` 为起始基准；**真空流**零帧 → `base=0`，既有 0..6 全序列行为与测试不变；`type:"error"` 单帧沿用上游 error 自带序号。
- **F-04（P3）Anthropic 阻断帧补 `message_start`**：既有四帧（`content_block_start → content_block_stop → message_delta → message_stop`）之前补恰一 `message_start`（空 `content`、null `stop_reason`、usage 全 0；`id` 取会话标识、缺失回退 `blocked-0`），复用真空流 `message_start` 构造；canonical `gateway-protocol-fix` spec 的"四件套顺序"同步修订为"五件套顺序"，原四帧内容与顺序不动。
- **F-05（P3）Anthropic 中途断流语义规范化（不改代码）**：中途断流（已发内容帧后异常 EOF）保持仅记 `truncated_mode=open_ended`、**SHALL NOT** 合成 `message_stop`；在 `llm-protocol-hardening` spec 补齐"中途断流 vs 真空流"分野条款，使规范真相源完整。
- **F-08（P3）Chat 错误载荷帧即终端**：带顶层 `error` 且无 `choices` 的数据帧 SHALL 视为终止事件——不补 `[DONE]`，并以独立观测（`upstream_error`）区别于中途截断的 `open_ended`；判据限定避免与"choice 内含 error 字段"的正常形态误撞。

### 三、流式出口与解析（`SSE`/`TRN`）

- **F-07（P3）多行 data 出口保真**：出口将含换行的 data 载荷按 `\n` 拆为多条带 `data:` 前缀的行后再补块终止空行，与解析侧 WHATWG 单 `\n` 连接严格互逆，**SHALL NOT** 输出无前缀裸行。抽 `sse::data_frame(prefix, data)` 单一实现替换 5 处重复构造；`event:`/`id:`/`retry:` 信封不受影响。
- **D2（P2）`pending_events` 硬上限**：`PENDING_EVENTS_MAX=8`，超限丢最旧 + 计数（`pending_events_dropped`，经 `take_*` 由泵排入观测）+ 每流首次 warn。TRN-1 的 `event` FIFO 与 `id` 最近值语义、以及"分块信封流与同内容非分块流计数逐一致"均**不变**。
- **F-09（P3）Content-Type 大小写不敏感**：新增 `is_event_stream(ct)`（取 `;` 前段 trim 后 `eq_ignore_ascii_case`），收敛 `should_pump_stream` 与 `dispatch` 两个决策站点；`stream_flag` 回退语义不变。
- **F-10（P3）跨槽 hold 放行序显式声明（不改代码）**：放行序显式定义为"每槽按到达序取出、由该槽完成事件驱动"，跨槽并行 item 的相对 `sequence_number` 次序**不被保证**；按 `stream-protocol-parity` spec「无法保序则显式声明并由测试锁定」条款登记，并补交错并行 item 用例锁定实际放行序。

### 四、脱敏与会话保真（`PII`/`RED`）

- **B1（P2）残余帧 JSON 转义还原**：`spawn/terminal.rs` 残余路径由 `restore_response_with_spans` 改为 `restore_response_with_spans_json`，消除明文含 `"`/`\`/控制字符时产出非法 JSON。
- **B4（P3）未闭合 JSON 片段深度计**：对已知工具参数载体帧（Responses `response.function_call_arguments.delta`、Anthropic `content_block_delta` + `delta.type=input_json_delta`、键名 `partial_json`/`arguments`）下的**未闭合** JSON 片段按"外层字符串 + 内层容器"计 `depth+1`；完整可解析容器的既有路径与全部现有用例**不改**；载体以外的普通字符串（如 `delta.text`）**SHALL NOT** 应用加一。若载体判定不可靠，降级为"声明限制 + 锁定回归用例"，**SHALL NOT** 无差别加一。
- **B2（P3）`chat_bucket` spec 纠偏（不改代码）**：canonical `redaction-audit-coverage` spec 文本更新为位域公式 `(ci << 16) | (idx & 0xFFFF)`（`ci, idx < 2^16` 单射无碰撞，`ci=0` 与历史 `ci*64+idx` 等值）；已确认桶键仅作审计去重标识、全仓无解码路径。
- **D3（P2）自定义规则聚合超时不记账**：聚合墙钟超时或阻塞任务 panic 时仅记一条全局 warn（含规则数与预算）并返回零命中，**SHALL NOT** 对任何规则执行超时记账；规则停用仅由 batch 内逐规则 `find_iter` Err 路径触发（连续 3 次）。已知残余（持续慢规则导致每帧零自定义命中）显式登记于 design。
- **ARH-4（P2）规则集 Arc 化 + 批量记账**：`PiiDetector::custom` 改 `RwLock<Arc<Vec<(String, Regex, String)>>>`，`scan_custom` 仅 `Arc::clone`（**SHALL NOT** 每帧深克隆规则集）；写点用 `Arc::make_mut`。`account_rule` 批量为 `account_rules_batch`（单次获取 `strikes`/`disabled`，保持既有锁序）；扫描结果与停用状态机语义逐项不变。

### 五、资源上限（`RES`）

- **D1（P2）`pending_tool_frames` 记账 fail-closed**：`AuditHold` 新增 `account_pending_frame(bytes)`（条目维度复用 `AUDIT_HOLD_MAX_ENTRIES=4096`，字节维度以独立计数器受 `AUDIT_HOLD_MAX_BYTES` 约束）；`event_loop` 缓冲前记账，超限复用既有 `reject_reason="audit-hold-overflow"` 阻断臂。**SHALL NOT** 静默丢弃可审计数据；回归须覆盖"同一 index 零字节分片洪泛"下有界且被阻断。

### 六、架构声明与边界（`ARH`）

- **ARH-2（P2）单帧单解析收敛**：每帧 `ev.data` 的 JSON 解析收敛为 `event.rs::parse_event_data` 单点；`sticky_terminal_event` / `responses_failed_incomplete` / `responses_error_object` 改收 `Option<&Value>`（原字符串签名降为 `#[cfg(test)]` 包装）。守护升级为"动态解析计数 + 生产段（首个 `#[cfg(test)]` 之前）零 `from_str`"双守卫。
- **ARH-8（P3）`filter_hop_headers_counted` 用 `Vec<HeaderName>`**：直接 `remove(&HeaderName)`，去掉对 `HeaderMap` 键的 `to_lowercase()` 与字符串重解析（键已由 `http` 规范小写）；`Connection` 头内动态项仍按自由文本 lower+trim。性能收益标注为**假设**（待 bench），不作为对外性能承诺。
- **ARH-9/10/11 显式收窄 canonical spec（不改代码）**：ARH-9 收敛对象限定为协议**判定/分派谓词**（已为 `Protocol` 类型化方法），逐协议差异产物构造**不算**重复分派；ARH-10 `UpstreamStatus` 强制范围限定为网关**边界/分发点**，纯谓词 `classify_empty` 的 `u16` 入参为例外；ARH-11 仅对已枚举不变量（hop 方向、tool 位域、carry 剥离）提供守护，**SHALL NOT** 承诺未枚举项。
- **边界与声明锁修正**：`llm_gateway/mod.rs` 的 `axum::body::Bytes` 改 `bytes::Bytes`（`bytes` 已是直接依赖），使"service 生产仅允许 `axum::http::HeaderMap` 纯数据白名单"声明成立；声明锁守护改为对首个 `#[cfg(test)]` **之前的生产前缀** token-scan `axum::`，非白名单文件命中即失败，白名单文件内命中须为 `axum::http::*`。`RegisterParams` 的 trim 与构造下沉为 `service::register_map::parse_register_params`（handler 仅调用）；`HashChangeOutcome::from_reaction` 保留为领域解析器并声明为已知边界。

### 七、死代码与重复收敛（`DCD`）

- **DCD-5 收敛**：5 个仅测试引用的 `pub` 项降为 `#[cfg(test)] pub(crate)`（`GatewayMetrics::truncated_count`/`hop_filtered_count`/`nondialog_passthrough_count`、`MatrixApproval::pending_event_ids`、`chunk::scan_builtin`，与既有 `conv_missing_count` 等模式一致）。r2 归档 `tasks.md` §8.4 的虚高勾选在本 change 的 design 覆盖表中显式更正（归档目录禁改）。
- **有界去重**：抽取 `service::redaction::restore_guard`（`inner_json_intact` + `restore_guard_ok`，供 `frame_feed` 与 `nonstream` 共用）、`llm_gateway::strip_veil_internal_headers`（替换 3 处 `x-veil-*` 剥离）、`sse::data_frame`（替换 5 处 `data: {..}\n\n`）；`NORMALIZED_HEADER_NAME/VALUE` 提升为生产 `pub(crate) const` 并复用；Chat `[DONE]` 统一走 `chat_done_frame()`。测试内断言文本与 `hop.rs` 动态项处理**不纳入**本次抽取。

### 八、管理面与文档（`OPS`/`DOC`）

- **D5（P3）`series?since=` 非法值 400**：仅接受 `[dhm]<整数>` 形态，非法返回 `400 + E_BAD_REQUEST`（消息列明合法形态），**SHALL NOT** 以 `i64::MIN` 回退为全量无过滤；README §3 与 canonical spec 补注取值形态；epoch/日期形态需另立 change。
- **D6（P3）宽限去重表 TTL 驱逐**：`HashMap<String,u64>`（value = `expires_at`），`GRACE_NOTIFY_DEDUP_MAX=4096` 不变；达上限先清扫已过期，仍满则逐出 `expires_at` 最小者 + warn；**SHALL NOT** 整表清空。
- **门控 404 安全头**：`OBSERVABILITY_DISABLE=1` 门控的 404 响应补与既有 admin 响应一致的安全头，消除与 `observability-admin` spec 的偏离。
- **双 canonical 收口（F-06，P2）**：删除 `stream-protocol-parity` 的「Empty streams stay open-ended for chat/anthropic」整节，替换为指向 canonical `llm-protocol-hardening` 的迁移声明（三协议真空流最小终止；`truncated_mode` 观测口径保留；**SHALL NOT** 依历史文本实现开放结尾）。**同批修订 canonical `llm-proto-closeout`** 的同源旧条款（`spec.md:28-40` 真空流 open-ended、`:47-54` `finish_reason` 后记 `open_ended` 且 SHALL NOT 补 `[DONE]`），使真相源唯一。
- **文档指针与语义批**：README §6.4（`event_loop.rs` 指针 + 符号锚）、README §7.5 与 `credential-auth-hardening` spec（`vault_ops.rs` 行号）、`docs-test-parity` spec 与 3 处源码注释（`env_parse.rs` 行号、`main.rs:45→46`）、`docs-contract-sync` spec、`go-client-interop` spec、`credential-flow-parity` 与 `credential-api` 两处"未 enrolled 兼容放行"语义（改写为"默认转审批（`AUTO_APPROVE=false` 才 403）"，指向 `credential-auth-hardening` 真相源）、`credential-flow-parity` 低危行号偏移批、README §7.2 `total_tokens` 求和回退语义、3 处陈旧源码注释。
- **门禁措辞降级**：`check_doc_paths.py` 与 `gate.sh`/`scripts/README.md` 的"行号语义校验"改述为"行号范围校验（存在性 + 在界内）"；`docs-test-parity` spec 显式声明"被引行内容与文档语义的一致性由评审保证，门禁脚本不校验"；登记升级触发条件（若同类漂移再现则改为登记式语义锚点表）。
- **文档完整性缺口**：补 `PROXY_URL`/`PROXY_HTTP_TIMEOUT`（README §5）、`VEIL_APPROVAL_E2E_URL`/`VEIL_APPROVAL_E2E_CALLER`、`scripts/README.md` 的 `PENDING_LINE_REFS` 说明。

### 九、Go 客户端对齐（`GO`）

- **非法 env 回退**：`PROXY_APPROVAL_TIMEOUT`/`PROXY_HTTP_TIMEOUT` 解析失败时回退到**文档默认 `300s`** 并向 stderr 告警，**SHALL NOT** 静默取 30s。
- **退出码语义**：子命令 flag 集改 `flag.ContinueOnError`——用法错误退出 1、`-h` 退出 0，退出码 2 **专用于**「已受理待审批」。
- **测试真实形状**：审批测试主用例改用真实 Rust 202 形状（`{"error":{"code":"E_PENDING",…}}`，断言 `regID == ""`），另留一条 Python 基线（顶层 `reg_id`）用例覆盖 `proxy.go` 的 `reg_id` 回退；回退逻辑保留并注明"对 Rust 服务器恒不命中"。`go vet`/`go test` 保持全绿。

## Capabilities

### New Capabilities

无（本 change 只修改既有 capability）。

### Modified Capabilities

- `credential-vault-singleton`: 还原授权为请求级 minted-set，未授权 token 按幻觉剥离（B3）；收窄/作废「PII 全局持久双模」旧条款（与请求级 PII 声明冲突，B3 同批）。
- `credential-approval-dual-mode`: `begin` 软上限 + `Saturated` → `429 + Retry-After`（D4）。
- `llm-protocol-hardening`: 合成帧序号游标、中途断流/真空流分野、Chat 错误帧终端语义（F-02/F-03/F-05/F-08）。
- `llm-gateway`: 截断状态白名单由三态扩为四态（新增 `upstream_error`）（F-08 同批）。
- `llm-proto-closeout`: 删除空流 open-ended 旧条款、对齐 `[DONE]` 补发与 `clean_close` 口径（F-06 扩展）。
- `gateway-protocol-fix`: Anthropic 阻断帧升五件套（F-04）。
- `protocol-compliance-fix` / `llm-streaming-parity`: Anthropic 终止「三件套」旧声明同字对齐五件套（F-04 扩展）。
- `stream-fidelity-fix`: 多行 data 出口保真（F-07）。
- `gateway-transport-fidelity`: `pending_events` 上限、Content-Type 大小写不敏感（D2/F-09）。
- `stream-protocol-parity`: 删除空流 open-ended 条款、跨槽放行序显式声明（F-06/F-10）。
- `redaction`: 残余帧 JSON 转义、未闭合片段深度计（B1/B4）。
- `redaction-audit-coverage`: `chat_bucket` 位域公式纠偏（B2）。
- `pii-custom-compat`: 聚合超时不记账 + 规则集 Arc 化（D3/ARH-4）。
- `observability-admin`: `since` 校验 400、门控 404 安全头、宽限去重 TTL（D5/D6）。
- `architecture-cleanup`: ARH-2/4/8/9/10/11 收窄与收敛、D4 backstop 条款、声明锁与边界修正。
- `docs-test-parity`: 门禁措辞降级与语义声明、指针修正。
- `docs-contract-sync`: `OBSERVABILITY_DISABLE` 证据指针修正。
- `go-client-interop`: 客户端三处对齐（GO）。
- `deadcode-positional-cleanup`: DCD-5 收敛与有界去重抽取。
- `credential-flow-parity` / `credential-api`: 未 enrolled 语义纠正（指向 `credential-auth-hardening` 真相源）。
- `credential-auth-hardening`: `vault_ops.rs` 证据指针修正（G-1）。

## Non-goals

- 不重开 `veil-audit-r2-remediation` 已声明的有意偏离（Anthropic 中途断流不补终端、跨槽放行序、`ValidationCache`/`x-veil-protocol` 内联保留）。
- 不做流内 `responses_block_frames`（`status:"completed"`）与 `responses_failed_frame`（`status:"failed"`）的语义统一（属既有设计，另立 change）。
- 不实现 `check_doc_paths.py` 的通用语义锚点校验（本次选择降级措辞 + 声明，见 design D-E）。
- 不引入新依赖；不改变 `CredentialVault` 的 token 形态与跨请求同 token 语义。
