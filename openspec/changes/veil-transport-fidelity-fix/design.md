## Context

独立审计（2026-09-13，传输保真维）在 LLM 网关入站/出站路径确认 14 项待收敛偏差（见 proposal Why 与覆盖表）。现状真相源：

- 入站 URL 只取 path：`src/handler/llm/dispatch.rs:62` `parts.uri.path()`，`:124` `format!("{}{}", base, path)`，query 静默丢失（`T1`）。
- 非流响应头全丢：`src/handler/llm/nonstream.rs:253-257` 的 `(StatusCode, String).into_response()` 由 axum 强制 `text/plain; charset=utf-8`；`:275-277` 的 `(status, bytes.to_vec()).into_response()` 强制 `application/octet-stream`；上游 `Retry-After`/`x-request-id`/rate-limit 头无转发路径（`T2`）。`x-veil-protocol` 仅在 `:212-215`（阻断）与 `:264-267`（JSON 后处理）置位（`T10`）。
- 超时叠加：`src/state.rs:154` 单 client `.timeout(HTTP_TIMEOUT_SECS=30)`（`src/config/env_parse.rs` 默认 `30`）经 reqwest `TotalTimeoutBody` 覆盖整响应体读取；`src/service/llm_gateway/mod.rs:207-245` 每次重试各重置 30s（`T3`）。
- 非内存边界：`src/handler/llm/nonstream.rs:148` `up.bytes()` 全量读入，`:156` 才判 `len > ctx.nonstream_max_bytes`（`T4`）。
- 协议宽容：`src/service/llm_gateway/protocol.rs:54-78` `lenient_match` 的「父路径 + 额外单段」分支把 `/v1/messages/count_tokens`、`/v1/responses/{id}` 判为对话协议（`T5`）。
- 非流还原：`src/handler/llm/nonstream.rs:231` 用字节级 `restore_response_with_spans`，而流式用 `src/service/redaction/scope.rs:194 restore_response_with_spans_json`（`src/handler/llm/pump/spawn.rs:496`）（`T6`）。
- usage：`src/service/llm_gateway/usage.rs:71-75` 单事件缺 total 时按本事件 `prompt+completion` 派生，`:92-103` 五列各自 `max` → 派生 total 被当最终值（`T7`）。
- skip 分段：`src/service/redaction/scope.rs:293-318` 按区间切段后逐段 `redact_response_new_pii_tracked`，各段为不完整 JSON 时 `json_walk` 不递归 stringified JSON（`T8`）。
- 检索审计：`src/service/llm_gateway/tool.rs:109-130 retrieval_args` 只读顶层 `arguments/input/args` → `queries/query`（`T11`）。
- 重试分类：`src/service/llm_gateway/mod.rs:228-237` 仅 `e.is_connect() || e.is_timeout()` 退避，其余 `Err` 直接 502（`T13`）。
- 判序：`src/handler/llm/nonstream.rs:155-158` `classify_empty` 后且仅 `status<400` 判超限，与 Python `_llm.py:2936-2944`（先 `_is_nonstream_oversize`、无状态门、记 `metrics_ctx['status']=502` + warning）的观测差异未声明（`T14`）。
- 死臂：NonDialog `NonstreamOutcome::Stream`（`src/handler/llm/dispatch.rs:180-219`、`src/handler/llm/nonstream.rs:96`）本 change 不修（`T9`）；NonDialog 透传契约（README §7.6）与 query 语义待补充说明（`T12`）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与 README；不碰审计 verdict 与脱敏 recognizer；不新增依赖。

## Goals / Non-Goals

**Goals：**

- 给出 `T1`-`T8`、`T10`、`T11`、`T13`、`T14` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「入站 query 保真」「上游响应头保真」「长流不截断」「非流内存有界」「官方子资源不误判」「还原后 JSON 可解析」「usage total 跨事件正确」收敛为 spec 契约。
- 记录 `T9` 转出与 `T12` 契约引用，防止重复修复或口径悬空。

**Non-Goals：**

- 不改流式 `AuditHold`/boundary 放行与流式还原链（由 `veil-stream-fidelity-fix` 范围承载）。
- 不修 `T9` 死臂（由 `veil-arch-hygiene-closeout` H11 承接）。
- 不改审计 verdict、脱敏 recognizer 集合/采样、`stream_options` 注入与 usage 缓存列口径。
- 不引入新依赖、不改部署形态。

## Decisions

### D1：`T1` query 用 `Uri::query()` 原样拼接，不做重编码

**决策**：上游 URL 由 `format!("{}{}", base_trimmed, path)` 扩为 `path + query`：从 `parts.uri.query()` 取原样字符串，存在时（含空串以外的判定按 `is_some`）以 `?` 拼接，无则不加。`path` 仍取 `uri.path()`，不回退 `uri.to_string()`（避免把 scheme/host 拼进上游 URL）。

**理由**：`Uri::query()` 返回原始、未解码的 query 切片，天然保序、保 `%` 编码与 `+` 形态；`to_string()` 含整个请求目标（含 path），与上游基址拼接会重复 path 且引入 scheme 解析歧义。空 query（`?` 后为空）与无 query 的区分对本修复无行为影响，统一按「有 query 才加 `?`」处理即可。

**备选**：`url` crate `Url::set_query`（重编码 `%` 大小写与 `+`，破坏字节保真，不采用）；`parts.uri.to_string()` 直接拼接（重复 path，不采用）。

### D2：`T2` 响应头在消费 body 前快照，hop 过滤后逐条转发

**决策**：在 `serve_nonstream` 中 `up.bytes()`/`bytes_stream()` 之前克隆 `up.headers()` 为 `HeaderMap`，经 `filter_hop_headers_counted(&mut map, "downstream", decode_enabled, Some(metrics))` 过滤；JSON/阻断/超限/空体/错误透传各分支构造 `Response` 时逐条 `builder.header(k, v)` 转发。`content-type` 缺失时 JSON 分支回退 `application/json`，非 JSON 错误透传回退框架默认。`x-veil-*`（`x-veil-protocol`、`x-veil-normalized`）在转发后追加/覆盖。

**理由**：上游 `content-type` 与 `Retry-After`/rate-limit 头是下游 SDK 重试与诊断的真相源；现有 `(status, String)`/`(status, Vec<u8>)` 构造由 axum 推断内容类型，属框架副作用而非上游声明。hop 过滤复用 NonDialog 分支已验证的 `filter_hop_headers_counted`，两方向口径一致。快照必须早于 `up.bytes()`（`reqwest::Response::bytes` 消费 self）；`up.bytes_stream()` 分支同样先取头。

**备选**：只对 JSON 分支转头上游头（错误分支仍被框架覆盖，不采用）；同时透传上游 `x-veil-*`（伪造网关声明，不采用）。

### D3：`T3` 流式 client 去总超时，启动期构造双 client

**决策**：`build_http_client` 拆为两个入口——既有 `build_http_client`（非流：总超时 `HTTP_TIMEOUT_SECS`）与新增流式构造（不调 `.timeout()`；`read_timeout` 是否配置由 apply 实测决定，倾向配置一个远大于事件间隔的读空闲阈值）。两者均在 `AppState` 启动期构造；`fetch_upstream_with_retry` 增加显式 `client` 由调用方传入（签名已含 `client: &reqwest::Client`，仅需按路径选 client）。dispatch.rs 流式分支传流式 client，非流分支与 NonDialog 透传保持既有 client。

**理由**：reqwest `ClientBuilder::timeout` 是「请求总时长（含响应体读取）」而非连接超时，长流必然被 30s 截断；Python 原仓对 SSE 无同口径总超时。拆 client 而非改全局超时，保证非流/透传的故障快速失败语义与既有 README §1 口径不变。「启动期构造 + 共享注入」满足 `http-client-singleton` spec（禁止请求路径新建，未要求全进程唯一 client）。

**读空闲超时取值（apply 回写）**：流式 client **不配置** `read_timeout`（默认禁用/无），失活连接依赖 TCP keepalive 回收。理由：本 change 不新增配置项，避免在未实测上游/代理 keepalive 行为前引入可能误杀慢流的阈值；如需读空闲回收另立 change 交付。实现落于 `src/state.rs::build_stream_http_client`，口径同步 README §1/§7.2。

**备选**：全局去掉超时（非流失去 fail-fast，不采用）；流式路径按请求新建 client（违反 `http-client-singleton`，不采用）；仅调大全局超时（长流仍可能被截断，不采用）。

### D4：`T4` content-length 预检 + `bytes_stream` 有界累计

**决策**：JSON 判定/还原前：

1. `up.content_length()` 若 `Some(n)` 且 `status<400` 且 `n > cap` → 立即 502 `response_too_large`（不读 body）；
2. 否则以 `up.bytes_stream()` 累计读取，累计超过 `cap` 且 `status<400` 即停止并 502；
3. `status>=400` 维持现有透传语义；错误体超限的记忆界不在本 change 扩围（记入 Risks）。

**理由**：`bytes()` 无上限，8MB 配置项沦为「事后判定」；`content-length` 预检对声明体最省资源，分块场景必须靠累计截断。`NonDialog` 已用 `bytes_stream()`，同一 API 可复用。

**备选**：仅 content-length 预检（分块绕过，不采用）；读取后判长（现状缺陷，不采用）；引入 `http_body_util::Limited`（新依赖/新适配层，不采用）。

### D5：`T5` 官方子资源显式排除，保留既有宽容语义

**决策**：`lenient_match` 的「父路径 + 额外单段」分支增加排除条件：`v1/messages` 的额外单段为 `count_tokens` 或 `batches` 时返回 `None`；`v1/responses` 的额外单段一律返回 `None`（其额外段均为官方响应对象检索）。严格尾缀与尾斜杠/其余一层宽容语义不变（`/v1/chat/completions/extra` 仍命中并计数）。

**理由**：官方语义中 `count_tokens` 是独立端点（body 形态与响应体均不同）、`GET /v1/responses/{id}` 返回响应对象而非生成调用；误判会导致请求被改写、响应被注入/审计，甚至被合成阻断体替换。相较「收紧为仅尾斜杠宽容」，排除法保留 `llm-gateway` canonical「一层后缀宽容」契约与既有测试，改动面最小。`v1/responses/{id}/cancel`、`input_items` 为两段后缀，现状即 `NonDialog`，无需额外条件。

**备选**：收紧为仅尾斜杠宽容（破坏既有 `protocol.rs` 测试与 canonical 契约，不采用）；维护 URL 前缀白名单（对任意上游域名不可行，不采用）。

### D6：`T6` 非流 JSON 分支改用转义还原变体

**决策**：`src/handler/llm/nonstream.rs:231` 的 `restore_response_with_spans(&vault, &text)` 改为 `restore_response_with_spans_json`（`src/service/redaction/scope.rs:194`），与流式 JSON 帧入口同语义；返回 span 继续供 `redact_response_new_pii_with_skip` 使用（坐标语义一致，均为转义后文本区间）。

**理由**：非流 JSON 体的还原结果必须仍是合法 JSON；字节级直写会在明文含 `"`/`\`/控制字符时破坏 JSON，触发 `:239-249` 的「回退上游原文」分支，客户端拿到的是占位符而非明文——既是正确性缺陷也是可用性回退。流式已用转义变体并经 `guard_restored_frame` 验证；非流复用同一入口可消除双实现漂移。

**备选**：非流保留字节级 + 重解析失败再转义重试（路径复杂、仍先破后修，不采用）；对非 JSON 响应也强制转义（非 JSON 无 JSON 上下文，维持现状）。

### D7：`T7` total 显式优先，缺失时按合并后 prompt+completion 归一

**决策**：`Usage` 合并（`src/service/llm_gateway/usage.rs:92-103`）改为：`prompt/completion/cached_*` 逐列 `max` 不变；`total_tokens` 若任一事件携带显式 total 则取显式值 `max`；若**全部事件均无显式 total**，最终 `total_tokens = max(prompt)+max(completion)`（合并完成后归一）。实现可用「显式 total 标记位」或合并后重算两步；口径写死为「explicit_max else prompt_max+completion_max」。

**理由**：Anthropic 流式 usage 分散在 `message_start.message.usage`（含初始 input 与部分 output）与 `message_delta.usage`（增量 output）；按单事件派生 total 再取 max，会得到 `max(in+1, 0+50)=101`，与真实 `100+50=150` 不符。逐列 max 后求和是「不双计」口径下的自然闭合。

**备选**：完全忽略 single-event 派生 total、仅用 prompt+completion 求和（显式 total 与分列不一致时丢失上游声明，不采用）；对 delta 事件做增量累加（与「max 不双计」口径冲突，不采用）。

### D8：`T8` 跳过分段后可解析段递归 walk

**决策**：`redact_response_new_pii_with_skip`（`src/service/redaction/scope.rs:293-318`）在段处理时，对每个非跳过段先尝试作为完整 JSON 解析并 walk（含 `json_walk::process_text` 的嵌套 stringified JSON 语义）；解析失败时维持现有按文本段处理。跳过段继续字节原样拼接。

**理由**：按还原 span 切段后，工具调用参数（例如 `arguments` 字段的 JSON 字符串）可能整段落在非跳过段内但与切分点错位，导致 `json_walk` 无法识别结构、嵌套内新 PII 漏检。段级「可解析即结构化」是无损增强：不改变跳过段的字节契约，也不影响不可解析段的既有行为。

**备选**：整响应先做一次还原前的新 PII 预扫（会与跳过语义冲突，误掩刚还原明文，不采用）；不处理（保持漏检，不采用）。

### D9：`T10` `x-veil-protocol` 在各响应构造分支统一置位

**决策**：抽公共置头 helper（或等价内联），在 `serve_nonstream` 的以下响应构造点统一追加 `x-veil-protocol`：错误体透传（`:275-277`）、超限 `oversize_response`（`:291-300`）、空体 `empty_body_response`（`src/handler/llm/mod.rs:62`，经非流分支调用）、JSON 后处理（现状保留）。NonDialog 首字节透传分支不额外置位（上游头转发为既有契约）。

**理由**：`x-veil-protocol` 是下游识别网关协议分支的观测契约（`gateway_tests.rs` 已锁定成功分支）；错误/超限路径缺失使观测面断裂。改动为纯增量头，不影响 body/status。

**备选**：只在超限分支补（429/空体仍缺，不采用）；由 middleware 统一兜底（跨路由且会覆盖 NonDialog 透传语义，不采用）。

### D10：`T11` `retrieval_args` 增补官方 `action` 读取

**决策**：`retrieval_args`（`src/service/llm_gateway/tool.rs:109-130`）在顶层 `arguments/input/args` 与 `queries/query` 之间/之前增读 `action` 对象：`action.query` 字符串直取、`action.queries` 数组/其他非 null 值 `serde_json::to_string`；顶层回退保留。`results` 仍排除。apply 阶段先用真实 Responses payload 与官方文档核验 `action` 形态，再锁定读取顺序与测试。

**apply 锁定（读取顺序）**：`arguments/input/args` → `action.query` → `action.queries` → 顶层 `queries/query`；`action` 内 `query`/`queries` 为 `null` 时跳过继续回退。官方形态 `{"type":"web_search_call","action":{"type":"search","query":"..."}}` 已由 `retrieval_args_action_query`、`web_search_action_audit_both_paths`（流/非流双路径）锁定。

**理由**：官方 `web_search_call` 条目的查询在 `action` 内（`{"type":"search","query":...}`），现有实现只看顶层导致查询可能不进审计 hold；audit 宁可误报不可漏审（README §6.5 口径）。`file_search_call` 官方条目既有顶层字段也有 `action` 形态，保留回退可兼容。

**备选**：仅读 `action.query`（legacy/top-level 形态回退丢失，不采用）；在事件分桶处改结构（改动面大于字符串提取，不采用）。

### D11：`T13` 拿头前瞬断统一退避（connect/timeout/request 类）

**决策**：`fetch_upstream_with_retry`（`src/service/llm_gateway/mod.rs:225-238`）的退避条件由 `e.is_connect() || e.is_timeout()` 扩为 `e.is_connect() || e.is_timeout() || e.is_request()`（reqwest 中 `is_request` 覆盖请求层错误：connect/timeout/body/decode/redirect 的请求侧）。非瞬断的「明确业务失败」保留直接 `Err`。退避序列（0.5s→1s→2s）与最多 3 次不变；`Ok(resp)` 后不再重试的边界不变。

**理由**：`send()` 返回 `Err` 意味着响应头尚未到达，请求未向客户端产生任何输出，重试幂等安全（Python 对 `ServerDisconnectedError`/`ClientConnectionError` 即统一退避 3 次）；行中连接 reset 在拿头前多表现为请求层错误，现实现直接 502 弱于 Python。`is_request` 在 reqwest 中即为上述请求侧错误的并集，语义与「拿头前瞬断」一致。

**备选**：枚举 `is_body`/`is_decode` 等其他谓词（`is_request` 已覆盖，冗余）；把 `Err` 全部重试（含无法判定的非瞬断错误，扩大副作用，不采用）。

### D12：`T14` 判序保持 canonical，差异文档化

**决策**：不改 `src/handler/llm/nonstream.rs:155-158` 的判序与状态门（`classify_empty` 先算、`status<400` 且 `len > cap` 超限动作先于空体 502；canonical `runtime-parity-limits` 已锁「先判空体（分类）、再判超限（动作）」与「错误状态超限不改写」）。在 design 与 README §4/§7.2 记录与 Python `_llm.py:2936-2944` 的观测差异：Python `_is_nonstream_oversize` 无状态门、在 oversize 分支设 `metrics_ctx['status']=502` 并 warning，本仓超限分支无独立指标/日志。补 `len>8MB` 非 JSON 200 体用例锁定 502 `response_too_large`（不走空体 502）。

**理由**：canonical spec 已把 Rust 口径（含错误状态豁免，与 N2/D6 错误体透传一致）定为契约；Python 无状态门会改写错误体，属已知有意偏离。差异仅在指标/日志观测面，改代码风险大于收益，故选择「文档化」。

**备选**：对齐 Python（去掉状态门并补 metrics/日志）——与 canonical `runtime-parity-limits`「错误状态超限不改写」冲突，需改 canonical，不采用；保持沉默（审计可追溯性差，不采用）。

### D13：`T9`/`T12` 记录项处理

- **`T9` 转出**：NonDialog `NonstreamOutcome::Stream` 死臂（`src/handler/llm/dispatch.rs:180-219`、`src/handler/llm/nonstream.rs:96`）由 change `veil-arch-hygiene-closeout` H11 承接；本 change 不触碰 `dispatch.rs` 该分支，仅在覆盖表与 design 本条交叉引用。
- **`T12` 契约引用与 query 语义**：NonDialog 字节透传口径以 **README §7.6** 为文档契约；`T1` 落地后 README §7.6 已补「入站 query 保序保编码随 path 一并转发、不改写 body、不触发审计/用量」语义（与 §5「任意 `/{tail}` 透传」一致，消除漂移）。实现真相源为 `src/handler/llm/dispatch.rs::build_upstream_url`：query 取 `Uri::query()` 原始切片，按「path + `?` + raw query」拼接，保序保 `%` 编码与 `+` 形态，无 query 不加 `?`，基址自带 query 以 `&` 合并（详见 D1）。

## Risks / Trade-offs

- [`T1` query 拼接与上游基址含 query] → 基址配置若自带 `?x=y`，简单拼接会产生两个 `?`。缓解：apply 阶段对基址做断言/规范化（去尾 `?`/剥 query 或明确禁止），并在测试中覆盖基址含 query 的边界。
- [`T2` 转头上游头引入安全面] → 上游恶意头（如伪造 `x-veil-normalized`）可能误导下游。缓解：`x-veil-*` 由网关在过滤后覆盖写入；hop 过滤沿用既有单向口径。
- [`T3` 流式无总超时导致连接泄漏] → 上游半死连接可能长期占用。缓解：配置读空闲超时（待 apply 实测选值）或依赖 TCP keepalive；风险记入 Open Questions。
- [`T4` 错误体仍可全量读入] → `status>=400` 大错误体不受 cap 约束（canonical 语义），仍有 OOM 面。缓解：`content-length` 预检可扩展为「错误体超阈值直接透传流式转发（不缓冲）」的后续任务；本 change 记录为已知残余风险。
- [`T5` 排除法遗漏未来官方子资源] → 新子资源可能再次误判。缓解：spec 以「额外段默认 NonDialog（除既有宽容形态）」为原则表述不如实现显式；apply 阶段补注释与清单，review 时按官方目录复查。
- [`T6` 转义还原改动非流输出字节] → 明文含特殊字符时输出形态变化（从截断回退变为正确转义）。属修正预期，README §7.7 的字节保真声明不受影响（零替换仍字节透传）。
- [`T7` total 归一规则改动统计口径] → 依赖旧派生 total 的大盘数值会变化。README §7.2 补一句「total 显式优先，缺失时 prompt+completion 合并后求和」。
- [`T13` 扩宽重试增大上游压力] → 对持续瞬断的上游多 3 倍请求。缓解：仍限 3 次、仅拿头前、指数退避；README §7.2/`llm-gateway` canonical「拿头前 3 次」不变。
- [`T14` 差异仅文档化] → 观测面与 Python 不同步。缓解：design/README 显式记录，监控口径差异可查。

## Migration Plan

1. 按 tasks 顺序落地：先请求/响应保真（`T1`/`T2`/`T10`），再超时与容量（`T3`/`T4`），再协议与还原（`T5`/`T6`），再口径与审计（`T7`/`T8`/`T11`），再重试与判序（`T13`/`T14`），最后记录与门禁。
2. 每组独立 `cargo test -p veil <组>`；README §5/§7.2/§7.6 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；下游可感知的变化（query 转发、响应头透传、长流不再截断、官方子资源改判透传、审计查询字段补齐）由 README 与 spec 声明。

## Open Questions

- `T3` 流式 client 读空闲超时：**已决（apply 回写）**——不配置（默认禁用/无），失活连接依赖 TCP keepalive；本 change 不新增配置项，如需读空闲回收另立 change。口径见 D3 与 README §1/§7.2。
- `T11` 官方 `web_search_call`/`file_search_call` 的 `action` 精确形态（是否含 `queries`、`sources`、`url` 等）：apply 阶段用真实 Responses payload 与官方文档核验后锁定读取顺序与测试；核验结论回写 design D10。
- `T5` 是否需要在 `llm-gateway` canonical spec 归档期同步「官方子资源默认 NonDialog」措辞：待 apply 落地后随归档流程评审。
