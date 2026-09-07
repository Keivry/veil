## Why

credential-proxy（Python aiohttp，v0.9.47）已演进为 Mixin 堆叠架构（`proxy.py` 主类组合 `_credential` / `_token` / `_pii` / `_llm` / `_audit` / `_metrics` / `_admin` / `_matrix` / `_registry` / `_tpm` / `_sse` 共 11 个 Mixin），带来三类结构性问题：

- **Mixin 隐式耦合**：跨 Mixin 共享可变状态靠 `self.xxx` 约定（如 `pii_scope`、`audit_hold`、`tool_calls_pending_events`、`bytes_written`），无类型边界。v0.9.6 被迫把每请求状态迁往 `ContextVar` 仍是补丁式收敛；`_strip_partials` 漏接 7 处出口（Round 17 R4）、`audit_cb` 未传参（Round 15 F-03）等接线缺陷反复出现，根因是 Mixin 间无显式接口契约。
- **GIL / 单进程性能**：PII 联合正则扫描约 90ms/MB、大 body 逐 recognizer 扫描、流式增量扫描与 `run_in_executor` 线程池混用（ReDoS 守卫独占小池），单进程吞吐受 GIL 与事件循环阻塞制约；`_snapshot` 跨线程裸读需事后加锁快照（v0.9.40），并发模型脆弱。
- **错误处理缺失**：Python 侧大量 `try/except` 兜底 + `logger.warning` 继续，與 Rust 的 `anyhow` / `thiserror` 式结构化错误（错误链、分类、可观测打点）不等价；`ENOSPC` 降级内存-only、`QueueFull` 丢快照等路径靠散落分支实现，无统一错误类型。

同时累积了**三协议合规债**（chat/completions、anthropic messages、responses 三协议并行演进留下）：

1. **HOP 头不全**：`_sse.py` 逐跳头过滤清单缺口，上游 `connection` / `keep-alive` / `transfer-encoding` 等逐跳头可能透传下游，违反 HTTP/1.1 逐跳语义。
2. **Chat 阻断缺 `[DONE]` 嫌疑**：审计阻断注入（`_build_block_event`）后是否补发 `data: [DONE]` 各路径不一致，下游 Hermes 可能把阻断流误判为截断而重试或挂起。
3. **tool 提取丢 id / 漏 legacy 形态**：`_extract_tool_calls_non_stream` 与流式累积只认新形态，`function_call` legacy 形态、`tool_calls[].id` 在部分路径丢失，审计看到的 args 与下游执行的不一致。
4. **`is_chat_tail` 宽容匹配无观测**：尾缀判定容忍一层自定义后缀但无日志无指标，非对话请求（`v1/models` 等）一旦误判即污染统计口径（v0.9.35 BREAKING 之后仍靠约定）。
5. **请求改写字节不等**：`separators=(',', ':')` 空白压缩与 `ensure_ascii=False` 的 `\uXXXX` 明文化属语义等价但字节不等价，下游签名 / 缓存键 / 对账场景可能断裂，且无显式契约声明。
6. **`conv_id` 缺 `incomplete` / `error`**：`_extract_conv_id` 只认成功形态，`response.incomplete` / `response.failed` / 错误事件的会话 id 丢失，`CREDENTIAL_PROXY_DEBUG_DIR` 落盘与审计关联断链（v0.9.7 只补了 `data.response.id` 一处）。

## What Changes

用 Rust（axum + tokio + reqwest + rusqlite）分层重写 veil，替代 Mixin 堆叠为显式分层（`router` / `handler` / `service` / `state` / `error`），全量覆盖原路径逻辑与 42 个测试文件移植，并在重写中一次性结清上述 6 项协议修正：

- **修正 1，HOP 头过滤补全**：修正前仅过滤部分逐跳头；修正后按 RFC 9110 逐跳清单（`connection`、`keep-alive`、`proxy-authenticate`、`proxy-authorization`、`te`、`trailer`、`transfer-encoding`、`upgrade` + `connection` 头内列名的动态项）双向过滤，大小写不敏感，过滤动作记 `hop_filtered_total{dir}` 指标。
- **修正 2，Chat 阻断统一补 `[DONE]`**：修正前阻断注入后 `[DONE]` 有无不定；修正后 chat/completions 阻断包恒以 `data:[DONE]` 恰 1 个收尾（anthropic 补 `content_block_stop` + `message_delta` + `message_stop`、responses 阻断补 `response.completed`、截断补 `response.failed`），并在 `stream_meta` 记录 `terminal_injected=true`，下游一律视为正常结束不再重试。
- **修正 3，tool 提取保 id + 兼容 legacy**：修正前 `id` 在部分路径丢失、`function_call` 不识别；修正后统一提取器保留 `id`（缺失时按 `index` 合成 `call_stable_<index>` 并标记 `id_synth=true`），同时识别 `message.function_call` / `delta.function_call` legacy 形态并归一为标准 tool_calls，审计读归一后原文。
- **修正 4，`is_chat_tail` 判定可观测**：修正前宽容匹配静默生效；修正后保留一层后缀宽容但每次宽容命中记 `chat_tail_lenient_total{tail}` 并在 debug 日志留痕，`/_admin/metrics` 暴露该计数，非对话请求误判可被发现。
- **修正 5，请求改写字节契约显式化**：修正前静默压缩空白；修正后默认保持字节等价（仅替换 token 子串，不重排 JSON），`normalize_json_whitespace=1` 显式开启才允许压缩，且开启时在响应头 `x-veil-normalized:json-whitespace` 声明，签名场景默认安全。
- **修正 6，`conv_id` 覆盖 incomplete / error**：修正前仅成功事件提取；修正后提取器覆盖 `response.incomplete` / `response.failed` / `error` 事件的 `id`（含 `data.response.id` 单层与双层回退），提取失败记 `conv_id_missing_total{reason}`，debug 落盘按 `unknown_<hash8>` 归档不断链。

## Capabilities

### Modified Capabilities（平价行为为主）

- `rust-credential-api`（Modified）：7 凭据路由 + 三因子（`X-Get-Binary-Hash` + `X-Get-Binary-Secret` header 兼容 `body.secret` + `body.auth.caller_hash` / `caller_path`）+ 自动放行三态 `True` / `False` / `None`（hash_mismatch 转 Matrix）+ caller 注册表（`caller_registry.json` + `sha256` 完整性 + 原子 rename，继承原行为，`hmac.compare_digest` + SHA256 绑定，0600 文件权限）+ 凭据审批 300s（审计 90s 见下，`AUDIT_TIMEOUT` 禁 110-130）
- `rust-llm-gateway`（Modified）：三协议反向代理（chat / anthropic / responses）+ SSE slow/fast 双路径 + 审计 hold 挂起与 fail-closed + 截断三态 `silent_discard` / `open_ended` / `synthesized_failed`（仅 responses）记 `stream_meta.truncated_mode` 并落 metrics
- `rust-redaction`（Modified）：凭据 token（`__VG_CRED_NNNNNN__`）+ PII（`__PII_<seq>_<rand8>__` CSPRNG）+ JSON-walk（嵌套串、BOM、转义、残缺清理）+ 6 recognizer 联合正则（lookaround 中文边界禁 `\b`、Luhn/GB 校验位、豁免清单、ReDoS 100ms / 连续 3 次停用 / 独立池、字典独立扫描）
- `rust-audit-tpm-matrix`（Modified）：输出审计 block/approve（默认 off）+ JSONL 审计日志（10MB x 5 轮转，0600，先脱敏后截断，剥离 `\x00-\x1f`，写失败双层 fail-closed）+ TPM 强制硬件（TPM 不可用 SHALL 启动失败，MUST NOT 软件回退）+ Matrix 五分支（解锁 / 注册 / 哈希变更 / 凭据 / 审计，`✅` / `❎` / `🔓` 映射）
- `rust-observability-admin`（Modified）：指标聚合（内存环 10k + daily 30 天 / hourly 7 天 / 5min 覆盖 UPSERT，仅对话计数，12 桶 p95，`is_precise` 语义）+ 6 admin 路由唯一表（`/_admin/`、`/_admin/health`、`/_admin/metrics`、`/_admin/series`、`/_admin/events`、`/_admin/events/stream`）+ 鉴权（`X-Admin-Token` > `__Host-admin_token` Cookie > `?access_token` 仅 SSE，非 SSE 带 query 恒 401，HMAC 等长比较，限流按 remote 不读 XFF，通用 10/min/IP 超限 429 + `Retry-After`，SSE 5/IP 并发 + 60s ping + 5min 强制重连）+ SSE 实时推送
- `rust-protocol-compliance-fix`（Modified）：6 项协议修正 FIX-1 至 FIX-6（HOP RFC 9110 全集 + `Connection` 动态项 + `reqwest` 编解码配对、`[DONE]` 终止闭合、tool 三元组 + legacy、`is_chat_tail` 唯一判定 + 宽容可观测、字节契约、conv_id 全覆盖），详见 protocol-compliance-fix spec

### New Capabilities（仅新增可观测项）

- `terminal_injected`：阻断/合成终止注入标记（`stream_meta.terminal_injected=true`，FIX-2 新增）
- `x-veil-normalized`：`normalize_json_whitespace=1` 重写声明头（`x-veil-normalized:json-whitespace`，FIX-5 新增）
- `conv_id_missing`：`conv_id_missing_total{reason}` 缺失计数 + `unknown_<hash8>` 归档（FIX-6 新增）
- `chat_tail_lenient`：`chat_tail_lenient_total{tail}` 宽容命中计数 + debug 日志（FIX-4 新增）
- `hop_filtered`：`hop_filtered_total{dir}` 过滤计数（FIX-1 新增）

## Impact

- **修改文件**：veil 全新建（`src/` 分层模块：`router` / `handler` / `service` / `state` / `error` / `config`、`Cargo.toml` 依赖 pin、`Dockerfile` 多阶段构建、`docker-compose.yml`、`admin.html` 复用、`openspec/changes/rust-rewrite-veil/` 提案与任务）。**不改动 credential-proxy 原仓任何文件**。
- **Cargo 依赖 pin**：`axum`、`tokio`、`reqwest`（编解码开关配对）、`rusqlite`（WAL）、`serde` / `serde_json`、`tracing`、`thiserror`、`anyhow`、`moka`（全局凭据 LRU）、`rand`（`OsRng`）、`hmac`，版本在 `Cargo.toml` 精确 pin，`Cargo.lock` 入库。
- **env 全表**：`HOMESERVER` / `ROOM_ID` / `MATRIX_ACCESS_TOKEN` / `OBSERVABILITY_ADMIN_TOKEN`（必填，缺失拒启动；`OBSERVABILITY_ADMIN_TOKEN` 独立不得复用业务 token）/ `AUDIT_TIMEOUT`（禁 110-130）/ `AUDIT_POLICY_FILE` / `PII_HOLD_MAX` / `AUDIT_HOLD_MAX_BYTES` / `DATA_DIR` / `LLM_<PORT>` 端口映射 / `normalize_json_whitespace`（默认关闭，`1` 开启重写）/ `PII_VALUE_SAMPLE_ENABLED` / `PII_VALUE_SAMPLE_PERSIST` / `PII_VALUE_SAMPLE_HMAC_KEY`。
- **API 兼容承诺**：7 凭据路由（`POST /credential`、`GET /health`、`GET /registrations`、`POST /register-caller`、`POST /revoke`、`POST /revoke/emergency`、`POST /approve-hash-change`）+ 通配 LLM（`chat/completions`、`v1/messages`、`v1/responses` 三协议 + 非对话透传）+ 6 admin 路由（`/_admin/`、`/_admin/health`、`/_admin/metrics`、`/_admin/series`、`/_admin/events`、`/_admin/events/stream`）保持路径、状态码、SSE 帧语义字节兼容；除 6 项修正声明的行为外，其余字节语义与 v0.9.47 一致。
- **测试**：42 个 `*_test.py` 移植矩阵（见 tasks.md 第 8 章映射表），含 `sentinel_{chat,anthropic,responses}.jsonl` 录制回放与 `api_spec_conformance` 真实 SDK（openai/anthropic）对照。
- **部署**：Docker 多阶段构建（builder + runtime 瘦镜像）+ compose 回环三端口对等（`127.0.0.1:8877/8878/8879`），`DATA_DIR` / TPM / KeePass 卷挂载与原仓一致；`ruff check + format` 对应为 `cargo fmt --check + cargo clippy -- -D warnings` 门禁。
