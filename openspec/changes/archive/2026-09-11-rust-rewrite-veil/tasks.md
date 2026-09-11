## 1. 脚手架与 fail-closed 配置

- [x] 1.1 初始化 Cargo 工程（axum + tokio + reqwest + rusqlite + serde + tracing），分层目录 `src/{router,handler,service,state,error,config}` 落定
  - 验收：`cargo build` 通过；模块边界单向依赖（handler 只调 service，service 只读 state）
- [x] 1.2 统一错误类型（`thiserror` 分类 + `anyhow` 上下文链），映射 HTTP 状态码（认证 403 / 上游透传 / 空体 502）
  - 验收：每类错误有唯一 `code` 并进日志字段；未知错误默认 500 不泄漏内部细节
- [x] 1.3 配置加载 fail-closed：缺必填项（`HOMESERVER` / `ROOM_ID` / `MATRIX_ACCESS_TOKEN` / `OBSERVABILITY_ADMIN_TOKEN`）直接拒绝启动；非法值（`AUDIT_TIMEOUT` 为 0/负/110-130、`PII_HOLD_MAX` 非正整数、approve 无白名单）启动报错
  - 验收：非法配置单测全绿；启动报错信息指明变量名与合法区间
- [x] 1.4 rusqlite 初始化（WAL + `busy_timeout=5000` + `synchronous=NORMAL` + `user_version`），文件及 `-wal`/`-shm` 均 0600（`umask 0o077`）
  - 验收：权限断言测试通过；`ENOSPC` 时降级内存-only 且 `health.sqlite_ok=false`，进程不崩

## 2. 凭据 API（7 路由 + 三因子 + 注册表）

- [x] 2.1 实现 7 路由：`POST /credential`、`GET /health`、`GET /registrations`、`POST /register-caller`、`POST /revoke`、`POST /revoke/emergency`、`POST /approve-hash-change`
  - 验收：路由级单测覆盖 7 路径状态码；与原仓路径拼写逐字一致
- [x] 2.2 三因子认证（`X-Get-Binary-Hash` + `X-Get-Binary-Secret` header 兼容 `body.secret` + `body.auth.caller_hash` / `caller_path`，`hmac.compare_digest` 时序安全比较；空配置仅未 enrolled 放行且 Secret 仍校验；自动放行三态 `True` / `False` / `None`；`caller_hash==GET_BINARY_HASH` 拒 403）
  - 验收：三因子缺一即 403；伪造 secret / `caller_hash==GET_BINARY_HASH` 直调 `--raw` 被拒绝 403
- [x] 2.3 Caller 注册表（`caller_registry.json` + `sha256` 完整性 + 原子 rename，继承原行为，脚本 SHA256 绑定，哈希变更走 Matrix 审批，`--script-path` 注册）
  - 验收：注册/匹配放行/篡改拦截/吊销/紧急吊销全路径覆盖；篡改后需重新审批
- [x] 2.4 轻量入口对等（`credential-proxy-only` 自动批准语义、`llm-proxy-only` 纯代理，approve 在轻量入口降级 block 并告警）
  - 验收：轻量入口配 approve 时明确告警降级，不静默忽略

## 3. 脱敏（token / PII / json-walk）

- [x] 3.1 凭据 token（`__VG_CRED_NNNNNN__` 全局映射 + 请求级作用域，`_strip_partials` 残缺清理接全出口，幻觉完整 token 剥离）
  - 验收：残缺前缀不泄漏；模型幻觉完整 token 被剥离；非流式与流末残余出口语义与流式一致
- [x] 3.2 PII 检测器（对应 redaction spec SHALL：6 内置 recognizer 手机号/身份证/银行卡/邮箱/IP/API 密钥 + 联合正则 + lookaround 中文边界禁 `\b` + Luhn/GB 校验位 + 保留豁免清单 + 自定义正则 ReDoS 100ms 独立池 + 连续 3 次超时停用 + 字典独立扫描 + CJK 边界）
  - 验收：每种类型命中/误报对照全绿；`^(a+)+$` 恶意模式 100ms 内拦截；含 `\b` 正则拒绝加载
- [x] 3.3 请求级 PII token（`__PII_<seq>_<rand8>__`，`rand8` 用 CSPRNG，空洞跳过稳态下标，同值复用，响应期注册不进请求还原表）
  - 验收：同值复用同一 token；PII 还原不触达全局凭据映射；并发注册无下标冲突
- [x] 3.4 json-walk（嵌套 stringified JSON 递归、顶层叶节点 loads→walk→dumps、`\ufeff` BOM 剥离、`p@ss"quote` / `\u` 转义安全、len>1M / depth>5 守卫回退 plain）
  - 验收：嵌套 `tool_calls.arguments` 特殊字符回归用例全绿；超限输入回退不崩

## 4. LLM 网关（三协议 + SSE 双路径 + 审计 hold）

- [x] 4.1 三协议反向代理（`chat/completions`、`v1/messages`、`v1/responses` + 非对话透传），`LLM_<PORT>` 端口映射，上游重试（仅拿头前重试最多 3 次，指数退避 0.5s→1s→2s，中段断连走 fail-closed 丢弃注入不重试）
  - 验收：三协议非流式整包还原正确；非流式 usage 同流式口径捕获（responses 单层 `response.usage` + Anthropic `message.usage`）；上游拿头前瞬断重试后成功，中段断连不重试走 fail-closed；空体 502 四分支一致（流式空流注入转 502 / 非流式空体非 JSON 转 502 / `502`/`401` 透传不改写 / 非对话豁免）；协议分发冲突时 tail 优先于 Content-Type
- [x] 4.2 SSE slow/fast 双路径（WHATWG 切行、`data:`/`event:` 行级还原、16KB/30s 行缓冲兜底、10s keepalive 注释、`byte_buf` 残余 `json-aware`）
  - 验收：跨分片 token 还原正确（含 UTF-8 半字符按字节缓冲 + IncrementalDecoder 组装，不逐 chunk replace 解码）；slow/fast keepalive 对齐（10s 注释，不计 `sse_event`）；截断三态唯一值 `silent_discard` / `open_ended` / `synthesized_failed`（仅 responses）记 `stream_meta.truncated_mode` 并落 metrics
- [x] 4.3 审计 hold（tool call 全程缓冲至 verdict 前不 flush，`AUDIT_HOLD_MAX_BYTES` 超限 fail-closed 拒绝，挂起期新危险调用一律拒绝）
  - 验收：审批 keepalive 句柄 per-request 持有不跨请求共享，首包即挂起亦保活；未出 verdict 无 tool call 事件流出；超限按 rejected 注入拒绝且 pending 清理
- [x] 4.4 阻断注入（与 FIX-2 同字：chat 阻断恒以 `data:[DONE]` 恰 1 个收尾；anthropic 补 `content_block_stop` + `message_delta` + `message_stop`；responses 阻断补 `response.completed`、截断补 `response.failed`；合成块必须带 `event:` 行）
  - 验收：阻断后无 dangling tool_use 块；三协议终止事件形态断言全绿；合成块含 `event:` 行

## 5. 协议合规修正（6 项，每项独立任务）

- [x] 5.1 HOP 头过滤补全（RFC 9110 全集双向过滤 + `Connection` 内列名动态项，大小写不敏感 + `reqwest` 编解码开关配对）
  - 验收：含逐跳头的上游响应经代理后无残留；`hop_filtered_total{dir}` 计数递增
- [x] 5.2 Chat 阻断统一补 `[DONE]`（与 FIX-2 同字：chat 阻断/空流恒以 `data:[DONE]` 恰 1 个收尾；anthropic 补 `content_block_stop` + `message_delta` + `message_stop`；responses 阻断补 `response.completed`、截断补 `response.failed`；合成块必须带 `event:` 行；`stream_meta.terminal_injected=true`）
  - 验收：阻断流下游 Hermes 不再重试；三协议终止事件形态断言全绿
- [x] 5.3 tool 提取保 id + legacy 兼容（保留 `id`，缺失合成 `call_stable_<index>` 标 `id_synth=true`，识别 `message.function_call` / `delta.function_call` legacy 与 `custom_tool_call` 归一为 `(id, name, args)`）
  - 验收：legacy `function_call` 危险调用被审计拦截；`id` 缺失场景审计与转发一致；非 string args 规范化为 JSON 串（dict `dumps`，缺失记告警不断链，不静默置空透传）
- [x] 5.4 `is_chat_tail` 可观测宽容匹配（全协议唯一判定，禁内联 `endswith` B1 审计旁路；一层后缀宽容保留 + `chat_tail_lenient_total{tail}` 计数 + debug 留痕）
  - 验收：宽容命中在 `/_admin/metrics` 可见；`v1/models` 非对话请求不计入统计
- [x] 5.5 请求改写字节契约（与 FIX-5 同字：默认仅子串替换不重排 JSON；`normalize_json_whitespace=1` 开启才允许 `dumps` 重写并带 `x-veil-normalized:json-whitespace`）
  - 验收：默认关闭下请求体除 token 替换外字节一致；开启后声明头存在
- [x] 5.6 `conv_id` 全覆盖（`response.incomplete` / `response.failed` / `error` 事件单双层 id 提取，失败记 `conv_id_missing_total{reason}` 并按 `unknown_<hash8>` 归档；header 注入与 body 字节等价冲突显式豁免）
  - 验收：incomplete/error 场景 debug 落盘不断链；缺失计数可观测

## 6. 审计 / TPM / Matrix

- [x] 6.1 策略引擎（对应 audit-tpm-matrix spec SHALL：审计三模式默认 off + 危险模式规则：危险 shell、敏感路径写入、网络外传；参数规范化：空白合并、`\uXXXX`/`\xXX` 转义、拆链、单层变量展开、别名折叠、`..` O(n) 规范化；`AUDIT_POLICY_FILE` 加载 + `examples/audit-policy.yaml` 示例。Non-Goal：策略文件热重载不做，改配置重启生效）
  - 验收：规范化命中对照用例全绿；`find --delete` O(n) 无回溯；非法策略文件启动报错
- [x] 6.2 阻断与审批模式（block 直接拦截；approve 复用 Matrix pending/超时：凭据 300s / 审计 90s（`AUDIT_TIMEOUT` 禁 110-130），默认拒绝；白名单 MXID 正则 + 发送者校验 + event id 精确匹配 + 幂等 + reaction 精确匹配，`_ask` 返回 None 立即 rejected 并清理；接线：`AppState.approval` 持网关（白名单/`AUDIT_TIMEOUT` 来自 Config），`record_pending` 建单 submit + Bot best-effort 发送后立即 202，问询经 `await_credential_approval`（300s）/`await_audit_approval`（90s 口径），`main` 常驻 60s 孤儿清扫）
  - 验收：审批通过/拒绝/超时/发送失败四路径全绿；非白名单 reaction 被忽略；孤儿 pending 60s 清扫回收；建单落网关 + 凭据300s/审计90s 分表口径单测全绿
- [x] 6.3 审计日志（`DATA_DIR/audit.log` JSONL：先脱敏后截断摘要、零明文、`\x00-\x1f` 剥离、0600、10MB x 5 轮转、写失败双层 fail-closed + 熔断计数）
  - 验收：日志行合法单 JSON；响应期新 PII 明文不落盘；`block` 仍阻断、`off` 不阻断
- [x] 6.4 TPM 强制硬件（trait 化 `TpmUnlock`：真实 TPM 实现 + CI 用 mock TPM；TPM 不可用 SHALL 启动失败，MUST NOT 软件回退；接线：`main` 启动链经 `startup_tpm` 门禁 fail-closed，默认真实 TPM，`VEIL_ALLOW_MOCK_TPM=1` 仅 CI/本地联调显式放行。Non-Goal：KeePass 真实 kdbx 后端 + 主密钥 TPM 派生随占位延后（`MockKeePass` 边界与生产风险见 credential-api spec KeePass 条））
  - 验收：CI 用 mock TPM 全绿；TPM 不可用启动失败；无软件回退验收项；`startup_tpm(true)` 放行 / 无硬件 `startup_tpm(false)` 失败单测全绿
- [x] 6.5 Matrix Bot（五分支解锁/注册/哈希变更/凭据/审计，标识 `✅`/`❎`/`🔓`；凭据审批白名单与审计同规则：MXID 正则 + 发送者校验 + event id 精确匹配 + 幂等；解锁与注册审批消息不含明文密钥/PII）
  - 验收：Matrix 集成测试（真实 reaction 路径）通过；审批摘要无明文

## 7. 可观测 / _admin

- [x] 7.1 指标聚合（内存环 10k + rusqlite 日/小时聚合，覆盖式 UPSERT 不翻倍，仅对话端点计数，延迟 12 桶 p95 近似，`is_precise` 标记；`truncated_mode` 三态按 mode 分标签计数）
  - 验收：重启后 1h/24h 口径断言正确；`other` 桶不再含非对话数据；非流式 usage 同流式口径计入（responses 单层 `response.usage` + Anthropic `message.usage`）；快照/ring/覆盖 UPSERT 为继承行为不重定义；`truncated_mode` 三态分标签计数可观测
- [x] 7.2 6 admin 路由（唯一表 `/_admin/`（JSON 索引占位终态，独立 admin.html 为 Non-Goal，见 observability-admin spec）、`/_admin/health`、`/_admin/metrics`、`/_admin/series`、`/_admin/events`、`/_admin/events/stream`），鉴权（`X-Admin-Token` > `__Host-admin_token` Cookie > 仅 SSE 的 `?access_token`，非 SSE 带 query token 恒 401，HMAC 等长比较；token 名映射：服务端环境变量 `OBSERVABILITY_ADMIN_TOKEN` → 客户端请求头 `X-Admin-Token`），限流（10/min/IP 429 + Retry-After，SSE 5 并发/IP + 60s ping + 5min 强制重连）
  - 验收：鉴权优先级与 401 语义单测全绿；限流按直连对端 IP 计数（不读代理头）
- [x] 7.3 摘要脱敏单一路径（对应 observability-admin spec SHALL：`redact→truncate` 先脱敏后截断，`__PII__`/`__VG_CRED__`/`sk-`/email → `[REDACTED:*]`，UTF-8 半字符保护，`_SECRET_PATTERNS` 覆盖 JSON 键形态。Non-Goal：采样 hover 展示归 7.4，不在本任务）
  - 验收：`{"password":"hunter2"}` 落盘形态为脱敏后；控制字符不产生伪造条目
- [x] 7.4 PII 值级掩码采样（对应 observability-admin spec sqlite 口径：默认关闭，`PII_VALUE_SAMPLE_ENABLED/PERSIST/HMAC_KEY`，掩码当场生成明文不出作用域，仅 `is_chat_tail` 触发，7 天滚动。Non-Goal：关闭时仅计数不落采样）
  - 验收：关闭时仅计数；开启后 hover 展示掩码 TopN 且 hash 为 HMAC 口径

## 8. 移植验证

- [x] 8.1 sentinel 录制回放（`scripts/sentinel_record.py` 移植为 Rust 版，对 `sentinel_{chat,anthropic,responses}.jsonl` `--check` 回放，覆盖截断/空流/坏 JSON/断连形态）
  - 验收：三份 sentinel 在 Rust 网关下 `--check` 全绿；空流按协议注入最小可解析 SSE 而非空体
- [x] 8.2 `api_spec_conformance` 真实 SDK 对照（openai SDK + anthropic SDK 官方包直连 Rust 网关：三协议流式/非流式/tool call/阻断语义；SDK 版本在 `Cargo.toml` / 对照脚本 pin 并记录）
  - 验收：真实 SDK 下三协议用例全绿；拒绝消息客户端可解析
- [x] 8.3 门禁线（`cargo fmt --check` + `cargo clippy -- -D warnings` 全绿，对应原仓 `ruff check + ruff format --check`；`cargo test` 全绿对应 `pytest` 全绿）
  - 验收：CI 三门禁全绿；clippy 零警告
- [x] 8.4 42 文件移植映射表（原 `tests/*_test.py` @ 源 commit pin → Rust 内联单测（`src/**/tests`）+ 集成（`tests/`）+ 脚本（`scripts/`），逐项勾选，遗漏即 fail；sentinel 路径 `sentinel_{chat,anthropic,responses}.jsonl`；openai/anthropic SDK 版本随表 pin）
  - 验收：下表 42 项全部勾选且对应 Rust 测试通过（勘误：下表 `src/service/llm_gateway/mod.rs` 均指现 `src/service/llm_gateway/mod.rs`，单文件已拆为子模块目录，语义不变）

| # | 原文件（@ 源 commit pin，随表锁定） | Rust 对应（内联单测 `src/**` / 集成 `tests/` / 脚本 `scripts/`；sentinel 路径见 8.1，openai/anthropic SDK 版本见 8.2 pin） | 状态 |
|---|--------|----------------|------|
| 源 commit pin | 全表 `tests/*_test.py` 锁定同一源 commit（填写后冻结） | `SRC_PIN=46f6ff665c869b02c154c10df431c638c2177fd9` | - [x] |
| sentinel 路径 | `sentinel_{chat,anthropic,responses,v1_models}.jsonl`（8.1 回放） | `tests/fixtures/sentinel_*.jsonl` + `tests/sentinel_check_tests.rs` | - [x] |
| SDK 版本 pin | openai SDK / anthropic SDK（8.2 对照） | `scripts/api_conformance.py` 头注 + `scripts/README.md`（openai==3.5.0 / anthropic==1.1.0） | - [x] |
| 1 | `token_test.py` | `src/service/credential_vault.rs` 内联单测 | - [x] |
| 2 | `credential_test.py` | `src/service/mod.rs` + `src/router.rs` 内联单测 | - [x] |
| 3 | `matrix_test.py` | `src/service/matrix.rs` 内联单测 | - [x] |
| 4 | `llm_test.py` | `src/service/llm_gateway/mod.rs` + `src/service/sse.rs` 内联单测 | - [x] |
| 5 | `llm_truncation_test.py` | `src/service/sse.rs` 内联单测（截断三态同口径） | - [x] |
| 6 | `llm_truncation_realdata_test.py` | `src/service/sse.rs` 内联单测（截断三态同口径） | - [x] |
| 7 | `llm_empty_coverage_test.py` | `src/service/llm_gateway/mod.rs` + `src/service/block_inject.rs` 内联单测 | - [x] |
| 8 | `sse_stream_loop_test.py` | `src/service/sse.rs` 内联单测 | - [x] |
| 9 | `stream_restore_lock_test.py` | `src/service/sse.rs` 内联单测 | - [x] |
| 10 | `usage_capture_responses_test.py` | `src/service/llm_gateway/mod.rs` 内联单测（`extract_usage`） | - [x] |
| 11 | `pii_test.py` | `src/service/pii.rs` 内联单测 | - [x] |
| 12 | `pii_token_test.py` | `src/service/pii.rs` + `src/service/redaction.rs` 内联单测 | - [x] |
| 13 | `pii_llm_test.py` | `src/service/redaction.rs` 内联单测 | - [x] |
| 14 | `pii_stream_integration_test.py` | `src/service/redaction.rs` + `src/router.rs` live 用例 | - [x] |
| 15 | `pii_concurrency_test.py` | `src/service/pii.rs` 内联单测 | - [x] |
| 16 | `pii_ipv6_time_test.py` | `src/service/pii.rs` 内联单测 | - [x] |
| 17 | `pii_value_samples_test.py` | `src/service/metrics.rs` 采样器内联单测 | - [x] |
| 18 | `pii_regression_fix_test.py` | `src/service/pii.rs` 内联单测 | - [x] |
| 19 | `pii_placeholder_prompt_test.py` | `src/service/llm_gateway/mod.rs` 内联单测 | - [x] |
| 20 | `pii_placeholder_prompt_integration_test.py` | `src/service/llm_gateway/mod.rs` 内联单测 | - [x] |
| 21 | `detection_hardening_test.py` | `src/service/pii.rs` 内联单测 | - [x] |
| 22 | `residual_hardening_test.py` | `src/service/sse.rs` + `src/service/redaction.rs` 内联单测 | - [x] |
| 23 | `redact_extra_test.py` | `src/service/metrics.rs`（摘要脱敏）内联单测 | - [x] |
| 24 | `vault_stable_test.py` | `src/service/credential_vault.rs` + `src/service/pii.rs` 内联单测 | - [x] |
| 25 | `audit_test.py` | `src/service/audit.rs` 内联单测 | - [x] |
| 26 | `audit_hook_test.py` | `src/service/audit_hold.rs` 内联单测 | - [x] |
| 27 | `audit_block_test.py` | `src/service/audit.rs` + `src/service/block_inject.rs` 内联单测 | - [x] |
| 28 | `audit_stream_test.py` | `src/service/audit_hold.rs` 内联单测 | - [x] |
| 29 | `audit_env_test.py` | `src/config.rs` 内联单测 | - [x] |
| 30 | `audit_perf_test.py` | `src/service/audit.rs` 内联单测（O(n) 锚点同口径） | - [x] |
| 31 | `audit_approve_test.py` | `src/service/matrix.rs` + `src/service/audit.rs` 内联单测 | - [x] |
| 32 | `audit_approve_stream_test.py` | `src/service/audit_hold.rs` + `src/service/matrix.rs` 内联单测 | - [x] |
| 33 | `observability_admin_test.py` | `src/service/admin.rs` + `src/router.rs` 内联单测 | - [x] |
| 34 | `observability_metrics_test.py` | `src/service/metrics.rs` 内联单测 | - [x] |
| 35 | `observability_series_test.py` | `src/service/metrics.rs` + `src/service/admin.rs` 内联单测 | - [x] |
| 36 | `observability_sse_metrics_test.py` | `src/service/admin.rs` 内联单测 | - [x] |
| 37 | `observability_model_filter_test.py` | `src/service/metrics.rs` 内联单测 | - [x] |
| 38 | `observability_non_dialog_test.py` | `src/service/llm_gateway/mod.rs` + `src/service/metrics.rs` 内联单测 | - [x] |
| 39 | `observability_pii_value_test.py` | `src/service/metrics.rs` 采样器内联单测 | - [x] |
| 40 | `observability_upstream_filter_test.py` | `src/service/metrics.rs` 内联单测 | - [x] |
| 41 | `api_spec_conformance_test.py` | `scripts/api_conformance.py`（8.2 真实 SDK，14/14） | - [x] |
| 42 | `scripts/sentinel_record.py` + 三份 sentinel jsonl | `tests/fixtures/` + `tests/sentinel_check_tests.rs`（8.1 回放，9/9） | - [x] |
