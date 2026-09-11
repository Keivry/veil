## Why

Python `credential-proxy` → Rust `veil` 重构的功能与测试审查发现 3 个 P0 不可用/越权（Matrix 审批闭环缺失、TPM 解封参数与路径错误、Caller 字段级 ACL 缺失）、1 处阻塞性架构违规（网关每请求新建 `Client`）、6 处文档与代码矛盾、5 类 P0 测试缺口（`audit_approve_stream` 流级、`pii_ipv6_time`、`series/model/upstream` 查询、截断合成、性能锚点）以及三协议流式审计的增量累积风险。此时开修复 change，把全部问题收敛为可验证契约，避免带病进入生产。

## What Changes

- **P0-1，Matrix 审批闭环**：补常驻 sync 循环 + `on_reaction→resolve` 接线 + `sync_token` 持久化 + `lock/status/forget` 三指令 + 自反应/`room_id`/`server_timestamp` 过滤；`is_mxid_allowed` 由正则匹配改回精确成员匹配。
- **P0-2，TPM 解封正确性**：`createprimary` 补 `-G rsa2048 -g sha256`；`unseal` 改读 `config.tpm_dir/seal.pub+priv`；`startup_tpm` 解出密钥注入 KeePass 而非丢弃；加解锁后缓存避免每次查询重解。
- **P0-3，Caller 字段级 ACL**：注册模型补 `name/description/entries{entry→fields}/allow_mode/can_auto_unlock/old_hash宽限` 或显式声明越权风险并收紧默认拒绝；恢复 `_check_entry_allowed` 等价检查。
- **P0-4，网关 Client 单例真正落地**：`gateway_serve` 改收 `&Client`/共享态透传，删请求路径 `Client::builder().build()` 与 `matrix.rs Client::new`；单测断言转发路径复用（`veil-hardening` 的 `http-client-singleton` spec 已声明但被违反，本 change 负责 enforcement）。
- **流式审计 parity**：Responses `function_call_arguments.delta` 按 `item_id/output_index+sequence_number` 累积至 `done` 才审计；Anthropic 按块 `index` 字段分桶（不用枚举下标）；`thinking/signature/citations/refusal/reasoning/mcp/file_search` 明确透传且审计策略（审计或放行）；Responses 字符串 `input` 与 Anthropic 非法 `system` 形态的占位符注入策略显式化（fail-open 时 warn）。
- **PII 自定义兼容**：加回 YAML 极简子集 + TXT 名单 + 4 别名（`PII_CUSTOM_PATTERN_FILE/PII_SENSITIVE_DICT_FILE/PII_SENSITIVE_NAMES_FILE/PII_RULES_FILE`），或以 **BREAKING** 声明仅支持 JSON 并提供迁移脚本；补约束校验（name 与 `(?P<name>)` 同名、禁 `\b`、禁嵌套组、与 6 内置重名拒绝、跨文件去重）。
- **可观测兼容**：`/_admin/series` 四窗口与 `events?verdict`、`metrics?model&upstream` 加兼容层，或以 **BREAKING** 声明新查询形态（`granularity/since/protocol/kind/limit`）并升级大盘调用方。
- **文档契约对齐**：修正多端口选路上游（`resolve_upstream(None)` 恒缺省）、`PII_PLACEHOLDER_PROMPT=off` 不生效、`GET_BINARY_HASH` 独立生效、8MB 审计上限死锚点、`/health` 超集字段 5 处矛盾。
- **行为变更显式化**：**BREAKING** 声明脱敏默认关→开、采样持久内存→落盘、凭据淘汰 FIFO→LRU 三处，并给出迁移说明。
- **测试闭环**：补 `pii_ipv6_time` 16 项、`audit_approve_stream` 13 项流级、`series/model/upstream/pii_value` 查询、`truncation` TSS01-04+真实数据、性能锚点、四误报守卫等 P0/P1 用例（详见 tasks）。

## Capabilities

### New Capabilities

- `matrix-approval-closure`：常驻 sync、reaction 接线、token 持久化、三指令、过滤器、白名单精确匹配、超时与清扫口径。
- `tpm-unseal-correctness`：createprimary 模板、seal 路径、启动注入、缓存与超时、Mock 门禁。
- `caller-field-acl`：注册模型、字段级授权、宽限与哈希变更通知、限流。
- `http-client-governance`：Client 单例 enforcement、pending TTL 合表、时序比较统一、`is_private_ip` 补全、KeePass 锁显式化、死依赖清理。
- `llm-streaming-parity`：三协议流式增量累积、占位符注入形态、残缺/幻觉处理、终止帧、空流兜底、审计拦截注入。
- `pii-custom-compat`：自定义规则文件格式、别名、约束校验、fail-closed 语义。
- `observability-compat`：series/events/metrics 查询兼容或 BREAKING 声明。
- `docs-contract-alignment`：README 与 spec 与代码三源一致性修正。
- `behavior-changes`：三处默认值/语义 BREAKING 声明与迁移。
- `test-coverage-closure`：P0/P1 补测清单与验收标准（断言级）。

### Modified Capabilities

- 无。`openspec/specs/` 当前为空；`veil-hardening` 的 `http-client-singleton` 等契约保持不动，本 change 只做 enforcement 与增量。

## Impact

- **影响代码**：`src/service/matrix.rs`、`src/service/tpm.rs`、`src/keepass.rs`、`src/main.rs`、`src/registry.rs`、`src/service/mod.rs`、`src/handler/mod.rs`、`src/state.rs`、`src/approval.rs`、`src/auth.rs`、`src/service/llm_gateway/mod.rs`、`src/service/sse.rs`、`src/service/audit_hold.rs`、`src/service/block_inject.rs`、`src/service/pii.rs`、`src/config.rs`、`src/service/metrics.rs`、`src/service/admin.rs`、`src/router.rs`、`README.md`、`Cargo.toml`。
- **影响系统**：审批可用性（approve 全链路）、TPM 解锁、授权越权面、转发性能、流式审计窗口、可观测大盘兼容、部署文档确定性。
- **依赖**：`tpm2-tools` 命令行模板、`reqwest` 连接池、`tokio` 运行时、`rusqlite` 聚合表、`axum` 限流层；测试依赖真实 kdbx 固件与三协议 SDK 回放。
