## Why

Python `credential-proxy` → Rust `veil` 的全量比对审查发现：凭据/网关存在 3 处阻断性语义断裂（全局 Vault/Scope 单请求化致跨请求无法还原、三因子 `header==caller` 误判致正常脚本转审批、凭据审批阻塞改 202 抛单致 Go 客户端不断链）、三协议 LLM 网关 7 处结构/审计风险（`instructions` 未注入、还原后二次掩码、非流零审计、Anthropic 分桶错位等），以及注册表、审计策略、指标口径、管理面、测试 E2E 真空等共计 40+ 项缺失/漂移/弱断言。此时开 change，把全部问题收敛为可验证契约，否则不可替换上线。

## What Changes

- **P0-1，全局映射单例化**：`CredentialVault`/`PiiDetector` 由每请求新建改为全局单例 + 请求快照只读；网关只读快照透传已注册映射；PII 提供全局持久开关（默认关）与请求隔离双模。
- **P0-2，三因子解耦**：`header_hash` 与 `caller_hash` 分开校验（header==GET_BINARY_HASH、secret 独立校验、caller 独立走注册/审批）；header 缺失允许纯 `body.auth` 形态；`--raw` 终端拦截补 `use_token=false` 条件。
- **P0-3，凭据审批双模**：新增 `CREDENTIAL_BLOCK_WAIT=1` 时 enrolled 篡改/未 enrolled 走 300s 阻塞等 reaction（与原仓一致），默认保持 202 抛单；老 Go 无需改造即可用阻塞模。
- **P0-4，三协议网关修复（7 步）**：`responses.instructions` 注入 + `input string|array` 分流；`restored_spans` 跳过防二次掩码；非流补 tool 提取 + 审计 + 阻断体；Anthropic 取外层 `index`；`content_block_stop/item_done` 按 index 审计不清全局完成；BOM/[DONE]/残余/dedupe 终端去重；usage 口径统一 `max` + 文档化 + `json_walk` 深炸弹守卫。
- **P1 注册表/审批链**：空 entries 默认语义对齐（未知 entry/field 转审/拒绝而非全拒，迁移期 warn 可配）；同 hash 不同 path 允许双注册；Python 文件格式迁移工具（转 BTreeMap + `.bak`）；`lock` 清 pending/master/cache 全量；`status/forget` 文案对齐；注册/吊销/哈希变更 Matrix 审批链恢复或显式 BREAKING 声明。
- **P1 审计 parity**：补 `allow/deny` 名单、`internal_suffixes`、host 提取、`audit_precheck`、`MXID` evaluate 内校验、旧 `AUDIT_ENABLED` 兼容；策略文件全量形态兼容；日志截断/控字符/secret 模式对齐；`is_complete_event` 去重复分支；`decide_via_gateway` 落实 Block/Approve。
- **P1 PII parity**：fuzzy 恢复 `IGNORECASE`（序号回查另作开关）；hardened 补字典 CJK/保留前缀/ip_network/ReDoS/lru differentiations；自定义命名组校验放宽到原仓口径；字典改独立扫描（去分支爆炸）；采样掩码按 kind 六分支；占位符关闭条件对齐；`PII_CUSTOM_*` 三槽叠加；补 `partial_prefix_hints`/流持有说明。
- **P1 指标/管理面**：桶边界改回 12 桶 Python 值；Usage 补 `cached_read/write/unknown`；`daily/hourly` 补 pii/cred/audit 列或双写兼容视图；`five_min` 滚动/覆盖 UPSERT/重启回填对齐；`redact_summary` 口径对齐；admin `health` 豁免限流；Cookie http 回退 + `Set-Cookie` 签发；补 `OBSERVABILITY_DISABLE`/`ENV=dev` 回环免 token（或 BREAKING 声明）；Token 独立补 `DATA_DIR/admin_token` 文件检查；SSE 补 15s 快照/2s 增量/过滤维度或声明。
- **P1 网关传输/入口**：`resolve_upstream` 透传入口端口上下文或删除死代码；多端口监听或文档明确单端口；`CREDENTIAL_MASTER_PASSWORD`/`CREDENTIAL_PORT` 兼容声明；`AUTO_APPROVE` credential-only 自动批准语义落实。
- **P1 安全/传输细节**：`mlockall`（linux 失败仅 warn）；`secret_eq` 恒时比较去长度泄漏；TPM 超时 `15s→30s`、去 `pcrread` 探测或文档化、保留 stderr 诊断；KeePass 候选排序改首条、去 Recycle/Notes 需声明、`is_unlocked` 判口令非空；HOP 头集差异文档化；`CREDENTIAL_PROXY_DEBUG_DIR` 四件落盘或声明；紧急吊销补文件读取 + 三因子 + 内网判定对齐；`registrations` 鉴权恢复三因子或声明。
- **测试闭环**：补 3 个 HTTP E2E（截断开环/approve 流/跨行 SSE）+ 空流 hold 矩阵 + 并发隔离 + 解锁单 ask + 观测 DB 持久（7 天滚动/0600）+ 收紧 10 处弱断言（ReDoS/性能/`is_precise`/p95/帧级序列/`[DONE]` 精确计数/嵌套强断言/采样全矩阵）。
- **文档契约对齐**：修正 HOP/超时/桶/限流/掩码/fuzzy/custom 叠加/usage 口径等未声明漂移；`BUILTIN_NAMES` 注释错数等注释修复。

## Capabilities

### New Capabilities

- `credential-vault-singleton`: 全局 Vault/PII 单例 + 快照 + 双模开关。
- `three-factor-decoupling`: header/caller 解耦、纯 body 形态、`--raw` use_token 条件。
- `credential-approval-dual-mode`: 202 抛单 + `CREDENTIAL_BLOCK_WAIT` 阻塞双模。
- `llm-gateway-structural-fixes`: instructions 注入、restored_spans、非流审计、Anthropic index、完成标记、BOM/DONE/dedupe、usage 口径 + 深炸弹守卫。
- `registry-parity`: 空表语义、hash 冲突、格式迁移、lock/status/forget、审批链。
- `audit-parity`: 名单/后缀/host/precheck/MXID/策略文件/日志口径/hold 清理。
- `pii-parity`: fuzzy/hardened/自定义/字典/掩码/占位符/三槽叠加。
- `metrics-admin-parity`: 桶/Usage/表列/滚动/health 豁免/Cookie/文件检查/SSE 快照。
- `entry-transport-parity`: 选路上下文、多端口、轻量入口、mlockall、TPM/KeePass/HOP/DEBUG_DIR/紧急吊销。
- `test-e2e-closure`: 3 E2E + 边缘矩阵 + 弱断言收紧（断言级）。
- `docs-contract-alignment-2`: 未声明漂移修正与注释修复。

### Modified Capabilities

- 无。`openspec/specs/` 为空；既有 `veil-hardening`/`veil-review-remediation` 契约保持不动，本 change 只做增量 enforcement 与 parity 补齐。

## Impact

- **影响代码**：`src/service/mod.rs`、`src/handler.rs`、`src/service/credential_vault.rs`、`src/service/redaction.rs`、`src/service/pii.rs`、`src/service/llm_gateway.rs`、`src/service/json_walk.rs`、`src/service/sse.rs`、`src/service/audit.rs`、`src/service/audit_hold.rs`、`src/service/block_inject.rs`、`src/service/metrics.rs`、`src/service/admin.rs`、`src/registry.rs`、`src/auth.rs`、`src/config.rs`、`src/state.rs`、`src/router.rs`、`src/main.rs`、`src/keepass.rs`、`src/service/tpm.rs`、`src/service/matrix.rs`、`src/approval.rs`、`README.md`、`Cargo.toml`。
- **影响系统**：凭据可用性（Go 直连）、LLM 结构保真（工具调用）、审计拦截率、指标可比性、管理面兼容、部署文档确定性。
- **依赖**：`tokio/moka/reqwest/rusqlite/axum` 现有依赖；测试需 mock 上游 + 真 kdbx 固件 + 三协议回放。
