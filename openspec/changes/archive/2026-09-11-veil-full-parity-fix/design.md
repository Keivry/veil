## Context

见 `proposal.md` Why。现状：`src/service/credential/mod.rs:55` 每次新建 Vault、`handler.rs:1178` 每次新建 Detector 致跨请求还原断裂；`mod.rs:321` header==caller 耦合致 Go 正常请求误转审批；凭据审批只有 202 抛单无阻塞等；网关 `instructions` 未注入、还原后二次掩码、非流零审计、Anthropic 内层 index、全局完成误标；注册表/审计/指标/管理面多处口径重写；测试只有单测无 HTTP E2E。约束：不改 Go 二进制协议、不引入重型依赖、fail-closed 优先、阈值数值不动（只修接线）。

## Goals / Non-Goals

**Goals：**

- 给出单例 + 快照、三因子解耦、审批双模、网关 7 修复的最小改动面与状态机。
- 给出注册/审计/PII/指标“对齐或 BREAKING 二选一”的默认推荐（默认对齐）。
- 给出 E2E 补齐与弱断言收紧的验收线。

**Non-Goals：**

- 不输出逐行 diff；不定 Go 客户端改造（只定网关侧兼容位）。
- 不重设阈值数值（10/min、5/IP、10MB、90s、300s 维持）。
- 不交付 `admin.html` 静态页（仍为 Non-Goal）。

## Decisions

### D1：Vault/Detector 全局单例 + 请求快照只读

**决策**：`AppState` 新增 `Arc<CredentialVault>` + `Arc<PiiDetector>` 全局（`OnceLock` 或启动构造），查询命中复用；网关 `redact` 只读快照（快照 + 重编正则加版本缓存，避免每次重编 CPU 爆炸）；PII 全局持久另加开关默认关，请求隔离为默认。

**理由**：与原仓全局复用对齐是唯一不断链解；快照避免网关写全局的锁竞争。

**备选**：保持单请求隔离并声明 BREAKING——会断 prompt-cache 与跨接口还原，不采用。

### D2：三因子分开校验 + 阻塞双模

**决策**：header、secret、caller 三路独立校验；`CREDENTIAL_BLOCK_WAIT=1` 时 enrolled 篡改/未 enrolled 走 `MatrixApproval::ask` 300s 阻塞，否则 202；`matches_old_hash` 后先查 enabled 再比 hash，恢复可达性。

**理由**：与 Go 发包形态（header≠caller）对齐；双模让存量不断链、新部署可用抛单。

**备选**：全切阻塞——会逼新客户端改轮询，不采用。

### D3：网关以 done 为准、还原带 span 跳过

**决策**：`restored_spans` 随还原透传给新检出；非流先提 tool 再审计；Anthropic 取外层 index；`stop/item_done` 只清单槽；BOM 后判 DONE、残余丢弃、终端 dedupe；usage 取 max。

**理由**：与官方“done 为准、增量不可信”一致；span 跳过是保结构的核心。

**备选**：逐字段白名单重写 walk——通用 walk 已全覆盖，只缺注入与审计，不采用。

### D4：注册/审计/PII/指标默认对齐，确需收敛走 BREAKING

**决策**：空表转审、hash 只判 path、旧格式迁移、allow/deny 名单、host 提取、字典独立扫描、三槽叠加、桶改回 12 桶、health 豁免等先对齐；`admin.html`/SSE 快照等多媒体口径若确需收敛，另起 BREAKING 声明 + 大盘升级。

**理由**：存量部署与旧大盘不断链优先。

### D5：测试先补 3 E2E 再收紧弱断言

**决策**：`tests/http_e2e_{truncation,audit_approve,sse_loop}.rs` 用 mock 上游真 HTTP；ReDoS 改真超时记账、性能改秒级、`is_precise` 双条件、p95 三态、帧级序列、`[DONE]` 精确计数。

**理由**：E2E 堵最大风险，弱断言收紧防陪错。

## Risks / Trade-offs

- [Risk] 全局 Vault 延长秘密驻留 → Mitigation：LRU 上限 + `clear` 显式接口 + 文档声明。
- [Risk] 阻塞模引入 300s 长尾 → Mitigation：仅 `CREDENTIAL_BLOCK_WAIT=1` 启用，默认抛单无影响。
- [Risk] 对齐扩大查询/策略矩阵 → Mitigation：内部映射 + 单测锁定新旧等价。
- [Risk] 增量 hold 抬内存 → Mitigation：沿用 `AUDIT_HOLD_MAX_BYTES` 超限 fail-closed。
- [Risk] 跨事件 PII 半截仍漏掩 → Mitigation：本次先保结构正确，跨事件聚合另起任务。

## Migration Plan

1. 落地 P0（单例/解耦/双模/网关 7 修）并全绿 P0 用例后发预发布，跑 `scripts/api_conformance.py` + Go 直连。
2. 灰度启用注册收紧与指标对齐，观察审批与曲线一周期。
3. 升级大盘到新口径后摘除兼容层；归档时把 11 份 spec 提升为常驻契约。

## Open Questions

- 无。确需收敛为 BREAKING 的口径（admin.html/SSE 快照/多端口）已在 spec 留“或声明”分支，apply 时若决策反转只改实现任务，不改 spec。
