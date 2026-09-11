## Context

见 `proposal.md` Why。现状：`src/service/matrix.rs` 有 `submit/ask/resolve/sweeper` 纯函数但 `poll_sync` 无人调用；`src/service/tpm.rs` 模板与路径双错且启动丢弃密钥；`src/registry.rs` 模型简化丢字段级 ACL；`src/handler/llm/mod.rs gateway_serve` 每请求新建 Client（违反 `veil-hardening/http-client-singleton`）（勘误：原文 `src/handler.rs`，路径已拆分，语义不变）；`extract_tool_calls` 对 Responses 仅识 `output[]`、对 Anthropic 用枚举下标；`config.rs` 自定义规则仅 JSON、`parse_placeholder_prompt` 漏 `off`；`admin.rs/metrics.rs` 查询形态已变但无兼容层。约束：不改 Go 二进制协议、不引入重型依赖、fail-closed 优先于兼容。

## Goals / Non-Goals

**Goals：**

- 给出 P0 三件套（Matrix 闭环、TPM、ACL）与单例 enforcement 的最小改动面与合表/复用方案。
- 给出流式增量累积（Responses 三级索引、Anthropic index 分桶）与占位符分流的可实施状态机。
- 给出 PII/可观测“兼容或 BREAKING 二选一”的决策点与默认推荐。

**Non-Goals：**

- 不输出逐行 diff；不定 Go `get` 客户端改造（只定网关侧兼容位）。
- 不重设阈值数值（10/min、5/IP、10MB/8MB、90s、300s 维持，只修接线与文档）。
- 不引入 `admin.html` 静态页（仍为 Non-Goal）。

## Decisions

### D1：Matrix 闭环以后台 sync 任务 + 双表合一为首选

**决策**：`main.rs` 启动 `MatrixBot::spawn_sync_loop`（since 持久化文件、指数退避、启动时间戳过滤），回调 `MatrixApproval::resolve`；`PendingApprovals` 并入 `MatrixApproval` 或加 `created_ms + 60s sweeper`，`record_pending` 单写单清；`is_mxid_allowed` 改精确匹配；补四段日志与 MXID 启动校验。

**理由**：纯函数已就绪，缺的只是常驻驱动与表治理；合表消除双写不一致。

**备选**：保持双表仅加清扫——改动小但双写窗口仍在，不采用。

### D2：TPM 按密封模板原样回放 + 启动注入 + 缓存

**决策**：`RealTpm::unseal` 命令补 `-G rsa2048 -g sha256`，路径改 `config.tpm_dir`，`startup_tpm` 返回密钥交 `keepass::tpm_password_provider` 缓存（`OnceCell`/`Mutex<Option>` + `Zeroizing`），查询复用；超时与 `VEIL_ALLOW_MOCK_TPM=1` 精确门禁保留。

**理由**：与 Python v0.8.8 密封侧对齐是唯一正确解；缓存消除每次重解的性能倒退。

**备选**：改密封侧模板迁就实现——需重密封现网密钥，风险大，不采用。

### D3：ACL 先收紧默认拒绝，再补模型

**决策**：先加 `_check_entry_allowed` 等价拒绝（未知 entry/field 默认转审/拒绝），再补 `name/desc/entries/allow_mode/old_hash` 模型与宽限通知；`register-caller` 请求形态兼容 Go 侧 `name/script_path`（网关侧做字段映射，协议不 breaking）。

**理由**：先堵越权，后补体验；默认拒绝 fail-closed。

### D4：流式审计以 `done` 为准、`delta` 只累积不执行

**决策**：`AuditHold` 按 `(item_id/output_index)` 建槽、`sequence_number` 保序、`done` 全量校验后 `evaluate`；Anthropic 按事件 `index` 字段分桶；Chat 保持 `index` 拼接；次要事件默认透传+策略表声明审计/放行；字符串 `input`/非法 `system` 不注入+warn。

**理由**：与官方“`done` 为准、增量不可信”一致，消除分片期放行窗口。

### D5：PII/可观测默认走兼容层，BREAKING 需迁移脚本

**决策**：PII 先加 YAML/TXT+别名+约束校验（复用 Python 解析语义），确需收敛再走 BREAKING+迁移脚本；`series/events/metrics` 先加 `range/model/upstream/verdict` 兼容参数（内部映射到新查询），大盘升级后再摘除。

**理由**：存量部署与旧大盘不断链优先。

### D6：单例与治理小步快走

**决策**：`gateway_serve(state: &AppState)` 直接用 `state.http_client`，Matrix 复用同一 Client；`secret_eq` 新增 HMAC 等长函数替换 `ct_eq` 于 Secret 路径；`is_private_ip` 补全四段或文档限 IPv4；`AUDIT_SCAN_BODY_LIMIT` 更名 `AUDIT_SUBLIMIT_CEILING`；`cargo-udeps` 清 `moka`。

## Risks / Trade-offs

- [Risk] Matrix 常驻 sync 引入长连接故障域 → Mitigation：指数退避 + token 持久化 + sweeper 兜底，单测注水断连场景。
- [Risk] TPM 缓存主口令延长内存驻留 → Mitigation：`Zeroizing` + `clear_cache` 显式接口 + 文档声明。
- [Risk] ACL 收紧导致存量调用方被拦 → Mitigation：先 warn+审批过渡一版，再默认拒绝，并给出注册补齐指引。
- [Risk] 兼容层扩大查询矩阵 → Mitigation：兼容参数内部映射、单测锁定新旧等价，下一版摘除。
- [Risk] Responses 增量 hold 抬高内存 → Mitigation：沿用 `AUDIT_HOLD_MAX_BYTES` 上限，超限 fail-closed。

## Migration Plan

1. 落地 P0（Matrix/TPM/ACL/单例）并全绿 P0 用例后发预发布，跑 `scripts/api_conformance.py` 20 项 + Go 直连验证。
2. 灰度启用 ACL 收紧与采样持久声明，观察审批与指标一周期。
3. 升级大盘到新查询口径后摘除兼容层；归档本 change 时把 10 份 spec 提升为常驻契约。

## Open Questions

- 无。PII 仅 JSON 收敛 vs 全兼容二选一已在 D5 给默认（先兼容），apply 时若决策反转只改 `pii-custom-compat` 的实现任务，不改 spec（spec 已覆盖两种形态的 fail-closed 语义）。
