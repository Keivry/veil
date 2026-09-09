## Context

现状：Rust 632 用例 vs Python 727 用例，`sentinel_sdk_replay` 12 项已移植，`tests/http_e2e_credential.rs` 已有隔离建 app 与真回环形态，`src/service/audit.rs` 为策略引擎归属，`src/service/metrics/aggregate.rs` 锁定窗口与常量。缺角集中在 B1 至 B9 九组语义无测试，B10 三处 flaky 系 5ms 分片投递竞态。约束：只加测试与等待加固，不改生产语义。中文函数名经 grep 验证零残留，不设任务。README 第 6 节五条 BREAKING 为预期漂移，不判遗漏。

## Goals / Non-Goals

**Goals：**

- 给出 B1 至 B10 每组补测形状、断言点与边缘条件，使 apply 可机械执行。
- 给出 flaky 加固的有界等待方案与复核点。
- 四处可追踪：proposal、spec、design、tasks 对 B1 至 B10 一一对应。

**Non-Goals：**

- 不改生产实现。不复制 skill 块。不改既有 changes。不提交 commit。

## Decisions

### D1：B1 admin 全矩阵用隔离 e2e 锁定

**决策**：新增 `tests/http_e2e_admin_matrix.rs`，复用 `http_e2e_credential.rs` 隔离建 app 形态。断言优先级 header 大于 Cookie 大于 query 且 query 仅 SSE 生效，非 SSE 带 query 恒 401，token 经文件加载与环境变量独立，`OBSERVABILITY_DISABLE=1` 全 404。

**理由**：管理面鉴权为 P0，无矩阵则绕过不可感知。

### D2：B2 audit_perf 按原 6 用例等价移植

**决策**：新增 `tests/audit_perf_bound.rs` 或 `src/service/audit.rs` 内联性能锚，对大 body 给宽松耗时上界。锚为回归线而非墙钟门限，CI 慢机不红。

**理由**：原 6 用例完全缺失，大 body 退化无感知。

### D3：B3 非流空体走真 e2e 断言 502

**决策**：在 LLM 非流 e2e 加空体与 strip 后空体两用例，断言 502 与 `E_EMPTY_BODY`，另加 `bytes_written==0` 守门单测。

**理由**：空 200 透传会误导调用方重试语义。

### D4：B4 PII 四回归文件一对一移植

**决策**：按原四回归文件逐项移植 30 余断言，落 `src/service/pii/` 内联单测。含 IPv6 时间戳、前导零 IPv4 归一、句末句号、URL 订单号、保留段豁免、CJK 边界、`lru_cache`。

**理由**：逐项移植防弱化漂移，一对一可审计。

### D5：B5 metrics 六语义分单测与 e2e 两层

**决策**：QueueFull 丢最老、flush 去抖 2 秒、hourly 与 daily 窗口、model 白名单含 `:@`、upstream 与 PII 双计走 `aggregate.rs` 归属单测。SSE 15 秒快照形状走 e2e 断言字段集。

**理由**：聚合语义适合单测，快照形状须经 HTTP 面验证。

### D6：B6 vault 四语义走单测锁定

**决策**：`rand8 token_hex` 不可枚举用批量生成无碰撞断言，`gap_skip` 空洞复用用删除再分配断言，fuzzy 非法拒绝用非法形态矩阵断言，BOM 与 depth 与三包装器用解析器单测断言。

**理由**：vault 为进程单例语义，单测即可锁定，无需 e2e。

### D7：B7 限流三语义走真回环 e2e

**决策**：伪造代理头仍按 TCP 远端计数用真回环 e2e 断言，`unknown` 桶用缺 model 形态断言，SSE 断开清理用建连断开再建连断言。

**理由**：限流计数依赖连接层远端地址，单测不可信。

### D8：B8 审批三语义走 e2e 与单测分层

**决策**：`AUTO_APPROVE` 三态走 handler 级 e2e 三用例，`approve_hash_change` 非 full 降级阻断走入口模式矩阵断言，篡改转 pending 202 走篡改哈希 e2e 断言。

**理由**：入口模式与审批流转跨层，须经路由面验证。

### D9：B9 deny 摘要双形态走审计断言

**决策**：Bearer 形态与键值 JSON 形态各一用例，断言摘要脱敏且无明文，形态字段齐全。

**理由**：摘要形态决定审计可查性，缺一即盲区。

### D10：B10 flaky 改有界等待并复核两处

**决策**：`http_e2e_sse_loop:76`、`truncation_matrix:60`、`sdk_replay:79` 三处 5ms 分片投递改为 readiness 轮询首选，轮询不可行则 20ms 固定等待。复核 `truncation:62` 50ms 是否足够，复核 `audit.rs:1086` 线程 sleep 链式上限是否叠加超标。

**理由**：5ms 在 CI 慢机必竞态，轮询或 20ms 为最小有界修复。

## Risks / Trade-offs

- [用例膨胀致 CI 变慢] 指标与 PII 优先单测化，仅鉴权、限流、空体、快照走 e2e，tasks 标注每项级别。
- [性能锚在慢机 flaky] 上界取宽松值，只防数量级退化，不卡精确墙钟。
- [危险语料误触发审计] 审批与 deny 用例走 `AUDIT_MODE=off` 隔离或合成语料。

## Migration Plan

1. 先 B1 与 B7 与 B3 等 P0 与 P1 网关面，再 B4 与 B5 与 B6 单测层，再 B8 与 B9 审批审计面，最后 B10 加固全量重跑。
2. 每批 `cargo test` 回归，慢机重复三轮确认无 flaky。
3. 回滚：新增用例与等待加固可独立 revert，零运行时风险。

## Open Questions

- 无。
