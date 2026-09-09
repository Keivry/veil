## Why

全量合规审查结论：Rust `cargo test` 约 632 用例 vs Python 727 用例（约 87%），骨干对齐但 10 组测试缺口未立项。最密的 Python `llm_test` 90 用例仅部分移植，`sentinel_sdk_replay` 12 项已移植无需重做，但以下缺角仍开环：B1 管理面鉴权全矩阵无 e2e（优先级、非 SSE query 恒 401、token 文件独立性、观测总开关）；B2 原 `audit_perf_test` 6 用例完全缺失，大 body 耗时无上限锚；B3 非流空体转 502 无 e2e（`bytes_written==0` 守门）；B4 PII 回归 30 余断言弱化（IPv6 时间戳、前导零 IPv4、句末句号、URL 订单号等，四回归文件未一对一移植）；B5 metrics 六语义缺（QueueFull 丢最老、flush 去抖、窗口语义、model 白名单、上游 PII 双计、SSE 快照形状）；B6 vault 四语义缺（token 不可枚举、空洞复用、fuzzy 拒绝、BOM 与深度与包装器）；B7 限流三语义缺（TCP 远端、unknown 桶、SSE 断开清理）；B8 审批三语义缺（三态、非 full 降级、篡改转 pending）；B9 deny 摘要双形态缺（Bearer 形态、键值 JSON 形态）；B10 三处 flaky 集中在 5ms 分片投递。本 change 一次补齐 10 组，只加测试与 flaky 加固，不碰实现语义。

## What Changes

- **补 B1，admin 全矩阵 e2e**：`X-Admin-Token` 大于 Cookie 大于 `?access_token` 仅 SSE 优先级，非 SSE 带 query 恒 401，admin token 文件独立性，`OBSERVABILITY_DISABLE=1` 全 404。
- **补 B2，audit_perf 耗时锚**：原 `audit_perf_test` 6 用例等价移植，大 body 耗时上限锚，宽松上界防 flaky。
- **补 B3，非流空体 502 e2e**：空体转 502 `E_EMPTY_BODY`，strip 后空体同口径，`bytes_written==0` 守门断言。
- **补 B4，PII 回归一对一移植**：四回归文件逐项移植 30 余断言，含 IPv6 时间戳、前导零 IPv4 归一、句末句号、URL 订单号、保留段豁免、CJK 边界、`lru_cache` 语义。
- **补 B5，metrics 六语义**：QueueFull 丢最老、flush 去抖 2 秒、hourly 与 daily 窗口语义、model 白名单含 `:@`、upstream 与 PII 双计、SSE 15 秒快照形状。
- **补 B6，vault 四语义**：`rand8 token_hex` 不可枚举、`gap_skip` 空洞复用、fuzzy 非法拒绝、BOM 与 depth 与三包装器。
- **补 B7，限流三语义**：TCP 远端不采信代理头、`unknown` 桶、SSE 断开清理。
- **补 B8，审批三语义**：`AUTO_APPROVE` 三态、`approve_hash_change` 非 full 降级阻断、篡改转 pending 202。
- **补 B9，deny 摘要双形态**：Bearer 形态与键值 JSON 形态各一断言。
- **改 B10，flaky 加固**：三处 5ms 分片改 readiness 轮询或 20ms，`truncation:62` 50ms 复核，`audit.rs:1086` 线程 sleep 链式上限复核。

## Capabilities

### New Capabilities

- `review-coverage-fill`：上述 B1 至 B10 的用例清单、断言强度、flaky 加固与豁免声明。

### Modified Capabilities

- 无既有 spec 需求变更。只新增测试资产与加固，既有 `coverage-closure` 真源 spec 不动。

## Non-Goals（显式）

- 不改任何 `src/` 实现语义。失败用例若暴露实现 bug，转对应修复 change，不在本 change 修实现（flaky 加固的等待策略除外）。
- 不改既有 changes 文件。不提交 commit。
- 不恢复 `admin.html` 交付。不恢复 `CREDENTIAL_PROXY_DEBUG_DIR` 四件落盘。
- 中文函数名零残留已验证，无需改名，不在本 change 设任务。

## Impact

- **新增文件**：`openspec/changes/veil-review-test-fill/` 下 proposal、design、specs、tasks。apply 阶段新增 `tests/` e2e 与 `src/` 内联单测，加固三处 flaky 等待。
- **影响系统**：只影响测试代码与 CI 稳定性。生产行为零变更。
- **依赖**：既有真回环 harness（见 `tests/http_e2e_credential.rs` 隔离建 app 形态）、`tests/sentinel_sdk_replay.rs` 12 项清单形态、`src/service/audit.rs` 策略引擎、`src/service/metrics/aggregate.rs` 窗口与常量。基线 Python 727 vs Rust 632，`llm_test` 90 为最密对照源。
- **真源与漂移声明**：`openspec/specs/coverage-closure` 为真源。README 第 6 节五条 BREAKING 为预期漂移，非遗漏判据，不在本 change 验收为缺口。
