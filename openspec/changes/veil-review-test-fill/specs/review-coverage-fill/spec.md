## Purpose

补齐审查发现的 10 组测试缺口并加固 flaky，只加测试与等待策略，不改生产语义。中文函数名零残留已验证，不设改名需求。

## ADDED Requirements

### Requirement: B1 管理面鉴权全矩阵覆盖

系统 SHALL 以 e2e 锁定管理面鉴权优先级与总开关语义：`X-Admin-Token` 大于 Cookie，仅 SSE 可用 `?access_token` 回退，非 SSE 带 query 恒 401，admin token 文件独立，`OBSERVABILITY_DISABLE=1` 全 404。

#### Scenario: 优先级 header 大于 Cookie 大于 query

- **WHEN** 同一请求携带 header 与 Cookie 与 query 三种凭证且 header 有效
- **THEN** header 生效，其余被忽略且请求按 header 鉴权结果放行或拒绝

#### Scenario: 非 SSE 带 query 恒 401

- **WHEN** 非 SSE 管理接口以 `?access_token` 携带有效 token 但无 header 与 Cookie
- **THEN** 恒返回 401，不回退放行

#### Scenario: 观测总开关全 404

- **WHEN** 置位 `OBSERVABILITY_DISABLE=1` 后访问任一 `/_admin` 接口
- **THEN** 全返回 404，与 token 有效性无关

### Requirement: B2 审计性能耗时上限

系统 SHALL 移植原 `audit_perf_test` 6 用例等价语义，对大 body 审计链给出耗时上限锚，且上界宽松不引入 flaky。

#### Scenario: 大 body 审计耗时有界

- **WHEN** 对大 body 请求执行审计判定链
- **THEN** 耗时低于声明上界且判定结论正确

### Requirement: B3 非流空体转 502

系统 SHALL 以 e2e 锁定非流空响应体转 502 `E_EMPTY_BODY`，含 strip 后空体形态，且 `bytes_written==0` 守门有效。

#### Scenario: 空体转 502

- **WHEN** 上游非流响应体为空或 strip 后为空
- **THEN** 网关返回 502 且错误码为 `E_EMPTY_BODY`，不透传空 200

### Requirement: B4 PII 回归一对一移植

系统 SHALL 将四回归文件逐项移植，30 余断言覆盖 IPv6 时间戳、前导零 IPv4 归一、句末句号、URL 订单号、保留段豁免、CJK 边界、`lru_cache` 语义。

#### Scenario: 边缘形态脱敏正确

- **WHEN** 输入含前导零 IPv4、IPv6 时间戳混合、句末句号、URL 查询串中订单号
- **THEN** 前导零 IPv4 按归一口径处理，时间戳不误杀，句号保留在占位符外，订单号按规则脱敏

#### Scenario: 保留段与 CJK 边界豁免

- **WHEN** 输入命中保留段或 CJK 边界粘连
- **THEN** 保留段豁免不脱敏，CJK 边界按既有口径不断字误杀

### Requirement: B5 指标六语义覆盖

系统 SHALL 覆盖 QueueFull 丢最老、flush 去抖 2 秒、hourly 与 daily 窗口语义、model 白名单含 `:@`、upstream 与 PII 双计、SSE 15 秒快照形状。

#### Scenario: 队列满丢最老

- **WHEN** 指标队列满后继续入队
- **THEN** 丢弃最老样本，最新样本保留且计数可查

#### Scenario: 快照形状稳定

- **WHEN** 查询 SSE 15 秒快照
- **THEN** 字段形状与 `series` 窗口语义一致，不多不少

### Requirement: B6 凭据 vault 四语义覆盖

系统 SHALL 覆盖 `rand8 token_hex` 不可枚举、`gap_skip` 空洞复用、fuzzy 非法拒绝、BOM 与 depth 与三包装器。

#### Scenario: token 不可枚举

- **WHEN** 连续生成多个 `rand8 token_hex`
- **THEN** 无可预测序列，不与历史值碰撞

#### Scenario: 空洞复用与非法拒绝

- **WHEN** 删除后产生空洞再分配，以及传入 fuzzy 非法形态
- **THEN** 空洞被复用，非法形态被拒绝且 vault 状态不变

### Requirement: B7 限流三语义覆盖

系统 SHALL 覆盖 TCP 远端不采信代理头、`unknown` 桶语义、SSE 断开清理。

#### Scenario: 代理头不可伪造绕过

- **WHEN** 请求携带伪造 `X-Forwarded-For` 且 TCP 远端已超限
- **THEN** 仍按 TCP 远端计数拒绝，不采信代理头

#### Scenario: 断开清理限流槽

- **WHEN** SSE 连接断开
- **THEN** 其并发槽被释放，后续新连接可建连

### Requirement: B8 审批三语义覆盖

系统 SHALL 覆盖 `AUTO_APPROVE` 三态、`approve_hash_change` 非 full 降级阻断、篡改转 pending 202。

#### Scenario: 三态各走各路

- **WHEN** `AUTO_APPROVE` 分别取 `true`、`false`、`none`
- **THEN** 依次为放行、拒绝、转 Matrix 审批，不混路

#### Scenario: 篡改转 pending 建单

- **WHEN** 已注册调用方哈希被篡改
- **THEN** 返回 202 建单 pending，不直接放行不同行拒绝

### Requirement: B9 拒绝摘要双形态覆盖

系统 SHALL 对 deny 摘要的 Bearer 形态与键值 JSON 形态各设断言。

#### Scenario: 双形态均可审计

- **WHEN** 拒绝分别携带 Bearer 头形态与键值 JSON 形态凭证
- **THEN** 两种形态摘要均脱敏记录且无明文泄漏

### Requirement: B10 flaky 加固有界等待

系统 SHALL 将三处 5ms 分片投递改为 readiness 轮询或 20ms 等待，复核 `truncation:62` 50ms 与 `audit.rs:1086` 线程 sleep 链式上限。

#### Scenario: 加固后稳定通过

- **WHEN** 在 CI 慢机重复运行加固后的三处用例
- **THEN** 通过率稳定，无 5ms 竞态失败，且总时长增量有界
