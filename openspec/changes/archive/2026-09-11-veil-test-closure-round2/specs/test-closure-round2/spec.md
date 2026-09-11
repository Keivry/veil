## Purpose

补齐 6 类测试缺口并核查 4 处可疑断言，显式豁免 `admin.html`。

## ADDED Requirements

### Requirement: 流式保真补齐

系统 SHALL 有断线重试真 E2E、n2 广播隔离、字段级保真、嵌套还原回归四类用例。

#### Scenario: 断线重试可恢复

- **WHEN** 上游首连断开次连成功
- **THEN** 下游终见完整流且重试符合退避曲线

#### Scenario: 双路不串扰

- **WHEN** 流含 `index:0/1` 交织 tool 分片
- **THEN** 各路独立累积且审计按槽触发

#### Scenario: 保真字段原样透传

- **WHEN** 流式/非流式响应含 `id/object/created/model/index/finish_reason/usage`
- **THEN** 改写后上述字段与上游逐项一致（单测全字段对比）

#### Scenario: 嵌套还原回归

- **WHEN** 响应含嵌套 stringified JSON（如 `p@ss"quote`、`__PII_` 双下划线、`arguments` 内转义）
- **THEN** 还原后结构与语义不变且单测锁定

### Requirement: 审批载荷精确

系统 SHALL 对批准/拒绝做载荷级断言，而非仅 `!blocked`。

#### Scenario: 批准原样释放

- **WHEN** 危险调用被批准
- **THEN** 下游见原始 args 全串

#### Scenario: 拒绝无泄漏

- **WHEN** 危险调用被拒绝
- **THEN** 下游见阻断帧且无原始参数子串

### Requirement: 淘汰容量锁定

系统 SHALL 以显式测试锁定 LRU 语义与容量分表。

#### Scenario: 热点驻留

- **WHEN** 热点被循环访问后触发逐出
- **THEN** 冷条目先被逐出

#### Scenario: 容量分表常量锁定

- **WHEN** 查阅凭据/PII 容量常量
- **THEN** 凭据表 `MAX_TOKEN_ENTRIES=5000`、PII 请求/响应单表 `PII_MAX_ENTRIES=1000` 且单测断言

#### Scenario: 缓存往返与深炸弹回退

- **WHEN** 命中 redact 缓存、重建、深嵌套炸弹、roundtrip 破坏四场景
- **THEN** 逐项有单测（命中复用/重建一致/深层截断不崩/破坏回原串）

### Requirement: 性能与豁免决策有结论

系统 SHALL 对 perf 门限二选一有签字结论，对 `admin.html` 有 conformance 豁免注释。

#### Scenario: 豁免可查

- **WHEN** 查阅 `scripts/api_conformance.py`
- **THEN** 可见 `admin.html NON_GOAL` 豁免注释

#### Scenario: 性能二选一有签字

- **WHEN** 性能门限决策完成
- **THEN** spec 记录“恢复墙钟门限或文档声明锚点代替”二选一结论及 maintainers 签字位置

### Requirement: 可疑断言逐项核对

系统 SHALL 核对 ipv6 第 17 项、TSS04 计费、`15s` 快照 shape、`stream+JSON` 组合四项并记录结论。

#### Scenario: 核对有记录

- **WHEN** 四项核对完成
- **THEN** 每项有“实现/文档/测试”三者之一的结论记录
