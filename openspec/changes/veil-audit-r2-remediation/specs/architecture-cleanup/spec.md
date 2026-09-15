## ADDED Requirements

### Requirement: 单帧单次 JSON 解析

系统对每个 SSE 帧 SHALL 至多执行一次完整 JSON 解析，并复用该解析产物承载审计判定、内层 stringified-JSON 递归校验与转发决策；SHALL NOT 对同一帧重复解析（当前 `src/handler/llm/pump/event_loop.rs:145,273`、`src/handler/llm/pump/frame_feed.rs:33,36` 与 `inner_json_intact` 路径合计最多 4 次）。解析复用 SHALL NOT 改变帧序、帧内容、审计判定、还原结果与终端恰一语义。

#### Scenario: 单帧仅解析一次

- **WHEN** 上游投递单帧 SSE 数据（含需内层递归校验的嵌套 JSON）
- **THEN** 该帧仅解析一次，审计/还原/转发决策复用同一解析结果（解析计数证据可见该帧解析次数为 1 而非 4）

#### Scenario: 解析复用行为逐字节不变

- **WHEN** 对复用解析的实现运行全部流式相关回归
- **THEN** 帧序、帧内容、审计时序与终端恰一语义与复用前逐项一致

### Requirement: 流式/非流请求上下文统一

系统 SHALL 将 `StreamPumpCtx`（17 字段）与 `NonstreamCtx`（16 字段）重叠的请求级字段合并为单一共享请求上下文（`src/handler/llm/dispatch.rs` 装配点），由单一装配点构造并供流式与非流路径复用；SHALL NOT 保留重叠 14 字段的双份装配，以消除装配漂移。共享上下文 SHALL 保持两路径字段取值与语义等价。

#### Scenario: 两路径共用同一请求上下文

- **WHEN** 分别经流式与非流路径处理同一请求
- **THEN** 两路径使用同一请求上下文类型，请求级字段取值一致

#### Scenario: 无重复装配漂移

- **WHEN** 运行结构等价单测
- **THEN** 共享上下文字段映射无缺失或新增漂移，重叠字段不再双份装配

### Requirement: PII 自定义规则批量扫描

`scan_custom`（`src/service/pii/custom.rs:407-412,430`）SHALL 以单次 `spawn_blocking` 任务扫描一帧的全部规则与分块；SHALL NOT 对每规则每分块各起一个阻塞任务（任务 churn）。规则集 SHALL 以只读共享引用（如 `Arc`）传递给扫描任务；SHALL NOT 每帧克隆规则集。批量扫描 SHALL 与逐规则逐分块扫描结果等价。

#### Scenario: 单次任务扫描全部规则与分块

- **WHEN** 一帧包含多条自定义规则与多个分块
- **THEN** 仅调度一次阻塞任务完成该帧全部规则/分块扫描

#### Scenario: 规则集只读共享不逐帧克隆

- **WHEN** 连续多帧经 `scan_custom` 扫描
- **THEN** 规则集经只读共享引用复用，不随帧克隆

#### Scenario: 批量扫描结果等价

- **WHEN** 运行等价性测试
- **THEN** 命中结果与逐规则逐分块扫描逐项一致

### Requirement: 重试零重复克隆

上游重试路径（`src/handler/llm/dispatch.rs`）SHALL 使用可重放请求体（或引用）以避免对请求头/体的重复克隆；每次重试 SHALL NOT 再次克隆请求头与请求体。重试分类、退避序列（`0.5s→1s→2s`、最多 3 次）与拿头后不重试语义 SHALL 不变。

#### Scenario: 重试不重复克隆

- **WHEN** 请求经历多次上游重试
- **THEN** 请求头/体不随重试次数重复克隆，可重放体被复用

#### Scenario: 重试语义不变

- **WHEN** 运行重试相关回归
- **THEN** 退避序列、最大次数与分类判定与现状一致

### Requirement: 热路径零每请求 HashSet 分配

审计与还原热路径 SHALL NOT 为每个请求新建 `HashSet`；SHALL 复用请求级容器或采用延迟/小容器分配（如 `SmallVec`/请求级缓存）。行为 SHALL 不变。

#### Scenario: 非相关请求不产生该分配

- **WHEN** 处理不触发相关集合使用的请求
- **THEN** 不产生该 `HashSet` 分配（惰性/零分配）

#### Scenario: 行为与分配策略解耦

- **WHEN** 运行审计/还原回归
- **THEN** 结果与逐请求新建容器实现逐项一致

### Requirement: 协议分派单一入口

协议判定/分派 SHALL 收敛为单一分派点（或类型化方法）供全仓复用；SHALL NOT 保留当前 19 处/13 文件的重复协议分支扩散。收敛 SHALL 保持分派结果等价。

#### Scenario: 分派点收敛

- **WHEN** 检查全仓协议分派点
- **THEN** 协议分派经单一入口或类型化方法，无重复扩散实现

#### Scenario: 分派结果不变

- **WHEN** 运行三协议分派回归
- **THEN** 分派结果与收敛前一致

### Requirement: 上游状态码受约束类型

上游状态码 SHALL 以受约束类型（`src/service/llm_gateway/` 的 newtype/带校验）承载，SHALL NOT 以裸 `u16` 在服务层无约束传递。非法状态值的处理（不 panic、不改写对外语义）SHALL 与现状一致。

#### Scenario: 合法状态码经受约束类型

- **WHEN** 上游返回合法 HTTP 状态码
- **THEN** 经受约束类型构造并正常参与透传/判定

#### Scenario: 非法状态值处理一致

- **WHEN** 构造或接收非法状态值
- **THEN** 处理与现状一致，不 panic，不改变对外行为

### Requirement: 服务层不变量守护补齐

服务层 SHALL 以 `debug_assert` 或类型约束承载其职责范围内的不变量守护；SHALL NOT 使部分不变量仅存于 handler 层而服务层无守护。守护补齐 SHALL NOT 改变 release 构建的对外行为。

#### Scenario: debug 构建暴露调用约定

- **WHEN** debug 构建下以违反不变量的输入调用服务层入口
- **THEN** 触发守护断言（或类型层拒绝），暴露调用约定

#### Scenario: release 行为不变

- **WHEN** release 构建运行既有测试
- **THEN** 对外行为与补齐前一致

### Requirement: 停机接线与清理单例

进程停机路径（`src/main.rs` 与清理路径）SHALL 实际接线 `notify.shutdown()` 触发优雅停机；SHALL NOT 保留未接线的 shutdown 通知。`GatewayCleanup` SHALL NOT 构造第二个 `AppState`，清理 SHALL 复用既有实例。

#### Scenario: 停机触发优雅停机

- **WHEN** 进程收到停机信号
- **THEN** 优雅停机通知被触发，后台任务按序停止

#### Scenario: 清理不构造第二个 AppState

- **WHEN** 执行 `GatewayCleanup`
- **THEN** 复用既有 `AppState`，不产生第二个实例或重复初始化/资源泄漏
