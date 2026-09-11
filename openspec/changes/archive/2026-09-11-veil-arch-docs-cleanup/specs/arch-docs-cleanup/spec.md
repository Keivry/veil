## Purpose

收敛 handler 结构、限流有界、观测显式与 6 处文档一致性，无协议行为变更。

## ADDED Requirements

### Requirement: handler 按入口拆分且行为一致

系统 SHALL 将凭据与 LLM 处理分离到独立模块，conformance SHALL 全绿，状态码 SHALL 集中注释。

#### Scenario: 拆分后行为一致

- **WHEN** 拆分合入后跑 conformance
- **THEN** 14/14 通过且路由表不变

### Requirement: 限流表有界清扫

系统 SHALL 对凭据/注册限流表做有界清扫，只删过期键。

#### Scenario: 长跑不膨胀

- **WHEN** 限流表超 1000 键或 60s 未扫
- **THEN** 过期键被清理且未过期键保留

### Requirement: 观测定时显式

系统 SHALL 有 `wal_checkpoint` 调用点与 `QueueFull` 丢最老单测，KeePass 串行语义 SHALL 文档化。

#### Scenario: 队列满可观测

- **WHEN** 指标队列满
- **THEN** 丢最老且 `dropped` 计数加一

### Requirement: 六处文档一致

系统 SHALL 修复 off 注释、阈值表头、Go 鉴权列、端口措辞、BREAKING 追加、conformance 豁免六处，README SHALL 为唯一入口且与 spec 同字。

#### Scenario: off 注释与实现一致

- **WHEN** 查阅 `redaction.rs` 占位注释与 `Config::is_falsy`
- **THEN** 以 `Config` 为准（`off` 视为关）且 `off→关闭` 单测通过

#### Scenario: 阈值表头显式入口维度

- **WHEN** 查阅 README §4 阈值表
- **THEN** 表头含“是否接入口”列（`10MB` 接入口 enforcement、`8MB` 纯 ceiling 锚点）

#### Scenario: Go 表鉴权列完整

- **WHEN** 查阅 README §5 Go 对接表
- **THEN** 含“鉴权”列（`registrations` 需 `X-Admin-Token`，旧直读 401）

#### Scenario: 端口措辞无歧义

- **WHEN** 查阅 README 端口章节
- **THEN** 表述为“单进程单监听 + compose 三映射宿主机入口区分”，无“不存在多端口重构”措辞

#### Scenario: BREAKING 与豁免同字

- **WHEN** 比对 approval/test change 的 BREAKING/豁免文案
- **THEN** 与本 change §1.3-1.4 同字（互引 owner，见 tasks）
