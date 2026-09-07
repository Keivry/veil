## Purpose

说明 Go get 客户端如何零改动对接 Rust 网关，锁定路径、鉴权头、三因子字段与 SSE 语义。

## ADDED Requirements

### Requirement: Go 客户端路径零改动对接

网关 SHALL 保持 Go `get` 客户端所用路径与方法不变，使其无需修改即可对接。

#### Scenario: 存量 Go 客户端直连

- **WHEN** 未修改的 Go get 客户端按原路径与方法发起调用
- **THEN** 网关正确路由并返回与既有语义一致的响应

### Requirement: 三因子鉴权字段兼容

网关 SHALL 兼容三因子鉴权字段（哈希头、密钥头或体、调用方标识），缺失或不匹配时按既有语义拒绝或转审。

#### Scenario: 三因子齐全通过

- **WHEN** Go 客户端携带完整三因子字段发起取用
- **THEN** 网关按既有语义放行或进入审批而不报协议错误

#### Scenario: 三因子缺失可诊断

- **WHEN** Go 客户端缺失任一因子字段
- **THEN** 网关返回明确的鉴权失败而不是空响应或挂起

### Requirement: SSE 语义对 Go 透明

网关 SHALL 保证 SSE 帧语义对 Go 客户端透明，阻断终止闭合行为与既有约定一致。

#### Scenario: Go 消费阻断流正常结束

- **WHEN** Go 客户端消费一条被审计阻断的流
- **THEN** 客户端收到终止帧并视为正常结束而不重试或挂起
