# gateway-pipeline-units Specification

## Purpose
把网关转发拆为请求改写（request_rewrite）、非流转发（nonstream）、流式泵（stream_pump）三个职责单一的单元，使各自可独立单测并独立验证错误映射与输入输出契约。

## Requirements

### Requirement: request_rewrite 纯改写

改写单元 SHALL 仅对请求体做 token 子串替换与声明头附加，MUST NOT 发起任何网络 I/O。

#### Scenario: 改写无网络依赖

- **WHEN** 以任意合法请求体调用改写单元
- **THEN** 返回改写后请求体与声明头全程无网络访问

#### Scenario: 默认字节等价

- **WHEN** 未显式开启空白压缩即改写 JSON 请求
- **THEN** 输出除 token 替换外与输入字节等价且不重排结构

### Requirement: nonstream 一发一收

非流单元 SHALL 接收改写后请求并返回完整上游响应，失败时 SHALL 映射为明确状态码。

#### Scenario: 非流转发成功

- **WHEN** 上游返回完整非流响应
- **THEN** 非流单元原样返回状态码与响应体

#### Scenario: 非流上游失败映射

- **WHEN** 上游超时或不可达
- **THEN** 非流单元返回网关级错误状态码而非挂起

### Requirement: stream_pump 字节泵与终止闭合

流泵单元 SHALL 把上游字节流泵为下游 SSE 帧流并保证终止闭合，阻断或合成终止时 SHALL 注入终止标记。

#### Scenario: 流式正常收尾

- **WHEN** 上游流正常结束
- **THEN** 下游收到恰当终止帧且不再追加多余终止

#### Scenario: 阻断注入终止

- **WHEN** 审计阻断发生在流中
- **THEN** 下游收到阻断事件后恒有终止帧且终止注入标记为真
