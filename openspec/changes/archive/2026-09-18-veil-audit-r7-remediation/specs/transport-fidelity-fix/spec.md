# Spec Delta

## MODIFIED Requirements

### Requirement: 流式转发独立超时策略

系统 SHALL 对流式（SSE）上游转发使用独立 client：MUST NOT 施加覆盖整个响应体读取的总超时（避免长流被 `HTTP_TIMEOUT_SECS` 截断）；MAY 配置读空闲超时用于失活连接回收。非流与 NonDialog 透传 SHALL 保持既有总超时口径（`HTTP_TIMEOUT_SECS`，默认 `30`s）。两类 client SHALL 在启动期构造并经共享态注入，MUST NOT 在请求路径构造新 `reqwest::Client`。流式 client 的读空闲超时与失效口径（无 / 取值）SHALL 在 design 与 README 显式声明。

非流请求（`stream` 未显式为 `true`）而上游仍返回 `status < 400` 且 `content-type: text/event-stream` 时（`R7-05`），系统 SHALL 复用**已取得**的上游响应经字节泵转发，SHALL NOT 重新发起上游请求（非幂等）；该路径 SHALL 受非流 client 的 `HTTP_TIMEOUT_SECS` 总超时约束（含响应体读取，超时按中途断流终端路径 fail-closed 收尾）；需长流者 SHALL 显式 `stream: true` 以获独立无总超时 client。该口径 SHALL 在 README §7.2 显式声明，SHALL NOT 以新增 502/错误码等 wire 行为处理。

#### Scenario: 长流不因总超时中断

- **WHEN** 以较小 `HTTP_TIMEOUT_SECS`（如 `1`）配置启动，上游流式持续产出超过该时长且事件间隔小于读空闲阈值
- **THEN** 下游流持续收到事件、不被网关以超时中断

#### Scenario: 非流保持总超时

- **WHEN** 非流上游响应头到达后长时间不返回 body
- **THEN** 网关按 `HTTP_TIMEOUT_SECS` 超时映射为网关错误，行为与修复前一致

#### Scenario: 启动期构造共享注入

- **WHEN** 审查转发路径实现
- **THEN** 请求处理函数内不存在 `Client::new`/`Client::builder` 调用，两类 client 均于启动期构造并经共享态注入

#### Scenario: 非流请求遇上游 SSE 受总超时

- **WHEN** 请求 `stream` 未为 `true`，上游返回 `status < 400` 且 `content-type: text/event-stream`
- **THEN** 网关复用已取得的上游响应经字节泵转发（不重发上游请求），受非流 client 总超时约束；README §7.2 含该声明；长流须显式 `stream: true`
