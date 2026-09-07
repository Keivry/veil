## Purpose

约定转发上游复用单个进程级 reqwest Client（连接池共享），消除按请求新建 Client 的握手与建连浪费，并锁定可观测与配置语义。

## ADDED Requirements

### Requirement: Client 单例复用

系统 SHALL 在进程内复用单个 `reqwest::Client` 实例处理全部上游转发请求，MUST NOT 在请求路径上构造新 Client。

#### Scenario: 多请求共享同一 Client

- **WHEN** 连续发起两次上游转发请求
- **THEN** 两次请求使用同一 Client 句柄且连接池复用生效

#### Scenario: 禁止请求路径新建 Client

- **WHEN** 审查转发路径实现
- **THEN** 请求处理函数内不存在 `Client::new` 调用，Client 仅在启动期构造并经共享态注入

### Requirement: Client 池配置可配

系统 SHALL 支持经配置项调整 Client 超时与连接池上限，未配置时使用保守默认值。

#### Scenario: 默认值生效

- **WHEN** 未显式配置 Client 参数即启动
- **THEN** 系统以默认值启动且转发功能正常

#### Scenario: 配置覆盖生效

- **WHEN** 显式配置超时与池上限后发起转发
- **THEN** 新参数生效且超限请求按错误映射返回可观测错误
