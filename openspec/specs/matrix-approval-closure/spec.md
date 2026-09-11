# matrix-approval-closure Specification

## Purpose
补齐 Matrix 审批的运行时闭环：维持带 `since` token 的常驻 sync 循环并持久化、按原因接线 reaction 五分支、支持 `lock/status/forget` 文本指令与历史事件过滤，并纠正白名单精确匹配与超时口径漂移，使凭据与审计审批端到端可用。

## Requirements

### Requirement: 常驻同步循环与 token 持久化

系统 SHALL 在网关运行期间维持 Matrix `/sync` 常驻循环，携带 `since` token 并在每次成功同步后持久化，下次启动复用。

#### Scenario: 重启不丢 token

- **WHEN** 网关正常处理一批 sync 后重启
- **THEN** 新进程从持久化 token 处继续同步，不重放历史审批消息

#### Scenario: 断连指数退避

- **WHEN** sync 请求因断连失败
- **THEN** 系统按指数退避重试且不丢失已提交的 pending 审批单

### Requirement: reaction 接线与五分支处理

系统 SHALL 将收到的 reaction 事件按原因映射到五分支（unlock / 注册自动放行 / 注册普通审批 / 注册拒绝 / 哈希变更 / 凭据审批 / 审计审批），仅白名单成员的 ✅/❎/🔓 生效，未知分支与失配 `event_id` MUST 以 no-op 忽略。

#### Scenario: 批准放行

- **WHEN** 白名单成员对某 pending 单发送 ✅（或注册场景 🔓）
- **THEN** 对应 `ask/ask_audit` 返回批准且摘要中无明文

#### Scenario: 失配忽略

- **WHEN** reaction 指向不存在的 `event_id` 或非成员发送
- **THEN** 系统忽略且不改变任何 pending 状态

### Requirement: 文本指令与过滤器

系统 SHALL 支持 `lock/status/forget` 三文本指令；SHALL 忽略自反应、非目标 `room_id` 事件以及 `server_timestamp` 早于启动时间的历史事件。

#### Scenario: 三指令可用

- **WHEN** 管理员发送 `lock` / `status` / `forget`
- **THEN** 系统分别执行锁定、状态回显、遗忘 token 并回消息确认

#### Scenario: 历史事件不重放

- **WHEN** sync 返回启动前的历史 reaction
- **THEN** 系统丢弃且不触发任何审批决议

### Requirement: 白名单精确匹配与超时口径

系统 SHALL 对审批白名单做精确成员匹配（MUST NOT 当正则解释）；凭据审批超时 300s、审计审批超时 `AUDIT_TIMEOUT`（默认 90s，禁止 110-130s），超时返回未决并清理 pending；孤儿单 60s 清扫；审批链路补全已发送/等待中/超时/结果四段日志；MXID 非法格式启动期拒绝。

#### Scenario: 精确匹配

- **WHEN** 白名单为 `@admin:example.com` 且发送者为 `evil-admin:example.comX`
- **THEN** 系统拒绝该 reaction

#### Scenario: 超时清理

- **WHEN** 某审批单超过其超时仍无 reaction
- **THEN** 系统返回超时、清理 pending 且不泄漏明文
