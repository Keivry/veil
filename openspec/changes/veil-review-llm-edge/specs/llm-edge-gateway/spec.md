## Purpose

锁定 LLM 边缘与网关 9 项口径修复的可验证行为：归一化声明、非流回退链、双缓冲分工、空流合成守门、会话透传、IPv6 选路、编码声明。

## ADDED Requirements

### Requirement: Responses 占位符注入归一化声明

系统 SHALL 对占位符说明注入分支按所选方案处理：纳入 `x-veil-normalized` 置位条件③，或明确声明占位符注入不声明；所选方案 SHALL 单测锁定。

#### Scenario: 注入分支声明一致

- **WHEN** 请求体经占位符说明注入改写
- **THEN** `normalized_out` 与所选方案一致，且下游响应头按 `normalized_out` 置位

### Requirement: 纯脱敏字节替换不置位口径

系统 SHALL 声明纯脱敏子串替换（字节级，未重序列化）不置位 `x-veil-normalized`，即使替换后长度变化；该口径 SHALL 单测锁定。

#### Scenario: 长度变化仍不置位

- **WHEN** 纯脱敏替换改变请求体字节长度但未重序列化
- **THEN** `normalized_out` 为假且无 `x-veil-normalized` 头

### Requirement: 非流还原回退前残缺重试

系统 SHALL 在非流还原后 JSON 校验失败时先经 `strip_partials` 重试一次，仍失败才回退上游原文；回退 SHALL 记 metrics 或 warn 可观测。

#### Scenario: 残缺可挽回不丢还原

- **WHEN** 还原后 JSON 破裂但剥离残缺形态后可解析
- **THEN** 下游收到剥离后还原体而非上游原文

#### Scenario: 仍失败回退可观测

- **WHEN** 重试后仍不可解析
- **THEN** 下游收到上游原文且有 warn 或 metrics 记录

### Requirement: 非错误状态 JSON 后处理声明

系统 SHALL 声明非 502/401 错误状态的 JSON 体仍进后处理链（用量记录加审计判定加还原），非字节等价为有意行为；该语义 SHALL 单测锁定。

#### Scenario: 400 系 JSON 仍后处理

- **WHEN** 上游回 400 系 JSON（如 `truncation:disabled`）
- **THEN** 系统走完整后处理链而非原样透传

### Requirement: 双缓冲分工明确

系统 SHALL 将 `AuditHold` 与 `pending_tool_frames` 统一为一套缓冲，或以注释明确两者分工（谁持有何种分片、何时移交）；分工 SHALL 单测锁定。

#### Scenario: 缓冲职责可追踪

- **WHEN** 流式 tool 分片到达且审计 hold 开启
- **THEN** 分片去向符合注释声明的分工，无双重持有或丢失

### Requirement: 空流合成排除注释帧

系统 SHALL 使 `comment_only` 心跳帧不置位 `any_frame_sent`，纯心跳流 SHALL 仍合成终端帧。

#### Scenario: 纯心跳仍合成终端

- **WHEN** 上游流仅含 `:` 注释心跳帧
- **THEN** 下游仍收到合成终端帧而非悬空结束

### Requirement: 非流转泵透传请求会话

系统 SHALL 在非流转流泵分支透传请求会话标识，不再以空值合成会话；透传失败回退合成 SHALL 记 `conv_missing`。

#### Scenario: 转泵会话可追踪

- **WHEN** 非流请求携会话标识但上游回 SSE
- **THEN** 泵内终端与截断帧复用请求会话而非合成随机值

### Requirement: Host IPv6 方括号解析

系统 SHALL 以方括号解析 `Host` 头中的 IPv6 字面量（如 `[::1]:8878` 取端口 `8878`），裸冒号 IPv6 无端口 SHALL 回退缺省上游而非误取尾段。

#### Scenario: 方括号 IPv6 取端口

- **WHEN** `Host: [::1]:8878`
- **THEN** 入口端口解析为 `8878`

#### Scenario: 裸 IPv6 不误判

- **WHEN** `Host: ::1`（无端口）
- **THEN** 入口端口为 `None`，走缺省上游

### Requirement: 编码剥离对外 identity 声明

系统 SHALL 以一行日志或文档声明解码开启时剥离 `content-encoding`/`content-length`、对外统一 `identity`；该行为 SHALL 单测锁定已覆盖。

#### Scenario: gzip 上游对外 identity

- **WHEN** 上游回 `content-encoding: gzip` 且解码开启
- **THEN** 下游响应无 `content-encoding`/`content-length`，且有声明可查
