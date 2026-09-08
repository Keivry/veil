## Purpose

补齐输出审计策略引擎与日志口径，使危险工具调用拦截率与原仓一致且零明文落盘。

## ADDED Requirements

### Requirement: 策略引擎补名单与预检

审计 SHALL 支持 `allow/deny` 名单、`internal_suffixes`、host 提取、`audit_precheck`、evaluate 内 MXID 白名单校验、旧 `AUDIT_ENABLED` 兼容；策略文件 SHALL 兼容原仓全量形态（allow/deny/dangerous 可覆盖）。

#### Scenario: allow 名单放行

- **WHEN** 调用命中 allow 名单
- **THEN** 系统放行且不误报

#### Scenario: 内网后缀不判外传

- **WHEN** host 命中 internal 后缀
- **THEN** 系统不按外传危险处理

### Requirement: 日志脱敏口径对齐

审计日志 SHALL 先脱敏后截断；截断长度/控字符/secret 模式 SHALL 与原仓一致（120 语义或文档化差异）；强化层异常 SHALL 返回 `[REDACTED:unverified]` 而非明文。

#### Scenario: 强化层异常零明文

- **WHEN** PII 强化层异常
- **THEN** 日志落盘为占位符而非明文

### Requirement: hold 完成判定清理

`is_complete_event` 不可达重复分支 SHALL 删除；`decide_via_gateway` SHALL 落实 Block/Approve 而非 Noop 占位。

#### Scenario: Responses done 才审计

- **WHEN** 增量未收齐 done
- **THEN** 系统暂缓放行，收齐后审计
