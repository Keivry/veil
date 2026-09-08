## Purpose

修复管理面与指标查询的兼容断裂，或以显式 BREAKING 声明新口径并升级调用方。

## ADDED Requirements

### Requirement: 查询兼容

系统 SHALL 兼容旧查询（`series?range=1h/24h/7d/30d`、`metrics/events?model&upstream`、`events?verdict` 接受旧值并标注弃用），或以 BREAKING 声明新口径（`granularity/since/protocol/kind/limit`）并同步升级大盘与脚本；`/_admin/` SHALL 明确为 JSON 索引终态；鉴权优先级（头 > Cookie > 仅 SSE query）与非 SSE query 恒 401 SHALL 保持；限流按 TCP 远端计数、不读代理头；`OBSERVABILITY_DISABLE`、`admin_token` 文件交叉检查、`Secure/HttpOnly` 语义 SHALL 明确保留或声明移除。

#### Scenario: 旧大盘可用

- **WHEN** 旧大盘以 `range=24h&model=gpt-4o` 查询
- **THEN** 系统返回正确结果或明确的弃用标注，不返回空结果误导

### Requirement: 存储与口径

指标存储 SHALL 保持 WAL、`busy_timeout`、`0600`（含 wal/shm）、ENOSPC 降级内存-only；仅对话端点计数；flush 为覆盖式 UPSERT 不翻倍；延迟 12 桶 p95 近似与 `is_precise` 语义明确；摘要脱敏单一路径先脱敏后截断；PII 值采样掩码与 HMAC 口径明确。

#### Scenario: 磁盘满不崩

- **WHEN** 磁盘写满
- **THEN** 进程降级内存-only、`health.sqlite_ok=false` 且不崩溃
