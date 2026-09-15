# metrics-admin-parity Specification

## Purpose
恢复指标口径与管理面兼容性：对齐 12 桶延迟边界、缓存 usage 列、daily/hourly 双写、five_min 滚动、`redact_summary` 与 `is_precise` 双条件，并保证 health 豁免限流、Cookie 回退与 token 文件交叉检查，使旧大盘与告警不断链。

## Requirements

### Requirement: 指标口径对齐

延迟桶 SHALL 改回 12 桶 Python 边界；Usage SHALL 补 `cached_read/write/unknown`；`daily/hourly` SHALL 补 pii/cred/audit 列或提供双写兼容视图；`five_min` 滚动/覆盖 UPSERT/重启回填 SHALL 对齐；`redact_summary` 口径 SHALL 对齐；`is_precise` SHALL 为 `(窗口>=3600s && 样本>=100)` 双条件；p95 SHALL 为桶中位近似。`model` 分桶 SHALL 在响应体缺失有效 `model` 字段时回退到**请求侧 model**，流式与非流式 SHALL 使用同一回退口径；仅当请求与响应均无有效 `model` 时才 SHALL 落 `unknown_model`。

#### Scenario: 历史曲线可比

- **WHEN** 对比迁移前后 24h p95
- **THEN** 桶边界一致，曲线无跳变

#### Scenario: 低流量标近似

- **WHEN** 样本不足 100
- **THEN** `is_precise=false` 并标 `≈`

#### Scenario: 响应缺 model 回退请求 model

- **WHEN** 上游响应体不含有效 `model` 字段（流式或非流式）但请求体含 `model`
- **THEN** 该次观测按请求 `model` 分桶，不落 `unknown_model`

#### Scenario: 双侧均无 model 才落 unknown_model

- **WHEN** 请求体与响应体均无有效 `model` 字段
- **THEN** 该次观测落 `unknown_model` 桶

### Requirement: 管理面兼容

`/_admin/health` SHALL 豁免限流；Cookie SHALL 支持 http 回退并签发 `Set-Cookie`；Token 独立 SHALL 补 `DATA_DIR/admin_token` 文件检查；`OBSERVABILITY_DISABLE`/`ENV=dev` 回环免 token SHALL 恢复或以 BREAKING 声明；SSE SHALL 补 15s 快照/2s 增量/过滤维度或声明；`metrics` 过滤 SHALL 按 model/upstream 生效或明确全局口径。

#### Scenario: health 不被限流误伤

- **WHEN** 管理接口被打满
- **THEN** health 仍 200

#### Scenario: 非 SSE query 恒 401

- **WHEN** 非 SSE 接口以 query 传 token
- **THEN** 系统返回 401
