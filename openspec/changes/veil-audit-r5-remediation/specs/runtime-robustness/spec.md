# Spec Delta

## ADDED Requirements

### Requirement: 配置文本形态校验字节级安全

启动期配置文本形态校验（`src/config/validate.rs::has_placeholder_token_shape` 的占位符形态扫描及同类文本索引扫描）SHALL 以**字节级安全**方式推进与切片：按字节推进的索引 SHALL 恒落在字符边界上，文本切片（如 `text[i..]`/`text[i + 6..]`）SHALL 恒为合法 UTF-8 边界；SHALL NOT 因索引落入多字节字符中间而 panic。含多字节字符（如中文）的自定义文案（`PII_PLACEHOLDER_PROMPT_TEXT`）SHALL 被正常校验且 SHALL NOT 使启动期 panic。校验语义（合法占位符形态检出→回退内置默认文案、超长按字符边界截断）SHALL 保持不变。

#### Scenario: 中文文案校验不 panic

- **WHEN** `PII_PLACEHOLDER_PROMPT_TEXT` 含多字节字符（如中文）且不含任何合法占位符形态
- **THEN** 启动期校验正常完成、不 panic，该文案按自定义值生效（不错误回退默认）

#### Scenario: 中文文案中的合法形态仍被检出

- **WHEN** 自定义文案含多字节字符且同时含合法占位符形态（如 `__PII_1_ab12cd34__` 或 `__VG_CRED_42__`）
- **THEN** 形态校验仍检出该占位符并回退内置默认文案，全程不 panic

### Requirement: 指标聚合脏数据不得静默归零或符号失真

指标回填/聚合读取路径（`src/service/metrics/aggregate.rs::backfill_rows_blocking` 的重启回填与 `src/service/metrics/aggregate.rs::query_series_blocking` 的序列读取；含 `part.trim().parse().unwrap_or(0)` 的桶值解析与 `row.get::<_, i64>(..) as u64` 的符号转换）SHALL NOT 对损坏或越界的存储计数静默失真：不可解析的桶值 SHALL 记 `warn!` 并计数后按有界策略收敛（SHALL NOT 无提示地归零），负的存储计数 SHALL 按有界策略收敛（SHALL NOT 经符号回绕伪装为极大值）。上述收敛 SHALL 不中断聚合流程。

#### Scenario: 损坏桶值显式告警不静默归零

- **WHEN** 重启回填读取到不可解析的桶值
- **THEN** 记 `warn!` 与相应计数，值按有界策略收敛（不静默归零），聚合流程继续

#### Scenario: 负值不符号失真为极大值

- **WHEN** 重启回填或序列读取遇到负的存储计数
- **THEN** 该值按有界策略收敛（不因符号回绕变为极大值），并记 `warn!` 与相应计数
