## MODIFIED Requirements

### Requirement: 指标口径声明无陈旧 TODO

README §7.3 SHALL 以「命中率本地不测量（wont-measure）」表述 prompt-cache 差异，SHALL NOT 残留 `TODO(metrics)` 字样；声明 SHALL 与 `src/service/metrics.rs` 模块文档（`:7-12`）**逐义同字**（同一措辞集）。

**会话级例外下的锁步同字（`veil-pii-conversation-cache`）**：当引入 `PII_SCOPE_MODE=conversation`（有界、租户+会话作用域、非持久）后，README §7.3 与 `src/service/metrics.rs:7-12` SHALL 在**同一变更批内同步**更新为同义口径——「默认请求级隔离为隐私硬要求 + `conversation` 显式启用时于有界、非持久窗口内允许会话级关联」；两侧措辞 SHALL 保持一致（same wording），MUST NOT 单侧更新致文档-代码漂移。`request`（默认）语义下本要求与原条文逐项一致。

#### Scenario: TODO 字样清零

- **WHEN** 检索 README 全文
- **THEN** 零命中 `TODO(metrics)`；零命中「TODO(metrics) 以此为 wont-measure 闭环」旧句式

#### Scenario: 口径同字

- **WHEN** 比对 README §7.3 与 `src/service/metrics.rs:7-12`
- **THEN** 两侧均表述为「命中率差异本地不测量（wont-measure）」且理由一致（上游 provider 侧计费指标不可见真值 + 请求隔离为隐私硬要求）；若引入会话级例外，两侧仍 SHALL 逐义一致（默认请求级 + 有界会话级例外的措辞同批同步）

#### Scenario: 会话级例外不破坏同字

- **WHEN** `PII_SCOPE_MODE=conversation` 的语义被写入 README §7.3
- **THEN** `src/service/metrics.rs:7-12` 在同一变更批内被同步更新为同义口径（默认请求级为隐私硬要求 + 有界、非持久会话级例外），任一侧单独漂移即判失败
