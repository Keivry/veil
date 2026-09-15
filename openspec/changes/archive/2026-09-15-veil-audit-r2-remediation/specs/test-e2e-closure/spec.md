## MODIFIED Requirements

### Requirement: 边缘矩阵与弱断言收紧

空流 hold 四分支矩阵、并发 Scope/audit_hold 隔离、并发解锁单 ask、观测 DB 持久（按日 UPSERT/7 天滚动/0600 含 wal-shm/persist=0 不建表/401 不泄漏）SHALL 补齐；ReDoS（真超时记账 + `<200ms`）、性能锚点（5000 字典/1MB/增量秒级）、`is_precise` 双条件、p95 三态、帧级 `event:` 序列断言、`[DONE]` 精确单帧计数 + 子串负例、嵌套 `p@ss"quote/\u/BOM` 强断言、采样全矩阵 SHALL 收紧。既有宽松/假绿断言 SHALL 一并钉死：`tests/http_e2e_ratelimit.rs:145-149` 的 `Ok(Ok(_))` SHALL 拆分为 `Ok(Ok(Some(_)))`（断言连接保持打开）与 `None => panic!`（显式失败），SHALL NOT 以单一模式同时匹配 `Some`/`None` 致无法区分保持打开与被关闭；`src/handler/llm/pump/fragments/tests.rs:60` 的宽松析取 `is_empty() || len()==1` SHALL 钉死为单一期望值；`src/service/tpm.rs:342-364` 的条件化断言 SHALL 改为硬件缺失时显式 skip 标记或注入桩，SHALL NOT 条件不满足即空转假绿（与 `test-coverage-fill`「TPM 测试不空转」同源）；`src/service/audit/hold/tests.rs:65-67` 的死分支 SHALL 移除或改为有效断言。

#### Scenario: 限流断言区分保持打开与被关闭

- **WHEN** 运行 `tests/http_e2e_ratelimit.rs` 的连接保持/关闭断言
- **THEN** 保持打开路径以 `Ok(Ok(Some(_)))` 断言、被关闭路径以 `None => panic!` 断言；单一 `Ok(Ok(_))` 匹配模式不再存在，无法区分两态的弱断言会使测试失败

#### Scenario: 分片析取钉死

- **WHEN** 检查 `src/handler/llm/pump/fragments/tests.rs` 的分片数量断言
- **THEN** 期望值为唯一确定值，不再出现 `is_empty() || len()==1` 式恒宽析取

#### Scenario: TPM 测试不空转

- **WHEN** 在无 TPM 硬件环境运行 TPM 相关测试
- **THEN** 以显式 skip 标记或注入桩执行，不产生条件化断言空转的未区分通过；与 `test-coverage-fill`「TPM 测试不空转」契约一致

#### Scenario: hold 测试死分支清除

- **WHEN** 审查 `src/service/audit/hold/tests.rs:65-67`
- **THEN** 前置断言已锁定的死分支被移除或改为有效断言，目标行为回退时测试失败

#### Scenario: 性能退化被捕获

- **WHEN** 5000 字典扫描超过 500ms
- **THEN** 测试失败告警
