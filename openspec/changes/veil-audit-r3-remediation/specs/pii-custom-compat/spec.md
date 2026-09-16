## ADDED Requirements

### Requirement: 聚合超时不逐规则记账

系统 SHALL 在 `scan_custom` 的**聚合墙钟超时**（`tokio::time::timeout` 到期）或阻塞任务 panic 时，SHALL NOT 对任何规则执行超时记账；系统 SHALL 仅记一条全局 warn（含规则数与预算）并返回零命中。规则停用 SHALL 仅由 batch 内逐规则 `find_iter` 的 `Err` 路径触发（连续 `RE_DOS_STRIKES=3` 次）；SHALL NOT 由聚合超时触发。

已知残余 SHALL 显式登记：持续慢规则会使每帧零自定义命中（自定义 PII 的 fail-open），但不再全量停用规则集；唯一可观测面为上述全局 warn。

#### Scenario: 聚合超时不触发停用

- **WHEN** 自定义规则扫描发生一次聚合墙钟超时
- **THEN** 不递增任何规则的超时计数、不触发三连停用，仅记一条全局 warn 并返回零命中

#### Scenario: 逐规则 Err 仍触发停用

- **WHEN** batch 内某规则的 `find_iter` 连续 3 次返回 `Err`
- **THEN** 该规则被停用并记 warn，停用计数在健康检查 `pii_custom_disabled` 可见

### Requirement: 规则集 Arc 只读共享与批量记账

`PiiDetector::custom` SHALL 以 `RwLock<Arc<Vec<(String, Regex, String)>>>` 承载规则集；`scan_custom` SHALL 仅做 `Arc::clone` 传递只读共享引用，SHALL NOT 每帧深克隆规则集。唯一写点 SHALL 使用 `Arc::make_mut` 增改。超时记账 SHALL 以批量口径 `account_rules_batch(&[(name, timed_out)])` 单次获取 `strikes` 与 `disabled`（保持既有锁序），逐规则成功清零/超时累计/三连停用并跳过已停用者，SHALL NOT 对每规则各取双锁。

#### Scenario: 连续多帧不逐帧克隆

- **WHEN** 连续多帧经 `scan_custom` 扫描
- **THEN** 规则集经 `Arc::clone` 复用同一只读引用，不随帧深克隆

#### Scenario: 批量记账单次加锁

- **WHEN** 一帧内多条规则进入超时/成功记账
- **THEN** 单次获取 `strikes` 与 `disabled` 完成全部记账，锁序与停用状态机结果逐项不变
