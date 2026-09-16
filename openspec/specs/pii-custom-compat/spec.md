# pii-custom-compat Specification

## Purpose
恢复与原仓一致的自定义脱敏规则加载能力：支持合并文件与分离文件、JSON/极简 YAML/TXT 名单及四个历史别名，严格校验命名组、禁用 `\b` 与嵌套、跨文件去重与重叠跳过，并以显式 BREAKING 收敛差异并给出迁移路径。

## Requirements

### Requirement: 文件格式与别名

系统 SHALL 支持合并文件与分离文件两种配置（`PII_CUSTOM_RULES_FILE` 优先并可与 `PII_CUSTOM_PATTERNS_FILE/PII_CUSTOM_DICT_FILE` 叠加），SHALL 支持 JSON 与极简 YAML 与 TXT 名单（每行一名，`#` 注释忽略），SHALL 兼容 4 别名（`PII_CUSTOM_PATTERN_FILE/PII_SENSITIVE_DICT_FILE/PII_SENSITIVE_NAMES_FILE/PII_RULES_FILE`）；已配置但缺文件/不可读/解析失败/形态非法 SHALL 拒启动，空文件/零命中仅 warn。

#### Scenario: YAML 可用

- **WHEN** 以 YAML 合并文件配置自定义规则并启动
- **THEN** 系统正常加载且命中后指标出现自定义 kind

#### Scenario: 缺文件拒启动

- **WHEN** 已配置路径但文件不存在
- **THEN** 系统拒绝启动而非静默未加载

### Requirement: 约束校验与管线语义

`name` SHALL 与 `(?P<name>...)` 内同名；禁止 `\b`（须用 lookaround）；禁止嵌套命名组；与 6 内置重名 SHALL 拒绝；跨文件重名 SHALL 去重；命中区间与 `__PII_*__/__VG_CRED_*__` 重叠 SHALL 跳过；凭据值优先；超长输入按 1MB 分块；单规则超时守卫连续 3 次停用；字典独立扫描且 `name/person` 走 CJK 边界。上述通过校验的自定义规则/模式/字典 SHALL 在运行时注入检测器并生效：启动装配 SHALL 以 `PII_CUSTOM_RULES_FILE`/`PII_CUSTOM_PATTERNS_FILE`/`PII_CUSTOM_DICT_FILE`（含短名内联槽与全部别名）调用运行时加载并注入检测器，MUST NOT 仅做启动校验而在运行时零接线。加载失败 SHALL 沿用既有 fail-closed 语义（缺文件/不可读/解析失败/形态非法拒启动），MUST NOT 静默降级为空规则集。运行时命中 SHALL 可观测（命中 kind 反映到指标/审计面，停用计数反映到健康检查 `pii_custom_disabled`）。

#### Scenario: 违规被拒

- **WHEN** 自定义规则含 `\b` 或与内置 `phone` 重名
- **THEN** 系统拒绝该规则并告警，不静默加载

#### Scenario: 自定义规则运行时命中

- **WHEN** 配置自定义规则/模式/字典文件（或内联槽）且启动成功
- **THEN** 命中自定义规则时扫描返回对应 kind，且该命中在指标/审计面可观测，证明规则已在运行时注入生效（非仅启动校验）

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
