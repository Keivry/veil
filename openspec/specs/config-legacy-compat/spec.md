# config-legacy-compat Specification

## Purpose
锁定遗留环境变量兼容面：`AUDIT_ENABLED` 回退语义（fail-closed）、遗留变量 warn 清单完整性与 README §7.4 锁步、`CREDENTIAL_BLOCK_WAIT` 真值集合文档契约。

## Requirements

### Requirement: AUDIT_ENABLED 遗留回退

系统 SHALL 在 `AUDIT_MODE` 缺失或空白时经 `audit_enabled_compat` 回退读取 `AUDIT_ENABLED`：真值集合 `1`/`true`/`yes`/`on`（trim + 大小写不敏感）SHALL 映射为 `block`（fail-closed）；`AUDIT_MODE` 显式非空时 SHALL 优先且不触发回退；非真值/空白 SHALL 不生效（缺省 `off`）。回退实现 SHALL 由 `Config::load_from` 调用，不得留 dead code 中间态。

#### Scenario: 缺 AUDIT_MODE 时 AUDIT_ENABLED 真值转 block

- **WHEN** 环境未设置（或仅空白）`AUDIT_MODE` 且 `AUDIT_ENABLED` 为 `1`/`true`/`yes`/`on` 之一（trim + 大小写不敏感）
- **THEN** `Config::load_from` 得到的 `audit_mode` 为 `block`，并在启动加载期打出指名该回退的 warn

#### Scenario: AUDIT_MODE 显式优先

- **WHEN** `AUDIT_MODE` 显式非空（如 `off`）且同时 `AUDIT_ENABLED=1`
- **THEN** 采用 `AUDIT_MODE` 的值，`AUDIT_ENABLED` 不生效

#### Scenario: 非真值不触发回退

- **WHEN** `AUDIT_ENABLED` 为 `0`/`false`/`off`/未知值/空白
- **THEN** 不产生回退，缺省审计模式仍为 `off`

#### Scenario: 回退经生产调用链接线

- **WHEN** 查阅 `audit_enabled_compat` 的调用点
- **THEN** `Config::load_from` 为其唯一生产调用点，无「定义未接线」的 dead code 中间态

### Requirement: 遗留变量 warn 清单完整性

系统 SHALL 维护 `LEGACY_IGNORED_VARS` 为遗留变量的唯一权威清单，名称集合恰为 `CREDENTIAL_MASTER_PASSWORD`、`CREDENTIAL_PORT`、`CREDENTIAL_PROXY_DEBUG_DIR`、`ENV`、`ALLOW_LOOPBACK_NO_TOKEN`、`CREDENTIAL_API_PORT`；任一变量非空置位 SHALL 在启动加载期 warn 并给出改名指引，且该值 SHALL 不改变任何配置生效值。README §7.4 SHALL 与该清单逐项锁步：两侧名称集合相等，任一侧增删未同步即告警失败。

#### Scenario: 新纳入变量置位即 warn

- **WHEN** `ENV`/`ALLOW_LOOPBACK_NO_TOKEN`/`CREDENTIAL_API_PORT` 任一被设为非空
- **THEN** 启动加载期产生指名 warn（含改用指引），行为保持不读取，配置生效值不变

#### Scenario: 清单与文档锁步

- **WHEN** 运行 README-清单一致性测试
- **THEN** `LEGACY_IGNORED_VARS` 名称集合与 README §7.4 各行首列变量名集合相等，任一侧增删未同步即测试失败

#### Scenario: 清单集合锁定

- **WHEN** 运行集合锁单测
- **THEN** 清单恰为上述六项；增删须同时更新测试与本 spec，防静默漂移

### Requirement: CREDENTIAL_BLOCK_WAIT 真值文档契约

README SHALL 把 `CREDENTIAL_BLOCK_WAIT` 的开启条件声明为真值集合 `1`/`true`/`yes`/`on`（trim + 大小写不敏感），默认关闭；文档 SHALL 与 `parse_bool_off`/`is_truthy` 实现一致，不得只写 `=1`。

#### Scenario: 真值集合文档与实现一致

- **WHEN** 查阅 README 的 `CREDENTIAL_BLOCK_WAIT` 行
- **THEN** 开启条件写明 `1/true/yes/on` 四种真值且默认关闭，与 `parse_bool_off` 口径一致

#### Scenario: 真值全量生效

- **WHEN** 分别设置 `CREDENTIAL_BLOCK_WAIT=1/true/yes/on`
- **THEN** `credential_block_wait` 均为 true；`0/false/off` 与未设置均为 false

### Requirement: OBSERVABILITY_DISABLE 豁免管理 token 门禁

`OBSERVABILITY_DISABLE` 精确 `=1`（去空白）时，`/_admin*` 全 `404`（与 token 有效性无关）；此时系统 SHALL NOT 要求 `OBSERVABILITY_ADMIN_TOKEN`——缺 token SHALL NOT 导致拒启动，管理面请求因全 `404` 而不进入鉴权。token 校验门禁（含启动期门禁顺序）SHALL 在 `OBSERVABILITY_DISABLE=1` 时被豁免，使「禁用即不要求 token」语义自洽。取值非 `=1`（未设或其它值）时 SHALL 保持既有必填与鉴权语义不变。

#### Scenario: 禁用时缺 token 不拒启动

- **WHEN** `OBSERVABILITY_DISABLE=1` 且未设置 `OBSERVABILITY_ADMIN_TOKEN`
- **THEN** 系统正常启动（不因缺 token 拒启动），且 `/_admin*` 全 `404`

#### Scenario: 禁用时请求恒 404

- **WHEN** `OBSERVABILITY_DISABLE=1`，携带任意 token 或不携带 token 请求 `/_admin/*`
- **THEN** 一律返回 `404`，与 token 有效性无关

#### Scenario: 非 1 取值保持必填语义

- **WHEN** `OBSERVABILITY_DISABLE` 未设或非 `=1` 取值
- **THEN** 管理 token 仍按既有语义必填与鉴权，行为不变

### Requirement: PII_HOLD_MAX 上界与非法值处理

`PII_HOLD_MAX`（默认 `64`，须 ≥1 正整数）SHALL 施加显式上界（与响应侧缝窗语义匹配，上界取值 `1048576`/1MB）；取值超过上界 SHALL 被钳位到上界并记 warn，SHALL NOT 让超出上界的缝窗生效；非法取值（非正整数）SHALL 显式拒绝启动，SHALL NOT 静默回退默认或按非法值运行。

#### Scenario: 超过上界被钳位

- **WHEN** `PII_HOLD_MAX` 取值大于上界（如 `1048576`）
- **THEN** 生效缝窗被钳位到上界并记 warn，内存占用有界

#### Scenario: 非法值拒启动

- **WHEN** `PII_HOLD_MAX` 取值为零、负数或非整数
- **THEN** 启动以配置错误被拒绝，给出合法取值说明，不静默回退默认值
