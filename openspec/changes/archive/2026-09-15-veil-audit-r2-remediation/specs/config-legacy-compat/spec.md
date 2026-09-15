## ADDED Requirements

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
