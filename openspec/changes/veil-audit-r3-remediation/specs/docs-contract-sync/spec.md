## MODIFIED Requirements

### Requirement: 环境变量表完整

二进制读取的每个环境变量 SHALL 在 README 环境变量表有可检索的行；新增读取 SHALL 同 change 补行；README:26 的「未列出的变量二进制不读取」断言 SHALL 在补录完成后为真。

#### Scenario: 隐藏开关被补录

- **WHEN** 核查 `OBSERVABILITY_DISABLE`（`src/config/env_parse.rs:295-296`、`src/router.rs:19-28`）
- **THEN** README 变量表含该行，语义为精确 `=1`（去空白）时 `/_admin*` 全 404 且与 token 有效性无关（`tests/http_e2e_admin_matrix.rs:252-254`）

#### Scenario: 完整性断言可复核

- **WHEN** 用 grep 从 `src/config/env_parse.rs` 提取 `get("...")` 变量名，与 README 环境变量表的反引号变量名做差集
- **THEN** 差集为空（表外无二进制读取变量）
