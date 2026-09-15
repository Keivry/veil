## ADDED Requirements

### Requirement: AuditLogger 并发追加与轮转测试

系统 SHALL 为审计日志追加与轮转提供并发回归测试（实现对证：`src/service/audit/log.rs:461-474`）：多线程并发追加 SHALL 断言无丢行、无交错损坏（每行完整、落盘行数等于写入总数），并发追加与轮转 SHALL 断言轮转产物完整可读且不丢已确认写。该契约对标原仓 `test_append_and_concurrent_safe`；若测试暴露实现缺口，SHALL 在 apply 阶段同步修复实现而非放宽断言。

#### Scenario: 并发追加不丢行

- **WHEN** 多线程并发对同一 `AuditLogger` 追加已知条数的记录
- **THEN** 落盘行数等于写入总数、每行完整无交错，任一并发写不丢失

#### Scenario: 轮转并发不损坏

- **WHEN** 在并发追加的同时触发日志轮转
- **THEN** 轮转产物与活跃文件均可读、零明文、已确认写不丢，测试对丢行或损坏具备区分度

### Requirement: GET /registrations 部署密钥鉴权分支测试

系统 SHALL 为 `GET /registrations` 的部署密钥鉴权分支提供 e2e 测试（实现对证：`src/service/credential/vault_ops.rs:154-159`；现测 `tests/http_e2e_credential.rs:385` 仅覆盖管理 token）：匹配的 `X-Get-Binary-Secret` SHALL 放行并返回注册表，密钥不匹配 SHALL 401，管理 token 与部署密钥双缺 SHALL 401。测试 SHALL 锁定「管理面鉴权（`X-Admin-Token` 或部署密钥）两者任一」语义，SHALL NOT 仅以管理 token 路径抵充分支覆盖。

#### Scenario: 部署密钥匹配放行

- **WHEN** 携带与配置一致的 `X-Get-Binary-Secret` 请求 `GET /registrations`
- **THEN** 返回 200 与注册表体，状态码与响应形状符合契约

#### Scenario: 密钥不匹配与双缺拒绝

- **WHEN** 分别以错误的 `X-Get-Binary-Secret`、以及管理 token 与部署密钥皆缺请求 `GET /registrations`
- **THEN** 两场景均返回 401，且不返回注册表内容

### Requirement: TPM 测试不空转

系统 SHALL 使 TPM 相关测试在硬件存在与否两种环境下均不产生「条件化断言空转」的假绿（实现对证：`src/service/tpm.rs:342-364`）：硬件缺失或不可用时 SHALL 以显式 skip 标记（可识别、非静默通过）或注入测试桩替代执行，SHALL NOT 以「条件不满足即跳过全部断言」方式静默通过。该契约与 `test-e2e-closure` 的同源假绿收紧条款一致。

#### Scenario: 硬件缺失显式标记

- **WHEN** 在无 TPM 硬件的环境运行 TPM 测试
- **THEN** 输出显式 skip 标记或经注入桩执行等价断言，测试结果不呈现为未区分的通过

#### Scenario: 硬件存在执行真实断言

- **WHEN** 在具备 TPM 的环境运行同一测试
- **THEN** 执行真实断言路径，不因条件分支跳过关键校验

### Requirement: 测试死分支清除

系统 SHALL 清除测试中的死分支：`src/service/audit/hold/tests.rs:65-67` 中被前置断言已锁定的分支 SHALL 被移除，或改写为具备区分度的有效断言；SHALL NOT 保留永不执行或因前置不变量恒真的分支作为表面覆盖。

#### Scenario: 死分支不残留

- **WHEN** 审查 `src/service/audit/hold/tests.rs` 的目标分支
- **THEN** 原死分支已移除或替换为「行为回退即失败」的有效断言，覆盖计数不虚增

### Requirement: tool_calls 参数内脱敏还原端到端测试

系统 SHALL 提供端到端集成测试闭合「脱敏→还原」在 `tool_calls` 参数内的覆盖缺口：请求体在工具调用参数内携带 PII 时，网关 SHALL 以占位符替换，响应侧 SHALL 将占位符还原为与请求逐字一致的原文。现有真 SDK conformance 请求体不含 token，不足以覆盖该路径，测试 SHALL 独立构造含 PII 的 `tool_calls` 参数并断言逐字一致。

#### Scenario: 工具参数内占位符往返

- **WHEN** 请求在 `tool_calls`/函数调用参数内携带已知 PII，经网关到回声上游后返回响应
- **THEN** 上游侧该 PII 已被占位符替换、响应侧还原为与请求逐字一致的原文，占位符不泄漏到下游

## MODIFIED Requirements

### Requirement: 真 SDK 脚本纳入门禁

系统 SHALL 为 `scripts/api_conformance.py`（23 项：14 常规 + 3 阻断 + 5 取用 + 1 无库 503）提供显式 gate 步骤（`scripts/gate.sh` 或等价可执行步骤），串联格式化、lint、单测、文档路径校验、文件大小校验与真 SDK 一致性；SHALL 声明前置条件（Python venv、SDK pin `openai==3.5.0`/`anthropic==1.1.0`、Mock TPM 回退）与失败非零退出语义；缺前置时 SHALL 显式报错或经参数显式跳过并打印理由，SHALL NOT 静默跳过。SHALL 保留脚本口径，SHALL NOT 改写为 cargo 测试。

#### Scenario: gate 步骤可执行且失败非零

- **WHEN** 在具备前置条件的环境执行 gate
- **THEN** 六步全绿退出码 0；真 SDK 脚本输出「共 23 项，失败 0 项」；任一子步骤失败即整体非零退出

#### Scenario: 前置条件与显式跳过

- **WHEN** Python venv/SDK 缺失时执行 gate
- **THEN** 以显式前置条件错误退出，或经显式参数跳过并在输出打印跳过理由与 doc 链接；不出现无输出的静默跳过

#### Scenario: 文档口径同步

- **WHEN** 查阅 README §8.5 与 `scripts/README.md`
- **THEN** 命中「已纳入 gate 步骤 + 前置条件 + 跳过语义」表述，且本仓口径为真 SDK 脚本 23 项（14 常规 + 3 阻断 + 5 取用 + 1 无库 503）；README §8.5 的 23 项明细与脚本输出一致，原仓 12 项（cargo）对照标签不与之冲突
