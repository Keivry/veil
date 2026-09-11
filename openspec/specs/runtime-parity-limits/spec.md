# runtime-parity-limits Specification

## Purpose
显式锁定 parity 收口的运行时行为契约：非流对话响应体上限（含与审计 ceiling 的检查点区分）、PII 字典文件名别名接受、凭据审批默认异步 `202` 契约、PII 序号分配有界复用。与本 change 的 design.md 决策同源，apply 阶段实现与测试均以本 spec 为准。

## Requirements

### Requirement: 非流对话响应体上限声明

系统 SHALL 支持 `NONSTREAM_MAX_BYTES` 配置（默认 `8388608`，即 8MB），对非流对话响应体（chat/completions、v1/messages、v1/responses 尾缀）执行上限检查；当上游状态非错误（`status < 400`）且响应体长度严格大于上限时 SHALL 返回 `502`，JSON 体 SHALL 为 `{"error":{"message":"response too large","type":"response_too_large"}}` 且 `Content-Type: application/json`（对齐 Python `_llm.py:2942`）；上游状态为错误（`status >= 400`）时该上限 SHALL NOT 改写响应，非 JSON 错误体按状态码与正文字节原样透传、错误 JSON 走调用方完整后处理链。显式设置但非整数或小于 `1` 时系统 SHALL 拒绝启动（fail-closed）。非对话（`Protocol::NonDialog`）透传路径 SHALL NOT 受该上限约束。该上限与非流路径既有 502/401 错误体处理、空体分类的先后语义 SHALL 与 Python 对齐：先判空体，再判超限。

#### Scenario: 超限命中

- **WHEN** 上游状态非错误且非流对话响应体长度大于 `NONSTREAM_MAX_BYTES`
- **THEN** 系统返回 502 且 JSON 体 error.type 为 response_too_large、error.message 为 response too large

#### Scenario: 错误状态超限不改写

- **WHEN** 上游返回 `status >= 400` 且响应体长度大于 `NONSTREAM_MAX_BYTES`
- **THEN** 系统不触发超限 502，非 JSON 错误体按状态码与字节原样透传，错误 JSON 走完整后处理链

#### Scenario: 边界等于上限放行

- **WHEN** 非流对话响应体长度恰好等于 `NONSTREAM_MAX_BYTES`
- **THEN** 系统不触发超限分支，按正常响应处理

#### Scenario: 非对话透传不受限

- **WHEN** 非对话路径（如模型列表）响应体超过上限
- **THEN** 系统仍字节透传，不检查、不改写为 502

#### Scenario: 配置非法拒启动

- **WHEN** `NONSTREAM_MAX_BYTES` 被显式设为非整数或 `0`
- **THEN** 启动被拒绝并给出明确配置错误（不静默回退默认值）

#### Scenario: 与审计 ceiling 为不同检查点

- **WHEN** 查阅 spec 与 README §4 的 8MB 取值说明
- **THEN** 文档显式区分 `NONSTREAM_MAX_BYTES`（非流响应体，入口 enforcement）与 `AUDIT_SUBLIMIT_CEILING_BYTES`（审计子限锚点，非入口 enforcement），两者不可互相替代

### Requirement: PII 字典文件名别名接受

系统 SHALL 在自定义字典文件槽接受 `PII_DICT_FILE` 作为别名，与主名 `PII_CUSTOM_DICT_FILE` 及既有别名 `PII_SENSITIVE_DICT_FILE`/`PII_SENSITIVE_NAMES_FILE`/`PII_CUSTOM_DICT` 等价加载；多个变量并存时 SHALL 按声明的列序取首个非空项，且列序 SHALL 保证 `PII_DICT_FILE` 相对 Python 三个历史名的优先级与 Python 一致（`PII_DICT_FILE` > `PII_SENSITIVE_DICT_FILE` > `PII_SENSITIVE_NAMES_FILE`）。别名已配置但文件缺失、不可读或解析失败时 SHALL 拒启动（沿用既有 `PII_CUSTOM_*` fail-closed 语义）；README 环境变量表 SHALL 为该别名提供归属，legacy 规则表 SHALL NOT 将 `PII_DICT_FILE` 列为「二进制不读取」。

#### Scenario: 别名与主名等价加载

- **WHEN** 同一字典文件内容分别经 `PII_CUSTOM_DICT_FILE`（主名）与 `PII_DICT_FILE`（别名）配置启动
- **THEN** 字典命中集合与脱敏结果一致

#### Scenario: 别名文件缺失拒启动

- **WHEN** `PII_DICT_FILE` 指向不存在或不可读的文件
- **THEN** 系统拒绝启动并指明该变量与路径（不静默忽略）

#### Scenario: 多变量并存按列序优先

- **WHEN** `PII_DICT_FILE` 与 `PII_SENSITIVE_DICT_FILE` 同时设置
- **THEN** 系统采用 `PII_DICT_FILE`（列序在前），与 Python `_pii.py:569` 优先级一致

#### Scenario: README 归属可查

- **WHEN** 在 README 环境变量表检索 `PII_DICT_FILE`
- **THEN** 该名出现在字典文件变量行且说明等价加载语义，legacy 规则表中无该名

### Requirement: 凭据审批默认异步 202 契约

系统 SHALL 保持凭据审批默认异步：`CREDENTIAL_BLOCK_WAIT` 未设或非 `1` 时，enrolled 哈希篡改/未 enrolled 待审请求 SHALL 立即返回 `202` 与 `E_PENDING`（已建单 + best-effort 发送审批），SHALL NOT 阻塞同请求等待。`CREDENTIAL_BLOCK_WAIT=1` 时系统 SHALL 恢复同步阻塞语义：`300`s 内 Matrix 批准后同一请求返回凭据，拒绝返回 `403`，超时按拒绝处理且不悬挂。README §6 SHALL 收录该默认差异为 BREAKING（含 `202 + E_PENDING` 轮询语义与恢复开关），§5 Go 对接指引 SHALL 覆盖 `202` 处理并记录核实结论；两模式 SHALL 各有 e2e 锁定。

#### Scenario: 默认 202 不挂起

- **WHEN** 默认配置下待审凭据请求到达且 Matrix 未决
- **THEN** 同请求立即返回 202 + E_PENDING，pending 建单可见，请求不阻塞

#### Scenario: 阻塞模式批准返回凭据

- **WHEN** `CREDENTIAL_BLOCK_WAIT=1` 且审批在超时前批准
- **THEN** 同一请求返回凭据（无 202），语义与 Python `_credential.py:433,455` 一致

#### Scenario: 阻塞模式超时按拒绝

- **WHEN** `CREDENTIAL_BLOCK_WAIT=1` 且超时内无审批结论
- **THEN** 系统按拒绝/超时口径返回且无悬挂任务，语义与 Python `_credential.py:433` 一致

#### Scenario: BREAKING 与 Go 结论声明完备

- **WHEN** 查阅 README §6 与 §5
- **THEN** §6 含该默认差异为 BREAKING 的条目及恢复开关，§5 含 Go 客户端对 202 的处理结论，二者与 spec 本需求无矛盾

### Requirement: PII 序号分配有界复用

系统 SHALL 以游标 + 已用集方式分配 PII 命中序号，SHALL NOT 在每次注册时重建全量已用序号集合并线性找洞；序号 SHALL 在 `[1, PII_MAX_ENTRIES]`（1000）内回收复用空洞，SHALL NOT 重复，SHALL NOT 越界。淘汰导致的序号释出 SHALL 可被后续分配复用。

#### Scenario: 空洞回收复用

- **WHEN** 已分配序号因淘汰/释出形成空洞后发生新注册
- **THEN** 新注册优先复用空洞序号且不与在用序号冲突

#### Scenario: 单请求分配线性有界

- **WHEN** 同一请求内连续注册 K 个不同命中（K 至 `PII_MAX_ENTRIES`）
- **THEN** 分配不随每次注册做全量重建扫描（以分配计数或等价可观测指标断言线性有界）

#### Scenario: 上限内不重复不越界

- **WHEN** 单请求注册数达到 `PII_MAX_ENTRIES`
- **THEN** 所有序号互不重复且落在 1 至 1000 之间
