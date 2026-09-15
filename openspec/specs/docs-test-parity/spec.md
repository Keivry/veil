# docs-test-parity Specification

## Purpose
锁定 veil 仓库「文档-契约-测试」三者一致的可验证契约：文档中指向上游 Python 仓库与本地 Rust 源码的行号引用必须与取证内容一致，canonical spec 与 README 的口径必须同源，模块文档必须齐备；测试断言必须具备区分度（禁止假绿、常量自锁与恒真），关键路径的覆盖缺口必须闭合。该契约使「文档即契约、测试即守护」可被门禁与人工复核核验。

## Requirements

### Requirement: 文档行号引用与上游取证一致

README 与 canonical spec 中指向 Python 原仓 `_llm.py`/`_credential.py` 的每个行号引用 SHALL 与该文件当前内容语义匹配；引用 502 响应体形态时 SHALL 指向实际构造该体的行（`_llm.py:2951-2961`），引用「超限观测（warning + `metrics_ctx['status']=502`）」时 SHALL 覆盖 `metrics_ctx['status']=502` 所在行（`2936-2946`）；README 指向 `_credential.py` 超时归并描述的引用 SHALL 指向实际内容行（`_credential.py:445`），SHALL NOT 沿用失效的 `_credential.py:433`。已核实准确的行号引用 SHALL 保持不变；指向冻结归档语料的引用 SHALL NOT 被回改。

#### Scenario: 502 体引用可核验

- **WHEN** 打开 `_llm.py:2951-2961`
- **THEN** 可见 `_jdumps({'error': {'message': 'response too large', 'type': 'response_too_large'}})` 与 `status=502`、`headers={'Content-Type': 'application/json'}`，与 README/spec 所述 502 JSON 体同字

#### Scenario: 超限观测引用覆盖状态位

- **WHEN** 打开 `_llm.py:2936-2946`
- **THEN** 同时覆盖 `_is_nonstream_oversize` 判定、`logger.warning('LLM 非流式超限 fail-closed...')` 与 `metrics_ctx['status'] = 502`

#### Scenario: 凭据超时行号引用可核验

- **WHEN** 核查 README 指向 `_credential.py` 的超时归并引用
- **THEN** 指向 `_credential.py:445`（实际超时归并描述行），零命中失效的 `_credential.py:433`

#### Scenario: 准确引用不回改

- **WHEN** 核查 `README.md:783` 指向 `_llm.py:2633` 与 `src/config/env_parse.rs:56` 指向 `_llm.py:139`
- **THEN** `_llm.py:2633` 为 `async def _ensure_nonempty_stream(`、`_llm.py:139` 为 `NONSTREAM_MAX_BYTES = int(os.environ.get('NONSTREAM_MAX_BYTES', '8388608'))`，两处保持原样

### Requirement: 源码注释指针准确

Rust 源码注释中引用的本地文件与行号 SHALL 指向所述内容；引用「approve 空白名单启动门禁」时 SHALL 指向配置解析处的 `src/config/env_parse.rs:469-478`（`validate_approve_whitelist` + 空白名单拒启动）与显式门禁 `src/main.rs:45`（`preflight_whitelist`），SHALL NOT 指向 `env_parse.rs:307-310`（该处为 `load_storage` 返回值列表）；引用 keepalive `spawn_gated` 接线时 SHALL 指向实际存在的符号或路径（如 `service::audit::RequestKeepalive::spawn_gated` 或 `handler/llm/pump/spawn/setup.rs` 的接线点），SHALL NOT 指向不存在的 `pump.rs::spawn_gated`。

#### Scenario: 门禁注释指向真实位置

- **WHEN** 核查 `src/service/audit/verdict.rs`、`src/service/audit.rs`、`src/service/block_inject.rs`、`src/handler/llm/nonstream.rs` 中关于 approve 空白名单门禁的注释
- **THEN** 其指针为 `env_parse.rs:469-478`（+ `main.rs:45`），打开后确为白名单校验与拒启动逻辑

#### Scenario: keepalive 符号指针不悬空

- **WHEN** 全文检索源码注释中的 `pump.rs::spawn_gated`
- **THEN** 零命中该不存在符号；相关注释指向实际存在的 keepalive 接线符号/路径，且对应文件存在

### Requirement: canonical spec 与 README 口径同源

canonical spec SHALL 与 README 的等价性判定同源：`behavior-changes` spec SHALL NOT 将「凭据淘汰 FIFO 改 LRU」列为 **BREAKING**（README §6.3 已判定为「容量分表确认（非 BREAKING）」并附 Python 基线 commit 与真 LRU 取证）；`docs-contract-sync` spec 描述 §6 引言时 SHALL 使用实际数目（BREAKING「十处」、§6 共 11 小节、§6.3 非 BREAKING），SHALL NOT 使用过时的「六处」「7 小节」。

#### Scenario: 淘汰策略不被误标 BREAKING

- **WHEN** 核查 `openspec/specs/behavior-changes/spec.md` 的「脱敏默认与采样持久与淘汰策略」Requirement
- **THEN** FIFO→LRU 表述为非 BREAKING 容量分表确认，附 Python 基线 commit（`46f6ff665c869b02c154c10df431c638c2177fd9`）与 `_token.py` 真 LRU/容量取证

#### Scenario: §6 计数与 README 一致

- **WHEN** 核查 `openspec/specs/docs-contract-sync/spec.md` 的「等价项不列为 BREAKING」Scenario
- **THEN** 其为「十处」BREAKING、§6 共 11 小节，且 `openspec validate --all --strict` 零失败

### Requirement: 模块级文档齐备

仓库顶层模块文件（含 `src/lib.rs` 与 `src/router.rs`）SHALL 具备 `//!` 模块级文档；`src/lib.rs` SHALL 包含描述 crate 职责与模块组成的 `//!` 头；`src/router.rs` SHALL 包含描述路由装配与中间件职责的 `//!` 头，与其它模块风格一致。

#### Scenario: router 模块文档存在

- **WHEN** 读取 `src/router.rs` 首部
- **THEN** 存在 `//!` 模块文档且描述路由/中间件职责

#### Scenario: lib 根模块文档存在

- **WHEN** 读取 `src/lib.rs` 首部
- **THEN** 存在 `//!` 模块文档且描述 crate 职责/模块组成，文档门禁覆盖 lib 根

### Requirement: 端点文档与实现及原仓一致

README 对 `GET /registrations` 的鉴权描述 SHALL 与原仓行为一致：原仓 `_credential.py::handle_registrations` 调用 `_require_auth`（校验 `GET_BINARY_HASH` + `GET_BINARY_SECRET`，未配置时兼容跳过），故 SHALL NOT 表述为「原仓无鉴权直读」；本仓管理面鉴权（`X-Admin-Token` 或 `X-Get-Binary-Secret`）SHALL 准确陈述。

#### Scenario: registrations 鉴权描述可核验

- **WHEN** 对照 README §5 表与 §7.5 与 Python `_credential.py:189-191`、`103-142`
- **THEN** 文档不再声称原仓无鉴权；两处描述与本仓实现（`src/handler/credential.rs:43-54`）同源

### Requirement: 测试断言有区分度

测试断言 SHALL 在目标行为回退时失败：SHALL NOT 使用恒真析取、常量自锁（仅比对常量而不触发逻辑）或与被测行为无关的输入使断言失去区分度（假绿）。注册闭环测试 SHALL 使用与注册/审批相同的 caller；metrics 边界删除测试 SHALL 在多 distinct 主键下断言「过期删、新鲜留」；审计超时竞态区间契约 SHALL 由边界值验证拒启动分支；阻断帧测试 SHALL 对终端帧是否存在做严格断言。

#### Scenario: 注册闭环同 caller

- **WHEN** 运行注册闭环 e2e
- **THEN** 闭环取用使用注册/审批的同一 caller（`/srv/flow.sh` + `h-flow-1`），且换用未注册 caller 时测试失败

#### Scenario: 边界删除可区分

- **WHEN** 在 metrics 采样表写入 fresh/boundary/expired 三个 distinct 主键后执行 purge
- **THEN** 仅过期行被删，fresh/boundary 保留

#### Scenario: 竞态区间拒启动被行为覆盖

- **WHEN** 以 `109/110/130/131` 边界值触发审计超时校验
- **THEN** 落入 `110..=130` 的值被拒，区间外的值通过；删除该逻辑时测试失败

#### Scenario: 阻断帧终端断言非恒真

- **WHEN** Anthropic 阻断/截断帧构造后检查终端帧
- **THEN** 断言对 `message_stop` 是否存在具备区分度，不因理由文案恒含 `truncated` 而恒真

### Requirement: 关键路径覆盖缺口闭合

关键路径 SHALL 具备可回归的测试覆盖：交互式 KeePass 解锁链（TPM 解封→口令→库解锁，含失败与重解封）、审计 `on_reaction` 白名单矩阵（含空白名单落定）、动态 PII 映射的审计零明文不变量、metrics 摘要对 IPv4/身份证/卡号的兜底、Anthropic 真 SDK 的 error/CR-only/thinking 行为、流式 approve HTTP e2e。缺口 SHALL 以新增用例或既有用例核验闭环，SHALL NOT 以近似路径的测试抵充。

#### Scenario: KeePass 解锁链覆盖失败与重解封

- **WHEN** 运行解锁链测试组
- **THEN** 覆盖 unseal 失败、错口令、并发冷启动单开、lock 后需重新解封四类用例

#### Scenario: 空白名单 reaction 落定可锁定

- **WHEN** 审计 `on_reaction` 在 `APPROVAL_WHITELIST` 为空时收到 reaction
- **THEN** 行为与 `veil-audit-policy-enforcement` 的 `POL-5` 决策一致并被单测锁定

#### Scenario: 动态 PII 零明文

- **WHEN** 请求期动态映射生成的占位符进入审计记录/摘要
- **THEN** 审计记录中不含明文，断言零明文不变量

#### Scenario: metrics 摘要三项兜底

- **WHEN** metrics 摘要遇到 IPv4/身份证/卡号形态的敏感值
- **THEN** 该值被兜底脱敏，无明文外泄；IPv4/身份证/卡号三类各有一条测试锁定

#### Scenario: Anthropic 真 SDK 覆盖扩充

- **WHEN** 运行 `scripts/api_conformance.py`
- **THEN** Anthropic error、CR-only 分块、thinking 三项由真 SDK 断言覆盖并通过，`tool_use` 既有覆盖不回退

#### Scenario: 流式 approve e2e 核验

- **WHEN** 运行流式 approve HTTP e2e
- **THEN** 既断言 pending 建单、流不断链、无阻断帧三要素；若发现子场景缺口则补测
