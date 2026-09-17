# docs-contract-sync Specification

## Purpose
把「文档-契约-仓库状态」收敛为可验证的单一事实源：README 的每个 spec 引用可解析、阈值表可追溯、环境变量表完整、重写基线陈述与上游取证一致、OpenSpec 归档卫生可核验。

## Requirements

### Requirement: 文档引用可解析且无悬空 spec 名

README SHALL 使每个 spec 引用可解析：canonical 引用 SHALL 指向 `openspec/specs/<capability>/spec.md`；指向未归档 change 的引用 SHALL 显式给出完整路径 `openspec/changes/<change>/specs/<capability>/spec.md` 并标注「未归档」；仓库 SHALL NOT 出现裸 spec 名引用（如 `arch-docs`）。

#### Scenario: canonical 引用可解析

- **WHEN** 归档把 `credential-api`/`observability-admin` 晋升为 canonical 后核对 README:87/160/408
- **THEN** 引用均可定位到 `openspec/specs/` 下实际存在的目录（`test -f openspec/specs/<capability>/spec.md` 成立）

#### Scenario: 未归档引用显式标注

- **WHEN** README 引用仍留在唯一未归档 change `veil-hardening` 的 `admin-ratelimit-contract`（README:5/200）
- **THEN** 引用为完整 change-local 路径并标注「未归档」，而非裸 spec 名

#### Scenario: 错误名引用消除

- **WHEN** 全文检索 README 的 spec 引用
- **THEN** 不再出现裸名 `arch-docs`；README:427 的 D9 互引指向 `arch-docs-cleanup`（或完整 `veil-arch-docs-cleanup` 路径）且可解析

### Requirement: 阈值表与 spec 同字且可追溯

README §4 阈值表 SHALL 与 `admin-ratelimit-contract` spec 同字；每行 SHALL 可追溯到 spec 需求与 enforcement 点；阈值变更 SHALL 在同一 change 内同步 README 与 spec，SHALL NOT 单侧漂移。

#### Scenario: 逐行同字

- **WHEN** 逐行比对 README §4 与 `admin-ratelimit-contract` spec 的限流/上限取值与超限行为
- **THEN** 通用 admin `10/min` + `429` + `Retry-After`、SSE `5/IP`、通用体 `10MB` + `413`、审计类 `8MB` ceiling 锚点逐项一致

#### Scenario: 变更同源

- **WHEN** 未来调整任一阈值
- **THEN** 同一 change 同时修改 README 与 spec（diff 同源），不出现单侧漂移

### Requirement: 环境变量表完整

二进制读取的每个环境变量 SHALL 在 README 环境变量表有可检索的行；新增读取 SHALL 同 change 补行；README:26 的「未列出的变量二进制不读取」断言 SHALL 在补录完成后为真。

#### Scenario: 隐藏开关被补录

- **WHEN** 核查 `OBSERVABILITY_DISABLE`（`src/config/env_parse.rs:295-296`、`src/router.rs:19-28`）
- **THEN** README 变量表含该行，语义为精确 `=1`（去空白）时 `/_admin*` 全 404 且与 token 有效性无关（`tests/http_e2e_admin_matrix.rs:252-254`）

#### Scenario: 完整性断言可复核

- **WHEN** 用 grep 从 `src/config/env_parse.rs` 提取 `get("...")` 变量名，与 README 环境变量表的反引号变量名做差集
- **THEN** 差集为空（表外无二进制读取变量）

### Requirement: 重写基线陈述经上游取证

README 相对原仓（Python `credential-proxy`）的差异陈述 SHALL 以锁定的基线 commit 取证；经核实为等价的项 SHALL NOT 列为 BREAKING；逐跳头等对照 SHALL 给出双侧精确项数与文件行号来源。

#### Scenario: 等价项不列为 BREAKING

- **WHEN** 核查凭据/PII 淘汰策略
- **THEN** README §6.3 为「容量分表确认（非 BREAKING）」并附 Python 基线 commit 与 `_token.py` 真 LRU（`:231`、`:523-538`）、容量（`:102`、`:141`）证据；§6 引言同步为「十处」BREAKING（§6 共 11 小节，§6.3 为非 BREAKING 容量分表确认）

#### Scenario: HOP 对照精确

- **WHEN** 查阅 README §7.1 原仓对照
- **THEN** 表述为「原仓显式 7 项 HOP（含 `host`，`_sse.py:16-26`）→ 本仓 8 项 + `Connection` 动态项（`hop.rs:7-16`），`host` 由 `forward_headers` 单独剥（`handler/llm/mod.rs:34-46`）」

### Requirement: OpenSpec 归档卫生

任务 100% 完成的 change SHALL 在验证通过后归档，canonical specs SHALL 反映已完成的 delta；归档 SHALL 以 tasks 全勾为前置，SHALL 以 `openspec validate --archived` 与 `openspec validate <name> --strict` 零失败为门槛；未完成 change SHALL 保持打开并登记承接项。

#### Scenario: 完成 change 已归档

- **WHEN** 归档执行后运行 `openspec list --json`
- **THEN** 冻结名单内 19 个完成 change 均移入 `openspec/changes/archive/` 且活跃列表不再包含它们；`openspec/specs/` 含全部晋升能力

#### Scenario: 归档前置校验

- **WHEN** 对任一候选 change 执行归档
- **THEN** 其 `status=complete`（tasks 全勾）且 `openspec validate <name> --strict` 零失败，`openspec validate --archived` 全绿后方执行 `openspec archive <name> --yes`

#### Scenario: 半成品保持打开

- **WHEN** `veil-hardening` 仍有 5.1–5.3 未勾
- **THEN** 该 change 保持活跃不归档，其 `admin-ratelimit-contract` 等 spec 以 change-local 路径可见

### Requirement: README 源码定位指针与实现一致

README 中对 `src/` 的符号/文件定位引用 SHALL 指向实际存在的路径与符号，SHALL 优先采用符号锚点（`文件::符号`）而非行号；行号锚点仅在目标行内容稳定且经 `scripts/check_doc_paths.py` 在界校验时使用。README §6.4 的流式审批内存 pending 建单指针 SHALL 指向 ARC-1 迁移后的 `src/handler/llm/pump/spawn/event_loop.rs` 的 pending 建单符号（`handle_event`，取符号锚点或经校正的行号），SHALL NOT 沿用已迁移的旧路径 `spawn.rs::audit_pending`。

终端合成与真空流守门指针 SHALL 指向 `veil-stream-terminator-convergence` 收敛后的单一所有者：README §7.2 的中途断流终端合成指针 SHALL 指向 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator` 的 `plan_midstream` 与 `commit`，SHALL NOT 以重构前的 `src/handler/llm/pump/spawn.rs` + `src/handler/llm/pump/synth_flush.rs` 组合充当终端决策指针；README §8.6 的真空流合成守门指针 SHALL 指向 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_empty_stream`，SHALL NOT 指 `src/handler/llm/pump/spawn.rs`。

README 的行号锚点 SHALL 与目标行内容一致：指向「上游未配置 → `502 E_EMPTY_BODY`」的 `src/handler/llm/dispatch.rs:150` 已内容漂移（该行现为会话作用域 store 分支），SHALL 改用符号锚点（`src/handler/llm/dispatch.rs::gateway_serve` 的 `resolve_upstream` 未配置分支）或校正后的行号。README SHALL NOT 把仅作度量名约定使用的 `hop_filtered_total` 表述为 Rust 符号：逐跳剥离的记录入口为 `src/service/llm_gateway/metrics.rs::GatewayMetrics::record_hop_filtered`（读取侧 `src/service/llm_gateway/metrics.rs::GatewayMetrics::hop_filtered_count`），该处 SHALL 指向真实符号或显式标注为度量名。

README 的请求归一化声明（`R5-11`）与 Anthropic 扩展思考签名连续性声明（`R5-12`）SHALL 与实现同步：§7.7（请求归一化与 `x-veil-normalized` 注入即声明）与 §7.11（Anthropic thinking 签名连续性）的 `src/` 指针 SHALL 采用符号锚点并指向真实符号，SHALL NOT 沿用已漂移的行号指针。README §7.2 中「非流…下游恒收 `200`（与流式恒 200 闭合对称）」的表述 SHALL 由 `R5-43` 取代：流式上游 2xx 状态码 SHALL 透传（canonical `llm-critical-compliance` 的 E4「流式恒 200」随该 change 修订；`llm-critical-compliance` 的 delta 由 sibling capability 承载，不在本 capability 内），README SHALL NOT 继续声称流式恒 200。

#### Scenario: §6.4 指针可解析

- **WHEN** 核查 README §6.4 的 `audit-hold` 内存 pending 建单指针
- **THEN** 其指向 `src/handler/llm/pump/spawn/event_loop.rs` 的 pending 建单符号（`handle_event`，符号锚点或范围内且内容一致的行号），该路径存在且与实现一致，零命中已迁移的 `spawn.rs::audit_pending`

#### Scenario: 终端合成指针指向单所有者

- **WHEN** 核查 README §7.2 中途断流终端策略的源码指针
- **THEN** 指向 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator` 的 `plan_midstream`/`commit`（单一所有者），不再指 `src/handler/llm/pump/spawn.rs` 或以其充当终端决策入口

#### Scenario: 空流守门指针指向单所有者

- **WHEN** 核查 README §8.6 真空流合成守门的源码指针
- **THEN** 指向 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_empty_stream`，不再指 `src/handler/llm/pump/spawn.rs`

#### Scenario: dispatch 行号锚点不漂移

- **WHEN** 核查 README 中「上游未配置 → `502 E_EMPTY_BODY`」的 `src/handler/llm/dispatch.rs:150` 引用
- **THEN** 该引用改符号锚点或校正行号，打开后确为 `resolve_upstream` 未配置分支（而非会话作用域 store 分支）

#### Scenario: 幽灵符号不表述为 Rust 符号

- **WHEN** 全文检索 README 的 `hop_filtered_total`
- **THEN** 其指向 `src/service/llm_gateway/metrics.rs::GatewayMetrics::record_hop_filtered`/`hop_filtered_count` 真实符号或显式标注为度量名，不表述为可解析的 Rust 符号

#### Scenario: R5-11/R5-12 README 同步与流式 200 声明取代

- **WHEN** 核查 README §7.7（请求归一化）与 §7.11（Anthropic thinking 签名连续性）的 `src/` 指针，以及 §7.2 的流式状态码表述
- **THEN** §7.7/§7.11 指针指向真实符号锚点（非漂移行号）；§7.2「与流式恒 200 闭合对称」已被 `R5-43`（流式上游 2xx 状态码透传）取代，README 不再声称流式恒 200

### Requirement: README 测试口径标签与脚本一致

README §8.5 的真 SDK 一致性口径 SHALL 采用脚本 **24 项**约定（`scripts/api_conformance.py` 24 项 = 14 常规 + 4 阻断 + 5 取用 + 1 无库 503，由 `bash scripts/gate.sh` 第 6 步 live 实测登记），SHALL NOT 以错位的「12 项（cargo）」标签描述本仓脚本口径，避免与脚本实际计数冲突；原仓对照如需保留历史 cargo 口径 SHALL 明确标注其归属，不与本仓脚本口径混用。该计数 SHALL 以 `scripts/api_conformance.py` 的 live 输出为准（脚本结果汇总处打印通过项数）：计数文案与实测不符时 SHALL 同批修订文案，SHALL NOT 影响 gate 第 6 步判定（该步仅校验脚本退出码，不比较项数）。

`scripts/gate.sh` 头注若硬编码该计数，SHALL 与 README §8.5 的 24 项一致（`R6-04`）；计数调整 SHALL 同步修改两处，SHALL NOT 单侧漂移，亦 SHALL NOT 保留陈旧计数。

#### Scenario: 标签与脚本计数一致

- **WHEN** 对照 README §8.5 与 `scripts/api_conformance.py` 输出的项数
- **THEN** 本仓口径为 24 项且明细（14 常规 + 4 阻断 + 5 取用 + 1 无库 503）一致；「12 项（cargo）」不再作为本仓脚本口径标签出现

#### Scenario: 计数为 live 实测且不影响 gate 第 6 步

- **WHEN** `bash scripts/gate.sh` 第 6 步执行 `scripts/api_conformance.py` 并打印 `共 24 项，失败 0 项`
- **THEN** README §8.5 与 canonical 口径为 live 实测的 24 项；计数文案与脚本输出不符时仅需修订文案，gate 第 6 步仍只按脚本退出码判定（全项通过即 0），不因计数差异失败

#### Scenario: 门禁头注计数与 README 同源

- **WHEN** 检索 `scripts/gate.sh` 头注的 conformance 项数与 README §8.5
- **THEN** 两处计数一致（均为 24 项，或头注不硬编码计数而指向 README §8.5）

### Requirement: 文档行号引用可校验

`scripts/check_doc_paths.py` SHALL 在路径存在性校验之外，解析 `path:line`（含 `path:start-end`）形式的行号引用并校验其落在目标文件实际行数范围内；行号越界 SHALL 非零退出并打印悬空引用所在文件与行。该校验 SHALL 纳入 `scripts/gate.sh` 的文档路径步骤，作为文档行号漂移的根因治理。

对符号引用（`文件::符号`，含多段 `文件::A::B`）SHALL 增加**存在性校验**：取符号链末段标识符，SHALL 在目标 `.rs` 文件内以标识符形态出现；目标为门面模块（同名目录存在，如 `src/service/block_inject.rs` 与 `src/service/block_inject/` 并存）时 SHALL 允许在该模块子树（同名目录下 `**/*.rs`）内解析，以覆盖 `pub use <子模块>::*` 重导出形态。解析失败 SHALL 非零退出并打印引用所在文件、行与符号（`R6-07`）。

在界校验 SHALL NOT 被当作内容一致性的充分条件：内容可能漂移的行号锚点 SHALL 改用符号锚点（`文件::符号`），使指针随实现演进保持可解析。符号存在性校验 SHALL 仅为**结构校验**（末段标识符存在性），SHALL NOT 被当作符号可见性、签名或「被引行/符号语义与文档叙述一致」的充分条件——后者的内容一致性 SHALL 仍由 code review 保证；`scripts/check_doc_paths.py` 的职责边界为「路径存在性 + 行号在界 + 符号末段标识符存在性」。归档 change 目录（`openspec/changes/archive/**`）的 `::Symbol` 引用为归档时刻冻结快照，SHALL 整体豁免存在性断言并按处数打印（与行号引用同口径）。README 的 `src/` 指针 SHALL 以此口径改写（含 §7.2 终端合成、§8.6 空流守门与漂移的 `dispatch.rs` 行号锚点）。本条为 `R5-22`（源码注释/文档指针校正）与 design D14（「符号锚点优先」）的规范落点；`R5-22` 的源码注释侧指针校正（见 `docs-test-parity` capability）SHALL 与本条同口径，两者 SHALL NOT 对同一指针给出不同要求。

#### Scenario: 越界行号致门禁失败

- **WHEN** 文档某 `path:line` 引用的行号超出目标文件实际行数（以临时构造的越界用例验证）
- **THEN** `scripts/check_doc_paths.py` 非零退出并列出该悬空引用，gate 文档路径步骤失败

#### Scenario: 合法行号引用通过

- **WHEN** 文档引用 `src/handler/llm/pump/spawn/event_loop.rs:414`（在文件行数范围内）
- **THEN** 校验通过、退出码 0，并报告行号引用校验计数

#### Scenario: 不稳定行号改符号锚点

- **WHEN** 核查 README 中实现位置易漂移的 `src/` 指针
- **THEN** 其采用符号锚点（如 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_midstream`），经 `scripts/check_doc_paths.py` 的路径存在性校验通过，不依赖易漂移的行号

#### Scenario: 缺失符号致门禁失败

- **WHEN** 文档引用 `src/error.rs::NoSuchSymbolForTest`（目标文件内不存在的末段标识符，临时构造用例）<!-- doc-paths-ignore -->
- **THEN** `scripts/check_doc_paths.py` 非零退出并打印该引用所在文件、行与符号，gate 文档路径步骤失败

#### Scenario: 门面重导出符号可解析

- **WHEN** 文档引用 `src/service/block_inject.rs::protocol_block_frames_modeled`（实现位于 `src/service/block_inject/frames.rs`，经门面 `pub use` 重导出）
- **THEN** 校验通过（模块子树解析），符号引用计数包含该处

#### Scenario: 归档符号引用豁免

- **WHEN** 归档 change 文档（`openspec/changes/archive/**`）含现行源码已不存在的符号引用
- **THEN** 该引用不被判失败，脚本按处数打印「归档文档符号引用 N 处未校验」（与行号引用同口径）

### Requirement: README 错误码正面档与合成体字段口径

README SHALL 对网关对话路径产出的错误码提供**正面档**说明（触发条件 + 状态码 + 错误体字段形态），SHALL NOT 仅以否定式附带提及。至少 SHALL 覆盖 `E_EMPTY_BODY`：触发条件为非流对话上游异常空体/非 JSON 体 → 下游 `502`（`src/error.rs::VeilError::code` 的码映射与 `src/error.rs::VeilError::status_code` 的 `EmptyBody → BAD_GATEWAY`；网关级错误体构造见 `src/handler/llm/mod.rs::empty_body_response`，入口级故障见 `src/handler/llm/dispatch.rs::gateway_serve` 的 `resolve_upstream` 未配置分支），并说明其与 `response_too_large` 超限 502 的先后关系（超限判定先于空体/非 JSON 判定）。

合成错误体字段名的 README 对齐 SHALL 为**可选（SHOULD）**项，SHALL NOT 以「纠错」框架表述（`M-4`，`veil-audit-r4-remediation`）：README §4 阈值表行现措辞为「`502` + `response_too_large` JSON 体」，**并未**声称字段名为 `error.code`，故本要求 SHALL NOT 将其定性为错误表述。系统 SHOULD（可选）在该行补 `error.type` 字段名以对齐代码（`src/handler/llm/nonstream.rs::oversize_response` 构造的 `{"error":{"message":"response too large","type":"response_too_large"}}`）；该对齐为可选、非阻断验收项，未执行不判失败。无论是否对齐，README SHALL NOT 出现把该字段描述为 `error.code` 的措辞。

上述指针 SHALL 采用符号锚点（`文件::符号`），SHALL NOT 使用行号区间（`R6-01`/`R6-02`）：`src/error.rs`、`src/handler/llm/nonstream.rs`、`src/handler/llm/dispatch.rs` 的实现位置 R5 重构后已漂移，行号锚点无法自证一致。

#### Scenario: E_EMPTY_BODY 有正面档

- **WHEN** 在 README 中检索 `E_EMPTY_BODY`
- **THEN** 命中正面档条目，说明触发条件（非流空体/非 JSON → 502）、状态码与错误体字段形态，且指针为 `src/error.rs::VeilError::status_code` 的 `EmptyBody` 分支（符号锚点，非行号）

#### Scenario: 超限与空体先后关系声明

- **WHEN** 核查 README 对 `E_EMPTY_BODY` 与 `response_too_large` 的说明
- **THEN** 明确超限判定先于空体/非 JSON 判定（与 `src/handler/llm/nonstream.rs::serve_nonstream` 实现一致）

#### Scenario: §4 字段名可选对齐（非纠错）

- **WHEN** 核查 README §4 的非流对话响应上限行
- **THEN** 可选补 `error.type` 字段名以对齐 `src/handler/llm/nonstream.rs::oversize_response`；未补不判失败；两种情形均零命中 `error.code` 措辞，且不出现「纠正错误表述」的定性

#### Scenario: 本要求定位引用为符号锚点

- **WHEN** 核查本要求（及 README 对应段落）对错误码与超限体构造的定位引用
- **THEN** 引用均为符号锚点——`src/error.rs::VeilError::code`、`src/error.rs::VeilError::status_code`、`src/handler/llm/nonstream.rs::oversize_response`、`src/handler/llm/dispatch.rs::gateway_serve`——不再为行号区间形式；其他 capability 自身的锚点由各自 delta 承载，不在本能力内重复断言

#### Scenario: scripts/README 口径一致

- **WHEN** 核查 `scripts/README.md` 关于 `check_doc_paths.py` 的归档豁免与 `PENDING_LINE_REFS` 说明
- **THEN** 与 `scripts/check_doc_paths.py` 实现一致，无需改动
