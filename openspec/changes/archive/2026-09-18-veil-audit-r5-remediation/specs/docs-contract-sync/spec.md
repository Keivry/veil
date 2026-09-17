# Spec Delta

## MODIFIED Requirements

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

### Requirement: 文档行号引用可校验

`scripts/check_doc_paths.py` SHALL 在路径存在性校验之外，解析 `path:line`（含 `path:start-end`）形式的行号引用并校验其落在目标文件实际行数范围内；行号越界 SHALL 非零退出并打印悬空引用所在文件与行。该校验 SHALL 纳入 `scripts/gate.sh` 的文档路径步骤，作为文档行号漂移的根因治理；对非 `path:line` 形态的引用（如纯符号引用）SHALL 保持路径存在性校验不变。

在界校验 SHALL NOT 被当作内容一致性的充分条件：内容可能漂移的行号锚点 SHALL 改用符号锚点（`文件::符号`），使指针随实现演进保持可解析；`scripts/check_doc_paths.py` 的职责边界仍为「路径存在性 + 行号在界」，被引行内容与文档语义的一致性 SHALL 由 code review 保证。README 的 `src/` 指针 SHALL 以此口径改写（含 §7.2 终端合成、§8.6 空流守门与漂移的 `dispatch.rs` 行号锚点）。本条为 `R5-22`（源码注释/文档指针校正）与 design D14（「符号锚点优先」）的规范落点；`R5-22` 的源码注释侧指针校正（见 `docs-test-parity` capability）SHALL 与本条同口径，两者 SHALL NOT 对同一指针给出不同要求。

#### Scenario: 越界行号致门禁失败

- **WHEN** 文档某 `path:line` 引用的行号超出目标文件实际行数（以临时构造的越界用例验证）
- **THEN** `scripts/check_doc_paths.py` 非零退出并列出该悬空引用，gate 文档路径步骤失败

#### Scenario: 合法行号引用通过

- **WHEN** 文档引用 `src/handler/llm/pump/spawn/event_loop.rs:414`（在文件行数范围内）
- **THEN** 校验通过、退出码 0，并报告行号引用校验计数

#### Scenario: 不稳定行号改符号锚点

- **WHEN** 核查 README 中实现位置易漂移的 `src/` 指针
- **THEN** 其采用符号锚点（如 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_midstream`），经 `scripts/check_doc_paths.py` 的路径存在性校验通过，不依赖易漂移的行号
