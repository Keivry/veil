# Spec Delta

## MODIFIED Requirements

### Requirement: 源码注释指针准确

Rust 源码注释中引用的本地文件与符号 SHALL 指向所述内容，SHALL 优先采用符号锚点（`文件::符号`）而非行号；引用「approve 空白名单启动门禁」时 SHALL 指向配置解析处的 `src/config/env_parse.rs::validate_approve_whitelist` 与显式门禁 `src/main.rs::preflight_whitelist`（原 `env_parse.rs:493` 行号锚点已内容漂移——该行现为 `load_limits` 的 `audit_hold_max_bytes`，SHALL NOT 再作为指针），SHALL NOT 指向已失效的旧行号 `env_parse.rs:469-478` / `main.rs:45`，SHALL NOT 指向 `env_parse.rs:307-310`（该处为 `load_storage` 返回值列表）；引用 keepalive `spawn_gated` 接线时 SHALL 指向实际存在的符号或路径（如 `src/service/audit/hold.rs::RequestKeepalive::spawn_gated` 或 `src/handler/llm/pump/spawn/setup.rs` 的接线点），SHALL NOT 指向不存在的 `pump.rs::spawn_gated`。

源码注释引用的符号 SHALL 存在，SHALL NOT 把仅作度量名约定使用的名字表述为可解析的 Rust 符号：`src/handler/llm/nonstream.rs::clone_upstream_headers` 与 `src/service/llm_gateway/hop.rs::filter_hop_headers_counted` 的逐跳剥离文档注释 SHALL NOT 把 `hop_filtered_total` 表述为 Rust 符号——`hop_filtered_total` 为 README §7.1 约定的 Prometheus 度量名（`{dir}` 标签约定），非 Rust 符号；注释 SHALL 指向真实记录入口 `src/service/llm_gateway/metrics.rs::GatewayMetrics::record_hop_filtered`（读取侧 `src/service/llm_gateway/metrics.rs::GatewayMetrics::hop_filtered_count`），或显式标注 `hop_filtered_total` 为度量名。

`src/handler/llm/pump/spawn/setup.rs` 关于终端状态机的注释在复述「取代 7 枚终端相关 bool」清单（`any_frame_sent`/`terminated`/`rejected_sticky`/`block_injected`/`audit_blocked`/`terminal_sent`/`responses_failed_sent`）时 SHALL 指明：这些同名项在别处为**纯函数参数**（如 `src/handler/llm/pump/decide.rs::responses_control_action` 的 `terminal_sent`/`responses_failed_sent`、`src/handler/llm/pump/decide.rs::should_apply_midstream_terminal` 的 `block_injected`/`any_frame_sent`，以及 `src/handler/llm/pump/event.rs` 的纯谓词参数），SHALL NOT 使读者误认为它们是 `PumpLoopState` 的现存状态字段；现存终端状态的唯一所有者 SHALL 为 `PumpLoopState.terminator: StreamTerminator`。

源码注释对**枚举变体数**与**路径等价性**的声称 SHALL 与实现一致：`src/service/sse/meta.rs::TruncatedMode` 的注释 SHALL 表述为「四态」（实际变体 `SilentDiscard`/`OpenEnded`/`SynthesizedFailed`/`UpstreamError`），SHALL NOT 表述为「三态」；`src/service/metrics/aggregate.rs::TRUNCATED_MODES` 的注释 SHALL 同步表述为「四态」（`F` 扩域，`B-1` 同批），SHALL NOT 残留「唯一三态」；`src/service/llm_gateway/tool.rs::extract_tool_calls_with` 关于 item-done 路径与「非流路径同结论」的注释 SHALL 与实现一致（非流 `output[]` 须实际经 `responses_item_tool_name`（`src/service/llm_gateway/tool_responses.rs::responses_item_tool_name`）等价判定后方可声称同结论）。注释文本准确性为 **code-review 项**；其**行为验收**以 canonical `llm-gateway`「截断三态（唯一值）」的四态白名单落点测试与 A 的流/非流 parity 测试为准（`M-5`），SHALL NOT 以 grep 命中「四态」/「同结论」为验收。

#### Scenario: 门禁注释指向真实位置

- **WHEN** 核查 `src/service/audit/verdict.rs`、`src/service/audit.rs`、`src/service/block_inject.rs`、`src/handler/llm/nonstream.rs` 中关于 approve 空白名单门禁的注释
- **THEN** 其指针为 `src/config/env_parse.rs::validate_approve_whitelist`（+ `src/main.rs::preflight_whitelist`），打开后确为白名单校验与拒启动逻辑

#### Scenario: keepalive 符号指针不悬空

- **WHEN** 全文检索源码注释中的 `pump.rs::spawn_gated`
- **THEN** 零命中该不存在符号；相关注释指向实际存在的 keepalive 接线符号/路径，且对应文件存在

#### Scenario: TruncatedMode 注释与变体数一致

- **WHEN** 核查 `src/service/sse/meta.rs::TruncatedMode` 顶部文档注释与 `src/service/metrics/aggregate.rs::TRUNCATED_MODES` 注释
- **THEN** 两处均表述为「四态」，与 `TruncatedMode` 的四个变体一致，零命中「三态」；该项验收为 code-review（注释文本），行为判据归 canonical `llm-gateway` 四态白名单落点测试（M-5）

#### Scenario: tool 注释同结论成立

- **WHEN** 核查 `src/service/llm_gateway/tool.rs::extract_tool_calls_with` 的「同结论」注释
- **THEN** 非流 `output[]` 路径实际经等价工具判定（`src/service/llm_gateway/tool_responses.rs::responses_item_tool_name`），注释与实现一致，流/非流一致性测试通过

#### Scenario: 逐跳注释符号不悬空

- **WHEN** 核查 `src/handler/llm/nonstream.rs::clone_upstream_headers` 与 `src/service/llm_gateway/hop.rs::filter_hop_headers_counted` 中关于逐跳剥离的注释
- **THEN** 其指向真实符号 `src/service/llm_gateway/metrics.rs::GatewayMetrics::record_hop_filtered`（读取 `hop_filtered_count`）或显式标注 `hop_filtered_total` 为度量名，不把该度量名当作可解析的 Rust 符号

#### Scenario: 终端 bool 注释澄清为函数参数

- **WHEN** 核查 `src/handler/llm/pump/spawn/setup.rs` 关于「取代 7 枚终端相关 bool」的注释
- **THEN** 注释指明同名项在 `decide.rs`/`event.rs` 等处为纯函数参数、非 `PumpLoopState` 现存状态字段，且现存终端状态唯一所有者为 `terminator: StreamTerminator`
