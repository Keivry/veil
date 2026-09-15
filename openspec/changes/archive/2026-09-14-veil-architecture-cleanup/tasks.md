## 1. 死代码清除（`ARC-5`）

- [x] 1.1 `src/service/llm_gateway/hop.rs:31-33` 删除 `pub fn filter_hop_headers` 定义，并删除 `src/service/llm_gateway/mod.rs:286` 的同名重导出；保留 `filter_hop_headers_counted` 为唯一入口，确认 `hop.rs` 内 `#[cfg(test)]` 单测未调用裸函数
  - 验证：`grep -rn "filter_hop_headers" src/ tests/` 仅命中 `filter_hop_headers_counted`（含调用点），无裸 `filter_hop_headers` 定义/引用
  - 验证：`cargo test -p veil --lib llm_gateway::hop` 与 `cargo test -p veil --test http_e2e_nondialog_passthrough` 全绿（hop 过滤行为不变）
- [x] 1.2 编译与告警门禁：删后 `cargo clippy --tests --all-targets -- -D warnings` 无 `dead_code` 警告
  - 验证：`cargo clippy --tests --all-targets -- -D warnings` 退出 0、无 `dead_code`/`unused_imports` 警告
  - 验证：`cargo build` 退出 0，`src/service/llm_gateway/mod.rs` 重导出列表与其被引用情况一致

## 2. 上游响应头克隆 + hop 过滤单一 helper（`ARC-4`）

- [x] 2.1 `src/handler/llm/nonstream.rs` 新增单一 helper（如 `clone_upstream_headers(up, metrics) -> HeaderMap`）：封装上游头克隆（现 `:325-333` 与 `:389-397` 逐字重复段）+ `downstream_decode_enabled` 配对 + `filter_hop_headers_counted(..., "downstream", decode_enabled, Some(metrics))`
  - 验证：`grep -n "fn clone_upstream_headers" src/handler/llm/nonstream.rs` 命中单一 helper 定义
  - 验证：`grep -c "let mut resp_headers = HeaderMap::new();" src/handler/llm/nonstream.rs` 结果 ≤1（头克隆仅存于 helper）
- [x] 2.2 `passthrough_upstream_response`（`:321`）与 `snapshot_downstream_headers`（`:388`）改调 2.1 helper；两路径各自职责（前者 `builder`/`Body::from_stream`、后者 `x-veil-*` 剔除）保留
  - 验证：`grep -n "clone_upstream_headers" src/handler/llm/nonstream.rs` 命中两处调用点
  - 验证：`cargo test -p veil --test http_e2e_nondialog_passthrough` 与 `cargo test -p veil --lib handler::llm::nonstream` 全绿（下游响应头集合与编码配对不变）

## 3. 三协议 tool 提取器统一（`ARC-3`）

- [x] 3.1 在 `src/service/llm_gateway/tool.rs` 建立单一三臂提取核心（以 `extract_tool_calls` 的 `Vec<ToolCall>` 为规范输出，覆盖两实现分支并集：Chat `delta`/`message`/`function_call`/`custom_tool_call`；Anthropic `content_block`/`delta`/`content`/`message.content`/`function_call`/`custom_tool_call`；Responses `function_call_arguments.delta/done`、检索事件、`output_item.added/done`、`output` 数组），`extract_tool_calls`（`tool.rs:196-578`）改调核心
  - 验证：`cargo test -p veil --lib service::llm_gateway::tool` 全绿（Chat/Anthropic/Responses 提取单测无回退）
  - 验证：`grep -n "pub fn extract_tool_calls" src/service/llm_gateway/tool.rs` 命中且函数体不含并行三臂重复 walk（改为调核心）
- [x] 3.2 `src/handler/llm/pump/fragments.rs:11-19` 的 `extract_tool_fragments` 改薄适配：调用 3.1 核心后映射为既有元组 `(index, Some(id), name, args)`；保持 `spawn.rs:223/:315` 调用点与返回类型不变
  - 验证：`cargo test -p veil --lib handler::llm::pump::fragments` 全绿（frag↔calls 等价对照用例如 `fragments/tests.rs` 无一回退）
  - 验证：`cargo test -p veil --lib pump::fragments` 与 `cargo test -p veil --test http_e2e_audit_approve` 全绿（流式审计/阻断路径行为不变）
- [x] 3.3 重复面收敛确认：两路径三臂 walk 不再各存一份
  - 验证：`grep -c "Protocol::Responses" src/handler/llm/pump/fragments.rs` 显著下降（碎片文件不再含完整 Responses 三臂 walk）
  - 验证：`cargo clippy --tests --all-targets -- -D warnings` 退出 0，无未使用 helper/死分支警告

## 4. 审批决策表受管化 + 仅驱逐终态（`ARC-2`）

- [x] 4.1 `DecisionTable` 由 `Arc<Mutex<DecisionTable>>` 承载：`src/state.rs` 的 `AppState` 增字段与构造（`:137` 附近 `impl AppStateParts`），`src/service/credential/mod.rs` 的 `AppStateParts`（`:55`）增访问器 `fn decisions(&self) -> &Arc<Mutex<DecisionTable>>`；移除 `src/service/credential/approval.rs:233` 的 `static DECISIONS` 与 `:235-237` 的 `decisions()`，所有调用点（`:311/:333/:338`、`record_credential_decision`、`consume_decision`、测试辅助 `credential_decision_slot`）改经 `state.decisions()`
  - 验证：`grep -rn "static DECISIONS\|fn decisions() -> &'static" src/` 零命中（进程级 static 已移除）
  - 验证：`cargo test -p veil --lib service::credential::approval` 全绿（`202` 消费闭环/三态落定无回退）
- [x] 4.2 驱逐策略改为仅终态（软上限）：`resolve`（`:200-218`）超软上限时按 `Decided.created` 升序（同刻 key 字典序 tie-break）驱逐最早终态条目，**`InFlight` 永不驱逐**；无可驱逐终态且仍超限时记 warn、递增超软上限计数指标（`approval_decision_overflow_total`）、不驱逐并允许暂时超出（`InFlight` 受 Matrix 审批票并发度约束为最终 backstop）
  - 验证：新增/改写单测断言含 `InFlight` 的表在触发驱逐后 `InFlight` 条目保留（如注入小上限 + 混合条目）
  - 验证：新增单测断言「表内全部为 `InFlight` 且超软上限」时零驱逐、记 warn 且 `approval_decision_overflow_total` 递增 1
  - 验证：`cargo test -p veil --lib service::credential::approval` 全绿；`sweep`（`:163-171`）TTL 清理与终态语义不变
- [x] 4.3 软上限行为可测：以可注入软上限断言写入超上限终态后表条目数 ≤ 软上限，被驱逐者恒为终态；仅余 `InFlight` 超限时不驱逐、有界性靠终态落定恢复
  - 验证：`cargo test -p veil --lib service::credential::approval` 新增软上限用例通过（终态有界、驱逐对象恒 `Decided`；仅 `InFlight` 超限时零驱逐且计数指标递增）
  - 验证：`cargo test -p veil --test http_e2e_credential_approval` 与 `cargo test -p veil --test http_e2e_approval` 全绿（对外审批语义不变）
- [x] 4.4 软上限计数只读暴露：`DecisionTable` 增 `pub fn overflow_count(&self) -> u64` 与 `pub fn entry_count(&self) -> usize`；`src/handler/admin.rs::admin_metrics` 读 `state.decisions` 并在 `GET /_admin/metrics` JSON 增 `approval_decision_overflow_total`（u64）与 `decision_table_size`（usize），锁中毒时按 `0` 降级且不影响既有键
  - 验证：`cargo test -p veil --lib service::credential::approval` 新增只读访问器用例通过（仅 `InFlight` 超软上限时 `overflow_count` 逐次递增、`entry_count` 反映允许暂时超出的条目数）
  - 验证：`cargo test -p veil --test http_e2e_metrics_snapshot` 全绿（`/_admin/metrics` 含 `approval_decision_overflow_total`/`decision_table_size` 数值键，空窗为 0，既有指标键不变）

## 5. 流泵按职责拆分（`ARC-1`）

- [x] 5.1 聚合循环状态：将 `src/handler/llm/pump/spawn/setup.rs:74-152` 的 `StreamPumpCtx` 解构与局部状态初始化收敛为 setup 构造器，返回 `PumpLoopState`（`forwarded`/`agg`/`terminal_sent`/`any_frame_sent`/`pending_tool_frames`/`hold`/`meta`/`carry` 等），置于 `spawn/setup.rs`
  - 验证：`grep -n "struct PumpLoopState" src/handler/llm/pump/spawn/setup.rs` 命中；`grep -n "PumpLoopState" src/handler/llm/pump/spawn.rs` 命中使用点<!-- doc-paths-ignore -->
  - 验证：`cargo build` 退出 0（状态聚合未改变语义）；`spawn.rs:49-699` 行数较拆分前下降
- [x] 5.2 主循环薄层 + 单事件处理提取：`spawn.rs:149-658` 拆出 `run_pump(...)`（chunk 读取 `:150-163`、parser 喂入 `:169-173` 留薄层）与 `handle_event(&mut state, ev, &deps) -> ControlFlow`（现 `:174-654`），置于 `spawn/event_loop.rs`；单事件内部再按职责提取 Responses 控制动作（`:237-307`）、分片入 hold 与审计（`:370-489`）、还原/PII/发送（`:533-654`）
  - 验证：`cargo test -p veil --test http_e2e_truncation_matrix` 全绿（帧序/终端/`truncated_mode` 不变）
  - 验证：`cargo test -p veil --test http_e2e_audit_approve` 与 `cargo test -p veil --test http_e2e_sse_loop` 全绿（审计阻断与增量到达不变）
- [x] 5.3 收尾提取 + 薄壳化：`spawn.rs:659-698` 的 `terminal::finalize` 调用 + 指标记录 + `PumpOutcome` 提取为 `spawn/finish.rs`；`spawn_stream_pump` 收敛为薄壳（setup → run_pump → finish）
  - 验证：`grep -n "fn spawn_stream_pump" src/handler/llm/pump/spawn.rs` 命中且函数体为薄壳（无 400+ 行内联逻辑）
  - 验证：`python3 scripts/check_file_sizes.py` 退出 0（拆分产出各文件 ≤800 行）；`cargo test -p veil --lib handler::llm::pump` 全绿
- [x] 5.4 拆分函数规模守门：确保拆分后无新增巨型函数
  - 验证：新增测试/守卫断言 `spawn_stream_pump` 及拆分出函数均低于单文件 800 行上限（`python3 scripts/check_file_sizes.py` 通过）
  - 验证：`cargo clippy --tests --all-targets -- -D warnings` 退出 0

## 6. 行为保持与门禁终检

- [x] 6.1 全量回归：ARC-1–ARC-5 全部落地后跑完整测试套件
  - 验证：`cargo test` 全绿，无既有测试回退（对照基线通过的 1090+ 用例）
  - 验证：`cargo fmt --check` 与 `cargo clippy --tests --all-targets -- -D warnings` 退出 0
- [x] 6.2 结构与文档门禁：文件大小与文档路径检查
  - 验证：`python3 scripts/check_file_sizes.py` 退出 0（全部 `src/**/*.rs` ≤800 行）
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0（不引入失效路径引用）
- [x] 6.3 覆盖与行为保持终检：确认五项发现均落地且无行为漂移
  - 验证：逐项复核覆盖表 ARC-1–ARC-5：`spawn_stream_pump` 拆分完成、决策表无 `static` 且 `InFlight` 不被驱逐、tool 提取器单实现、nonstream helper 双调用、`filter_hop_headers` 零引用
  - 验证：`openspec validate veil-architecture-cleanup --strict` 0 failures（规划 artifacts 一致）
