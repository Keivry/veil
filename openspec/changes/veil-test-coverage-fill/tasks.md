## 1. `T1` 泵关键决策点直接单测（HIGH）

- [x] 1.1 新增 `src/handler/llm/pump/decide.rs`（`pub(super)`、无 async/无 IO）：`responses_control_action`（N1 守卫 + error/failed 分类）、`should_backfill_chat_done`（P1 四条件）、`should_buffer_tool_frame`（hold-until-complete）、`tool_replay_slot`（完成帧重放槽，包装 `outer_event_index`）、`should_suppress_held_output`（边界 hold 抑制）、`sticky_suppress_action`（rejected_sticky 抑制）；把 `spawn.rs:199-217/222-259/280-286/299-304/482/625-628` 的对应内联判定替换为调用（metrics/副作用留调用点，布尔决策入纯函数）
  - Verify: `cargo test -p veil stream_tests`、`cargo test -p veil proto_closeout_tests`、`cargo test -p veil tss` 全绿（等价重构锁定，零既有断言改动）
  - Verify: `grep -c "decide::" src/handler/llm/pump/spawn.rs` ≥6 处调用；`wc -l src/handler/llm/pump/spawn.rs` ≤ 800（`check_file_sizes.py` 口径）

- [x] 1.2 新增 `#[cfg(test)] mod spawn_tests`（声明于 `src/handler/llm/pump.rs`，文件 `src/handler/llm/pump/spawn_tests.rs`），承载 7 决策点真值表：每点 ≥2 正例 + ≥1 负例；复用 `stream_tests.rs` 的 `pump_ctx`/`loopback_server`/`collect_pump` harness（可见性不足则抽 `pump_test_support` 共享模块，不复制实现）
  - Verify: `cargo test -p veil spawn_decision` 通过，7 组真值表用例逐项存在（`spawn_decision_responses_control_truth_table`、`spawn_decision_backfill_chat_done_truth_table`、`spawn_decision_buffer_tool_frame_truth_table`、`spawn_decision_tool_replay_slot_truth_table`、`spawn_decision_suppress_held_output_truth_table`、`spawn_decision_sticky_suppress_truth_table`、`spawn_decision_empty_stream_gate_call_order`）
  - Verify: `cargo test -p veil spawn_tests` 全绿且仅依赖 loopback mock（无外部网络/无墙钟断言）

- [x] 1.3 补泵直测 4 例（与 `proto_closeout_tests` 的 closeout 级路径不重复）：`direct_n1_completed_then_error_single_terminal`（completed→error/incomplete 真值组合下终端恰一）、`direct_p1_backfill_preserves_usage_tail`（`[DONE]` 恰一 + usage 尾帧保留 + `truncated_mode=open_ended`）、`direct_boundary_hold_released_at_terminal`（边界 hold 在终端帧处释放不吞帧）、`direct_rejected_sticky_suppresses_tool_frames`（粘滞后无 tool/终止帧透传）
  - Verify: `cargo test -p veil direct_n1_completed_then_error_single_terminal direct_p1_backfill_preserves_usage_tail direct_boundary_hold_released_at_terminal direct_rejected_sticky_suppresses_tool_frames` 全绿
  - Verify: 每例断言下游帧序列/计数（终端恰一、usage 保留、hold flush、sticky 后帧数为 0），并在测试注释标注对应决策点与原仓 `llm_test.py` 锚点

## 2. `T2` 薄弱 e2e 断言厚度提升（MED）

- [x] 2.1 `tests/http_e2e_pii_concurrency.rs::t3_1_pii_100_concurrent_restore_isolated_no_crosstalk`：保持 `CONCURRENCY=100` 与 120s 预算，新增请求级断言（每路 200、本路 `phone(i)` 还原、本路占位符已还原为号码、他路号码缺席）、100×99 全对串扰矩阵显式计数、`/_admin/metrics` 的 `requests==100`
  - Verify: `cargo test -p veil t3_1_pii_100_concurrent_restore_isolated_no_crosstalk` 通过；断言条数 ≥3×CONCURRENCY（grep/运行日志核对）
  - Verify: 新增全对矩阵断言（任一路不含他路号码，含自环跳过），且 `requests==100` 断言落文件

- [x] 2.2 `tests/http_e2e_metrics_snapshot.rs::b5_snapshot_shape_matches_series_and_empty_window_ok`：字段存在性升级为类型/取值断言（`is_precise` 布尔、`sse_events`/`ring_len`/`dropped`/`p95_ms` 数值、`tokens` 六列、`truncated` 三 mode、`per_protocol`/`per_model` 行），并新增 seed 后 series 行求和 == 快照 `requests`/`total` 一致性断言
  - Verify: `cargo test -p veil b5_snapshot_shape_matches_series_and_empty_window_ok` 通过；断言数 ≥ 字段数×2（存在性 + 类型）
  - Verify: series 与快照取值一致性断言（非仅形状）落文件，空窗零值语义保留

- [x] 2.3 `tests/http_e2e_nondialog_passthrough.rs::t2_1_nondialog_models_passthrough_with_count_and_no_side_effects`：新增连续三次透传计数 1→2→3、`hop_filtered` 方向计数、上游收到路径/方法/头断言、状态码与 `content-type` 不被改写、凭据/PII 占位符零注入、无用量（`requests==0`）/无审计事件保持
  - Verify: `cargo test -p veil t2_1_nondialog_models_passthrough_with_count_and_no_side_effects` 通过；计数断言覆盖 1→2→3
  - Verify: 新增断言证明透传臂零副作用（无 `__PII_`/`__VG_CRED_` 形态、无 `x-veil-normalized`、上游收到的头经 hop 过滤）

## 3. `T3` 真 SDK 脚本纳入门禁（MED）

- [x] 3.1 新增 `scripts/gate.sh`：串联 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、`python3 scripts/check_doc_paths.py`、`python3 scripts/check_file_sizes.py`、`python3 scripts/api_conformance.py`；任一失败整体非零；缺 Python venv/SDK 时显式报错或 `GATE_SKIP_CONFORMANCE=1` 显式跳过并打印理由（不静默）；脚本头注释登记前置条件（venv、SDK pin、Mock TPM 回退）
  - Verify: `bash scripts/gate.sh` 在具备前置条件环境退出码 0；人为置败任一子步骤（如临时非法 fmt）时退出码非零
  - Verify: `python3 scripts/api_conformance.py` 输出「共 20 项，失败 0 项」并退出码 0（TPM 无硬件时走内建 Mock 回退）

- [x] 3.2 文档同步：README §8.5 由「口径不同非回归缺失」更新为「已纳入 gate 步骤 + 前置条件 + 跳过语义」，保留原仓 12 项 vs 本仓 20 项口径说明；`scripts/README.md` 登记 `gate.sh` 用法、SDK pin 与 venv 路径
  - Verify: `grep -n "api_conformance" README.md` 命中 §8.5 新表述（含 gate 与前置条件）；旧「口径不同非回归缺失」不再作为唯一结论
  - Verify: `grep -n "gate" scripts/README.md` 命中用法、前置条件与跳过语义

## 4. `T4` 可观测性测试粒度恢复（MED）

- [x] 4.1 `tests/http_e2e_metrics_filter.rs` 补 series 旧 range 四档 e2e：`1h/24h/7d/30d` 分别断言 `granularity=five_min/hourly/daily/daily` + `deprecated` 标注 + 与同窗新口径 points 逐点等价；未知 range 口径维持既有
  - Verify: `cargo test -p veil legacy_range_four_tiers` 通过；四档逐项断言
  - Verify: 等价性断言落文件（`range=R` 与对应新 granularity 的 points 逐点相等），既有 `range=24h` 断言保留

- [x] 4.2 新增 model/upstream 筛选 e2e（`tests/http_e2e_metrics_filter.rs` 或新 `tests/http_e2e_admin_stream_filter.rs`）：SSE 建连 `?model=&upstream=` 命中/未命中/双条件交集/空值不过滤；`/_admin/metrics|events?model=&upstream=` 弃用忽略口径（`deprecated` 标注 + 结果与全局一致）
  - Verify: `cargo test -p veil sse_stream_model_upstream_filter` 通过；命中流非零事件、未命中流零事件
  - Verify: `cargo test -p veil metrics_events_deprecated_ignore` 通过；deprecated 标注 + 全局口径一致

- [x] 4.3 SSE 快照形状与计数 e2e：消费 mock SSE 流后读取 `/_admin/metrics`，断言 `sse_events` 相对基线精确增加（= 下游收到帧数）、`per_protocol` 行、`truncated`/`chat_tail_lenient`/`is_precise` 类型与取值
  - Verify: `cargo test -p veil sse_snapshot_shape_after_stream` 通过
  - Verify: 断言 `sse_events` 增量与流帧数一致且类型为数值，`per_protocol` 行存在

## 5. `GO` 网关侧契约锁定（MED，`veil-hardening` 5.x 交叉引用）

- [x] 5.1 新增 `tests/go_interop_contract.rs`：模拟 Go `FetchCredential` 纯 body POST（无三因子头、仅 `body.auth.caller_hash/caller_path`）→ 403 且错误体为 `{"error":{"code":...,"message":...}}` 对象（`error` 非 string，锁定「Go 不可直接解析」根因）；`body.secret` 兼容与 `body.auth.get_binary_secret`/`get_binary_hash` **被采纳**（等价头，`auth.rs:22-45`，`credential/mod.rs:84-90` 标注 Go 别名）的行为锁定
  - Verify: `cargo test -p veil go_shaped_credential_body_only_rejected` 通过
  - Verify: 断言错误体 JSON 对象形状（`error.code` 存在、`error` 为对象非字符串）

- [x] 5.2 同文件补三因子齐全/缺失矩阵与三协议阻断流终止：齐全（头体一致）→ 放行或转审；缺哈希头/密钥头/`body.auth.*`/冒用各 → 403 或 202 明确诊断；阻断相 chat 恰一 `[DONE]`+`[blocked:`、anthropic `message_stop`+`content_block_stop`、responses `response.failed`，即时闭合
  - Verify: `cargo test -p veil go_three_factor_matrix` 通过
  - Verify: `cargo test -p veil go_blocked_stream_terminates` 通过；三协议各断言终止帧恰一且无重试/挂起

- [x] 5.3 交叉引用登记：测试文件头注释标注对应 `veil-hardening` 5.1/5.2/5.3；design D5 与 proposal 覆盖表声明「真机 Go 闭环仍由 `veil-hardening` 承接」；不改 `veil-hardening` 任何文件
  - Verify: `grep -rn "veil-hardening" openspec/changes/veil-test-coverage-fill/ tests/go_interop_contract.rs` 命中交叉引用
  - Verify: `git diff --name-only` 对 `openspec/changes/veil-hardening/` 零改动

## 6. 记录项（`R1`/`R2`）

- [x] 6.1 `#[ignore]` 零验证：`grep -rn "#\[ignore" src/ tests/` 仅命中 `tests/http_e2e_pii_concurrency.rs:6` 注释；`cargo test -- --list` 无 ignored 统计；保持该状态
  - Verify: `grep -rn "#\[ignore" src/ tests/` 输出无属性行（仅 `//!` 注释）
  - Verify: `cargo test 2>&1 | grep "test result"` 各 suite 均为 0 ignored

- [x] 6.2 design.md D6 记录零直接覆盖文件清单与可接受理由：`sse/emit.rs`/`meta.rs`/`parser.rs`、`block_inject/frames.rs`/`terminal.rs`、gateway 面 facade；标注上层覆盖计数（`sse.rs` 30 项、`block_inject.rs` 24 项；apply 实测，审计基线 29 + 前序 change 新增 1）
  - Verify: `grep -n "零直接覆盖" design.md` 命中清单与「可接受，不补独立测试模块」判定
  - Verify: `cargo test -- --list | grep -c "service::sse::"` = 30（审计基线 29；前序 change 新增 1，apply 实测）且 `grep -c "service::block_inject::tests"` = 24（计数证据）

## 7. 门禁与回归

- [x] 7.1 apply 完成后全量质量门禁：`cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿（≥784 passed / 0 failed，新增用例全绿且零既有回退）
  - Verify: 三条命令退出码 0；`cargo test` 总数 ≥784 且 failed=0
  - Verify: `python3 scripts/check_file_sizes.py` 与 `python3 scripts/check_doc_paths.py` 退出码 0（新增测试文件 ≤800 行）

- [x] 7.2 `openspec validate veil-test-coverage-fill --strict` 0 failures
  - Verify: 命令输出 `is valid`
  - Verify: 覆盖表 11 行与 spec 6 个 Requirement 一一对应（`grep -c "T1\|T2\|T3\|T4\|GO\|R1\|R2"` 对照）

- [x] 7.3 gate 全链路执行并登记结果（含 `scripts/api_conformance.py` 20 项）；缺前置时按 D3 显式跳过并记录理由，不得静默
  - Verify: `bash scripts/gate.sh` 退出码 0，或输出显式跳过理由并留有登记
  - Verify: `scripts/api_conformance.py` 输出「共 20 项，失败 0 项」
