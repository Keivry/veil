## 1. `T1` 入站 query 保序转发

- [x] 1.1 `src/handler/llm/dispatch.rs:62/124`：`llm_proxy_handler` 保留 `parts.uri.query()`，`gateway_serve` 拼接上游 URL 时按「path + (`?` + raw query)」生成（无 query 不加 `?`，不重编码、不重排）；`path` 仍取 `uri.path()`，不引入 scheme/host
  - 验证：`cargo test -p veil query_string_forwarded_raw` 通过；mock 上游断言请求目标为 `/v1/models?limit=10&after=abc`（同序同编码）与 `/v1/chat/completions?trace=1&x=a%2Bb`
  - 验证：`cargo test -p veil query_absent_no_question_mark` 通过；无 query 请求的目标与修复前逐字节一致
- [x] 1.2 补非对话与对话双路径 query 用例（空值参数 `limit=`、重复键、`+` 与 `%2F` 编码），并覆盖上游基址自带 query 的边界（断言不产生双 `?` 或明确拒绝）
  - 验证：`cargo test -p veil query_empty_value_and_duplicate_keys` 通过
  - 验证：`cargo test -p veil --test http_e2e_nondialog_passthrough` 全绿（NonDialog 透传 query 不断链）

## 2. `T2` 非流响应头透传

- [x] 2.1 `src/handler/llm/nonstream.rs:136-148`：`up.bytes()` 前快照上游响应头，经 `src/service/llm_gateway/hop.rs:41 filter_hop_headers_counted("downstream")` 过滤后，在 JSON 后处理与错误透传分支逐条转发（保留 `content-type`；`x-veil-*` 由网关过滤后覆盖写入）
  - 验证：`cargo test -p veil nonstream_upstream_headers_forwarded` 通过；200 `application/json` 响应下游 `content-type` 为 `application/json`，429 响应含 `retry-after: 30` 与 `x-request-id`
  - 验证：`grep -n "text/plain; charset=utf-8" src/handler/llm/nonstream.rs` 无残留（不再由 `(StatusCode, String)` 构造对话响应）
- [x] 2.2 补逐跳过滤与 `x-veil` 覆盖用例：上游带 `connection`/`transfer-encoding` 不入下游；上游自带 `x-veil-protocol` 不得覆盖网关派生值
  - 验证：`cargo test -p veil nonstream_hop_filtered_and_veil_override` 通过
  - 验证：`cargo test -p veil --test http_e2e_sse_loop` 与 `--test http_e2e_nondialog_passthrough` 全绿无回退

## 3. `T10` 网关生成响应统一 `x-veil-protocol`

- [x] 3.1 `src/handler/llm/nonstream.rs:275-277`（错误透传）、`:291-300`（超限）、`src/handler/llm/mod.rs:62 empty_body_response`：统一置 `x-veil-protocol`（`chat`/`anthropic`/`responses`），与 `:212-215`/`:264-267` 成功/阻断分支口径一致
  - 验证：`cargo test -p veil nonstream_error_response_has_protocol_header` 通过；429 透传响应含对应协议头
  - 验证：`cargo test -p veil nonstream_502_responses_have_protocol_header` 通过；超限 502 与空体 502 均含对应协议头
- [x] 3.2 三协议矩阵：Chat/Anthropic/Responses 的错误与超限响应各自携带正确协议值（不互相串值）
  - 验证：`cargo test -p veil protocol_header_matrix_nonstream` 通过

## 4. `T3` 流式独立超时 client

- [x] 4.1 `src/state.rs:148-161`：拆分启动期 client 构造——流式入口不设覆盖整响应体读取的总超时（`timeout`），可选配置读空闲超时；`AppState` 注入两份共享 client；`src/handler/llm/dispatch.rs` 流式分支传流式 client、非流/NonDialog 保持既有 client
  - 验证：`cargo test -p veil stream_client_has_no_total_timeout` 通过；以 `HTTP_TIMEOUT_SECS=1` 配置 + mock 长流（间隔 < 读空闲阈值、总时长 > 1s）断言下游持续收到事件
  - 验证：`cargo test -p veil nonstream_keeps_total_timeout` 通过；非流长体仍按 `HTTP_TIMEOUT_SECS` 超时映射网关错误
- [x] 4.2 README §1（`HTTP_TIMEOUT_SECS` 行）与 §7.2 补流式/非流超时口径说明；design 的读空闲超时取值决策回写
  - 验证：`grep -n "流式" README.md` 命中流式无总超时声明；`grep -n "HTTP_TIMEOUT_SECS" README.md` 语义与实现一致
  - 验证：`cargo test -p veil --test http_e2e_sse_loop` 全绿（流式回归不因 client 拆分断裂）

## 5. `T4` 非流响应体有界读取

- [x] 5.1 `src/handler/llm/nonstream.rs:148-158`：`content-length` 预检（`status<400` 且声明值 > cap → 立即 502 `response_too_large`，不读 body）；改用 `bytes_stream()` 有界累计，累计超限即停读并 502；`status>=400` 语义不变；`len == cap` 放行
  - 验证：`cargo test -p veil nonstream_oversize_content_length_precheck` 通过；声明超限时上游 body 未被读取（mock 计数为 0）
  - 验证：`cargo test -p veil nonstream_oversize_chunked_bounded_read` 通过；分块累计超限即 502，且不先全量缓存
- [x] 5.2 补边界用例：无 `content-length` 分块恰好 `len == cap` 放行；`status>=400` 超限错误体按 N2/D6 透传不改写
  - 验证：`cargo test -p veil nonstream_bounded_read_boundary` 通过
  - 验证：`cargo test -p veil nonstream` 组全绿（含既有 `src/handler/llm/nonstream/tests/f2.rs` 超限回归）

## 6. `T5` 协议尾判定排除官方子资源

- [x] 6.1 `src/service/llm_gateway/protocol.rs:54-78 lenient_match`：额外单段为 `v1/messages/{count_tokens|batches}` 或 `v1/responses/{任意单段}` 时不判对话协议（返回 `NonDialog`）；严格尾缀与尾斜杠/其余一层宽容语义不变
  - 验证：`cargo test -p veil official_subresources_are_nondialog` 通过；`count_tokens`/`batches`/`v1/responses/{id}`/`v1/responses/{id}/cancel`/`v1/responses/{id}/input_items` 均 `Protocol::NonDialog`
  - 验证：`cargo test -p veil single_suffix_lenient_match_with_count` 全绿（`/v1/chat/completions/extra` 仍命中并计数）
- [x] 6.2 补 e2e：`POST /v1/messages/count_tokens` 与 `GET /v1/responses/{id}` 字节透传、不注入占位符、不记对话用量、不触发审计后处理（含上游响应为错误 JSON 时不被合成阻断体替换）
  - 验证：`cargo test -p veil --test http_e2e_nondialog_passthrough official_subresource_passthrough` 通过
  - 验证：`cargo test -p veil protocol_lenient_regression` 通过

## 7. `T6` 非流 JSON 还原按转义变体

- [x] 7.1 `src/handler/llm/nonstream.rs:230-235`：`restore_response_with_spans` 改为 `restore_response_with_spans_json`（`src/service/redaction/scope.rs:194`），span 继续传 `redact_response_new_pii_with_skip`；非 JSON 段不适用
  - 验证：`cargo test -p veil nonstream_restore_escaped_json_variant` 通过；vault 明文含 `"`、`\` 时下游 JSON 可解析、字段为完整明文、无占位符残留、`restore_fallback` 计数为 0
  - 验证：`cargo test -p veil nonstream_restore_retry_stripped_*` 复核后全绿（既有「引号破裂回退」用例按新语义更新或删除，不得留过时断言）
- [x] 7.2 补控制字符与嵌入字符串用例：明文含换行/制表符、明文嵌在嵌套 stringified JSON 内
  - 验证：`cargo test -p veil nonstream_restore_control_chars` 通过

## 8. `T7` Anthropic 流式 usage total 跨事件口径

- [x] 8.1 `src/service/llm_gateway/usage.rs:71-75/92-103`：合并规则改为「显式 total 取 `max`；全部事件无显式 total 时 `total = max(prompt)+max(completion)`」，写死口径注释
  - 验证：`cargo test -p veil anthropic_usage_total_across_events` 通过；`message_start{in:100,out:1}` + `message_delta{out:50}` 得 `prompt=100/completion=50/total=150`
  - 验证：`cargo test -p veil usage_explicit_total_priority` 通过；显式 total 与分列和不一致时取显式 `max`
- [x] 8.2 补三协议回归：Chat 单帧 usage、Responses `response.completed.usage` 三级回退数值不因合并改动漂移
  - 验证：`cargo test -p veil usage_merge_regression` 通过
  - 验证：`cargo test -p veil usage_tests` 组全绿

## 9. `T8` 还原区间跳过后的嵌套重检

- [x] 9.1 `src/service/redaction/scope.rs:293-318 redact_response_new_pii_with_skip`：非跳过段先尝试整体 JSON 解析并 walk（含嵌套 stringified JSON），解析失败维持文本段处理；跳过段保持字节原样
  - 验证：`cargo test -p veil skip_segments_recursive_stringified_pii` 通过；同一响应既还原凭据又命工具参数内新 PII，两者均正确处理
  - 验证：`cargo test -p veil skip_segments_byte_identical` 通过；仅跳过区间且零命中时输出与输入逐字节一致
- [x] 9.2 补跳过区间边界用例（相邻/重叠 span、段首尾截断）与关闭响应侧检测的旁路回归
  - 验证：`cargo test -p veil skip_span_boundaries` 通过

## 10. `T11` web_search_call 官方 action 审计

- [x] 10.1 `src/service/llm_gateway/tool.rs:109-130 retrieval_args`：增读 `action` 对象（`action.query` 字符串、`action.queries` 数组/其他非 null 序列化），保留顶层 `queries/query` 回退；`results` 继续排除；apply 阶段用真实 Responses payload 核验官方形态并回写 design D10
  - 验证：`cargo test -p veil retrieval_args_action_query` 通过；`{"type":"web_search_call","action":{"type":"search","query":"veil audit"}}` 提取参数含 `veil audit`
  - 验证：`cargo test -p veil retrieval_args_legacy_fallback` 通过；顶层 `query`/`queries` 形态提取不回退
- [x] 10.2 补流/非流双路径审计用例：`web_search_call` 经流式分片与非流 `extract_tool_calls` 均进 hold，查询不因 `action` 形态漏审
  - 验证：`cargo test -p veil web_search_action_audit_both_paths` 通过
  - 验证：`cargo test -p veil tool_extract_parity` 全绿无回退

## 11. `T13` 拿头前瞬断重试分类

- [x] 11.1 `src/service/llm_gateway/mod.rs:225-238`：退避条件扩为 `e.is_connect() || e.is_timeout() || e.is_request()`；退避序列 0.5s→1s→2s 与最多 3 次不变；`Ok(resp)` 后不重试
  - 验证：`cargo test -p veil retry_request_layer_transient` 通过；mock 首次 RST、随后成功时下游无错误且重试计数为 1
  - 验证：`cargo test -p veil retry_bounded_three_attempts` 通过；持续 RST 时最多 3 次退避后返回网关错误
- [x] 11.2 补拿头后断连不重试用例（既有 fail-closed 终止路径），并核对 README §7.2 与 `llm-gateway` canonical「拿头前 3 次」措辞一致
  - 验证：`cargo test -p veil midstream_reset_no_retry` 通过
  - 验证：`grep -n "拿头前" README.md` 命中且语义与实现一致

## 12. `T14` 非流超限/空体判序与观测口径

- [x] 12.1 维持 `src/handler/llm/nonstream.rs:155-158` 判序（`classify_empty` 先算、`status<400` 且 `len > cap` 超限动作先于空体 502）；补 `len>8MB` 非 JSON 200 体用例断言 502 `response_too_large`（不走空体 502）
  - 验证：`cargo test -p veil nonstream_oversize_non_json_200` 通过
  - 验证：`cargo test -p veil --test http_e2e_nondialog_passthrough` 全绿（NonDialog 不受上限约束）
- [x] 12.2 design D12 与 README §4/§7.2 记录与 Python `_llm.py:2936-2944` 的观测差异（无状态门、`metrics_ctx['status']=502` + warning、本仓无独立超限指标）
  - 验证：`grep -n "T14" openspec/changes/veil-transport-fidelity-fix/design.md` 命中差异记录；README §4 超限行含「与 Python 观测差异见 design」指向

## 13. 记录与转出（`T9`/`T12`，无代码改动）

- [x] 13.1 proposal 覆盖表与 design D13 记录 `T9`：NonDialog `NonstreamOutcome::Stream` 死臂由 change `veil-arch-hygiene-closeout` H11 承接，本 change 不改 `src/handler/llm/dispatch.rs:180-219` 与 `src/handler/llm/nonstream.rs:96`
  - 验证：`grep -rn "veil-arch-hygiene-closeout" openspec/changes/veil-transport-fidelity-fix/` 命中
  - 验证：apply 阶段 `git diff --name-only` 对 NonDialog Stream 分支无改动
- [x] 13.2 design D13 记录 NonDialog 字节透传契约引用（README §7.6）与 query 语义；README §7.6 补「入站 query 保序保编码随 path 转发、不做 body 改写/审计/用量」说明，消除与 README §5 的漂移
  - 验证：`grep -n "7.6" README.md` 段落含 query 转发声明；`grep -n "README §7.6" openspec/changes/veil-transport-fidelity-fix/design.md` 命中

## 14. 门禁与回归

- [x] 14.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退（含 `src/service/llm_gateway/protocol.rs` 宽容用例）
- [x] 14.2 `openspec validate veil-transport-fidelity-fix --strict` 0 failures；`python3 scripts/check_doc_paths.py` 退出码 0
  - 验证：validate 输出 `is valid`；check_doc_paths 无 missing/pending 断言失败
- [x] 14.3 `scripts/api_conformance.py` 三协议用例通过（环境允许本地起服务时执行）；长流与官方子资源场景纳入手工核验
  - 验证：脚本输出全通过；`/v1/messages/count_tokens`、`GET /v1/responses/{id}` 在 conformance 与手工 curl 中均字节透传
