## R1. E7-P0 thinking 混帧漏提

- [x] R1.1 `pump.rs` 主循环先调 `extract_tool_fragments` 再算 `is_minor_event`，混帧走 tool 通道进 hold
  - Verify：构造 `content_block_delta` 同含 `thinking_delta` 与 `partial_json` 的帧，断言 `extract_tool_fragments` 非空且 `hold.push_fragment` 被调用
  - Verify：纯 `thinking_delta` 帧断言 `is_minor_event` 为真且 hold 无新增，`cargo test -p veil pump` 通过
- [x] R1.2 补混帧回归单测并跑 hold 时序
  - Verify：混帧单测断言工具增量被缓冲审计、thinking 部分透传，`cargo test -p veil mixed_thinking_tool` 通过
  - Verify：既有 `pump.rs:1435-1460` minor 相关单测全绿，无快照回退

## R2. E8-P1 terminal contains 字符串判定

- [x] R2.1 `pump.rs:202-234` 改 `serde_json` 解析后按 `type` 精确判定终结
  - Verify：`{"type": "error"}` 带空格变体帧断言触发终结合成截断，`cargo test -p veil terminal_error` 通过
  - Verify：正文含 `response.completed` 字符串但 `type` 为 `output_text.delta` 的帧断言不终结、继续转发
- [x] R2.2 解析失败兜底加计数
  - Verify：非法 JSON 帧走 contains 兜底且计数加一，`cargo test -p veil terminal_fallback` 通过
  - Verify：Chat 与 Anthropic 终止分支行为不变，既有 terminal 单测全绿

## R3. E9-P1 incomplete 合成 conv 不一致

- [x] R3.1 泵内记录流内首见 `id`，合成截断帧优先使用
  - Verify：先送 `response.created{id:resp_123}` 再送 `incomplete`，断言合成 `responses_truncated_frames` 入参为 `resp_123`，`cargo test -p veil incomplete_conv` 通过
  - Verify：`resolve_conv_id` 本体（`tool.rs:572`）签名不变，`cargo test -p veil conv` 通过
- [x] R3.2 缺失回退归档不断链
  - Verify：流内无 id 时断言回退 `unknown_<hash>` 且 `conv_missing` 计数加一
  - Verify：下游收到唯一终结帧，`dedupe_terminal` 恰一单测通过

## R4. E1-P1 stream_options=false 保留文档化

- [x] R4.1 `README §7.2` 追加显式 false 语义段
  - Verify：文档含“显式 false 即放弃流式用量，按 key 合并保留不覆写”字样，`grep -n "显式 false" README.md` 命中
  - Verify：`protocol.rs:126-145` 与 `rewrite.rs:172-190` 代码零改动，`git diff --stat` 无 src 变更
- [x] R4.2 metrics 空 usage 桶告警指引
  - Verify：文档含空 usage 桶先查显式 false 的排查句，`grep -n "空 usage" README.md` 命中
  - Verify：`stream_options_conflict_merged_by_key_not_replaced` 单测仍通过，false 保留语义未漂移

## R5. E2-P1 Responses 双字段部分非法整体回退

- [x] R5.1 `placeholder.rs:189-213` 改逐字段独立注入独立回退
  - Verify：`input` 合法 string 加 `instructions` 非法 number 时断言 `input` 注入保留、`instructions` 原值不变，`cargo test -p veil placeholder_responses` 通过
  - Verify：`placeholder_schema_ok` 保留作最终兜底，双字段均非法时整体返回 `None`
- [x] R5.2 更新既有占位快照
  - Verify：双合法场景断言双字段均注入，`cargo test -p veil placeholder` 全绿
  - Verify：Chat 与 Anthropic 注入路径行为不变，无跨协议回退

## R6. E4-P1 阻断体状态码不对称

- [x] R6.1 二选一落地：统一恒 200 或文档声明差异
  - Verify：若选统一，`nonstream.rs:150-189` 阻断分支断言 `StatusCode::OK`，上游 502 输入仍回 200 加阻断体，`cargo test -p veil nonstream_block_status` 通过
  - Verify：若选声明，`README §8` 或对应 spec 含差异声明句且单测断言非流保留上游码、流式恒 200
- [x] R6.2 三协议阻断对称回归
  - Verify：Chat、Anthropic、Responses 非流阻断状态码行为一致符合所选方案，`cargo test -p veil block_inject` 通过
  - Verify：conformance 脚本三协议阻断用例通过，所选方案在 design D6 落字一致
