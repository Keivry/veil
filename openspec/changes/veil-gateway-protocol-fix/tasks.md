## 1. Chat 阻断帧形态（D1）

- [x] 1.1 `chat_block_frames` 改 `delta` 三帧形态 + 同步既有单测期望
  - Verify: `src/service/block_inject.rs` 首帧含 `delta` 且不含 `"message"`，末帧为裸 `data: [DONE]`
  - Verify: `cargo test block_inject` 全绿且 `count_done==1` 断言通过
  - Verify: `scripts/api_conformance.py` 20/20 通过
- [x] 1.2 `ensure_event_lines` Chat 豁免 `event:` 补全（Anthropic/Responses 保持）
  - Verify: Chat 帧经补全后仍无 `event:` 行，非 DONE 帧为纯 `data:` 形态
  - Verify: Anthropic/Responses 缺 `event:` 行仍被补全
  - Verify: 既有 `缺event行阻断载荷补全` 单测按协议拆分后通过

## 2. Anthropic 与 Responses 帧（D2/D3）

- [x] 2.1 Anthropic 阻断改 `text` 块 + `message_stop` 空对象
  - Verify: 四帧顺序 `start/stop/delta/message_stop` 不变且首块 `type=="text"`
  - Verify: `message_stop` 数据为 `{"type":"message_stop"}` 无自造字段
  - Verify: `anthropic四件套终止且顺序锁定` 单测更新后通过
- [x] 2.2 Responses 全序列阻断/截断帧（`added/delta/done/completed|failed`）
  - Verify: 阻断流含 `output_item.added` 且尾帧为 `response.completed`，`terminal_count==1`
  - Verify: 截断流尾帧为 `response.failed` 且不含 `completed`
  - Verify: `responses阻断与截断区分` 等单测更新后通过
- [x] 2.3 非流 Chat 阻断补 `id/object/created/model/usage` 回显 + Anthropic `blocked-0` 口径统一
  - Verify: 非流 Chat 阻断体 `object=="chat.completion"` 且 `id` 非空
  - Verify: Anthropic 空 `conv_id` 回退为 `blocked-0`（非流与流一致）
  - Verify: `anthropic非流阻断六字段完整` 与新增字段单测通过

## 3. 状态机加固（D4/D6）

- [x] 3.1 泵尾空流守门改终端状态位（替代 `forwarded==0`）
  - Verify: 残余已发场景不再合成二次空流帧（新增回归单测）
  - Verify: 真空流仍合成三协议恰一终端帧
  - Verify: `tests/http_e2e_truncation.rs` 与 sentinel 回放通过
- [x] 3.2 `usage max` 递减/乱序锁定 + `message_delta` 累计覆盖单测
  - Verify: 递减输入记录值不回退，乱序输入取历史最大
  - Verify: 无 `sum` 双计行为（新增单测锁定）
- [x] 3.3 `NonDialog` 转泵 `conv` 归档统一 + 双实现 `index` 对齐注释 + 四终止函数分工注释
  - Verify: `NonDialog` 回 SSE 场景阻断帧 id 与对话路径同源
  - Verify: `extract_tool_calls` 头注释含外层 `index` 对齐声明
  - Verify: 全量 `cargo test` 通过

## 4. BoundaryHold 收窄（D5）

- [x] 4.1 `mask_span_bytes` 逐字符豁免（信封位跳过）+ roundtrip 单测
  - Verify: 含信封字符的跨缝命中中非信封位仍被掩码
  - Verify: 掩码前后帧体仍为合法 JSON（roundtrip 不破坏）
  - Verify: 既有 `BoundaryHold` 单测全绿
- [x] 4.2 `filter_window` IPv6 全字母组缝邻保护
  - Verify: 全字母 IPv6 组紧邻缝合缝不再被 `"key":` 误删（新增单测）
  - Verify: 正常 JSON 键过滤行为不变（既有单测通过）
- [x] 4.3 `stream_options` 键冲突、`truncation` 透传、`thinking/signature` 不透明三项回归单测
  - Verify: 已存在 `stream_options object` 内键冲突时按 key 合并而非替换
  - Verify: `truncation:disabled` 上游 400 原样透出不吞错
  - Verify: 含 `signature/redacted_thinking` 的流经网关后字节一致
