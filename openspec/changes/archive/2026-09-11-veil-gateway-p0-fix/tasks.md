## 1. stream_options 键内合并

- [x] 1.1 `should_inject_stream_options` 改为键内 `include_usage` 缺失判定，验证：`stream_options={"other":1}` 用例转发体含双键
- [x] 1.2 `inject_stream_options` 非对象形态替换 + warn，验证：非法形态单测回退可解析
- [x] 1.3 Anthropic 永不注入回归，验证：三协议矩阵单测通过

## 2. Anthropic 非流阻断体补全

- [x] 2.1 `nonstream_block_body` 补 `id/type/role/usage/model`，验证：严格 SDK 形态单测通过
- [x] 2.2 更新既有阻断快照单测，验证：`cargo test block_inject` 通过

## 3. Responses 阻断截断可读化

- [x] 3.1 阻断前补 `output_text.delta` 明文，验证：下游先见文本再见唯一 `completed`
- [x] 3.2 截断前补 `TRUNCATED_MESSAGE` 或文档声明空语义，验证：单测锁定所选且无伪造 `completed`
- [x] 3.3 delta 帧不计入终止计数，验证：`dedupe_terminal` 恰一单测通过

## 4. 终止计数与空格口径

- [x] 4.1 `count_done` 改行级精确，验证：`arguments` 内同串用例计数不变
- [x] 4.2 双空格 `data:` 回归单测，验证：`data:  {json}` 可解析

## 5. 组合路由与形态锁定

- [x] 5.1 `stream:true+application/json` 组合单测（实现 owner；`veil-test-closure-round2/tasks.md 4.4` 仅记录核对结论，不双写实现），验证：按 design 路由且 conformance 14/14 通过；apply 前实测定稿后删除 design D5“翻转” clause
- [x] 5.2 Chat 阻断文案统一（中/英二选一），验证：下游展示一致且单测锁定
- [x] 5.3 Anthropic `blocked` 占位二次调用验证，验证：占位名不在 allow 名单且 `input:{}` 合法
