## 1. Responses 占位符注入归一化（E3-P2）

- [x] 1.1 按 D1 所选方案改 `request_rewrite` 占位符分支或 README §7.7，Verify: `rewrite.rs:83-93` 注入用例 `normalized_out` 与所选一致；下游响应头按 `normalized_out` 置位单测通过
- [x] 1.2 同步更新既有快照并跑回归，Verify: `cargo test rewrite_unit_tests` 通过；`cargo test` 全绿无快照残留失败

## 2. 纯脱敏字节替换口径（E13-P2）

- [x] 2.1 README §7.7 补字节替换不置位一句，Verify: 文档含长度变化不置位声明；`rewrite.rs:55-77` 对应单测 `normalized_out == false` 通过
- [x] 2.2 加长度变化锁定单测，Verify: 脱敏替换前后长度不同用例不置位；`cargo test rewrite` 通过

## 3. 非流还原残缺重试（E5-P2）

- [x] 3.1 `serve_nonstream` 校验失败分支先 `strip_partials` 重试，Verify: `nonstream.rs:192-207` 破裂可挽回用例返回剥离后还原体；仍失败回退原文且 warn 可观测
- [x] 3.2 回退记 metrics 并跑回归，Verify: 回退计数 metrics 单测通过；`cargo test nonstream` 通过

## 4. 错误 JSON 后处理声明（E6-P2）

- [x] 4.1 `nonstream.rs:225-231` 尾部分支加意图注释并文档声明，Verify: 400 系 JSON 走后处理单测通过；文档含非 502/401 仍后处理声明
- [x] 4.2 跑非流回归，Verify: `cargo test nonstream_empty_tests` 通过；401/502 豁免透传行为不变

## 5. 双缓冲分工（E10-P2）

- [x] 5.1 按 D5 所选统一缓冲或加分工注释，Verify: `pump.rs:289-320` 注释或统一后 tool 分片去向可追踪；完成前缓冲不透传单测通过
- [x] 5.2 跑流泵回归，Verify: `cargo test pump` 通过；截断丢弃计数行为不变

## 6. 空流合成排除注释（E11-P2）

- [x] 6.1 锁定 `comment_only` 不置位 `any_frame_sent`，Verify: `pump.rs:637-680` 纯心跳用例 `should_synthesize_empty_stream(false,false,false)` 为真；注释帧透传但不记位单测通过
- [x] 6.2 跑空流回归，Verify: `cargo test empty_stream` 通过；真空三协议终端恰一不变

## 7. 非流转泵会话透传（E12-P2）

- [x] 7.1 转泵分支透传请求会话标识，Verify: `nonstream.rs:118-129` 不再以 `resolve_conv_id(None, Null)` 合成；泵内终端帧复用请求会话单测通过
- [x] 7.2 缺失回退可观测，Verify: 无会话时合成且记 `conv_missing`；`cargo test conv` 通过

## 8. Host IPv6 解析（A1-P1）

- [x] 8.1 `gateway_serve` 入口端口改方括号解析，Verify: `src/handler/llm/mod.rs:127-139` 处 `Host: [::1]:8878` 解析为 `8878`；裸 `::1` 回退 `None` 单测通过
- [x] 8.2 跑选路回归，Verify: `resolve_upstream` 缺省回退行为不变；`cargo test llm` 通过

## 9. 编码剥离声明（A5-P2）

- [x] 9.1 `hop.rs:33-73` 编码分支加一行日志并补 README §7.1 一句，Verify: `content-encoding: gzip` 剥离且对外 `identity` 单测通过；文档含统一 `identity` 声明
- [x] 9.2 跑 HOP 回归，Verify: `cargo test hop` 通过；双向计数 `hop_filtered_total` 行为不变
