## B1. Responses 注入收窄（决策 b）

- [x] B1.1 `protocol.rs` `should_inject_stream_options` 收窄为仅 `Protocol::Chat`；注释记录官方依据与决策
  - Verify：`Protocol::Responses` 不在注入匹配；`cargo test protocol` 全绿
- [x] B1.2 `protocol.rs:213` 测试改名 `stream_options_injected_only_for_chat` 并改断言（Responses 不注入）
  - Verify：新断言通过
- [x] B1.3 `rewrite.rs:490` `rewrite_t3_responses_true_injection_integration` 改为「不注入且字节保留」；新增「Responses 用户自带 `stream_options` 原样保留」用例
  - Verify：`cargo test rewrite` 全绿
- [x] B1.4 README §7.2 合并语义句限定 Chat；§7.7 条件① 表述对齐
  - Verify：`grep -n "include_usage\|stream_options" README.md` 全部为 Chat 语境或决策记录
- [x] B1.5 回归：`cargo test` + `scripts/api_conformance.py` + sentinel 回放；真上游用量对照一次
  - Verify：全绿；Responses 用量记录不缺失（若缺失触发 R1）
- [x] B1.6 design R1 回退条款保持与 apply 结论登记
  - Verify：design 含 R1；apply 后结论（是否触发回退）已注明

## B2. 空流对齐与声明

- [x] B2.1 `stream_tests.rs` 补 Anthropic 真空流 open-ended 用例（对齐 chat 断言）
  - Verify：零合成帧、无 `message_stop`、`truncated_mode=open_ended`
- [x] B2.2 三协议空流 e2e 对照（chat/anthropic 零帧且连接正常关闭；responses 收 failed）
  - Verify：e2e 全绿
- [x] B2.3 README §8 新增 8.6 决策声明（差异、风险、依赖下游 stub、与原仓 `_ensure_nonempty_stream` 对比、引用 spec）
  - Verify：§8.6 存在且引用 `stream-protocol-parity`
- [x] B2.4 Hermes stub 证据复核 → 结论登记 §8.6。分级处置：①证实存在→保持 open-ended 并登记证据；②无法证实→§8.6 标注「待人工确认」open item（owner：下游集成）+ 触发后续 change 评估「chat/anthropic 空流补终止帧」路线（需修订 `stream-protocol-parity`）
  - Verify：§8.6 含证据或 open item + 升级路径登记

## B3. Chat 缺 [DONE] 可观测

- [x] B3.1 流泵：Chat 记录 `finish_reason` 非 null；流末缺 `[DONE]` → `set_truncated(OpenEnded)` + warn + 指标（不合成帧）
  - Verify：`cargo test` 全绿；无字节变更
- [x] B3.2 单测：`finish_reason:"stop"` 后 EOF 无 `[DONE]` → 断言 open_ended 且零合成
  - Verify：新用例通过
- [x] B3.3 README §7.2 增口径句（无 `[DONE]` 的 open-ended 处置）
  - Verify：句含「无 [DONE]」「open-ended」

## B4. error 统一锁定

- [x] B4.1 单测/复核：`error` 事件 → 恰一 `response.failed`、无 completed、无重复终端
  - Verify：断言存在且通过
- [x] B4.2 README §7.2 统一语义字面复核保持
  - Verify：grep 复核同字

## B5. message_delta 一致性

- [x] B5.1 核验 `message_delta` 粘滞终止 + 按槽清理双路径（`event.rs`/`hold.rs`）
  - Verify：书面结论（一致/不一致 + file:line 证据）
- [x] B5.2 补单测：tool_use 槽完成 + `message_delta` 同帧 → 审计恰一次、无重复清理
  - Verify：新用例通过
- [x] B5.3 若 B5.1 不一致：最小修复 + 回归；否则登记「不适用」
  - Verify：全绿或「不适用」登记
  - 结论：不一致**不成立**（结论：一致）。审查报告所述「`message_delta` 参与按槽清理」与代码不符——`message_delta` 仅粘滞终止（`pump/event.rs:66`），按槽清理由 `content_block_stop`/`item_done`（`audit/hold.rs:239-244` + `:248-252`）驱动，故按槽清理角色**不适用**，无需修复。详见 design.md D5。

## B6. sequence_number 容忍

- [x] B6.1 单测：断序 `sequence_number` 帧原样透传不 panic、恰一终端
  - Verify：新用例通过
- [x] B6.2 README §7.2 增容忍口径句（透传优先、不丢帧）
  - Verify：句含「sequence_number」

## B7. 占位符门控口径

- [x] B7.1 核验 `\d{6,}` 门控既有单测；README §7.2/§8 增口径句（有意保守）
  - Verify：单测存在 + 文档句存在

## B8. 措辞 sweep

- [x] B8.1 全文 sweep §7.2/§7.4/§7.7/§8：凡涉 `include_usage`/`stream_options` 表述与 B1 收窄一致
  - Verify：`grep` 逐处复核无「Responses 注入」残留（决策记录除外）
