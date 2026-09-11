## 1. `H2` 流式还原破帧防护

- [x] 1.1 `src/service/redaction/scope.rs`：新增 JSON 上下文还原变体（如 `restore_response_with_spans_json`，对外保留既有 `restore_response_with_spans`），写回明文按 RFC 8259 转义 `"`/`\`/控制字符；`src/handler/llm/pump/spawn.rs:450-460` 的 JSON 分支改用新入口，plain 分支（`:490-505`）维持字节级原样还原
  - Verify: `cargo test -p veil stream_restore_quotes_escaped` 通过；构造注册明文 `pa"ss`，断言下游帧 `serde_json::from_str` 成功且 `["text"]=="pa\"ss"`（语义等价）
  - Verify: `grep -n "restore_response_with_spans_json" src/service/redaction/scope.rs src/handler/llm/pump/spawn.rs` 命中且仅 JSON 分支调用；`grep -n "restore_response_with_spans" src/handler/llm/pump/spawn.rs` 确认 plain 分支仍用旧入口
- [x] 1.2 `src/handler/llm/pump/spawn.rs:450-460`：还原后逐帧 `jloads` 校验，失败回退还原前占位符帧（`ev.data`）+ `tracing::warn` + `gateway_metrics.record_restore_fallback()`；对齐非流 `src/handler/llm/nonstream.rs:235-245` 的 `retry_stripped` 回退语义
  - Verify: `cargo test -p veil stream_restore_fallback_keeps_token` 通过；断言失败路径下游帧含 `__VG_CRED_` 占位符、JSON 可解析、`restore_fallback` 计数 +1
  - Verify: `grep -n "record_restore_fallback" src/handler/llm/pump/spawn.rs` 命中新增调用点；`grep -n "fn retry_stripped" src/handler/llm/nonstream.rs` 命中且非流行为未改
- [x] 1.3 补 `H2` 四场景测试：明文含双引号、反斜杠、换行控制字符、病态回退（还原后仍破损）
  - Verify: `cargo test -p veil stream_restore_special_chars` 通过；四场景断言（合法 JSON / 转义形态 / 回退计数 / 不破帧）
  - Verify: `cargo test -p veil nonstream` 全绿，非流 `restore_fallback` 既有用例不回退

## 2. `H1` JSON 字节保真

- [x] 2.1 `src/service/redaction/scope.rs:176-191`：`redact_response_new_pii` 与 `:198-242` `redact_response_new_pii_with_skip` 增加替换追踪（对齐 `redact_request` 的 FIX-5 `replaced` Cell），全程零替换时返回原文、不触发 `json_walk::process_text` 的 `jdumps`
  - Verify: `cargo test -p veil response_zero_replacement_byte_identical` 通过；`{"b":2,"a":1}` 输入输出字节相等
  - Verify: `grep -n "replaced" src/service/redaction/scope.rs` 命中响应侧两入口追踪；零替换用例断言 `json_walk::process_text` 未产出重排（可经测试钩子或输出字节断言）
- [x] 2.2 `Cargo.toml:15` 改为 `serde_json = { version = "1", features = ["preserve_order"] }`；`src/service/sse/parser.rs:317-331` `json_aware_line` 去重复序列化（JSON 合法即返回输入，仅保留校验；`classify_residue` 语义不变）
  - Verify: `cargo test -p veil json_key_order_preserved` 通过；含新 PII 的重序列化帧键序为原始 `b,a`（非 `a,b`）
  - Verify: `cargo test -p veil json_aware_line_no_second_pass` 通过；同一已处理帧经 `json_aware_line` 输出与输入字节一致
  - Verify: `cargo test -p veil` 全绿（`preserve_order` 对既有键序快照的影响已按 design D2 处理）
- [x] 2.3 数字/空白残余偏离处理：零替换路径逐字节保留（如 `1e3` 不被改写成 `1000.0`）；重序列化路径的已知偏离在 README §7.1/§7.7 声明（apply 阶段执行）
  - Verify: `cargo test -p veil response_number_literal_passthrough` 通过；`1e3` 零替换时下游字节不变
  - Verify: `grep -n "preserve_order" Cargo.toml` 命中；README 声明段落含「数字表示/空白」已知偏离（apply 后 `grep -n "已知偏离" README.md` 命中）
- [x] 2.4 `src/service/redaction/scope.rs::redact_request` 报告「是否经 `loads→walk→dumps` 重序列化」，`src/handler/llm/rewrite.rs:65-66` 据此置 `normalized_out`（handler 输出 `x-veil-normalized`）；非 JSON 字节替换与原文透传不置位
  - Verify: `cargo test -p veil request_json_redaction_declares_normalized` 通过；JSON 脱敏后 `out.normalized_out==true` 且下游响应含 `x-veil-normalized: json-whitespace`
  - Verify: `cargo test -p veil` 中既有点位 `rewrite_pure_redaction_byte_replace_keeps_normalized_false_e13`（`src/handler/llm/rewrite.rs:336`）已按 design D3 更新或删除，非 JSON 字节替换仍不置位
  - Verify: `grep -n "7.7" README.md` 段落不再含「纯脱敏子串替换（字节级，未重序列化）」旧断言（apply 后）

## 3. `M1` content-encoding 解码配对

- [x] 3.1 `src/handler/llm/mod.rs:34-46 forward_headers`：剥离或重写下游 `accept-encoding` 为网关支持集（`gzip, br, deflate`，或 design D4 决策下含 `zstd`）；`src/service/llm_gateway/hop.rs:62-70` 剥头与 `src/state.rs:145-148` reqwest 解码保持配对
  - Verify: `cargo test -p veil forward_headers_strips_accept_encoding` 通过；返回 `HeaderMap` 无 `accept-encoding` 或等于支持集
  - Verify: `grep -n "ACCEPT_ENCODING\|accept-encoding" src/handler/llm/mod.rs` 命中剥离/重写逻辑；`cargo test -p veil hop` 全绿
- [x] 3.2 zstd 行为测试与决策落地：上游返回 `content-encoding: zstd` 时不得出现「无编码头 + 压缩字节」；若启用 zstd 则 `Cargo.toml:12` reqwest 增加 `zstd` feature 并纳入支持集
  - Verify: `cargo test -p veil hop_decode_pairing_zstd` 通过；zstd 场景断言「解压剥头」或「保留编码头」二者之一
  - Verify: 启用时 `grep -n "zstd" Cargo.toml` 命中 reqwest feature；未启用时 design D4 记录「剥离 accept-encoding 单方案」且 `grep -n "accept-encoding" README.md` 命中声明
- [x] 3.3 补多值/别名边界：`accept-encoding: gzip, br`、`content-encoding: x-gzip`、多值 content-encoding
  - Verify: `cargo test -p veil hop_encoding_multivalue_alias` 通过；各场景行为符合 spec「内容编码解码配对」三 Scenario
  - Verify: `cargo test -p veil gzip_stripped_as_identity_a5`（`src/service/llm_gateway/hop.rs:113`）不回归

## 4. `M2` Responses 失败帧诊断保真

- [x] 4.1 `src/handler/llm/pump/event.rs:137-145`：`responses_error_message` 扩展为提取 error 对象（`code`/`type`/`param`/`message` 存在即保留）；`src/handler/llm/pump/spawn.rs:226-252` 合成帧的 `response.error` 输出该对象
  - Verify: `cargo test -p veil responses_error_preserves_code_param` 通过；`response.failed` 的 `response.error.code=="rate_limit_exceeded"`、`param=="model"`
  - Verify: `cargo test -p veil responses_error_single_failed` 不回归；合成帧无 `output_index` 注入、无重复终端
- [x] 4.2 缺失 `message`/非对象 error 的回退与 README §7.2 lossy 声明
  - Verify: `cargo test -p veil responses_error_no_message_fallback` 通过；回退既有 `{"id","status"}` 形态、无 panic、无空体
  - Verify: `grep -n "lossy\|诊断字段" README.md`（apply 后）命中 §7.2 声明；无未声明丢弃字段

## 5. `M3` opaque 字段原字节透传

- [x] 5.1 `src/handler/llm/pump/spawn.rs`：`is_anthropic_opaque_event`（`event.rs:235-250`）命中的 Anthropic thinking/signature/redacted 帧（含真实 wire `content_block_start` 的 `content_block.type` 载体）跳过 `redact_response_new_pii_with_skip` 与 `json_aware_line`，以字节级还原后帧透传（token 精确还原可执行，不触发全帧重排）
  - Verify: `cargo test -p veil opaque_frames_bypass_scan` 通过；`signature_delta`/`redacted_thinking` 输出字节 == 上游字节
  - Verify: `grep -n "is_anthropic_opaque_event" src/handler/llm/pump/spawn.rs` 命中短路分支（位于响应扫描/`json_aware_line` 调用之前 `continue`）
- [x] 5.2 补 `M3` 四场景测试：`signature_delta` 字节不变、`redacted_thinking` 密文不掩码、`thinking_delta` 内 token 精确还原不重排、真实 wire `content_block_start`（opaque 载体在 `content_block.type`）逐字节透传不掩码（`real_wire_redacted_content_block_start_not_masked`）
  - Verify: `cargo test -p veil redacted_thinking_pii_shaped_cipher_not_masked` 通过；无 `__PII_` 注入、无字节改写
  - Verify: `cargo test -p veil thinking_delta_token_restore_no_reorder` 通过；token 还原为明文且帧其余字节与上游一致
  - Verify: `cargo test -p veil real_wire_redacted_content_block_start_not_masked` 通过；`content_block_start` 的 `content_block.type` 为 `redacted_thinking`/`thinking` 时逐字节透传、无 `__PII_`

## 6. `L1` 残缺剥离边界收敛

- [x] 6.1 `src/service/credential_vault.rs:36-42 cred_partial_re` 与 `src/service/pii/chunk.rs:111-119 pii_partial_re`：收窄到确证占位符残缺形态（`__VG_` + 可选 `CRED` + 可选 `_数字`；`__PI` + 可选 `I` + 可选 `_数字_hex` + 边界），后续为合法单词字符的正文不剥离
  - Verify: `cargo test -p veil strip_partials_legal_text_untouched` 通过；`__VG_CREDENTIALS`/`__PIXEL`/`__PII_DATA` 输出逐字节不变
  - Verify: `cargo test -p veil partial_prefix_stripped_without_leak`（`src/service/credential_vault.rs:216`）不回归；`__VG_CRED_000`/`__PII_3_ab` 仍被剥离
- [x] 6.2 补 design D7 差分用例表测试（合法正文 vs 真残缺 vs 前缀本身）
  - Verify: `cargo test -p veil strip_partials_differential` 通过；用例表逐条断言与 design D7 一致
  - Verify: `cargo test -p veil scope_tests` 全绿（`strip_partial_and_token_fn_semantics` 等既有出口用例不回归）

## 7. `GO` Go 网关侧兼容收敛

- [x] 7.1 复核并锁定**既有** `body.auth.*` 回退：`src/service/credential/auth.rs:22-45`（`effective_secret`/`effective_binary_hash`）已实现头缺失时回退读取 `body.auth.get_binary_secret`/`get_binary_hash`，`src/service/credential/mod.rs:84-90` 明示为 Go 互操作别名；本任务仅补回归测试与锁定，**不新增实现**（如 apply 时发现缺失则按 spec 补齐）；三因子语义、`ct_eq` 时序比较与 403 行为不变
  - Verify: `cargo test -p veil three_factor_body_auth_fallback` 通过；`body.auth.get_binary_secret`/`get_binary_hash` 被采纳（`auth.rs:22-45`），仅缺 `caller_hash`/`caller_path` 时返回 403「body.auth.caller_hash/caller_path 必填」
  - Verify: `grep -n "get_binary_hash\|get_binary_secret" src/service/credential/auth.rs` 命中 `effective_secret`/`effective_binary_hash` 回退；`cargo test -p veil three_factors` 不回归
- [x] 7.2 `src/handler/mod.rs:16 health_handler` 与 `src/handler/credential.rs:223 register_caller_handler`：响应在不删既有字段前提下提供 Go 可解析加性超集（health 含 `status/unlocked` 等；register 含 `name/script_path/script_hash/entries/allow_mode` 兼容路径）
  - Verify: `cargo test -p veil health_superset_fields` 通过；响应同时含 `ok`/`sqlite_ok`/`status`/`unlocked`
  - Verify: `cargo test -p veil register_caller_go_shape_superset` 通过；Go 形态字段可解析且既有字段不删、重名 409 语义不变
- [x] 7.3 error 形态决策与 SSE 透明固化：网关保持 `{"error":{"code","message"}}` 对象契约，Go 解析容忍交叉引用 `veil-hardening` 5.2（不改该 change 文件）；SSE 终止帧对 Go 透明写入 spec
  - Verify: `grep -rn "veil-hardening" openspec/changes/veil-gateway-fidelity-fix/` 命中 5.2 交叉引用；`git diff --name-only` 不含 `openspec/changes/veil-hardening/`（apply 阶段）
  - Verify: `cargo test -p veil go_sse_terminal_transparent`（或复用既有阻断流 e2e）通过；Chat `[DONE]` 恰一、Anthropic `message_stop` 恰一、Responses 终端恰一
  - Verify: `grep -n "5.2\|8.3" README.md`（apply 后）命中 Go 承接边界声明

## 8. 文档同步与门禁

- [x] 8.1 README 三节同步（记录项）：§7.7 按 design D3 修订（删除「纯脱敏字节级替换」不成立前提）、§7.2 补 M1 非支持编码豁免与 M2 lossy 边界、§7.1 补解码配对口径；若 `veil-docs-contract-resync` 已先落地对应段落，则降级为只读复核、不重复编辑同一行（先落地者写实，后到者复核）
  - Verify: `grep -n "7.7" README.md` 无「纯脱敏子串替换（字节级，未重序列化）」旧断言且与 spec「请求归一化声明诚实」Scenario 同字
  - Verify: `grep -n "7.2" README.md` 含 M2 诊断字段/lossy 声明；`grep -n "7.1" README.md` 含 `accept-encoding`/解码配对口径
- [x] 8.2 门禁：全量质量检查
  - Verify: `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 三条命令退出码 0
  - Verify: `openspec validate veil-gateway-fidelity-fix --strict` 输出 valid（0 failures）
- [x] 8.3 端到端回归与改动面核对
  - Verify: `scripts/api_conformance.py` 三协议流式/非流式/阻断用例全通过
  - Verify: `git diff --name-only` 限于 proposal「Impact」清单（生产代码 + 单测 + README + Cargo.toml），无 Go 源码与既有 change 文件改动
