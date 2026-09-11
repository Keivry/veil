## 1. F1 凭据审批 202 契约声明与兼容

- [x] 1.1 README §6 增列 F1 BREAKING：默认 `202` 异步（Python 为同步阻塞 `300`s 同请求返回凭据），并声明 `CREDENTIAL_BLOCK_WAIT=1` 恢复旧阻塞；六项扩为七项，验证：`grep` §6.7 命中 `202`/`CREDENTIAL_BLOCK_WAIT`/Python 对照三要素，且与 design.md D1 同字
- [x] 1.2 README §1/§5 锁定 `202 + E_PENDING` 轮询语义（已建单、客户端轮询重试；阻塞模式无需轮询），验证：两处文案与 `runtime-parity-limits` spec「凭据审批默认异步 202 契约」逐条比对零漂移
- [x] 1.3 补默认 202 e2e（HTTP 层）：未决审批下 `POST /credential` 立即 `202` + `E_PENDING`、同请求不挂起、pending 建单可查，验证：新增 e2e 通过且用例墙钟 < 秒级
- [x] 1.4 补 `CREDENTIAL_BLOCK_WAIT=1` e2e：批准后同请求返回 `__VG_CRED_` 凭据；超时（`tokio::time::pause/advance` 注入时钟或缩短测试超时，不真等 `300`s）按拒绝/超时口径返回，验证：批准与超时两 e2e 通过、无悬挂任务残留
- [x] 1.5 核实并记录 Go `get` 对 `202` 的处理（`get/internal/proxy.go::FetchCredential` 的解析/错误路径），结论写入 README §5/§6 并注明与 `veil-hardening` 5.2 未勾项的联动；不修改 `veil-hardening` 文件，验证：结论句可 `grep`、含 Go 侧是否可直接轮询的明确判定与后续承接建议

> 硬性约束：1.1/1.5 未完成则 F1 不算闭环（保持 `202` 必须同时交付 BREAKING 声明 + Go 兼容说明 + e2e，不留未声明漂移）。

## 2. F2 非流响应体上限

- [x] 2.1（F2）`src/config/env_parse.rs` 新增 `NONSTREAM_MAX_BYTES`（默认 `8388608`；显式非整数或 `<1` 拒启动，与 `HTTP_TIMEOUT_SECS` 同 fail-closed 口径）并入 `Config`，验证：配置单测三例（缺省 `8388608`、覆盖生效、非法拒启动）通过
- [x] 2.2 `src/handler/llm/nonstream.rs` 对话非流缓冲点判定 `len > cap` → `502`，JSON 体 `{"error":{"message":"response too large","type":"response_too_large"}}` 且 `Content-Type: application/json`（对齐 Python `_llm.py:2942`），验证：超限单测命中且响应形状与 Python 同字
- [x] 2.3 边界与旁路测试：`len == cap` 放行（严格大于语义）、`Protocol::NonDialog` 透传不受限、非对话错误体行为不变，验证：三例单测通过
- [x] 2.4 README §4 阈值表新增行：非流对话响应上限 `8MB`、超限 `502`、入口 enforcement，验证：与 spec「非流对话响应体上限声明」取值/行为逐项比对零漂移
- [x] 2.5 spec 显式区分检查点：`NONSTREAM_MAX_BYTES`（非流响应体、入口 enforcement）vs `AUDIT_SUBLIMIT_CEILING_BYTES`（审计子限锚点、非入口 enforcement），验证：spec 文本含两检查点对照场景、`grep AUDIT_SUBLIMIT_CEILING_BYTES` 可查
- [x] 2.6 精化（Oracle 残留观察②）：超限仅对非错误状态（`status < 400`）生效；`status>=400` 超限体不改写 502（非 JSON 透传、JSON 走完整链），spec/README 同步限定
  - 验证：`cargo test -p veil f2_oversize_error_body_passes_through_not_rewritten_to_502` 通过；spec 含「错误状态超限不改写」场景、README §1 行含「仅非错误」限定

## 3. F3 PII 字典文件别名

- [x] 3.1（F3）`src/config/env_parse.rs` 字典槽补 `PII_DICT_FILE` 别名（保持与 Python 三个历史名的相对优先级：`PII_DICT_FILE` > `PII_SENSITIVE_DICT_FILE` > `PII_SENSITIVE_NAMES_FILE`；Rust 主名 `PII_CUSTOM_DICT_FILE` 仍列首），验证：配置单测断言别名路径被采用
- [x] 3.2 「别名与主名等价加载」测试：同一字典内容分别经主名与 `PII_DICT_FILE` 启动，字典命中与脱敏结果一致，验证：等价性单测通过
- [x] 3.3 README §1 环境表字典行补 `PII_DICT_FILE` 归属，且 §7.4 legacy 规则不得落入「二进制不读取」，验证：`grep` 命中归属行、legacy 表内无该名

## 4. F5 PII 序号分配有界

- [x] 4.1（F5）`src/service/pii/scope.rs` 以游标 + 已用集替换 `next_hole(used_seqs(&inner))` 每次全量重建，验证：单测断言 K 次注册不做每次全量重建（以分配计数或等价可观测指标）
- [x] 4.2 空洞回收：淘汰/释放后的序号被复用且不与在用序号冲突，验证：空洞回收复用单测通过
- [x] 4.3 界内不重复：单请求注册至 `PII_MAX_ENTRIES=1000` 无重复、无越界，验证：上限边界单测通过

## 5. T1 阻塞模式 e2e

- [x] 5.1（T1）批准路径 e2e（`CREDENTIAL_BLOCK_WAIT=1`，HTTP 层）：请求挂起期间由审批侧批准，同请求返回凭据（无 `202`），验证：e2e 通过且与 Python `_credential.py:433,455` 语义一致
- [x] 5.2 超时路径 e2e：注入时钟/缩短超时，等待超时后按拒绝/超时口径返回且不悬挂，验证：响应码与 spec 场景一致、无遗留后台任务
- [x] 5.3 客户端早断连幂等 e2e：请求 future 提前 drop 后 pending 建单可清理、批准不 panic、无资源泄漏（补齐 `src/service/audit/hold.rs:737-754` 仅 keepalive 存活断言的凭据侧对应覆盖），验证：e2e 通过且断连后重复触发幂等

## 6. T2 Responses CR-only 回放

- [x] 6.1（T2）`tests/fixtures/` 新增 Responses CR-only fixture（一行 CR 终止、含 `response.completed`），验证：fixture 入库且逐字节无 LF
- [x] 6.2 `tests/sentinel_sdk_replay.rs` 新增 Responses CR-only 回放断言，对标现有 06 Anthropic CR/LF 双路径（`tests/sentinel_sdk_replay.rs:255`），验证：CR-only 与 LF 输出一致、新增测试通过

## 7. T3 refusal 集成 + ReDoS 上界

- [x] 7.1（T3）refusal 集成级「独立还原」测试：Chat 流式 refusal 帧经网关后还原为明文（非原样透传 / 非占位），验证：集成测试通过（当前仅 `src/service/sse.rs:331` / `src/handler/llm/pump/event.rs` 单元覆盖）
- [x] 7.2 ReDoS 墙钟绝对上界测试：对抗输入（如 `^(a+)+$`）扫描在明确绝对上界常量内返回，不依赖仅预算断言与连续三次禁用记账，验证：挂起上界测试通过（现有 `malicious_pattern_fast_reject_and_disable_after_three_timeouts` 之外新增）

## 8. 收口与一致性

- [x] 8.1 README-契约一致性校验（§1/§4/§5/§6 vs `runtime-parity-limits` spec 场景逐项），验证：逐项比对零漂移，无未声明配置忽略（新变量均有 README 表与 legacy 规则归属）
- [x] 8.2 遗留项登记：Go `202` 结论 open item owner、T1 时钟注入方式选择（`tokio::time` 暂停 vs 测试缩短超时）记录到 design.md Open Questions，验证：`openspec validate veil-parity-gap-closeout --strict` 通过且 open item 可追溯
