## Why

六维深度审查（2026-09-11，LLM 网关传输保真面：JSON 字节保真 / 流式还原 / 逐跳解码 / opaque 字段 / 残缺清理 / Go 兼容）确认 7 项真实缺陷与 1 项文档记录缺口，均违反既有契约或 README 声明：

- **H2（High，真实缺陷）流式还原破帧无回退**：`CredentialVault::register`（`src/service/credential_vault.rs:82-109`）仅拒绝 token 形态，不拒绝含 `"`/`\` 的明文；`restore`（`:151`）经 `replace_all_by_map`（`:180-198`）做**未转义**明文替换；响应流式路径 `src/handler/llm/pump/spawn/event_loop.rs:576-599`（`restore_response_with_spans` → `redact_response_new_pii_with_skip` → `json_aware_line`）**无 JSON 校验/回退**，明文含特殊字符即破坏帧结构；非流路径 `src/handler/llm/nonstream.rs:235-245` 有 `jloads` 校验 + `retry_stripped` + 回退上游原文，流式无对齐。
- **H1（High，真实缺陷）JSON 重序列化与 normalized 合同不符**：`Cargo.toml:15` `serde_json = "1"` 未启用 `preserve_order`（Map = BTreeMap，键名字典序）；响应侧 `src/service/redaction/scope.rs:176-191` 的 `redact_response_new_pii` **无条件** `json_walk::process_text`（`loads→walk→dumps`，`src/service/json_walk.rs:137-163`），`:213-215` spans 为空时同样委托它；`src/service/sse/parser.rs:317-331` 的 `json_aware_line` 再次重序列化；导致键序重排、数字表示改写（实测 `1e3→1000.0`）、空白改变，偏离 Python 外科式字段替换基线。请求侧 `src/handler/llm/rewrite.rs:65-66`：`redact_request` 发生替换即经 json_walk 重序列化，却仍 `normalized_out=false` 不置 `x-veil-normalized`，与 README §7.7「纯脱敏子串替换（字节级，未重序列化）」矛盾。
- **M1（Medium，真实缺陷）content-encoding 剥头不解压**：`src/service/llm_gateway/hop.rs:62-70` 在 `DECODE_ENABLED=true` 时无条件剥 `content-encoding`/`content-length`；`src/state.rs:145-148` 仅启用 gzip/brotli/deflate（`Cargo.toml:12` 无 zstd feature）；`src/handler/llm/mod.rs:34-46` 的 `forward_headers` **未剥离下游 `accept-encoding`**。上游用 zstd/多值/`x-gzip` 别名时 reqwest 不解压却被剥头 → 下游拿损坏字节。
- **M2（Medium，有意设计但 lossy）Responses `error→response.failed` 丢诊断字段**：`src/handler/llm/pump/spawn/event_loop.rs:219-271` 合成 `response.failed` 仅取 `error.message`（`pump/event.rs:137-145` `responses_error_message`），上游 error 的 `code`/`param`/`type` 丢失。
- **M3（Medium，真实缺陷）opaque 字段被扫描/重排**：Anthropic `signature_delta`/`redacted_thinking`/`thinking` 经 `src/handler/llm/pump/event.rs:214-231`（minor 判定）后仍走 `scope.rs:176-191` 响应侧扫描与 `json_aware_line` 重序列化，可能误掩码/改字节，破坏签名完整性。
- **L1（Low，真实缺陷）`strip_partials` 误删风险**：`src/service/credential_vault.rs:45` `strip_cred_partials`（正则 `:36-42`）与 `src/service/pii/chunk.rs:111-124` `strip_pii_partials` 可能删除正文中合法 `__VG_C...`/`__PI...` 序列（缺差分测试锁定边界）。
- **GO（闭环，Medium）Go 端到端 5.1–5.3 未闭环**（由 change `veil-hardening` 承接）：存量 Go `get` 不发三因子头恒 403、error/health/register 形态不兼容、Go 无 SSE 消费代码（详见 README §5/§8.3 与 `veil-hardening/tasks.md` 第 5 节验证记录）。
- **记录项（文档同步）**：H1 与 README §7.7、M2 与 §7.2 的文档表述已与实现漂移，须随本 change 修复同批更新（本 change 只规划，不改 README）。

真相源为 `src/service/credential_vault.rs`、`src/service/redaction/scope.rs`、`src/service/json_walk.rs`、`src/service/sse/parser.rs`、`src/handler/llm/{rewrite,nonstream,mod}.rs`、`src/handler/llm/pump/{spawn,event}.rs`、`src/service/llm_gateway/hop.rs`、`src/state.rs`。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/` 与 README。

引用规范：JSON（RFC 8259）字符串转义规则；HTTP 内容编码（RFC 9110 §8.4 `Content-Encoding` / `Accept-Encoding`）；Anthropic Messages streaming（`signature_delta`/`redacted_thinking` 签名完整性）；OpenAI Responses streaming（`response.failed.response.error` 对象）；README §7.1/§7.2/§7.7 与 `veil-hardening` 5.x 记录。

## What Changes

- **`H2` 流式还原破帧防护**：JSON 帧写回按 JSON 字符串转义规则转义还原明文（`"`→`\"`、`\`→`\\`、控制字符转义），并对每帧还原结果做 `jloads` 校验；校验失败回退**还原前占位符帧**（fail-closed，不破帧）+ warn + `record_restore_fallback`；与非流 `retry_stripped` 回退语义对齐（`nonstream.rs:235-245`）。
- **`H1` 响应侧字节保真**：`redact_response_new_pii` 增加「零替换即原文返回」短路（对齐请求侧 FIX-5）；`Cargo.toml` 启用 `serde_json` `preserve_order`；`json_aware_line` 去重复序列化（仅校验、不再二次 `dumps`）；无法消除的数字表示/空白偏离在 README §7.1/§7.7 声明。
- **`H1` 请求侧声明诚实**：`Scope::redact_request` 报告「是否经 `loads→walk→dumps` 重序列化」，`rewrite.rs` 据此正确置位 `normalized_out` / `x-veil-normalized`；README §7.7 同批修订（记录项；备选方案为 span 级字节替换，见 design D3）。
- **`M1` content-encoding 解码配对**：`forward_headers` 剥离/重写下游 `accept-encoding` 为网关实际支持集（或按 design D4 决策显式启用 `zstd` feature），保证「reqwest 解码成功才剥 `content-encoding`/`content-length`」；补 zstd/多值/`x-gzip` 别名回归。
- **`M2` 失败帧诊断保真**：合成 `response.failed` 的 `response.error` 保留上游 `code`/`type`/`param`/`message`；无法保留的字段在 README §7.2 显式声明 lossy 范围（记录项）。
- **`M3` opaque 字段透传**：`signature_delta`/`redacted_thinking`/`thinking` 等 minor/opaque 帧短路响应侧 PII 扫描与 `json_aware_line` 重序列化，字节级透传（已注册 token 仍可经字节级精确还原，不触发全帧重排）。
- **`L1` 残缺剥离边界收敛**：收窄 `cred_partial_re`/`pii_partial_re` 到确证占位符残缺形态；补 `__VG_CREDENTIALS`/`__PIXEL` 等合法正文差分测试。
- **`GO` 网关侧兼容收敛**：锁定**既有** `body.auth.get_binary_hash`/`get_binary_secret` 回退（`auth.rs:22-45` 已实现，`credential/mod.rs:84-90` 标注 Go 别名；本 change 补回归测试与文档而非新增实现）；`/health` 与 `/register-caller` 补加性超集字段；error 保持对象契约、Go 解析容忍交由 `veil-hardening` 5.2 承接（交叉引用，不改该 change 文件）；SSE 终止对 Go 透明由 spec 固化（已成立项）。
- **文档同步（记录项，apply 阶段与行为同批）**：README §7.7（H1）、§7.2（M1 编码豁免/M2 lossy 声明）、§7.1（M1 解码配对口径）。

## Capabilities

### New Capabilities

- `gateway-fidelity`：LLM 网关传输保真契约——流式还原破帧防护（转义+回退）、响应/请求 JSON 字节保真与归一化声明、content-encoding 解码配对、Responses 失败帧诊断保真、opaque 字段原字节透传、残缺剥离边界、Go 网关侧兼容。

### Modified Capabilities

- 无。`openspec/specs/` 既有契约的行为不动；本 change 新增 capability，README §7.1/§7.2/§7.7 随行为同批更新。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `H2` | High（真实缺陷） | 流式还原写回 JSON 转义 + 逐帧 `jloads` 校验；失败回退占位符帧 + `record_restore_fallback`；与非流 `retry_stripped` 对齐 | 1.1、1.2、1.3 |
| `H1` | High（真实缺陷） | 响应侧零替换短路 + `preserve_order` + `json_aware_line` 去重；请求侧重序列化即置位 `x-veil-normalized`；README §7.7 同步 | 2.1、2.2、2.3、2.4 |
| `M1` | Medium（真实缺陷） | `accept-encoding` 剥离/重写（或显式 zstd feature）；解码与剥头配对；zstd/多值/别名回归 | 3.1、3.2、3.3 |
| `M2` | Medium（有意设计 lossy） | 合成 `response.failed` 保留 `response.error.{code,type,param,message}`；README §7.2 lossy 声明 | 4.1、4.2 |
| `M3` | Medium（真实缺陷） | opaque/minor 帧短路响应侧扫描与重序列化，字节级透传/还原 | 5.1、5.2 |
| `L1` | Low（真实缺陷） | 收敛 `cred_partial_re`/`pii_partial_re` 边界；合法正文差分测试 | 6.1、6.2 |
| `GO` | Medium（闭环） | 锁定既有 `body.auth.*` 回退（`auth.rs:22-45`，非新增）；health/register 加性超集；error 形态决策与 `veil-hardening` 5.x 交叉引用；SSE 终止透明固化 | 7.1、7.2、7.3 |
| `DOC` | 记录（H1 §7.7 / M2 §7.2 / M1 §7.1 文档同步） | README 三节与实现同批修订；design D9 记录口径 | 8.1、8.2、8.3 |

## Non-Goals（显式）

- **不修改任何既有文件**：本 change 只交付规划 artifacts，不改 `src/`、README、`openspec/specs/` 与既有 `openspec/changes/`（含 `veil-hardening`）；不提交 commit。
- **不重复已收口项**：三协议终端语义（N1/P4）、空流终止（P2）、非 JSON 错误体透传（N2）由 change `veil-llm-protocol-hardening` 承接，本 change 不触碰其行为。
- **不改审计 verdict、脱敏 recognizer 集合、采样策略、容量分表与 usage 口径**。
- **不修改 Go 源码**：Go 侧 `FetchCredential` 头/解析修复由 `veil-hardening` 5.1–5.3 承接；本 change 仅规划网关侧兼容与文档声明（交叉引用，不修改该 change 文件）。
- **不做全量 span 级脱敏重写**：响应侧采用「零替换短路 + `preserve_order` + 去重复序列化」方案；彻底字节级外科替换列为后续可选（design D2 备选 B）。
- **不恢复回环免 token / 调试落盘 / 明文落盘等既有 Non-Goal**；不新增除 `serde_json preserve_order`（与 design D4 决策下的 `reqwest zstd` feature）外的依赖。
- **与 `veil-runtime-robustness` 的编辑面重叠由串行合入约定收敛**：两 change 均触及 `src/service/redaction/scope.rs`（`redact_response_new_pii*` / `restore_response*`）与 `src/handler/llm/pump/spawn.rs`（还原/脱敏调用段）；apply 阶段按「行为保真（本 change）先、复杂度重构（runtime B2/B3）后」串行合入，或同批由同一实现负责；禁止双方各自重写同一函数体。

## Impact

- **新增文件**：`openspec/changes/veil-gateway-fidelity-fix/` 下 `proposal.md`、`design.md`、`specs/gateway-fidelity/spec.md`、`tasks.md`、`.openspec.yaml`。
- **apply 阶段改动面**：`src/service/credential_vault.rs`、`src/service/redaction/scope.rs`、`src/service/json_walk.rs`、`src/service/sse/parser.rs`、`src/handler/llm/rewrite.rs`、`src/handler/llm/nonstream.rs`（对齐参照）、`src/handler/llm/pump/spawn.rs`、`src/handler/llm/pump/event.rs`、`src/handler/llm/mod.rs`、`src/service/llm_gateway/hop.rs`、`src/handler/credential.rs`、`src/service/credential/auth.rs`、`src/handler/mod.rs`、`src/service/credential/mod.rs`、`src/state.rs`、`Cargo.toml`（`preserve_order`，可选 `zstd`）、对应单测与 `README.md` §7.1/§7.2/§7.7。
- **影响系统**：响应/请求 JSON 字节保真、流式还原安全（不破帧不泄漏）、HTTP 内容编码正确性、Anthropic opaque 字段完整性、Go 互操作闭环。
- **依赖**：`serde_json` 启用 `preserve_order`（引入 indexmap 传递依赖）；`reqwest` 可选启用 `zstd` feature（design D4 决策）；无其他新依赖。
