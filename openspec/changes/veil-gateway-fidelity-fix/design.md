## Context

六维深度审查（2026-09-11）在 LLM 网关传输保真面确认 7 项真实缺陷与 1 项文档记录缺口（见 proposal Why 与覆盖表）。现状真相源：

- 流式还原链路 `spawn.rs:450-460` 无 JSON 校验/回退；明文替换为未转义字节（`credential_vault.rs:180-198 replace_all_by_map`），明文含 `"`/`\` 即破帧（`H2`）。非流已有 `nonstream.rs:235-245` 的 `jloads` 校验 + `retry_stripped` + 回退。
- 响应侧 `scope.rs:176-191 redact_response_new_pii` 无条件 `json_walk::process_text`（`json_walk.rs:137-163` loads→walk→dumps），`scope.rs:213-215` skip 为空时同样走它；`sse/parser.rs:317-331 json_aware_line` 再次 `process_text`；`Cargo.toml:15` 未启用 `preserve_order`（BTreeMap 字典序）→ 键序/数字/空白改变（`H1` 响应侧）。请求侧 `rewrite.rs:65-66` 重序列化却不置 `normalized_out`，README §7.7 声称「纯脱敏字节级替换不置位」（`H1` 请求侧）。
- `hop.rs:62-70` 无条件剥 `content-encoding`/`content-length`；`state.rs:145-148` 仅 gzip/brotli/deflate；`handler/llm/mod.rs:34-46 forward_headers` 透传客户端 `accept-encoding` → zstd 等编码被剥头不解压（`M1`）。
- `spawn.rs:226-252` 合成 `response.failed` 仅取 message（`event.rs:137-145`），丢 `code/param/type`（`M2`）。
- `event.rs:214-231 is_minor_event` 仅跳过 hold/审计，`spawn.rs:450-460` 仍对 thinking/signature/redacted 帧做扫描与重序列化（`M3`）。
- `credential_vault.rs:36-47` 与 `pii/chunk.rs:108-124` 的残缺正则可能误删合法 `__VG_C...`/`__PI...` 正文（`L1`）。
- Go 互操作缺口与既有结论见 README §5/§8.3 与 `veil-hardening/tasks.md` 第 5 节验证记录（`GO`）。

约束：本 change 只写规划 artifacts，不改 `src/`、README 与任何既有 openspec 文件；`veil-hardening` 5.x 仅交叉引用不修改；不提交 commit。

## Goals / Non-Goals

**Goals：**

- 给出 `H2`/`H1`/`M1`/`M2`/`M3`/`L1`/`GO` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「流式还原不破帧」「JSON 帧零替换逐字节透传」「归一化声明诚实」「解码与剥头配对」「失败帧诊断保真」「opaque 字段原字节」「残缺剥离不误删」「Go 网关侧兼容」收敛为 spec 契约；README §7.1/§7.2/§7.7 与行为同批同步（任务 8.x）。
- 锁定 H1/H2 的决策与备选，防止 apply 阶段选型漂移。

**Non-Goals：**

- 不做全量 span 级字节替换重构（D2/D3 备选 A，列为后续可选 change）。
- 不改三协议终端/空流/非 JSON 错误体语义（已由 `veil-llm-protocol-hardening` 收口）。
- 不改审计 verdict、脱敏 recognizer、容量分表、usage 口径。
- 不修改 Go 源码（Go 侧修复归 `veil-hardening` 5.1–5.3，交叉引用不改文件）。
- 不引入除 `serde_json preserve_order`（与 D4 决策下的 `reqwest zstd` feature）外的依赖。

## Decisions

### D1：`H2` 流式还原采用「JSON 字符串转义 + 逐帧校验回退」双层防护

**决策**：

1. **首选转义**：仅对可解析 JSON 的流式帧，在 `Scope` 还原入口提供 JSON 上下文还原变体（如 `restore_response_with_spans_json`，内部对写回明文按 RFC 8259 转义 `"`、`\`、控制字符），`spawn.rs:450-460` 的 JSON 分支使用该变体；plain 分支保持字节级原样还原。
2. **兜底回退**：对还原后帧做 `jloads` 校验（复用 `json_aware_line` 的解析路径）；失败时下游发送**还原前占位符帧**（`ev.data`，token 保留、不破帧），并 `tracing::warn` + `metrics.record_restore_fallback()`，对齐非流 `retry_stripped` 回退语义（`nonstream.rs:235-245`）。

**理由**：`replace_all_by_map` 是通用字节替换，无法感知 JSON 字符串上下文；明文含引号/反斜杠/控制字符是合法凭据形态，不能拒绝注册（备选 A）。转义保证「语义正确 + 帧合法」；回退保证任何病态输入下也不破帧（fail-closed，占位符保留不泄漏）。两层叠加覆盖「可转义」与「转义后仍破损」两类场景。

**备选**：

- A：`CredentialVault::register` 拒绝含 `"`/`\` 的明文——合法凭据被拒、改变注册语义，不采用。
- B：仅校验回退不转义——含特殊字符的凭据永远无法在流式还原（功能退化），仅作兜底不作首选；两者叠加为决策。
- C：对整帧做 base64/JSON5 包装——改协议形态，不采用。

### D2：`H1` 响应侧采用「零替换短路 + `preserve_order` + `json_aware_line` 去重」

**决策**：

1. `redact_response_new_pii` / `redact_response_new_pii_with_skip` 增加替换追踪（对齐 `redact_request` 的 FIX-5 `replaced` Cell）：全程零替换时直接返回原文（跳过 `jdumps`），仅命中叶才走重序列化。
2. `Cargo.toml:15` 改为 `serde_json = { version = "1", features = ["preserve_order"] }`，重序列化路径对象键保持原序。
3. `json_aware_line`（`sse/parser.rs:317-331`）去掉第二次 `process_text`：JSON 合法即返回输入字节（仅校验），Leaf 处理由调用方（scope 层）先行完成；`classify_residue` 语义保持不变。
4. 仍存在的数字表示/空白偏离（serde_json 行为，`preserve_order` 不解决，如 `1e3` → `1000.0`）在 README §7.1/§7.7 显式声明为已知偏离；零替换路径不产生该偏离。

**理由**：Python 基线是外科式字段替换；现状对 100% 透传帧也重排，键序/数字/空白全变。短路以最小风险覆盖绝大多数帧；`preserve_order` 消除键序偏离；去重消除二次序列化。数字表示无法零成本消除，必须诚实声明（不得沉默）。

**备选**：

- A：全面 span 级字节替换（在原文上按检测 span 替换，未命中字节永不动）——最保真，但 detector 需暴露 span、嵌套 JSON 字符串转义上下文复杂、改动面大；列为后续可选 change，本 change 不采用。
- B：仅启用 `preserve_order` 不做短路——未命中帧仍被空白/数字重写，不采用。
- C：改用其他 JSON 库（如 serde_json 的 RawValue 逐叶替换）——与 A 同量级重构，不采用。

### D3：`H1` 请求侧采用「重序列化即置位」的诚实声明

**决策**：`Scope::redact_request` 向调用方报告「是否经 `loads→walk→dumps` 重序列化」（JSON 合法且走 `process_text` 产出即 true；非 JSON 纯文本字节替换与原文透传为 false）；`rewrite.rs:65-66` 据此置 `normalized_out`，handler 输出 `x-veil-normalized: json-whitespace`。README §7.7 修订为「请求体经 JSON 重序列化即置位；非 JSON 字节级替换与原文透传不置位」。

**理由**：README §7.7 现措辞建立在「纯脱敏为字节级替换」这一不成立的前提上；JSON 请求发生替换必然重序列化（键序/数字/空白可能变化），声明头必须与实际字节变换一致，否则下游无法判断兼容需求。

**备选**：

- A：span 级字节替换使请求侧也不重排，从而恢复「字节级不置位」——与 D2 备选 A 联动，改动面大，列为后续。
- B：仅改 README 不置位（承认重排但继续不声明）——继续撒谎，不采用。
- C：不区分，只要 `redacted_text != original_text` 就置位——非 JSON 字节替换也置位（过度声明）；采用「重序列化判定」更精确，若实现成本过高可按 C 降级并在 spec 场景同步（保守置位不违背诚实原则）。

### D4：`M1` 剥离/重写 `accept-encoding`，解码与剥头由 reqwest 配对

**决策**：`forward_headers`（`handler/llm/mod.rs:34-46`）删除下游 `accept-encoding`（或重写为网关支持集 `gzip, br, deflate`）；`state.rs:145-148` 维持 reqwest gzip/brotli/deflate 解码；`hop.rs:62-70` 剥头条件不变（此时上游只会回网关支持集且 reqwest 已解压）。若 apply 选 zstd 加强：`Cargo.toml:12` reqwest 增加 `zstd` feature 并纳入重写支持集。补 zstd/多值/`x-gzip` 行为测试。

**理由**：根因是客户端 `accept-encoding` 原样透传，上游可返回网关无法解码的编码，而剥头逻辑无法感知；剥离/重写后由 reqwest 自选并自动解压，剥头与解码天然配对，无需追踪编码能力。

**Apply 决策（2026-09-11 落地）**：未启用 `reqwest` `zstd` feature，采用「剥离 `accept-encoding` 单方案」——`forward_headers` 剥离下游头后由 reqwest 在缺席时注入 `gzip/deflate/br` 支持集；`hop::downstream_decode_enabled` 以「响应 `content-encoding` 仍存在 ⇒ tower-http 未解压」判定配对，上游若仍回不支持编码（zstd）/别名（`x-gzip`）/多值编码，则保留编码头与 `content-length` 供下游自解（不无声明剥头）。回归锚点：`hop_decode_pairing_zstd`、`hop_encoding_multivalue_alias`、`forward_headers_strips_accept_encoding`。

**备选**：

- A：启用 zstd feature 全解码——增加构建成本，且未来新编码仍会复现；作为可选加强而非唯一方案。
- B：按上游实际 `content-encoding` 决定是否剥头（能解才剥）——需显式探测 reqwest 解码结果、与其自动解码耦合，复杂度高，不采用。
- C：让客户端决定（保头透传压缩字节）——下游需自行解压且 SSE 解析器可能被压缩流破坏，不采用。

### D5：`M2` 合成 `response.failed` 保留 error 诊断字段

**决策**：`responses_error_message`（`event.rs:137-145`）扩展为提取 `response.error` 对象（`code`/`type`/`param`/`message` 存在即保留），`block_inject::responses_failed_frame` 输出该对象；缺失 `message` 时回退既有 `{"id","status"}` 形态。README §7.2 声明 lossy 边界（若官方响应结构对字段有限制，实测后按实际保留范围声明）。

**理由**：错误诊断（如 `code:"rate_limit_exceeded"`、`param`）是下游重试/告警依据；仅取 message 丢失结构化语义，且 README §7.2 未声明该 lossy，属未声明行为。

**备选**：

- A：维持 message-only + README 声明 lossy——`veil-hardening` 已暴露形态兼容放大下游成本，选择保真优先；若实现中严格 SDK 拒收扩展字段（预期不会），再回退声明。
- B：透传上游原始 error 帧不合成——违反「恒恰一终端」合成口径（错误事件可能不成合法终止），不采用。

### D6：`M3` opaque 帧短路响应侧扫描与重序列化

**决策**：`spawn.rs` 事件循环中，`is_minor_event` 命中 Anthropic thinking/signature/redacted（`event.rs:214-231`）或按类型判定为 opaque 的帧，跳过 `redact_response_new_pii_with_skip` 与 `json_aware_line`，以「字节级还原后帧」透传；已注册 token 的还原仍可经字节级精确替换，但不触发全帧重排与掩码。审计 hold/次要判定维持现状（`spawn.rs:307-308`）。

**理由**：`signature_delta` 与 `redacted_thinking` 承载签名/密文，任何字节改写都会导致下游校验失败；`thinking` 由上游生成（非用户输入），新 PII 扫描收益低、完整性代价高。

**备选**：

- A：仅跳过扫描、保留重序列化——仍改字节、破坏签名，不采用。
- B：完全不做还原也跳过——若流内含 token 会泄漏占位符或明文形态错误，不采用（保留字节级精确还原）。
- C：仅对 `signature_delta`/`redacted_thinking` 短路、`thinking` 维持现链路——`thinking` 同样受签名覆盖（后续 `signature_delta` 对其校验），一并短路；若实测 `thinking` 无签名约束可放宽并回改 spec。

### D7：`L1` 残缺剥离边界收敛 + 差分测试表

**决策**：收窄 `cred_partial_re`（`credential_vault.rs:36-42`）与 `pii_partial_re`（`pii/chunk.rs:111-119`）：仅当匹配确证为占位符前缀续段（`__VG_` + 可选 `CRED` + 可选 `_数字`；`__PI` + 可选 `I` + 可选 `_数字_hex`）且后随边界（空白/标点/串尾）时剥离；后续为合法单词字符（如 `__VG_CREDENTIALS`、`__PIXEL`、`__PII_DATA`）一律不剥离。补差分用例表（合法文本 vs 真残缺），保留完整凭据 token 在还原先行后的清理口径（既有 `partial_prefix_stripped_without_leak` 测试不退化）。

**理由**：残缺剥离是防半截占位符泄漏的必要保护（原仓 `_strip_partials` 语义），不能整体删除；风险在边界误伤，用收窄 + 差分测试锁定。

**备选**：

- A：整体移除残缺剥离——半截占位符泄漏，违反原仓语义，不采用。
- B：维持现状仅补测试——误删风险仍在且无修复，不采用。

### D8：`GO` 网关侧兼容收敛与 Go 承接边界

**决策**：

1. **三因子 `body.auth.*` 容忍（既有实现，验证锁定）**：`service/credential/auth.rs:22-45`（`effective_secret`/`effective_binary_hash`）已实现头缺失时回退读取 `body.auth.get_binary_hash` / `body.auth.get_binary_secret`，`service/credential/mod.rs:84-90` 明示 Go 互操作别名；本 change 仅补回归测试与文档锁定，不新增实现（若 apply 发现缺失则补齐），三因子语义、时序安全比较与 403 行为不变。
2. **`/health` 加性超集**：`health_handler`（`handler/mod.rs:16`）在保留 `ok/sqlite_ok/sqlite_error` 基础上提供 `status/unlocked`（README 示例）及 Go `get status` 所需加性字段；只增不删。
3. **`/register-caller` 加性兼容**：`register_caller_handler`（`handler/credential.rs:223`）响应提供 Go 形态（`name/script_path/script_hash/entries/allow_mode`）可解析的加性超集；既有字段与重名 409 语义不删不改。
4. **error 形态决策**：网关保持 `{"error":{"code","message"}}` 对象契约（README 示例与测试锁定）；Go `error string` 解析容忍由 `veil-hardening` 5.2 承接（交叉引用该 change 任务，不修改其文件）。
5. **SSE 终止透明**：已成立（README §5 结论）——本 change 以 spec 固化「流恒以终止帧闭合、Go 不重试不挂起」。

**理由**：网关可零风险提供的兼容（body.auth 回退、加性字段）直接落地；error 形态双向不兼容只能改一侧，改 Go 归 `veil-hardening` 5.x 既有边界（本仓不动 Go 源码）；SSE 透明已是事实，需契约锁定防漂移。

**备选**：

- A：网关把 `error` 改为字符串——破坏自家契约与 README 示例，不采用。
- B：网关加 `error_message` 顶层字段——Go struct 仍先按 `error` 对象反序列化失败，无实效，不采用。
- C：网关容忍 `body.auth.*` 但 health/register 不动——存量 Go `get status/list` 仍不可用，不采用。

### D9：记录项——README 文档同步范围

**决策**：apply 阶段与行为改动同批同步 README：§7.7（H1 请求归一化声明 + 响应字节保真/已知偏离）、§7.2（M1 非支持编码口径 + M2 lossy 边界）、§7.1（M1 解码配对声明）。本 change 的 tasks 8.x 承载；规划阶段不改 README。

**理由**：README 为唯一文档入口，§7.7 已因 H1 漂移；行为变化必须同批更新，防止再次不一致。

## Risks / Trade-offs

- [`D1` 转义后帧字节 ≠ 原文替换结果] → JSON 语义等价（解析后字符串值相同）但字节形态为转义；下游若做原始字节比对（不应）会看到差异；spec 以「JSON 语义等价 + 可解析」为准。
- [`D1` 回退保留占位符] → 特殊字符凭据在病态帧中不还原为明文（功能降级但安全）；`restore_fallback` 指标可观测，warn 含帧预览便于定位。
- [`D2` `preserve_order` 全局生效] → 其他序列化点（metrics JSON、请求体输出）键序从字典序变为插入序，可能影响既有快照测试；apply 阶段全量回归并接受键序变化（或对特定点显式排序）。
- [`D2` 数字/空白偏离保留] → `1e3`→`1000.0` 在重序列化路径仍存在；以 README 声明 + 零替换短路缩小影响面，彻底消除依赖备选 A（后续 change）。
- [`D3` 置位后下游行为变化] → 此前误判字节等价的下游可能改走兼容路径；属修复预期，README §7.7 声明。
- [`D4` 剥离 accept-encoding] → 上游可能不压缩（内网/容器带宽上升）；重写支持集可保留压缩收益。
- [`D5` error 扩展字段] → 极少数严格 SDK 若拒收未知字段，则按实测回退 lossy 声明（README 同步）。
- [`D6` thinking 跳过扫描] → thinking 内新 PII 不再掩码；签名完整性优先，且 thinking 为上游生成内容，风险接受并在 design 记录。
- [`D7` 正则收窄] → 个别半截形态可能漏剥；差分测试锁定「确证残缺」集合防退化，出口另有完整 token 兜底剥离。
- [`D8` body.auth 回退] → 读取来源增加但三因子语义与 403 不变；保持 `ct_eq` 时序安全比较，攻击面不变（secret/hash 仍须匹配）。

## Migration Plan

1. 按 tasks 顺序落地：先 H2/H1（字节安全与保真，1–2 组），再 M1/M2/M3（3–5 组），再 L1/GO（6–7 组），最后文档同步与门禁（8 组）。
2. 每组独立 `cargo test -p veil <组>`；README §7.1/§7.2/§7.7 与行为改动同批更新；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；`preserve_order` 与可选 `zstd` feature 单独成 commit 便于剥离；无 schema/数据迁移。
4. 发布口径：请求侧 `x-veil-normalized` 置位范围扩大、响应帧键序/字节形态恢复、`accept-encoding` 转发策略变化为下游可感知行为，由 README 三节声明；无 BREAKING 环境变量。

## Open Questions

- 无。D2/D3 的备选 A（全量 span 级字节替换）若后续立项，需另立 change 并同步 README §7.7 与 spec 的字节保真条款；D4 的 zstd 加强若实测无 zstd 上游流量可降级为「剥离 accept-encoding」单方案。
