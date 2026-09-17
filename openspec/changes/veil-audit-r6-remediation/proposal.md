# Proposal

## Why

第六轮审计（Oracle 只读深审 + 三项独立核实）确认代码基线健康：`cargo clippy --tests --all-targets -- -D warnings` 全绿、1491 项测试通过、生产代码无 `unwrap`/`expect`、无文件超 800 行、D1（bug）/D2（架构）/D4（死代码）/D6（会话级缓存友好）/D7（结构/语义/工具调用保全）未见新缺陷。

但审计发现 6 项可核实缺陷：1 项传输保真缺口（上游同名多值响应头被折叠为末值，属未声明差异），其余为 R5 大 diff（+5467/−871）后遗留的文档/规范锚点与措辞漂移。真相源（README + canonical spec）与实际实现需重新一致，并为多值头补齐回归覆盖。

## What Changes

- **AUDIT-03（唯一运行时行为变更）**：上游同名多值响应头逐值透传。`clone_upstream_headers`（`src/handler/llm/nonstream.rs`）与 `stream_upstream_passthrough`（`src/handler/llm/dispatch.rs`）由 `HeaderMap::insert` 改 `HeaderMap::append`；网关自置头仍用 `insert`（覆盖语义不变）；新增多值（两条 `Set-Cookie`/`warning`）回归测试。
- **AUDIT-01/02**：漂移的 `path:line` 锚点改符号锚点——README 4 处段落（§4 阈值表、§7.2×2、§7.5；另有 §7.2 一处复核）+ 3 个 canonical capability 的定位引用（`docs-contract-sync`、`nonstream-audit-align`、`credential-auth-hardening`）；canonical 修正经本 change 的 change-local delta 于归档时合并，本 change SHALL NOT 手改 `openspec/specs/**`。
- **AUDIT-04**：`scripts/gate.sh` 头注 conformance 计数由「23 项」改为「24 项」，与 README §8.5 与脚本实际计数一致。
- **AUDIT-05**：收窄 `src/handler/llm/mod.rs` 注释的 `x-veil-protocol` 口径为「非流对话路径 + 流式错误透传路径」；README 经核查无过宽措辞（无重复修复项）；SSE 成功路径与 NonDialog 透传不置该头（与 canonical 范围一致，不引入新 wire 行为）。
- **AUDIT-06**：修正 `llm-gateway` spec 与 README §7.2 的 `Speed::Fast` 边界描述——生产 `agg` 恒以帧终止 `\n\n` 结尾，标点分支不可达，实际边界为 `FAST_EMIT_THRESHOLD_BYTES`（4096 字节）；`is_punct_boundary` 保留为 API，不回退 STP-6 的攒批裁决。

### Non-goals

- 不扩展 `scripts/check_doc_paths.py` 做语义校验（决策 1 选项 C）：canonical `docs-contract-sync`「文档行号引用可校验」明确其职责边界为「路径存在性 + 行号在界」，语义一致由 code review 保证；扩展需改动该 canonical 要求，登记为后续 change。
- 不给 SSE 成功响应新增 `x-veil-protocol`（决策 3 选项 B）：不引入新 wire 行为。
- 不复活 `Speed::Fast` 标点分支（决策 4 选项 B）：不改变下游发送节奏，保留 STP-6 裁决。

## Capabilities

### New Capabilities

（无）

### Modified Capabilities

- `docs-contract-sync`: README 与 canonical 的漂移行号锚点改符号锚点；错误码正面档指针校正；`gate.sh` 计数与 README §8.5 的 24 项对齐。
- `nonstream-audit-align`: 「空体与非 JSON 502 门控边界」的单入口 `classify_empty` 指针改符号锚点。
- `credential-auth-hardening`: 「紧急吊销通道仅认管理 token 与内网来源」的 admin token 检查指针改符号锚点。
- `llm-gateway`: 「WHATWG 缓冲与 slow / fast 双速」的 `Speed::Fast` 边界描述与生产实际对齐。
- `transport-fidelity-fix`: 「非流上游响应头透传」补「同名多值逐值保留」要求；「网关生成非流错误响应统一协议头」补范围声明（SSE 成功与 NonDialog 不置，README/注释不得声称统一）。
- `gateway-transport-fidelity`: 流式错误透传路径补同名多值响应头保留要求。

## Impact

- **代码**：`src/handler/llm/nonstream.rs`、`src/handler/llm/dispatch.rs`（`insert → append` 各一处）、`src/handler/llm/mod.rs`（注释措辞）；新增多值头回归测试。
- **文档**：`README.md`（§4 阈值表、§7.2、§7.5）、`scripts/gate.sh`（头注）。
- **规范**：上述 6 个 canonical capability 的 delta spec。
- **无 API/配置/依赖变更**；**无 BREAKING**；多值头透传修正为传输保真补齐（原折叠行为未声明）。
