## ADDED Requirements

### Requirement: README 错误码正面档与合成体字段口径

README SHALL 对网关对话路径产出的错误码提供**正面档**说明（触发条件 + 状态码 + 错误体字段形态），SHALL NOT 仅以否定式附带提及。至少 SHALL 覆盖 `E_EMPTY_BODY`：触发条件为非流对话上游异常空体/非 JSON 体 → 下游 `502`（`src/error.rs:86-97` 的码映射与 `:110` 的 `EmptyBody → BAD_GATEWAY`；网关级错误体构造见 `src/handler/llm/dispatch.rs:150`），并说明其与 `response_too_large` 超限 502 的先后关系（超限判定先于空体/非 JSON 判定）。

合成错误体字段名的 README 对齐 SHALL 为**可选（SHOULD）**项，SHALL NOT 以「纠错」框架表述（`M-4`，`veil-audit-r4-remediation`）：README §4 阈值表行（`README.md:253`）现措辞为「`502` + `response_too_large` JSON 体」，**并未**声称字段名为 `error.code`，故本要求 SHALL NOT 将其定性为错误表述。系统 SHOULD（可选）在该行补 `error.type` 字段名以对齐代码（`src/handler/llm/nonstream.rs:566` 的 `{"error":{"message":"response too large","type":"response_too_large"}}`）；该对齐为可选、非阻断验收项，未执行不判失败。无论是否对齐，README SHALL NOT 出现把该字段描述为 `error.code` 的措辞。

#### Scenario: E_EMPTY_BODY 有正面档

- **WHEN** 在 README 中检索 `E_EMPTY_BODY`
- **THEN** 命中正面档条目，说明触发条件（非流空体/非 JSON → 502）、状态码与错误体字段形态，且与 `src/error.rs:110` 一致

#### Scenario: 超限与空体先后关系声明

- **WHEN** 核查 README 对 `E_EMPTY_BODY` 与 `response_too_large` 的说明
- **THEN** 明确超限判定先于空体/非 JSON 判定（与 `src/handler/llm/nonstream.rs` 实现一致）

#### Scenario: §4 字段名可选对齐（非纠错）

- **WHEN** 核查 `README.md:253` 的非流对话响应上限行
- **THEN** 可选补 `error.type` 字段名以对齐 `src/handler/llm/nonstream.rs:566`；未补不判失败；两种情形均零命中 `error.code` 措辞，且不出现「纠正错误表述」的定性

#### Scenario: scripts/README 口径一致

- **WHEN** 核查 `scripts/README.md` 关于 `check_doc_paths.py` 的归档豁免与 `PENDING_LINE_REFS` 说明
- **THEN** 与 `scripts/check_doc_paths.py:67,71-72` 实现一致，无需改动

## MODIFIED Requirements

### Requirement: README 测试口径标签与脚本一致

README §8.5 的真 SDK 一致性口径 SHALL 采用脚本 **24 项**约定（`scripts/api_conformance.py` 24 项 = 14 常规 + 4 阻断 + 5 取用 + 1 无库 503，由 `bash scripts/gate.sh` 第 6 步 live 实测登记），SHALL NOT 以错位的「12 项（cargo）」标签描述本仓脚本口径，避免与脚本实际计数冲突；原仓对照如需保留历史 cargo 口径 SHALL 明确标注其归属，不与本仓脚本口径混用。该计数 SHALL 以 `scripts/api_conformance.py` 的 live 输出为准（`scripts/api_conformance.py:794` 打印 `len(RESULTS)`）：计数文案与实测不符时 SHALL 同批修订文案，SHALL NOT 影响 gate 第 6 步判定（该步仅校验脚本退出码，不比较项数）。

#### Scenario: 标签与脚本计数一致

- **WHEN** 对照 README §8.5 与 `scripts/api_conformance.py` 输出的项数
- **THEN** 本仓口径为 24 项且明细（14 常规 + 4 阻断 + 5 取用 + 1 无库 503）一致；「12 项（cargo）」不再作为本仓脚本口径标签出现

#### Scenario: 计数为 live 实测且不影响 gate 第 6 步

- **WHEN** `bash scripts/gate.sh` 第 6 步执行 `scripts/api_conformance.py` 并打印 `共 24 项，失败 0 项`
- **THEN** README §8.5 与 canonical 口径为 live 实测的 24 项；计数文案与脚本输出不符时仅需修订文案，gate 第 6 步仍只按脚本退出码判定（全项通过即 0），不因计数差异失败
