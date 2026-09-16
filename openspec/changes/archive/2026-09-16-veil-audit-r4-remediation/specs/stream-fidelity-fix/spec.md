## MODIFIED Requirements

### Requirement: 多行 data 出口保真

系统 SHALL 在 SSE 出口把含换行的 data 载荷按解析侧行终止集合（`\n`、`\r\n`、`\r`）拆为多条带 `data:` 前缀的行后再补块终止空行；SHALL NOT 输出无前缀裸行。出口 SHALL NOT 仅按 `\n` 拆分而把裸 `\r`/`\r\n` 留在单条 `data:` 行内——解析侧视裸 CR 为行终止（`src/service/sse/parser.rs:207-226`），若出口不拆则同一事件会被解析侧错切为额外帧或造成 `event:` 名错配。该行为 SHALL 由单一 `sse::data_frame(prefix, data)` 实现承载并替换既有重复构造；`event:`/`id:`/`retry:` 信封字段 SHALL NOT 受影响。

**声明式 WHATWG LF 归一（B-3，`veil-audit-r4-remediation`）**：解析侧对同一事件内多条 `data:` 行按 WHATWG 规范以**单个 `\n`** 连接（`src/service/sse/parser.rs:327` 的 `data_parts.join("\n")`），该 LF 连接为**已锁定**行为（canonical `stream-fidelity-fix`「多行 data 按 WHATWG 连接」）。因此含裸 `\r`/`\r\n` 的载荷**不可能**经 `emit → parse` 逐字节还原——CR 出口拆分后由解析侧按 `\n` 连接即归一为 LF。本要求在 `\n` 载荷上 SHALL 逐字节互逆；对含裸 CR 的载荷 SHALL 明确声明为 **LF 归一**（SHALL NOT 声称逐字节一致、SHALL NOT 声称含 `\r\n` 字节恒等），且该归一 SHALL 不产生额外事件边界、不造成 `event:`/`id:`/`retry:` 名错配、终态事件数恒恰一。

#### Scenario: 多行载荷出口拆分

- **WHEN** 某事件的 data 载荷含换行（非 JSON 多行形态）
- **THEN** 出口按行终止集合拆为多条 `data: <行>`，无无前缀裸行，尾部补恰一空行

#### Scenario: 出口与解析互逆

- **WHEN** 出口拆分后的 `\n` 多行 data 再经解析侧 WHATWG 单 `\n` 连接
- **THEN** 还原载荷与原始载荷逐字节一致（**仅限以 `\n` 分隔的载荷**；含裸 `\r`/`\r\n` 的载荷按相邻「裸 CR 载荷声明为 LF 归一」场景作已声明 LF 归一，SHALL NOT 以逐字节恒等断言）

#### Scenario: 裸 CR 载荷声明为 LF 归一

- **WHEN** data 载荷含裸 `\r`（或 `\r\n`），经出口拆分后再由解析侧解析
- **THEN** 出口不把裸 CR 留在单条 `data:` 行内；解析侧按单 `\n` 连接得**已声明的 LF 归一**值（如 `a\rb` → `a\nb`），不产生被误切的新事件边界，事件数恒恰一，`event:`/`id:`/`retry:` 不错配

#### Scenario: 信封字段不受影响

- **WHEN** 同一事件携带 `event:`/`id:`/`retry:` 与多行 data
- **THEN** 信封字段原样透出，仅 data 部分按行拆分

#### Scenario: 注释不再过度声明

- **WHEN** 核查 `sse::data_frame` 的注释
- **THEN** 其「互逆」声明限定为与解析侧行终止集合（`\n`/`\r\n`/`\r`）相关、并对含裸 CR 载荷显式声明 LF 归一，SHALL NOT 声称仅按 `\n` 即逐字节严格互逆（含 `\r\n`）

#### Scenario: 回归测试锁定声明口径

- **WHEN** 核查新增回归测试（如 `sse_data_frame_cr_roundtrip`）与既有往返测试（`src/service/sse/cr_tests.rs:73` 的 `sse_multiline_data_roundtrip`）
- **THEN** 含裸 CR 载荷断言按已声明 LF 归一值一致且恰一事件，不以「逐字节一致（含 `\r\n`）」为断言
