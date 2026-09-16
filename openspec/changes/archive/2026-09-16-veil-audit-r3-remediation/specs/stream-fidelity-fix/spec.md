## MODIFIED Requirements

### Requirement: 中途断流终端策略

系统 SHALL 按协议固化中途断流（未发终端的异常 EOF 或 `chunk()` 报错）终端策略：Chat SHALL 补发恰一 `data: [DONE]` 并记 `truncated_mode=open_ended`；Anthropic SHALL NOT 合成 `message_stop`（仅记 `open_ended` 观测，不伪造成功终止）；Responses 在已发帧时 SHALL 合成恰一 `response.failed` 并记 `synthesized_failed`，未发帧时维持真空流最小终止。三协议终端 SHALL 恒恰一。

Chat **干净收尾**（已出现非 null `finish_reason` 后干净 EOF、即使未收到 `data: [DONE]`）SHALL 仅补发恰一 `data: [DONE]`，`truncated_mode` SHALL NOT 记 `open_ended`；`open_ended` SHALL 仅用于无成功收尾信号的异常结束。

README §7.2 与 §8.6 SHALL 与策略同批同步。截断残余帧（未以空行或完整边界终结的半帧）SHALL NOT 被二次加 `data:` 前缀转发（对齐 Python 丢弃残余），SHALL NOT 使下游因重复 `data:` 前缀遇到解析错误；残余 SHALL 按剥离前缀丢弃或按既有口径丢弃半帧，含 CR-only 残余。

#### Scenario: Chat 中途断流补 DONE

- **WHEN** Chat 上游已发内容帧后断流且从未发 `data: [DONE]`
- **THEN** 下游收到恰一 `data: [DONE]`，且 `truncated_mode=open_ended`

#### Scenario: Chat 干净 EOF 不记 open_ended

- **WHEN** Chat 上游已发非 null `finish_reason` 后干净 EOF 且未发 `data: [DONE]`
- **THEN** 下游收到恰一 `data: [DONE]`，且 `truncated_mode` 不置 `open_ended`

#### Scenario: Anthropic 中途断流不伪造终止

- **WHEN** Anthropic 流中途断流
- **THEN** 下游不收到合成的 `message_stop`，`truncated_mode=open_ended` 记录截断

#### Scenario: Responses 中途断流合成失败终端

- **WHEN** Responses 已发内容帧后中途断流
- **THEN** 下游收到恰一 `response.failed`，`truncated_mode=synthesized_failed`

#### Scenario: 截断残余不被二次加前缀

- **WHEN** 上游在帧中途断流留下残余半帧（含 CR-only 残余）
- **THEN** 该残余不被以 `data:` 前缀重复转发，下游不解析到重复前缀，残余按口径丢弃

## ADDED Requirements

### Requirement: 多行 data 出口保真

系统 SHALL 在 SSE 出口把含换行的 data 载荷按 `\n` 拆为多条带 `data:` 前缀的行后再补块终止空行，使出口拆分与解析侧 WHATWG 单 `\n` 连接严格互逆；SHALL NOT 输出无前缀裸行。该行为 SHALL 由单一 `sse::data_frame(prefix, data)` 实现承载并替换既有重复构造；`event:`/`id:`/`retry:` 信封字段 SHALL NOT 受影响。

#### Scenario: 多行载荷出口拆分

- **WHEN** 某事件的 data 载荷含换行（非 JSON 多行形态）
- **THEN** 出口按 `\n` 拆为多条 `data: <行>`，无无前缀裸行，尾部补恰一空行

#### Scenario: 出口与解析互逆

- **WHEN** 出口拆分后的多行 data 再经解析侧 WHATWG 单 `\n` 连接
- **THEN** 还原载荷与原始载荷逐字节一致

#### Scenario: 信封字段不受影响

- **WHEN** 同一事件携带 `event:`/`id:`/`retry:` 与多行 data
- **THEN** 信封字段原样透出，仅 data 部分按行拆分
