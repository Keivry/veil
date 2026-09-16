## MODIFIED Requirements

### Requirement: Responses 合成帧序号完整

系统 SHALL 使 Responses 合成帧（含真空流全序列与阻断序列）携带必需的 `sequence_number`，且为单调序列；SHALL NOT 省略该字段。

泵内 SHALL 维护「已见上游序号上界」游标（`responses_seq_cursor: Option<u64>`）：仅当协议为 Responses 且帧为可解析 JSON 时更新，取既有游标与上游 `sequence_number` 的最大值；缺 `sequence_number` 的帧 SHALL NOT 更新游标，回退值 SHALL 被忽略，断序 SHALL NOT 升级为错误。合成注入（阻断 7 帧序列与截断单帧）的起始基准 SHALL 为 `cursor.map_or(0, |c| c + 1)`；真空流（零帧）游标为空、基准 `0`，既有 0..6 全序列 SHALL 保持不变；`type:"error"` 单帧 SHALL 沿用上游 error 自带 `sequence_number`，SHALL NOT 重新编号。

#### Scenario: 合成帧带序号

- **WHEN** 合成 Responses 帧（7 帧全序列或阻断序列）
- **THEN** 每帧含 `sequence_number` 且序列单调

#### Scenario: 不省略序号

- **WHEN** 以 SDK 或结构校验检查合成帧
- **THEN** 不存在缺失 `sequence_number` 的帧

#### Scenario: 阻断帧接续上游序号

- **WHEN** 审计阻断发生在已透传最大 `sequence_number=N` 之后
- **THEN** 合成序列起始序号为 N+1，全程单调、不倒退、不重复

#### Scenario: 真空流基准为 0

- **WHEN** Responses 上游返回 200 且零帧
- **THEN** 合成全序列 `sequence_number` 自 0 起（0..6），与既有口径一致

#### Scenario: 缺序号帧不推进游标

- **WHEN** 上游帧无 `sequence_number` 或其序号回退
- **THEN** 游标不更新（保持既有上界），后续合成基准不回退

#### Scenario: error 单帧沿用上游序号

- **WHEN** 上游 `type:"error"` 自带 `sequence_number=7`
- **THEN** 合成 `response.failed` 携带序号 7，不重新编号

## ADDED Requirements

### Requirement: Anthropic 真空流与中途断流分野

系统 SHALL 区分 Anthropic **真空流**与**中途断流**：真空流（零字节零残余）SHALL 走最小可解析终止（`message_start` + `message_stop`）；中途断流（已发内容帧后异常 EOF 或 `chunk()` 报错）SHALL 仅记 `truncated_mode=open_ended` 观测，SHALL NOT 合成 `message_stop` 或任何终端数据帧，SHALL NOT 伪造成功终止。

#### Scenario: 中途断流不补 stop

- **WHEN** Anthropic 上游已发送内容帧后异常 EOF
- **THEN** 下游不收到合成的 `message_stop`，`truncated_mode=open_ended` 被记录

#### Scenario: 真空流仍最小终止

- **WHEN** Anthropic 上游返回 200 且零帧
- **THEN** 下游收到 `message_start` 与 `message_stop` 各恰一，不因中途断流条款而放行开放结尾

### Requirement: Chat 错误载荷帧即终端

系统 SHALL 将带顶层 `error` 且无 `choices` 的 Chat 数据帧视为终止事件：命中即置终端已发，SHALL NOT 在流末补发 `data: [DONE]`；并以独立观测 `TruncatedMode::UpstreamError`（`upstream_error`）区别于中途截断的 `open_ended`。判据 SHALL 限定为「顶层 `error` 存在」与「`choices` 缺席」同时成立，SHALL NOT 误伤 `choice` 内含 `error` 字段或顶层 `error` 与 `choices` 共存的正常形态。

#### Scenario: error 帧后不补 DONE

- **WHEN** Chat 流中出现带顶层 `error` 且无 `choices` 的数据帧
- **THEN** 系统置终端已发、不再注入 `data: [DONE]`，观测记为 `upstream_error`（非 `open_ended`）

#### Scenario: choice 内含 error 不误伤

- **WHEN** Chat 帧的 `choices[].error` 字段非空或顶层 `error` 与 `choices` 共存
- **THEN** 该帧不被判为终端，既有透传与收尾语义不变

### Requirement: responses_failed_frame 手写信封保留声明

系统 SHALL 保留 `responses_failed_frame` 的手写信封构造：`responses_frame` **无条件**写入 `sequence_number`，而失败帧 SHALL 仅在上游 error 携带序号时写入 `sequence_number`；系统 SHALL NOT 为「序号不可得」情形新增字段，以维持 README §7.2 的 TRN-2 lossy 边界（可得时写入、缺失不填充）。本要求 SHALL NOT 被解读为要求信封去重；信封格式在 `frames.rs` 内至少 5 处重复，单点统一不构成收敛，SHALL NOT 在本批抽取（信封去重列为可选后续）。

#### Scenario: 序号不可得不新增字段

- **WHEN** 上游 error 未携带 `sequence_number` 而合成 `response.failed`
- **THEN** 合成帧不含 `sequence_number` 字段（不无条件写入），与 lossy 边界一致

#### Scenario: 序号可得时写入

- **WHEN** 上游 error 携带 `sequence_number`
- **THEN** 合成 `response.failed` 写入该序号
