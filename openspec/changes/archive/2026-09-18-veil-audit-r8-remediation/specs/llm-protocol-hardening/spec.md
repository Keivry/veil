# Spec Delta

## MODIFIED Requirements

### Requirement: Responses 合成帧序号完整

系统 SHALL 使 Responses 合成帧（含真空流全序列与阻断序列）携带必需的 `sequence_number`，且为单调序列；SHALL NOT 省略该字段。

泵内 SHALL 维护「已见上游序号上界」游标（`responses_seq_cursor: Option<u64>`）：仅当协议为 Responses 且帧为可解析 JSON 时更新，取既有游标与上游 `sequence_number` 的最大值；缺 `sequence_number` 的帧 SHALL NOT 更新游标，回退值 SHALL 被忽略，断序 SHALL NOT 升级为错误。合成注入（阻断 7 帧序列与截断单帧）的起始基准 SHALL 为 `cursor.map_or(0, |c| c.saturating_add(1))`，后续合成帧序号 SHALL 以饱和加法递增（`saturating_add`，`R8-04`）；上游 `sequence_number == u64::MAX` 时 SHALL NOT panic、SHALL NOT 回绕为非单调序列。真空流（零帧）游标为空、基准 `0`，既有 0..6 全序列 SHALL 保持不变；`type:"error"` 单帧 SHALL 沿用上游 error 自带 `sequence_number`，SHALL NOT 重新编号。

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

#### Scenario: 极值序号饱和不溢出

- **WHEN** 上游 `sequence_number == u64::MAX` 后触发合成注入（阻断或截断）
- **THEN** 合成基准与后续序号按饱和加法处理，SHALL NOT panic、SHALL NOT 回绕为非单调序列
