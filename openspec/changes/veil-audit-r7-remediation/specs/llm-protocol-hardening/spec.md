# Spec Delta

## MODIFIED Requirements

### Requirement: Chat 错误载荷帧即终端

系统 SHALL 将带顶层 `error` 且无 `choices` 的 Chat 数据帧视为终止事件：命中即置终端已发，SHALL NOT 在流末补发 `data: [DONE]`；并以独立观测 `TruncatedMode::UpstreamError`（`upstream_error`）区别于中途截断的 `open_ended`。判据 SHALL 限定为「顶层 `error` 存在」与「`choices` 缺席」同时成立，SHALL NOT 误伤 `choice` 内含 `error` 字段或顶层 `error` 与 `choices` 共存的正常形态。

系统 SHALL 使 Anthropic `error` 终端同样记录 `upstream_error` 观测（该值对非 Responses 协议本就合法）：Anthropic 流中 `type:"error"` 作为终端透出且此前未发终端时，除既有终端语义外，`truncated_mode` SHALL 置 `upstream_error`，SHALL NOT 留空（`None`）使「上游错误即终端」的第四态在 Anthropic 面失明。

Responses `type:"error"` 合成 `response.failed` SHALL 走其自有路径并记录 `synthesized_failed`（`R7-03`）：终端计划（`plan_responses_error`）SHALL 携带 `truncated: Some(TruncatedMode::SynthesizedFailed)`；调用点 SHALL 解构该观测并在 `commit` 后**无条件**调用 `set_truncated`（与中途断流调用点同口径），SHALL NOT 以终端帧是否送达（`terminal_ok`）门控观测；`terminal_ok` 仍只决定 `commit` 的终端帧位与 `StreamMeta.terminal_injected`。`set_truncated` 自带的 Responses-only 守卫 SHALL 保持不变，调用点 SHALL NOT 重复协议门控。

#### Scenario: error 帧后不补 DONE

- **WHEN** Chat 流中出现带顶层 `error` 且无 `choices` 的数据帧
- **THEN** 系统置终端已发、不再注入 `data: [DONE]`，观测记为 `upstream_error`（非 `open_ended`）

#### Scenario: choice 内含 error 不误伤

- **WHEN** Chat 帧的 `choices[].error` 字段非空或顶层 `error` 与 `choices` 共存
- **THEN** 该帧不被判为终端，既有透传与收尾语义不变

#### Scenario: Anthropic error 终端记 upstream_error

- **WHEN** Anthropic 流透传 `type:"error"` 事件且此前未发终端
- **THEN** 该帧仍作为终端透出，且 `truncated_mode` 记为 `upstream_error`（非 `None`、非 `open_ended`）

#### Scenario: Responses error 终端记 synthesized_failed

- **WHEN** Responses 流透传 `type:"error"` 事件且此前未发终端
- **THEN** 合成恰一 `response.failed`，`truncated_mode` 记为 `synthesized_failed` 并落 metrics 分标签计数；下游早断（终端帧未送达）时观测仍落（不低于一次），`terminal_ok` 仅影响终端帧位
