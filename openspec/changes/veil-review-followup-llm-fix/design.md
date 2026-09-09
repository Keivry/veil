## Context

现状：`usage.rs` 非流/流式对 Responses 取 `response.usage` 双层嵌套，与官方顶层 `usage` 不符；`fragments.rs/tool.rs` 桶键缺 `ci`；`placeholder.rs` 前缀匹配误伤 `*` 字面；`usage.rs` 快路径全量序列化。约束：只改取数优先级、桶键、形态校验、快路径实现，不碰 verdict/PII/阻断帧；真相源 `stream-protocol-parity/nonstream-compliance`。

## Goals / Non-Goals

Goals：给出函数级改动形状与单测锁定，使 apply 逐项独立验证。
Non-Goals：不设计新用量口径、不改审计判定、不引入新依赖。

## Decisions

### D1：Responses 用量顶层优先、嵌套回退（F-P1a）

决策：`extract_usage_nonstream/stream` 对 Responses 改为顶层 `usage` 优先，其次 `response.usage`，最后 `response.response.usage` 回退；`cached_columns` 同口径。补真实 `resp_xxx` 体单测（顶层 input/output/total + `input_tokens_details.cached_tokens`）。
理由：官方非流为顶层 `usage`，流式为 `response.completed.response.usage`；当前双层优先会漏记标准体。
备选：维持双层优先并声明上游为定制形态，不采用（与官方 SDK 互操作断裂）。

### D2：tool 桶键混入 choice 序号（F-P1b）

决策：Chat（含流/非流）桶键由 `index` 改为 `(ci, index)` 二元或 `ci*64+index`；`synth_id` 输入同步混入 `ci`；Anthropic 外层→内层→枚举、Responses `output_index/item_id` 不动。`custom_obj_to_call` 同步。
理由：`n>1` 时跨 choice 同 index 必然碰撞；legacy 已用 `ci`，统一消除不一致。
备选：文档声明不支持 `n>1`，不采用（官方允许 `n>1` 多 choices）。

### D3：占位符精确形态校验+说明幂等（F-P2a）

决策：`has_placeholder_tokens` 改为正则/精确解析：`__PII_<seq>_<hex8>__` 全段 hex、`__VG_CRED_<6+digits>__` 全段 digits；`__PII_*__` 字面不算。`inject_placeholder_prompt` 前加“已含说明跳过”：若首条 system/array 已含默认说明指纹则不再前插。
理由：前缀匹配误伤说明文案自身，导致重复注入膨胀请求。
备选：维持前缀匹配并在 prompt 去掉 `__PII_*__` 字样，不采用（说明可读性下降）。

### D4：用量快路径零分配（F-P2b）

决策：`extract_usage_stream` 快路径改为 `obj.contains_key("usage") || obj.get("response").is_some() ...` 借用判断，不做 `to_string()`；重体仍走 `usage_from_obj` 归一。
理由：每分片全量序列化是 O(n) 浪费，高吞吐下 CPU 可观测。
备选：维持现状，不采用（泵热点）。

## Risks / Trade-offs

- [顶层优先后定制上游双层体仍命中回退] → 三级回退保留 → 不断链。
- [桶键改后旧审计快照变化] → tasks 设快照更新项 → 单测锁定新键。
- [精确校验漏掉未来新形态] → 未知形态走原透传不断链 → 新形态另立任务。

## Migration Plan

1. 按 tasks F1→F4 顺序逐项修，每项独立单测，失败只回滚该项。
2. 用量与桶键变更先加回归单测再改实现，最后跑 conformance。
3. 文档在 README §7.2 用量段落追加顶层优先说明一句。

## Open Questions

- 无。若实测上游确为双层定制体，以实测体为准保留三级回退顺序并同步文档。
