## Context

现状（见 proposal.md Why）：三协议主体合规，6 处缺口集中在流泵判定、conv 归档、注入粒度、状态码对称四类。约束：只改流泵判定顺序、conv 取值优先级、占位注入粒度、阻断状态码与文档，不碰审计 verdict 与 PII recognizer；真相源为 `openspec/specs/stream-protocol-parity` 与 `nonstream-compliance`；`README §6-8` 为 BREAKING 声明区，E1 与 E4 若选文档方案须落字到 §7.2 或 §8。

## Goals / Non-Goals

**Goals：**

- 给出每项修复的函数级改动形状与单测锁定方式，使 apply 可逐项落地独立验证。
- 收敛二选一（E4 状态码统一或声明），消除“以谁为准”疑问。

**Non-Goals：**

- 不设计 approve 同步或挂起语义。
- 不输出逐行代码 diff，只定签名形状、判定口径与帧形态。
- 不引入新依赖。

## Decisions

### D1：混帧先提工具片段，剩余 thinking 才走 minor（E7-P0）

**决策**：`pump.rs` 主循环内把 `extract_tool_fragments` 提前到 `is_minor_event` 之前。`frags` 非空则 `is_tool_event=true`，走现有 tool 通道（`hold.push_fragment` 或 `push_responses_fragment`）；`minor` 计算保持 `!is_tool_event && is_minor_event(...)` 不变。Anthropic 侧 `thinking_delta` 加 `partial_json` 混帧因此必进审，纯 thinking 帧仍透传。

**理由**：审计宁可误报不可漏审。互斥判定把整帧标 minor 会吞掉混在其中的工具调用，违背 hold-until-complete。工具优先后，`event==data.type` 仍成立，`delta` 增量语义不变。

**备选**：保持互斥判定不变，只给 thinking 加白名单，工具增量继续漏审，不采用。

### D2：Responses 终止改 serde_json 按 type 精确判定（E8-P1）

**决策**：`pump.rs:202-234` 与 `235-275` 两处 `contains` 改为先 `serde_json::from_str` 解析，成功则按 `type` 字段精确匹配终结集合（`response.completed/response.failed/response.incomplete/error`）；解析失败才回退现有 contains 兜底并计数。Anthropic 与 Chat 分支不动。

**理由**：字符串匹配把正文关键词误判为终结，也会漏掉带空格或转义变体。按 `type` 判定与 Responses 官方事件模型一致，`completed/failed` 终结语义不变。

**备选**：继续加 contains 变体枚举，变体无穷尽，不采用。

### D3：incomplete 合成 conv 优先流内首见 id（E9-P1）

**决策**：泵内维护 `stream_first_id`（首个含可用 `id` 的流内帧），合成截断帧时优先用它；仅其缺失时调用 `resolve_conv_id(None, Null)` 归档。`resolve_conv_id` 本体（`tool.rs:572`）不动。

**理由**：归档值是 `unknown_<hash>`，与流内真实 `resp_*` 无法关联，下游与审计都断链。流内优先恢复关联性，缺失回退保留不断链保证。

**备选**：恒用归档值并文档声明不一致为有意，关联断裂，不采用。

### D4：显式 false 保留不动，只补文档与告警说明（E1-P1）

**决策**：`protocol.rs:126-145` 的 `or_insert` 与 `rewrite.rs:172-190` 单测锁定的按 key 合并语义不动。`README §7.2` 追加一段：“`include_usage:false` 为显式放弃流式用量，网关按 key 合并保留，不覆写为 true；此时流式无 usage 帧，metrics 空 usage 桶为预期”。metrics 文档同步一句告警指引。

**理由**：行为正确，无需改代码。缺的是用户预期管理，否则空 usage 会被当故障报修。

**备选**：把 false 强行覆写为 true，用量完整但违背用户显式意图，不采用。

### D5：Responses 双字段独立注入独立回退（E2-P1）

**决策**：`placeholder.rs:189-213` 的 `inject_placeholder_prompt` 改为逐字段处理：对 `input` 与 `instructions` 各自做注入加形态校验，各自决定保留或回退该字段；仅当双字段都非法时整体返回 `None`。`placeholder_schema_ok` 保留作最终兜底。

**理由**：整对象校验把合法字段的改动连坐丢弃，可用性降。字段独立后，Chat `delta` 增量与 Anthropic `event==data.type` 不受影响，Responses `input/instructions` 各为 string 或 array 的形态要求逐字段仍成立。

**备选**：维持整体回退，合法改动丢失，不采用。

### D6：阻断状态码统一恒 200 或文档声明差异二选一（E4-P1）

**决策**：apply 时二选一并单测锁定。首选统一恒 200：`nonstream.rs:150-189` 阻断分支固定 `StatusCode::OK`，与流式恒 200 闭合对称。若实测证明保留上游码对排障不可少，则选文档声明：在 `README §8` 或对应 spec 写明“非流保留上游码、流式恒 200”为有意差异，并加单测断言该差异。

**理由**：对称性降低客户端分支复杂度。关键是双边一致且可验证，而非谁对谁错。

## Risks / Trade-offs

- [混帧改序后 hold 量上升] → 误报优于漏审 → 监控工具审计量突变属预期。
- [精确判定解析失败回退] → 兜底 contains 仍在 → 回退计数可观测。
- [首见 id 缺失] → 归档回退 → 不断链，`conv_missing` 计数加一。
- [D6 选统一 200 后旧客户端按状态码排障] → 文档声明加迁移指引 → 回滚开关为切回保留码。
- [双字段独立注入后快照变化] → 既有单测快照更新 → tasks 设独立快照任务。

## Migration Plan

1. 按 tasks R1→R6 顺序逐项修，每项独立单测验证，任一项失败只回滚该项。
2. 判定类变更（D1、D2）先加混帧与变体回归单测，再改实现，最后跑三协议 conformance。
3. 文档类变更（D4、D6 声明选项）先落字 `README §7.2` 或 §8，再补单测断言文档语义。

## Open Questions

- 无。D6 二选一已在本 design 收敛；若 apply 实测严格客户端对状态码另有要求，以实测为准锁定其中之一并同步文档。
