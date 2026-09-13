# stream-fidelity-fix Specification

## Purpose
锁定 LLM 网关三协议（Chat / Anthropic / Responses）流式面修复后的保真契约：默认逐帧增量、审计持有仅在未完成 tool 分片存在时生效、Responses 槽级完成与全局完成隔离、合成终端保序、跨帧占位符缝合还原、中途传输错误可观测与断流终端策略固化、流式上游错误状态透传、审计 hold 字节按槽回收、截断合成发送成功才置位、流式审批不挂起声明。

## Requirements

### Requirement: 默认逐帧增量输出

系统 SHALL 在无未完成审计持有 tool 分片时逐帧放行上游内容帧，SHALL NOT 因流级「未完成」状态（如 `held()=!completed&&!rejected` 在流开始即为真）把整条流缓冲为单帧。持有抑制 SHALL 仅在审计模式非 `off`、确有未完成 tool 分片、本帧非次要事件且有输出三者同时成立时生效；完成事件审计后（含 `NeedApproval` 建单，不阻塞流）相关槽 SHALL 释放出抑制集。keepalive 门控 SHALL 与抑制判据同源：仅存在未完成 tool 分片时抑制保活帧，无未完成分片时保活帧 SHALL 按周期发送。

#### Scenario: 默认配置逐帧到达

- **WHEN** `AUDIT_MODE` 未设（默认 `off`）且 mock 上游慢速分片投递多帧文本
- **THEN** 下游在终止帧前已按帧收到内容（非终止时才一次性拼接），无全流缓冲

#### Scenario: 无分片不抑制

- **WHEN** 审计开启但流中不存在任何未完成 tool 分片
- **THEN** 文本帧逐帧透传，不因 hold 未完成而抑制

#### Scenario: keepalive 门控仅随未完成分片

- **WHEN** 流中无未完成 tool 分片
- **THEN** keepalive 保活帧按周期发送；存在未完成 tool 分片时保活帧被门控抑制

### Requirement: Responses 槽级完成与全局完成隔离

系统 SHALL 仅以 `response.completed`、`response.failed`、`response.incomplete` 作为 Responses 全局完成事件。`response.output_item.done` 与 `response.function_call_arguments.done` SHALL 仅标记并审计对应槽（槽级 done），SHALL NOT 置全局完成、SHALL NOT 使后续 item 的分片跳过累积与审计。多 item 流中任一 item 命中阻断策略时 SHALL 注入阻断终端，危险参数 SHALL NOT 透传。

#### Scenario: item0 完成后 item1 危险参数被阻断

- **WHEN** item0 良性完成（`response.output_item.done`）后 item1 到达 `exec {"command":"rm -rf /"}` 且 `AUDIT_MODE=block`
- **THEN** 下游收到阻断帧，危险参数不透传；item1 不得因 item0 完成而跳过审计

#### Scenario: per-item done 不置全局完成

- **WHEN** 流中仅到达 `response.function_call_arguments.done`
- **THEN** 全局完成状态未置位，后续 item 分片照常累积并接受审计

### Requirement: 合成终端保序

系统 SHALL 在合成终端帧（`type:"error"` → `response.failed`、截断 → `response.failed`）之前 flush 边界滞留帧，并保证滞留内容帧先于合成终端帧下行；SHALL NOT 把滞留帧拖到 EOF 或终端帧之后。终端帧发出后 SHALL NOT 再有任何数据帧。

#### Scenario: error 合成保序

- **WHEN** 上游先发含增量 A 的帧、随后发 `type:"error"`
- **THEN** 下游先收到含 A 的内容帧，再收到恰一 `response.failed`

### Requirement: 跨帧占位符缝合还原

系统 SHALL 对跨帧切分的 `__VG_CRED_*__` 与 `__PII_*__` 占位符执行跨帧缝合：帧尾若为占位符合法前缀的残缺形态，SHALL 持有该前缀至下一帧拼接后还原，SHALL NOT 在本帧按残缺剥离而丢失还原。流结束（正常/截断/错误）时仍未配对的残余前缀 SHALL 按既有残缺剥离口径清理，且 SHALL NOT 泄漏原文。凭证与 PII 两类 token 的跨帧切分均 SHALL 覆盖。

#### Scenario: 凭证跨帧缝合

- **WHEN** 上游分两帧发送 `__VG_CRE` 与 `D_000001__`
- **THEN** 下游收到该凭证的还原后明文，无被剥离的残片

#### Scenario: PII 跨帧缝合

- **WHEN** PII token 在帧间被切开（前缀帧 + 续段帧）
- **THEN** 下游收到该 PII 的还原后明文

#### Scenario: 流末残余前缀剥离

- **WHEN** 流结束时仍有无法配对的占位符残缺前缀
- **THEN** 该前缀被剥离，输出不含原文泄漏

### Requirement: 中途传输错误可观测

系统 SHALL 在流式上游 `chunk()` 返回 `Err` 时记录 warn 日志与截断观测（`truncated_mode` 与指标），SHALL NOT 静默按正常 EOF 退出。

#### Scenario: mid-stream 断连可观测

- **WHEN** mock 上游在已发送部分帧后连接中断（`chunk()` 报错）
- **THEN** 日志含截断告警、截断观测被记录，流按协议终端策略收尾而非静默结束

### Requirement: 中途断流终端策略

系统 SHALL 按协议固化中途断流（未发终端的异常 EOF 或 `chunk()` 报错）终端策略：Chat SHALL 补发恰一 `data: [DONE]` 并记 `truncated_mode=open_ended`；Anthropic SHALL NOT 合成 `message_stop`（仅记 `open_ended` 观测，不伪造成功终止）；Responses 在已发帧时 SHALL 合成恰一 `response.failed` 并记 `synthesized_failed`，未发帧时维持真空流最小终止。三协议终端 SHALL 恒恰一。README §7.2 与 §8.6 SHALL 与策略同批同步。

#### Scenario: Chat 中途断流补 DONE

- **WHEN** Chat 上游已发内容帧后断流且从未发 `data: [DONE]`
- **THEN** 下游收到恰一 `data: [DONE]`，且 `truncated_mode=open_ended`

#### Scenario: Anthropic 中途断流不伪造终止

- **WHEN** Anthropic 流中途断流
- **THEN** 下游不收到合成的 `message_stop`，`truncated_mode=open_ended` 记录截断

#### Scenario: Responses 中途断流合成失败终端

- **WHEN** Responses 已发内容帧后中途断流
- **THEN** 下游收到恰一 `response.failed`，`truncated_mode=synthesized_failed`

### Requirement: 流式上游错误状态透传

系统 SHALL 在流式请求的上游响应 `status>=400` 或 `content-type` 非 `text/event-stream` 时，透传上游状态码与正文字节（与非流路径语义一致）；SHALL NOT 不看状态码一律转入 SSE 泵并恒定回 200。README §7.2 SHALL 同步该透传口径。

#### Scenario: 500 JSON 错误体

- **WHEN** `stream:true` 请求上游返回 500 且正文为 JSON
- **THEN** 下游收到 500 与同一 JSON 正文字节

#### Scenario: 500 HTML 错误体

- **WHEN** 上游返回 500 且正文为 HTML（非 `text/event-stream`）
- **THEN** 下游收到 500 与同一 HTML 正文字节，不被改写为 200 SSE

### Requirement: 审计 hold 字节按槽回收

系统 SHALL 按槽记账审计持有字节，并在槽完成/清理时回收：Chat/Anthropic 的槽清理（`clear_index`）、Responses 的 per-item `done` 槽审计清理、`mark_completed`/`mark_rejected` SHALL 归还对应字节。长流多工具调用 SHALL NOT 因累计不回收而误判溢出 fail-closed；真实超限 SHALL 仍拒绝并清仓。

#### Scenario: 长流多工具不误判溢出

- **WHEN** 长流中多个 tool 调用依次完成并清槽，单次与同时活跃分片均未超上限
- **THEN** 不触发 overflow 拒绝，审计按槽正常放行

#### Scenario: 真实超限仍 fail-closed

- **WHEN** 单个调用分片累计超过 `AUDIT_HOLD_MAX_BYTES`
- **THEN** 拒绝并清理持仓，不透出参数

### Requirement: 截断合成发送成功才置位

系统 SHALL 仅在截断合成帧实际发送成功后置位 `terminal_sent`（及帧计数位）；发送失败（下游已断）时 SHALL NOT 强制置位以掩盖空流合成守门。截断叠加下游早断 SHALL 不悬挂、不 panic，且结果可观测。

#### Scenario: 截断时下游早断

- **WHEN** 截断合成帧发送时下游已断开（`send` 失败）
- **THEN** 泵不悬挂/不 panic，`terminal_sent` 不因发送失败强制置位（`PumpOutcome` 可观测）

### Requirement: 流式审批不挂起声明

系统 SHALL NOT 因 `AUDIT_MODE=approve` 下的危险调用挂起流等待 Matrix 真人审批，SHALL NOT 为此合成阻断帧；危险调用 SHALL 转 pending 记录（审计观测），流 SHALL 继续。Python 原仓审批挂起期独立保活未迁移属显式非目标（见 design），恢复该语义需新 change 交付；README §6.4 为本声明引用源。

#### Scenario: approve 模式不挂起

- **WHEN** `AUDIT_MODE=approve` 且流中危险调用命中 `NeedApproval`
- **THEN** pending 记录建立、流不断链、下游不收到阻断帧
