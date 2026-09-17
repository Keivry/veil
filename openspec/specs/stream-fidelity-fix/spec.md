# stream-fidelity-fix Specification

## Purpose
锁定 LLM 网关三协议（Chat / Anthropic / Responses）流式面修复后的保真契约：默认逐帧增量、审计持有仅在未完成 tool 分片存在时生效、Responses 槽级完成与全局完成隔离、合成终端保序、跨帧占位符缝合还原、中途传输错误可观测与断流终端策略固化、流式上游错误状态透传、审计 hold 字节按槽回收、截断合成发送成功才置位、流式审批不挂起声明。

## Requirements

### Requirement: 默认逐帧增量输出

系统 SHALL 在无未完成审计持有 tool 分片时逐帧放行上游内容帧，SHALL NOT 因流级「未完成」状态（如 `held()=!completed&&!rejected` 在流开始即为真）把整条流缓冲为单帧。持有抑制 SHALL 仅在审计模式非 `off`、确有未完成 tool 分片、本帧非次要事件且有输出三者同时成立时生效；完成事件审计后（含 `NeedApproval` 建单，不阻塞流）相关槽 SHALL 释放出抑制集。keepalive 门控 SHALL 与抑制判据同源：仅存在未完成 tool 分片时抑制保活帧，无未完成分片时保活帧 SHALL 按周期发送。抑制判据中的「有输出」SHALL 以实际放行（emitted）语义为准：本帧未产生可放行输出时 SHALL NOT 触发抑制，SHALL NOT 以取反条件（如传 `!emitted`）作为抑制实参导致抑制/放行极性反转；非空数据帧与零字节/空输出帧的判定 MUST 与 emitted 语义一致。

#### Scenario: 默认配置逐帧到达

- **WHEN** `AUDIT_MODE` 未设（默认 `off`）且 mock 上游慢速分片投递多帧文本
- **THEN** 下游在终止帧前已按帧收到内容（非终止时才一次性拼接），无全流缓冲

#### Scenario: 无分片不抑制

- **WHEN** 审计开启但流中不存在任何未完成 tool 分片
- **THEN** 文本帧逐帧透传，不因 hold 未完成而抑制

#### Scenario: keepalive 门控仅随未完成分片

- **WHEN** 流中无未完成 tool 分片
- **THEN** keepalive 保活帧按周期发送；存在未完成 tool 分片时保活帧被门控抑制

#### Scenario: 抑制极性随 emitted

- **WHEN** 存在未完成 tool 分片但当前帧未产生可放行输出（`emitted` 为假）
- **THEN** 不触发持有抑制；仅在本帧确有未放行输出时才抑制，不出现极性反转导致的错误吞帧

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

系统 SHALL 对跨帧切分的 `__VG_CRED_*__` 与 `__PII_*__` 占位符执行跨帧缝合：帧尾若为占位符合法前缀的残缺形态，SHALL 持有该前缀至下一帧拼接后还原，SHALL NOT 在本帧按残缺剥离而丢失还原。流结束（正常/截断/错误）时仍未配对的残余前缀 SHALL 按既有残缺剥离口径清理，且 SHALL NOT 泄漏原文。凭证与 PII 两类 token 的跨帧切分均 SHALL 覆盖。Anthropic 不透明增量（thinking / signature 等 opaque delta）SHALL NOT 绕过跨帧 token 携带：其中携带的占位符片段 SHALL 与其他文本一样参与跨帧缝合还原；若判定其无法安全缝合，系统 SHALL 显式声明 fail-closed 的不完整还原范围并锁定测试，SHALL NOT 静默原文透出。

#### Scenario: 凭证跨帧缝合

- **WHEN** 上游分两帧发送 `__VG_CRE` 与 `D_000001__`
- **THEN** 下游收到该凭证的还原后明文，无被剥离的残片

#### Scenario: PII 跨帧缝合

- **WHEN** PII token 在帧间被切开（前缀帧 + 续段帧）
- **THEN** 下游收到该 PII 的还原后明文

#### Scenario: 流末残余前缀剥离

- **WHEN** 流结束时仍有无法配对的占位符残缺前缀
- **THEN** 该前缀被剥离，输出不含原文泄漏

#### Scenario: opaque thinking 增量参与缝合

- **WHEN** Anthropic thinking/signature 等 opaque 增量在帧间被切开并携带占位符片段
- **THEN** 该片段参与跨帧缝合还原，不绕过跨帧携带

#### Scenario: 无法缝合时显式 fail-closed

- **WHEN** opaque 增量中的占位符片段无法安全缝合
- **THEN** 按声明的 fail-closed 范围处理（不泄漏原文），行为由测试锁定

### Requirement: 中途传输错误可观测

系统 SHALL 在流式上游 `chunk()` 返回 `Err` 时记录 warn 日志与截断观测（`truncated_mode` 与指标），SHALL NOT 静默按正常 EOF 退出。

#### Scenario: mid-stream 断连可观测

- **WHEN** mock 上游在已发送部分帧后连接中断（`chunk()` 报错）
- **THEN** 日志含截断告警、截断观测被记录，流按协议终端策略收尾而非静默结束

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

### Requirement: 流式上游错误状态透传

系统 SHALL 在流式请求的上游响应 `status>=400` 或 `content-type` 非 `text/event-stream` 时，透传上游状态码与正文字节（与非流路径语义一致）；SHALL NOT 不看状态码一律转入 SSE 泵并恒定回 200。README §7.2 SHALL 同步该透传口径。

对进入 SSE 泵的上游 2xx 响应（`status < 400` 且 `content-type` 为 `text/event-stream`），下游流式响应 SHALL 逐字携带上游的 2xx 原状态码（如 `201`/`202`/`206`），SHALL NOT 硬编码改写为 `200`；`<400` 的入泵门控 SHALL NOT 放宽。

#### Scenario: 500 JSON 错误体

- **WHEN** `stream:true` 请求上游返回 500 且正文为 JSON
- **THEN** 下游收到 500 与同一 JSON 正文字节

#### Scenario: 500 HTML 错误体

- **WHEN** 上游返回 500 且正文为 HTML（非 `text/event-stream`）
- **THEN** 下游收到 500 与同一 HTML 正文字节，不被改写为 200 SSE

#### Scenario: 2xx 非 200 状态透传

- **WHEN** 上游以 `status < 400` 且 `content-type: text/event-stream` 进入 SSE 泵，状态码为 `201`/`202`/`206` 之一
- **THEN** 下游流式响应携带上游原 2xx 状态码（不被改写为 `200`），流式正文字节不变

### Requirement: 审计 hold 字节按槽回收

系统 SHALL 按槽记账审计持有字节，并在槽完成/清理时回收：Chat/Anthropic 的槽清理（`clear_index`）、Responses 的 per-item `done` 槽审计清理、`mark_completed`/`mark_rejected` SHALL 归还对应字节。长流多工具调用 SHALL NOT 因累计不回收而误判溢出 fail-closed；真实超限 SHALL 仍拒绝并清仓。hold 记账 SHALL 同时施加条目数（或零字节分片计数）维度上限，SHALL NOT 仅按累计字节计数；零字节分片（`output_item.added`、空 `function_call` 等不计 `total_bytes` 的碎片）SHALL 同样受限，使零字节分片洪泛下内存有界。条目数超限 SHALL 与字节超限同样 fail-closed 并清仓。

hold 的字节记账（累计 `total_bytes`、待定帧字节计数及归还）SHALL 使用饱和算术（`saturating_add`/`saturating_sub`）；SHALL NOT 以裸 `+=`/`-=` 在 `u64`/`usize` 上累加/归还致溢出回绕，SHALL NOT 在接近类型上界时 panic。与 `stream-protocol-parity`「hold 放行保持 sequence_number 相对序」同源同义（措辞 MUST NOT 漂移）：`src/service/audit/hold.rs::push_responses_fragment` 内 `slot.next_seq + 1`、`.max(seq_no + 1)` 与 `total_bytes +=` 三处裸算术 SHALL 全部饱和化——不回绕、不 panic、不复用 `BTreeMap` 键；上游 `seq_no == u64::MAX` 的极值入参分支 SHALL 由单元测试显式锁定。饱和后的超限判定 SHALL 仍按既有语义 fail-closed 并清仓。

#### Scenario: 长流多工具不误判溢出

- **WHEN** 长流中多个 tool 调用依次完成并清槽，单次与同时活跃分片均未超上限
- **THEN** 不触发 overflow 拒绝，审计按槽正常放行

#### Scenario: 真实超限仍 fail-closed

- **WHEN** 单个调用分片累计超过 `AUDIT_HOLD_MAX_BYTES`
- **THEN** 拒绝并清理持仓，不透出参数

#### Scenario: 零字节分片洪泛有界

- **WHEN** 上游洪泛零字节 tool 分片（不增加累计字节）
- **THEN** 条目数维度上限生效，hold 内存有界并 fail-closed，不无界增长

#### Scenario: 字节记账饱和不溢出

- **WHEN** 审计 hold 的累计字节接近类型上界并继续累加（含归还后再累加），或某槽 `sequence_number` 达 `u64::MAX` 推进保序游标
- **THEN** 记账饱和（不回绕为小值、不 panic、不复用 `BTreeMap` 键），`seq_no == u64::MAX` 极值分支由单元测试锁定，超限判定仍按既有语义触发 fail-closed 并清仓

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

### Requirement: SSE 解析器无效字节单调消费与缓冲有界

系统 SHALL 在 SSE 解析接收任意字节（含非法 UTF-8 序列）时保证消费位置单调前进（`push` 后已消费偏移不后退、不原地停滞），遇无效序列 SHALL 按替换语义（对齐 Python `errors='replace'`：以替换字符或等价方式消费该无效片段）继续推进，SHALL NOT 因 `valid_up_to` 不前进而使解析器永久卡死（wedge）或待处理缓冲无界增长。跨行文本携带（text_carry）与解析缓冲 SHALL 有总字节上限，超限 SHALL 按有界策略处理（截断/丢弃并计数），SHALL NOT 无界累积。流末（EOF）残余字节 SHALL 按同一替换语义处理，SHALL NOT 仅在 EOF 一次性做 lossy 解码而掩盖中途停滞。

#### Scenario: 无效字节后继续解析

- **WHEN** 上游在数据流中投递一段非法 UTF-8 字节序列后继续投递合法事件
- **THEN** 解析消费该无效序列（替换语义）并继续处理后续事件，不卡死、不丢后续事件

#### Scenario: 无效字节不无界累积

- **WHEN** 上游持续投递非法 UTF-8 字节且不发送行终止
- **THEN** 待处理缓冲受总字节上限约束，达上限后有界处理并计数，不发生无界内存增长

#### Scenario: text_carry 有总上限

- **WHEN** 单个事件的数据行被切分且跨行携带字节累计超过总上限
- **THEN** 超限部分按有界策略处理并计数，text_carry 不无界增长

#### Scenario: EOF 残余按替换语义

- **WHEN** 流在非法或截断的多字节序列中途结束
- **THEN** 残余按替换语义处理，不停滞、不 panic

### Requirement: 客户端断连中止上游读取并回收泵任务

系统 SHALL 在下游客户端断开时终止对上游流的读取，SHALL NOT 在内层跳出后仍由外层循环继续拉取 `chunk()`；断连时 SHALL 通过取消令牌或 JoinHandle 监视回收泵任务，SHALL NOT 让泵任务脱离（detach）后继续占用上游连接。断连中止 SHALL NOT 破坏终端恰一语义：既定的终端判定与收尾保持一致，SHALL NOT 因中止产生重复或缺失的终端帧；中止 SHALL 可观测。

#### Scenario: 断连中止上游读取

- **WHEN** 下游在流中途断开而上游仍可继续投递
- **THEN** 网关停止从上游读取，上游连接被关闭/中止，不再拉取后续 chunk

#### Scenario: 泵任务被回收

- **WHEN** 客户端断开触发中止
- **THEN** 泵任务进入回收/取消路径而非永久 detach，运行期无任务泄漏

#### Scenario: 终端恰一不被破坏

- **WHEN** 客户端在终端帧之前断开
- **THEN** 不产生重复终端帧，也不因中止新增终端

### Requirement: 输出攒批生效或声明

`Speed::Fast` 攒批模式 SHALL 在满足边界条件时实际合并相邻输出为更少帧（可观测为下行帧数减少）；若该模式被判定为不再使用，系统 SHALL 显式声明其停用并移除恒不生效的死分支，SHALL NOT 保留恒不生效的死逻辑。攒批 SHALL NOT 改变输出字节内容与终端恰一语义。

#### Scenario: Fast 攒批实际生效

- **WHEN** 连续输出满足攒批边界条件
- **THEN** 输出以更少的合并帧下发，且内容逐字节等价

#### Scenario: 未启用时不攒批

- **WHEN** 非 Fast 模式
- **THEN** 输出逐产出下发，不合并

#### Scenario: 停用需显式声明

- **WHEN** `Speed::Fast` 判定为死分支而删除
- **THEN** 规范显式声明其停用，不存在恒不生效的保留分支

### Requirement: SSE 注释帧保真

系统 SHALL 在 SSE 解析与出口中对注释行（以 `:` 起始，含块内注释与行内注释）保持保真：SHALL NOT 丢弃注释内容，SHALL NOT 把同一块内的注释拆分或额外合并为独立多余事件。注释 SHALL NOT 改变数据事件的字段归属与计数口径。

#### Scenario: 块内注释不丢失

- **WHEN** 上游在同一块内发送注释行与数据行
- **THEN** 注释被保真透传，未被丢弃

#### Scenario: 首注释不被拆分

- **WHEN** 块首为注释行
- **THEN** 该注释不成为独立多余事件，也不与后续数据错配

#### Scenario: 行内注释保真

- **WHEN** 注释出现在事件行之后
- **THEN** 注释内容按原样透出，不影响数据事件归属

### Requirement: SSE 事件计数口径一致

系统 SHALL 对 SSE 事件计数采用统一口径：解析读取计数与运行时指标计数（如 `add_sse_event`）SHALL 一致；审计 hold 阻断等路径注入的合成帧 SHALL 被纳入计数，或被显式声明排除且该声明与实现一致，SHALL NOT 出现「只读计数与生产指标口径不一致」。

#### Scenario: 注入帧纳入计数

- **WHEN** 阻断路径注入合成 SSE 帧
- **THEN** 事件计数按统一口径包含该注入帧

#### Scenario: 计数口径一致

- **WHEN** 同一上游流分别经解析读取计数与运行时指标计数
- **THEN** 两口径结果一致，或排除项被显式声明且与实现一致

### Requirement: 多行 data 按 WHATWG 连接

系统 SHALL 将同一事件内多条 `data:` 行按 WHATWG SSE 规范以单个 `\n` 连接后作为一个事件的 data 处理，SHALL NOT 把多行 data 压平（flatten）为单行或以其它形态丢失行边界。空 `data` 行 SHALL 按空字符串参与连接。

#### Scenario: 多行 data 连接

- **WHEN** 同一事件含 `data: a` 与 `data: b` 两行
- **THEN** 事件 data 为 `a\nb`（以单个 `\n` 连接）

#### Scenario: 空 data 行参与

- **WHEN** 连接序列中包含无冒号或空的 data 行
- **THEN** 该空值按规范参与拼接

#### Scenario: 单行 data 不变

- **WHEN** 事件仅含一行 data
- **THEN** data 不被追加换行

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
