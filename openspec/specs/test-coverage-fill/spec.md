# test-coverage-fill Specification

## Purpose
锁定测试补齐后的可验证契约：流泵关键决策点有直接单测（含纯函数真值表与泵直测）、三个薄弱 e2e 断言厚度提升、真 SDK 一致性脚本纳入显式 gate、可观测性测试粒度恢复到 model/upstream/series/SSE 快照维度、Go `get` 请求形状的网关侧行为有 Rust 契约锁定、零直接覆盖文件与零禁用测试有登记。契约只约束测试资产与门禁，不改变任何生产语义。

## Requirements

### Requirement: 泵关键决策点直接单测

系统 SHALL 为 `src/handler/llm/pump/spawn.rs` 主循环的 7 个关键决策点提供**直接**单元测试：终止判定、N1 守卫、P1 补 DONE、空流守门、边界 hold 释放、tool hold-until-complete、rejected_sticky 抑制。系统 SHALL 将主循环内联布尔判定抽为无 IO 纯函数（`decide.rs`，`pub(super)`），使每个决策点可用真值表直接断言；SHALL 在 `spawn_tests` 模块中以泵直测覆盖至少「恰一终端」「P1 补发」「hold 释放」「sticky 抑制」四类组合行为。抽取 SHALL 为等价重构，既有 `stream_tests`/`proto_closeout_tests`/`http_e2e_truncation_matrix` 全绿为锁定条件；SHALL NOT 降低既有间接覆盖。

#### Scenario: 泵恰好一终端的直接单测

- **WHEN** 以 `response.completed` 后跟 `type:"error"` 或 `response.incomplete` 的序列驱动 `spawn_stream_pump`
- **THEN** 下游帧序列断言终端恰一（`response.completed`），无后续数据帧/合成 `response.failed`，且该断言不经由 `proto_closeout_tests` 的间接路径、而是通过 `decide::responses_control_action` 真值表 + 泵直测双重锁定

#### Scenario: P1 补发条件真值表

- **WHEN** 对 `should_backfill_chat_done` 输入协议、`terminal_sent`、`saw_finish_reason`、`truncated_mode` 已置四维组合
- **THEN** 仅「Chat 且未终端且见 `finish_reason` 且未截断」为真，其余组合为假；泵直测断言补发后 `[DONE]` 恰一且 `finish_reason` 后的 usage 尾帧保留

#### Scenario: hold-until-complete 缓冲与重放

- **WHEN** 审计开启且收到未完成 tool 分片，随后收到同槽/index 完成帧
- **THEN** 真值表断言 `should_buffer_tool_frame` 仅对「审计开、tool 事件、未完成、非 index 完成」为真；泵直测断言残缺分片不达下游、完成时按到达序重放且槽号路由正确（`tool_replay_slot` 全集/单槽/无槽三分支）

#### Scenario: rejected_sticky 抑制与边界释放

- **WHEN** 阻断已粘滞（`rejected_sticky=true`）后继续到达 `[DONE]`、终端帧、tool 分片、完成事件与普通文本帧
- **THEN** 真值表断言 `sticky_suppress_action` 对前四类 Drop、普通文本 Pass；泵直测断言边界 hold 在终端帧处释放（不吞最后一帧）、阻断后无 tool 帧透传

### Requirement: 薄弱 e2e 断言厚度提升

系统 SHALL 提升三个薄弱 e2e 的断言密度：`t3_1_pii_100_concurrent_restore_isolated_no_crosstalk` SHALL 具备请求级校验与全对串扰矩阵；`b5_snapshot_shape_matches_series_and_empty_window_ok` SHALL 断言字段类型、取值与 series 一致性；`t2_1_nondialog_models_passthrough_with_count_and_no_side_effects` SHALL 断言计数递增、hop 过滤与零副作用。SHALL NOT 改变 `CONCURRENCY=100`、120s 超时预算与 mock 拓扑，SHALL NOT 引入时序性断言。

#### Scenario: PII 100 并发逐请求校验

- **WHEN** 100 路并发非流请求各自携带本路唯一号码经网关到回声上游
- **THEN** 每路断言状态码 200、本路号码已还原、本路占位符形态经本路 scope 还原；对全部 i≠j 断言第 i 路体不含第 j 路号码（100×99 全对矩阵）；并断言 `/_admin/metrics` 的 `requests==100`

#### Scenario: 快照形状与取值

- **WHEN** seed 已知用量后读取 `/_admin/metrics` 与 `/_admin/series`（daily/hourly/five_min）
- **THEN** 断言 `ok`/`requests`/`is_precise`/`sse_events`/`ring_len`/`dropped` 的类型与取值，`tokens` 六列、`truncated` 三 mode、`per_protocol`/`per_model` 的行结构；且 series 行求和与快照 `requests`/`total` 一致；空窗快照为零值而非缺字段

#### Scenario: NonDialog 透传计数与无副作用

- **WHEN** 连续三次 `GET /v1/models` 经 NonDialog 臂透传
- **THEN** 断言下游体与上游原文逐字节一致、计数 1→2→3 递增、hop 过滤计数方向正确、无用量（`requests==0`）、无审计事件、无凭据/PII 占位符注入、状态码与 `content-type` 不被改写

### Requirement: 真 SDK 脚本纳入门禁

系统 SHALL 为 `scripts/api_conformance.py`（23 项：14 常规 + 3 阻断 + 5 取用 + 1 无库 503）提供显式 gate 步骤（`scripts/gate.sh` 或等价可执行步骤），串联格式化、lint、单测、文档路径校验、文件大小校验与真 SDK 一致性；SHALL 声明前置条件（Python venv、SDK pin `openai==3.5.0`/`anthropic==1.1.0`、Mock TPM 回退）与失败非零退出语义；缺前置时 SHALL 显式报错或经参数显式跳过并打印理由，SHALL NOT 静默跳过。SHALL 保留脚本口径，SHALL NOT 改写为 cargo 测试。

#### Scenario: gate 步骤可执行且失败非零

- **WHEN** 在具备前置条件的环境执行 gate
- **THEN** 六步全绿退出码 0；真 SDK 脚本输出「共 23 项，失败 0 项」；任一子步骤失败即整体非零退出

#### Scenario: 前置条件与显式跳过

- **WHEN** Python venv/SDK 缺失时执行 gate
- **THEN** 以显式前置条件错误退出，或经显式参数跳过并在输出打印跳过理由与 doc 链接；不出现无输出的静默跳过

#### Scenario: 文档口径同步

- **WHEN** 查阅 README §8.5 与 `scripts/README.md`
- **THEN** 命中「已纳入 gate 步骤 + 前置条件 + 跳过语义」表述，且本仓口径为真 SDK 脚本 23 项（14 常规 + 3 阻断 + 5 取用 + 1 无库 503）；README §8.5 的 23 项明细与脚本输出一致，原仓 12 项（cargo）对照标签不与之冲突

### Requirement: 可观测性测试粒度恢复

系统 SHALL 按新 API 语义恢复可观测性测试粒度：SSE 建连 `?model=&upstream=` 的实际筛选 SHALL 有 e2e；metrics/events 旧 `?model=&upstream=` 的「忽略过滤 + deprecated 标注」口径 SHALL 有 e2e；series 旧 `range=1h/24h/7d/30d` 四档映射 SHALL 逐档有 e2e 并与同窗新口径等价；SSE 快照形状（`sse_events` 计数与字段类型）SHALL 有显式断言。

#### Scenario: series 旧 range 四档映射

- **WHEN** 以同一 seed 窗分别请求 `range=1h`、`24h`、`7d`、`30d`
- **THEN** 四档分别断言 `granularity` 为 `five_min`/`hourly`/`daily`/`daily`、附 `deprecated` 标注，且 points 与同窗新口径逐点等价；未知 range 行为与既有单测口径一致

#### Scenario: model/upstream 筛选

- **WHEN** 以 `/_admin/events/stream?model=&upstream=` 建两条流并注入命中/未命中事件，或以 `/_admin/metrics?model=&upstream=` 查询
- **THEN** SSE 命中流收到事件、未命中流零事件、双条件取交集、空值不过滤；metrics/events 旧参数返回 deprecated 标注且结果与全局口径一致

#### Scenario: SSE 快照形状与计数

- **WHEN** 消费一条 mock SSE 流后读取 `/_admin/metrics`
- **THEN** 断言 `sse_events` 相对基线精确增加（等于下游收到帧数）、`per_protocol` 对应行存在、`truncated`/`chat_tail_lenient`/`is_precise` 类型与取值符合契约

### Requirement: Go 请求形状契约锁定

系统 SHALL 以镜像 Go `get` 请求形状的 Rust 集成/契约测试锁定网关侧行为：纯 body POST 无三因子头、三因子齐全/缺失矩阵、三协议阻断流终止；SHALL 在测试与 change 文档中显式声明真机 Go 闭环仍由 `veil-hardening` 5.1–5.3 承接；SHALL NOT 修改 `veil-hardening` 任何文件。

#### Scenario: Go 形状直连行为锁定

- **WHEN** 以 Go `FetchCredential` 形状（纯 body、无 `X-Get-Binary-Hash`/`X-Get-Binary-Secret` 头）请求 `POST /credential`
- **THEN** 断言 403 且错误体为 `{"error":{"code":...,"message":...}}` 对象（`error` 非 string），锁定 Go 侧不可直接解析的根因契约

#### Scenario: 三因子齐全/缺失矩阵

- **WHEN** 依次以齐全（头体一致）、缺哈希头、缺密钥头、缺 `body.auth.*`、`caller_hash==GET_BINARY_HASH` 五种形状请求
- **THEN** 齐全为放行或转审、缺失各为 403 明确诊断、冒用为 403；全程无空响应或挂起

#### Scenario: 三协议阻断流终止

- **WHEN** 以 `AUDIT_MODE=block` 与极小 hold 上限触发三协议阻断
- **THEN** chat 恰一 `data: [DONE]` 且含 `[blocked:`、anthropic 含 `message_stop`+`content_block_stop`、responses 含 `response.failed`，且即时闭合（无重试/挂起断言）

### Requirement: 覆盖登记与禁用测试为零

系统 SHALL 在 design.md 登记零直接覆盖文件清单与可接受理由（覆盖来源计数），并 SHALL 保持 `#[ignore]`/禁用测试为 0。

#### Scenario: 零直接覆盖文件登记

- **WHEN** 查阅 design.md 记录项
- **THEN** 命中 `sse/emit.rs`/`meta.rs`/`parser.rs`、`block_inject/frames.rs`/`terminal.rs`、gateway 面 facade 清单及上层覆盖计数（`sse.rs` 30 项、`block_inject.rs` 24 项；apply 实测）与「可接受」判定

#### Scenario: 禁用测试为零

- **WHEN** 执行 `grep -rn "#\[ignore" src/ tests/` 与 `cargo test -- --list`
- **THEN** 无 `#[ignore]` 属性命中（仅注释文本），测试清单无 ignored 条目
