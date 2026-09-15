## Context

本 change 是 2026-09-15 独立六维审计（12 项并行审计 + 编排者复核）的整改规划，全部发现登记与修复落点以 `proposal.md` 的「发现覆盖表」为唯一事实源（本 change 自包含，不依赖仓外文档）。相较 2026-09-14 首轮审计，本轮把范围从「运行时可靠性」扩展到协议保真、脱敏、审计策略、凭据/注册、管理面、架构与文档/测试全维度。

**审计范围与编排者复核**：12 项并行审计覆盖 P0/P1/P2/P3 与外部仓库伴生缺陷；对四项最高风险断言由编排者独立复核：

- `src/service/pii/chunk.rs:213-215`（同步 `scan_builtin_sync`）与 `:274-276`（异步 `scan_builtin`）上下文窗口裸字节切片，已用 `rustc` 复现 `byte index 2 is not a char boundary`（调用链 `src/service/pii/rewrite.rs:54`），请求级可远程触发 panic（DoS）。
- `src/handler/llm/pump/event_loop.rs:571-577`（`:573` 传 `!emitted`）的极性反转经 git 证实：`60620c3` 原为 `!out_data.is_empty()`，重构后语义反转（语义源 `decide.rs:118-125`、`frame_feed.rs:72-116`）。
- 自定义 PII 规则生产零接线经三方交叉确认：`load_custom_all` 全仓仅定义（`custom.rs:272`）+ 测试调用（`custom/tests.rs:276`）；`Config.pii_custom_*_file` 仅测试读取；`main.rs` 无 custom 引用。
- `src/state.rs:76` 注册表加载失败被 `.unwrap_or_default()` 静默吞为空表（`store.rs:193-208` 的 `load_from` 本身正确返回 Err）。

**基线事实**：Rust `494f2bc` 全绿门禁——`bash scripts/gate.sh` 六步全绿（fmt / clippy `--tests --all-targets -D warnings` / cargo test / `check_doc_paths.py` / `check_file_sizes.py`（142 文件 ≤800 行）/ 真 SDK conformance 23/23）；`openspec validate --all --strict` 基线 91/0；真 SDK 23 项 = 14 常规 + 3 阻断 + 5 取用 + 1 无库 503；Python 对照 `df1b523`。

**三条 RE-OPENED 残留及其再开启原因**（属「修复不完整」，非「再回归」，须在 change 说明中显式记录）：

- `POL-6` 判 partial——裸 `curl/wget <host>` 外传分支缺失（`src/service/audit/rules.rs:317-347` vs Python `_audit.py:787-813`），由 `APP-2` 收口。
- `RED-1` 判 partial——非流臂未做内层 stringified-JSON 校验、`collect_token_depths` 不扫对象 key（`src/handler/llm/nonstream.rs:264`、`src/service/pii/scope.rs:459-463`），由 `NLP-3`/`NLP-4` 收口。
- `RUN-4` 判 partial——`upstream_read_errors`/`admin_rate_evicted`/`aggs_evicted` 只累加不输出（`src/service/llm_gateway/mod.rs:184-197`、`src/handler/admin.rs:286-310`），由 `OPS-1` 收口。

**约束**：本 change 只写规划 artifacts，不改 `openspec/specs/`（canonical）、`src/`、`tests/`、README；不新增依赖；不启动实现；任务中的代码改动是给 apply 阶段的指令。规范约束以 canonical spec 名称引用（如 `openspec/specs/stream-fidelity-fix/spec.md`、`openspec/specs/stream-protocol-parity/spec.md`、`openspec/specs/llm-protocol-hardening/spec.md`、`openspec/specs/redaction/spec.md`、`openspec/specs/credential-flow-parity/spec.md`、`openspec/specs/observability-admin/spec.md`、`openspec/specs/runtime-reliability/spec.md`、`openspec/specs/config-legacy-compat/spec.md` 等），不在此转述 spec 文本。

## Goals / Non-Goals

**Goals：**

- 为全部登记发现（1 条 P0、8 条 P1、35 条 P2、约 45 条 P3 与 4 条外部仓库缺陷）给出可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把最高风险项（远程 panic、解析器卡死、极性反转、审计绕过、自定义 PII 失效）收敛为 spec 契约，并保持既有对外语义（除显式 BREAKING 项外）逐字不变。
- 记录关键决策（切片策略、取消原语、上限口径、契约形态、波次排序）及其备选，供实现与复核对照。
- 以单一 change 覆盖 P0→P3 全部波次，使修复、测试、文档与门禁按同一证据链归档。

**Non-Goals：**

- 不追求「零误报」：脱敏/审计判定维持「误报优于漏审」，裸 host 外传、自定义 PII 接线等会新增命中，属预期。
- 不改已声明为「有意差异」的行为（如 IP 字面量一律非内网、请求级 PII 隔离、capacity 分表、`PII_HOLD_MAX` 语义映射）。
- 不承诺跨实现值一致（如 PII 序号值），不承诺未登记项。
- 不重构对外接口的既有语义（除 `allow_mode` 词汇、`OBSERVABILITY_DISABLE` token 语义、紧急吊销 token 源等显式 BREAKING 项）。
- 不在本仓实施外部仓库（Python `credential-proxy`、Go `get`）的伴生修复，仅登记与规划。
- 不提交 commit、不运行 `openspec validate`（由编排者终验）。

## Decisions

### 决策组 A：P0 与流式解析健壮性

#### D1：上下文窗口切片改为「字符边界安全」而非「失败即回退跳过」（`APP-1`）

**决策**：`src/service/pii/chunk.rs:213-215` 与 `:274-276` 两处窗口切片改用字符边界安全切片——优先用 `floor_char_boundary`/`ceil_char_boundary` 把窗口起止点对齐到最近字符边界（保持窗口语义与检出覆盖不变），或以 `get(cs..ce)` 回退到「触界即缩窗」；两者不得 panic。补多字节 UTF-8 跨界回归测试（含 `62/60/3[47]/[45]` 前缀与多字节字符紧邻场景）。

**理由**：`bank_card` 窗口在 Luhn 校验之前切片，前缀形态即可触发；热路径 panic 是请求级 DoS，必须从根上消除（不 panic），而非靠放宽前缀匹配掩盖。字符边界对齐保持精确率（不丢跨窗命中），仅边界点微调。

**备选**：① 仅 `get()` 回退并在 `None` 时跳过本窗——最简单但会漏掉「多字节字符恰跨窗」的少量检出，精确率下降；② 对输入先做 ASCII 归一——改变原文语义、破坏还原，不采用；③ 在 window 外先 `char_indices` 建索引——等价但每请求额外分配，热路径成本高，不采用。

#### D2：解析器消费无效 UTF-8 序列，保证 push 单调前进（`STP-2`）

**决策**：`src/service/sse/parser.rs:29-48` 在 `from_utf8` 返回 `error_len().is_some()`（真无效字节）时消费该无效序列（对齐 Python `errors='replace'`：替换字符或跳过），使 `valid_up_to` 每轮前进；`text_carry`/缓冲补总上限；EOF 残余按同一替换策略处理。补无效字节 + 无限流回归测试。

**理由**：当前无效字节时 `valid_up_to` 不前进 → 解析器永久卡死、缓冲无界增长，EOF 一次性 `from_utf8_lossy` 又产出乱码。消费无效序列是最小改动即可恢复单调前进，且与 Python 判定对齐。

**备选**：① 跳过整段不可解析前缀——可能丢合法尾随字节，与 Python 不对齐；② 遇到无效字节即关闭连接——把畸形输入升级为断流，与容错目标冲突；③ 保存原始字节绕开 UTF-8 校验——破坏下游文本处理与还原，不采用。D2 只解「卡死」，D1 只解「panic」，二者边界互不覆盖。

#### D3：泵取消采用取消令牌 + JoinHandle 监视，客户端断开即中止上游读取（`STP-3`/`ARH-1`）

**决策**：`src/handler/llm/pump/event_loop.rs:104-114`（`BreakFor` 仅 break 内层、外层 while 继续 `chunk()`）与 `src/handler/llm/dispatch.rs:254/298`（`let _pump=` detach JoinHandle）改为：外层循环感知取消（`tokio_util::sync::CancellationToken` 或等价 `watch`/`Notify` 原语），客户端断开时置取消、中止上游读取并回收泵任务；保持终端恰一语义不变；补「断连后上游连接被关闭」回归测试。若引入取消令牌需评估依赖可行性——优先复用既有 tokio 原语，不新增外部依赖。

**理由**：detach + 仅 break 内层导致断连后上游连接与泵任务泄漏，长流下资源累积。取消令牌显式贯通内外层，JoinHandle 监视保证任务回收可观测，语义最小。

**备选**：① 仅监视 JoinHandle 并 `abort()`——`abort` 点不确定，可能在写终端帧中途取消，破坏「终端恰一」；② Drop-based 取消（guard drop 触发）——隐式且与现有 `let _pump=` 生命周期耦合，时序难验证；③ 依赖 `Body` 流被下游 drop 自然终止——当前正是此路径失效根因，不采用。

#### D4：极性修正为 `emitted`，并以改名纪律使误用不可发生（`STP-4`/`MSP-1`/`RSP-1`）

**决策**：`src/handler/llm/pump/event_loop.rs:571-577` 的 `should_suppress_held_output` 实参由 `!emitted` 改为 `emitted`；同时按语义重命名相关形参/局部（使「传取反值」在类型或命名上不可误写），并补三协议 held 输出抑制/放行回归测试（含 held 非空 + 无数据帧场景）。语义以 `decide.rs:118-125`（`out_data_nonempty`）与 `frame_feed.rs:72-116`（返回 `emitted`）为准。

**理由**：这是热路径上的静默语义反转，仅修实参易再被重构回归；改名纪律把「语义即变量名」固化，降低复发概率。

**备选**：① 仅改实参不加改名——最小改动但无防复发；② 把判定内联到调用点——分散逻辑、测试面变窄；③ 反转 `should_suppress_held_output` 内部语义——会污染其它调用点，不采用。

#### D5：Responses 缺 per-item `.done` 的槽在全局完成时「先审后放」（`STP-1`/`RSP-2`）

**决策**：`src/handler/llm/pump/hold.rs:203-215` 的 `responses_triples` 仅认 `done_seen`；`event_loop.rs:301-324` 全局完成路径对 `tool_replay_slot(Some(None))` 直接重放；`terminal.rs:115-142` 终审同样排除非 done 槽。修复：全局完成路径对 `!done_seen` 槽按**已累积参数先审计判定再放行**（Block 则筛除/阻断），并补「缺 per-item done + 危险参数」回归测试。语义与逐-item done 路径一致（per canonical `openspec/specs/stream-protocol-parity/spec.md`）。

**理由**：现测总在 `response.completed` 前发 `.done`，故绕过未被覆盖；真实上游可直接进全局完成，造成 block 模式审计绕过。先审后放把两条路径收敛到同一判定。

**备选**：① 全局完成时不重放非 done 槽（直接丢弃）——会丢用户内容，不可接受；② 强制要求上游补 `.done`——网关无法控制上游；③ 仅在 `terminal.rs` 补审——重放已先发生，绕过仍存在。

#### D6：hold 增加条目数与零字节分片计数维度（`STP-5`）

**决策**：`src/handler/llm/pump/hold.rs` 在字节上限（默认 `AUDIT_HOLD_MAX_BYTES`）之外，为 hold 增加**条目数上限**与**零字节分片计数**维度（`output_item.added`/空 `function_call` 不计 `total_bytes`），使零字节分片洪泛同受约束；补「零字节分片洪泛 → 内存有界」回归测试。

**理由**：仅按字节计，零字节分片可不触发 8MB 上限却无限累积条目，内存无界。

**备选**：① 仅给零字节分片计 1 字节——近似但阈值语义模糊；② 硬上限仅条目数不管字节——大参数仍可爆内存；③ 不设条目上限依靠采样——不可控。

#### D7：截断残余帧按 Python 丢弃半帧，不二次加 `data:` 前缀（`CHC-2`）

**决策**：`src/handler/llm/pump/terminal.rs:209-238` + `frame_feed.rs:72-86` 的残余处理对齐 Python `_llm.py:2718-2720`：丢弃半帧（或先剥离已存在的 `data:` 前缀后再判定），避免把裸残余二次加 `data:` 前缀转发导致下游 `JSONDecodeError`；补「残余帧」回归测试（含 CR-only）。

**理由**：当前对截断残余再次加 `data:` 前缀，产出非法 SSE 载荷；Python 直接丢弃残余，语义简单且下游安全。

**备选**：① 对残余做 JSON 修复后转发——伪造内容、违反保真；② 转发但不加前缀——仍可能被下游当非法行；③ 仅在 CR-only 时特殊处理——覆盖不全。

#### D8：合成 chat 流帧补齐 `id/object/created/model` 与单调 `sequence_number`（`CHC-3`/`RSP-3`）

**决策**：`src/service/block_inject/frames.rs:29-38` 的合成 chat 流帧补齐 `id`/`object`/`created`/`model`（取自会话上下文或稳定默认值）；`:94-125` 的全部 7 帧合成帧补单调 `sequence_number`。补 SDK 解析/结构回归测试。

**理由**：缺字段与缺 `sequence_number` 使严格 SDK 解析失败；Python 亦缺但属规范缺口，本仓补齐不改变阻断语义。

**备选**：① 保持缺失并声明——SDK 兼容性下降；② 由上游字段透传——阻断帧是网关合成，无上游来源；③ `sequence_number` 每帧从 0 重开——违反单调，SDK 可能拒收。

#### D9：合成 `response` 对象补齐必需字段，并移除 conformance try/except 掩盖（`RSP-4`）

**决策**：`src/service/block_inject/frames.rs` 的合成/阻断 `response` 对象补齐必需字段（`output`、`status` 等），使 SDK `get_final_response().output_text` 不再抛 `TypeError`；`scripts/api_conformance.py` 去掉 try/except 掩盖或加显式断言。补 SDK 可解析回归测试。

**理由**：当前 conformance 的 try/except 把「SDK 抛错」吞掉，掩盖了真实缺陷；补齐字段 + 去掩盖使门禁恢复真实信号。

**备选**：① 仅去 try/except 不补字段——门禁转红暴露缺陷但不修；② 仅补字段不去掩盖——未来回归仍被吞；③ 用最小 `response` 只保 `output`——其余字段缺失仍可能抛错。

### 决策组 B：非流与传输

#### D10：`looks_sse` 分支前置 `status < 400` 守卫（`NLP-1`）

**决策**：`src/handler/llm/nonstream.rs:113-126`（`looks_sse` 判定在 status 检查前）与 `src/handler/llm/pump/event.rs:29-31`（`build_sse_response` 硬编码 200）改为：`looks_sse` 分支前置 `status < 400` 守卫，错误状态一律走错误体透传（状态码与正文字节保留），不再合成 200 SSE。对照 `dispatch.rs:243` 流式分支已有 `status>=400` 守卫、Python `_llm.py:6127-6135` 保留上游状态码。补上游 4xx/5xx + SSE content-type 回归测试（per canonical `openspec/specs/nonstream-audit-align/spec.md`）。

**理由**：把上游 4xx/5xx 改写为 200 假流会掩盖错误，与流式分支口径不一致。

**备选**：① 仅在 `looks_sse` 命中且 status>=400 时加标记——仍合成 200；② 改为 `status == 200` 才进 SSE——过窄，2xx 非 200（如 201）被误判（另见 NLP-6 边界）；③ 完全移除 `looks_sse` 合成——破坏正常 SSE 非流回包处理。

#### D11：非流错误体同样有界读（`NLP-5`）

**决策**：`src/handler/llm/nonstream.rs:130-159` 的 `status>=400` 错误体 `up.bytes()` 无界读改为有界读（超限截断或流式转发，内存安全），状态码与正文语义不变；补大错误体回归测试（per canonical `openspec/specs/transport-fidelity-fix/spec.md`）。

**理由**：TRN-3 的有界读只覆盖非错误臂，错误臂仍可被巨大 4xx/5xx 体打爆内存。

**备选**：① 对错误体套 `NONSTREAM_MAX_BYTES` 并 502——违反「错误体按透传语义不改写」；② 只记录 warn 不约束——内存风险仍在；③ 流式转发错误体——增加复杂度且改变既有读取形态。

#### D12：非流还原守卫升级为与流式同一嵌套校验（`NLP-3`）

**决策**：`src/handler/llm/nonstream.rs:264` 仅外层 `from_str` 的守卫升级为与流式 `src/handler/llm/pump/frame_feed.rs:45-68` 同一守卫（内层 stringified-JSON 递归校验）；`collect_token_depths`（`src/service/pii/scope.rs:459-463`）纳入对象 key；补内层破损 JSON 非流回归测试（per canonical `openspec/specs/redaction-audit-coverage/spec.md`）。

**理由**：RED-1 首轮只修流式臂，非流臂未覆盖，属修复不完整；两条路径共用同一守卫消除漂移。

**备选**：① 非流单独实现一套等价逻辑——重复且易漂移；② 仅补对象 key 不补内层校验——仍漏内层破损场景。

#### D13：按 span 实际深度逐点转义，深度统计覆盖对象 key（`NLP-4`/`CHC-1`）

**决策**：`src/service/pii/scope.rs:404-426,210-217` 由「同明文按明文 max 深度统一转义」改为按 span 实际所在深度逐点转义（而非聚合 max）；深度统计覆盖对象 key；补「同明文跨深度」与「键位深度」回归测试（per canonical `openspec/specs/redaction/spec.md`）。

**理由**：聚合 max 造成浅层过度转义（内容损坏），对象键位漏算造成欠转义回退；逐点转义同时消除两侧误差。

**备选**：① 仅补对象 key 仍用 max——过度转义仍在；② 仅改逐点不补 key——欠转义仍在；③ 统一按最浅深度——深层欠转义。

#### D14：model 分桶响应缺失回退请求 model（`NLP-2`）

**决策**：`src/handler/llm/nonstream.rs:173-174` 分桶时，响应无 `model` 回退请求 model（对照 Python `_llm.py:2975-2977`），流/非流同口径；补无 model 响应回归测试（per canonical `openspec/specs/metrics-admin-parity/spec.md`）。

**理由**：当前响应无 model 全记 `unknown_model`，指标失真。

**备选**：① 保留 `unknown_model` 并加维度——运维不可用；② 从 conv_id 猜测 model——不可靠。

### 决策组 C：PII / 脱敏 / 审计策略

#### D15：自定义 PII 规则在 `AppState` 构建时注入运行时检测器，保持 fail-closed（`DCD-1`）

**决策**：`src/state.rs:104-105` 仅 `PiiDetector::new()` + `set_hardening` 的构建路径，改为以 `config.pii_custom_*_file` 调 `load_custom_all`/字典加载并注入检测器；注册表/字典加载错误沿用 fail-closed（已拒启动）。补「配置自定义规则 → 运行时命中 → 指标/审计可见」端到端回归测试（per canonical `openspec/specs/pii-custom-compat/spec.md`）。

**理由**：特性当前完全失效（仅启动校验、从不注入运行时），是 P1 缺陷；在构建期接线最小改动且复用既有 fail-closed。

**备选**：① 请求路径惰性加载——每请求开销与锁竞争，且错误时机不可控；② 保留现状并声明——特性不可用，违背 spec 要求；③ 仅加载不入检测器——等于未修。

#### D16：`curl`/`wget` 增加「命令词 + 裸 host 参数」外传判定，控制误报（`APP-2`）

**决策**：`src/service/audit/rules.rs:317-347` 为 `curl`/`wget` 增加「命令词 + 裸 host 参数」外传分支（含 `-X`/`--data` 等参数后 host、`http://` 前缀变体），对齐 Python `_audit.py:787-813`；补裸 host 用例（含负例：本地/GitHub 白名单不变）。RE-OPENED `POL-6` 收口（per canonical `openspec/specs/audit-policy-enforcement/spec.md`）。

**理由**：无 scheme、无重定向、无管道的裸 host 请求当前漏审（Python 拦截）；对齐后收口首轮 partial。

**备选**：① 仅对含 `http://`/`https://` 的形态判定——裸 host 仍漏；② 用宽松正则匹配任意 host 字样——误报激增；③ 声明为有意差异——与 Python 策略面偏差扩大。

#### D17：审计策略加载支持顶层 JSON 对象（`APP-3`）

**决策**：`src/service/audit/policy.rs:70-82` 增加顶层 JSON 分支（与 YAML mapping 同解析），fail-closed 语义不变；补 JSON 策略文件回归测试（per canonical `openspec/specs/audit-rules-parity/spec.md`；对照 Python `_audit.py:222-234`）。

**理由**：顶层 JSON 形态被拒启动，而 Python 接受，造成兼容缺口。

**备选**：① 仅支持 YAML 并声明——兼容性缺口保留；② 用通用解析库猜测——增加依赖与形态歧义。

#### D18：Block/Allow 审计日志补参数脱敏摘要（`APP-4`）

**决策**：`src/service/audit/sink.rs:77-96` 的 Block/Allow 记录补参数脱敏摘要（复用 ten-form 摘要引擎），保持 0600 与「先脱敏后落盘」顺序；补日志形态回归测试（per canonical `openspec/specs/audit-parity/spec.md`）。

**理由**：Python 每条记录均含脱敏摘要，Rust 缺失使取证人无法从日志判断参数形态。

**备选**：① 仅记参数长度——信息不足；② 记原文——违反零明文；③ 记完整参数但不脱敏——安全风险。

#### D19：还原 span 逐出现点映射，避免 skip 过度覆盖（`APP-5`）

**决策**：`src/service/pii/scope.rs:147-185` 由「明文子串全量查找定位」改为逐出现点映射（不整段 skip），保证响应侧独立同值明文仍被掩码；补同值多出现点回归测试（per canonical `openspec/specs/redaction/spec.md`）。

**理由**：当前 skip 集可能过度覆盖，导致响应侧独立同值明文不被掩码（漏脱敏）。

**备选**：① 保留全量查找并加二次校验——定位仍不精确；② 用全局唯一标记——改变 token 形态。

### 决策组 D：凭据 / 注册 / Matrix / Go

#### D20：注册表加载失败错误上抛，fail-fast 拒启动（`CRD-1`）

**决策**：`src/state.rs:76` 的 `.unwrap_or_default()` 改为启动路径错误上抛（拒启动）并记 error 日志；沿用 canonical C14 已声明的 fail-closed 语义；补损坏注册表启动拒绝回归测试（per canonical `openspec/specs/credential-flow-parity/spec.md`）。

**理由**：静默吞为空表违反 fail-closed，损坏注册表会导致 ACL 完全失效而无人察觉。

**备选**：① 吞错 + 告警指标——仍以空表运行（fail-open）；② 回退到内建默认注册表——凭空放行；③ 上抛但降级为只读——语义复杂且非需求。

#### D21：`allow_mode` 输出映射 `auto/manual`，保留输入三态兼容（`CRD-3`）

**决策**：`src/handler/credential/mod.rs:147-183` 的 `GET /registrations` 响应补齐 Go 契约 `type` 字段；`allow_mode` 输出映射 `auto`/`manual`（不再序列化 `true/false/none`）；输入保留三态兼容（`auto`→true、`manual`→none、未知回退 auto + warn）；补 Go 形状契约测试（现有 TST Go 请求形状锁定扩展响应形状）（per canonical `openspec/specs/go-client-interop/spec.md`）。

**理由**：Go 客户端期望 `auto/manual`，当前词汇反向导致解析失败。

**备选**：① 仅改输出不回退输入——旧客户端报错；② 双写 `allow_mode` 与布尔——契约混乱；③ 声明为有意差异——Go 契约破坏。

#### D22：revoke 202 采用「声明轮询契约 + 注册路径幂等查询」双半修复（`CRD-2`/`CRD-6`）

**决策**：分两半：① veil 侧 README §5 与 `go-client-interop` spec 显式声明 revoke 202 轮询契约（与 `/credential` `E_PENDING` 同口径）；② Go 仓修复（轮询或声明需 `CREDENTIAL_BLOCK_WAIT=1`）登记为外部仓库伴生修复；同时收敛常规注册/吊销 202 重试语义——注册路径补幂等查询（同请求重试返回同一 pending/终态），吊销路径按声明的轮询语义与 README 对齐（`vault_ops.rs:297/389`）。补重试回归测试。

**理由**：Go `get revoke` 把 202 当成功是静默假成功；注册重试得 409、吊销重试重复建单与 README 不符。声明契约 + 注册幂等是成本最低且可验证的收敛。

**备选**：① 全路径实现强幂等——改动面大且需跨进程状态；② 仅声明不改代码——重试仍异常；③ 改为同步阻塞默认——BREAKING 且违背既有默认。

#### D23：紧急吊销 token 源变更显式声明为 BREAKING（`CRD-7`）

**决策**：`src/service/credential/vault_ops.rs:458-464` 的紧急吊销管理 token 源从 `CREDENTIAL_ADMIN_TOKEN` 改为 `OBSERVABILITY_ADMIN_TOKEN` 的事实，在 `credential-auth-hardening` spec + README §7.5 显式声明 token 源与迁移；补双 token 场景回归测试（per canonical `openspec/specs/credential-auth-hardening/spec.md`）。

**理由**：源变更未声明属静默 BREAKING，运维按旧变量配置会失效。

**备选**：① 双 token 都接受——扩大攻击面；② 保留旧源——与当前实现不符；③ 仅文档声明不补测试——无回归锁。

#### D24：审批消息预置 reaction，发送失败仅 warn（`CRD-5`）

**决策**：`src/service/credential/approval.rs:79-95` 建单后按分支预置 reaction 提示（表情列表与 Python `_matrix.py:282-331` 对齐），发送失败仅 warn 不阻断；补预置调用回归测试（per canonical `openspec/specs/matrix-approval-closure/spec.md`）。

**理由**：管理员需手输表情且 `🔓` 不可发现，预置提升可用性且失败不影响建单。

**备选**：① 硬失败拒建单——可用性风险；② 仅文档提示表情集——仍不可发现；③ 不复用 Python 表情集——口径漂移。

### 决策组 E：管理面 / 指标 / 配置

#### D25：三个运行时计数器经 `/_admin/metrics` 暴露（`OPS-1`）

**决策**：`src/service/llm_gateway/mod.rs:184-197` 的 `upstream_read_errors`/`admin_rate_evicted`/`aggs_evicted` 经 `src/handler/admin.rs:286-310` 的 `/_admin/metrics` 暴露（新增键，只增不改）；补「计数递增在 metrics 可见」回归测试。RE-OPENED `RUN-4` 收口（per canonical `openspec/specs/runtime-reliability/spec.md`）。

**理由**：只累加不输出使 spec「运维可感知」不成立。

**备选**：① 仅日志不暴露——无法阈值告警；② 复用既有键——语义歧义；③ 暴露为 gauge——与单调计数语义不符。

#### D26：管理面统一补安全响应头（`OPS-2`）

**决策**：`src/handler/admin.rs` 管理面统一补安全响应头（`Cache-Control: no-store` 等），SSE 除外或同加；补头存在性回归测试（per canonical `openspec/specs/observability-admin/spec.md`）。

**理由**：全仓零命中，Python `_admin.py` 有，管理面数据敏感不应被缓存。

**备选**：① 仅核心路由加——覆盖不全；② 含 SSE 加 `no-store`——可能干扰事件流；③ 声明不加——安全面缺口保留。

#### D27：管理面 SSE 事件名对齐 `event` 并补 `done` 终止帧，`admin.html` 同步适配（`OPS-3`）

**决策**：`src/handler/admin.rs:607/635` 的每事件名由 `message` 改为 `event`（对齐 Python `_admin.py:534/596`），并补 `done` 终止帧；`admin.html:1037` 监听随之适配；补 SSE 帧序列回归测试（per canonical `openspec/specs/observability-admin/spec.md`）。

**理由**：事件名与终止帧与 Python 不一致，下游（含自带 console）监听 `event` 收不到；无 done 无法判断流闭合。

**备选**：① 双发 `message` 与 `event`——事件重复；② 仅改事件名不补 done——闭合语义仍缺；③ 保持现状声明——契约偏差。

#### D28：SQL 侧窗口键改用可比整数序 `window_ord`（`OPS-8`）

**决策**：`src/service/metrics/aggregate.rs`/`store.rs` 的 SQL since 过滤/retention 由窗口键字符串比较改为与内存侧一致的可比整数序（`window_ord`）或规范格式；补跨位数窗口回归测试（per canonical `openspec/specs/observability-admin/spec.md`）。

**理由**：字符串比较在位数进位处（如 `h9` vs `h10`）失真，内存侧 `window_ord` 已修而 SQL 侧未修。

**备选**：① 补零填充字符串——需迁移既有数据；② 仅内存侧修——SQL 查询仍错；③ 改表结构——迁移成本大。

#### D29：`/_admin/events` limit 默认与上限对齐 50/200（`OPS-6`）

**决策**：`src/handler/admin.rs` 的 events limit 默认值/上限由 100/500 对齐 Python 的 50/200（或显式声明差异）；补边界回归测试（per canonical `openspec/specs/observability-admin/spec.md`）。

**理由**：默认与上限漂移造成运维预期不一致；50/200 更保守有界。

**备选**：① 声明差异不改——漂移保留；② 取更小值——超出需求。

#### D30：SSE `Lagged` 可恢复（跳帧/提示）而非断连（`OPS-7`）

**决策**：`src/handler/admin.rs` SSE loop 在 broadcast `Lagged` 时继续（跳帧/提示）而非断连；补 Lagged 场景回归测试（per canonical `openspec/specs/observability-admin/spec.md`）。

**理由**：`Lagged` 属正常背压，断连会放大重连风暴并丢后续事件。

**备选**：① 断连 + 客户端重连——放大负载；② 阻塞等待——可能死锁；③ 静默丢弃——不可观测。

#### D31：SSE granularity 非法值显式报错/警告、快照补全、补 `X-Accel-Buffering: no`（`OPS-9`）

**决策**：`src/handler/admin.rs` 的 SSE granularity 非法值由静默回退改为显式报错或 warn；SSE metrics 快照补全缺失字段；SSE 补 `X-Accel-Buffering: no`；补回归测试（per canonical `openspec/specs/observability-admin/spec.md`）。

**理由**：静默回退掩盖配置错误，快照字段不全影响消费，反代缓冲会拖延 SSE。

**备选**：① 仅 warn 不补字段——观测仍缺；② 仅补字段不校验——配置错误不可见；③ 不改——问题保留。

#### D32：`PII_HOLD_MAX` 增加上界钳位与非法值处理（`ARH-6`）

**决策**：`src/config/env_parse.rs` 为 `PII_HOLD_MAX` 增加合理上界（如 ≤1MB 或与既有常量匹配）与非法值处理（拒启动或 warn + 钳位）；补边界测试（per canonical `openspec/specs/config-legacy-compat/spec.md`）。

**理由**：无上界钳位，超大值会引入无界缝窗缓冲风险。

**备选**：① 仅拒非法下限——上界仍缺；② 硬编码不改——配置面风险。

#### D33：`OBSERVABILITY_DISABLE=1` 语义裁决——管理面全 404 且不要求 token（`OPS-4`）

**决策**：`src/config/env_parse.rs:405` 的 DISABLE=1 豁免必填 token：DISABLE=1 时管理面全 404（已有）且不要求 token，调整配置门禁顺序使其不因缺 token 拒启动；补 DISABLE 场景回归测试（per canonical `openspec/specs/config-legacy-compat/spec.md`）。

**理由**：置 DISABLE 仍要求 token 否则 401，语义自相矛盾（应为 404 且启动不依赖 token）。

**备选**：① 要求 token 且返 404——仍需配置，违背 DISABLE 语义；② DISABLE 时完全不解析 token——等价于本决策方向；③ 声明为有意差异——运维困惑。

### 决策组 F：架构与死代码

#### D34：架构项收敛为单次解析复用、上下文合并、批量扫描、受约束状态码、shutdown 接线（`ARH-2`/`ARH-3`/`ARH-4`/`ARH-10`/`ARH-12`）

**决策**：五项合并规划：① `event_loop.rs:145,273` + `frame_feed.rs:33,36` + `inner_json_intact` 的单帧最多 4 次全量 JSON 解析改为单次解析并传递复用（逐字节行为不变）；② `StreamPumpCtx`（17 字段）与 `NonstreamCtx`（16 字段）重叠 14 字段合并共享结构体、消除 dispatch 双份装配（`src/handler/llm/dispatch.rs`）；③ `src/service/pii/custom.rs:407-412,430` 的每帧 clone 规则集 + 每规则每分块 `spawn_blocking` 改为单任务批量扫描、共享只读规则引用（`Arc`）；④ `src/service/llm_gateway/` 的 `Upstream` 状态码引入受约束类型（newtype/serde 校验），非法值处理与现状一致；⑤ `src/main.rs` 接线 `notify.shutdown()` 并消除 `GatewayCleanup` 二次 AppState 构造。补等价性/性能敏感路径回归测试（per canonical `openspec/specs/architecture-cleanup/spec.md`）。

**理由**：均为行为不变的结构优化，合并规划可共享等价性测试与波次。

**备选**：① 拆成 5 个独立 change——审查碎片化、跨文件耦合难一次性验证；② 只做其中高风险项（解析复用/批量扫描）——漂移风险与 shutdown 缺口仍在；③ 不做架构项——性能与可维护性债务累积。

#### D35：重复实现合并为单一实现 + 重导出（`DCD-2`/`DCD-4`/`DCD-5`/`DCD-6`/`DCD-7`/`DCD-8`）

**决策**：① 删除 `ApprovalGateway` trait + `NoopApproval` + `ApprovalOutcome` 死抽象（仅测试引用，优先删除）；② `is_valid_mxid`（`src/service/matrix/validate.rs:267` ↔ `branch.rs:72`）单一实现 + 重导出；③ 20 个仅测试引用的 pub API 收敛可见性——其中 6 个 metrics getter 随 `OPS-1` 暴露；④ `strip_yaml_quotes`↔`unquote` 合并；⑤ poison helper ×3 合并；⑥ `file_len_under_800_or_split`（18 份）提取共享测试支撑模块。补等价测试（per canonical `openspec/specs/deadcode-positional-cleanup/spec.md`）。

**理由**：死抽象与重复实现增加维护面与漂移风险。

**备选**：① 保留并声明——债务累积；② 只删死抽象不合重复代码——漂移仍在；③ 一次性大重构——超范围。

### 决策组 G：文档 / 测试 / 流程

#### D36：扩展 `check_doc_paths.py` 校验行号语义并纳入 gate（`DCS-ROOT`）

**决策**：`scripts/check_doc_paths.py` 由「仅校验路径存在性」扩展为解析 `path:line` 引用并校验行号在文件行数内（可选 anchor 校验），纳入 gate；同步修正 `docs-contract-sync`/`docs-test-parity`/`docs-contract-resync` 的失效行号指针与 README §6.4/§8.5（per canonical `openspec/specs/docs-contract-sync/spec.md`）。补脚本自测。

**理由**：行号指针批量失效的根因是门禁只验路径不验行号；不修根因则文档漂移复发。

**备选**：① 仅逐条修行号不加校验——复发；② 外部 markdown linter——无法校验 `path:line` 语义；③ 人工审查——不可持续。

#### D37：测试断言收紧（钉死期望 + 显式 panic）（`FAKE-1`/`FAKE-2`/`TCP-3`/`TCP-4`/`CHC-7`）

**决策**：① `tests/http_e2e_ratelimit.rs:145-149` 的 `Ok(Ok(_))` 改为 `Ok(Ok(Some(_)))` 显式保持打开、`None => panic!`；② `src/handler/llm/pump/fragments/tests.rs:60` 宽松析取 `is_empty() || len()==1` 钉死期望值；③ TPM 测试（`src/service/tpm.rs:342-364`）硬件缺失时显式 skip 标记或注入桩，避免空转假绿；④ `src/handler/llm/pump/hold/tests.rs:65-67` 死分支移除或改有效断言；⑤ 补 `tool_calls` 参数内脱敏→还原端到端集成测试。补必要实现缺口（per canonical `openspec/specs/test-e2e-closure/spec.md`、`openspec/specs/test-coverage-fill/spec.md`）。

**理由**：弱断言使回归不可见，属门禁真实性问题。

**备选**：① 保留宽松断言——假绿风险；② 仅新增测试不收紧旧断言——旧盲区仍在；③ 硬件测试直接跳过——无覆盖且无标记。

#### D38：外部仓库（Python + Go）缺陷登记在本 change、实施在外部仓（`PY-1`..`PY-3`、`CRD-2` Go 半）

**决策**：Python `credential-proxy` 伴生缺陷（`tests/llm_test.py` 30 处 `assert True` 等）与 Go `get` 仓 revoke 轮询修复登记为本 change 外部仓库伴生修复（tasks 11.x），apply 时在各自仓库实施并提交后回填记录，不在本仓 tasks 标记完成；本仓只落「声明 revoke 202 轮询契约」的 spec/README 半边。

**理由**：修复必须发生在代码所在仓库；单一 change 登记保持证据链完整，但不越仓修改。

**备选**：① 在本仓复制 Python 测试——无意义；② 不为外部缺陷立 change 记录——证据链断裂；③ 等待外部仓自修——无时间保证。

#### D39：单 change、四波次实施（P0 → P1 → P2 → P3）

**决策**：全部发现收敛为单一 change，按风险波次实施：波次 1 = P0（`APP-1`）；波次 2 = P1（8 条 + 三条 RE-OPENED 收口）；波次 3 = P2（35 条）；波次 4 = P3（约 45 条）。每波次独立过门禁（fmt/clippy/test + `check_doc_paths`/`check_file_sizes` + conformance）后进入下一波；归档时作为整体单元归档。

**理由**：用户要求完整性——全部发现必须一次收敛且证据链同源；分波实施控制单次审查负担与回归定位成本，但共享同一 change 上下文避免跨 change 口径漂移。

**备选**：① 按 P 级别拆 4 个 change——跨 change 依赖（如 `OPS-1` 与 `DCD-5` metrics getter、`APP-2` 与 `POL-6` 收口）易漂移；② 全部一次提交——审查负担与回归定位成本过高；③ 仅修 P0/P1 归档、P2/P3 另立——用户要求的完整性不满足。

## 声明保留（不修）清单

以下发现判定为「声明保留」而非行为变更，登记于本 design 并在 proposal 覆盖表标注 `DECLARE`：

- **ARH-5 `ValidationCache` 全局（非请求级）**：缓存有界且语义正确，无界增长或正确性缺陷均不存在，仅登记不修（有界正确）。
- **DCD-9 `x-veil-protocol` 手工内联 3 处**：三处类型面不同，无法在保持类型安全的前提下统一为单一实现，保留内联（类型面差异）。

除上述两条外，`proposal.md` 覆盖表未标记其它 `DECLARE` 行；`POL-6`/`RED-1`/`RUN-4` 虽为首轮 partial，但已由 `APP-2`/`NLP-3`+`NLP-4`/`OPS-1` 收口，属修复范围而非声明保留。

## 风险 / Trade-offs

- [mega-change 审查负担] → 单 change 覆盖 1 P0 + 8 P1 + 35 P2 + 约 45 P3 + 4 外部项，reviewer 上下文压力大；以四波次分次过门禁 + 决策组聚类（A–G）压缩认知面，每波次独立验证后再进下一波。
- [极性修复触碰热路径] → `D4` 改动 `event_loop.rs` 每次 held 输出判定；风险为语义二次反转，以三协议 held 抑制/放行回归测试锁定，并以改名纪律使误写不可发生。
- [自定义 PII 接线改变运行时行为] → `D15` 使此前「配置但从不生效」的规则开始命中，脱敏量与 `pii_custom_disabled` 计数可能上升，属预期；监控灰度观察，异常规则可经 ReDoS 守卫停用。
- [`allow_mode` 词汇 BREAKING] → `D21` 输出由 `true/false/none` 改 `auto/manual`，依赖旧序列化值的下游会解析异常；同批更新 README §5 + canonical `go-client-interop` spec + 契约测试，输入保留三态兼容降低迁移成本。
- [管理面 SSE 契约变更] → `D27` 事件名 `message`→`event` 且新增 `done` 帧，自带 `admin.html:1037` 需同步适配；同批修改并以帧序列回归测试锁定，外部消费方迁移在 README 声明。
- [测试数量/CI 时间增长] → 新增大量回归测试（尤其 e2e/并发/无效字节/大错误体），gate 时长上升；以按波次过门禁避免全量重复，长耗时用例（TPM/并发）显式标记，必要处并行化测试模块。
- [外部仓库滞后] → Python/Go 修复依赖外部仓提交节奏，本 change 只能保证本仓半边（声明/契约）落地；以 tasks 11.x 显式登记未完成状态，禁止本仓误标完成。
- [`D12`/`D13` 深度/守卫收敛] → 逐点转义与同一守卫可能改变边缘输出（如浅层不再过度转义）；以「同明文跨深度」「键位深度」「内层破损 JSON」回归测试锁定新口径，确认内容损坏修复而非新增。
- [`D3` 取消原语依赖] → 取消令牌若需新依赖则违反「不新增依赖」约束；实现优先复用既有 tokio 原语，无法满足时以 JoinHandle 监视 + 显式 abort 点评估作为回退并在实现中记录。
- [`D28` SQL 窗口键变更] → 既有 sqlite 数据的窗口键格式可能与新整数序不兼容；以迁移期兼容读或声明重算窗口处理，补跨位数窗口回归。

## Migration Plan

1. **波次实施**：波次 1 落地 P0（`APP-1`，含切片安全与多字节回归）→ 波次 2 落地 P1（含 `POL-6`/`RED-1`/`RUN-4` 三条 RE-OPENED 收口）→ 波次 3 落地 P2 → 波次 4 落地 P3。每波次内按决策组（A–G）顺序组织，先实现后补测试，再统一过门禁。
2. **每波次门禁**：`bash scripts/gate.sh` 六步全绿（fmt / clippy `--tests --all-targets -D warnings` / cargo test / `check_doc_paths.py` / `check_file_sizes.py` / 真 SDK conformance 23/23），任一失败不进下一波。
3. **BREAKING 同批更新**：`allow_mode` 词汇（`D21`）、`OBSERVABILITY_DISABLE` token 语义（`D33`）、紧急吊销 token 源（`D23`）、管理面 SSE 契约（`D27`）须在**同一 apply 波次**内同步更新 README 相关章节与对应 canonical spec，不得滞后。
4. **外部仓库**：Python/Go 伴生修复（`D22`/`D38`）在本仓 apply 完成后于各自仓库实施并提交，回填 tasks 11.x 记录；本仓不代改。
5. **回滚策略**：按波次 revert 对应 commit——每波次独立提交，回滚即 revert 该波次；无 schema 破坏性迁移、无新依赖（`D3` 若引入依赖须单独评估）、无部署形态变化。
6. **终验**：全部波次完成后由编排者运行 `openspec validate veil-audit-r2-remediation --strict`（0 failures）并做只读终审，随后作为整体单元归档。
