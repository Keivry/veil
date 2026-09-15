## Why

本 change 承载 2026-09-15 第二轮独立审计（12 项并行审计 + 编排者复核）的修复规划：登记 P0×1、P1×8、P2×35、P3 约 45 条，以及外部仓库（Python credential-proxy）伴生 4 条。审计基线 Rust `494f2bc` 门禁全绿（`gate.sh` 6/6、真 SDK conformance 23/23、142 文件 ≤800 行、`openspec validate --all --strict` 91/0），故这些是现有门禁未捕获的二阶缺陷——热路径 panic、协议/语义漂移、接线失效（代码存在但从未接入运行时）、死抽象与文档漂移，而非已知失败回归；覆盖表去重后共 109 行（P0 1、P1 8、P2 48、P3 45、RE-OPENED 3、外部 4，其中 P2 含别名/组合行）。本 change 只交付规划 artifacts，实现与文档改动留待 apply 阶段。

其中 3 项为上一轮审计判 PARTIAL 的 RE-OPENED 残留，本 change 显式收口：**POL-6**（裸 `curl/wget <host>` 外传漏审）由 APP-2 收口（tasks 4.1/4.2）；**RED-1**（非流还原守卫与深度转义未覆盖）由 NLP-3/NLP-4 收口（tasks 4.5～4.8）；**RUN-4**（运行时计数器只累加不暴露）由 OPS-1 收口（tasks 6.1/6.2）。同时把 DCD-1（自定义 PII 规则仅启动校验、从不注入运行时检测器）这类「特性完全失效」纳入必修面。

## What Changes

- **P0 热路径 panic（APP-1）**：`bank_card` 上下文窗口两处裸字节切片（`src/service/pii/chunk.rs:213-215`、`:274-276`）改为字符边界安全切片，保持窗口语义不变；补多字节 UTF-8 跨界 + 前缀形态回归测试。
- **流式管线与协议保真（STP/MSP/CHC/RSP 流式面）**：`Utf8ByteBuffer::push` 无效字节消费前进 + 缓冲总上限（STP-2，修复永久卡死）；客户端断连取消令牌中止上游读取并回收泵任务（STP-3/ARH-1）；`should_suppress_held_output` 实参极性修正为 `emitted`（STP-4/MSP-1/RSP-1，RE-OPENED）；hold 增加条目数/零字节分片上限（STP-5）；截断残余帧剥前缀丢弃、不再二次加 `data:`（CHC-2）；合成 chat/Responses 帧补必需字段（CHC-3/RSP-3/RSP-4，SDK 可解析、conformance 去 try/except 掩盖）；Responses 全局完成路径对未 done 槽按已累积参数先审后放（STP-1≡RSP-2，block 模式绕过修复）；`refusal:null` 与干净 EOF 判定修正（CHC-4/CHC-5）；多 `data:` 行按 `\n` 连接（MSP-2）、Anthropic 阻断帧真实 index（MSP-3）、opaque 分支接入 TokenCarry（MSP-4）、hold 放行保序（RSP-5）、item-done 审计覆盖扩展（RSP-6）、缺 `event:` 帧不注入（RSP-7）；Fast 攒批/注释帧/text_carry 上限与 `input:[]` 占位、请求方向 `x-veil-*` 剥离（STP-6～9/NLP-8）。
- **非流与传输（NLP）**：`4xx/5xx + text/event-stream` 不再改写为 200 假流，错误状态与正文透传（NLP-1，**BREAKING：输出不再伪造成功状态**）；非流错误体有界读（NLP-5）；model 指标分桶回退请求 model（NLP-2）；非流还原守卫升级为内层 stringified-JSON 校验（NLP-3）；502 门控边界与尾判定大小写口径对齐或显式声明（NLP-6/NLP-7）。
- **PII/脱敏/审计策略（APP/DCD-1）**：启动期以 `config.pii_custom_*_file` 调 `load_custom_all`/字典加载并注入检测器，自定义规则从失效到运行时可用（DCD-1）；span 改为逐出现点映射、同值独立明文仍掩码（APP-5）；同明文跨深度逐点转义 + 对象 key 深度统计（NLP-4/CHC-1）；IPv4 豁免补 `192.88.99.0/24`（APP-9）、`internal_suffixes` 补 `.corp.example`（APP-10）；裸 `curl/wget <host>` 外传判定分支（APP-2，RE-OPENED POL-6）；`AUDIT_POLICY_FILE` 接受顶层 JSON 对象（APP-3，兼容放宽：新增接受形态、非法仍 fail-closed）；审计日志 Block/Allow 补参数脱敏摘要（APP-4）；`partial_prefix_hints` 64 总上限（APP-6）；spec 文本纠错（APP-7/APP-8）。
- **凭据/注册/Matrix/Go（CRD）**：注册表加载失败 fail-fast 拒启动（CRD-1）；哈希变更落定不复活 `revoked/enabled`（CRD-4）；审批消息预置 reaction 表情（CRD-5）；202 重试语义收敛为 README/spec 显式声明 + 注册路径幂等查询（CRD-6）；**BREAKING：紧急吊销管理 token 源显式声明为 `OBSERVABILITY_ADMIN_TOKEN` 并给迁移指引（CRD-7）**；tmp 0600 无宽权限窗（CRD-9）、管理 token 恒时等长比较（CRD-10）、迁移保留字段（CRD-11）、宽限通知去重（CRD-12）、IPv4-mapped 环回识别（CRD-13）、lookup 优先活跃条目（CRD-14）；**BREAKING：`GET /registrations` 响应补 `type` 并将 `allow_mode` 输出词表改为 `auto/manual`（CRD-3，输入三态兼容）**；revoke 202 轮询契约登记与 Go 仓伴生修复（CRD-2）。
- **管理面/指标/限流/配置（OPS/ARH-6/DCD-3/STP-10）**：三个运行时计数器在 `/_admin/metrics` 暴露（OPS-1，RE-OPENED RUN-4）；管理面安全响应头（OPS-2）；SSE 事件名 `event` + `done` 终止帧（OPS-3）；`OBSERVABILITY_DISABLE=1` 时免 token 且全 404（OPS-4）；`pii_value_samples` 形状对齐或声明（OPS-5）；events limit 对齐 Python `50/200` 或显式声明（OPS-6，**若对齐则属 BREAKING 默认值变化，design 裁决**）；SSE `Lagged` 可恢复（OPS-7）；窗口键整数序（OPS-8）；granularity 显式处理 + 快照补全 + `X-Accel-Buffering: no`（OPS-9）；`PII_HOLD_MAX` 上界钳位（ARH-6）；限流周期清扫接线（DCD-3）；SSE 事件计数口径统一（STP-10）。
- **架构优化（ARH）**：单帧单次 JSON 解析复用（ARH-2）、共享请求上下文合并（ARH-3）、`scan_custom` 批量化 + Arc 共享（ARH-4）、重试去重复克隆（ARH-7）、分配复用（ARH-8）、协议分派收敛（ARH-9）、状态码受约束类型（ARH-10）、服务层不变量下移（ARH-11）、`notify.shutdown()` 接线与消除二次 AppState（ARH-12）；`ValidationCache` 声明保留（ARH-5，DECLARE，仅 design 登记）。
- **死代码/去重（DCD）**：删除 `ApprovalGateway`/`NoopApproval` 死抽象（DCD-2）、`is_valid_mxid` 单一实现（DCD-4）、`authorize_entry`/`TurnToApproval` 清理或接线（CRD-8）、仅测试引用 pub API 收敛（DCD-5）、YAML 引号 helper 合并（DCD-6）、poison helper 合并（DCD-7）、`file_len_under_800_or_split` 提取共享测试支撑（DCD-8）；`x-veil-protocol` 手工内联声明保留（DCD-9，DECLARE）。
- **文档与文档门禁（DCS）**：README 指针/标签修正（DCS-3/DCS-4/DCS-5/DCS-11）、canonical spec 行号修正（DCS-2）、归档 spec 历史指针批量修正（DCS-7/8/12..14）、源码注释符号指针（DCS-6）、`src/lib.rs` 补 `//!` 模块文档（DCS-9）、`scripts/README.md` 补 `PENDING_REFS` 例外（DCS-10）、`check_doc_paths.py` 扩展行号语义校验并纳入 gate（DCS-ROOT）。
- **测试补强（TCP/FAKE/CHC-7/DCS-1）**：AuditLogger 并发追加/轮转（TCP-1）、部署密钥鉴权分支 e2e（TCP-2）、TPM 测试硬件缺失显式 skip（TCP-3）、`tool_calls` 参数内脱敏→还原 e2e（CHC-7）、弱断言收紧（FAKE-1/2/3/4）、死分支移除（TCP-4）、spec conformance 计数 20→23（DCS-1）。
- **外部仓库伴生修复（跨仓，只登记不实施）**：Go `get` revoke 202 处理（CRD-2 第②半，task 11.1）；Python credential-proxy 的 PY-1（30 处 `assert True` 恢复真实断言）、PY-2（恒真析取/吞异常）、PY-3（弱断言加强）（tasks 11.2～11.4）；PY-4 无独立发现（登记占位）。

## Capabilities

### New Capabilities

无（本 change 只修改既有 capability）。

### Modified Capabilities

- `stream-fidelity-fix`: SSE 解析无效字节前进与缓冲有界、客户端断连取消上游读取、held 输出抑制判定修正（RE-OPENED）、hold 条目数上限、截断残余帧剥离、多 `data:` 行连接、opaque 分支接入 carry、Fast 攒批与注释帧保真。
- `stream-protocol-parity`: Responses 全局完成路径未 done 槽先审后放、refusal 判定修正、干净 EOF 与异常收尾区分、hold 放行保序、item-done 审计覆盖扩展、缺 `event:` 帧不注入。
- `llm-protocol-hardening`: 合成 chat 流帧补 `id/object/created/model`、合成 Responses 帧补 `sequence_number` 与 `response` 必需字段（SDK 可解析）。
- `gateway-transport-fidelity`: `input:[]` 空数组占位清洁、Anthropic 阻断帧真实 index、请求方向 `x-veil-*` 内部头剥离。
- `transport-fidelity-fix`: 非流错误体有界读（错误臂与正路径同口径）。
- `nonstream-audit-align`: 上游 `4xx/5xx + text/event-stream` 不再改写 200 假流；空体/非 JSON 502 门控边界对齐。
- `gateway-protocol-fix`: 协议尾判定大小写口径对齐 Python 或显式声明宽容为有意。
- `redaction`: 切片字符边界安全（P0）、span 逐出现点映射、IPv4 豁免补段、`internal_suffixes` 补默认后缀、同明文跨深度逐点转义、recognizer 计数文本 6→7。
- `redaction-audit-coverage`: 非流内层 stringified-JSON 还原守卫、对象 key 深度扫描、`refusal:null` 判定修正。
- `pii-custom-compat`: 启动期加载并注入自定义规则/模式/字典至运行时检测器（特性从失效到可用）。
- `pii-parity-closeout`: `partial_prefix_hints` 64 总上限、IPv4 掩码文本 spec 纠错。
- `audit-policy-enforcement`: 内建危险规则覆盖裸 `curl/wget <host>` 外传（RE-OPENED POL-6 收口）。
- `audit-rules-parity`: `AUDIT_POLICY_FILE` 接受顶层 JSON 对象（与 YAML mapping 同解析）。
- `audit-parity`: 审计日志 Block/Allow 记录补参数脱敏摘要。
- `credential-flow-parity`: 注册表加载 fail-fast、哈希变更不复活条目、202 重试语义声明、tmp 0600 无宽权限窗、管理 token 恒时等长比较、迁移字段保留、宽限通知去重、IPv4-mapped 环回、lookup 优先活跃。
- `credential-auth-hardening`: 紧急吊销管理 token 源显式声明（`OBSERVABILITY_ADMIN_TOKEN`，BREAKING 登记）。
- `go-client-interop`: `GET /registrations` 补 `type` 字段、`allow_mode` 输出 `auto/manual`（BREAKING）、revoke 202 轮询契约声明。
- `matrix-approval-closure`: 审批消息预置 reaction 表情（发送失败仅 warn 不阻断）。
- `observability-admin`: 管理面安全响应头、SSE 事件名 `event` + `done` 终止帧、`pii_value_samples` 形状、events limit 默认/上限、`Lagged` 可恢复、窗口键整数序、granularity 显式处理与 `X-Accel-Buffering`。
- `metrics-admin-parity`: model 分桶缺失回退请求 model；SSE 事件计数口径统一（含 block 注入帧）。
- `runtime-reliability`: 三个运行时计数器在管理面可见（RE-OPENED RUN-4 收口）、管理面限流周期清扫接线。
- `config-legacy-compat`: `OBSERVABILITY_DISABLE=1` 不要求 token；`PII_HOLD_MAX` 上界钳位。
- `architecture-cleanup`: 单帧单次解析、共享请求上下文、`scan_custom` 批量化、重试去克隆、分配复用、协议分派收敛、状态码受约束类型、服务层不变量、shutdown 接线。
- `deadcode-positional-cleanup`: 删除 `ApprovalGateway` 死抽象、`is_valid_mxid` 单一实现、死代码清理、重复 helper 合并、共享测试支撑提取。
- `test-coverage-fill`: AuditLogger 并发/轮转测试、部署密钥鉴权 e2e、TPM 显式 skip、`tool_calls` 参数内脱敏→还原 e2e、conformance 计数 20→23。
- `test-e2e-closure`: `Ok(Ok(_))` 弱断言收紧为 `Some`、死分支移除、宽松析取钉死期望值。
- `docs-contract-sync`: 取证指针与 README §6.4 指针修正、README §8.5 标签修正、`check_doc_paths.py` 行号语义校验纳入 gate（DCS-ROOT）。
- `docs-test-parity`: spec 自身行号修正、README `_credential.py` 行号、源码注释符号指针、`src/lib.rs` 模块文档。
- `docs-contract-resync`: 归档 spec 历史行号指针批量修正、`scripts/README.md` 补 `PENDING_REFS` 例外。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

> 本表覆盖审计登记全部发现（P0/P1/P2/P3 去重后逐行 + 3 项 RE-OPENED 残留 + 外部仓库 4 行）；task 编号以本节为准（含权威修正：APP-7→4.18、APP-8→4.19、STP-10→6.16、FAKE-1→10.4、DCS-1→10.5、TCP-3/FAKE-3→10.6、TCP-4/FAKE-4→10.7、FAKE-2→10.8、CHC-7→10.9、DCS-ROOT→9.10、DCS-2→9.1、DCS-3→9.2、DCS-4→9.3、DCS-5→9.4、DCS-6→9.5、DCS-7/8/12..14→9.6、DCS-9→9.7、DCS-10→9.8、DCS-11→9.9）。

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `APP-1` | P0 | `bank_card` 窗口两处切片改字符边界安全切片（`chunk.rs:213-215`/`:274-276`），保窗口语义；多字节 UTF-8 跨界回归 | 1.1、1.2 |
| `STP-1`（≡`RSP-2`） | P1 | Responses 全局完成路径对 `!done_seen` 槽先审后放（重放前同审计判定）；缺 per-item done + 危险参数回归 | 2.1、2.2 |
| `STP-2` | P1 | `Utf8ByteBuffer::push` 无效字节消费前进（对齐 `errors='replace'`）+ 缓冲总上限 + EOF 同策略 | 2.3、2.4 |
| `NLP-1` | P1 | `looks_sse` 分支前置 `status<400` 守卫，错误状态一律透传（不再合成 200 SSE）；**BREAKING** | 3.1、3.2 |
| `CRD-1` | P1 | 注册表加载失败改错误上抛 fail-fast 拒启动 + error 日志（沿用 C14 fail-closed） | 5.1、5.2 |
| `CRD-2` | P1 | revoke 202 轮询契约显式声明（README/spec）；Go 仓修轮询或声明 `CREDENTIAL_BLOCK_WAIT=1` | 5.3、11.1 |
| `CRD-3` | P1 | `GET /registrations` 补 `type`；`allow_mode` 输出 `auto/manual`（输入三态兼容+未知回退 warn）；**BREAKING** | 5.4、5.5 |
| `APP-2` | P1 | `curl`/`wget` 增加命令词 + 裸 host 参数外传判定（含 `-X`/`--data`/`http://` 变体）；RE-OPENED POL-6 | 4.1、4.2 |
| `DCD-1` | P1 | `AppState` 构建时按 `pii_custom_*_file` 加载并注入检测器；fail-closed 不变；端到端命中回归 | 4.3、4.4 |
| `STP-3`/`ARH-1` | P2 | 取消令牌/JoinHandle 监视：断连中止上游读取并回收泵任务；终端恰一不变 | 2.5、2.6 |
| `STP-4`/`MSP-1`/`RSP-1` | P2 | `should_suppress_held_output` 实参 `!emitted`→`emitted`（RE-OPENED）；三协议 held 输出回归 | 2.7、2.8 |
| `STP-5` | P2 | hold 增加条目数/零字节分片计数硬上限；零字节洪泛有界回归 | 2.9、2.10 |
| `NLP-2` | P2 | model 分桶响应缺失回退请求 model（流/非流同口径）；无 model 回归 | 3.3、3.4 |
| `NLP-3` | P2 | 非流还原升级为内层 stringified-JSON 递归校验；`collect_token_depths` 纳入对象 key；RE-OPENED RED-1 | 4.5、4.6 |
| `NLP-4`/`CHC-1` | P2 | 按 span 实际深度逐点转义（不聚合 max）；key 深度统计；同明文跨深度 + 键位回归 | 4.7、4.8 |
| `NLP-5` | P2 | 非流 `status>=400` 错误体有界读（超限截断/流式转发）；大错误体回归 | 3.5、3.6 |
| `CRD-4` | P2 | `approve-hash-change` 落定不改 `revoked/enabled`（仅更新哈希与宽限）；不复活回归 | 5.6、5.7 |
| `CRD-5` | P2 | 建单后按分支预置 reaction 表情（与 Python 对齐）；失败仅 warn；预置调用回归 | 5.8、5.9 |
| `CRD-6` | P2 | 202 重试语义：README/spec 显式声明 + 注册路径幂等查询；重试回归 | 5.10 |
| `CRD-7` | P2 | 紧急吊销 token 源显式声明（`OBSERVABILITY_ADMIN_TOKEN`）+ 迁移；**BREAKING**；双 token 回归 | 5.11、5.12 |
| `APP-3` | P2 | `AUDIT_POLICY_FILE` 支持顶层 JSON 对象（与 YAML mapping 同解析）；fail-closed 不变；JSON 回归 | 4.9、4.10 |
| `APP-4` | P2 | Block/Allow 记录补参数脱敏摘要（复用 ten-form 引擎）；先脱敏后落盘顺序与 0600 不变 | 4.11、4.12 |
| `APP-5` | P2 | 还原 span 改逐出现点映射（不整段 skip），同值独立明文仍掩码；多出现点回归 | 4.13、4.14 |
| `OPS-1` | P2 | `/_admin/metrics` 暴露 `upstream_read_errors`/`admin_rate_evicted`/`aggs_evicted`（只增不改）；RE-OPENED RUN-4 | 6.1、6.2 |
| `OPS-2` | P2 | 管理面统一补安全响应头（`Cache-Control: no-store` 等），SSE 例外或同加；头存在性回归 | 6.3、6.4 |
| `OPS-3` | P2 | 管理面 SSE 事件名对齐 `event` + 补 `done` 终止帧；`admin.html` 监听同步 | 6.5、6.6 |
| `OPS-4` | P2 | `OBSERVABILITY_DISABLE=1` 时不要求 token（全 404 语义保持）；DISABLE 场景回归 | 6.7 |
| `OPS-5` | P2 | `pii_value_samples` 形状与字段位置对齐 Python（metrics 嵌套）或显式声明；形状契约测试 | 6.8 |
| `OPS-6` | P2 | `/_admin/events` limit 默认/上限对齐 Python `50/200` 或显式声明；边界回归 | 6.9 |
| `OPS-7` | P2 | SSE broadcast `Lagged` 时跳帧继续（不断连）；Lagged 场景回归 | 6.10 |
| `OPS-8` | P2 | SQL 侧窗口键改用与内存侧一致的可比整数序（`window_ord`）；跨位数窗口回归 | 6.11、6.12 |
| `OPS-9` | P2 | granularity 非法值显式报错/warn；快照字段补全；SSE 补 `X-Accel-Buffering: no` | 6.13 |
| `TCP-1` | P2 | AuditLogger 并发追加 + 轮转并发回归（多线程不丢行、轮转不损坏） | 10.1、10.2 |
| `TCP-2` | P2 | `GET /registrations` 部署密钥分支 e2e（匹配放行/不匹配 401/双缺 401） | 10.3 |
| `FAKE-1` | P2 | `http_e2e_ratelimit.rs:145-149` 收紧为 `Ok(Ok(Some(_)))`、`None => panic!`；超限拒绝断言 | 10.4 |
| `DCS-1` | P2 | canonical `test-coverage-fill` spec 计数 20→23 + 明细口径；README §8.5 一致性 | 10.5 |
| `DCS-2` | P2 | `docs-test-parity` spec 行号修正（`env_parse.rs:469-478`/`main.rs:45`） | 9.1 |
| `DCS-3` | P2 | `docs-contract-sync` spec 两处取证指针修正（`342-347`；`252-254`） | 9.2 |
| `DCS-4` | P2 | README §6.4 指针改为 `src/handler/llm/pump/spawn/event_loop.rs:414` | 9.3 |
| `ARH-2` | P2 | 每帧单次 JSON 解析并复用（含内层递归）；行为逐字节不变 | 7.1 |
| `ARH-3` | P2 | 合并 `StreamPumpCtx`/`NonstreamCtx` 共享上下文，消除双份装配；等价单测 | 7.2 |
| `ARH-4` | P2 | `scan_custom` 批量扫描共享只读规则（Arc），消除逐规则 `spawn_blocking` churn | 7.3 |
| `ARH-5` | P2 | `ValidationCache` 声明保留（有界且正确），仅登记不修改 | DECLARE（design 登记） |
| `ARH-6` | P2 | `PII_HOLD_MAX` 增加合理上界钳位/非法值拒启动或 warn；边界测试 | 6.14 |
| `ARH-7` | P2 | 重试路径用可重放体/引用消除重复克隆；行为不变 | 7.4 |
| `ARH-8` | P2 | `HashSet` 复用/延迟分配（请求级）；行为不变 | 7.5 |
| `ARH-9` | P2 | 协议分派（19 处/13 文件）收敛为单一分派点或类型化方法 | 7.6 |
| `ARH-10` | P2 | `Upstream` 状态码引入受约束类型（newtype/serde 校验）；非法值处理与现状一致 | 7.7 |
| `ARH-11` | P2 | 服务层补齐/下移不变量守护（debug_assert/类型）；行为不变 | 7.8 |
| `ARH-12` | P2 | 接线 `notify.shutdown()` 并消除 `GatewayCleanup` 二次 AppState；停机回归 | 7.9 |
| `DCD-2` | P2 | 删除 `ApprovalGateway`/`NoopApproval`/`ApprovalOutcome` 死抽象并清理测试引用 | 8.1 |
| `DCD-3` | P2 | `AdminRateTable::sweep_rate` 周期清扫接线（配套 RUN-2 有界）或修正注释；运行可见测试 | 6.15 |
| `DCD-4` | P2 | `is_valid_mxid` 双份 15 行合并为单一实现 + 重导出；等价测试 | 8.2 |
| `CHC-2` | P2 | 截断残余帧剥 `data:` 前缀丢弃（对齐 Python 丢半帧），不再二次前缀转发；残余帧回归 | 2.11、2.12 |
| `CHC-3` | P2 | 合成 chat 流帧补 `id/object/created/model`；SDK 解析回归 | 2.13、2.14 |
| `RSP-3` | P2 | 合成 Responses 全 7 帧补单调 `sequence_number`；结构回归 | 2.15 |
| `RSP-4` | P2 | 合成/阻断 `response` 对象补必需字段（`output`/`status` 等）使 SDK 可解析；conformance 去掩盖 | 2.16、2.17 |
| `STP-6` | P3 | `Speed::Fast` 攒批边界修正使攒批生效（或声明保留并删死分支）；攒批行为测试 | 2.18 |
| `STP-7` | P3 | 块内注释保真透传/正确合并；注释用例 | 2.19 |
| `STP-8` | P3 | `text_carry` 补总缓冲上限与超限策略；回归 | 2.20 |
| `STP-9` | P3 | `empty_placeholder` 覆盖空数组 `input:[]`；参数累积清洁测试 | 2.21 |
| `STP-10` | P3 | `sse_event_count` 计数口径统一（block 注入帧纳入或明确排除并声明）；一致性测试 | 6.16 |
| `NLP-6` | P3 | 空体/非 JSON→502 门控边界对齐 Python（`status==200`）或显式声明差异并锁测试 | 3.7 |
| `NLP-7` | P3 | 宽容路径匹配大小写对齐 Python（敏感）或声明宽容为有意；大小写用例 | 3.8 |
| `NLP-8` | P3 | 请求方向同样剔除 `x-veil-*`（大小写不敏感）；回归 | 2.22 |
| `CRD-8` | P3 | `authorize_entry`/`TurnToApproval` 清理或接线 + 注释修正 | 8.3 |
| `CRD-9` | P3 | 注册表 tmp 创建即 0600（`OpenOptionsExt::mode`），无先创建后 chmod 窗；权限断言 | 5.13 |
| `CRD-10` | P3 | 管理 token 改恒时等长比较（hash/HMAC 后比较）；时序不变量测试 | 5.14 |
| `CRD-11` | P3 | 迁移保留 `old_hash_expires_at`/`allow_mode`/`reg_id`（缺省语义明确）；迁移回归 | 5.15 |
| `CRD-12` | P3 | 宽限通知按条目+窗口去重；回归 | 5.16 |
| `CRD-13` | P3 | `is_private_ip` 识别 IPv4-mapped IPv6 环回（`::ffff:127.0.0.1`）；用例 | 5.17 |
| `CRD-14` | P3 | `lookup_by_hash` 优先活跃条目或声明序；用例 | 5.18 |
| `APP-6` | P3 | `partial_prefix_hints` 补 64 总条数上限；有界测试 | 4.15 |
| `APP-7` | P3 | canonical `pii-parity-closeout` spec 6-7 字符 IPv4 掩码文本修正（实现正确） | 4.18 |
| `APP-8` | P3 | canonical `redaction` spec recognizer 计数 6→7（实现/Python 均 7）；计数断言 | 4.19 |
| `APP-9` | P3 | IPv4 保留豁免补 `192.88.99.0/24`；用例 | 4.16 |
| `APP-10` | P3 | 默认 `internal_suffixes` 补 `.corp.example`；用例 | 4.17 |
| `TCP-3`/`FAKE-3` | P3 | TPM 测试硬件缺失时显式 skip 标记或注入桩，消除空转假绿 | 10.6 |
| `TCP-4`/`FAKE-4` | P3 | `hold/tests.rs:65-67` 死分支移除或改有效断言 | 10.7 |
| `FAKE-2` | P3 | `fragments/tests.rs:60` 宽松析取钉死期望值 | 10.8 |
| `DCD-5` | P3 | 20 个仅测试引用 pub API 收敛可见性（6 个 metrics getter 随 OPS-1 暴露） | 8.4 |
| `DCD-6` | P3 | `strip_yaml_quotes`↔`unquote` 合并单一实现；等价测试 | 8.5 |
| `DCD-7` | P3 | poison helper ×3 合并 | 8.6 |
| `DCD-8` | P3 | `file_len_under_800_or_split`（18 份）提取共享测试支撑模块 | 8.7 |
| `DCD-9` | P3 | `x-veil-protocol` 手工内联 3 处声明保留（类型面不同），仅登记 | DECLARE（design 登记） |
| `CHC-4` | P3 | `is_minor_event(Chat)` 修正：`refusal:null` 才次要；用例 | 2.23 |
| `CHC-5` | P3 | 干净 EOF（有 `finish_reason` 无 `[DONE]`）与异常收尾区分判定；用例 | 2.24 |
| `CHC-6` | P3 | `chat_bucket` 64 步长饱和改无碰撞；合成阻断帧多 choice 覆盖或声明；测试 | 2.25 |
| `CHC-7` | P3 | 补 `tool_calls` 参数内脱敏→还原端到端集成测试（请求含 PII→占位符→响应逐字一致） | 10.9 |
| `MSP-2` | P3 | 多 `data:` 行按 WHATWG 以 `\n` 连接后处理；用例 | 2.26 |
| `MSP-3` | P3 | 终端最终审计 Anthropic 阻断帧用真实 index（去硬编码 0）；多块回归 | 2.27 |
| `MSP-4` | P3 | opaque（thinking/signature）分支接入 TokenCarry 或声明 fail-closed 不完整还原并锁测试 | 2.28 |
| `RSP-5` | P3 | hold 放行保序（按 seq 重排）或声明；交错回归 | 2.29 |
| `RSP-6` | P3 | `output_item.done` 审计覆盖扩展至其它工具 item 类型或声明范围；用例 | 2.30 |
| `RSP-7` | P3 | 无 `event:` 的 data 帧不补 `event: message`（保持原形态）或声明；用例 | 2.31 |
| `DCS-5` | P3 | README `_credential.py:433`→`445` 行号修正 | 9.4 |
| `DCS-6` | P3 | 源码注释 `pump.rs::spawn_gated` 不存在符号指针修正 | 9.5 |
| `DCS-7`/`DCS-8`/`DCS-12..14` | P3 | 归档 spec 历史行号指针批量修正（仅修指针、保留归档语义） | 9.6 |
| `DCS-9` | P3 | `src/lib.rs` 补 `//!` 模块文档；文档门禁覆盖 lib 根 | 9.7 |
| `DCS-10` | P3 | `scripts/README.md` 补 `PENDING_REFS` 例外说明 | 9.8 |
| `DCS-11` | P3 | README §8.5「12 项（cargo）」标签修正为 23 项脚本口径 | 9.9 |
| `DCS-ROOT` | P3 | `check_doc_paths.py` 扩展 `path:line` 行号语义校验 + anchor 可选校验，纳入 gate | 9.10 |
| `POL-6-residual` | RE-OPENED（P1 收口） | 裸 host 分支缺失由 APP-2 收口；RE-OPENED 记录于本 change | 4.1、4.2 |
| `RED-1-residual` | RE-OPENED（P2 收口） | 非流守卫 + 深度转义由 NLP-3/NLP-4 收口；RE-OPENED 记录于本 change | 4.5～4.8 |
| `RUN-4-residual` | RE-OPENED（P2 收口） | 计数器未暴露由 OPS-1 收口；RE-OPENED 记录于本 change | 6.1、6.2 |
| `PY-1` | P1（外部仓） | Python `tests/llm_test.py` 30 处 `assert True` 恢复真实断言；外部仓实施 | 11.2（外部仓） |
| `PY-2` | P2（外部仓） | 恒真析取（`:1168/1496`）钉死期望值；吞异常断言改显式失败 | 11.3（外部仓） |
| `PY-3` | P3（外部仓） | 仅类型断言与弱析取加强；外部仓实施 | 11.4（外部仓） |
| `PY-4` | —（外部仓） | 无独立发现（登记占位，无需修复） | —（外部仓） |

## Non-Goals（显式）

- **无实现**：本 change 只交付规划 artifacts（proposal/design/29 个 capability delta/tasks）；不改 `src/`、`tests/`、`README.md`，不启动实现。
- **规划期不改 canonical spec**：`openspec/specs/` 修改全部留待 apply 阶段按 delta 合入；本 change 不改 `openspec/changes/` 内其他既有文件。
- **声明保留项不携带行为变更**：`ARH-5`（`ValidationCache` 全局但有界正确）与 `DCD-9`（`x-veil-protocol` 手工内联 3 处）在本 change 明确保留，仅登记于 design.md「声明保留（不修）」清单，不产生修复任务。
- **不新增依赖**：不引入任何新 crate；沿用既有 `tokio`/`tracing`/`serde`/`axum`/`rusqlite` 等。
- **不削弱门禁**：`gate.sh` 六步、`openspec validate --strict`、真 SDK conformance 23/23 与 800 行上限不得放宽；DCS-ROOT 只增强文档校验。
- **外部 Python 仓修复只登记不实施**：PY-1～PY-3 在 `/home/keivry/项目/Python/credential-proxy` 另行实施并在该仓记录，不得在本仓标记完成；Go `get` 仓的 revoke 202 修复（task 11.1）同理。
- **不为 Python 对齐而放弃已声明有意差异**：Rust 有意更严/不同的口径（如 §6.9 私网一律非内网、§7.3 请求隔离、§6.7 超时归并与 `202` 轮询口径、`PII_HOLD_MAX` 缝窗语义）保持既有声明，不在本 change 回退；仅对回归性漂移（无声明差异）按修复要点对齐。

## Impact

- **新增 artifacts**：本 change 目录下 `proposal.md`、`design.md`、`specs/<29 capability>/spec.md`（delta）、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面（按模块组）**：PII/脱敏/审计——`src/service/pii/{chunk,scope,emit,custom}.rs`、`src/service/audit/{rules,policy,sink,log}.rs`；流式泵与 SSE——`src/service/sse/parser.rs`、`src/handler/llm/pump/*`（`event_loop`/`hold`/`terminal`/`frame_feed`/`event`/`fragments`/`spawn`）、`src/service/block_inject/{frames,tool}.rs`、`src/handler/llm/{mod,nonstream,dispatch}.rs`；凭据/注册/Matrix/Go——`src/state.rs`、`src/service/credential/*`、`src/service/registry/store.rs`、`src/service/matrix/{approval,validate,branch}.rs`、`src/handler/credential/*`；管理面/指标/配置——`src/handler/admin.rs`、`src/service/admin/{ratelimit,state}.rs`、`src/service/metrics/{aggregate,store}.rs`、`src/config/env_parse.rs`；架构/死代码——`src/handler/llm/dispatch.rs`、`src/service/llm_gateway/*`、`src/main.rs`、`src/lib.rs`；文档与测试——`README.md`、`scripts/check_doc_paths.py`、`scripts/README.md`、`tests/*` 与归档 spec 指针。
- **影响系统**：请求热路径稳定性（防远程 panic DoS）、三协议流式/非流传输保真、审计与脱敏正确性、自定义 PII 特性可用性、凭据注册/吊销/审批语义、管理面可观测契约、归档文档可信度。
- **外部仓库接触面**：Python credential-proxy（tasks 11.2～11.4 登记，实际修复在该仓）与 Go `get` 客户端（CRD-2 的 11.1：revoke 202 轮询或声明）。
- **依赖**：无新依赖，仅既有依赖与测试设施。
