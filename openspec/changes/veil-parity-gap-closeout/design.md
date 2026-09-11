## Context

现状（见 proposal.md Why）：parity 审计锁定 7 项缺口并定位到行号。`F1` 是已发生但未声明的默认值漂移（Rust `202` 非阻塞 vs Python 同步阻塞 `300`s）；`F2`/`F3` 是 Python 行为在 Rust 缺失（非流响应上限、PII 字典别名被静默丢弃）；`F5` 是序号分配 O(K²) 性能退化；`T1`/`T2`/`T3` 是测试盲区。

约束：本 change 只写规划 artifacts，不改 `src/`/`README.md`/`tests/`；不改其他 change 文件；F2 默认值与 Python 对齐；F1 若保持 `202` 必须同时交付 BREAKING 声明 + Go 兼容说明 + e2e；新配置不得静默忽略（须在 README 表与 legacy 规则中有归属）。

## Goals / Non-Goals

**Goals：**

- 把 `F1` 从「未声明漂移」收敛为「已声明有意设计 + 开关 + 双模式 e2e + Go 结论」，行为不回退。
- 以与 Python 同名的可配上限收口 `F2`，并在 spec/README 中区分非流上限与审计 ceiling 两个检查点。
- `F3`/`F5` 低风险恢复：别名等价加载 + 序号分配有界复用。
- `T1`/`T2`/`T3` 用可验证的测试形态补盲，全部可在秒级 CI 内执行。

**Non-Goals：**

- 不把凭据审批默认改回同步阻塞（保持 `202`，恢复语义只经 `CREDENTIAL_BLOCK_WAIT=1`）。
- 不改审计 ceiling 取值，不改脱敏/审计 verdict 口径。
- 不改 Go 二进制（只核实并记录其 `202` 行为）。
- 不新增外部依赖，不改动其他 change。

## Decisions

### D1：F1 保持默认 202 异步，以 BREAKING 声明 + 开关 + e2e 收口

**决策**：默认（`CREDENTIAL_BLOCK_WAIT` 未设或非 `1`）保持 `202 + E_PENDING` 非阻塞为终态：同请求立即返回已建单，客户端按轮询语义重试；`CREDENTIAL_BLOCK_WAIT=1` 恢复 Python 式同步阻塞（`300`s 内批准同请求返回凭据、拒绝 `403`、超时按拒绝且不悬挂，对齐 `_credential.py:26,433,455`）。README §6 增列该差异为 BREAKING，§5 覆盖 Go 对 `202` 的处理结论；两模式各补 e2e。

**理由**：`202` 已实现且 README §1 已记开关，问题本质是「未声明 + 未测试」而非行为本身有缺陷；改回阻塞默认会二次破坏已对接部署并引入 Matrix 挂起/长连接超时风险。轮询语义对客户端可观测（`E_PENDING` 稳定错误码），声明后即无静默漂移。

**备选**：

- 改回 Python 同步阻塞默认：二次 BREAKING + 挂起风险，不采用。
- 维持现状不声明：违反「不得留未声明漂移」硬约束，不采用。

**202 轮询语义（spec 锁定）**：`202 + E_PENDING` = 已建单等待 Matrix 人工审批；客户端应轮询重试同一请求（建议指数退避），批准后重试返回凭据、拒绝后返回 `403`；`CREDENTIAL_BLOCK_WAIT=1` 时无需轮询。

**Go 兼容核实**：`get/internal/proxy.go::FetchCredential` 无条件 `json.Unmarshal` 响应体再判 `>=400`；`202` 处于其成功分支，若响应体字段可解析则按成功处理。需在 apply 时以实际响应体（`{"error":{"code":"E_PENDING",...}}`）核实是否落入 `CredentialResponse` 可解析范围，并将结论写入 README §5/§6；Go 二进制修复不在本 change 范围（open item）。

### D2：F2 上限值与非流检查点

**决策**：变量名与 Python 同名 `NONSTREAM_MAX_BYTES`，默认 `8388608`（8MB，对齐 `_llm.py:139`）；可配，显式非整数或 `<1` 拒启动（fail-closed，与 `HTTP_TIMEOUT_SECS`/`PII_HOLD_MAX` 同口径）；作用于非流对话响应体（三协议对话尾缀），严格 `len > cap` 触发 `502`，体为 `{"error":{"message":"response too large","type":"response_too_large"}}`（对齐 `_llm.py:2942`）；`Protocol::NonDialog` 透传不受限。判定点放在对话缓冲点后、空体分类与 JSON 后处理前，与 Python 先判空体再判超限的先后语义对齐。

**理由**：与 Python 默认同值避免迁移回归；可配保留逃生口；fail-closed 与仓库既有阈值口径一致。Rust 当前非对话走 `Body::from_stream` 透传、对话走 `up.bytes()` 缓冲，判定点天然存在于缓冲路径，改动面小。

**备选**：

- 复用 `AUDIT_SUBLIMIT_CEILING_BYTES`（8MB）：检查点语义不同——审计 ceiling 是子限锚点、非入口 enforcement、不拦响应体，不采用。
- 硬编码不可配：Python 可配，迁移会失去逃生口，不采用。
- 非法值静默回退默认值（Python 行为）：静默掩盖配置错误，与仓库 fail-closed 口径不符；列为「有意不恢复」（见下节），不采用。

### D3：F3 字典别名列序与 fail-closed

**决策**：字典文件槽新增 `PII_DICT_FILE`，列序保证与 Python 三个历史名的相对优先级一致（`PII_DICT_FILE` > `PII_SENSITIVE_DICT_FILE` > `PII_SENSITIVE_NAMES_FILE`），Rust 主名 `PII_CUSTOM_DICT_FILE` 保持列首；已配置别名文件缺失/不可读/解析失败沿用 `load_custom_file` fail-closed 拒启动；README §1 表补归属、§7.4 不列为 legacy 不读取。

**理由**：Python `_pii.py:569,679` 实际读取该名，静默丢弃属漏脱敏安全缺口；`load_custom_file` 已有完整的拒启动语义，零新增机制。

**备选**：仅 README 注明「不读」——能力缺失不可用文档免责，不采用。

### D4：F5 游标 + 已用集分配

**决策**：`ScopeInner` 维护序号游标与已用序号集合，注册时从游标起找首个未用序号（含空洞回收），淘汰时归还序号；替换 `next_hole(&used_seqs(&inner))` 的每次全量重建。上限 `PII_MAX_ENTRIES=1000` 与序号区间 `[1, 1000]` 不变，均在既有 `inner` 锁内完成，不引入新锁。

**理由**：现算法单请求 K 次注册为 O(K²)（每次重建 `HashSet` + 线性找洞），游标方案均摊 O(1)，行为等价（空洞复用语义保持）。

**备选**：

- 保持现状只加测试：低成本优化不做无谓负债，不采用。
- 序号单调递增不回收：序号膨胀且破坏既有空洞复用语义，不采用。

### D5：T1/T2/T3 测试形态

**决策**：`T1` 用 HTTP 层 e2e 覆盖阻塞模式批准/超时/早断连；超时以 `tokio::time` 暂停推进或测试缩短超时实现，禁止真等 `300`s；断言无悬挂任务与资源回收。`T2` 新增 Responses CR-only fixture（一行 CR 终止）并对标现有 06 Anthropic CR/LF 双路径（`tests/sentinel_sdk_replay.rs:255`）断言输出一致。`T3` 补 refusal 集成级独立还原（明文还原非透传），ReDoS 补墙钟绝对上界（现有仅预算断言 + 连续三次禁用记账，`src/service/pii/custom.rs:387`）。

**理由**：三项均为审计点名的覆盖盲区，形态与既有测试设施（sentinel 回放、tokio 时钟）一致，无新设施成本。

## 有意不恢复的 Python 行为（显式）

1. **凭据审批默认同步阻塞 `300`s（F1）——不恢复**：Rust 保持默认 `202` 异步。理由：长连接友好、避免 Matrix 挂起；以 BREAKING 声明 + `CREDENTIAL_BLOCK_WAIT=1` 开关 + 双模式 e2e 收口漂移。恢复旧默认须新 change 并撤回 §6 条目。
2. **`NONSTREAM_MAX_BYTES` 非法值静默回退 8MB——不恢复**：Rust 改为显式非法拒启动。理由：静默回退掩盖配置错误，与仓库 fail-closed 三约束口径不符；默认值本身与 Python 对齐。
3. **以下既有声明维持原判，不在本 change 恢复**（防止范围蔓延）：空流终止帧不伪造（README §8.6）、PII 跨请求隔离（§7.3）、流式审批不挂起（§6.4）、回环免 token 未迁移（§6.6）、FIFO 改 LRU（§6.3）。

## Risks / Trade-offs

- [F1 声明后 Go 客户端无法解析 `202` 体] → 客户端报错掩盖真实审批状态 → apply 时核实并在 §5/§6 给出明确结论与承接建议（Go 侧修复新 change）；202 明示 `E_PENDING` 错误契约。
- [F2 引入对话非流整体缓冲] → 内存形态变化（Python 本就整体缓冲，Rust 现为透传+JSON 缓冲混合）→ 上限 8MB 兜底，仅对话路径生效，NonDialog 不受影响。
- [F3 别名优先级错配] → 多变量并存时取错文件 → 列序单测锁定，等价性单测覆盖。
- [F5 游标状态与并发冲突] → 序号重复/丢失 → 复用既有 `inner` 锁，单测覆盖空洞回收与并发。
- [T1 超时测试耗时] → CI 拖慢或假超时 → 注入时钟/缩短超时，用例秒级，禁止真等 `300`s。

## Migration Plan

1. 本 change 先落 spec/design/tasks（规划）；apply 按 tasks 顺序执行：F1 声明与 e2e → F2 → F3 → F5 → T1/T2/T3 → 收口一致性。
2. 每步独立验证（配置单测、e2e、README 比对、`openspec validate --strict`），任一步失败只回滚该步。
3. 回滚策略：F2/F3/F5 可独立回滚；F1 只补声明不改行为，声明一旦发布不静默撤回（撤回须新 change）。

## Open Questions（apply 收口记录）

- **Go `get` 对 `202` 的解析结论（task 1.5，已核实）**：`get/internal/proxy.go::FetchCredential`
  先整包 `json.Unmarshal` 再判 `status >= 400`；网关 `202` 体 `error` 为对象而 Go
  `CredentialResponse.Error` 为 `string`，反序列化在状态判定前即失败并报「解析响应失败」→
  **Go 存量客户端不可直接轮询**。承接：Go 侧容忍 `202/E_PENDING`（解析 error 对象或按状态码
  分派后轮询）由新 change 承接，owner 随新 change 立项指定；与 `veil-hardening` 5.2 未勾项联动，
  本 change 不改其文件（结论已写入 README §5/§6.7）。
- **T1 超时 e2e 时钟注入方式定稿（task 5.2，已选定）**：采用「测试内缩短审批超时值」——
  e2e 经 `Config.credential_approval_timeout_secs = 1` 注入（生产装配仍固定 `300`s）；
  不启用 `tokio::time::pause`：`MatrixApproval::ask` 截止判定用 std `Instant`，暂停 tokio 时钟
  不会推进该截止且 50ms 轮询空转。用例实测约 1s，无 `300`s 真实等待。
