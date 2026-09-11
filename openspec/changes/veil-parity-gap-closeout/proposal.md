## Why

`veil-parity-gap-closeout` 前置的 parity 审计锁定 7 项缺口（`F1`/`F2`/`F3`/`F5`/`T1`/`T2`/`T3`），均已定位到文件行号，但尚未进入任何 change 承接：

- `F1`（HIGH）：凭据审批默认由 Python 的同步阻塞 `300`s 改为 `202` 非阻塞，README「行为变更（BREAKING）」六项未收录，§5 却称「Go 客户端无需修改」——属未声明漂移；两模式无 e2e，Go 对 `202` 的处理未核实。
- `F2`（MED）：`NONSTREAM_MAX_BYTES`（默认 `8388608`、可配）被静默丢弃，非流对话响应体无上限；Python `_llm.py:139/:259-260/:2942` 的 `502 {"error":{"message":"response too large","type":"response_too_large"}}` 语义在 Rust 缺失。
- `F3`（MED）：`PII_DICT_FILE` 别名未进字典文件槽（`PII_CUSTOM_DICT_FILE/PII_SENSITIVE_DICT_FILE/PII_SENSITIVE_NAMES_FILE/PII_CUSTOM_DICT`），Python 侧该名读取（`_pii.py:569,679`）在 Rust 静默不生效 → 漏脱敏。
- `F5`（LOW）：PII 命中序号分配每次重建 `HashSet` 线性找洞，单请求 K 次注册 O(K²)（`src/service/pii/scope.rs:102,244-250`，上限 `PII_MAX_ENTRIES=1000`）。
- `T1`/`T2`/`T3`（测试缺口）：阻塞模式（`CREDENTIAL_BLOCK_WAIT=1`）无超时/早断连 e2e；sentinel fixtures 无 Responses CR-only 回放；refusal 缺集成级独立还原、ReDoS 缺墙钟绝对上界。

不收口的后果：安全（漏脱敏）、稳定性（无上限响应体拖垮内存）、合规（未声明 BREAKING）、性能（O(K²) 白费）、回归无锁。本 change 只交付规划 artifacts，实现留 apply 阶段。

## What Changes

- **F1 凭据审批 202 契约声明与兼容**：保持默认 `202` 异步为有意设计；README §6 增列 BREAKING，锁定 `202 + E_PENDING` 轮询语义，声明 `CREDENTIAL_BLOCK_WAIT=1` 恢复 Python 式同步阻塞（`300`s 内批准同请求返回凭据、超时按拒绝）；补默认/阻塞两模式 e2e；核实并记录 Go `get` 对 `202` 的处理（联动 `veil-hardening` 5.2 未勾项，不改其文件）。
- **F2 非流响应体上限**：新增 `NONSTREAM_MAX_BYTES` 可配变量（默认 `8388608`，对齐 Python）；非流对话响应体严格超限时返回 `502` + `response_too_large`；与审计 ceiling `AUDIT_SUBLIMIT_CEILING_BYTES`（8MB，非入口锚点）在 spec 中显式区分；README §4 增检查点行。
- **F3 PII 字典别名**：`PII_DICT_FILE` 加入字典文件槽，与主名等价加载（缺失文件 fail-closed），列序保持与 Python 三个历史名的相对优先级一致；README §1 环境表补归属，§7.4 legacy 规则不落入「不读取」。
- **F5 PII 序号分配**：`next_hole(used_seqs())` 全量重建改为游标 + 已用集分配，空洞回收复用，序号在 `[1, PII_MAX_ENTRIES]` 内不重复，均摊 O(1)。
- **T1 阻塞模式 e2e**：`CREDENTIAL_BLOCK_WAIT=1` 的批准、`300`s 超时（注入时钟/缩短超时）、客户端早断连幂等三场景。
- **T2 Responses CR-only 回放**：新增 CR-only fixture 与 SDK 回放断言，补齐现仅 Anthropic CR/LF 覆盖的空白。
- **T3 refusal 集成 + ReDoS 上界**：refusal 集成级「独立还原」测试；ReDoS 扫描墙钟绝对上界测试。

## Findings 覆盖表

| ID | 严重度 | 修复要点 | task 编号 |
|:---|:-------|:---------|:----------|
| `F1` | HIGH | 保持默认 `202` 异步；README §6 增列 BREAKING + `202` 轮询语义 + `CREDENTIAL_BLOCK_WAIT=1` 恢复同步阻塞；补两模式 e2e；核实记录 Go `get` 对 `202` 处理（联动 `veil-hardening` 5.2） | 1.1–1.5 |
| `F2` | MED | 新增 `NONSTREAM_MAX_BYTES`（默认 `8388608`，可配，显式非法拒启动）；非流对话响应超限 `502 response_too_large`；与审计 ceiling 8MB 检查点区分；README §4 归属 | 2.1–2.5 |
| `F3` | MED | `PII_DICT_FILE` 加入字典文件别名槽（与主名等价加载，缺失文件 fail-closed）；README 表与 legacy 归属 | 3.1–3.3 |
| `F5` | LOW | PII 序号分配改游标 + 已用集，空洞回收复用，单请求 O(K)，序号不重复不越界 | 4.1–4.3 |
| `T1` | MED | `CREDENTIAL_BLOCK_WAIT=1` 批准 / `300`s 超时 / 客户端早断连幂等三场景 e2e | 5.1–5.3 |
| `T2` | LOW | 新增 Responses CR-only fixture + SDK 回放断言（现仅 Anthropic CR/LF） | 6.1–6.2 |
| `T3` | LOW | refusal 集成级独立还原测试；ReDoS 墙钟绝对上界测试 | 7.1–7.2 |

## Capabilities

### New Capabilities

- `runtime-parity-limits`：非流响应体上限（含与审计 ceiling 的检查点区分）、PII 字典文件名别名接受、凭据审批默认异步 `202` 契约、PII 序号分配有界复用。

### Modified Capabilities

- 无。本 change 不修改 `openspec/specs/` 既有需求；README 为文档载体，其更新由 apply 任务承担，不构成 spec 变更。

## Non-Goals（显式）

- 不把凭据审批默认改回同步阻塞 `300`s；保持 `202`，只补声明、开关与测试（决策见 design.md D1）。
- 不改审计 ceiling `AUDIT_SUBLIMIT_CEILING_BYTES`（8MB 锚点）取值与语义，仅在 spec 中区分两个检查点。
- 不改脱敏口径（recognizer 集合、占位符形态、豁免与 ReDoS 降级策略维持原样）。
- 不改 Go 二进制源码（`get/` 只核实行为并记录结论；Go 侧修复属另一 change）。
- 不改 `src/`、`README.md`、`tests/` 任何现有文件；本 change 只新增本目录 artifacts，不改其他 change 文件，不提交 commit。
- 不引入新外部依赖。

## Impact

- **新增文件（本 change）**：`openspec/changes/veil-parity-gap-closeout/` 下 `proposal.md`、`design.md`、`tasks.md`、`.openspec.yaml`、`specs/runtime-parity-limits/spec.md`。
- **apply 阶段影响面**：`src/config/env_parse.rs`（`+2` 配置：`NONSTREAM_MAX_BYTES`、`PII_DICT_FILE` 别名）、`src/handler/llm/nonstream.rs`（对话非流上限判定）、`src/service/pii/scope.rs`（分配算法）、`tests/`（T1/T2/T3 e2e 与 fixture）、`README.md` §1/§4/§5/§6。
- **影响系统**：安全（PII 漏脱敏收口）、稳定性（超限响应体拒绝）、接口契约（未声明漂移登记为 BREAKING）、性能（序号分配去 O(K²)）、测试覆盖率。
- **依赖**：无新增依赖；沿用 `cargo test`、`tokio::time` 测试时钟与既有 sentinel 回放设施。
