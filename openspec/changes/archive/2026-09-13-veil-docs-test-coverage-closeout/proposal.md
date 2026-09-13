## Why

独立审计（2026-09-13，测试覆盖与文档面）确认 13 项收口项（G1–G13）：7 项测试覆盖缺口（G1–G7，其中 vault/审计规范化两处含脏数据逃逸与审计绕过风险）、1 项弱断言加强（G8）、3 项文档同步（G9–G11）、2 项记录（G12–G13）。相对 Python 原仓（`/home/keivry/项目/Python/credential-proxy`）的行为修复由各自 change 承接，本 change 只补测试与文档收口：

- **测试缺口（G1–G7）**：`G1` vault 稳定性（fuzzy 大小写/非法口径、三包装器 nasty 值仍合法 JSON、三校验器回退契约，Python `tests/vault_stable_test.py:132-345`）无 Rust 等价 → 非流式脏数据逃逸风险；`G2` 审计规范化（转义/管道优先级/`../`/`find` 泛洪/别名 rm，Python `tests/audit_test.py:95-242`）无专项测试 → 审计绕过风险；`G3` 审计环境降级（legacy `AUDIT_ENABLED`→block、approve 空白名单降级、初始化不建任务，Python `tests/audit_env_test.py:49-257`）Rust 仅常量测试；`G4` PII 值采样持久化 18 例（7 天滚动/热切换/跨天 topn/same-masked/401 不泄漏，Python `tests/observability_pii_value_test.py`）缺持久化取证；`G5` KeePass 解锁流（超时/单问/raw 上下文/ask 失败/双表清理，Python `tests/credential_test.py:215-721`）Rust 仅 `fetch_credential` 级；`G6` detection hardening 开关矩阵（默认关/非法值/bare 前缀/CJK 边界/analyzer 缓存，Python `tests/detection_hardening_test.py:48-160`）Rust 仅 redos/CJK 抽样；`G7` debounce/解析（2s 窗口、`model:version` 冒号，Python `tests/redact_extra_test.py:176-208`）Rust 仅 fast_debounce 阈值。
- **弱断言（G8）**：`src/service/sse.rs` `push_bytes` 仅断言帧切分；`src/service/json_walk.rs:177,197,261` 仅 `assert!(parse(...).is_ok())`；`src/handler/llm/dispatch.rs:384` 仅 `ok.is_ok()`；`src/service/admin/ratelimit.rs:72,77,121,130` 仅 happy path；`tests/http_e2e_metrics_snapshot.rs:99` 仅空窗 shape；`src/config/env_parse/tests.rs:62` 仅默认值 getter；`file_len_under_800_or_split` 元测试需注明非行为覆盖。
- **文档（G9–G11）**：`G9` README 路径/口径三处偏差（§1「未列出变量二进制不读取」缺审计 `$VAR`/`HOME` 直读例外；§4.1 `OLD_HASH_GRACE_SECS` 来源误标 `src/registry.rs`；`VEIL_ALLOW_MOCK_TPM` 未写 trim 后 `=="1"`）与 `scripts/README.md` 缺 `go_interop_e2e.py`；`G10` `AUTO_APPROVE` 别名、Cookie 回退/签发、SSE 过滤/近环回放/超限 `Retry-After=60`、health 豁免实现细节未文档化；`G11` 阻塞审批超时 `408`→`403` 归并未在 README §5/§6.7 明示（Python `_credential.py:433` 为 `408`）。
- **记录（G12–G13）**：`G12` LLM 核心有意差异未集中登记（调试落盘 §8.2、跨 TCP UTF-8 无损、断连任务寿命、空 `data:` 心跳丢弃、NonDialog 透传 §7.6，以及由 credential-flow-parity / pii-parity-closeout 裁决的限流维度、旧哈希宽限、紧急吊销、信封、双必填、PII 语义映射）；`G13` README §6/§7 声明逐条与代码一致性核验（本轮通过）未落档。

真相源：Python 原仓测试（上列路径，审计记名 `vault_stable.py`/`detection_hardening`/`redact_extra` 分别对应 `vault_stable_test.py`/`detection_hardening_test.py`/`redact_extra_test.py`）、Rust `src/` 与 `tests/`、`README.md`、`scripts/README.md`。本 change 只规划（proposal/design/spec/tasks），不改 `src/`、`tests/`、`README.md`、`scripts/`；测试补录与文档同步留待 apply 阶段。

引用契约：canonical `openspec/specs/docs-test-closure/spec.md`、`openspec/specs/coverage-closure/spec.md`；归属 change `veil-audit-rules-parity`（A5/A7）、`veil-pii-parity-closeout`（P11/P13、P5–P8）、`veil-credential-flow-parity`（C11–C16）、`veil-stream-fidelity-fix`（流式增量/多工具审计回归测试归其所有）。

## What Changes

- **`G1` vault 稳定性等价测试**：补 fuzzy 精确/宽松（含大小写漂移）测试、三包装器 nasty 值 JSON 合法性与还原契约测试、三校验器回退契约测试；`PII_FUZZY_RESTORE` 非法值口径（Rust 非真值按关、不拒启动）登记为有意差异并交叉引用 A7。
- **`G2` 审计规范化专项测试**：补转义/管道优先级/`../`/`find` 泛洪/别名 rm 五类专项用例，与 A5 修复同批，不重复实现级测试。
- **`G3` 审计环境降级语义测试**：补 legacy `AUDIT_ENABLED`→block（显式 `AUDIT_MODE` 优先）、`approve` 空白名单判定入口降级 block、初始化期不建任务三类测试，与 A7 联动。
- **`G4` PII 值采样持久化取证测试**：按 Python 18 例映射补 7 天滚动、热切换 1→0、跨天 topn、same-masked 合并、401 不泄漏测试，与 P11 联动。
- **`G5` KeePass 解锁交互路径测试**：补解锁超时/并发单问、raw 直连 vs 脚本上下文、ask 失败不悬挂、双表清理测试。
- **`G6` detection hardening 开关矩阵测试**：补开关默认/真值/非真值矩阵、ASCII 粘连、CJK 边界、analyzer 缓存复用测试，与 P13 联动。
- **`G7` debounce/解析测试**：补 `model:version` 冒号分桶与 flush 幂等/窗口测试；Rust 无 2s 去抖以 design 登记为事件驱动批量的等价语义。
- **`G8` 弱断言加强**：按清单逐项加强 6 处断言并注明元测试口径（`file_len_under_800_or_split` 保留、非行为覆盖）。
- **`G9` README/scripts 路径与口径修正**：§1 加审计 `$VAR`/`HOME` 直读例外注；§4.1 来源更正 `src/registry/entry.rs`；`VEIL_ALLOW_MOCK_TPM` 写明 trim 后 `=="1"`；`scripts/README.md` 补 `go_interop_e2e.py`。
- **`G10` 未文档化行为补录**：`AUTO_APPROVE` 别名集、Cookie 回退/签发、SSE 过滤/近环回放/超限 `Retry-After=60`、health 豁免实现细节。
- **`G11` BREAKING 补充**：README §5/§6.7 明示阻塞审批超时 `408`→`403` 归并差异，并补测试锁定。
- **`G12` 有意差异登记**：design 集中登记 11 项 LLM 核心有意差异，逐项交叉引用归属 change。
- **`G13` README 声明核验落档**：§6/§7 逐条核验记录（文件:行证据）落入 design，供归档审计追溯。
- **测试与文档（apply 阶段）**：新增/加强测试全部落 `tests/` 或 `src/**/tests`，README/`scripts/README.md` 修正随同批。

## Capabilities

### New Capabilities

- `docs-test-coverage-closeout`：测试覆盖与文档收口契约——7 项测试缺口 Rust 等价覆盖、弱断言加强标准、README/scripts 路径与口径修正、未文档化行为补录、审批超时码差异明示、有意差异登记、README 声明核验落档。

### Modified Capabilities

- 无。本 change 新增 capability；canonical `docs-test-closure`/`coverage-closure` 既有条款不删不改，本 spec 仅补齐其未覆盖的 G 组缺口；README/scripts 文档随 apply 阶段同步。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `G1` | HIGH（测试缺口） | fuzzy 精确/宽松/大小写 + 三包装器 nasty 值 JSON 合法性 + 三校验器回退契约；非法值口径登记（联 A7） | 1.1、1.2、1.3 |
| `G2` | HIGH（测试缺口） | 转义/管道优先级/`../`/find 泛洪/别名 rm 五类专项用例（联 A5） | 2.1 |
| `G3` | MED（测试缺口） | legacy→block 与显式优先、approve 空白名单降级、初始化不建任务（联 A7） | 3.1、3.2、3.3 |
| `G4` | MED（测试缺口） | 18 例映射：7 天滚动/热切换/跨天 topn/same-masked/401 不泄漏（联 P11） | 4.1 |
| `G5` | MED（测试缺口） | 解锁超时/并发单问、raw 上下文、ask 失败、双表清理 | 5.1、5.2、5.3 |
| `G6` | MED（测试缺口） | 开关矩阵/bare 前缀/CJK 边界/analyzer 缓存（联 P13） | 6.1、6.2 |
| `G7` | LOW（测试缺口） | 冒号版本分桶 + flush 幂等/窗口；无 2s 去抖差异登记 | 7.1、7.2 |
| `G8` | LOW（弱断言） | sse/json_walk/dispatch/ratelimit/metrics/env_parse 六处加强 + 元测试注明 | 8.1–8.7 |
| `G9` | 文档 | §1 例外注、§4.1 来源、TPM 口径、scripts/README 补 runner | 9.1–9.4 |
| `G10` | 文档 | AUTO_APPROVE 别名、Cookie、SSE 过滤/回放/Retry-After=60、health 豁免 | 10.1–10.5 |
| `G11` | 文档/BREAKING | README 明示 408→403 归并 + 测试锁定 | 11.1、11.2 |
| `G12` | 记录 | 11 项有意差异集中登记 + 跨 change 交叉引用 | 12.1、12.2 |
| `G13` | 记录（核验） | §6/§7 逐条核验（文件:行）落档；偏差转出 | 13.1、13.2 |

## Non-Goals（显式）

- **不重复流式归口**：流式默认增量、多工具审计阻断等流式回归测试由 `veil-stream-fidelity-fix` 所有（其 spec/tasks 为准），本 change 仅交叉引用。
- **不修行为**：G1–G7 只补测试（断言 Rust 现行行为与契约）；行为修复（A5/A7/P11/P13/C11–C16 等）归各自 change，本 change 不裁决、不实现。
- **不新增 canonical 行为反转**：G8 加强断言不得改变既有测试通过前提；发现的行为偏差转出至归属 change。
- **不改 `src/`、`tests/`、`README.md`、`scripts/`**：本 change 只交付规划 artifacts；不修改 `openspec/changes/` 内其他 change 文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-docs-test-coverage-closeout/proposal.md`、`design.md`、`specs/docs-test-coverage-closeout/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`tests/http_e2e_vault_stability.rs`、`src/service/json_walk.rs`（测试）、`src/service/redaction/scope_tests.rs`、`src/service/audit/normalize.rs`、`src/service/audit/rules.rs`、`src/service/audit/verdict.rs`（测试）、`src/config/env_parse/tests.rs`、`src/service/metrics/sample/tests.rs`、`src/service/metrics/store/tests.rs`、`src/service/metrics/aggregate.rs`（测试）、`src/keepass.rs`、`src/service/credential/approval.rs`、`tests/http_e2e_credential_approval.rs`、`src/service/pii/detector/tests.rs`、`src/service/sse.rs`（测试）、`src/handler/llm/dispatch.rs`（测试）、`src/service/admin/ratelimit.rs`（测试）、`tests/http_e2e_metrics_snapshot.rs`、`README.md` §1/§3/§4.1/§5/§6/§7、`scripts/README.md`。
- **影响系统**：测试覆盖门禁强度、README/scripts 文档口径一致性、归档审计可追溯性。
- **依赖**：无新依赖；与 `veil-audit-rules-parity`（A5/A7）、`veil-pii-parity-closeout`（P11/P13）、`veil-credential-flow-parity` 存在 apply 顺序依赖（其修复先落地，本 change 测试锁定其结论）。
