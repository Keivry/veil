## Why

独立审计（2026-09-13，PII/脱敏与自定义规则面）确认 14 项待收敛偏差：锁健壮性 1 项（高）、缺失能力 3 项、跨实现分歧 8 项、取证 1 项、低确证核验 2 项（其中 1 项与分歧合计 3 项需裁决）。

- **缺失/高风险**：`P14`（high）`src/service/pii/custom.rs` 9 处 `.expect("检测器锁无毒")`（`:88`、`:118`、`:119`、`:175`、`:176`、`:209`、`:213`、`:321`、`:322`）在持锁 panic 毒化后使 `scan`/`load` 热路径继续 panic；同仓 `src/service/pii/scope.rs:26` 的 `recover_mutex` 已实现 `PoisonError::into_inner` 优雅恢复，两处口径不一。`P1` Python `_pii.py:1196 partial_prefix_hints`（自定义字面前缀 + 字典全名 cap64，SSE 切分时 hold 等待）在 Rust 无对应实现，自定义字面量被切开时首帧直接放行。`P2` ReDoS 连续 3 次超时停用（`custom.rs:321` 记 strike、`custom.rs:154 disabled_snapshot`）未接 health（Python `_pii.py:1349 set_health_flag`），规则降级运维不可见。`P3` 还原命中不 touch（`src/service/pii/scope.rs:256-293 restore_exact` 无 `touch_order`，对照 Python `_token.py:381-401` 还原命中 `move_to_end` 双表提升），高频还原热值仍可被逐出，与「真 LRU」声明部分不符。
- **分歧**：`P4` fuzzy 还原超集（Rust `scope.rs:218-253` 宽松 `(?i)__PII_\d+_[^_\s]{1,16}__` 按序号回查，截断/改写亦还原、无 fuzzy 审计分类；Python `_token.py:409-468` 仅全形态 `IGNORECASE` 8hex + malformed/unregistered/fuzzy 三分类审计）；`P5` 序号分配顺序（Rust `scope.rs:93-114` 游标 O(1) 均摊、逐出后不回填 vs Python `_token.py:260-275` 全量扫描最小空洞）；`P6` 残缺剥离收窄（Python `_token.py:136` 允许无序号 hex 形 `__PII_ab12` 亦剥；Rust `src/service/pii/chunk.rs:113-121` 无序号 hex 一律不剥）；`P7` `PII_HOLD_MAX` 语义重构（Python `PII_HOLD_MAX=64` 为审计 hold 尾部持有；Rust `src/service/redaction/seam.rs:12-75` 为跨帧缝窗掩码 + JSON 信封过滤）；`P8` 自定义变量超集（Python 仅 6 个 `*_FILE`；Rust 另有内联 `PII_CUSTOM_RULES/PATTERNS/DICT`，`src/config/custom_file.rs:394`）；`P9` 掩码边缘（非 4 段 6-7 字符 IPv4 形 Python `_pii.py:1013-1016` 前4/后4 vs Rust `src/service/pii/detector.rs:193-206 short()` 前3/后3；Rust 另认 `bankcard/apikey` 别名）；`P10` 字典非硬化边界不对称（Rust `custom.rs:182-201` after 用 `is_cjk=alnum∪CJK`（含全部 Unicode 字母数字），`café张三` 类判定与 Python `_pii.py:1400` 相反）；`P12` 占位符提示禁形态大小写（Python `_pii.py:310` 大小写敏感 `__VG_CRED_\d+__`；Rust `src/service/llm_gateway/placeholder.rs:13-34` 门控无大小写分支）；`P13`（低确证）内置 ASCII 粘连门归属（Rust `detector.rs:480-506 hardened_keep` 对 phone/id_card/bank_card/api_key 做 ASCII 粘连丢弃；Python 主扫描未见对应内置门，仅字典 `_dict_boundary_ok`）。
- **取证**：`P11` 采样 7 天滚动 SQL 未取证（`PII_VALUE_SAMPLE_PERSIST` 默认开与 README §6.2 一致；`src/service/metrics/store.rs:323-350/446-448/466-468` 的复合键建表、7 天滚动 DELETE 与覆盖 UPSERT 未在建表 SQL 层验证）。

真相源：`src/service/pii/custom.rs`、`src/service/pii/scope.rs`、`src/service/pii/chunk.rs`、`src/service/pii/detector.rs`、`src/service/redaction/seam.rs`、`src/config/custom_file.rs`、`src/service/metrics/store.rs`、`src/service/metrics/sample.rs`、`src/service/llm_gateway/placeholder.rs`、`src/handler/llm/pump/spawn.rs`。原仓对照基线为 Python `credential-proxy` 的 `_pii.py`/`_token.py`（行号随 finding）。

本 change 只交付规划 artifacts（proposal/design/spec/tasks），不改 `src/` 与 `tests/`；实现与 README 同步留待 apply 阶段。

## What Changes

- **`P14` 锁中毒恢复统一**：`custom.rs` 全部 9 处 `.expect("检测器锁无毒")` 改为 `PoisonError::into_inner` 恢复（首次 warn，复用 `scope.rs:19-31` 形态）；补中毒注入测试断言 `scan`/`load` 不 panic、结果正确。
- **`P1` 自定义规则跨帧前缀 hold（裁决-实现）**：`custom.rs` 暴露 `partial_prefix_hints()`（自定义字面前缀 + 字典全名，cap64、按长降序去重）；流式出口对帧尾 hint 前缀滞留至下一帧判定（完整命中整体掩码；不匹配放行；终止 flush 与既有 `BoundaryHold::flush` 同语义）；补跨帧自定义规则测试。备选（声明 Non-Goal 依赖缝窗）不采用，见 design D2。
- **`P2` 降级 health 可见**：health 响应新增只增字段（停用自定义规则计数），数据源 `disabled_snapshot()`；`src/main.rs`/`src/handler/admin.rs` health 组装接线；补降级后 health 可见测试。
- **`P3` 还原命中 touch**：`restore_exact` 命中时对请求表/响应表分别 `touch_order` 提升（命中即刷新热度）；补热值不逐出测试；注册复用路径语义不变。
- **`P4` fuzzy 超集文档化 + 审计分类（裁决-文档化）**：保持 `PII_FUZZY_RESTORE` 开关语义（默认关闭），文档锁定宽松还原边界为已声明超集（仅请求表、响应表/未知序号原样保留）；fuzzy 还原命中新增独立审计分类计数；不改变关闭时精确还原口径。
- **`P5` 序号游标语义锁定**：以测试锁定游标 + 已用集分配（回卷、淘汰释放复用、满表 `PII_MAX_ENTRIES + 1` 语义），文档声明与 Python 最小空洞的可见序号差异仅影响关联性，不承诺值一致。
- **`P6` 残缺剥离收窄确认（裁决-文档化）**：文档确认 D7 有意收窄（无序号 hex 形 `__PII_AB` 不剥、后随单词字符正文不剥）；补边界测试锁定；不对齐 Python 放宽。
- **`P7` PII_HOLD 语义映射**：文档声明 `PII_HOLD_MAX` 为响应侧跨帧缝窗字符数（0 = 响应侧关闭直通），审计 hold 字节上限由 `AUDIT_HOLD_MAX_BYTES` 独立承载；补跨缝掩码/窗口 0/信封分割行为矩阵测试。
- **`P8` 自定义变量超集**：README 环境变量全表区分文件变量（`*_FILE`，路径语义）与内联变量（无 `_FILE` 后缀，内容语义）；核验内联与文件共享 fail-closed 校验；补一致性测试。
- **`P9` 掩码边缘与别名**：非 4 段 6-7 字符 IPv4 形掩码对齐原仓前4/后4（重叠不裁剪）；`bankcard/apikey` 别名文档化为已声明超集；补边界测试。
- **`P10` 字典非硬化边界对齐**：`dict_boundary_ok` 非强化 `name/person` 的 after 门由 `alnum∪CJK` 收窄为 CJK 表意文字（before 维持 ASCII-only）；补 `café张三` 类边界测试。
- **`P11` 采样滚动/覆盖取证**：核验 `store.rs` 复合键建表、7 天 `last_seen` 滚动 DELETE 与 `ON CONFLICT(day,upstream,kind,hash) DO UPDATE hits=hits+1` 覆盖；补跨天分键/重复 flush/滚动删除测试。
- **`P12` 占位符门大小写**：核验注入门与还原形态均为大小写敏感精确前缀（无折叠），补大小写漂移形测试锁定（`__pii_...`/`__vg_cred_...` 既不触发注入也不被还原）。
- **`P13` 硬化粘连门归属**：核验 Python 非 hardening 主扫描无内置 ASCII 粘连门；确认 Rust `hardened_keep` 仅 `PII_DETECTION_HARDENING=1` 生效属有意收紧并文档化；补开/关两态测试。
- **文档同步**：README 环境变量全表（`PII_CUSTOM_*` 文件/内联分列、`PII_HOLD_MAX` 语义）、health 响应字段与 §6.2/§6.3/§7 相关声明随行为同批更新。

## Capabilities

### New Capabilities

- `pii-parity-closeout`：审计后 PII/脱敏面的收口契约——锁中毒恢复、自定义规则跨帧前缀 hold、降级 health 可见、还原 LRU 提升、fuzzy 超集边界与审计分类、序号游标/残缺剥离语义锁定、`PII_HOLD_MAX` 语义映射、自定义变量内联超集、掩码边缘与字典边界对齐、采样滚动覆盖、门大小写与硬化归属。

### Modified Capabilities

- 无 canonical 行为反转：`pii-parity`、`pii-custom-compat`、`redaction`、`sampler-correctness` 既有契约不动；本 change 新增加固面。若 apply 阶段核验发现需修订 canonical 条文（如 `P13` 归属结论），随归档同步并在 design 回填。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `P1` | missing/【裁决】 | `custom.rs` 暴露 `partial_prefix_hints()`（字面前缀+字典全名 cap64）；流式帧尾 hint 前缀滞留判定；跨帧自定义规则测试 | 2.1、2.2、2.3 |
| `P2` | missing | 停用规则计数接 health（只增字段）；`disabled_snapshot` 计数入 health 组装；降级后可见测试 | 3.1、3.2、3.3 |
| `P3` | missing | `restore_exact` 命中双表 `touch_order`；热值不逐出测试；注册路径语义不变 | 4.1、4.2 |
| `P4` | divergent/【裁决】 | 文档化 fuzzy 序号回查超集边界；补 fuzzy 审计分类计数；关闭态口径不变测试 | 5.1、5.2、5.3 |
| `P5` | divergent | 游标 O(1) 分配语义测试锁定（回卷/复用/满表）；文档声明可见序号差异仅关联性 | 6.1、6.2 |
| `P6` | divergent/【裁决】 | 文档确认 D7 收窄；`__PII_AB` 不剥与 `__PII_12_` 剥离边界测试 | 7.1、7.2 |
| `P7` | divergent | 文档 `PII_HOLD_MAX` 语义映射；跨缝掩码/窗口 0/信封分割测试 | 8.1、8.2 |
| `P8` | divergent | README 内联/文件变量分列；fail-closed 一致性核验与测试 | 9.1、9.2、9.3 |
| `P9` | divergent | 6-7 字符 IPv4 形掩码前4/后4 对齐；`bankcard/apikey` 别名文档化；边界测试 | 10.1、10.2、10.3 |
| `P10` | divergent | 非强化 after 门收窄为 CJK 表意文字；`café张三` 边界测试 | 11.1、11.2 |
| `P11` | open | 核验建表/7 天滚动/覆盖 UPSERT；跨天/重复 flush/滚动删除测试 | 12.1、12.2 |
| `P12` | low | 核验门与还原大小写敏感一致；漂移形测试锁定 | 13.1、13.2 |
| `P13` | low | 核验 Python 非硬化行为；确认仅硬化生效并文档化；开/关两态测试 | 14.1、14.2 |
| `P14` | high | 9 处 `.expect` 改 `PoisonError::into_inner` 恢复（首次 warn）；中毒注入测试；残检零命中 | 1.1、1.2、1.3 |

## Non-Goals（显式）

- **不重开已声明基线**：README §6.2（采样持久默认开）与 §6.3（容量分表/真 LRU）维持现状，仅补可见性与取证；不重开 §6.2/§6.3 的 BREAKING 讨论。
- **不对齐 Python 序号分配**：`P5` 保持游标 O(1) 设计，不引入全量最小空洞扫描。
- **不放宽残缺剥离**：`P6` 维持 D7 收窄，不恢复无序号 hex 剥离（防误删正文）。
- **不重命名 `PII_HOLD_MAX`**：`P7` 以文档映射承载语义重构，避免配置 BREAKING。
- **不改协议/审计 verdict/采样策略与掩码主口径**：`P9` 仅对齐非 4 段 6-7 字符边缘，不动机器可读主掩码分支；不新增依赖；本 change 不含 `src/` 与 `tests/` 改动（apply 阶段落地）。
- **不触碰其他 change**：除 `openspec/changes/veil-pii-parity-closeout/` 外不改任何 change 目录。

## Impact

- **新增文件**：`openspec/changes/veil-pii-parity-closeout/` 下 `proposal.md`、`design.md`、`specs/pii-parity-closeout/spec.md`、`tasks.md`（`.openspec.yaml` 已存在）。
- **apply 阶段改动面**：`src/service/pii/custom.rs`、`src/service/pii/scope.rs`、`src/service/pii/chunk.rs`、`src/service/pii/detector.rs`、`src/service/redaction/seam.rs`（如需出口接线）、`src/handler/llm/pump/spawn.rs`、`src/handler/admin.rs`、`src/main.rs`（health 组装）、对应单测与 `README.md`（环境变量全表/health/§6/§7）。
- **影响系统**：PII 检测/还原、自定义规则流式安全、审计降级可观测性、采样持久化取证、health 响应兼容性（只增字段）。
- **依赖**：无新依赖；仅既有 `regex`/`fancy_regex`/`rusqlite`/`serde_json` 与测试设施。
