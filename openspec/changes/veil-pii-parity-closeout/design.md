## Context

独立审计（2026-09-13）在 PII/脱敏与自定义规则面确认 14 项待收敛偏差（见 proposal Why 与覆盖表）。现状真相源与关键行号：

- 锁健壮性：`src/service/pii/custom.rs` 9 处 `.expect("检测器锁无毒")`（`:88`、`:118`、`:119`、`:175`、`:176`、`:209`、`:213`、`:321`、`:322`）vs `src/service/pii/scope.rs:19-31 recover_mutex` 的 `PoisonError::into_inner` 恢复（`P14`）。
- 缺失能力：自定义规则流式前缀 hold 无实现（Python `_pii.py:1196 partial_prefix_hints`）（`P1`）；`disabled_snapshot`（`custom.rs:154`）未接 health（`P2`）；`restore_exact`（`scope.rs:256-293`）命中不 `touch_order`（`P3`）。
- 语义分歧：fuzzy 宽松回查与审计分类（`scope.rs:218-253`、`detector.rs:81-86`）（`P4`）；序号游标分配（`scope.rs:93-114`）（`P5`）；残缺失剥（`chunk.rs:113-121`）（`P6`）；`PII_HOLD_MAX` 缝窗语义（`seam.rs:12-75`、`dispatch.rs:139-143`）（`P7`）；内联自定义变量超集（`custom_file.rs:394`）（`P8`）；掩码边缘（`detector.rs:193-206`）（`P9`）；字典非硬化 after 边界（`custom.rs:182-201`）（`P10`）；采样建表/滚动/覆盖 SQL（`store.rs:323-350/446-448/466-468`）（`P11`）；占位符门大小写（`placeholder.rs:13-34`）（`P12`）；硬化粘连门（`detector.rs:480-506`，调用点 `:527/:541`）（`P13`）。

约束：本 change 只写规划 artifacts，不改 `src/` 与 `tests/`；不重开 canonical `pii-parity`/`pii-custom-compat`/`redaction`/`sampler-correctness` 已锁定契约；裁决项结论以本 design 为准。

## Goals / Non-Goals

**Goals：**

- 给出 `P1`..`P14` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把锁恢复、前缀 hold、健康可见、还原 LRU、fuzzy 超集边界、序号/残缺/缝窗语义、内联超集、掩码/字典边界、采样滚动与门大小写收敛为 spec 契约。
- 对 `P1`/`P4`/`P6` 三个【裁决】项给出推荐决策、理由与备选及拒绝原因。

**Non-Goals：**

- 不撤销既有 canonical 设计（O(1) 序号游标、D7 残缺收窄、fuzzy 开关、内联变量、别名受理）。
- 不重命名环境变量（`PII_HOLD_MAX` 保持名称与默认值，仅文档映射语义）。
- 不引入新依赖、不改协议面与审计 verdict、不改采样开关默认值。
- 不在本 change 内改 `src/`/`tests/`/README（均为 apply 阶段工作量）。

## Decisions

### D1：`P14` 统一锁中毒恢复（实现）

**决策**：在 `custom.rs` 引入与 `scope.rs:19-31` 同形的 poison 恢复（可提取 crate 内共享 helper），替换全部 9 处 `.expect("检测器锁无毒")`；首次恢复打一次 `tracing::warn`；恢复后按当前内存状态继续服务（`scan` 读当前映射，`load_*` 全量覆盖写自愈）。

**理由**：持锁 panic 毒化是进程级状态，`.expect` 会让**每个后续请求**在 `scan`/`load` 热路径 panic（拒绝服务放大）；而恢复语义下自定义规则可能处于部分加载态，此时降级为「已加载部分/无自定义规则」仍安全（内置 recognizer 与凭据链路不依赖 custom 锁）。`scope.rs` 已确立该恢复口径（B3/D3），统一后消除双标准。

**备选**：(a) 保持 `.expect` 让进程快速失败——热路径连续 panic，拒绝；(b) 用 `catch_unwind` 包裹调用点——锁状态仍毒化，不解决；(c) `panic = "abort"`——改变部署形态且超出范围，拒绝。

### D2：`P1` 自定义规则跨帧前缀 hold（裁决-实现）

**决策**：实现。`CustomDetector` 暴露 `partial_prefix_hints() -> Vec<String>`：自定义正则的可提取字面前缀 + 字典全名，cap 64 字符、按长度降序去重。流式出口在放行帧前判定「已滞留尾部 + 当前帧」的尾部是否匹配任一 hint 的**前缀**：匹配则滞留（不发送该尾段）至下一帧重新判定；拼接后完整命中则对跨帧区间整体掩码（复用 `seam.rs` 掩码原语）；不再匹配则整体放行。流终止/阻断 flush 与 `BoundaryHold::flush` 同语义（不丢内容）。

**理由**：Python `_pii.py:1196` 的语义是「半截敏感字面量不得先泄出」。Rust 既有 `BoundaryHold`（`seam.rs:12-75`）只对「窗口内完整命中」做跨缝掩码，两点不足：(a) 窗口 `pii_boundary_chars` 由 `PII_HOLD_MAX` 决定且可为 0（响应侧关闭直通，`dispatch.rs:139-143`）；(b) 流末或超窗时半截字面前缀仍已放行。前缀 hold 与缝窗正交：前者防半截泄漏，后者防完整命中漏检，二者叠加才对齐原仓。

**备选**：(a) 声明 Non-Goal，文档化依赖缝窗——窗口可配 0 且不解决半截泄漏，拒绝；(b) 仅对字典名做 hold——自定义正则字面量同样敏感，覆盖不足，拒绝；(c) 把 hints 并入 `BoundaryHold` 的 `spans_fn`——该回调语义是「窗口内完整区间」，不表达「前缀滞留」，机制不匹配，拒绝。

**参数**：hints cap 64 与 `PII_HOLD_MAX` 默认 64 同量级；窗口为 0 时前缀 hold 是否仍生效需在 apply 定稿（建议仍生效，因其不依赖缝窗；确认后回填 spec）。

### D3：`P2` 降级 health 可见（实现）

**决策**：health 响应新增只增字段 `pii_custom_disabled`（已停用自定义规则计数，数据源 `disabled_snapshot().len()`），在 `src/main.rs`/`src/handler/admin.rs` 既有 health 组装点接线；`/_admin/health` 保持原字段，README 期望样例同步。

**理由**：ReDoS 连续 3 次超时停用意味着防护能力静默降级，运维必须可见；health 已有「只增不减」兼容声明（README §1），新增字段不破坏探针。

**备选**：仅文档化（不可观测，拒绝）；新增 Prometheus 指标（缺现成 PII 指标面，扩大范围，拒绝）。

### D4：`P3` 还原命中 touch（实现）

**决策**：`restore_exact` 改为两阶段：先扫描收集命中（请求表命中 / 响应表命中 / 未知形态），后对命中项分别 `touch_order(&mut inner.pii_order, ...)` 与 `touch_order(&mut inner.resp_order, ...)`；未知形态维持「原样保留 + `count_malformed` 审计」，不 touch。命中即提升与 Python `_token.py:381-401` 双表 `move_to_end` 对齐。

**理由**：README §6.3 声明「真 LRU」；若仅注册刷新热度，高频还原热值会被注册流量按容量逐出，导致下游还原断链（token 保留原文泄漏/可用性双输）。两阶段结构同时解决闭包内不可变借用问题。

**备选**：文档化「仅注册刷新」为 known deviation——与 §6.3 声明冲突且造成还原失败，拒绝。

### D5：`P4` fuzzy 超集文档化 + 审计分类（裁决-文档化）

**决策**：保持 `PII_FUZZY_RESTORE` 开关（默认关闭）与 `(?i)__PII_\d+_[^_\s]{1,16}__` 宽松回查；在 spec/README 锁定边界：仅请求表、响应表与未知序号原样保留、开关开启时截断/改写形亦可还原属**有意超集**；fuzzy 还原命中新增独立审计分类计数（`fuzzy`，与 `malformed`/`unregistered` 同管道、调用方限流落盘）；关闭时精确还原口径不改变。

**理由**：canonical `pii-parity` spec 已锁定「序号回查另作独立开关」，离线对齐 Python（仅全形态 8hex IGNORECASE）会撤销既有特性并引入 BREAKING；审计分类是 Python 有、Rust 缺的可见性面，补它成本低且让超集可观测（相比推荐方案 a/b 更完整）。

**备选**：(a) 完全对齐 Python（移除序号回查/收窄宽松正则）——撤销 canonical 已交付特性，拒绝；(b) 仅文档化不补审计——超集还原不可观测，拒绝；(c) 默认开启超集——隐私面扩大，拒绝（维持默认关闭）。

### D6：`P5` 序号游标语义锁定（不重开实现）

**决策**：保持 `alloc_seq`（`scope.rs:93-114`）游标 + `used_seqs` 的 O(1) 均摊分配；补测试锁定回卷、淘汰 `release_seq` 复用与满表 `PII_MAX_ENTRIES + 1` 语义；文档声明与 Python 最小空洞的可见序号差异仅影响跨实现关联性，不承诺值一致。

**理由**：O(1) 分配是既有 canonical 设计选择（F5/D4）；Python 最小空洞最坏 O(n) 且与 LRU 逐出交互复杂。序号是内部 token 成分，`rand8`（CSPRNG）承担不可预测性，序号值本身不对外承诺。

**备选**：对齐 Python 全量扫描——性能回退且撤销既有设计，拒绝。

### D7：`P6` 残缺剥离收窄确认（裁决-文档化）

**决策**：保持 `pii_partial_re`（`chunk.rs:113-121`）D7 收窄：仅剥离确证残缺续段（`__PI` + 可选 `I` + 可选 `_序号` + 可选 hex，后随边界）；无序号 hex 形（`__PII_AB`）与后随合法单词字符的正文（`__PIXEL`/`__PII_DATA`）不剥。补边界测试锁定并文档化。

**理由**：无序号 hex 形与合法正文不可区分（`__PII_AB` 可能是标识符/变量名），剥离即误删用户数据；风险方向不对称——少剥罕见半截占位符 vs 多删常见正文。Python 宽容口径（`_token.py:136`）是历史实现，本仓已声明收窄（D7），确认优于回退。

**备选**：(a) 对齐 Python 放宽——误删正文风险，拒绝；(b) 完全不移除残缺——完整占位符残片会透出，与出口卫生目标冲突，拒绝。

### D8：`P7` `PII_HOLD_MAX` 语义映射（文档化）

**决策**：文档声明 `PII_HOLD_MAX`（默认 64）在 Rust 为**响应侧跨帧缝窗字符数**（0 = 响应侧关闭直通）；审计 hold 字节上限由 `AUDIT_HOLD_MAX_BYTES`（默认 1MB）独立承载；缝窗检测在 JSON 信封过滤后的解码文本空间进行并映射回原帧坐标、整帧延迟一级。补跨缝掩码 / 窗口 0 / 信封分割行为矩阵测试。

**理由**：变量已发布且与原仓同名同默认，重命名属配置 BREAKING；语义差异以文档映射吸收，README 环境变量表与 §6/§7 同步。行为已有 `seam.rs` 单测基础，补齐 spec 场景即可。

**备选**：重命名/新增双变量——配置 BREAKING，拒绝；保持静默差异——审计发现项，拒绝。

### D9：`P8` 自定义变量超集（文档 + 核验）

**决策**：README 环境变量全表将「文件路径」（`*_FILE` 系列：缺文件/不可读/解析失败拒启动）与「内联内容」（无 `_FILE` 后缀的 `PII_CUSTOM_RULES/PATTERNS/DICT`，同解析/同校验）分列；核验 `custom_file.rs` 两分支共享解析与 fail-closed 校验函数；补内联非法拒启动与叠加生效测试。

**理由**：现表把内联变量与文件变量并列，易误读为路径；内联是已实现超集（`custom_file.rs:394` 测试已覆盖内联变量名），文档补齐为主，代码仅测试补强。

**备选**：删除内联支持——BREAKING 且降低可用性，拒绝。

### D10：`P9` 掩码边缘对齐 + 别名文档化

**决策**：`mask_pii_value`（`detector.rs:193-206`）的非 4 段 6-7 字符 IPv4 形分支对齐原仓前 4/后 4（重叠不裁剪、逐字符）；`bankcard/apikey` 作为已声明别名保留并在 spec/README 记录。采样侧 `sample_mask`（`sample.rs:196-205`）由 canonical `sampler-correctness` 独立锁定，本 change 不扩散改动。

**理由**：掩码是下游可见形态（监控/人工核对），逐字对齐减少跨实现困惑；边缘值影响面极小、对齐成本极低。别名受理是兼容超集，无隐私影响。

**备选**：文档化差异不对齐——审计要求「对齐或文档化」二选一，对齐更彻底，选择对齐。

### D11：`P10` 字典非强化边界对齐

**决策**：`dict_boundary_ok`（`custom.rs:182-201`）非强化 `name/person` 分支的 after 门由 `is_cjk`（CJK ∪ 全部 Unicode 字母数字）收窄为 CJK 表意文字判定（`'\u{4e00}'..='\u{9fff}'`）；before 维持 ASCII 字母数字；强化分支（严格 CJK 双侧）不变。

**理由**：Python `_pii.py:1400` 非硬化 before 仅 ASCII、after 含 CJK；Rust 把 `é`/`ñ` 等变音字母也计入 after 阻断，导致「字典名紧贴西文变音词」的命中被误拒（漏检方向）。收窄后仅真正 CJK 紧贴时阻断，与 `保张三丰不误伤` 的注释意图同向。

**备选**：文档化不对称——审计要求「对齐边界」，且属漏检，选择对齐。

### D12：`P11` 采样滚动/覆盖取证（核验 + 测试）

**决策**：以 store 层测试锁定：建表复合键 `(day, upstream, kind, hash)`（`store.rs:348-355`）、启动旧单键表重建（`store.rs:323-347`）、7 天滚动 `DELETE FROM pii_value_samples WHERE last_seen < now - PII_SAMPLE_RETENTION_DAYS * 86400`（`store.rs:442-450`）、覆盖式 `ON CONFLICT(day, upstream, kind, hash) DO UPDATE SET hits = hits + 1`（`store.rs:465-469`）与跨天同值分键不合并；补跨天/重复 flush/滚动边界测试。若核验发现 SQL 与声明不符，修复范围限 store 层并回填证据。

**核验结论（apply 回填）**：实现与声明一致，无需修复。取证：`ensure_pii_value_samples_table` 建表主键 `PRIMARY KEY(day, upstream, kind, hash)`（`store.rs:348-355`）、旧单键表（无 `day` 列）`DROP TABLE` 重建（`store.rs:332-347`）、`purge_retention_blocking` 的 `last_seen < now - PII_SAMPLE_RETENTION_DAYS * 86400` 滚动删除（`store.rs:442-450`）、`persist_sample_batch` 的 `ON CONFLICT(day, upstream, kind, hash) DO UPDATE SET hits=hits+1, last_seen=excluded.last_seen`（`store.rs:465-469`）。测试锁定：`sample_upsert_rollover`（重复 flush 合一行且 hits=2、`last_seen` 刷新、超期行删除）、`sample_retention`（7 天边界内保留、越界删除），另既有 `persist_upsert_keys_on_day_upstream_kind_hash`/`legacy_single_key_table_rebuilds_to_composite` 覆盖跨天分键与重建。

**理由**：README §6.2 与 canonical `sampler-correctness`「Dedup keys include kind」已声明语义，缺的是建表 SQL 层取证与滚动边界测试；采样为趋势参考（不进主错链），测试覆盖正常路径即可。

**备选**：仅文档记录——审计要求「核验实现并补测试」，拒绝。

### D13：`P12` 占位符门大小写一致（核验 + 测试锁定）

**决策**：核验确认注入门（`placeholder.rs:36-44` 的 `__PII_`/`__VG_CRED_` 精确字节前缀）与还原形态（`pii_token_re`/`cred_token_shape_re` 大小写敏感）同口径；补大小写漂移形（`__pii_...`/`__vg_cred_...`）测试断言既不触发注入也不被还原；若核验发现任一侧放行则对齐到大小写敏感。

**理由**：Python `_pii.py:310` 大小写敏感；门控与还原必须同口径，否则出现「注入说明但还原失败」或「未注入却还原」的不一致。

**备选**：引入 IGNORECASE——改变已声明严格 token 形态，拒绝。

### D14：`P13` 硬化粘连门归属（核验后文档化为有意收紧）

**决策**：核验 Python 非 hardening 主扫描无对应内置 ASCII 粘连门（仅字典 `_dict_boundary_ok`）；确认 Rust `hardened_keep`（`detector.rs:489-515`）仅在 `PII_DETECTION_HARDENING=1`（调用点 `:536-537`/`:550-551`）生效，属有意收紧；文档记录归属；补开/关两态测试（关：粘连命中保留、与原仓一致；开：phone/id_card/bank_card/api_key 丢弃 ASCII 粘连、IPv4 另拒前导零段）。若核验发现 Python 强化路径有不同语义，则改为对齐并回填本决策。

**核验结论（apply 回填）**：Python 侧**非 hardening 与 hardening 主扫描均无**针对 `phone`/`id_card`/`bank_card`/`api_key` 的内置 ASCII 粘连门；`_is_detection_hardening()` 门控的 4 项增强为「保留地址精确前缀 + `ip_network` 兜底、ReDoS 守卫、字典独立扫描 CJK 边界、analyzer `lru_cache`」（`_pii.py:315-333`），唯一 ASCII 粘连门是字典 `_dict_boundary_ok`（`_pii.py:1416-1444`）。故 Rust `hardened_keep` 的 ASCII 粘连丢弃属 **Rust 独有的有意收紧**，非 Python 移植，默认关闭时不影响原仓行为。测试 `hardening_adjacency` 锁定两态；`grep -rn "hardened_keep" src/` 生产调用仅两处，均位于 `if self.hardening()` 分支内。

**理由**：门是 hardening 模式语义的一部分，默认关闭不影响原仓行为；低确证 finding 须先核验 Python 强化路径，避免误改。

**备选**：删除该门——削弱 hardening 能力，拒绝；对齐非强化（即默认开启）——改变默认行为，拒绝。

## Risks / Trade-offs

- [`P14` 恢复后状态可能部分更新] → `load_*` 为全量覆盖写（幂等自愈），`scan` 读当前映射无 panic；中毒注入测试覆盖 `scan`/`load` 两路径。
- [`P1` hint 提取对无可提取字面前缀的复杂正则退化] → 该规则退化为仅缝窗保护；hints 提取策略在 apply 定稿（见 Open Questions），文档声明退化边界。
- [`P1` 滞留改变首帧时序] → 与既有 `BoundaryHold` 同为一帧延迟语义；补「不匹配放行」与「终止 flush」场景防阻塞。
- [`P3` touch 改变逐出顺序] → 与 Python 真 LRU 对齐；补热值/冷值测试；容量常量（1000）不变。
- [`P2` health 字段只增不减] → 既有探针兼容；README 期望样例与字段名同批更新。
- [`P4` 超集仅开关开启时可还原截断 token] → 文档声明隐私边界（生产建议保持默认关闭）；fuzzy 计数暴露使用面。
- [`P9` 前4/后4 重叠不裁剪] → 逐字对齐原仓；掩码 64 上限（`truncate_mask`）不受影响。
- [`P10` 边界收窄新增字典命中] → 属漏检修复；指标波动属预期，测试逐条锁定。
- [`P12`/`P13` 核验结论可能与预期相反] → D13/D14 已写明「核验后对齐/回填」分支；若需 canonical 修订随归档同步。
- [`P11` SQL 与声明不符] → 修复限 `store.rs`，不改变采样默认开关与 canonical 去重键。

## Migration Plan

1. 按 tasks 顺序落地：先健壮性（`P14`），再流式安全（`P1`/`P7`），再可见性（`P2`/`P3`），再语义锁定（`P4`/`P5`/`P6`/`P12`/`P13`），再文档/取证/边界（`P8`/`P9`/`P10`/`P11`），最后门禁。
2. 每组独立 `cargo test -p veil <组>`；README 与环境变量表随行为同批更新；spec 场景与测试名对齐。
3. 回滚策略：按组 revert 对应 diff；无 schema 迁移（`P11` 仅测试）、无新依赖、无部署形态变化、无 BREAKING 配置项。
4. 发布口径：health 只增字段与掩码/边界对齐为可感知变化，README 同批声明；`P1` 前缀 hold 为流式时序变化（整帧延迟既有语义内），文档声明。

## Open Questions

- `P1` 字面前缀提取策略：`regex-syntax` HIR 遍历 vs 保守启发式（取 pattern 起始字面段）；若引入启发式，无可提取前缀的规则退化为缝窗保护，需在 apply 定稿并回填 spec。
- `P1` 窗口 `PII_HOLD_MAX=0`（响应侧关闭）时前缀 hold 是否仍生效：倾向生效（不依赖缝窗），apply 确认后回填。
- `P13` Python 强化路径核验结论：若存在对应内置门语义差异，改为对齐并回填 D14。
- `P11` finding 中的 `pii_value_agg`/「≤40 行/日」与实际 `pii_value_samples` + `top_n`（`admin.rs:408`）口径映射，取证时以代码为准回填。
