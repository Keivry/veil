## 1. `P14` 锁中毒恢复统一（high）

- [x] 1.1 `src/service/pii/custom.rs:88/118/119/175/176/209/213/321/322`：9 处 `.expect("检测器锁无毒")` 全部改为 `PoisonError::into_inner` 恢复（首次 warn 一次；可提取与 `src/service/pii/scope.rs:19-31` 同形的共享 helper），`scan`/`scan_custom`/`load_custom`/`load_dict`/strike 记账路径不再因锁毒化 panic
  - 验证：`cargo test -p veil pii_lock_poison` 通过；`grep -n "检测器锁无毒" src/service/pii/custom.rs` 零命中
  - 验证：`cargo clippy --tests --all-targets -- -D warnings` 退出码 0
- [x] 1.2 补中毒注入测试：同模块测试持锁 panic 毒化（`catch_unwind`）后断言 `scan`/`scan_custom` 正常返回、`load_custom` 后新规则生效（自愈）
  - 验证：`cargo test -p veil pii_lock_poison_recovery` 通过；断言恢复路径结果与未中毒基线一致且仅 warn 一次
- [x] 1.3 覆盖全部访问点的回归清单：逐行核对 9 处调用点均无 `.expect`/`unwrap`（含 `disabled`/`strikes` 锁）
  - 验证：`grep -rn "\.expect(\"检测器锁无毒\")" src/` 零命中；`cargo test -p veil custom` 全绿

## 2. `P1` 自定义规则跨帧前缀 hold（裁决-实现）

- [x] 2.1 `src/service/pii/custom.rs`：新增 `partial_prefix_hints()`——自定义正则可提取字面前缀 + 字典全名，cap 64 字符、按长度降序去重；无可提取前缀的规则退化声明（design Open Questions 定稿）
  - 验证：`cargo test -p veil partial_prefix_hints` 通过；断言 cap 64、降序、去重、字典全名在内
- [x] 2.2 流式出口接线（`src/handler/llm/pump/spawn.rs` 缝处理链）：帧尾匹配 hint 前缀时滞留至下一帧判定（完整命中跨帧整体掩码；不再匹配放行；终止/阻断 flush 与 `BoundaryHold::flush` 同语义）
  - 验证：`cargo test -p veil custom_prefix_hold` 通过；构造字典名/自定义正则字面量跨两帧，断言首帧不直接放行半截、完整命中被掩码、不匹配场景原样放行且无内容丢失
  - 验证：`cargo test -p veil boundary_hold` 全绿（既有缝窗语义无回退）
- [x] 2.3 补跨帧自定义规则矩阵测试：字典名/正则字面前缀/终止 flush/阻断 flush 四场景
  - 验证：`cargo test -p veil custom_prefix_hold_matrix` 通过；`PII_HOLD_MAX=0` 时行为按 design 定稿断言并记录

## 3. `P2` 降级规则 health 可见

- [x] 3.1 health 组装接线（`src/main.rs`/`src/handler/admin.rs`）：新增只增字段（停用自定义规则计数，数据源 `disabled_snapshot()`）
  - 验证：`cargo test -p veil health_pii_custom_disabled` 通过；构造停用（连续 3 次超时）后断言字段 ≥ 1
  - 验证：`grep -n "pii_custom_disabled" src/main.rs src/handler/admin.rs` 命中
- [x] 3.2 既有 health 字段兼容锁定测试（只增不改）
  - 验证：`cargo test -p veil health` 全绿；探针期望字段（`ok`/`sqlite_ok`/`status`/`unlocked`/`pending`/`llm_secrets`）不变
- [x] 3.3 README §1 健康检查期望样例与字段说明同步（新字段只增）
  - 验证：`grep -n "pii_custom_disabled" README.md` 命中；样例与实现字段名一致

## 4. `P3` 还原命中 touch

- [x] 4.1 `src/service/pii/scope.rs:256-293 restore_exact`：改两阶段（先收集请求表/响应表命中，后分别 `touch_order`），未知形态维持原样保留 + `count_malformed`
  - 验证：`cargo test -p veil restore_touch_lru` 通过；热值持续还原 + 注册流量触发淘汰后仍在表内，冷值先逐出
  - 验证：`cargo test -p veil restore` 全绿（精确还原/审计计数无回退）
- [x] 4.2 响应表命中提升与注册复用路径语义不变锁定测试
  - 验证：`cargo test -p veil restore_touch_dual_table` 通过；响应 token 条目热度刷新，`register` 同值复用仍 touch

## 5. `P4` fuzzy 超集文档化 + 审计分类（裁决-文档化）

- [x] 5.1 `src/service/pii/scope.rs:218-253`：fuzzy 还原命中新增独立审计分类计数（`fuzzy`，与 malformed/unregistered 同管道、调用方限流落盘）
  - 验证：`cargo test -p veil fuzzy_audit_category` 通过；开启开关且输入截断形时计数 +1 并返回还原值
- [x] 5.2 关闭态口径不变测试：`PII_FUZZY_RESTORE` 关闭时仅精确还原、无 fuzzy 计数、截断/改写形原样保留
  - 验证：`cargo test -p veil fuzzy_disabled_exact` 通过
- [x] 5.3 README（§6/§7 或环境变量表）文档锁定超集边界：仅请求表可还原、响应表/未知序号原样保留、开关开启时截断/改写形可还原属有意超集
  - 验证：`grep -n "PII_FUZZY_RESTORE" README.md` 命中且含超集边界表述

## 6. `P5` 序号游标语义锁定

- [x] 6.1 补游标分配测试：回卷、淘汰 `release_seq` 复用、全表占满返回 `PII_MAX_ENTRIES + 1` 且后续淘汰释放恢复
  - 验证：`cargo test -p veil alloc_seq_cursor` 通过；`scope.rs:93-114` 既有 `scan_steps` 测试口径断言探测步数线性有界
- [x] 6.2 文档声明可见序号差异仅影响关联性（README §6.3/§7 或 canonical 注释）
  - 验证：`grep -rn "最小空洞" README.md openspec/changes/veil-pii-parity-closeout/` 命中且表述为「仅关联性、不承诺值一致」

## 7. `P6` 残缺剥离收窄确认（裁决-文档化）

- [x] 7.1 `src/service/pii/chunk.rs:113-121` 边界测试：`__PII_AB` 不剥、`__PIXEL`/`__PII_DATA` 不剥、`__PII_12_` 剥离、完整形态保留
  - 验证：`cargo test -p veil pii_partial_narrowed` 通过
- [x] 7.2 文档确认 D7 有意收窄（README §6/§7 或 spec 场景）
  - 验证：`grep -rn "收窄" README.md openspec/changes/veil-pii-parity-closeout/specs/pii-parity-closeout/spec.md` 命中且含无序号 hex 不剥说明

## 8. `P7` PII_HOLD 语义映射

- [x] 8.1 补跨缝行为矩阵测试（`src/service/redaction/seam.rs`）：跨缝手机号两侧掩码、`PII_HOLD_MAX=0` 直通、JSON 信封隔断同掩码
  - 验证：`cargo test -p veil seam_matrix` 通过；`cargo test -p veil boundary_hold` 全绿
- [x] 8.2 README 环境变量表与 §7 记录语义映射：`PII_HOLD_MAX` = 响应侧跨帧缝窗字符数（0=关闭直通），审计 hold 字节由 `AUDIT_HOLD_MAX_BYTES` 独立承载
  - 验证：`grep -n "PII_HOLD_MAX" README.md` 命中且不再表述为审计 hold 上限；`grep -n "AUDIT_HOLD_MAX_BYTES" README.md` 命中

## 9. `P8` 自定义变量超集

- [x] 9.1 README 环境变量全表分列：文件变量（`*_FILE` 路径语义）与内联变量（`PII_CUSTOM_RULES/PATTERNS/DICT` 内容语义），fail-closed 规则同述
  - 验证：`grep -n "PII_CUSTOM_RULES" README.md` 命中且内联/文件语义可区分
- [x] 9.2 核验 `src/config/custom_file.rs` 内联与文件分支共享解析/fail-closed 校验；补内联非法拒启动与叠加生效测试
  - 验证：`cargo test -p veil custom_inline` 通过；非法内联拒启动且报错含变量名
- [x] 9.3 `veil-pii-parity-closeout` spec「自定义变量内联超集」场景与 README 表述一致核验
  - 验证：`grep -rn "内联" openspec/changes/veil-pii-parity-closeout/ README.md` 命中且无冲突表述

## 10. `P9` 掩码边缘与别名

- [x] 10.1 `src/service/pii/detector.rs:193-206`：非 4 段 6-7 字符 IPv4 形 `short()` 对齐原仓前 4/后 4（重叠不裁剪）
  - 验证：`cargo test -p veil mask_ipv4_edge` 通过；6/7 字符用例逐字断言前4/后4
- [x] 10.2 `bankcard`/`apikey` 别名受理文档化（spec/README），行为与主名一致测试
  - 验证：`cargo test -p veil mask_kind_alias` 通过；`grep -rn "bankcard\|apikey" README.md openspec/changes/veil-pii-parity-closeout/` 命中
- [x] 10.3 掩码 64 上限与既有分支回归（phone/email/bank/ipv6/api_key/other）
  - 验证：`cargo test -p veil mask_pii_value` 全绿

## 11. `P10` 字典非硬化边界对齐

- [x] 11.1 `src/service/pii/custom.rs:182-201`：非强化 `name/person` 的 after 门由 `alnum∪CJK` 收窄为 CJK 表意文字（before 维持 ASCII-only；强化分支不变）
  - 验证：`cargo test -p veil dict_boundary_nonhardened` 通过；`café张三` 类用例与 Python 非硬化口径一致
- [x] 11.2 边界矩阵测试：CJK 紧贴阻断、ASCII 粘连阻断、变音字母数字不误拒三组
  - 验证：`cargo test -p veil dict_boundary` 全绿（含强化开启严格 CJK 用例）

## 12. `P11` 采样滚动/覆盖取证

- [x] 12.1 核验 `src/service/metrics/store.rs:323-350/446-448/466-468`：复合键建表、旧单键表重建、7 天 `last_seen` 滚动 DELETE、`ON CONFLICT(day,upstream,kind,hash) DO UPDATE hits=hits+1`；证据行号回填 design
  - 验证：`cargo test -p veil sample_upsert_rollover` 通过；重复 flush 两行合一行且 hits=2；`last_seen` 超 7 天行被删
- [x] 12.2 补跨天分键不合并与滚动边界测试（第 7 天边界、窗口内保留）
  - 验证：`cargo test -p veil sample_retention` 通过；证据与 canonical `sampler-correctness` 去重键条款一致

## 13. `P12` 占位符门大小写一致

- [x] 13.1 核验 `src/service/llm_gateway/placeholder.rs:13-34` 注入门与还原形态（`pii_token_re`/`cred_token_shape_re`）同为大小写敏感精确前缀；若不一致则对齐
  - 验证：`cargo test -p veil placeholder_case_sensitive` 通过；`__vg_cred_000123__`/`__pii_...` 漂移形既不注入也不还原
- [x] 13.2 补大小写漂移形测试（注入侧与还原侧同断言）
  - 验证：`cargo test -p veil placeholder_case_drift` 通过

## 14. `P13` 硬化粘连门归属

- [x] 14.1 核验 Python 非 hardening 主扫描行为（无内置 ASCII 粘连门，仅字典 `_dict_boundary_ok`）并回填 design D14 结论
  - 验证：`openspec/changes/veil-pii-parity-closeout/design.md` D14 含核验结论与证据
- [x] 14.2 补开/关两态测试（`src/service/pii/detector.rs:480-506` 调用点 `:527/:541`）：强化关粘连保留、强化开丢弃、IPv4 前导零拒
  - 验证：`cargo test -p veil hardening_adjacency` 通过；`grep -rn "hardened_keep" src/` 生产调用仅在 hardening 分支

## 15. 门禁与回归

- [x] 15.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 15.2 `openspec validate veil-pii-parity-closeout --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 15.3 `python3 scripts/check_doc_paths.py` 退出码 0；README 与 spec 引用路径全部存在
  - 验证：脚本输出 `OK` 且无 `FAIL` 行
