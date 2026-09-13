# pii-parity-closeout Specification

## Purpose
锁定审计后 PII/脱敏面的收口契约：锁中毒恢复、自定义规则跨帧前缀 hold、降级 health 可见、还原命中 LRU 提升、fuzzy 超集边界与审计分类、序号游标与残缺剥离语义、`PII_HOLD_MAX` 语义映射、自定义变量内联超集、掩码边缘与字典边界对齐、采样滚动覆盖与门大小写/硬化归属。

## Requirements

### Requirement: 检测器锁中毒恢复

系统 SHALL 在自定义检测器的全部互斥锁访问点以 `PoisonError::into_inner` 恢复（首次恢复打一次 warn），SHALL NOT 使用 `.expect` 使持锁 panic 在后续请求的 `scan`/`load` 热路径持续放大；恢复后 `scan`/`load` SHALL 返回正常结果而非 panic。

#### Scenario: 锁中毒后扫描不 panic

- **WHEN** 自定义检测器某把锁被持锁 panic 毒化后调用 `scan`/`scan_custom`
- **THEN** 调用正常返回匹配结果，无 panic 传播，且首次恢复产生一条 warn

#### Scenario: 锁中毒后加载自愈

- **WHEN** 毒化后调用 `load_custom`/`load_dict` 重新加载
- **THEN** 新规则完整生效，后续扫描按新规则命中

### Requirement: 降级规则健康可见

系统 SHALL 在健康检查响应中暴露已停用自定义规则计数（`disabled_snapshot` 口径，只增字段），使 ReDoS 连续 3 次超时停用在运维面可见；既有 health 字段 SHALL 保持兼容（只增不改）。

#### Scenario: 停用后 health 可见

- **WHEN** 某自定义规则连续 3 次超时被停用
- **THEN** health 响应的停用计数字段 ≥ 1，且既有字段不变

#### Scenario: 无停用归零

- **WHEN** 无规则被停用
- **THEN** 停用计数字段为 0，health 探针兼容旧消费方

### Requirement: 还原命中提升 LRU

系统 SHALL 在还原命中时将对应条目提升为最近使用（请求表与响应表分别 `touch_order`），使高频还原热值在容量压力下不被逐出；未知形态 SHALL 维持原样保留与审计计数，不提升。

#### Scenario: 热值不被逐出

- **WHEN** 某已注册值持续出现在还原输入中，同时注册流量触发容量淘汰
- **THEN** 该热值仍在请求表内并可继续还原，冷值先被逐出

#### Scenario: 响应表命中同样提升

- **WHEN** 还原输入命中响应期 token（原样保留语义）
- **THEN** 该条目在响应表中的热度被刷新

### Requirement: 自定义规则跨帧前缀 hold

系统 SHALL 提供自定义规则前缀 hint（自定义正则可提取字面前缀 + 字典全名，cap 64、长度降序去重）；流式放行前若尾部匹配任一 hint 前缀，系统 SHALL 滞留至下一帧完成判定（完整命中则跨帧整体掩码；不再匹配则放行），SHALL NOT 在首帧直接放行半截自定义字面量。终止/阻断 flush SHALL 与既有 `BoundaryHold::flush` 同语义（不丢内容）。

#### Scenario: 跨帧字典名不先泄出

- **WHEN** 字典全名被 SSE 切分到相邻两帧且属于 hint 前缀
- **THEN** 首帧不直接放行半截字面量，拼接后完整命中被掩码

#### Scenario: 前缀不续接正常放行

- **WHEN** 帧尾匹配 hint 前缀但下一帧不构成该 hint
- **THEN** 滞留内容按原样放行，无内容丢失

#### Scenario: 终止时 flush 不阻塞

- **WHEN** 流在滞留状态下终止
- **THEN** 滞留内容按 flush 语义释放，终端帧恒恰一

### Requirement: fuzzy 还原超集与审计分类

系统 SHALL 保持 `PII_FUZZY_RESTORE` 开关语义（默认关闭）：关闭时按精确形态还原；开启时按序号回查的宽松还原 SHALL 作为已声明超集（截断/改写形亦可还原），仅请求表可还原、响应表与未知序号原样保留；系统 SHALL 对 fuzzy 还原命中记录独立审计分类计数（与 malformed/unregistered 同管道），SHALL NOT 改变关闭时的精确还原口径。

#### Scenario: 开启时截断形还原并计数

- **WHEN** `PII_FUZZY_RESTORE` 开启且输入含某请求 token 的截断/改写形
- **THEN** 按序号回查还原为原值，并记录一条 fuzzy 审计分类计数

#### Scenario: 关闭时口径不变

- **WHEN** `PII_FUZZY_RESTORE` 关闭
- **THEN** 仅精确形态还原，截断/改写形原样保留，无 fuzzy 计数

### Requirement: 序号游标分配语义

系统 SHALL 使用游标 + 在用序号集合的 O(1) 均摊分配：游标到顶回卷、淘汰释放的序号可复用、全表占满时返回 `PII_MAX_ENTRIES + 1` 并由紧随的 LRU 淘汰释放；与 Python 最小空洞扫描的可见序号值差异 SHALL 被文档声明为仅影响关联性，不承诺跨实现一致。

#### Scenario: 淘汰后序号复用

- **WHEN** 容量淘汰释放某序号后继续注册
- **THEN** 分配可复用该释放序号，不无限膨胀

#### Scenario: 满表语义

- **WHEN** 全部序号在用且注册继续
- **THEN** 分配返回 `PII_MAX_ENTRIES + 1`，紧随淘汰使后续分配恢复正常序号

### Requirement: 残缺剥离收窄锁定

系统 SHALL 仅剥离确证残缺续段（`__PI` + 可选 `I` + 可选 `_序号` + 可选 hex 段，且后随边界）；SHALL NOT 剥离无序号 hex 形（如 `__PII_AB`）与后随合法单词字符的正文（如 `__PIXEL`/`__PII_DATA`）；该收窄 SHALL 被文档确认为有意行为。

#### Scenario: 无序号 hex 不剥

- **WHEN** 文本含 `__PII_AB` 且后随边界
- **THEN** 逐字节原样保留

#### Scenario: 确证残缺续段剥离

- **WHEN** 文本含 `__PII_12_` 等带序号残段且后随边界
- **THEN** 该残段被剥离，完整 `__PII_<seq>_<rand8>__` 不受影响

### Requirement: PII_HOLD 语义映射

系统 SHALL 将 `PII_HOLD_MAX` 解释为响应侧跨帧缝窗字符数（0 = 响应侧关闭直通），审计 hold 字节上限由 `AUDIT_HOLD_MAX_BYTES` 独立承载；跨缝检测 SHALL 在 JSON 信封过滤后的解码文本空间进行并映射回原帧坐标、整帧延迟一级；该语义与 Python 审计 hold 尾部持有的映射 SHALL 被文档记录。

#### Scenario: 跨缝命中两侧掩码

- **WHEN** 敏感值被切分到相邻两帧且跨缝合处
- **THEN** 缝两侧的片段均被掩码，不出现半截明文

#### Scenario: 窗口零直通

- **WHEN** `PII_HOLD_MAX = 0`（或响应侧关闭）
- **THEN** 不启用缝窗滞留，帧按直通语义放行

#### Scenario: JSON 信封分割同掩码

- **WHEN** 敏感值被 JSON 结构字符（引号/括号等）隔断在窗口内
- **THEN** 信封过滤后仍按解码文本空间命中并掩码，结构字符保真

### Requirement: 自定义变量内联超集

系统 SHALL 支持内联内容变量 `PII_CUSTOM_RULES/PATTERNS/DICT`（与 `*_FILE` 文件变量叠加），内联与文件加载 SHALL 共享同一解析与 fail-closed 校验（缺文件/解析失败/形态非法拒启动）；README 环境变量全表 SHALL 区分文件变量与内联变量语义。

#### Scenario: 内联非法拒启动

- **WHEN** 内联变量内容形态非法
- **THEN** 启动被拒绝并指明变量名，而非静默忽略

#### Scenario: 内联与文件叠加

- **WHEN** 同时配置文件变量与内联变量
- **THEN** 两者规则叠加生效，加载顺序/优先级与既有列序一致

### Requirement: 掩码边缘与别名

系统 SHALL 使非 4 段 6-7 字符 IPv4 形值的 `mask_pii_value` 掩码与原仓一致（前 4/后 4，重叠不裁剪）；`bankcard`/`apikey` kind 别名 SHALL 作为已声明超集受理并记录。

#### Scenario: 6-7 字符 IPv4 形掩码

- **WHEN** kind 为 `ipv4` 且值非 4 段、长度为 6 或 7
- **THEN** 掩码取前 4 字符与后 4 字符拼接，与 Python 口径逐字一致

#### Scenario: 别名受理

- **WHEN** 采样/检测 kind 为 `bankcard` 或 `apikey`
- **THEN** 分别按 `bank_card`/`api_key` 分支处理，行为与主名一致

### Requirement: 字典非硬化边界对齐

系统 SHALL 使 `name`/`person` 字典命中的非强化边界与 Python 一致：before 仅 ASCII 字母数字阻断，after 仅 CJK 表意文字阻断，SHALL NOT 将全部 Unicode 字母数字计入 after 阻断；强化开启时维持严格 CJK 边界。

#### Scenario: 变音字母不误拒

- **WHEN** 字典名紧贴西文变音字母数字（如 `café`）且强化关闭
- **THEN** 命中按边界规则正常保留/拒绝，与 Python 非硬化口径一致

#### Scenario: CJK 紧贴阻断

- **WHEN** 字典名后紧贴 CJK 表意文字
- **THEN** 命中被阻断，避免更长名称的部分匹配

### Requirement: 采样滚动与覆盖

系统 SHALL 以复合键 `(day, upstream, kind, hash)` 覆盖式 UPSERT（`ON CONFLICT ... DO UPDATE SET hits = hits + 1`，重复 flush 不翻倍），SHALL 按 `last_seen` 保留 7 天滚动删除；建表/滚动/覆盖语义 SHALL 由 store 层测试锁定。

#### Scenario: 重复 flush hits 累加

- **WHEN** 同一天/同上游/同 kind/同 hash 两次落盘
- **THEN** 仅一行且 hits 为 2，不产生重复行

#### Scenario: 超期行被滚动删除

- **WHEN** 某行 `last_seen` 早于保留窗口（7 天）
- **THEN** 滚动清理删除该行，窗口内行保留

#### Scenario: 跨天同值分键

- **WHEN** 同值在相邻两天被采样
- **THEN** 生成两行（各自 day 键），hits 不互相合并

### Requirement: 占位符门大小写一致

系统 SHALL 保持占位符注入门与还原形态均为大小写敏感的精确前缀（`__PII_`/`__VG_CRED_`，无大小写折叠）；大小写漂移形 SHALL 既不触发注入也不被还原。

#### Scenario: 漂移形不触发注入

- **WHEN** 请求体含大小写漂移占位符（如 `__vg_cred_000123__`）
- **THEN** 不触发占位符说明注入

#### Scenario: 门与还原一致

- **WHEN** 文本含大小写漂移 token
- **THEN** 还原侧亦不放行该形态，门控与还原口径一致

### Requirement: 硬化粘连门归属

系统 SHALL 仅在 `PII_DETECTION_HARDENING` 开启时对 `phone`/`id_card`/`bank_card`/`api_key` 施加 ASCII 粘连丢弃（IPv4 另拒前导零段）；非强化路径 SHALL 与原仓一致（无该门）；归属差异 SHALL 文档记录为有意收紧。

#### Scenario: 强化开启丢弃粘连

- **WHEN** 强化开启且数字类命中两侧紧贴 ASCII 字母数字
- **THEN** 该命中被丢弃（IPv4 另拒前导零段）

#### Scenario: 强化关闭维持原仓

- **WHEN** 强化关闭
- **THEN** 粘连命中按非强化口径保留，与原仓行为一致
