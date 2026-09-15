# pii-parity-closeout Specification — delta

## MODIFIED Requirements

### Requirement: 自定义规则跨帧前缀 hold

系统 SHALL 提供自定义规则前缀 hint（自定义正则可提取字面前缀 + 字典全名，长度降序去重）；hint 集合 SHALL 以 64 为**总条数上限**（去重后超出按长度降序保留前 64），与 Python `partial_prefix_hints` 的总条数上限一致，SHALL NOT 只对单条 hint 长度设限而缺失总数上限。流式放行前若尾部匹配任一 hint 前缀，系统 SHALL 滞留至下一帧完成判定（完整命中则跨帧整体掩码；不再匹配则放行），SHALL NOT 在首帧直接放行半截自定义字面量。终止/阻断 flush SHALL 与既有 `BoundaryHold::flush` 同语义（不丢内容）。

#### Scenario: 跨帧字典名不先泄出

- **WHEN** 字典全名被 SSE 切分到相邻两帧且属于 hint 前缀
- **THEN** 首帧不直接放行半截字面量，拼接后完整命中被掩码

#### Scenario: 前缀不续接正常放行

- **WHEN** 帧尾匹配 hint 前缀但下一帧不构成该 hint
- **THEN** 滞留内容按原样放行，无内容丢失

#### Scenario: 终止时 flush 不阻塞

- **WHEN** 流在滞留状态下终止
- **THEN** 滞留内容按 flush 语义释放，终端帧恒恰一

#### Scenario: hint 总数有界

- **WHEN** 自定义规则/字典可提取的前缀 hint 去重后超过 64 条
- **THEN** 系统仅保留至多 64 条（长度降序优先），内存与匹配开销有界

### Requirement: 掩码边缘与别名

系统 SHALL 使非 4 段 IPv4 形值的 `mask_pii_value` 掩码与原仓一致：字符数 `<8` 时取首 1/尾 1（如 `123456` → `1****6`），`>=8` 时取前 4/后 4（如 `12345678` → `1234****5678`，重叠不裁剪）；4 段形仍为 `{前}.{二}.**.**`。`bankcard`/`apikey` kind 别名 SHALL 作为已声明超集受理并记录。

#### Scenario: 6-7 字符 IPv4 形掩码

- **WHEN** kind 为 `ipv4` 且值非 4 段、长度为 6 或 7
- **THEN** 掩码取首 1 字符与尾 1 字符拼接（如 `123456` → `1****6`），与 Python/实现逐字一致

#### Scenario: 别名受理

- **WHEN** 采样/检测 kind 为 `bankcard` 或 `apikey`
- **THEN** 分别按 `bank_card`/`api_key` 分支处理，行为与主名一致
