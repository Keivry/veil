# http-client-governance Specification

## Purpose
收紧网关共享态治理：强制转发路径复用单个 `reqwest::Client`、为 `PendingApprovals` 设 TTL 与清扫、统一密钥恒时比较与内网判定口径、避免锁跨 await 持有，并清理死依赖与死锚点，消除连接池浪费、内存泄漏与判定偏差。

## Requirements

### Requirement: Client 单例 enforcement

转发路径 SHALL 复用启动期构造的单个 `reqwest::Client`（MUST NOT 在请求路径构造新 Client，含 Matrix 发送路径）；超时与池上限走配置并有保守默认值。

#### Scenario: 转发复用

- **WHEN** 连续发起两次上游转发
- **THEN** 两次使用同一 Client 句柄且请求处理函数内无 `Client::new` 调用

### Requirement: pending 有界与比较统一

`PendingApprovals` SHALL 设 TTL 并由清扫器回收（MUST NOT 无限增长），或与 `MatrixApproval` 合表保证单写单清；凭据 Secret 比较 SHALL 采用等长 HMAC 比较（MUST NOT 早退泄漏长度）；`is_private_ip` SHALL 覆盖 `fd00::/8、fe80::/10、169.254.0.0/16、100.64.0.0/10` 或文档限定仅支持 IPv4 内网豁免；KeePass 缓存锁 SHALL 显式不跨 await 持有；`moka/fancy-regex` 等疑似死依赖 SHALL 经 `cargo-udeps` 确认后删除或补接线说明；8MB 审计上限锚点 SHALL 更名为子限 ceiling 并注释不接入口，或补第二检查点。

#### Scenario: 孤儿回收

- **WHEN** 某 pending 单超时后无后续 reaction
- **THEN** 清扫器在有界时间内回收且内存不持续增长

#### Scenario: 内网判定一致

- **WHEN** IPv6 内网地址请求紧急吊销
- **THEN** 系统按文档口径一致地豁免或转审，不出现实现与文档分叉
