## 1. 文档先行（零风险）

- [x] 1.1 删 `redaction.rs:246 off` 矛盾注释 + `off→关闭` 单测（与 `Config::is_falsy` 同口径，网关实际路径不变），验证：单测通过且注释与 `Config` 一致
- [x] 1.2 阈值表加“是否接入口”列 + Go 表加鉴权列 + 端口章节改写（单进程单监听 + 三映射入口区分），验证：文档评审通过
- [x] 1.3 `approve`/hold B 案 BREAKING 追加（README 6.4，复核与 approval change 同字），验证：双 change 文案一致
- [x] 1.4 `api_conformance.py` 豁免复核同字（NON_GOAL 字面一致），验证：双 change 文案一致

## 2. 限流与观测

- [x] 2.1 限流表有界 + 双触发清扫 + 边界单测（`RateTable` 内联清扫，无后台任务；state 类型已收敛），验证：过期清理/未过期保留双断言通过
- [x] 2.2 `wal_checkpoint` 调用点 + `QueueFull` 丢最老单测（刷盘后 best-effort TRUNCATE + 截断可执行单测；环满丢弃既有单测），验证：`dropped` 计数单测通过
- [x] 2.3 KeePass 串行化 + registry 注释（模块头并发契约），验证：代码评审确认

## 3. handler 拆分

- [x] 3.1 新建 `handler/credential.rs + llm.rs + mod.rs` re-export（直接切换无旧文件残留，对外 `handler::*` 路径不变；凭据测试随代码迁移），验证：编译通过（全绿）
- [x] 3.2 `error.rs` 状态码表集中注释（含 413 例外说明：入口直接构造，不经枚举），验证：注释与 `status_code()` 实现一致
- [x] 3.3 删旧 `handler.rs` 单文件 + conformance 回归（`git mv` 直接切换，conformance 20/20），验证：20/20 通过（脚本现 20 项，原 14/14 口径已超）
- [x] 3.4 文档-契约比对（阈值/鉴权列/端口/BREAKING/豁免逐项核对同字），验证：零漂移
