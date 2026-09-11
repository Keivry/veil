# runtime-robustness Specification

## Purpose
锁定运行时执行面（注册表写路径、SSE 流式还原热路径、std 锁恢复、注册表完整性与脚本哈希读取、registry 模块结构）在修复后的行为契约：I/O 不占 async 执行器与全局写锁、每帧还原复杂度与凭据表规模解耦、锁中毒不导致持续 500 或静默降级、完整性计算失败显式传播、脚本哈希读取有界且不阻塞 worker、registry 结构拆分保持公开路径与 800 行守卫。

## Requirements

### Requirement: 注册表落盘不得占用 async 执行器与全局写锁

系统 SHALL 在注册/吊销/哈希变更写路径中，仅在 `registry.write().await` 守卫内修改内存状态并生成待写字节；文件系统 I/O（目录创建、临时文件写、原子 rename、权限设置）SHALL 在释放写锁后经 `tokio::task::spawn_blocking`（或等价阻塞线程池）执行，SHALL NOT 在 tokio worker 线程同步执行，SHALL NOT 在写锁持有期间执行。系统 SHALL 保证写路径全序（先变更者先落盘），SHALL NOT 让旧快照覆盖新快照。落盘失败 SHALL 可观测（warn 日志或错误传播），SHALL NOT 以 `.ok()` 静默忽略。

#### Scenario: 落盘期间写锁不阻塞读路径

- **WHEN** 一次注册请求正在执行落盘（慢盘模拟）且另一请求并发执行鉴权查询（registry 读路径）
- **THEN** 读路径在落盘完成前即可返回，不被写锁或落盘阻塞

#### Scenario: 慢落盘不占 tokio worker

- **WHEN** 落盘被注入延迟且同一运行时有并发 SSE 转发任务
- **THEN** 转发任务照常调度，落盘在阻塞线程池执行而非 tokio worker

#### Scenario: 并发写不产生旧写覆盖新写

- **WHEN** 两个注册/吊销写请求先后完成内存变更并落盘
- **THEN** 落盘顺序与内存变更顺序一致，最终文件等于后一次变更后的状态

#### Scenario: 磁盘满或只读文件系统

- **WHEN** 落盘失败（磁盘满、只读挂载、rename 失败）
- **THEN** 失败以 warn/错误可观测，不静默吞错，且不 panic、不影响后续请求服务

### Requirement: 流式每帧还原不得全量克隆凭据表或重建正则

系统 SHALL 使 SSE 逐帧还原路径（token→明文）的成本与帧内 token 数相关（逐 token 直查），SHALL NOT 每帧克隆完整凭据表（`snapshot_t2p`/`snapshot_p2t`）。系统 SHALL 使响应侧脱敏路径（明文→token）的映射与 alternation 正则以「注册时失效」方式缓存，每帧访问 SHALL NOT 触发深克隆或正则重编译。还原输出 SHALL 与既有全量替换结果逐字节一致，还原步骤顺序（凭据还原 → PII 还原 → 幻觉剥离 → 残缺清理）SHALL 保持不变。注册新凭据后，后续帧 SHALL 立即可见该凭据。

#### Scenario: 大表单 token 帧不触全量快照

- **WHEN** 凭据表含 `MAX_TOKEN_ENTRIES` 上限条目且单帧仅含一个已注册 token
- **THEN** 还原结果与全量替换一致，且该帧不增加全量快照计数（`snapshot_calls` 不增长）

#### Scenario: 混合形态与步骤序不变

- **WHEN** 帧内同时含已注册凭据 token、未注册幻觉 token、PII token 与残缺形态
- **THEN** 输出与既有全量路径逐字节一致，幻觉剥离与残缺清理仍在其序位执行

#### Scenario: 注册后立即可还原

- **WHEN** 帧间注册了新凭据（含缓存已存在时）
- **THEN** 后续帧可还原新 token（缓存在注册时失效并重建），无缓存陈旧

#### Scenario: 并发注册与还原

- **WHEN** 还原帧与凭据注册并发执行
- **THEN** 无死锁、无 panic，结果与串行语义一致（至多滞后一次注册，下一帧收敛）

### Requirement: std 锁中毒不得导致持续失败或静默降级

系统 SHALL 在凭据 vault 与 PII scope 的 std 锁获取中以 `PoisonError::into_inner`（或等价恢复语义）继续使用内部状态，SHALL NOT 以 `.expect` panic 使后续每请求经 `spawn_contained` 转为 500；恢复 SHALL 记录告警。隔离判定（如 `contains_request_token`）遇锁中毒 SHALL 返回真实结果，SHALL NOT 静默降级为「不包含」。由运行时数据构建的正则 SHALL 有界：编译失败/超限 SHALL 回退为可恢复替换路径，SHALL NOT panic。

#### Scenario: 锁中毒后请求不降级

- **WHEN** 前序 panic 置毒某把 vault/scope 锁后新请求到达
- **THEN** 请求正常完成（不返回 500），并记录恢复告警

#### Scenario: 隔离判定不静默 false

- **WHEN** 隔离查询遇锁中毒且 token 实际在表内
- **THEN** 返回「包含」的真实结果，不得返回误判的「不包含」

#### Scenario: 最大规模正则不 panic

- **WHEN** 以 `MAX_TOKEN_ENTRIES` 上限的映射构建 alternation 正则
- **THEN** 编译成功或走回退替换，输出与逐键替换一致且无 panic

### Requirement: 注册表完整性计算失败必须显式传播

系统 SHALL 使 `integrity_of` 以 `Result` 返回；序列化失败 SHALL 使加载拒绝（返回存储错误）并使保存中止（不写临时文件、不覆盖原文件），SHALL NOT 以空串/默认值充当哈希使校验通过。

#### Scenario: 序列化失败拒绝加载

- **WHEN** 完整性计算因序列化失败无法完成（测试注入）
- **THEN** `load_from` 返回存储错误，不返回空哈希通过校验的注册表

#### Scenario: 保存失败不落盘

- **WHEN** 保存路径的完整性计算失败
- **THEN** 不产生临时文件与 rename，原注册表文件字节不变

### Requirement: 脚本哈希读取有界且不得在 async 上下文同步阻塞

系统 SHALL 以 `spawn_blocking`（或等价阻塞池）执行 `bind_script_sha256` 的文件读取，SHALL NOT 在 tokio worker 上同步读取，SHALL NOT 在注册表写锁持有期间读取。读取前 SHALL 校验路径长度与文件大小上限；超限或不可读 SHALL 走 `expected_hash` 派生回退并告警，SHALL NOT 无界读取或 panic。

#### Scenario: 超大文件不无界读取

- **WHEN** `caller_path` 指向超过大小上限的文件
- **THEN** 不读取该文件全部内容，按 `sha256(expected_hash:caller_path)` 回退派生并 warn，注册流程可用

#### Scenario: 读取不在写锁内

- **WHEN** 注册/哈希变更请求需要读取脚本文件
- **THEN** 文件读取在获取写锁前完成，并发写路径不被读盘阻塞

#### Scenario: 慢文件系统不占 worker

- **WHEN** 文件读取所在的文件系统缓慢（注入延迟）
- **THEN** 其他 tokio 任务照常调度（读取在阻塞池）

### Requirement: registry 结构拆分保持契约与红线

系统 SHALL 将 `src/registry.rs` 拆为门面与 `registry/{entry,store,acl,migrate}.rs` 子模块；`crate::registry::{CallerEntry, CallerRegistry, RegisterParams, AuthorizationDecision, bind_script_sha256, OLD_HASH_GRACE_SECS}` 等既有公开路径 SHALL 经 re-export 保持可用；`file_len_under_800_or_split` 守卫 SHALL 保持有效且阈值不被放宽；拆分 SHALL NOT 删除任何函数/常量或改变其语义。

#### Scenario: 公开路径不变

- **WHEN** 拆分后编译并运行既有测试
- **THEN** 所有 `crate::registry::*` 引用无需修改即可编译，测试全绿

#### Scenario: 红线守卫保持

- **WHEN** 拆分后运行文件长度守卫与 `scripts/check_file_sizes.py`
- **THEN** 各新文件 ≤800 行，`registry.rs` 守卫仍生效且阈值未被放宽

#### Scenario: 无死代码删除

- **WHEN** 审阅拆分 diff
- **THEN** 仅模块移动/可见性调整与 re-export，无函数/常量删除（死代码清理由 hygiene 类 change 承接）
