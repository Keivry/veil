# docs-test-coverage-closeout Specification

## Purpose
锁定测试覆盖与文档收口契约：G1–G7 七项测试缺口补 Rust 等价覆盖、G8 弱断言逐项加强为行为/值断言、G9–G11 三项 README/scripts 文档路径与口径修正、G12 LLM 核心有意差异登记（含跨 change 交叉引用）、G13 README §6/§7 声明逐条核验落档。行为修复归各归属 change（audit-rules-parity / pii-parity-closeout / credential-flow-parity / stream-fidelity-fix），本 spec 只覆盖测试与文档面。

## Requirements

### Requirement: vault 稳定性等价测试

系统 SHALL 为 vault 稳定性契约提供 Rust 等价测试：fuzzy 还原开关的精确/宽松语义与大小写漂移、三包装器（token 脱敏/还原、PII 脱敏、LLM 响应还原）处理 nasty 值后输出 SHALL 仍为合法 JSON、三校验器回退契约（合法原文 + 非法输出回退原文；非 JSON 原文回退输出）SHALL 被断言。`PII_FUZZY_RESTORE` 非法值口径若与 Python 拒启动不同（Rust 非真值按关闭处理），SHALL 作为有意差异登记并交叉引用 audit-rules-parity。

#### Scenario: 三包装器 nasty 值保持合法 JSON

- **WHEN** 输入含 `p@ss"quote`、`\u` 转义、嵌套 stringified JSON 与数组的 nasty 值经三包装器脱敏/还原
- **THEN** 每一步输出经 `serde_json` 解析均合法，且还原后字段值与原文一致

#### Scenario: 三校验器回退契约

- **WHEN** 合法原文 + 非法输出的校验函数被调用，以及非 JSON 原文 + 任意输出被调用
- **THEN** 前者返回原文，后者返回输出（原样回退），无 panic

#### Scenario: fuzzy 大小写宽松还原

- **WHEN** `PII_FUZZY_RESTORE` 开启且输入为已注册 token 的大小写漂移形态
- **THEN** 按序号回查还原为原值；关闭时该形态原样保留

### Requirement: 审计规范化专项测试

系统 SHALL 为审计 `normalize_args` 等价管线提供专项测试，至少覆盖转义处理、管道优先级、`../` 归一、`find` 泛洪、别名 `rm` 折叠五类输入，且 SHALL 与 audit-rules-parity 的 A5 修复同批落地、不重复其实现级测试。

#### Scenario: 别名与路径折叠

- **WHEN** 审计输入含 `/bin/rm`、`find -delete` 别名形与 `../` 拼接路径
- **THEN** 归一后命中危险规则（或按 A5 裁决的等价结论）与对照用例一致

#### Scenario: 转义与管道优先级

- **WHEN** 审计输入含转义字符与多段管道命令
- **THEN** 专项测试断言归一结果与 Python `tests/audit_test.py` 对应用例语义一致

### Requirement: 审计环境降级语义测试

系统 SHALL 覆盖审计环境降级语义：遗留 `AUDIT_ENABLED` 真值时回退 `block`、显式非空 `AUDIT_MODE` 优先、`approve` 模式空白名单在判定入口降级 `block`（审计仍启用）、初始化期同步上下文不建审批清扫任务。

#### Scenario: 遗留开关回退 block

- **WHEN** `AUDIT_MODE` 缺失或空白且 `AUDIT_ENABLED` 为真值
- **THEN** 判定入口按 `block` 处理；显式 `AUDIT_MODE=off` 时不受 `AUDIT_ENABLED` 影响

#### Scenario: approve 空白名单降级 block

- **WHEN** 判定入口收到 `Approve` 模式且白名单为空
- **THEN** 按 `block` 判定并记录 error 日志，不静默放行

#### Scenario: 初始化期不建任务

- **WHEN** 配置/状态在同步上下文构造
- **THEN** 不因启动清扫任务在无运行时的上下文 panic，任务创建仅发生在异步运行路径

### Requirement: PII 值采样持久化取证测试

系统 SHALL 覆盖 PII 值采样持久化 18 项场景，至少包含 7 天滚动、持久开关热切换 1→0、跨天 topn、same-masked 合并、401 响应不泄漏；持久化行 SHALL 仅含掩码与 hash，不落明文。

#### Scenario: 7 天滚动清理

- **WHEN** 采样行时间戳超出 7 天保留窗
- **THEN** 刷盘后超窗行被清理，窗内行保留

#### Scenario: same-masked 合并

- **WHEN** 同一掩码形态的采样在窗口内重复出现
- **THEN** 按复合键合并计数而非新增重复行

#### Scenario: 401 不泄漏

- **WHEN** 上游返回 401 的对话观测进入采样
- **THEN** 采样持久化不包含请求/响应明文，仅掩码与 hash

### Requirement: KeePass 解锁交互路径测试

系统 SHALL 覆盖 KeePass 解锁交互路径：解锁超时按拒绝、并发解锁仅一次问询、raw 直连与脚本上下文语义差异、ask 发送失败不悬挂、失败路径双表清理一致。

#### Scenario: 并发解锁单问

- **WHEN** 多个请求并发触发冷缓存解锁
- **THEN** 仅发起一次解锁问询，其余复用同一结果

#### Scenario: raw 上下文差异

- **WHEN** 终端直调请求 `--raw` 与脚本上下文请求 `--raw`
- **THEN** 直调被拒绝、脚本上下文放行，语义与 Python `tests/credential_test.py` 对应用例一致

#### Scenario: 失败路径双表清理

- **WHEN** 解锁被拒、超时或 ask 发送失败
- **THEN** 内存 pending 与矩阵 pending 两表均被清理，健康计数一致

### Requirement: detection hardening 开关矩阵测试

系统 SHALL 覆盖 `PII_DETECTION_HARDENING` 开关矩阵：默认关、真值开启、非真值关闭（非法值口径按 Rust 现行行为登记）、开启时 ASCII 粘连拒绝与前导零 IPv4 丢弃、CJK 边界不误伤、analyzer 缓存复用不重复编译；结论 SHALL 与 pii-parity-closeout 的 P13 核验互引。

#### Scenario: 开关矩阵

- **WHEN** `PII_DETECTION_HARDENING` 取默认/真值/非真值三种形态
- **THEN** 探测结果分别对应宽松、严格、宽松口径，且无非真值拒启动的行为

#### Scenario: CJK 边界与缓存复用

- **WHEN** 硬化开启且检测文本含 CJK 邻接与重复扫描
- **THEN** CJK 边界结果不误伤，analyzer 复用同一编译产物（可用调用计数断言）

### Requirement: debounce 与模型冒号解析测试

系统 SHALL 覆盖 metrics 刷盘幂等/窗口语义（重复 flush 覆盖式 UPSERT 不翻倍、批量窗口不丢行）与模型名冒号版本解析（如 `gpt-4o:2024-08-06` 分桶不归 `unknown_model`）。Rust 无 Python `_flush_sync` 2s 去抖的差异 SHALL 在 design 登记为事件驱动批量的等价语义，不作为缺失。

#### Scenario: 冒号版本号分桶

- **WHEN** 观测记录携带 `gpt-4o:2024-08-06` 模型名
- **THEN** 该名进入模型分桶且不归 `unknown_model`，仅按控制字符与长度归一

#### Scenario: 重复 flush 不翻倍

- **WHEN** 同一聚合窗连续 flush 两次
- **THEN** 落盘计数保持覆盖式（不翻倍），批量窗口内事件不丢

### Requirement: 弱断言测试加强

系统 SHALL 将弱断言测试逐项加强为行为/值断言：`src/service/sse.rs` 的 `push_bytes` 用例补重组语义、`src/service/json_walk.rs` 的解析断言补脱敏正确性、`src/handler/llm/dispatch.rs` 的 `ok.is_ok()` 补响应体断言、`src/service/admin/ratelimit.rs` happy path 补 429 阈值/窗口断言、`tests/http_e2e_metrics_snapshot.rs` 补非空窗业务值、`src/config/env_parse/tests.rs` 补关键转发路径；`file_len_under_800_or_split` 元测试 SHALL 保留并在 README 口径注明非行为覆盖。

#### Scenario: json_walk 脱敏值断言

- **WHEN** 深度/超深回退与包装器用例执行
- **THEN** 除 JSON 合法外，断言替换后的具体值而非仅 `is_ok()`

#### Scenario: ratelimit 阈值与窗口

- **WHEN** 同 IP 达到 10/min 阈值后第 11 次、以及窗口滚动后再次请求
- **THEN** 断言 `429`/`Retry-After` 取值与窗口行为（必要时注入可推进时钟）

#### Scenario: metrics 非空窗业务值

- **WHEN** 先写入已知事件再查询快照
- **THEN** 断言 `requests`/协议分桶等业务值，而非仅空窗 shape

### Requirement: README 路径与口径修正

系统 SHALL 修正 README/scripts 文档口径：§1 环境变量全表「未列出的变量二进制不读取」SHALL 追加例外（审计 `$VAR` 展开与 `HOME` 直读进程 env）；§4.1 `OLD_HASH_GRACE_SECS` 来源 SHALL 更正为 `src/registry/entry.rs`；`VEIL_ALLOW_MOCK_TPM` SHALL 声明 trim 后等于 `1` 才放行；`scripts/README.md` SHALL 补录 `go_interop_e2e.py`（14 项 e2e runner）。

#### Scenario: 例外加注

- **WHEN** 读者按 §1 理解「未列出变量不读取」
- **THEN** 例外注明确审计规则会对命令文本做 `$VAR`/`${VAR}` 进程 env 展开、`~/` 展开读 `HOME`，并给出 `src/` 证据引用

#### Scenario: 来源与 TPM 口径更正

- **WHEN** 核对 §4.1 `OLD_HASH_GRACE_SECS` 来源与 `VEIL_ALLOW_MOCK_TPM` 取值语义
- **THEN** 来源指向 `src/registry/entry.rs`，Mock TPM 说明为 trim 后 `== "1"`

#### Scenario: runner 补录

- **WHEN** 查阅 `scripts/README.md`
- **THEN** `go_interop_e2e.py` 的用途、14 项规模与用法被登记

### Requirement: 未文档化行为补录

系统 SHALL 在 README 补录未文档化行为：`AUTO_APPROVE` 别名集（`1/yes/0/no/pending/matrix`）、管理面 Cookie 回退 `admin_token` 与 Set-Cookie 签发分支、SSE `?model=&upstream=` 建连过滤与近环回放、SSE 并发超限 `Retry-After` 固定 60、`/_admin/health` 限流豁免实现细节。

#### Scenario: AUTO_APPROVE 别名

- **WHEN** 读者查阅 `AUTO_APPROVE` 取值说明
- **THEN** 别名集与非法值报错行被列出并指向 `src/config/env_parse.rs`

#### Scenario: 管理面 Cookie 与 SSE 过滤

- **WHEN** 读者查阅管理面鉴权与 SSE 事件流语义
- **THEN** Cookie 优先级/签发条件与 SSE 过滤、近环回放、并发超限 `Retry-After=60` 被明示

### Requirement: 审批超时码差异明示

系统 SHALL 在 README §5/§6.7 明示阻塞审批（`CREDENTIAL_BLOCK_WAIT=1`）超时相对 Python 原仓 `408` 的 `403` 归并差异，并作为 BREAKING 迁移指引；该 `403` 语义 SHALL 由测试锁定（同请求阻塞超时按拒绝返回 `403` 且不悬挂，若 credential-flow-parity 另有裁决则引用其结论）。

#### Scenario: 超时按拒绝 403

- **WHEN** `CREDENTIAL_BLOCK_WAIT=1` 且审批等待超时
- **THEN** 下游收到与「拒绝」一致的 `403`，不出现 `408` 或悬挂

#### Scenario: 文档明示差异

- **WHEN** 读者对比 Python 原仓迁移
- **THEN** README 明示 `408` → `403` 归并及迁移影响

### Requirement: 有意差异登记

系统 SHALL 在 design.md 登记 LLM 核心有意差异：调试四件落盘 Non-Goal、跨 TCP UTF-8 分片无损处理、下游断连任务寿命（`spawn_contained` 续跑）、空 `data:` 心跳丢弃、NonDialog 字节透传、限流维度、旧哈希宽限、紧急吊销、`/credential` 信封、`caller_path` 双必填、PII 语义映射；每一项 SHALL 交叉引用归属 change 的裁决，不重复裁决。

#### Scenario: 登记可追溯

- **WHEN** 归档审计查阅有意差异
- **THEN** design 登记表含每项差异、归属 change 与证据文件:行

#### Scenario: 不重复裁决

- **WHEN** 差异由 credential-flow-parity / pii-parity-closeout 已有裁决
- **THEN** 本 change 仅引用其 ID 与 design 段落，不新增平行结论

### Requirement: README 声明核验落档

系统 SHALL 将 README §6/§7 声明逐条与代码一致性核验（本轮通过）落档为 change 记录，附核验方法（逐条引用 + 文件:行）供归档审计追溯；核验发现的新偏差 SHALL NOT 静默忽略，须按归属 change 登记或转出。

#### Scenario: 核验记录可追溯

- **WHEN** 归档审计检查核验档
- **THEN** §6/§7 每条声明有对应核验结论与代码位置引用

#### Scenario: 新偏差转出

- **WHEN** 核验发现声明与代码不一致
- **THEN** 记录偏差并转出至归属 change，不在本 change 静默修正
