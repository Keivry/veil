# arch-hygiene-closeout Specification

## Purpose
锁定架构卫生收口后的内部契约：兼容垫片零生产引用守护、网关度量固定键原子计数、审计 env/home 显式注入确定性、注册解析归服务层、源码文件体量红线与拆分点、健康探针组装归服务层、锁序不变量、TPM 同步子进程调用约束、HTTP 客户端构造失败可见、失败通知有界跟踪、NonDialog 透传单一入口、集成测试脚手架统一。本 capability 不改任何对外可观测行为（指标键名、`/health` 字段、NonDialog 字节透传、流式/审批语义与阈值均保持）。

## Requirements

### Requirement: 兼容垫片零生产引用守护

系统 SHALL 保留 `src/service/audit_hold.rs` 为仅重导出并带 DEPRECATED 指引的兼容垫片（canonical `code-quality-cleanup` 要求路径与符号保留），SHALL 提供守护测试断言除垫片文件本体与测试白名单外，`src/` 内零 `audit_hold::` 字面引用；符号 SHALL 可经 `service::audit::*` 引用。

#### Scenario: 零生产引用守护

- **WHEN** 守护测试扫描 `src/` 中的 `audit_hold::` 字面
- **THEN** 仅垫片文件本体与测试白名单命中，任何生产新增引用使测试失败

#### Scenario: 兼容路径符号可用

- **WHEN** 下游经 `crate::service::audit_hold::{AuditHold, HoldVerdict, RequestKeepalive}` 引用
- **THEN** 编译通过且符号行为与 `service::audit::*` 一致

### Requirement: 网关度量固定键原子计数

系统 SHALL 将 `GatewayMetrics` 的 lenient/truncated/hop_filtered/conv_missing 四组映射计数改为固定键 `AtomicU64`，SHALL NOT 在请求/帧热路径持有全局 `Mutex<HashMap>`；已知键（协议尾、截断模式、hop 方向、conv 缺失原因）SHALL 精确计数并保持 `lenient_count`/`truncated_count`/`hop_filtered_count`/`conv_missing_count` 读接口与 `/_admin/metrics` 键名不变，未知键 SHALL 归 `other` 桶并告警。

#### Scenario: 并发计数不丢不重

- **WHEN** 多任务并发对同一已知键各记录 N 次
- **THEN** 该键读数恰为任务数 × N，无串行化且无丢失

#### Scenario: 指标键名保持

- **WHEN** `/_admin/metrics` 读取 `chat_tail_lenient` 三键与 `truncated`/`sse_events`
- **THEN** 键名与 JSON 形态与改动前一致，仅内部存储由映射锁改固定键原子

### Requirement: 审计环境注入确定性

系统 SHALL 使审计判定所需的 `HOME` 与 `${VAR}` 展开值经显式注入获取，SHALL NOT 在纯逻辑中直读进程环境变量：`expand_vars_single` SHALL 仅使用传入的 env 映射，`extract_path_tokens`/`expand_home` SHALL 使用注入的 home，`is_dangerous` SHALL 使用注入的启动期 env 快照而非空映射加进程回退。

#### Scenario: 空注入不漂移

- **WHEN** 以空 env 映射且未注入 home 判定含 `~/x` 与 `${VAR}` 的输入
- **THEN** 输出保留 `~/x` 与 `${VAR}` 字面，不读取宿主机进程环境

#### Scenario: 定制注入确定性

- **WHEN** 注入不同 env/home 快照判定同一输入
- **THEN** 判定结果分别由注入值唯一决定，同一快照重复运行结果一致

### Requirement: 注册解析归服务层

系统 SHALL 将注册 DTO→域的映射（`parse_register_entries`/`parse_register_allow_mode` 语义）下沉为服务层纯映射函数，输入为原始值而非 handler DTO；`src/handler/credential.rs` SHALL 仅提取原始字段并委派，SHALL NOT 承载条目/字段/放行模式的业务解析，且 `RegisterParams` 映射结果与改动前逐字段等价。

#### Scenario: 映射等价

- **WHEN** 对同一注册请求（对象/数组/字符串/单条目/`fields`/`allow_mode` 各形态）分别经旧 handler 解析与新服务层映射
- **THEN** `entries` 与 `allow_mode` 结果逐字段一致

#### Scenario: handler 零业务解析

- **WHEN** 检查 `src/handler/credential.rs`
- **THEN** 不再定义条目/放行模式解析函数，仅提取字段并调用服务层映射

### Requirement: 源码文件体量红线与拆分点

系统 SHALL 保持全仓 `src/**/*.rs` 单文件总行（含注释与测试）不超过 800 行，`check_file_sizes.py` 退出 0；对贴近上限的文件 SHALL 预置拆分点并实施：`src/service/pii/scope.rs` 内联测试外置为 `src/service/pii/` 下测试子模块，`src/handler/llm/pump/spawn.rs` 抽 `guard` 与 `terminal` 至 `src/handler/llm/pump/spawn/` 子模块；两文件路径 SHALL 保持不变。

#### Scenario: 红线全绿

- **WHEN** 执行 `check_file_sizes.py`
- **THEN** 退出码 0，无文件超 800 行

#### Scenario: 拆分后路径与行为不变

- **WHEN** `scope.rs` 测试外置与 `spawn.rs` 子模块抽取完成后运行既有单测与 e2e
- **THEN** 全部通过，`src/service/pii/scope.rs` 与 `src/handler/llm/pump/spawn.rs` 路径仍存在且文档引用不悬空

### Requirement: 健康探针组装归服务层

系统 SHALL 由 `service::health_status` 经 `AppStateParts` 组装 `/health` 的 `unlocked`/`pending`/`llm_secrets`，`src/handler/mod.rs` SHALL 仅序列化服务层结果，SHALL NOT 直读 `state.keepass`/`pending`/`vault`；`/health` 字段 SHALL 只增不减。

#### Scenario: 字段保持

- **WHEN** 请求 `GET /health`
- **THEN** 响应含 `ok`/`sqlite_ok`/`sqlite_error`/`status`/`unlocked`/`pending`/`llm_secrets`，值与改动前语义一致

#### Scenario: handler 无状态直读

- **WHEN** 检查 `src/handler/mod.rs` 的健康 handler
- **THEN** 仅调用服务层组装并序列化，不直接访问进程内状态字段

### Requirement: 锁序不变量与审查

系统 SHALL 在相关模块文档固化锁序不变量：`registry_save_lock` 先于 `registry.write()`、`strikes` 先于 `disabled`、流内 keepalive gate 不逆序获取 hold 锁；SHALL 提供新路径审查清单与源码扫描守护测试，对已登记写路径断言获取顺序。

#### Scenario: 不变量文档在位

- **WHEN** 检查 `src/service/credential/vault_ops.rs` 与 `src/service/pii/custom.rs` 模块文档
- **THEN** 命中上述锁序不变量与审查清单指引

#### Scenario: 守护测试拦截逆序

- **WHEN** 已登记写路径出现逆序或新增未登记写路径
- **THEN** 源码扫描守护测试失败并指出位置

### Requirement: TPM 同步子进程调用约束

系统 SHALL 使 TPM 同步子进程（`tpm2_*` 同步执行与存活探测）仅允许在启动期与 `spawn_blocking` 内调用，SHALL NOT 在 async 上下文直调；SHALL 提供调用点守护测试，白名单外调用即使测试失败。

#### Scenario: 白名单外调用被拦截

- **WHEN** `src/` 中出现白名单（`src/service/tpm.rs`、启动期、`src/keepass.rs` 的 `spawn_blocking`）之外的 TPM 同步调用点
- **THEN** 守护测试失败并列出违规文件

#### Scenario: 既有合规调用不误报

- **WHEN** 对当前启动期与 `spawn_blocking` 调用点运行守护测试
- **THEN** 测试通过，TPM 启动与解锁路径行为不变

### Requirement: HTTP 客户端构造失败可见

系统 SHALL NOT 在 HTTP 客户端构造失败时静默丢弃 timeout/pool 配置：失败 SHALL 以 warn 级别记录失败原因并保留可用降级客户端（或启动即错）；构造结果 SHALL 可通过注入失败在单测中验证。

#### Scenario: 构造失败告警

- **WHEN** 注入必然失败的客户端构造
- **THEN** 记录含失败原因的 warn，并返回可供调用的降级客户端，不静默吞错

#### Scenario: 正常构造配置保持

- **WHEN** 以合法 `Config` 构造客户端
- **THEN** timeout/pool 配置照常生效，行为与改动前一致

### Requirement: 失败通知有界跟踪

系统 SHALL 使 KeePass 失败等 Matrix 通知经统一有界 spool 发送：复用单一 Bot 实例、有界队列、常驻消费者且 `JoinHandle` 可跟踪；SHALL NOT 每次失败新建 Bot 并以无跟踪 `tokio::spawn` 无界发送；队列满 SHALL 丢弃并记计数/告警（best-effort 语义不变）。

#### Scenario: 有界队列不无界增长

- **WHEN** 短时间注入超过队列容量的失败通知
- **THEN** 队列占用不超过容量，超出部分被丢弃并计数/告警，无无界任务增长

#### Scenario: 实例复用与消费者可跟踪

- **WHEN** 触发多次失败通知
- **THEN** 仅存在一个 Bot 实例与一个消费者任务，`JoinHandle` 由 spool 持有并可停机跟踪

### Requirement: NonDialog 透传单一入口

系统 SHALL 使 NonDialog 请求经专用透传入口处理并返回 `Response`，SHALL NOT 在 `src/handler/llm/dispatch.rs` 以不可达的 `NonstreamOutcome::Stream` 臂处理 NonDialog；`NonstreamOutcome::Stream` SHALL 仅保留对话路径语义；NonDialog 字节透传行为 SHALL 不变。

#### Scenario: 死臂删除

- **WHEN** 检查 `src/handler/llm/dispatch.rs` 的 NonDialog 分支
- **THEN** 不存在 NonDialog `NonstreamOutcome::Stream` 匹配臂，透传经返回 `Response` 的专用入口

#### Scenario: 字节透传不变

- **WHEN** NonDialog 请求（含上游意外回 SSE）经新入口转发
- **THEN** 状态码与正文字节与改动前逐字节一致，`nondialog_passthrough` 计数照常

### Requirement: 集成测试脚手架统一

系统 SHALL 经 `tests/common/mod.rs` 提供统一的 `base_env`/`test_app`/`serve` 脚手架，支持 `extra`/`cfg_mut`/`db`/`locked` 参数化与 `Router` 或 `(Router, AppState)` 返回；各 `tests/*.rs` SHALL 复用该脚手架而非复制本地实现；纯单元测试文件 SHALL 不受影响。

#### Scenario: 脚手架复用

- **WHEN** 检查使用 harness 的 e2e 测试文件
- **THEN** 均经 `tests/common` 获取 `test_app`/`serve`，不再定义本地拷贝

#### Scenario: e2e 等价全绿

- **WHEN** 全部集成测试以统一脚手架运行
- **THEN** 与改动前同一断言集全部通过，无行为回退
