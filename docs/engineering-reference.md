## 1. 部署方式

### 前置条件

- Rust 工具链（本地直跑；开发/门禁为 `rust-toolchain.toml` 声明的 nightly，构建下限见 §7.13）或容器运行时（compose 部署）。
- Matrix 账号 + Homeserver（审批与 Bot token）。
- 生产建议 TPM 2.0 芯片；无硬件的开发机见下方 `VEIL_ALLOW_MOCK_TPM` 说明。

### 环境变量表

进程 env 的允许读取面（配置过滤集合 ∪ Config 外直读）恰为下表各具名变量。按端口选择上游的变量
（`LLM_` 前缀加端口，如 `LLM_8878`）不在读取面内：其进程 env 置位仅启动期 `warn`，请改用配置文件
`[llm.upstreams]`。白名单之外的进程 env 不影响生效配置（生效配置即 `Config`）：其中属文件专属清单者置位仅启动期
`warn` 并指引改用 `VEIL_CONFIG_FILE`，其余名一律不读取（例外仅下方三条）。白名单内的配置概念维持
`env 显式 > 文件 > 内建默认`；`VEIL_CONFIG_FILE` 只从进程 env 读取，不作为文件内可声明键。Fail-closed
约束：配置文件非法（缺失/语法/未知键/权限）拒启动、自定义 PII 规则文件缺文件或解析失败拒启动、无硬件 TPM 且未显式放行拒启动；Matrix 三要素与管理 token 均可缺省——缺省即关闭对应功能（不拒启动）。

| 变量 | 默认 | 说明 |
|:-----|:-----|:-----|
| `VEIL_CONFIG_FILE` | 空（不加载） | 引导变量：可选 TOML 配置文件路径；trim 后非空时 fail-closed 加载，见下方「配置文件层（TOML）」子节 |
| `RUST_LOG` | `warn` | 日志层直读（早于配置加载）：`EnvFilter` 指令，支持 per-target 过滤；非法指令回退默认并在 stderr 说明一行。不进入 `Config`、不参与配置校验 |
| `HOME` | 进程环境 | 审计策略 `$VAR`/`~/` 展开快照使用（`HOME` 单列 + 全量 vars，见下方例外①）；仅文本展开，不回写配置 |
| `VEIL_ALLOW_MOCK_TPM` | 未设置（硬件强制） | TPM 层直读：仅 trim 后等于字面 `1` 放行 Mock TPM，其余值仍走硬件门禁 fail-closed；专供无硬件开发机与 CI，生产禁用（见下方指引） |
| `MATRIX_ACCESS_TOKEN` | 空（可选） | Matrix Bot access token（密钥注入）；缺省即关闭 Matrix 通知/审批，不拒启动 |
| `OBSERVABILITY_ADMIN_TOKEN` | 空（可选） | `/_admin` 鉴权 Token，须独立（不得复用 `MATRIX_ACCESS_TOKEN`），建议 ≥32 字符（不足仅 warn 告警）；缺省或置空即 `/_admin*` 全 404，不拒启动（密钥注入） |
| `VEILCTL_SECRET` | 空（兼容模式） | 三因子之部署密钥（密钥注入）；为空即兼容模式（写端点仍 fail-closed） |
| `VEILCTL_BINARY_HASH` | 空 | 直调哈希门禁（密钥注入）：置位时拒绝调用方冒用 veilctl 自身哈希的直调（`caller_hash == VEILCTL_BINARY_HASH` → 403）；为空时该检查兼容跳过，与 `VEILCTL_SECRET` 无联动 |
| `PII_VALUE_SAMPLE_HMAC_KEY` | 空 | 值级采样 HMAC key（密钥注入）；未设退化为 SHA256 |

- compose 专用变量 `PORT_8877`/`PORT_8878`/`PORT_8879`/`TPM_HOST_PATH`/`DB_HOST_PATH` 不经二进制读取，属**容器编排层专用、非二进制读取面**（见 `docker-compose.yml`）。
- 「未列出的变量二进制不读取」的例外（仅此三处，均不影响 `Config` 生效值、亦不入白名单）：① 审计策略 `$VAR`/`${VAR}`/`~/` 展开快照——`src/service/audit/policy.rs::capture_process_env` 于策略加载时快照进程 env（`HOME` 单列 + 全量 vars），供命令文本展开（`src/service/audit/normalize.rs`）与 `~/` 家目录展开（`src/service/audit/rules.rs`）使用，结果只参与审计判定、不回写配置；② 依赖层进程 env（如 reqwest 系统代理 `HTTP(S)_PROXY`，按依赖默认行为，非本仓代码）；③ 测试期 `std::env::temp_dir`（非生产路径）。

### 配置文件层（TOML）

除上表白名单 env 外，可用一份 TOML 配置文件补充配置。进程 env 收敛后：**白名单概念**维持优先级
`env 显式 > 文件 > 内建默认`；**配置专属概念（文件专属清单内者）**的进程 env 面不存在，唯一来源即本文件，
优先级为 `文件 > 内建默认`。

- 引导变量：`VEIL_CONFIG_FILE` 指向文件路径，仅从进程 env 读取、不可写入文件（文件内声明 `veil_config_file`
  按未知键拒启动）；trim 后非空才加载，未设置（或仅空白）时不读盘，生效配置为「白名单 env + 内建默认」基线。
- fail-closed：已设置引导变量时，文件缺失/不可读/非普通文件/超过 1MB/TOML 语法错误/未知键/类型错误/
  枚举空串或集合外取值/正整数越界一律拒绝启动，错误信息指名 `VEIL_CONFIG_FILE`；空文件合法（等价于无文件覆盖）。
  文件值并入后复用与 env 完全相同的 `Config::load_from` 校验链，不因来源为文件而放宽。
- 合并优先级：每个**白名单**概念按 **env 显式名集合**（规范名 ∪ 存活别名）判定，集合内任一变量非空（trim 后）
  即 env 胜并记一条冲突 warn；否则取文件声明值；两处皆缺取内建默认。**文件专属**概念的进程 env 面恒空，文件恒胜。
  文件不引入新概念：下表每个键都对应一个白名单 env 名或一个文件专属概念；例外仅三处声明式结构化分节
  ——`[llm.upstreams]`（按端口展开为 `LLM_<port>`）、`[llm.targets]`（文件专属上游目标覆盖，无 env 对应源，见下）与 `[command]`（文件专属下游命令配置，见 command-api 规格）。
- 过滤边界：白名单过滤只作用于 `Config::from_env` 收集到的**进程 env**；`Config::load_from(&HashMap)` 与文件层
  「映射为规范名后注入」的通道**保持不变**（文件值到达 `Config` 的唯一路径即该注入），故测试/脚本经 map
  注入的键不受过滤影响。
- 审计 mode 层级：配置文件 `[audit].mode` > `[audit].policy_file` 所指策略文件的 `mode` > `off`
  ；配置文件 `mode` 视同显式，不得被策略文件的 `off` 静默降级为关闭审计。
- 密钥类文件权限门禁：文件声明 `matrix_access_token`/`observability_admin_token`/`veilctl_secret`/
  `veilctl_binary_hash`/`value_sample_hmac_key` 任一键时，Unix 下要求 `mode & 0o077 == 0`（即 `chmod 600`），
  否则拒绝启动并给出修正指引；env 覆盖不豁免该门禁（密钥文本已落盘）。非 Unix 平台该检查不适用。
  密钥类键建议继续走 env 注入。
- env-only 例外（不参与文件层，写入即未知键拒启动）：`RUST_LOG`、`VEIL_ALLOW_MOCK_TPM`、`HOME`
  与 compose 专用变量（`PORT_8877`/`PORT_8878`/`PORT_8879`、`TPM_HOST_PATH`、`DB_HOST_PATH`）。
  审计 `$VAR`/`~/` 展开仍快照进程 env，不注入文件值。
- 示例：`examples/veil.toml`（各分节代表键 + 中文注释；不含密钥类键，`0644` 权限即可加载）。

文件 schema 键表（TOML 分节写法；键集由锁步测试与 `src/config/file_layer.rs` 的封闭映射表逐项绑定，
`llm.targets` 与 `command` 为文件专属键根、无 env 对应源，增删须同步本表）：

| 文件键 | 规范 env 名 | TOML 类型 | 说明 |
|:--|:--|:--|:--|
| `auth.homeserver` | `HOMESERVER` | string | Matrix homeserver URL（概念可选：缺失即关闭 Matrix 通知/审批，不拒启动） |
| `auth.room_id` | `ROOM_ID` | string | Matrix 审批房间 ID（概念可选：同 homeserver，缺失即关闭 Matrix 通知/审批） |
| `auth.matrix_access_token` | `MATRIX_ACCESS_TOKEN` | string | Matrix Bot access token；密钥类（须 0600）；概念可选（缺失即关闭 Matrix 通知/审批） |
| `auth.observability_admin_token` | `OBSERVABILITY_ADMIN_TOKEN` | string | `/_admin` 鉴权 token，建议 ≥32 字符且不得与 Matrix token 相同；密钥类（须 0600）；概念可选（缺失即 `/_admin*` 全 404） |
| `auth.observability_disable` | `OBSERVABILITY_DISABLE` | bool | `true` → `/_admin*` 全 404 |
| `limits.audit_hold_max_bytes` | `AUDIT_HOLD_MAX_BYTES` | integer | 审计 hold 字节上限；≥1 |
| `limits.nonstream_max_bytes` | `NONSTREAM_MAX_BYTES` | integer | 非流对话响应体上限；≥1 |
| `limits.sse_frame_hard_bytes` | `SSE_FRAME_HARD_BYTES` | integer | SSE 单行/单事件硬上限；≥1（默认 8MiB，超限 fail-closed） |
| `audit.mode` | `AUDIT_MODE` | enum `off`/`block`/`approve` | 见上方审计 mode 层级；`approve` 须配 `approval_whitelist` |
| `audit.timeout` | `AUDIT_TIMEOUT` | integer | 审批超时秒数；禁止落在 110-130 竞态区间 |
| `audit.approval_whitelist` | `APPROVAL_WHITELIST` | array of string | 审批人 MXID 列表，数组按逗号连接为 env 值 |
| `audit.policy_file` | `AUDIT_POLICY_FILE` | string | 审计策略文件路径；其 `mode` 低于配置文件 `mode` |
| `storage.data_dir` | `DATA_DIR` | string | sqlite/审计日志父目录；派生 `db_dir`/`tpm_dir`/`caller_registry_path` |
| `storage.db_dir` | `DB_DIR` | string | kdbx 库目录（缺省 `<data_dir>/db`） |
| `storage.tpm_dir` | `TPM_DIR` | string | TPM 密封目录（缺省 `<data_dir>/tpm`） |
| `storage.caller_registry_path` | `CALLER_REGISTRY_PATH` | string | 调用方注册表路径（缺省 `<data_dir>/caller_registry.json`） |
| `storage.veilctl_secret` | `VEILCTL_SECRET` | string | 三因子之部署密钥；密钥类（须 0600） |
| `storage.veilctl_binary_hash` | `VEILCTL_BINARY_HASH` | string | 直调哈希门禁；密钥类（保守纳入门禁，须 0600） |
| `storage.auto_approve` | `AUTO_APPROVE` | enum `allow`/`deny`/`pending` | `allow`→放行、`deny`→拒绝、`pending`→Matrix 审批 |
| `storage.entry_mode` | `VEIL_ENTRY_MODE` | enum `full`/`credential-only`/`llm-only` | 入口语义模式 |
| `storage.credential_block_wait` | `CREDENTIAL_BLOCK_WAIT` | bool | 凭据审批 300s 阻塞双模开关 |
| `redaction.enabled` | `REDACTION_ENABLED` | bool | 脱敏总开关；env 别名 `PII_REDACTION_ENABLED` |
| `redaction.fuzzy_restore` | `PII_FUZZY_RESTORE` | bool | 残缺占位符按序号回查还原 |
| `redaction.detection_hardening` | `PII_DETECTION_HARDENING` | bool | 严格边界复核（丢弃 ASCII 粘连与前导零 IPv4） |
| `redaction.custom_rules_file` | `PII_CUSTOM_RULES_FILE` | string | 自定义正则文件；env 别名 `PII_RULES_FILE`/`PII_CUSTOM_RULES`；缺文件/解析失败拒启动 |
| `redaction.custom_patterns_file` | `PII_CUSTOM_PATTERNS_FILE` | string | 自定义模式文件；env 别名 `PII_CUSTOM_PATTERN_FILE`/`PII_CUSTOM_PATTERNS`；fail-closed 同上 |
| `redaction.custom_dict_file` | `PII_CUSTOM_DICT_FILE` | string | 字典文件；env 别名 `PII_DICT_FILE`/`PII_SENSITIVE_DICT_FILE`/`PII_SENSITIVE_NAMES_FILE`/`PII_CUSTOM_DICT`；fail-closed 同上 |
| `redaction.value_sample_enabled` | `PII_VALUE_SAMPLE_ENABLED` | bool | 值级采样总开关 |
| `redaction.value_sample_persist` | `PII_VALUE_SAMPLE_PERSIST` | bool | 值级采样落盘 |
| `redaction.value_sample_hmac_key` | `PII_VALUE_SAMPLE_HMAC_KEY` | string | 值级采样 HMAC key；密钥类（须 0600） |
| `redaction.placeholder_prompt` | `PII_PLACEHOLDER_PROMPT` | bool | 占位符说明注入 |
| `redaction.placeholder_prompt_text` | `PII_PLACEHOLDER_PROMPT_TEXT` | string | 自定义说明文案（4KB 上限，超限截断） |
| `redaction.normalize_json_whitespace` | `NORMALIZE_JSON_WHITESPACE` | bool | 请求体空白归一 |
| `pii_scope.mode` | `PII_SCOPE_MODE` | enum `request`/`conversation` | 会话级关联开关 |
| `pii_scope.ttl_secs` | `PII_SCOPE_TTL_SECS` | integer | 会话条目空闲 TTL 秒；≥1 |
| `pii_scope.max_conversations` | `PII_SCOPE_MAX_CONVERSATIONS` | integer | 会话条目上限；≥1 |
| `pii_scope.key_header` | `PII_SCOPE_KEY_HEADER` | string | 会话键请求头名；保留名拒启动 |
| `pii_scope.prev_id_max_entries` | `PII_PREV_ID_MAX_ENTRIES` | integer | `previous_response_id` 映射上限；缺省联动 `max_conversations` |
| `llm.default_upstream` | `LLM_UPSTREAM` | string | 缺省上游 URL |
| `llm.timeout_secs` | `HTTP_TIMEOUT_SECS` | integer | 非流/Dialog 上游整体超时秒；≥1 |
| `llm.pool_max_idle_per_host` | `HTTP_POOL_MAX_IDLE_PER_HOST` | integer | 每主机空闲连接上限；≥1 |
| `llm.pool_idle_timeout_secs` | `HTTP_POOL_IDLE_TIMEOUT_SECS` | integer | 空闲连接保活秒；≥1 |
| `llm.upstreams` | `LLM_<port>` | table（端口字符串 → URL） | 按入口端口逐键合并，与 env 互不整表覆盖；端口须为合法 u16 |
| `llm.targets` | `（文件专属）` | table（目标键 → 目标） | 上游请求头/请求体参数覆盖（文件专属，无 env 对应源）；目标键、硬拒清单、保留键与三段语义见下 |
| `command` | `（文件专属）` | table（命令配置分节） | 下游命令执行配置（文件专属，无 env 对应源）；schema 与行为见 command-api 规格 |
| `server` | `（文件专属）` | table（`bind` → 监听地址） | 监听地址（文件专属，无 env 对应源）：`bind` 须为 `IP:PORT` 字面量（不接受主机名）；缺省 `127.0.0.1:8877`，容器内写 `0.0.0.0:8877` |
| `keepass.backend` | `VEIL_KEEPASS_BACKEND` | enum `real`/`mock` | `mock` 仅 CI 逃生（生产禁用） |

**[llm.targets] 上游覆盖（文件专属分节，无 env 对应源；未声明时零行为变化）**

- 目标键：入口端口字符串（须为合法 `u16`，且存在对应上游——env `LLM_<port>` 或本文件 `[llm.upstreams]`；无对应上游拒启动）或保留键
  `default`（缺省上游的回退覆盖；缺省上游未定义拒启动）。不同写法归一后重复的目标（如 `"0078"` 与 `"78"`）拒启动。
- 覆盖语义：出站请求头在保留头剔除、`x-veil-*` 剥离与逐跳过滤之后注入，配置值恒胜客户端同名头（大小写不敏感），
  客户端其余头原样保留；`params` 仅对对话协议按协议子表（`chat`/`anthropic`/`responses`）生效，每协议三段
  `default`（缺则补）→ `override`（恒写）→ `drop`（删顶层键，缺失静默），注入在脱敏与占位符说明之后，参数值为配置原文；
  实际发生改写时响应带 `x-veil-normalized: json-whitespace`。
- `override` 冲突策略（目标级布尔，缺省 `true`）：`true` = 恒胜（上述语义）；`false` = 合并模式——headers 仅当客户端
  未发送同名头时新增，`params` 的 `default` 与 `override` 两段均仅在请求体原文缺失该顶层键时写入（客户端已有值恒保留），
     `drop` 不受开关影响（两态均删除所列顶层键）；合并模式下同一键跨段仍「后段生效」，但仅限配置段之间，绝不覆盖客户端值。
- 头值动态插值（仅 `headers` 表的值；`user_agent` 恒为字面值、不参与插值）：值内 `$` 触发展开，三种来源——
  `$conversation`（展开为会话键请求头首值，头名取 `pii_scope.key_header`，默认 `x-veil-conversation-id`）、
  `$request-id`（入站 `x-request-id` 首值）、`$header(<入站头名>)`（镜像任意入站头首值，头名大小写不敏感）；
  `$$` 转义为字面 `$`；一个值内允许多片段与字面混排；不含 `$` 的值走静态路径逐项零变化。
  来源缺失时该条目跳过不注入（不写、不改、不删——客户端同名头按未声明语义保留；不产生空值、不使请求失败）；
  来源头存在但值为空时按存在处理（展开为空值并照常注入）；来源头存在但其值不可解析为可见 ASCII 时按来源缺失
  处理（跳过不注入）；展开结果防御性校验失败时跳过并记一次 warn（理论不可达）。同表其余条目照常。
  非法形态在启动期拒启动（指名完整键路径 `llm.targets."<键>".headers.<头名>`）：未知变量、结尾孤立 `$`、
  未闭合/嵌套 `$header(`、空或非法头名、含 `$` 的镜像名、`$header(x-veil-*)` 内部命名空间引用。
  opencode 动态 session 配方：`headers` 写 `x-opencode-session = "$conversation"`——客户端携带会话键头时
  动态透传其首值（会话粘性随键头走），缺失时跳过（不注入伪造值）；合并模式下客户端自带该头时原样保留。
- `user_agent` 出站 `User-Agent` 恒胜覆盖（目标级字符串，与 `override` 正交）：声明后出站 UA 恒为该单一配置值——
  与 `override` 取值及客户端是否发送 UA 均无关；未声明时 UA 装配逐项零变化（客户端值透传、未发送则不含该头）。
  对话与 NonDialog 透传路径一致生效。值须为合法 HTTP 头值（禁 CR/LF），空/全空白/含首尾空白拒启动（不做静默修剪）；同一目标与 `headers` 中
  归一后为 `user-agent` 的键并存拒启动（两条 UA 通道语义不同，并存歧义）。opencode zen/go 兼容配方：
  `override = false` + `user_agent = "opencode/<实际安装版本>"` + `headers` 补 `x-opencode-client` 等静态身份头——
  opencode CLI 的动态身份头保留、第三方客户端缺项补齐且 UA 恒被替换。
- 缺省回退不命中覆盖：无端口专用上游且无缺省上游时按端口升序选 URL（端口升序兼容路径）不命中任何目标覆盖（行为不变）。
- 硬拒清单（任一项即拒启动）：`host`、`content-length`、`content-encoding`、`accept-encoding`、`transfer-encoding`、
  逐跳头（`connection`/`keep-alive`/`proxy-authenticate`/`proxy-authorization`/`te`/`trailer`/`upgrade`）、
  `x-veil-*` 前缀、鉴权身份类（`authorization`/`x-api-key`/`api-key`/`cookie`）；头名须为合法 HTTP 头名、头值禁 CR/LF、
  大小写归一后的重复头名拒启动。`accept-encoding` 由装配期剔除以保证网关仅声明自身支持集（上游只回可解码编码），
  配置重注入会破坏该不变量。
- 保留键（任一段出现即拒启动）：`model`/`stream`/`messages`/`input`/`instructions`/`system`/`stream_options`。
- 豁免：NonDialog 字节透传路径与 `count_tokens`（redact-only）仅注入请求头、忽略 `params` 并记一次 warn。
- 结构性键（闭集，由锁步测试与 `src/config/targets.rs` 绑定，增删须同步本表；端口号/头名/参数名等用户自定义键不参与键集比较）：

| 结构键 | 出现层级 | 说明 |
|:--|:--|:--|
| `headers` | 目标内 | 出站请求头表（头名 → 字符串；值支持 `$` 动态插值，见上） |
| `params` | 目标内 | 按协议分表的请求体参数覆盖容器 |
| `override` | 目标内 | 冲突策略：`true`（缺省）= 恒胜；`false` = 合并模式（仅补缺，`drop` 不受影响） |
| `user_agent` | 目标内 | 出站 `User-Agent` 恒胜覆盖值（与 `override` 正交；未声明零变化；与 `headers."user-agent"` 归一后互斥） |
| `chat` | params 内 | OpenAI Chat Completions 协议规则 |
| `anthropic` | params 内 | Anthropic Messages 协议规则 |
| `responses` | params 内 | OpenAI Responses 协议规则 |
| `default` | 协议段内 | 缺则补：仅当请求体缺少该顶层键时写入 |
| `override` | 协议段内 | 恒写：`override = true`（含缺省）时始终覆盖请求体同名字段；合并模式（`override = false`）降级为缺则补 |
| `drop` | 协议段内 | 删除：移除列出的请求体顶层键（缺失静默） |

### 遗留变量清单

下列 7 项为遗留名（二进制一律不读取），检出置位时启动期 `warn` 指引改名（权威表与逐项改用见 §7.4 遗留变量兼容表）。

`CREDENTIAL_MASTER_PASSWORD`、`CREDENTIAL_PORT`、`ENV`、
`ALLOW_LOOPBACK_NO_TOKEN`、`CREDENTIAL_API_PORT`、`CREDENTIAL_ADMIN_TOKEN`、`AUDIT_ENABLED`。

### 端口语义：单端口运行时 vs compose 三端口映射

**容器内单监听，不存在多端口运行时。**

- 单进程单监听：二进制与容器内均只监听 `127.0.0.1:8877` 一个端口（见 `src/main.rs`），
  凭据 API 与 LLM 代理共用该端口（LLM 按路径透传）；不存在多端口运行时。
- compose 三映射宿主机入口区分：三条映射（宿主机 `PORT_887x` → 容器 `8877`）只是宿主机入口区分；
  `LLM_8878`/`LLM_8879` 按入口宿主机端口选择上游，`LLM_UPSTREAM` 为缺省上游。宿主机端口可经
  `PORT_8877/8878/8879` 覆盖，回环绑定不变。
- 选路上游缺省唯一生效：`resolve_upstream(None)` 恒返回 `LLM_UPSTREAM` 缺省上游（未设则取端口升序
  首个 `LLM_<port>` 并 warn，序确定不依赖 `HashMap` 迭代），不按端口猜测；`LLM_8878`/`LLM_8879`
  仅在携带入口宿主机端口上下文时生效。当前行为由 `resolve_upstream` 单测锁定。

### 管理控制台说明（`admin.html` 范围）

- 接入方式：浏览器直接访问 `/_admin/`（或 `/_admin`）即得控制台 HTML（入口按 `Accept` 协商；脚本/`curl` 仍得 JSON 索引）；控制台自身**未鉴权**（壳内无数据）。
- 登录方式：页面向 `/_admin/health` 提交 `X-Admin-Token`，成功后由服务端 `Set-Cookie` 持久化（Cookie 模式后续免重复提交）；token 不落任何浏览器存储。
- 缓存语义：管理面统一 `Cache-Control: no-store`；不返回 `ETag`，不参与 304 协商。
- 数据来源：复用既有管理面七路由（含 `/_admin/commands`）；实时大盘走 `/_admin/events/stream` 的 SSE 快照事件 `event: metrics`（15s 周期，与 `/_admin/metrics` 同字段集）；审计事件事件名为 `event`，并含 `done` 终止帧。
- 图表：仅内联 SVG 渲染，不加载 Chart.js，无任何外部资源。
- 界面结构：单文件控制台采用左侧分区导航（概览 / 脱敏 / 性能 / 事件 / 命令调用）与明暗双主题——首屏默认跟随系统 `prefers-color-scheme`，侧栏按钮手动切换并以 `veil_theme` Cookie 记忆（不写 `localStorage`/`sessionStorage`）；窄屏（<860px）下侧栏折叠为顶部横排。
- 事件过滤：按 `kind`（可附 `since`）与 `limit`（默认 50、上限 200）；不提供 `model`/`upstream` 过滤。
- 范围切换：`?range=1h|24h|7d|30d`。
- 数据绑定（时间轴与 KPI）：图表 X 轴与 tooltip 以 series 点的 `ts_start`（窗口起始 Unix 秒）按浏览器本地时间渲染，`window` 仅作内部键、不作可读标签；KPI 总量取自 `/_admin/metrics` 与 SSE `metrics` 快照的 `pii_hits`/`pii_miss`/`cred_hits` 三个 additive 字段（命中率 = `pii_hits/(pii_hits+pii_miss)`，分母为 0 显示 `—`）。
- 指标字段兼容：上述新增字段只增不改；控制台不要求新增管理路由，也不依赖任何字段的移除或改名，旧调用方可忽略新字段。
- 事件空态说明：事件表为空且 `[audit].mode` 为默认 `off` 时，页面展示说明性空态文案——审计默认关闭时事件环仅承载截断/故障类事件，属设计语义而非故障。
- `[auth].observability_disable = true` 时 `/_admin/` 与其余管理面路由一致返回 404。
- `GET /_admin`（无尾斜杠）与 `GET /_admin/` 注册为同一 handler，均按 `Accept` 协商（浏览器得控制台 HTML、
  脚本得 JSON 索引），双注册见 `src/router.rs`；`/_admin/{*rest}` 未知子路径仍 404。
- 管理面鉴权：请求头 `X-Admin-Token`（对应环境变量 `OBSERVABILITY_ADMIN_TOKEN`）优先，
  其次 `__Host-admin_token` Cookie，最后仅 SSE 回退可用 `?access_token`；非 SSE 接口以 query 传 token 恒 401。
- 管理面 Cookie：鉴权 Cookie 名 `__Host-admin_token` 优先、回退 `admin_token`（`src/handler/admin.rs::cookie_admin_token`，
  兼容 http）；经头凭证有效访问非 SSE 路由时按 `Set-Cookie` 签发登录 Cookie（`with_admin_cookie`）——https
  （`X-Forwarded-Proto` 或 RFC 7239 `Forwarded` 内 `proto=https`）走 `__Host-admin_token; HttpOnly; Secure; SameSite=Strict`，
  否则回退 http 兼容 `admin_token`；token 含非法 cookie-octet 字符时拒绝签发。

### Mock TPM 指引（仅开发，生产禁用）

- 无 TPM 硬件的开发机/CI：设置 `VEIL_ALLOW_MOCK_TPM=1`（trim 后等于字面 `1` 才放行，其余值仍走硬件门禁 fail-closed），
  compose 下同时注释掉 `docker-compose.yml` 中 `devices` 两行。
- 生产必须接 TPM 2.0 硬件且不得设置该变量；以 Mock TPM 运行会打 warn 日志，禁止生产使用。
- `scripts/api_conformance.py` 已内建该回退：TPM 门禁失败时自动以 `VEIL_ALLOW_MOCK_TPM=1` 重试并打印本指引。

### 本地直跑

```bash
cp examples/veil.toml ./veil.toml            # 按需改 [auth].homeserver / [auth].room_id、[storage].data_dir、[llm]
export VEIL_CONFIG_FILE="$PWD/veil.toml"
export MATRIX_ACCESS_TOKEN='syt_...'
export OBSERVABILITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
# 无 TPM 硬件的开发机专用（生产禁用）：
export VEIL_ALLOW_MOCK_TPM=1

cargo run --release
```

- 部署参数（Matrix homeserver/room、数据目录、LLM 上游）仅从配置文件读取；同名进程 env 置位不生效（仅启动期告警）。
- 两 token 可缺省：缺省即关闭对应功能（启动期 warn），不拒启动。

服务监听 `127.0.0.1:8877`（回环，见 `src/main.rs`）。

### 容器部署

```bash
cp examples/veil.toml ./veil.toml            # compose 以 ./veil.toml 只读挂载到 /etc/veil/veil.toml
export MATRIX_ACCESS_TOKEN='syt_...'
export OBSERVABILITY_ADMIN_TOKEN="$(openssl rand -hex 32)"

docker compose up -d --build
```

- `./veil.toml` 须先存在（缺失时会以目录形态挂载、配置加载拒启动）；两 token 可缺省：缺省即关闭对应功能（启动期 warn）。

- 三端口默认仅回环：`127.0.0.1:8877`（凭据 API）、`127.0.0.1:8878`、`127.0.0.1:8879`（LLM 代理入口）。
  容器内服务固定监听 8877，三条映射均指向该端口；宿主机端口可经环境变量覆盖，
  回环绑定语义保持：`PORT_8877=19077 PORT_8878=19078 PORT_8879=19079 docker compose up -d`。
- 数据卷约定：`${DATA_DIR:-./data}:/data` 父卷在前，`/data/tpm` 与 `/data/db` 只读子卷在后。
- 默认不监听公网地址；外部访问必须经 TLS 反代。
- 反代必须透传协议头：`X-Forwarded-Proto: https` 或 RFC 7239 `Forwarded` 内 `proto=https`
  （至少其一，大小写不敏感）。二者皆缺时管理面 Cookie 判为非 https，`__Host-admin_token; Secure`
  降级为 http 兼容 `admin_token`（浏览器不再强制 Secure）。
- 无 TPM 硬件时：注释掉 `docker-compose.yml` 中 `devices` 两行，并设置 `VEIL_ALLOW_MOCK_TPM=1`（仅开发）。

### 健康检查（新人可执行）

```bash
# 存活探针（无需鉴权）
curl -fsS http://127.0.0.1:8877/health
# 期望（含超集字段 status/unlocked/pending/llm_secrets/pii_custom_disabled，向后兼容只增不减）：
# {"ok":true,"sqlite_ok":true,"sqlite_error":null,"status":"ok","unlocked":true,"pending":0,"llm_secrets":0,"pii_custom_disabled":0}

# 管理面探针（需 X-Admin-Token）
curl -fsS -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" http://127.0.0.1:8877/_admin/health
# 期望：{"ok":true,"sqlite_ok":true,"sqlite_error":null,"pii_custom_disabled":0}
```

## 2. 三因子鉴权

`POST /credential` 按以下三因子核验，时序安全比较（HMAC 等长比较）；任一因子缺失或不一致返回 403：

| 因子 | 字段 | 说明 |
|:-----|:-----|:-----|
| 因子 1：二进制完整性 | 请求头 `X-Veilctl-Binary-Hash` | `veilctl` 二进制的 SHA256 |
| 因子 2：部署密钥 | 请求头 `X-Veilctl-Secret`（兼容 `body.secret`） | Hermes 容器与网关共享的部署密钥 |
| 因子 3：调用者身份 | 请求体 `body.auth.caller_hash` / `caller_path` | 调用脚本文件的 SHA256 与路径 |

```bash
curl -fsS http://127.0.0.1:8877/credential \
  -H 'Content-Type: application/json' \
  -H "X-Veilctl-Binary-Hash: $(sha256sum "$(which veilctl)" | cut -d' ' -f1)" \
  -H "X-Veilctl-Secret: $VEILCTL_SECRET" \
  -d '{"auth":{"caller_hash":"<sha256(脚本)>","caller_path":"/srv/job.sh"}}'
```

语义补充：

- 服务端未配置对应调用方期望哈希（未 enrolled）时**默认转 Matrix 审批**
  （`202 + E_PENDING`；`[storage].auto_approve = "deny"` 时直接 `403`）——未注册调用方不直接取用凭据，
  自动放行仅对已注册调用方生效。
- `caller_hash == VEILCTL_BINARY_HASH`（终端直调而非脚本调用）拒绝 403。
- 自动放行三态（`[storage].auto_approve` 文件枚举）：`allow` 放行 / `deny` 拒绝 / `pending` 转 Matrix 审批（哈希不一致走 `pending` 分支）；
  三态取值由配置文件承载，非法值拒启动（`src/config/env_parse.rs::AutoApprove`）。
- 管理面鉴权优先级：`X-Admin-Token` 头 > `__Host-admin_token` Cookie > `?access_token`（仅 SSE 回退）；
  非 SSE 接口以 query 携带 token 恒 401。
- 写端点部署密钥强制：`POST /approve-hash-change`、`POST /register-caller`、
  `POST /revoke` 在部署未配置 `VEILCTL_SECRET`（compat 默认）为空时 fail-closed——
  一律 `403`（`E_AUTH`）且不执行任何注册/吊销/哈希变更动作；须配置非空部署密钥并与客户端
  `X-Veilctl-Secret`（或 `body.secret`）取值对齐。该约束**不适用于** `POST /credential` 读路径
  （compat 模式仍按既有语义跳过 Secret 因子），与三因子核验共用同一字段口径。

## 3. 限流规则

- 通用 admin 接口按源 IP 限流 `10/min`，超限返回 `429` 并携带 `Retry-After` 头（头名大小写不敏感， wire 形态为小写 `retry-after`）。
- 豁免集为四条路径，`src/service/admin/ratelimit.rs::admin_rate_exempt_paths()` 是唯一
  **声明清单**（仅作声明/测试与文档用途，不被生产路径消费，故非运行时真源）：
  `/_admin` 与 `/_admin/`（控制台壳，`router.rs` 两条注册指向同一 handler）、
  `/_admin/health`（存活探针）、`/_admin/events/stream`（长连接）。四路不占通用限流桶；
  `metrics`/`series`/`events` 数据接口的 `10/min` 阈值不变。豁免的**真实实现**是对应
  handler 不调用 `admin::check_admin_rate`，每个豁免 handler 以 `debug_assert!` 锁步，
  防止被当作"漏限流"回填。
- `/_admin/events/stream` 按 IP 限制并发 `5`，超限拒绝新连接（`429 + Retry-After: 60`，固定 60 秒）
  而不影响已建连接；保活 `60s` ping，`5min` 服务端强制重连；长连接按并发维度计量，
  不占速率桶，故并发 `5/IP` 是其唯一门。
- 残留风险登记：并发上限**不能**替代速率维度对抗「连上即断」式连接 churn（churn 会释放
  并发槽）。每次建连的成本（近环回放 + 首帧快照的取数）在 `authorize` 之后，故放大路径
  需有效 admin token；未认证流量只承担静态壳与 `401` 的极低成本。若需加固，应给该路由
  单独加一个宽松的连接速率门（如 `30/min`），而非把共享 `10/min` 桶收回。
- 一次控制台刷新 = 壳 + `/_admin/health` 探针 + SSE 建连共三请求，三者均已豁免；
  速率桶只服务数据接口，故刷新频率不受 `10/min` 约束（若计入则每次刷新吃 2 格、
  约 5 次刷新即 429，且建连失败会退化为假「连接中」）。
- 控制台前端退避：SSE `error` 不暴露响应头（`EventSource` 语义），故错误后先用
  `fetch` 对同一路径探一次（读状态码与 `Retry-After` 后立即中止），`429` 时按服务端
  给出的秒数等待再重连，其余按固定 `3s`；回退轮询在退避窗口内跳过，不持续占桶。
  上限由服务端 `Retry-After` 兜底（并发超限固定 `60s`）；SSE 退避用独立字段，
  不阻塞登录探针（后者本已豁免）。
- SSE 建连过滤与近环回放：`/_admin/events/stream` 支持建连 query 过滤 `?model=&upstream=`
  （`SseFilter::from_query`）；建连时按同过滤回放最近 20 条已脱敏事件（近环回放），
  并**立即**推一帧 `event: metrics` 快照（不等 `SSE_METRICS_INTERVAL` 周期 tick，
  空环时首屏不再空置 `15s`；周期 tick 仍按原节拍续推），
  实时推送亦按该过滤维度生效（`src/handler/admin/stream.rs::admin_events_stream`）。
- `10/min` 为速率维度、`5`/IP 为并发维度，两者正交且均为有意设计；SSE 不参与速率维度。
- 限流计数按 TCP 远端地址（不采信 `X-Forwarded-For` 等代理头，防伪造绕过）；
  经反代访问时所有客户端共享反代地址的同一限流桶。
- 凭据面限流按调用方维度独立计数：凭据取用按
  `caller_path:caller_hash` 桶、窗口 `2s`（`CREDENTIAL_RATE_WINDOW_SECS`），注册按 `source`
  桶、窗口 `1s`（`REGISTER_RATE_WINDOW_SECS`）；同一调用方窗口内第二次 `429`，其他调用方
  不受影响（跨方故障隔离）。该维度按调用方分桶而非全局单桶——
  全局单桶下任一调用方高频会阻塞所有调用方（跨方 DoS 面）。回退条款：若运维要求严格
  全局单桶，须另行交付，本条不静默改行为。
- `/_admin/series` 的 `since` 仅接受 `[dhm]<整数>` 形态（与 `day_key`/`hour_key`/`five_min_key`
  产出同形）；非法值返回 `400 + E_BAD_REQUEST`（消息列明合法形态），**不以全量无过滤回退**
  （不接受 `i64::MIN` 哨兵）。epoch 或日期形态支持须另行交付。

```bash
# 超限示例（同一 IP 一分钟内第 11 次调用通用 admin 接口）
# -> 429 {"error":{"code":"E_RATE_LIMITED",...}} + Retry-After: <秒数>
for i in $(seq 1 11); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" http://127.0.0.1:8877/_admin/metrics
done
```

### 旧查询兼容（已弃用，新口径优先）

旧大盘可继续工作，响应附 `deprecated` + `compat` 标注；新调用方请直接用新口径：

| 旧查询 | 兼容行为 | 新口径 |
|:-------|:---------|:-------|
| `series?range=1h/24h/7d/30d` | 映射 `1h→five_min`、`24h→hourly`、`7d/30d→daily`，与同窗新口径等价 | `series?granularity=daily\|hourly\|five_min&since=&protocol=` |
| `metrics/events?model=&upstream=` | 忽略过滤（全局口径，避免空结果误导）+ 弃用标注 | `series?protocol=` 按协议查询 |
| `events?verdict=<旧值>` | 接受 `allow/allowed/pass/approved/block/blocked/deny/rejected/need_approval/pending/approve` 并归一；命中环内 `kind` 才过滤，否则忽略过滤 + 弃用标注 | `events?kind=&since=&limit=` |

诚实声明：token 文件加载仅 `cfg(test)` 生效（生产 fail-closed 口径不变），限流 e2e 为用例级自建 App 隔离桶（生产共享桶语义不变）。

## 4. 阈值表

下表差异均为有意设计（不同检查点），超限行为统一为
`429 + Retry-After`（限流）、`413`（body 超限）与 `502`（非流对话响应超限）。

| 维度 | 取值 | 超限行为 | 是否接入口 | 说明 |
|:-----|:-----|:---------|:-----------|:-----|
| 通用 admin 接口限流 | `10/min`/IP | `429` + `Retry-After` | 是 | 速率维度；按 TCP 远端地址计数，不采信代理头；豁免 `/_admin`、`/_admin/`、`/_admin/health`、`/_admin/events/stream` 四路（数据接口阈值不变） |
| SSE 并发 | `5`/IP | 拒绝新连接，已建连接不受影响 | 是 | 并发维度；不占速率桶（见上行豁免集）；`60s` ping + `5min` 强制重连 |
| 通用请求体上限 | `10MB` | `413` | 是（入口唯一 enforcement） | 通用 JSON 检查点 |
| 非流对话响应上限 | `[limits].nonstream_max_bytes` 默认 `8MB` | `502` + `response_too_large` JSON 体（`error.type`，见 `src/handler/llm/nonstream.rs::oversize_response`） | 是（入口 enforcement） | 对话尾缀（chat/completions、v1/messages、v1/responses）响应体严格超限；`Protocol::NonDialog` 透传不受限；与审计 ceiling `AUDIT_SUBLIMIT_CEILING_BYTES`（子限锚点、非入口 enforcement）分属不同检查点，不可互相替代；本仓超限分支无独立指标与 warning、无状态门 |
| 审计类上限 | `8MB` | — | 否（纯 ceiling 锚点） | 策略子限 ceiling（`AUDIT_SUBLIMIT_CEILING_BYTES` 回归锚点：现网可配子限如 `[limits].audit_hold_max_bytes` 默认 1MB 均不得超过它）；与入口 `10MB` 属不同检查点、差异有意 |
| 审计日志轮转 | `10MB` x 5，`0600` | 写失败双层 fail-closed | 先脱敏后截断，零明文 |
| 审批超时 | `[audit].timeout` 默认 `90`s | — | 禁止落在 `110`-`130`s 竞态区间 |
| 凭据审批超时 | `300`s | — | 与审计 `[audit].timeout` 分表 |

`GET /health` 的 `pending` 计数在审批终态（批准/拒绝/超时）即时归零：内存侧与矩阵侧 pending
在同批终态清理，不依赖空闲票 `60s` 孤儿清扫延迟。

审批票回收两口径并存、不可混用：**空闲票 60s 回收上限**——
无阻塞等待者的孤儿票按分支 TTL（审计类 `60s`）清扫；**有阻塞等待者凭据类票 300s 阻塞 TTL**——
凭据/注册/哈希变更类存在阻塞等待者的未决票在其自身 `300s` 阻塞超时前不被回收。前者是清扫延迟上限，
后者是阻塞等待保留时长，维度不同（详见 §8.4）。内存侧 `PendingApprovals` 清扫与矩阵侧同口径按记录 TTL
执行（凭据/注册/吊销/哈希变更类阻塞票 `300s`、空闲/审计类 `60s`），不再对全部记录一律 `60s`。

`GET /health` 与 `/_admin/health` 的 `pii_custom_disabled`（只增字段）为已停用自定义规则计数
（`disabled_snapshot()` 口径）：ReDoS 守卫连续 3 次超时停用的
规则在此可见，无停用为 `0`；既有探针字段不变。

### 4.1 内部常量附录（未列即内部实现细节）

附录为可审计登记，不构成外部契约；未列出的常量均属内部实现细节。

| 符号 | 取值 | 来源 |
|:-----|:-----|:-----|
| `CREDENTIAL_RATE_WINDOW_SECS` | `2` | `src/config/env_parse.rs` |
| `REGISTER_RATE_WINDOW_SECS` | `1` | `src/config/env_parse.rs` |
| `PENDING_TTL_SECS` | `60` | `src/approval.rs` |
| `OLD_HASH_GRACE_SECS` | `3600` | `src/registry/entry.rs` |
| `RateTable::MAX_ENTRIES` | `4096` | `src/service/credential/ratelimit.rs` |
| `RateTable::SWEEP_LEN` | `1000` | `src/service/credential/ratelimit.rs` |
| `RateTable::SWEEP_SECS` | `60` | `src/service/credential/ratelimit.rs` |
| `SSE_FRAME_SOFT_BYTES` | `1MiB` | `src/config/env_parse.rs` |
| `SSE_FRAME_HARD_BYTES` | `8MiB`（默认；配置文件可覆写，解析值运行时注入解析器） | `src/config/env_parse.rs` |
| `EVENT_IDLE_TIMEOUT` | `30s` | `src/config/env_parse.rs` |
| `KEEPALIVE_INTERVAL` | `10s` | `src/config/env_parse.rs` |
| `RING_CAP` | `10000` | `src/service/metrics/aggregate.rs` |
| `METRICS_FLUSH_INTERVAL_SECS` | `60` | `src/service/metrics/store.rs` |
| `AGGS_MAX_ENTRIES` | `4096` | `src/service/metrics/aggregate.rs` |
| `AGGS_DAILY_KEEP` / `AGGS_HOURLY_KEEP` / `AGGS_FIVE_MIN_KEEP` | `32` / `170` / `1` | `src/service/metrics/aggregate.rs` |
| `ADMIN_RATE_MAX_ENTRIES` | `4096` | `src/service/admin/ratelimit.rs` |

## 5. Go 客户端对接指引

存量 Go `veilctl` 客户端无需修改即可对接：网关保持其所用路径与方法不变。客户端源码
内置本仓 `veilctl/`（模块路径与二进制名不变），`202 + E_PENDING`
轮询语义与退出码约定见本节末条。

| 用途 | 方法与路径 | 鉴权 |
|:-----|:-----------|:-----|
| 取用凭据 | `POST /credential` | 三因子（`X-Veilctl-Binary-Hash` + `X-Veilctl-Secret`/`body.secret` + `body.auth.caller_hash`/`caller_path`） |
| 查看注册 | `GET /registrations` | 管理面鉴权（`X-Admin-Token` 或部署密钥 `X-Veilctl-Secret`，两者皆缺/不匹配 401）；对接脚本须带凭据，Go `veilctl list` 经部署密钥可用 |
| 注册调用方 | `POST /register-caller` | 三因子（同取用；重名 409） |
| 吊销注册 | `POST /revoke`，紧急吊销 `POST /revoke/emergency` | 常规三因子；紧急吊销只认管理 token，无 token 须先过三因子（见 7.5） |
| 批准哈希变更 | `POST /approve-hash-change` | 三因子 |
| 命令目录 | `GET /commands` | 三因子写口径（头携带 `X-Veilctl-Binary-Hash`、`X-Veilctl-Secret`、`X-Caller-Hash`、`X-Caller-Path`） |
| 命令调用 | `POST /commands/{id}/invoke` | 三因子写口径 + `downstreams.allow_commands` 授权 |
| 命令调用日志 | `GET /_admin/commands` | 管理面鉴权（同其余 `/_admin` 路由） |
| LLM 代理透传 | 任意 `/{tail}`（含 `GET`；未知 admin 子路径除外） | 无（上游透传） |
| 存活探针 | `GET /health` | 无 |

```bash
# 取用（脱敏值，默认）
veilctl credential 网易 授权码
# 取用原文（仅限脚本内调用，终端直调被 403 拒绝）
veilctl credential 网易 授权码 --raw
# 注册 / 吊销
veilctl register --name "check-mail" --entry "网易" --fields "授权码" --desc "检查邮件" --auto
veilctl revoke --name "check-mail"
```

- `allow_mode` 契约：`POST /register-caller` 的 `allow_mode` 接受 `auto`（等价自动放行
  `true`）与 `manual`（等价转审批 `none`），与 Go `veilctl register --auto` 对齐；
  未知非空值回退 `auto` 布尔并记 `warn` 日志。
- 写端点部署密钥前置：`POST /register-caller`、`POST /revoke`、
  `POST /approve-hash-change` 要求部署已配置 `VEILCTL_SECRET`；compat 默认
  （未配置）下三者恒 `403`（`E_AUTH`）不执行动作。Go `veilctl` 实发
  `X-Veilctl-Secret`，配置后无需改客户端。`POST /credential` 取用路径不受影响。

- `POST /revoke` 异步 `202` 轮询契约：默认模式（`[storage].credential_block_wait` 未开启）下
  与 `POST /credential` 同口径——`202 + E_PENDING`（`{"error":{"code":"E_PENDING",...}}`）表示**已建单
  待审批**，**不代表吊销已完成**；调用方 SHALL 对同一请求轮询重试（建议指数退避），批准后吊销生效
  （条目 `revoked=true`/`enabled=false`），拒绝/超时返回 `403`，重试不重复建单。`[storage].credential_block_wait = true`
  时同请求阻塞返回终态、无需轮询。紧急吊销转常规审批路径**不受** `credential_block_wait` 影响，恒返回 `202 + E_PENDING`（`src/service/credential/vault_ops.rs::emergency_revoke` 经决策闭环异步落定）。

- `POST /revoke` 定位顺序 `key → caller_path → caller_hash → name`：
  `veilctl revoke --name "check-mail"` 命中未吊销同名条目；重名 409——未吊销条目重名注册直接拒绝，
  已吊销条目的名称释放可复用。

- 注册表存储语义：加载 fail-closed——解析失败或完整性
  sha256 失配一律拒绝加载（不回落空表放行）；落盘原子且同步——tmp 写后 `sync_all`、rename 后
  父目录 `sync_all`，保证掉电后已确认写不丢失；条目按 `BTreeMap` 键序稳定排序（完整性哈希与
  diff 可复现，插入序不作承诺）；`[storage].db_dir` 所指目录扫描排序取末位 `.kdbx`，仅当存在同名 `.key` 才配对
  （不取首个 `.key`，避免配错库）。

- 三因子字段：`X-Veilctl-Binary-Hash` + `X-Veilctl-Secret`（或 `body.secret`）+ `body.auth.caller_hash` /
  `caller_path`；齐全时按既有语义放行或进入审批，缺失时返回明确的鉴权失败（403），不会空响应或挂起。
- 凭据审批 `202` 轮询语义：默认（`[storage].credential_block_wait` 未开启）待审请求返回
  `202 + E_PENDING` 即已建单，客户端应对同一请求轮询重试（建议指数退避），批准后重试返回凭据、
  拒绝后 `403`；`[storage].credential_block_wait = true` 时无需轮询（同请求阻塞等待，批准返回凭据、拒绝/超时 `403`）。
  超时码归并：阻塞超时按拒绝返回 `403`（`VeilError::Auth`），与拒绝同码，下游重试语义一律按拒绝处理（见 §6.7）。
- Go `202` 处理（`veilctl/`，本仓内置客户端）：`veilctl revoke` / `veilctl register` / `veilctl credential` 在收到
  `202 + E_PENDING` 后按退避轮询**同一请求**（服务端经决策表幂等复用既有票，不重复建单）直至终态：
  批准 → 成功（吊销生效 / 注册生效 / 返回凭据），拒绝或超时 → `403` 报错；间隔与时限由
  `PROXY_APPROVAL_POLL`（默认 `2s`，逐次翻倍至 `10s`）与 `PROXY_APPROVAL_TIMEOUT`（默认 `300s`）控制。
  `--no-wait` 或 `PROXY_APPROVAL_WAIT=0` 时仅提交审批单并以**退出码 `2`** 表示「已受理未完成」
  （不再把 `202` 当成功）；`[storage].credential_block_wait = true` 时服务端阻塞返回终态，客户端单次调用即完成。
  错误体兼容（`ErrMessage`：网关对象取 `message`、兼容字符串形态错误体）与 `/credential`
  成功信封 `{"ok":true,"credential":{...}}` 不变；`202` 体不再报「解析响应失败」。
- Go 客户端环境变量（`veilctl/`，本仓内置）：`PROXY_URL`（网关基址，默认 `http://127.0.0.1:8877`）、
  `PROXY_HTTP_TIMEOUT`（单次 HTTP 超时秒数，默认 `300`；非法值回退默认并向 stderr 告警，
  fail-closed 不回退 `30s`）、`PROXY_APPROVAL_WAIT`（默认 `1`；`0` 立即返回待审批）、
  `PROXY_APPROVAL_TIMEOUT`（审批终态总时限，默认 `300s`）、`PROXY_APPROVAL_POLL`（轮询起始间隔，
  默认 `2s`，逐次翻倍至 `10s`）。审批真实网关 E2E（`veilctl/internal/approval_e2e_test.go`）由
  `VEIL_APPROVAL_E2E_URL`（网关基址）与 `VEIL_APPROVAL_E2E_CALLER`（一次性调用方名）共同启用，
  二者未同时设置即 `t.Skip`；该用例会向网关提交对 `VEIL_APPROVAL_E2E_CALLER` 的**真实吊销审批单**
  （破坏性，仅限可弃用调用方）。
- SSE 语义对 Go 透明：被审计阻断的流恒以终止帧闭合，客户端视为正常结束，不重试、不挂起。

### 5.1 下游命令执行（`[command]`）

命令能力由配置文件 `[command]` 分节承载（无 env 对应源）；`enabled = false`（缺省）时
`GET /commands` 与 `POST /commands/{id}/invoke` 均返回 404，其余面零行为差异。

- 定义：`hosts`（本期仅 `kind = "local"`，其他 kind 启动期拒绝）、`groups`（host 集合）、
  `commands`（绝对路径 `program` + `argv` 模板 `args`、`parameters`、`timeout_secs`、
  `requires_approval`）与 `downstreams`（`callers` 绑定注册表 `caller_path`、`allow_commands`、
  静态 `auto_approve` 规则）。未知键、悬空引用、非绝对路径、未声明参数占位与未实现 kind
  一律拒绝启动并指明键路径。
- 执行：argv 数组直传内核，SHALL NOT 经 shell；固定工作目录、最小环境变量、超时 kill、
  stdout/stderr 有界截断（超限标记 `truncated`）。
- 鉴权：复用三因子与调用者注册表，采用写口径（`VEILCTL_SECRET` 未配置即 403）。
  自动放行（`requires_approval = false`、`auto_approve`、accept-always）仅在调用方已注册
  且哈希匹配时生效；未注册/哈希失配仅当 `caller_path` 已绑定、命令在 `allow_commands` 内、
  目标在 `hosts` 范围内时转审批，否则 403。
- 审批：`MatrixBranch::Command`，`✅` 批准一次、`❎` 拒绝、`♾️` 批准并持久化 accept-always
  （`data_dir/command_grants.json`，`0600` 原子写，损坏按空）；超时（默认 300s）按拒绝。
  默认 `202 + E_PENDING`，`[command].block_wait = true` 时阻塞至终态。
- 幂等：同一次审批至多执行一次；并发/重复重入返回同一终态（不会重复执行）。
- 日志：`data_dir/commands.sqlite` 的 `command_invocations` 表记录审批状态、执行状态、
  退出码、耗时与脱敏截断后的参数/输出摘要；`GET /_admin/commands` 提供分页与过滤
  （`limit` 默认 50、上限 200），控制台「命令调用」分区消费同一数据源与 SSE `kind="command"`。

## 6. 行为语义与关键约束

本章登记运行时语义与 fail-closed 约束；配置键见 §1，传输声明见 §7，遗留决策见 §8。

### 6.1 脱敏总开关默认开启

- 脱敏总开关（`[redaction].enabled`）缺省时默认开启；关闭需显式 `enabled = false`。

### 6.2 PII 值采样持久默认开启落盘

- `[redaction].value_sample_persist` 默认开启（掩码 + hash 落盘 `pii_value_samples` 表，7 天滚动）；采样总开关 `[redaction].value_sample_enabled` 默认关闭，仅在其开启后持久语义才生效。
- 未设 `PII_VALUE_SAMPLE_HMAC_KEY` 时 hash 为无盐 SHA256，低熵 PII 可被离线字典枚举（仅趋势参考，生产必须配置 HMAC key 并经 env 注入，不落盘）。

### 6.3 容量分表与序号分配

- 容量：凭据 `MAX_TOKEN_ENTRIES=5000`、PII `PII_MAX_ENTRIES=1000`，均按真 LRU 驱逐（仅作容量复核锚点）。
- 序号分配：`PiiScope` 用游标 + 在用序号集合 O(1) 均摊分配（淘汰释放的序号可复用）；请求表维护独立序号空间，可观测不变量为表内「一个在用条目 ↔ 一个序号」（不出现重复序号）。在用序号集覆盖 `1..=PII_MAX_ENTRIES` 时下一次分配返回饱和哨兵 `PII_MAX_ENTRIES + 1`（表内至多一个在用条目持有），紧随的 LRU 淘汰释放空洞；按序号回查的 `fuzzy` 还原仅查请求表，未知序号不还原（完整未注册 token 形态随后原样透传，见 §7.8）；聚合上界为 `PII_MAX_ENTRIES`/会话。序号值非对外契约，不可预测性由 `rand8`（CSPRNG）承担。

### 6.4 流式审批挂起语义

- `[audit].mode = "approve"` 下流式网关危险调用转 pending 记录，不阻塞流、不合成阻断帧、不等待真人 reaction；拒绝/过期语义由凭据审批链承载。
- 路径：`audit-hold` 仅插入内存 pending 记录（建单点 `src/handler/llm/pump/spawn/event_loop.rs::handle_event`），不建 Matrix 审批票（无 tracked 发送、无真实 `event_id` 键建单）；审批建单路径白名单见 §6.7。
- 「危险调用被拦」在流式面表现为 pending 建单而非阻断帧，监控须查 pending 事件环而非流内阻断帧。

### 6.5 检索调用审计口径

- `file_search_call`/`web_search_call`（含 `file_search`/`web_search` 前缀事件与条目类型）流式与非流式统一计为 tool 调用：名按类型派生（`file_search`/`web_search`），参按 `arguments/input/args` 优先、`queries/query` 回退序列化。
- 检索结果（`results`）不进审计 hold（体量风险，只看查询）；verdict 与其他 tool 调用同通道（流/非流同调用同结论）。

### 6.6 回环免 token 未启用（ENV=dev / ALLOW_LOOPBACK_NO_TOKEN）

- 二进制不读取 `ENV` 与 `ALLOW_LOOPBACK_NO_TOKEN`，回环来源与外部来源同等鉴权（`X-Admin-Token` / Cookie / 仅 SSE 回退 query；无 token 恒 401）。
- dev 环境须显式配置 `OBSERVABILITY_ADMIN_TOKEN` 并携带 `X-Admin-Token`。

### 6.7 凭据审批默认异步 `202` 与阻塞模式

- 默认（`[storage].credential_block_wait` 未开启）：enrolled 哈希篡改/未 enrolled 待审请求立即返回 `202` + `E_PENDING`，先经 tracked 发送取真实 Bot Matrix event id 并以之为 pending 键建单，再即返回；同一请求不阻塞。
- 阻塞模式（`[storage].credential_block_wait = true`）：同请求阻塞至 `300`s，批准返回凭据、拒绝或超时按拒绝返回 `403`（`VeilError::Auth`，`src/service/credential/approval.rs`）。
- 发送路由：审批建单走 `NotificationSink::send_text_tracked`（需真实回执——真实 `event_id` 是反应回调命中 pending 的唯一键；发送失败/取不到 id 即 fail-closed 返回 `403`，不建不可决单）；事件环/失败通知走 `notify_text` 有界 spool 的 best-effort 路径（可丢、不计回执）。二者共用同一 Bot。
- 审批建单路径白名单：仅凭据、注册、命令、吊销（`MatrixBranch::Revoke`）四类路径经 `send_text_tracked` 以真实 `event_id` 建单；`audit-hold` 仅内存 pending（见 §6.4）、哈希变更经 best-effort `notify_text` 通知（`src/service/credential/approval.rs::notify_hash_change`），两者不建 Matrix 审批票。`unlock` 分支已删除（无建单路径，见 §8.4）。
- 轮询语义：`202 + E_PENDING` = 已建单等待 Matrix 人工审批；客户端应轮询重试同一请求（建议指数退避），批准后重试返回凭据、拒绝后 `403`。本仓内置 Go 客户端（`veilctl/`）按契约自动轮询，并以退出码 `2` 区分「已受理未完成」（见 §5）。
- 注册审批链：`POST /register-caller` 写入中立条目（`enabled=false`）后建 `MatrixBranch::Register` 审批单，复用同一双模口径（默认 `202 + E_PENDING` 抛单，阻塞模式至 `300s`）。三态落定：`✅` 置 `enabled=true` 并保留注册声明的 `allow_mode`、`♾️` 置 `enabled=true` 且 `allow_mode = allow`、`❎` 与等待超时置 `revoked=true`（fail-closed）。同一未决注册请求的重试经决策表幂等：返回同一 `202 + E_PENDING`、不重复建单、不返回 `409`；终态后重试返回终态（`✅`/`♾️` 放行、`❎`/超时 `403`），与 §5 revoke `202` 轮询契约同口径。
- 审批 reaction 四分支受理矩阵（常量 → 动作全局唯一，分支只决定受不受理）：

  | 分支 | `✅` | `♾️` | `❎` |
  | :-- | :-- | :-- | :-- |
  | 注册（`Register`） | 激活，保留注册 `allow_mode` | 激活 + `allow_mode = allow` | 吊销 |
  | 命令（`Command`） | 批准本次 | 批准 + 持久化 accept-always | 拒绝 |
  | 吊销（`Revoke`） | 执行吊销 | **不受理**（回执，票保持未决） | 不吊销 |
  | 凭据（`Credential`） | 批准本次 | **不受理**（回执，票保持未决） | 拒绝 |

  `HashChange`/`Audit` 无 Matrix 建单路径（仅原因分类标签），reaction 一律不落定。分支不受理与未知表情（含已退役的旧解锁表情）均回一条说明性消息且票保持未决；非白名单成员、非建单分支、失配 event id 保持静默（无回执）。审批默认异步 `202 + E_PENDING`，等待超时按 `403` 落定（不是 `408`）。

### 6.8 三因子 `caller_path`/`caller_hash` 双必填

- `POST /credential`/`POST /register-caller` 等三因子接口要求 `body.auth.caller_hash` 与 `body.auth.caller_path` 双必填，缺任一返回 `403`（`Auth`，`src/service/credential/auth.rs::handle_credential`）。
- `caller_path` 是注册表 ACL/吊销定位主键，`pending_key` 由 `caller_path:caller_hash` 构成；调用方须在 `body.auth` 补齐 `caller_path`（调用脚本的绝对路径）。放宽为 hash-only 会退化审批定位与审计关联。

### 6.9 内外网判定：IP 字面量一律非内网

- 审计网络外传判定中，IP 字面量一律非内网（可能外传）——RFC1918 `10.`/`172.16-31.`/`192.168.`、环回 `127.`/`::1`、链路本地 `169.254.`/`fe80::`、CGNAT `100.64.` 均不豁免；空/无法提取 host 亦按非内网 fail-closed 拦截。
- 仅 `localhost`/`.local`/`.internal` 内建豁免；其余内网域名请加入策略文件（`[audit].policy_file`）的 `internal_suffixes` 显式清单。目标为裸 IP 时无豁免手段（有意偏严）。

### 6.10 非法审计值拒启动

- 审计模式来源为配置文件 `[audit].mode`（另有 `[audit].policy_file` 所指策略文件的 `mode` 兜底，见 §6.11）；遗留 `AUDIT_ENABLED` 不被读取，置位仅启动期 `warn`、不改变生效模式。
- `[audit].timeout`（须 ≥1 且避开 `110-130` 竞态区间）与 `[limits].audit_hold_max_bytes`（须 ≥1 正整数）取值非法时拒启动，启动错误信息给出合法区间；不静默回落（fail-closed，防静默关闭审计）。

### 6.11 审计策略文件 fail-closed

- 审计策略文件（`[audit].policy_file` 所指路径）在启动期 fail-fast 加载并注入共享运行时状态（请求路径零读盘、零 env 快照）；不可读、含未知键、孤立列表项、非法 `mode`、无法解析行或列表段形态错误时拒启动，不降级为「无审计」空策略。加载早于 TPM 门禁、sqlite 初始化与后台任务。
- 策略 `mode` 参与运行模式判定并注入运行时配置（`state.config.audit_mode`）；优先级为配置文件 `[audit].mode` > 策略文件 `mode` > 默认 `off`。`dangerous:` 段兼容对象形 `{pattern, reason, network}`（YAML mapping 与 JSON 对象，`network` 缺省 `false`）与字符串形。
- 最终生效模式为 `approve`（无论来源）且 `[audit].approval_whitelist` 为空时，启动以配置错误拒绝。
- `[audit].approval_whitelist` 为空或未声明时审批白名单层不过滤；非空时非成员 reaction 被忽略（审计 `approve` 空名单由上述启动门禁兜底）。
- `[redaction].custom_rules_file`/`custom_patterns_file`/`custom_dict_file` 读取前施加 1MB（`1_048_576` 字节）上限，超限具名拒绝启动，恰 1MB 放行。
- 审计日志（`[storage].data_dir/audit.log`）创建即 `0600`（`OpenOptionsExt::mode`），轮转产物同样 `0600`。

### 6.12 日志层默认可见

- 进程启动第一步即安装 tracing 订阅者，默认向 stderr 输出 `warn` 及以上人类可读日志（无 ANSI），stdout 保持零输出。`RUST_LOG` 自此生效（`EnvFilter` 指令，支持 per-target 过滤；非法指令不拒启动，回退默认级别并在 stderr 说明一行）。
- 降级类告警（`mlockall` 失败、sqlite 降级 memory-only、凭据 alternation 回退）走日志层，默认 `warn` 级别可见且可被 `RUST_LOG` 抑制；进程终止类诊断（fail-fast 启动失败、TPM 门禁、端口绑定失败、`serve` 异常退出）与缺 HMAC 安全配置告警（`[redaction].value_sample_enabled = true` 且未设 `PII_VALUE_SAMPLE_HMAC_KEY`）保留裸 stderr，不受 `RUST_LOG` 影响（含 `RUST_LOG=off`）。
- 更多细节设 `RUST_LOG=info`/`RUST_LOG=debug`；噪声大用 per-target 指令（如 `RUST_LOG=warn,veil::handler::llm=error`）。`RUST_LOG` 登记见 §1「环境变量表」。

### 6.13 出口透传、响应侧 PII 分类计数下线与凭据前缀

- 未注册/未授权完整占位符 token 原样透传：响应出口不遮蔽、不移除未注册的完整 PII token 形（`__PII_<seq>_<rand8>__`）与未授权完整凭据 token 形（`__CRED_*__`），逐字节原样透出（不还原、不移除）；残缺形态仍按既有口径剥离。
- `/_admin/metrics` 不返回响应侧 PII 分类计数对象：`unregistered`/`malformed`/`fuzzy`/已遮蔽四类跳过点计数及其指标族、admin JSON 键与 console 面板行均不提供。
- 凭据占位符前缀统一为 `__CRED_`：`make_cred_token` 产出 `__CRED_%06d__`，两处硬编码字节偏移为 `7`；外部脚本按此前缀做字符串匹配。

## 7. 传输与兼容声明

### 7.1 逐跳（HOP）头集

网关双向过滤 RFC 9110 §7.6.1 逐跳头固定 8 项（大小写不敏感）：
`connection`、`keep-alive`、`proxy-authenticate`、`proxy-authorization`、
`te`、`trailer`、`transfer-encoding`、`upgrade`，
外加 `Connection` 头内列名的动态项。解码开启时（默认）额外剥离
`content-encoding`/`content-length`（已解码，对外统一 `identity`：如上游回
`content-encoding: gzip`，下游响应无该头与 `content-length`），
每次剥离经 `src/service/llm_gateway/metrics.rs::GatewayMetrics::record_hop_filtered` 计数（读取侧
`src/service/llm_gateway/metrics.rs::GatewayMetrics::hop_filtered_count`；`hop_filtered_total{dir}` 为其
Prometheus **度量名**约定、非可解析的 Rust 符号）并打 `tracing::debug`（`header`/`dir` 字段）。
网关固定剥 RFC 9110 §7.6.1 全集 8 项 + `Connection` 头内列名的动态项
（`src/service/llm_gateway/hop.rs::HOP_HEADERS`，经 `llm_gateway/mod.rs` 重导出亦可用），
解码配对开关见同文件 `src/service/llm_gateway/hop.rs::DECODE_ENABLED`，
其中 `host` 由 `src/handler/llm/mod.rs::forward_headers` 单独剥；
编码剥离即对外统一 `identity`，见同文件 `filter_hop_headers_counted` 内联注释与单测 `gzip_stripped_as_identity_a5`）。

解码配对补充：转发上游前 `src/handler/llm/mod.rs::forward_headers` 剥离下游
`accept-encoding`，由 reqwest 注入网关支持集（`gzip`/`br`/`deflate`）；`content-encoding`
仅在 reqwest 实际解压后（tower-http 已连同 `content-length` 移除）才对外 `identity`。
上游若仍回网关不支持编码（如未启用 feature 的 `zstd`）、别名（`x-gzip`）或多值编码，
该头与 `content-length` 保留供下游自解（`src/service/llm_gateway/hop.rs::downstream_decode_enabled`），
不得出现「无编码头 + 压缩字节」；支持集内的编码解码与剥头由同一判定配对。

### 7.2 usage 口径

多源 usage 取最大值（`max` 口径，不双计）：流式增量与完成帧 usage 按
`prompt_tokens`/`completion_tokens`/`total_tokens` 三列各自取 max。
`total_tokens` 显式优先与求和回退（互斥，勿混用）：若任一事件显式携带 `total_tokens`/`total`，
取显式值 `max`（保留上游声明）；若全部事件均未显式携带，最终按合并后的
`prompt_tokens_max + completion_tokens_max` **求和回退**（Anthropic `message_start` 输入 +
`message_delta` 输出必须求和而非取 max，见 `src/service/llm_gateway/usage.rs::merge_usage`）。
回退仅在无显式 total 时生效，不覆盖上游声明值。
Responses 取数顶层优先：非流按顶层 `usage` → `response.usage` → `response.response.usage`
三级回退，流式同口径（含 `response.completed` 事件；`src/service/llm_gateway/usage.rs::extract_usage_nonstream`
与同文件 `extract_usage_stream` 共用 `usage_from_paths` 同口径）；定制双层体仍经回退命中不断链。
缓存列 `cached_read`/`cached_write` 同样按列取 max：Anthropic 取顶层
`cache_read_input_tokens`/`cache_creation_input_tokens`，Responses 取
`input_tokens_details.cached_tokens`，Chat 取
`prompt_tokens_details.cached_tokens`（细节对象 `null`/缺失归零；
非 Anthropic 的 `cached_write` 恒零）。`model` 分桶与缓存列只加不改旧列。

Chat 显式 false 即放弃流式用量，按 key 合并保留不覆写：Chat 请求自带
`stream_options={"include_usage":false}` 时转发体保留 `false`，不覆写为 `true`
（按 key 合并语义，见 `src/service/llm_gateway/protocol.rs` 与
`src/handler/llm/rewrite.rs`）；此时流式无 usage 帧，metrics 空 usage 桶为预期而非异常。
`stream_options` 注入范围**仅 Chat**：注入判定的唯一来源为
`src/service/llm_gateway/protocol.rs::should_inject_stream_options`，其对非 Chat 协议 SHALL 直接返假。
Chat 三态保留：键**缺失**时注入
`{"include_usage":true}`；值为 `null`（用户显式第三态）时**原样保留 `null`**，不注入、不替换；
值为对象时仅在缺 `include_usage` 时按 key 合并，已含 `include_usage`（含 `false`）时原样保留；
字符串/数组等畸形形态维持 warn + 整体替换，不静默丢键。
Responses 系**不注入** `stream_options`（官方规范仅接受 `include_obfuscation`，无
`include_usage`），其流式用量一律经
`response.completed.response.usage` 三级回退记录，用户自带键逐字节保留；Anthropic `messages` 系同样
**不注入**（官方无该参数）。

下游发送语义 `Speed` 由 `audit_mode` 派生：
`src/handler/llm/pump/spawn/setup.rs` 按 `AuditMode::Off → Speed::Fast`、其余 → `Speed::Slow` 派生
（`src/service/sse/emit.rs::select_emit` 与同文件 `Speed` 定义），MUST NOT 作为独立配置项暴露；
两档仅描述下游发送节奏（`Slow` 见文即吐、`Fast` 的实际边界为 `FAST_EMIT_THRESHOLD_BYTES`（4096 字节）；下游 SSE 聚合缓冲（`agg`）恒以帧终止 `\n\n` 结尾，标点分支生产不可达（`is_punct_boundary` 保留为 API，不改 `agg` 切分）），
与 keepalive 10s 节奏无关，亦不构成「脱敏完整性」的判据。

流式 model 三级回退与三协议阻断帧回显：
流式模型提取按顶层 `model` → Anthropic 嵌套 `message.model` → Responses 嵌套 `response.model` 三级回退
（`src/handler/llm/pump/event.rs::stream_model_of`，与 `src/service/llm_gateway/tool.rs::extract_conv_id`
的 `response.id` 回退对称），使 Responses `response.completed` 携带的 `response.model` 参与分桶，
不再流式恒回退请求模型而与上游回显口径分裂；三协议流式阻断帧（`src/service/block_inject/frames.rs`
的生产入口 `protocol_block_frames_modeled` 及其分派 `anthropic_block_frames_modeled`/
`responses_block_frames_at_modeled`/`responses_failed_frame_modeled`，`chat_block_frames_full` 仍由生产内调用）
回显已知会话标识与请求/归一模型名（缺失才回退 `blocked-0`/`unknown_model`），与非流
`src/service/block_inject/frames.rs::nonstream_block_body` 的三协议回显口径一致。
非阻断合成终止帧同样回显模型：`synthesize_truncation_modeled` 与 `empty_stream_frames_modeled`
将流模型名写入 `response.failed.response.model`（此前恒 `unknown_model`），故 Responses 截断/真空合成的
`response.failed.response.model` 为真实模型名。
legacy 非 `_modeled` 包装（`chat_block_frames`/`protocol_block_frames`/`anthropic_block_frames`/
`anthropic_block_frames_full`/`responses_block_frames`/`responses_block_frames_at`/
`responses_truncated_frames`/`responses_failed_frame`/`synthesize_truncation`/`empty_stream_frames`）
现已 `#[cfg(test)]` 收编，SHALL NOT 被生产路径调用，以防模型回显被静默回退。

Anthropic `error` 终端观测：Anthropic 流中 `type:"error"`
作为终端透出且此前未发终端时，除既有终端语义外 `truncated_mode` 记 `upstream_error`（非 `None`、
非 `open_ended`），使「上游错误即终端」的第四态在 Anthropic 面可见（Chat 带顶层 `error` 且无 `choices`
的帧同记 `upstream_error`；Responses 走 `synthesized_failed` 自有路径）。

中途断流终端策略：上游 `chunk()` 报错或异常 EOF（流未发终端即结束）时，
网关按协议收尾并记 `truncated_mode` 观测；`chunk()` 报错另记 warn（含错误与已读字节），
不静默按正常 EOF 退出。Chat 补恰一 `data: [DONE]` 并记 `open_ended`（与既有
`finish_reason` 后补发合并为同一收尾路径，`finish_reason` 后到达的 usage 尾帧照常透传
不丢；上游已发 `[DONE]` 时不重复补发）；Anthropic 不合成 `message_stop`（不伪造成功
终止），仅记 `open_ended`；Responses 已发帧时合成恰一 `response.failed` 并记
`synthesized_failed`，零帧维持真空流最小终止（见 §8.6）。三协议合成终端恒恰一
（终端决策的单一所有者为 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator` 的
`plan_midstream`/`commit`；帧发送与计数仍留在 `src/handler/llm/pump/synth_flush.rs` 的
`flush_pre_terminal`/`midstream_terminal`，二者非终端决策所有者）。

SSE 出口信封保真：出口在 `event:` 重放基础上
保真透出 `id:`（WHATWG last-event-id——最近一次出现的 `id` 对后续无 `id` 事件持续有效，
空值 `id:` 重置）与合法整数 `retry:`（非数字值不透出）；上游把 `event:`/`id:` 与 `data:`
分置于不同块时，网关按 `event` FIFO、`id` 最近值跨块暂存并与后续含 `data` 块**同块重建**，
不产生无 `data` 的孤立 `event:` 块；跨块暂存不改事件/帧计数语义——分块信封流与同内容同块流的
`sse_event_count`、`add_sse_event()` 计数与转发帧数逐一致（见
`src/service/sse/parser.rs`、`src/handler/llm/pump/spawn.rs`）。

SSE 超长行有界混合（勿截断）：单行/单事件或未终结行尾（`text_carry`）超过软限 `SSE_FRAME_SOFT_BYTES`
（1MiB）时**完整缓冲并原样交付**，事件带 `oversize` 标记（取代旧 `truncated`），并记
`oversize_frame_bytes`/`oversize_frames`；`truncated_line_dropped_bytes` 退役为生产恒 0（字段保留兼容）。
超过可配硬上限 `[limits].sse_frame_hard_bytes`（默认 8MiB，配置文件可配、运行时注入解析器生效）时 fail-closed：
置 `carry_fatal`、停止解析并由既有中途断流收尾路径合成协议正确终止帧（Chat 恰一 `data: [DONE]`、
Anthropic 零合成帧、Responses 单帧
`response.failed`），观测复用 `TruncatedMode::OpenEnded`（Chat/Anthropic）/`SynthesizedFailed`（Responses），
不新增截断态；客户端不收到任何半截 JSON，解析缓冲有界（见 `src/service/sse/parser.rs`）。

Anthropic `message_start` 会话/模型提取：会话标识
从嵌套 `message.id` 提取，模型名顶层 `model` 优先、回退 `message.model`，使 `message_start`
之后不再恒为 `unknown_model`（见 `src/service/llm_gateway/tool.rs::extract_conv_id`、
`src/handler/llm/pump/spawn.rs`）。

Anthropic 阻断帧 index 与参数累积清洁：阻断帧
使用触发本次阻断的**真实 content block index**（仅无法获知时回退 `0`），多块流中不再错位；
`content_block_start` 的空占位 `input`（`{}`/空串/null）不计入参数累积，避免审计参数出现
`"{}{...}"` 前缀污染，非空完整 `input` 与 `partial_json` 语义不变（见
`src/service/block_inject/frames.rs`、`src/service/llm_gateway/tool.rs`）。

Responses 断序容忍：流中 `sequence_number` 不连续（跳号/回退）时帧原样透传、不 panic、
不丢帧，终端恰一，不因断序升级为错误日志（见 `src/handler/llm/pump/event.rs::extract_responses_seq`）。

Responses `error` 事件统一为失败终端：流中 `type:"error"` 合成恰一 `response.failed`，
不出现 `response.completed`、无重复终端（终端决策见
`src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_responses_error`，调用点为
`src/handler/llm/pump/spawn/event_loop.rs::handle_event` 的 Responses error 臂）。

Responses 失败帧诊断字段（lossy 边界）：合成 `response.failed.response.error`
兼容上游 error 事件的**两种形态**——官方 `ResponseErrorEvent`（`code`/`message`/`param`/
`sequence_number` 位于**顶层**）与既有嵌套 `error` 对象形态；嵌套字段优先，顶层
`code`/`param`/`message` 仅补缺。`sequence_number` 可得时写入合成 `response.failed`
载荷顶层。缺失 `message`（合并后为空）或 error 非对象时回退既有 `{"id","status"}` 形态；
error 对象中 `type`/`code`/`param`/`message` 之外的其余字段不保留，属已声明 lossy 范围，
下游诊断依赖须以本清单为准（见 `src/handler/llm/pump/event.rs::responses_error_object`、
`src/service/block_inject/frames.rs::responses_failed_frame_modeled`）。

空 usage 桶排查指引：观测到某模型空 usage 桶时，先查请求是否显式 `false`
（转发体保留原值即用户放弃流式用量），再判上游异常或采样缺失，不得直接按故障报修。

凭据占位符说明注入门控口径：`__CRED_` 门控要求序号 `\d{6,}`（生产 token 恒 6 位），
窄于 vault 还原侧 `\d{4,}`（兼容历史 4-5 位幻觉形）；4-5 位形态不触发说明注入属**有意保守**
（注入宜漏不宜误，还原侧仍按宽松口径处理，见 `src/service/llm_gateway/placeholder.rs`）。

非流阻断与错误状态声明：
非流上游为 **2xx** 且审计命中 `Block` 时，下游恒收 `200 + nonstream_block_body`；与流式路径对称的是
**阻断帧正文**（非流 `nonstream_block_body`、流式按协议注入阻断帧），**状态码不构成对称判据**——
流式上游 2xx 逐字透传原状态码（见下段）；
错误状态的 JSON 体（如 400 `truncation:disabled`）仍进完整后处理链
（用量记录＋审计判定＋还原），审计照记（`audit_blocks` 列 + warn 日志），但下游
**不合成阻断体**、状态码与正文保留、非字节等价为有意行为；`status>=400` 的非 JSON
错误体（429 限流文案、500 HTML、404 说明，含空体）原样透传状态码与正文字节，
不再合成 `502 E_EMPTY_BODY`（见 `src/handler/llm/nonstream.rs`）。

非流空体/非 JSON 错误码正面档：`E_EMPTY_BODY` 触发于非流对话上游
**仅 `status == 200`** 返回空体或非 JSON 体 → 下游 `502`（`src/error.rs::VeilError::code` 的码映射与
`src/error.rs::VeilError::status_code` 的 `EmptyBody → BAD_GATEWAY`）。错误体的字段形态为 `{"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}}`
（网关级装配见 `src/handler/llm/mod.rs::empty_body_response`；入口级故障如上流未配置亦以同码 `502` 返回，
见 `src/handler/llm/dispatch.rs::gateway_serve` 的 `resolve_upstream` 未配置分支）。判定先后关系：非流响应体上限（`[limits].nonstream_max_bytes`，超限 → `502`
`response_too_large`，见 §4 阈值表）判定**先于**空体/非 JSON 的 `E_EMPTY_BODY` 判定——有界读取先于空体
分类（`src/handler/llm/nonstream.rs::serve_nonstream`）；`status>=400` 的错误体不受二者改写，按上段透传语义保留
状态码与正文字节。注意两枚 502 错误体的字段名不同：`E_EMPTY_BODY` 用 `error.code`，超限 `response_too_large`
用 `error.type`（`src/handler/llm/nonstream.rs::oversize_response`）。

空体 502 四分支一致性：① 流式空流（零有效分片）SHALL 补
最小可解析终止帧后按正常流闭合，**SHALL NOT 转 502**（见 §8.6）；② 非流空体/非 JSON（**仅 `status == 200`**）
→ 502 `E_EMPTY_BODY`；③ 上游 `502`/`401` 原样透传、不改写；④ 非对话尾豁免（原文透传、不转 502、不计
对话用量，见 §7.6）。502 SHALL 仅适用于非流式空体/非 JSON，且**仅 `status == 200` 触发 `NonStreamTo502`**（唯一入口
`src/service/llm_gateway/mod.rs::classify_empty`）；其余非错误状态（`201`/`204`/`304` 等）按 `PassthroughOk` 透传。

流式上游错误状态透传：
`stream:true` 请求仅在
上游 `status<400` 且响应 `content-type` 为 `text/event-stream` 时进入 SSE 泵；
上游 `status>=400`（4xx/5xx 的 JSON/HTML/空体）或 2xx 非 `text/event-stream`
正文一律按非流口径保状态与正文字节透传（hop 头过滤 + `x-veil-protocol`，受
`[limits].nonstream_max_bytes` 约束），不改写为 200 SSE 假流；进入 SSE 泵的上游 2xx（`status<400` 且
`content-type: text/event-stream`）下游 SHALL 逐字携带上游原状态码（如 `201`/`202`/`206`），
SHALL NOT 硬编码改写为 `200`（实现见
`src/handler/llm/pump/event.rs::build_sse_response`），`<400` 入泵门不放宽；仅非错误状态（`status<400`）
严格超限走 502 `response_too_large`（见 `src/handler/llm/dispatch.rs::stream_upstream_passthrough`）。
有界读：透传读取先判上游 `content-length`，再按 `[limits].nonstream_max_bytes`
有界读，不先全量缓冲；超限 502 **严格作用于非错误状态**，4xx/5xx 错误体不因体大
改写状态或正文（有界读/流式转发仅为内存安全，错误体按透传语义不改写，与 §4
「错误体按透传语义不改写」一致）。内部头隔离：透传前剔除上游所有
`x-veil-*` 内部头（大小写不敏感），网关自置 `x-veil-protocol`/`x-veil-normalized`
在剔除后写入，上游同名声不得覆盖或泄漏。

流式/非流超时口径：流式（SSE）转发使用
启动期构造的独立 client，**不设**覆盖整响应体读取的总超时，故长流不因
`[llm].timeout_secs`（默认 `30`s）被截断；该 client 当前**不配置读空闲超时**
（默认禁用/无），失活连接依赖 TCP keepalive，如需回收须另行交付。
`[llm].timeout_secs` 仅约束非流与 NonDialog 透传路径（保持既有 fail-fast 语义）。
两类 client 均于启动期构造并注入 `AppState`（`http_client`/`http_stream_client`），
请求路径不新建 `reqwest::Client`（见 `src/state.rs::build_stream_http_client`）。

Matrix sync 长轮询超时口径：Bot 的 `/_matrix/client/v3/sync`
向服务端声明 `timeout=SYNC_TIMEOUT_MS`（`30`s），**并**为该请求单独设置 per-request
总超时 `sync_request_timeout()`（长轮询窗口 + `SYNC_TIMEOUT_MARGIN_MS`=`15`s = `45`s），
逐请求覆盖共享 client 的 `[llm].timeout_secs`（reqwest `RequestBuilder::timeout` 语义：
仅作用于本请求并覆盖 `ClientBuilder::timeout`）。二者相等时服务端在窗口到点后再叠加
一个 RTT 才返回，客户端 deadline 恒先触发，空闲窗口每次都被截断为假失败（warn + 退避），
故窗口与余量均不得压缩；`whoami`/发送等短请求不带该覆盖，仍受 `[llm].timeout_secs`
约束（见 `src/service/matrix/branch.rs::sync_request_timeout`）。

非流请求遇上游 SSE 口径：非流请求（`stream` 未显式为 `true`）
而上游仍返回 `status<400` 且 `content-type: text/event-stream` 时，网关**复用已取得**的上游响应经
字节泵转发，SHALL NOT 重发上游请求（非幂等）；该路径受**非流 client 的 `[llm].timeout_secs`
总超时**约束（含响应体读取），超时按中途断流终端路径 fail-closed 收尾；需长流者 SHALL 显式
`stream:true` 以获独立无总超时 client。该口径不引入新增 `502`/错误码等 wire 行为。

上游重试分类：**拿头前**（`send()` 返回
`Ok` 之前）的 connect/timeout/请求层瞬断（reqwest `is_connect`/`is_timeout`/`is_request`）
统一退避重试，序列 `0.5s→1s→2s`、最多 3 次（初次 + 3 = 最多 4 次请求）；一旦拿到
响应头（`send()` 返回 `Ok`）即不重试，中段断连按上文「中途断流终端策略」
fail-closed 收尾。档位硬编码，见 `src/service/llm_gateway/mod.rs::RETRY_DELAYS_MS`
与 `MAX_RETRY_ATTEMPTS`。

非流超限观测口径：`[limits].nonstream_max_bytes`
严格超限（仅 `status<400`）恒返回 502 `response_too_large`，`len == cap` 放行、
`status>=400` 错误体不改写；超限判定先于空体/非 JSON 502 生效。本仓超限分支**无独立
指标与 warning、无状态门**；该选择记录见对应设计说明。

### 7.3 请求隔离声明

PII 映射**默认**按请求隔离（`Scope::pii` 请求级容器，请求结束即销毁，跨请求不互见）；
凭据 `vault` 与 PII `detector` 为进程单例只读复用（还原不断链）。口径（与
`src/service/metrics.rs` 模块文档**同字**）：**默认**请求级隔离为隐私硬要求；`[pii_scope].mode = "conversation"`
显式启用时在**有界、非持久**窗口内允许会话级关联。本仓默认隐私更严，代价是跨请求
prompt-cache 命中率下降，属有意权衡：命中率差异本地不测量（wont-measure）——命中率是上游
provider 侧计费指标，网关侧不可见真值，即使代价未知也不回退默认口径。

会话作用域模式（`[pii_scope].mode = "conversation"`，默认 `request`）：显式启用后，
会话键成功推导时同一会话键内的同一明文跨轮铸造同一 token，使发往上游的前缀字节逐轮稳定
（缓存友好）；**凭据仍为请求级授权（见下段），会话级仅承载 PII**。

- 隐私增量（不得隐藏）：启用 `conversation` 后明文在 TTL 窗口（`[pii_scope].ttl_secs`，默认 `1800`s）
  内常驻内存（相对「请求结束即销毁」属回归）；会话内关联可接受（上游 provider 本就关联同一
  上下文轮次）；跨会话隔离保持。
- MUST NOT 承诺清单：不承诺 provider 缓存命中率可测量的提升（wont-measure 保持）、跨会话 token
  稳定性、**Responses 标量 `input` 形态的会话级 token 稳定**、**序号空间饱和后的 `fuzzy`
  还原确定性**、凭据占位符稳定性、零明文常驻、网关重启后 token 稳定、键推导含糊时的任何行为。
- 前置条件（会话级缓存友好**当且仅当**会话键成功推导时成立）：键按四级优先级首个命中者胜——
  ① 客户端显式头 `[pii_scope].key_header`（默认 `x-veil-conversation-id`，≤256 字节，且经租户命名空间
  + HMAC，原始值绝不作键）；② 协议原生键（**按协议白名单，不跨协议接受**：仅 Chat/Responses 的
  `prompt_cache_key`、仅 Responses 的 `previous_response_id`；Anthropic MUST NOT 接受二者、Chat MUST NOT
  接受 `previous_response_id`；协议不匹配的原生字段**静默忽略**——不命中第 2 级、不改变第 3/4 级
  推导结果、不告警、不计数）；③ 稳定前缀（**要求 `tools` +
  `system` + 首个 user turn 三者齐备**，对脱敏前规范化前缀做 HMAC；字段提取同按协议白名单——
  Anthropic 取原生顶层 `system` 或 `messages` 首条；Chat 仅 `messages`；Responses 取 `instructions`
  （首个 user turn 取**数组形** `input`），协议外字段不越界参与）。
  级别 1/2 依赖客户端配合（显式头 / `prompt_cache_key` / `previous_response_id`），级别 3 依赖请求形态齐备。
- 降级行为：**纯多轮 `messages` 请求（无工具、无会话键头、无协议原生键）即便
  `[pii_scope].mode = "conversation"` 亦落第 4 级逐请求**，不获跨轮 token 稳定；**Responses 标量（字符串）
  `input` 简写形态的第 3 级不可命中**（标量 `input` 是「当前轮全文」、随轮次增长，不作稳定 turn 锚点），
  同样落第 4 级逐请求并由既有 `record_request_fallback()` 计入观测；以上降级**不报错、不伪造键**
  （缓存失配属预期降级，非缺陷）。
- 缓存稳定性边界（已成立但 MUST NOT 作为稳定承诺）：(a) 第 3 级要求 `tools` + `system` +
  首个 user turn 的**内容跨轮冻结**，改写其内容即换键（键序/工具序扰动已由规范化归一，不在此列）；
  (b) 租户指纹纳入**完整上游基址（含 path/query）**与归一化客户端凭据头，切换上游基址或轮换凭据
  即换命名空间、此前铸造的键不可解析（缓存失配/重新铸造，不报错）；(c) 会话期间修改
  `[redaction].placeholder_prompt_text`（或切换注入开关）改变发往上游的前缀字节，应冻结该配置；(d)
  `src/service/json_walk.rs::SCAN_INPUT_LIMIT`（1 MiB）、`::CONTAINER_NEST_LIMIT`（128 层）、
  `::DEPTH_LIMIT`（5 层 stringified JSON）为回退阈值，超限正文回退原样处理，可能改变该请求的
  序列化形状。以上边界均不改变 token 还原正确性。
- 占位符说明注入的跨轮边界：注入仅在脱敏后请求体**仍含占位符 token** 时发生
  （`src/handler/llm/rewrite.rs` 经 `src/service/llm_gateway/placeholder.rs::has_placeholder_tokens` 判定），
  故「同会话两轮前缀字节一致」仅对**两轮均含 token**成立；token 首次出现的那一轮 SHALL 允许头部新增
  说明、前缀字节较前一轮增长（合法增长，非缓存失稳缺陷）。与 §7.7 同口径。
- 会话键头剔除与保留名校验：会话键头的剔除为**无条件**——独立于 `[pii_scope].mode`
  （默认 `request` 模式同样剔除）且覆盖任意自定义非 `x-veil-` 头名
  （`src/handler/llm/dispatch.rs::strip_conversation_header`）；其名与值 MUST NOT 转发上游或入日志。
  `[pii_scope].key_header` 在启动期做**保留名校验**（fail-closed）：命中真实鉴权/传输头名
  （`authorization`/`x-api-key`/`api-key`/HOP 集/`host`/`content-length`/`content-encoding`/
  `accept-encoding`，大小写不敏感）拒启动；除保留名外的任意自定义名 SHALL 被接受，安全性由**无条件剔除**保证（转发前剥离、不入上游请求头与日志，无需额外 allow-list）。
- 熵源故障 fail-closed：PII 注册失败区分两类——待注册值**本身即 token 形态/保留前缀**时
  静默跳过（既有语义，不替换、不改写、不失败）；`rand8` 的 `OsRng` **熵源/内部故障**时记 `warn!`
  （不含明文/token/键/头值）并计入指标，且**拒绝以未脱敏正文转发上游**：请求以 HTTP `502` + 错误码
  `E_PII_UNAVAILABLE`（码字面定义于 `src/error.rs`）收敛。
- `previous_response_id` 映射容量与写回观测：映射容量由 `[pii_scope].prev_id_max_entries`
  承载（**未声明时取 `[pii_scope].max_conversations` 的生效值**，任意配置下零行为变化），与 PII 会话容量
  解耦；因达容量逐出最旧条目时计映射逐出计数。写回仅限 `Protocol::Responses` 的响应完成处
  （`src/handler/llm/pump/spawn/event_loop.rs` 与 `src/handler/llm/nonstream.rs`，
  门控在 `src/service/redaction/conversation_key.rs::record_response_id`），仅「响应 id 缺失/为空」
  计一次 `conversation_writeback_miss`，无写回上下文与非 Responses 门控不计入。计数范围：**至多每响应一次**；
  流式仅在官方 Responses 终端帧（`response.completed`/`response.failed`/`response.incomplete`）处判定且该流**从未见 id** 时计一次；
  非流仅对 `status < 400` 的 JSON 响应体缺 id 计一次；`status >= 400` 错误响应与**流中段截断**声明为范围之外、不计入。
- 会话键回退可观测：仅三类**可判定**降级事件记 `tracing::warn!`（不含键/头值/明文/token）
  与内部计数——键推导返 `None` 落第 4 级、`ConversationScopeStore` 缺失、显式会话键头存在但非法被
  静默丢弃；「中途换键/变级」因键推导为逐请求无状态纯函数而不可观测，登记为非目标，**不新增**下游
  可观测响应头（`x-veil-scope` 及等价物非目标）。
- 模式开关：`[pii_scope].mode` 默认 `request`；`[pii_scope].ttl_secs`
  （默认 `1800`）、`[pii_scope].max_conversations`（默认 `1024`）、`[pii_scope].key_header`
  （默认 `x-veil-conversation-id`）为 `conversation` 模式参数；非法值拒启动（fail-closed）。

凭据还原授权：响应侧凭据
还原为**请求级授权**——仅当 token 属「本请求脱敏实际产出」（minted-set，随请求销毁）时才
调用 vault 还原；调用方自带的 `__CRED_<n>__` 字面量不还原（原样透传），不借进程单例的历史映射还原。
字面 token 无法还原属**有意收紧**（授权判据：非本请求产出者不还原）；依赖该行为的调用方须改由
请求侧真实脱敏产出 token。

PII 与凭据计数口径：

- `pii_hits` = 同一请求内内置/字典 PII 命中**既有作用域映射**（未新铸）的出现次数；`pii_miss` = 新铸占位符次数。
  两者按**出现点**逐个判定（同一字符串叶内同一值出现两次时，第一次计 `pii_miss`、第二次计 `pii_hits`）；
  `pii_miss` 为新增列，在 `metrics_daily` / `metrics_hourly` /
  `metrics_five_min` 三表同窗同协议累加（旧库启动期以幂等 `ALTER TABLE ... ADD COLUMN` 补列，只加不改既有列）。
- 由配置文件自定义规则（`[redaction].custom_rules_file`/`custom_patterns_file`/`custom_dict_file`）命中的值**显式排除**：不计入 `pii_hits`/`pii_miss`（该口径只覆盖内置与字典 PII）。
- `cred_hits` = 本次 LLM 请求内凭据明文**被替换的出现次数**；与凭据 API 侧计数
  **不同源、不可直接对账**；本仓不提供 `cred_miss`（请求路径不新铸凭据 token）。
- 作用域：`[pii_scope].mode = "request"`（默认）下两项 PII 计数仅反映同一请求内复用；`conversation` 模式下可跨轮命中，
  与进程级持久映射不同源（与本节上文请求隔离条目同口径）。
- 范围与暴露面：三项计数仅由**请求侧**脱敏路径产出（响应侧占位符还原不计入），仅对对话端点
  （非 `NonDialog`、非 `redact_only`）计数；总量在 `/_admin/metrics` 快照顶层与 SSE `metrics` 快照指标树中
  以同名字段暴露，并按窗口落在 `/_admin/series` 行内（快照为环内累计、series 为按窗口切分，口径一致）。
- 值级采样接线：`[redaction].value_sample_enabled` 开启后，chat-tail 请求命中 PII 时经真实请求路径调用
  `PiiValueSampler::sample`，`upstream` 取入口端口字符串、不得为空串；未配置
  `PII_VALUE_SAMPLE_HMAC_KEY` 时启动输出告警；采样只落掩码与 hash、不落明文。
- series 点时间字段：`/_admin/series` 与 SSE 快照的每个点新增 additive `ts_start`（`i64`，窗口起始 Unix 秒 =
  `window` 序号 × 桶跨度：`daily` 86400、`hourly` 3600、`five_min`/`5min` 300）；`window` 仍为内部键
  （`d`/`h`/`m` 前缀 + 整数序号），仅用于排序/过滤/驱逐，其形态与整数序不变量（`window_ord`、`since` 过滤、
  retention 驱逐）不变；SSE 快照与 REST 的 series 行继续同形。

### 7.4 遗留变量兼容表

| 遗留变量 | 状态 | 改用 |
|:---------|:-----|:-----|
| `CREDENTIAL_MASTER_PASSWORD` | 二进制不读取 | 主密码口令改走 TPM 解封（`startup_tpm_in`） |
| `CREDENTIAL_PORT` | 二进制不读取 | 宿主机端口改用 `PORT_8877/8878/8879`（仅改映射） |
| `ENV` | 二进制不读取（置位启动 warn） | dev 环境显式配置 `OBSERVABILITY_ADMIN_TOKEN` 并携带 `X-Admin-Token`（回环免 token 未迁移，见 §6.6） |
| `ALLOW_LOOPBACK_NO_TOKEN` | 二进制不读取（置位启动 warn） | 回环免 token 未迁移：dev 环境显式配置 `OBSERVABILITY_ADMIN_TOKEN` 并携带 `X-Admin-Token`（见 §6.6） |
| `CREDENTIAL_API_PORT` | 二进制不读取（置位启动 warn） | 入口统一走 `[storage].entry_mode` + 单端口 `8877`（见 §8.4） |
| `CREDENTIAL_ADMIN_TOKEN` | 二进制不读取（置位启动 warn） | 无替代：启动期交叉校验已废除；管理面/紧急吊销统一用 `OBSERVABILITY_ADMIN_TOKEN`（独立 token 由部署面保证，见 §7.5） |
| `AUDIT_ENABLED` | 二进制不读取（置位启动 warn） | 审计模式改用配置文件的 `[audit].mode`；env 真值回退（→ `block`）已移除（见 §6.10） |

沿用旧名部署不生效（置位仅启动期告警），须改用下表「改用」列给出的新形态。

### 7.5 吊销与注册鉴权声明

- 写端点鉴权前置：常规吊销 `POST /revoke`、注册 `POST /register-caller`、
  哈希变更 `POST /approve-hash-change` 的三因子守卫在部署未配置部署密钥
  （`VEILCTL_SECRET` 为空）时 fail-closed，动作前返回 `403`（`E_AUTH`）；
  须配置非空部署密钥。紧急吊销 `POST /revoke/emergency` 只认管理 token（见下）。
- 紧急吊销 `POST /revoke/emergency`：**必须**携带有效管理 token（请求体 `admin_token`
  或 `X-Admin-Token` 头，源为 `OBSERVABILITY_ADMIN_TOKEN`）；命中即直接吊销，不建审批单。
  未携带/无效时**网络位置不再构成任何放行依据**（客户端自证字段一律不受理），
  须先通过三因子校验（`body.auth` + `body.secret`，与写端点同源），不成立返回 `401`/`403`
  且**不建审批单**；三因子成立才转常规审批（`202 + E_PENDING`，条目未吊销）。
  容器内对端恒为 docker 网关地址，旧的按对端网段判定等于同网络任意容器可无 token 吊销，
  故已删除（`src/service/credential/vault_ops.rs::emergency_revoke`）。
- **Break-glass 前提（运维必读）**：无管理 token 的三因子路径需要建 Matrix 审批票，
  因此**依赖 Matrix homeserver 可达**；Matrix 不可达时建票失败，接口返回 `403` 而非 `202`。
  即"无 `OBSERVABILITY_ADMIN_TOKEN` + Matrix 宕机"等于**无法紧急吊销**。
  `OBSERVABILITY_ADMIN_TOKEN` 必须作为托管凭据长期持有，不能假设三因子通道总能兜底；
  上线前应演练一次"Matrix 宕机 + 紧急吊销"以确认 token 可用。
  调用示例：

  ```bash
  curl -sS -X POST http://127.0.0.1:8877/revoke/emergency \
    -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" \
    -H "content-type: application/json" \
    -d '{"caller_path":"/s/job.sh"}'
  ```
- 常规吊销 `POST /revoke`：经 Matrix 审批确认后执行——
  建单（`MatrixBranch::Revoke`，预置 `✅`/`❎`）后仅 `✅` 置 `revoked=true` 且 `enabled=false`；
  `♾️` 不受理（回执，票保持未决）、`❎` 与等待超时**保持条目原状**（不做破坏性动作）。
  默认 `202` 抛单，`[storage].credential_block_wait = true` 阻塞至 `300s`。
- `GET /registrations`：要求管理面鉴权（`X-Admin-Token` 或部署密钥
  `X-Veilctl-Secret`，见 `src/handler/credential.rs::registrations_handler`），两者皆缺/不匹配 401。
  Go `veilctl list` 携带部署密钥可用。
- 哈希变更 `POST /approve-hash-change`：`reaction` **必填**——
  `♾️` 批准新哈希并置 `allow_mode = allow`（自动放行）；`✅` 批准新哈希并降级为人工审批
  （`allow_mode = pending`）；`❎` 置 `enabled=false`。三态均写入旧哈希宽限
  （`old_hash` + `old_hash_expires_at = now + 3600s`）并更新 `script_sha256`。
  `reg_id` 仍可缺省回退 `caller_path`；`reaction` 缺省/空串/旧解锁表情/集合外取值返回 `400`
  并列出合法取值 `♾️`/`✅`/`❎`。
- 旧格式迁移：`[storage].caller_registry_path` 指向旧格式
  （`version`/`callers`/`allowed_entries` 形态）时，加载期一次性迁移——先备份 `.bak`（备份失败
  拒绝覆盖写，fail-closed），随后以新格式写回并返回内存态；新格式文件直读、不生成 `.bak`、不改写。
  只读挂载下备份失败会拒绝启动（报错指明 `.bak` 原因），调整挂载权限后重启即可，不会损坏旧文件。
- 审批消息内容：消息携带可读上下文——原因 + 调用方路径 +
  凭据场景的条目/字段元数据（如 `hash_mismatch :: /s/job.sh :: 网易/授权码`），审批人可判断批什么；
  敏感值（凭据明文、部署 Secret）不落消息，`key` 为 `caller_path:caller_hash`（哈希按既有口径呈现）。

### 7.6 非对话透传声明

- 非对话路径（`Protocol::NonDialog`，如模型列表等非 `chat/messages/responses`
  尾缀）保持字节透传： hop 头过滤后原文转发，不做用量记录、审计判定与
  凭据/PII 还原。
- 入站 query 随 path 一并转发：网关保留请求目标的原始 query 切片（`Uri::query()`），
  按「path + `?` + 原始 query」拼接上游 URL，**保序、保 `%` 编码与 `+` 形态**，
  不重排、不重编码；无 query 时不追加 `?`。该转发**不改写 body**，也不触发
  审计判定与用量记录（与 §5「LLM 代理透传任意 `/{tail}`」口径一致，消除漂移）。
  上游基址自带 query（`?x=y`）时把入站 query 以 `&` 合并到基址 query 之后，不产生双 `?`。
- 每次透传记 `GatewayMetrics.nondialog_passthrough`（流量验证用）；
  若流量验证表明该臂承载对话体需补还原/审计/用量，另立任务跟进。
- 非对话尾的空响应按 §7.2「空体 502 四分支一致性」的**非对话豁免**分支原文透传：不转 502、
  不计对话用量。

### 7.7 请求归一化声明（`x-veil-normalized`，注入即声明）

- 下游响应头 `x-veil-normalized: json-whitespace` 当且仅当转发前请求体被重序列化为紧凑 JSON
  时置位；未置位时无此头（不以空值占位）。该头只发下游，不向上游转发。
- 置位条件三选一：① Chat `stream_options` 注入分支（恒经 `to_vec` 重序列化，与配置开关无关，
  无条件置位，见 `src/handler/llm/rewrite.rs`；Responses 不注入，故不因此置位）；② `[redaction].normalize_json_whitespace = true` 且请求体可解析为
  JSON（紧凑化重序列化）；③ 占位符说明注入分支（经 `to_string` 紧凑重序列化）。
  纯脱敏替换与原文透传口径：JSON 容器内的脱敏替换经 `json_walk` loads→walk→dumps
  紧凑重序列化（`scope.rs::redact_request`），重序列化即置位 `x-veil-normalized`
  （`normalized_out` 随实际重序列化置位，不再有缺口）；原文透传（零替换）
  与非 JSON 字节级替换不置位。
- 响应侧字节保真与请求侧已知偏离：响应帧除占位符还原写回（含 RFC 8259 JSON 转义写回）
  外逐字节透传，不触发 `loads→walk→dumps` 全帧重序列化；键序、数字表示（如 `1e3`）
  与空白均不改写，还原写回仅改占位符 span，不引入键序、数字表示或空白改写。请求侧重序列化
  路径（上「置位条件」②③与 JSON 容器内脱敏替换）保持对象键序（`serde_json` `preserve_order`），
  但数字表示与空白仍可能被 `serde_json` 规整（已知偏离，如 `1e3` → `1000.0`），
  对上游实际收到的请求体做字节级比对须以此为准。
- 非流两处响应与 SSE 流响应均按同一 `normalized_out` 置位（见 `src/handler/llm/nonstream.rs`、
  `src/handler/llm/pump/event.rs::build_sse_response`，  经 `pump.rs` 与 `handler/llm/mod.rs` 重导出亦可用。
- 占位符说明注入的跨轮前缀增长边界（与 §7.3 同口径）：说明注入分支（置位条件③）仅在
  脱敏后请求体仍含占位符 token 时发生（经 `src/service/llm_gateway/placeholder.rs::has_placeholder_tokens`
  判定），故「同会话两轮前缀字节一致」仅对两轮均含 token 成立；token 首次出现的那一轮允许头部新增
  说明、前缀字节较前一轮增长（合法增长，非缓存失稳）；既有幂等守卫（已含说明不重复前插、返回原字节）
  不变。容器缺失时三协议不对称（Anthropic 缺 `system` 新建、Chat/Responses 容器缺失即不注入）见
  `src/service/llm_gateway/placeholder.rs::placeholder_schema_ok` 与本节上文「置位条件」。

### 7.8 PII 还原超集与残缺清理语义

- fuzzy 还原超集：`[redaction].fuzzy_restore`（默认关闭）开启时按序号回查的宽松还原属
  **有意超集**——截断/改写形（大小写漂移等）亦可还原；边界锁定为**仅请求表可还原**，
  未知序号 SHALL NOT 被解析为任何明文（该步不还原；完整 token 形态随后按本节下条原样透传）。
  开关关闭时仅精确形态还原，口径与既有行为一致。生产建议保持默认关闭。
- 未注册/未授权完整 token 原样透传：响应出口在 PII 还原之后不遮蔽或移除——
  完整未注册 PII token 形（`__PII_<seq>_<rand8>__`）与未授权完整凭据 token 形（`__CRED_*__`）
  逐字节原样透出（不还原、不移除、不掩码）；已注册完整 token（含 `conversation` 模式同会话键
  早期轮次注册者）照常还原，SHALL NOT 被移除。「跳过点分类可观测」的移除见 §6.13。
- 残缺占位符剥离为**有意收窄**：仅剥离确证残缺续段（`__PI` + 可选 `I` +
  可选 `_序号` + 可选 hex 段，且后随边界）；无序号 hex 形（如 `__PII_AB`）与后随合法
  单词字符的正文（如 `__PIXEL`/`__PII_DATA`）**不剥**，避免误删用户数据；
  完整形态的负向前瞻豁免正是完整未注册 token 得以原样透传的机制（PII 侧与凭据侧同一机制），SHALL NOT 改为对完整形态剥离。

### 7.10 掩码边缘与别名

- kind 别名集：`mask_pii_value` 受理 `bankcard`（等价 `bank_card`）、
  `id_card`（与 `bank_card` 同分支）与 `apikey`（等价 `api_key`），行为与主名逐字一致，
  属已声明兼容超集；别名集以本条登记为准。
- 非 4 段 IPv4 形：字符数 `<8` → 首 1/尾 1
  （如 `123456` → `1****6`），`>=8` → 前 4/后 4（如 `12345678` → `1234****5678`）；
  4 段形仍为 `{前}.{二}.**.**`。
- email：域名含 `.` → `***@***.<suffix>`；含 `@`
  但域名无 `.` → `***@***`（如 `a@b` → `***@***`）；无 `@` 落短值口径。
  其余分支与 64 字符截断上限不变。
- 摘要引擎兜底：管理面事件摘要引擎 `redact_summary`
  对 IPv4（4 段形）、身份证（17 位 + 数字/`X`）、卡号（13-19 位连续数字）三类形态兜底替换为
  `[REDACTED:ipv4]`/`[REDACTED:id_card]`/`[REDACTED:bank_card]`（检出形态与 `sample_mask`
  对应分支同口径）；摘要输出不含三类明文。

### 7.11 Anthropic 扩展思考签名连续性声明

会话级 token 稳定（`[pii_scope].mode = "conversation"` 且会话键成功推导，见 §7.3）是 Anthropic 扩展思考
（extended thinking）`signature` 连续性的**必要条件**（非充分条件）。本仓**不**承诺签名连续性——
MUST NOT 声称已实现或已验证。残余限制（三项）：① 网关**不校验**上游签名（`thinking_delta` 文本还原为
明文，`signature` 为对**占位符文本**的 opaque 签名）；② 会话条目淘汰/进程重启后 token 重新铸造；
③ 其他 provider 的签名 thinking 不在范围内。

本声明自 2026-09-16 起**生效**。

缓存稳定性边界（与 §7.3 同口径的 MUST NOT 承诺登记）：会话级 token 稳定（及本节签名连续性的
必要条件）仅在下列条件同时成立时才有意义——(a) 第 3 级稳定前缀的 `tools`/`system`/首个 user turn 内容
跨轮冻结；(b) 完整上游基址（含 path/query）与客户端凭据头归一不变；(c) `[redaction].placeholder_prompt_text`
与注入开关在会话期间冻结；(d) 正文未触发 `json_walk` 回退阈值（`src/service/json_walk.rs::SCAN_INPUT_LIMIT`
1 MiB / `::CONTAINER_NEST_LIMIT` 128 层 / `::DEPTH_LIMIT` 5 层 stringified JSON）。任一不满足即可能换键或
改变前缀字节，属已登记边界，不改变 token 还原正确性。

### 7.13 出站 TLS 信任根与构建期密码学依赖

`reqwest` 经 `rustls` feature 与 `rustls-platform-verifier` 取**操作系统信任库**，
故出站 HTTPS 的信任根来源为「OS 信任库」，属安全姿态声明：

- 运行环境必须提供系统 CA（容器 runtime 已装 `ca-certificates`，见 `Dockerfile`）；
  最小镜像缺 CA 即握手失败。
- OS 中注入的企业 MITM CA 会一并被信任。若要求「只信内置根、不信任系统注入 CA」，
  `0.13` 无对应 feature，须自配 rustls provider/roots，属另行交付。
- 构建期密码学依赖：`rustls` 经 `aws-lc-rs`（`aws-lc-sys`）编译 C/C++ 源码，需要
  C++ 编译器与 `cmake`；Dockerfile builder 阶段已显式安装 `g++ cmake make`
  （`rust:slim` 仅自带 gcc/cc/perl，缺则 `docker build` 失败）。
- 构建期工具链下限：源码使用 `str::floor_char_boundary`/`ceil_char_boundary`
  （`src/service/pii/chunk.rs`、`src/service/sse/parser.rs`），在 `1.89` 上仍为
  unstable（`E0658`）。两轴分工显式登记：
  **开发/门禁**工具链由 `rust-toolchain.toml` 声明为 nightly（`gate.sh` 的
  `cargo fmt --check`/`clippy` 依赖 nightly 的 rustfmt 不稳定选项，配置真源为仓库根
  `rustfmt.toml`）；
  **构建**工具链下限由 `Cargo.toml` 的 `package.rust-version` 声明（= `1.98.1`，
  即 Docker builder 已验证版本），任何更旧工具链（含 Dockerfile base tag 落后）在
  cargo 处即 fail-fast，不再等到 E0658。Docker builder 用 stable 即可（不跑 fmt/
  clippy，因此无需 nightly、不触发构建期下载）；base tag 须 ≥ 该下限，改动任一侧须
  重跑 `docker build` 验证，不得改用滚动 tag。

## 8. 遗留决策记录

本节锁定遗留决策与口径，后续变更不得静默漂移。

### 8.1 NonDialog 透传

- 非对话路径（`Protocol::NonDialog`）字节透传：hop 头过滤后原文转发，不做用量记录、审计判定与
  凭据/PII 还原（细节见 §7.6）。
- 每次透传记 `GatewayMetrics.nondialog_passthrough`（流量验证用）；若该臂承载对话体需补
  还原/审计/用量，另立任务跟进，不扩张本条范围。

### 8.2 调试落盘缺失

- 本仓无请求四件落盘调试功能。
- 排障代替指引：网关日志（stderr，人类可读，级别见 §1 `RUST_LOG`）+ `[audit].policy_file` 审计面；恢复落盘需另行交付，
  且落盘即涉密、须配套脱敏方案。

### 8.3 Go 对接验证

- 存量 Go `veilctl` 客户端对接指引见 §5；三项验证覆盖：`5.1` 存量 Go 直连全链路、`5.2` 三因子
  齐全/缺失两场景、`5.3` 阻断流终止（收到终止帧且无重试挂起）。端到端 runner：
  `scripts/go_interop_e2e.py`（共 14 项）。

### 8.4 入口与审批语义

- `[storage].entry_mode` 三态：`full`（默认）/ `credential-only` / `llm-only`，非法值拒启动。
- 非 `full` 入口下 `approve_hash_change` 降级为阻断（返回鉴权失败，不执行哈希变更，
  见 `src/service/credential/vault_ops.rs::approve_hash_change`）。
- Matrix 审批返回 `None` 即 rejected 并清理；审批票回收两口径并存、不得混用：
  **空闲票 60s 回收上限**——无阻塞等待者的孤儿票（审计类）按分支 TTL `60s` 清扫；
  **有阻塞等待者凭据类票 300s 阻塞 TTL**——凭据/注册/哈希变更类存在阻塞等待者的未决票，
  在其自身 `300s` 阻塞超时前不被回收；
  两口径对矩阵侧票与内存侧 `PendingApprovals` 一致适用。
- 文本指令 `lock`/`forget` 经网关侧清理接线：
  `lock` 清口令缓存 + KeePass 会话 + TPM 派生主密码缓存（清除并零化，**不阻止下次取用**——再次取用仍经 TPM 解封）+ 内存/矩阵 pending；`forget` 清 token 映射并以真实条数回执。
- `MatrixBranch::Unlock` 已删除：`unlock`/`解锁` 前缀原因在 `from_reason` 直接返回错误，
  `record_pending` fail-closed（不建一张永远不可决的票）。
- `[storage].auto_approve` 三态：`allow` 放行 / `deny` 拒绝 / `pending` 转 Matrix 审批（见 §2）。

### 8.5 测试口径注明

- 录制回放由 `tests/sentinel_check_tests.rs` + `tests/fixtures/` 覆盖。
- 本仓真 SDK 一致性口径为脚本 `scripts/api_conformance.py` **24 项（脚本口径，live 实测）**（脚本侧覆盖三协议 SDK 与阻断相）。
  **已纳入 gate 步骤**：`bash scripts/gate.sh` 第 6 步执行真 SDK 一致性
  （24 项 = 14 常规 + 4 阻断 + 5 取用 + 1 无库 503，由 gate 第 6 步 live 实测登记），第 7 步在 `veilctl/` 内执行 Go 客户端 `go vet ./...`
  与 `go test ./...`，与 fmt/clippy/test/文档路径/文件大小五步串联为七个步骤，任一失败整体非零退出。
  前置条件（第 6 步）：Python venv（默认 `<仓库根>/.venv/bin/python`，依赖 pin 见 `scripts/requirements-conformance.txt`；可用 `VEIL_CONFORMANCE_PYTHON` 覆盖）与 SDK pin `openai==3.5.0`/`anthropic==1.1.0` + `pykeepass`；无 TPM 硬件时脚本内建 `VEIL_ALLOW_MOCK_TPM=1` 回退（仅开发/CI，生产接 TPM 2.0 硬件）。
  前置条件（第 7 步）：本机 Go 工具链，在 `veilctl/` 目录内执行；**Go 版本由 `veilctl/go.mod`（`go 1.26`）
  在 `vet`/`test` 阶段强制**——Go ≥1.21 的 `GOTOOLCHAIN=auto` 会依 `go.mod` 自动选型/下载，
  Go <1.21 时版本指令在 `vet`/`test` 阶段明确报错并非零退出（fail-closed）。gate **SHALL NOT**
  增加版本字符串比较（会把本可成功的环境误判失败）。
  跳过语义：缺前置条件默认显式报错并非零退出；`GATE_SKIP_CONFORMANCE=1`（第 6 步）与
  `GATE_SKIP_GO=1`（第 7 步）为显式跳过并打印跳过理由与文档位置，不出现无输出的静默跳过。

### 8.6 空流三协议语义

- 行为：三协议真空流（零字节零残余）均补最小可解析终止——Chat 恰一 `data: [DONE]`
  （传输层终止标记，不伪造 `finish_reason`/内容/usage）；Anthropic 最小
  `message_start`+`message_stop`（空 content、null `stop_reason`、usage 全 0，不含
  `content_block_*`，不声称语义 stop_reason）；Responses 保持恰一 `response.failed` 全序列
  （失败语义，不伪造完成）。**SHALL NOT 转 502**（空体 502 仅适用非流，见 §7.2 四分支）。
  Anthropic 三态区分：**审计阻断**下游恰一五件套
  （`message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`，
  `message_start` 恒恰一且为首帧——上游首帧已下行时注入省略首帧、以下行在前的上游真帧充当首帧并保留其
  id/model/usage，未下行时注入合成首帧；
  定义于 `src/service/block_inject/frames.rs::anthropic_block_frames_modeled`）；**真空流**最小二帧
  （上述 `message_start`+`message_stop`）；**正常上游结束** SHALL NOT 合成任何终止帧，透传原始终端。
  `truncated_mode` 口径保留：Chat/Anthropic 记 `open_ended`（metrics 观测），Responses 记
  `synthesized_failed`——`open_ended` 仅余观测口径，不再代表「不发终止帧」。实现见
`src/service/block_inject/frames.rs::empty_stream_frames_modeled`（真空最小终止帧定义）与
`src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_empty_stream` 空流合成守门
（终端决策单一所有者）；三协议对照由单测 `vacuum_stream_three_protocol_e2e_comparison` 锁定。
- 语义面只补线级终止，不伪造内容/usage/成功（Anthropic `error` 本身即终端，其后不注入 `message_stop`）。
- 风险：Anthropic 严格 SDK 若要求 `message_delta` 才认流闭合，最小信封可能被拒收；
  以本节「真空流最小终止」语义为准，实测需要时另行补帧。
- 中途断流与真空流区分：真空流（零字节零残余）走本节的
  `empty_stream_frames_modeled` 最小终止；中途断流（已发内容帧或有截断信号后异常收尾）走
  「中途断流终端策略」（见 §7.2）——Chat 补恰一 `[DONE]`、Anthropic 仅记 `open_ended`
  不合成 `message_stop`、Responses 已发帧合成恰一 `response.failed`。两路径均保持三协议
  合成终端恒恰一，`truncated_mode` 观测口径保留（Chat/Anthropic `open_ended`、
  Responses `synthesized_failed`）。
