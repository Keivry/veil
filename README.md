# veil

Rust 实现的安全网关：凭据 API（三因子认证 + Matrix 审批）与 LLM 脱敏反向代理（SSE 流式还原 + 输出审计）。

本文档是部署与行为的唯一文档入口，阈值表与 `openspec/specs/admin-ratelimit-contract/spec.md`（canonical，自 `veil-hardening` 归档晋升）契约同字；如有出入以 spec 为准。

## 1. 部署方式

### 前置条件

- Rust 工具链（本地直跑）或容器运行时（compose 部署）。
- Matrix 账号 + Homeserver（审批与 Bot token）。
- 生产建议 TPM 2.0 芯片；无硬件的开发机见下方 `VEIL_ALLOW_MOCK_TPM` 说明。

### 必填环境变量

| 变量 | 说明 |
|:-----|:-----|
| `HOMESERVER` | Matrix homeserver URL |
| `ROOM_ID` | Matrix 审批房间 ID |
| `MATRIX_ACCESS_TOKEN` | Matrix Bot access token |
| `OBSERVABILITY_ADMIN_TOKEN` | `/_admin` 鉴权 Token，须独立（不得复用 `MATRIX_ACCESS_TOKEN`），建议 ≥32 字符（不足仅 warn 告警，不拒启动） |

### 环境变量全表（PII/AUDIT/TPM/LLM）

必填四项见上表；下表列出全部可选变量与默认值，未列出的变量二进制不读取。三大 fail-closed 约束：缺必填拒启动、
`PII_CUSTOM_*` 缺文件或解析失败拒启动、无硬件 TPM 且未显式放行拒启动。

例外（审计层）：`src/service/audit/policy.rs::capture_process_env` 于策略加载时快照进程 env（`HOME` 单列 +
全量 vars），供命令文本的 `$VAR`/`${VAR}` 展开（`src/service/audit/normalize.rs`）与 `~/` 家目录展开
（`src/service/audit/rules.rs`）使用；该两处读进程 env 不受本表「未列出即忽略」约束，但其结果只参与审计判定、
不回写配置。

| 分组 | 变量 | 默认 | 说明 |
|:-----|:-----|:-----|:-----|
| 认证 | `GET_BINARY_SECRET` / `CREDENTIAL_SECRET` | 空（兼容模式） | 三因子之部署密钥；前者优先 |
| 认证 | `GET_BINARY_HASH` | 空 | 独立生效：置位时拒绝调用方冒用 get 自身哈希的直调（`caller_hash == GET_BINARY_HASH` → 403）；为空时该检查兼容跳过，与 `GET_BINARY_SECRET` 无联动 |
| 认证 | `CREDENTIAL_ADMIN_TOKEN` | 空 | 遗留兼容项；若设置须与 `OBSERVABILITY_ADMIN_TOKEN` 不同；**不再作为紧急吊销放行依据**（见 §7.5） |
| 认证 | `AUTO_APPROVE` | `true` | 别名集（trim + 大小写不敏感）：`true/1/yes` 放行 / `false/0/no` 拒绝 / `none/pending/matrix` 转 Matrix 审批 |
| 认证 | `CREDENTIAL_BLOCK_WAIT` | 关闭 | 凭据审批双模开关；开启条件为真值集合 `1/true/yes/on`（trim + 大小写不敏感），enrolled 篡改/未 enrolled 待审走 `300`s 阻塞等 reaction，默认（未设/非真值）保持 `202` 抛单（建单 + best-effort 发送即返回，接线见 `src/service/credential/approval.rs::approval_dual_mode`）；默认模式客户端按 `E_PENDING` 对同一请求轮询重试（建议指数退避），阻塞模式无需轮询；示例：`CREDENTIAL_BLOCK_WAIT=1` |
| 入口 | `VEIL_ENTRY_MODE` | `full` | `full` / `credential-only` / `llm-only` |
| 入口 | `CALLER_REGISTRY_PATH` | `<DATA_DIR>/caller_registry.json` | 调用方注册表路径 |
| 入口 | `OBSERVABILITY_DISABLE` | 空（启用） | 精确 `=1`（去空白）时 `/_admin*` 全 404，且与 token 有效性无关；其余值不触发；生产不推荐 |
| 存储 | `DATA_DIR` | `/data` | sqlite、审计日志父目录；派生 `/data/tpm`（`seal.pub`+`seal.priv`）与 `/data/db`（`.kdbx`+`.key`） |
| 存储 | `DB_DIR` / `TPM_DIR` | `<DATA_DIR>/db` / `<DATA_DIR>/tpm` | kdbx 库目录（扫描排序取末位 `.kdbx`，同名 `.key` 优先）与 TPM 密封目录 |
| 存储 | `VEIL_KEEPASS_BACKEND` | `real` | `real` 真实 kdbx 后端；显式 `mock` 仅 CI 逃生（生产禁用） |
| 脱敏 | `REDACTION_ENABLED` | 开启 | 脱敏总开关；显式 `0/false/no/off` 关闭 |
| 脱敏 | `PII_REDACTION_ENABLED` | — | 原仓别名；仅当 `REDACTION_ENABLED` 为空时生效 |
| 脱敏 | `PII_RESPONSE_SIDE` | 开启 | 响应侧新检出注册占位符；关闭后新 PII 原样透出 |
| 脱敏 | `PII_FUZZY_RESTORE` | 关闭 | 残缺形态按序号回查还原 |
| 脱敏 | `PII_DETECTION_HARDENING` | 关闭 | 严格边界复核，丢弃 ASCII 粘连与前导零 IPv4 |
| 脱敏 | `PII_CUSTOM_RULES_FILE` / `PII_RULES_FILE` | 空 | 自定义正则**文件路径**（合并槽；可与分离槽叠加）；格式 JSON / 极简 YAML（`.yaml`）/ TXT 名单；已配置但缺文件/不可读/解析失败/形态非法一律拒启动，空文件仅 warn（见 `examples/pii-custom.yaml`） |
| 脱敏 | `PII_CUSTOM_RULES` | 空 | **短名槽变量**（相对原仓 6 个 `*_FILE` 的合并槽超集）：与 `*_FILE` 同槽、同文件路径解析、同 fail-closed，列序最低（无 `_FILE` 后缀仅为兼容别名） |
| 脱敏 | `PII_CUSTOM_PATTERNS_FILE` / `PII_CUSTOM_PATTERN_FILE` | 空 | 自定义模式**文件路径**（数组或 `{name: pattern}` 映射）；fail-closed 同 `PII_CUSTOM_RULES_FILE` |
| 脱敏 | `PII_CUSTOM_PATTERNS` | 空 | **短名槽变量**：与 `*_FILE` 同槽、同文件路径解析、同 fail-closed，列序最低（无 `_FILE` 后缀仅为兼容别名） |
| 脱敏 | `PII_CUSTOM_DICT_FILE` / `PII_DICT_FILE` / `PII_SENSITIVE_DICT_FILE` / `PII_SENSITIVE_NAMES_FILE` | 空 | 字典**文件路径**（TXT 每行一名，`#` 注释忽略）；各名等价加载，列序即优先级（`PII_DICT_FILE` 相对 Python 历史名优先，与原仓一致）；fail-closed 同 `PII_CUSTOM_RULES_FILE` |
| 脱敏 | `PII_CUSTOM_DICT` | 空 | **短名槽变量**：与 `*_FILE` 同槽、同文件路径解析、同 fail-closed，列序最低（无 `_FILE` 后缀仅为兼容别名） |
| 脱敏 | `PII_VALUE_SAMPLE_ENABLED` | 关闭 | 值级采样总开关 |
| 脱敏 | `PII_VALUE_SAMPLE_PERSIST` | 开启 | 值级采样落盘 |
| 脱敏 | `PII_VALUE_SAMPLE_HMAC_KEY` | 空 | 未设退化为 SHA256 |
| 脱敏 | `PII_PLACEHOLDER_PROMPT` | 开启 | 占位符说明注入；`0/false/no/off` 关闭 |
| 脱敏 | `PII_PLACEHOLDER_PROMPT_TEXT` | 内建默认 | 自定义文案（4KB 上限，超限截断；含合法占位符形态回退默认） |
| 脱敏 | `PII_HOLD_MAX` | `64` | **响应侧跨帧缝窗字符数**（须 ≥1 正整数；`PII_RESPONSE_SIDE` 关闭时窗口归零=直通不滞留）；缝合相邻两帧做跨缝 PII 检测，JSON 信封过滤后映射回原帧坐标、整帧延迟一级（见 §7.9）；审计 hold 字节上限由 `AUDIT_HOLD_MAX_BYTES` 独立承载，二者不同维度 |
| 脱敏 | `NORMALIZE_JSON_WHITESPACE` | 关闭 | 仅 `"1"` 开启请求体空白归一 |
| 脱敏 | `PII_SCOPE_MODE` | `request` | PII 作用域模式：`request`（默认，逐请求隔离，现行为）/ `conversation`（显式启用会话级关联）；非法值拒启动 |
| 脱敏 | `PII_SCOPE_TTL_SECS` | `1800` | `conversation` 模式会话条目空闲 TTL（秒，须 ≥1 正整数，非法拒启动） |
| 脱敏 | `PII_SCOPE_MAX_CONVERSATIONS` | `1024` | `conversation` 模式会话数上限（超限按 LRU 淘汰，须 ≥1 正整数，非法拒启动） |
| 脱敏 | `PII_SCOPE_KEY_HEADER` | `x-veil-conversation-id` | `conversation` 模式会话键第 1 级来源请求头名；属 `x-veil-*` 内部命名空间，MUST NOT 转发上游或入日志 |
| 审计 | `AUDIT_MODE` | `off` | `off` / `block` / `approve`；`approve` 必须配 `APPROVAL_WHITELIST` |
| 审计 | `AUDIT_ENABLED` | 空 | 遗留回退：`AUDIT_MODE` 缺失/空白时真值 `1/true/yes/on`（trim + 大小写不敏感）→ `block`（fail-closed），显式 `AUDIT_MODE` 优先，缺省仍 `off` |
| 审计 | `AUDIT_TIMEOUT` | `90`s | 禁止落在 `110`-`130`s 竞态区间，否则拒启动 |
| 审计 | `AUDIT_HOLD_MAX_BYTES` | `1048576` | 审计 hold 上限字节（须 ≥1 正整数） |
| 审计 | `AUDIT_POLICY_FILE` | 内建默认策略 | 审计策略文件路径；启动期 fail-fast 加载（损坏拒启动），文件 `mode` 生效（优先级 env 显式 > 文件 > off，见 §6.11） |
| 审计 | `APPROVAL_WHITELIST` | 空 | 审批人 Matrix ID 逗号分隔（`@user:server`） |
| TPM | `VEIL_ALLOW_MOCK_TPM` | 未设置（硬件强制） | 仅 trim 后等于字面 `1` 放行 Mock TPM（其余值仍走硬件门禁 fail-closed），专供无硬件开发机与 CI；生产禁用（见下方指引） |
| TPM | （硬编码）TPM 子进程单步超时 | `30s` | `tpm2_createprimary/load/unseal` 单步上限；存活探测走 `tpm2_pcrread sha256:0` 只读 PCR（不预演密封回放，差异有意，见 `src/service/tpm.rs`） |
| LLM | `LLM_UPSTREAM` | 空 | 缺省上游 URL；`scripts/api_conformance.py` 将其指向 mock 上游 |
| LLM | `LLM_<port>`（如 `LLM_8878`/`LLM_8879`） | 见 compose | 按宿主机入口端口选择上游 |
| LLM | `HTTP_TIMEOUT_SECS` | `30` | 非流与 NonDialog 上游转发整体超时（秒）；流式（SSE）路径用独立 client 不设覆盖整响应体读取的总超时，长流不因此截断（见 §7.2） |
| LLM | `NONSTREAM_MAX_BYTES` | `8388608` | 非流对话响应体上限（字节，须 ≥1 正整数，显式非法拒启动）；仅非错误（`status < 400`）响应严格超限 `502` + `response_too_large`，错误体按透传语义不改写（见 §4） |
| LLM | `HTTP_POOL_MAX_IDLE_PER_HOST` | `16` | 每主机空闲连接上限 |
| LLM | `HTTP_POOL_IDLE_TIMEOUT_SECS` | `90` | 空闲连接保活（秒） |
| compose 专用 | `PORT_8877` / `PORT_8878` / `PORT_8879` | `8877/8878/8879` | 仅改宿主机映射端口，不改容器内监听；二进制直跑时忽略（只监听 `127.0.0.1:8877`） |
| compose 专用 | `TPM_HOST_PATH` / `DB_HOST_PATH` | `./data/tpm` / `./data/db` | 宿主机只读挂载源；二进制直跑时忽略 |

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

- `GET /_admin/` 返回 JSON 索引占位（六路由表与就绪说明），为终态形态；独立 `admin.html` 静态页为 Non-Goal，
  本仓不交付（见 `observability-admin` spec），如需静态控制台由新 change 交付。
- `GET /_admin`（无尾斜杠）与 `GET /_admin/` 注册为同一索引 handler，均返回 200 JSON 索引
  （`src/router.rs` 双路由注册）；`/_admin/{*rest}` 未知子路径仍 404。
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
export HOMESERVER=https://matrix.example.com
export ROOM_ID='!roomid:example.com'
export MATRIX_ACCESS_TOKEN='syt_...'
export OBSERVABILITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
# 无 TPM 硬件的开发机专用（生产禁用）：
export VEIL_ALLOW_MOCK_TPM=1

cargo run --release
```

服务监听 `127.0.0.1:8877`（回环，见 `src/main.rs`）。

### 容器部署

```bash
export MATRIX_ACCESS_TOKEN='syt_...'
export OBSERVABILITY_ADMIN_TOKEN="$(openssl rand -hex 32)"

docker compose up -d --build
```

- 三端口默认仅回环：`127.0.0.1:8877`（凭据 API）、`127.0.0.1:8878`、`127.0.0.1:8879`（LLM 代理入口）。
  容器内服务固定监听 8877，三条映射均指向该端口；宿主机端口可经环境变量覆盖，
  回环绑定语义保持：`PORT_8877=19077 PORT_8878=19078 PORT_8879=19079 docker compose up -d`。
- 数据卷沿用原仓约定：`${DATA_DIR:-./data}:/data` 父卷在前，`/data/tpm` 与 `/data/db` 只读子卷在后。
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
| 因子 1：二进制完整性 | 请求头 `X-Get-Binary-Hash` | `get` 二进制的 SHA256 |
| 因子 2：部署密钥 | 请求头 `X-Get-Binary-Secret`（兼容 `body.secret`） | Hermes 容器与网关共享的部署密钥 |
| 因子 3：调用者身份 | 请求体 `body.auth.caller_hash` / `caller_path` | 调用脚本文件的 SHA256 与路径 |

```bash
curl -fsS http://127.0.0.1:8877/credential \
  -H 'Content-Type: application/json' \
  -H "X-Get-Binary-Hash: $(sha256sum "$(which get)" | cut -d' ' -f1)" \
  -H "X-Get-Binary-Secret: $GET_BINARY_SECRET" \
  -d '{"auth":{"caller_hash":"<sha256(脚本)>","caller_path":"/srv/job.sh"}}'
```

语义补充（与 `credential-api` spec 一致）：

- 服务端未配置对应调用方期望哈希（未 enrolled）时**默认转 Matrix 审批**
  （`202 + E_PENDING`；`AUTO_APPROVE=false` 时直接 `403`）——未注册调用方不再直接取用凭据，
  自动放行仅对已注册调用方生效（`AUTH-4`，**BREAKING**）。迁移：旧部署依赖未 enrolled 直接取用的
  须先完成注册审批，或恢复旧口径另立 change 并撤回本条。
- `caller_hash == GET_BINARY_HASH`（终端直调而非脚本调用）拒绝 403。
- 自动放行三态：`True` 放行 / `False` 拒绝 / `None` 转 Matrix 审批（哈希不一致走 `None` 分支）；
  别名集（trim + 大小写不敏感）：`true/1/yes` 放行、`false/0/no` 拒绝、`none/pending/matrix` 转审批
  （`src/config/env_parse.rs::AutoApprove`）。
- 管理面鉴权优先级：`X-Admin-Token` 头 > `__Host-admin_token` Cookie > `?access_token`（仅 SSE 回退）；
  非 SSE 接口以 query 携带 token 恒 401。
- 写端点部署密钥强制（`AUTH-11`，**BREAKING**）：`POST /approve-hash-change`、`POST /register-caller`、
  `POST /revoke` 在部署未配置 `GET_BINARY_SECRET`/`CREDENTIAL_SECRET`（compat 默认）时 fail-closed——
  一律 `403`（`E_AUTH`）且不执行任何注册/吊销/哈希变更动作；迁移须配置非空部署密钥并与客户端
  `X-Get-Binary-Secret`（或 `body.secret`）取值对齐。该约束**不适用于** `POST /credential` 读路径
  （compat 模式仍按 Python 语义跳过 Secret 因子），与三因子核验共用同一字段口径。

## 3. 限流规则

- 通用 admin 接口按源 IP 限流 `10/min`，超限返回 `429` 并携带 `Retry-After` 头（头名大小写不敏感， wire 形态为小写 `retry-after`）。
- `/_admin/health` 豁免通用 `10/min` 限流（存活探针高频；豁免集为
  `src/service/admin/ratelimit.rs::admin_rate_exempt_paths()` 唯一项），health 请求不占通用限流桶。
- `/_admin/events/stream` 按 IP 限制并发 `5`，超限拒绝新连接（`429 + Retry-After: 60`，固定 60 秒）
  而不影响已建连接；保活 `60s` ping，`5min` 服务端强制重连。
- SSE 建连过滤与近环回放：`/_admin/events/stream` 支持建连 query 过滤 `?model=&upstream=`
  （`SseFilter::from_query`）；建连时按同过滤回放最近 20 条已脱敏事件（近环回放），
  实时推送亦按该过滤维度生效（`src/handler/admin.rs::admin_events_stream`）。
- `10/min` 为速率维度、`5`/IP 为并发维度，两者正交且均为有意设计。
- 限流计数按 TCP 远端地址（不采信 `X-Forwarded-For` 等代理头，防伪造绕过）；
  经反代访问时所有客户端共享反代地址的同一限流桶。
- 凭据面限流按调用方维度独立计数（`C11`，`veil-credential-flow-parity`）：凭据取用按
  `caller_path:caller_hash` 桶、窗口 `2s`（`CREDENTIAL_RATE_WINDOW_SECS`），注册按 `source`
  桶、窗口 `1s`（`REGISTER_RATE_WINDOW_SECS`）；同一调用方窗口内第二次 `429`，其他调用方
  不受影响（跨方故障隔离）。该维度相对原仓 Python 全局单桶 `2s` 属**有意差异**——
  全局单桶下任一调用方高频会阻塞所有调用方（跨方 DoS 面）。回退条款：若运维要求严格
  全局单桶，须另立 change 交付，本 change 不静默改行为。
- `/_admin/series` 的 `since` 仅接受 `[dhm]<整数>` 形态（与 `day_key`/`hour_key`/`five_min_key`
  产出同形）；非法值返回 `400 + E_BAD_REQUEST`（消息列明合法形态），**不以全量无过滤回退**
  （`i64::MIN` 回退已移除）。epoch 或日期形态支持须另立 change 交付（见 canonical
  `openspec/specs/observability-admin/spec.md`「series since 取值形态校验」）。

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

诚实声明：B1.2 token 文件加载仅 `cfg(test)` 生效（生产 fail-closed 口径不变），B7 限流 e2e 为用例级自建 App 隔离桶（生产共享桶语义不变）。

## 4. 阈值表

下表与 `openspec/specs/admin-ratelimit-contract/spec.md`（canonical，自 `veil-hardening` 归档晋升）同字；差异均为有意设计（不同检查点），超限行为统一为
`429 + Retry-After`（限流）、`413`（body 超限）与 `502`（非流对话响应超限）。

| 维度 | 取值 | 超限行为 | 是否接入口 | 说明 |
|:-----|:-----|:---------|:-----------|:-----|
| 通用 admin 接口限流 | `10/min`/IP | `429` + `Retry-After` | 是 | 速率维度；按 TCP 远端地址计数，不采信代理头 |
| SSE 并发 | `5`/IP | 拒绝新连接，已建连接不受影响 | 是 | 并发维度；与 `10/min` 正交；`60s` ping + `5min` 强制重连 |
| 通用请求体上限 | `10MB` | `413` | 是（入口唯一 enforcement） | 通用 JSON 检查点 |
| 非流对话响应上限 | `NONSTREAM_MAX_BYTES` 默认 `8MB` | `502` + `response_too_large` JSON 体（`error.type`，见 `src/handler/llm/nonstream.rs:582`） | 是（入口 enforcement） | 对话尾缀（chat/completions、v1/messages、v1/responses）响应体严格超限；`Protocol::NonDialog` 透传不受限；与审计 ceiling `AUDIT_SUBLIMIT_CEILING_BYTES`（子限锚点、非入口 enforcement）分属不同检查点，不可互相替代；与 Python 观测差异见 design D12（`T14`：无独立指标/warning、无状态门） |
| 审计类上限 | `8MB` | — | 否（纯 ceiling 锚点） | 策略子限 ceiling（`AUDIT_SUBLIMIT_CEILING_BYTES` 回归锚点：现网可配子限如 `AUDIT_HOLD_MAX_BYTES` 默认 1MB 均不得超过它）；与入口 `10MB` 属不同检查点、差异有意 |
| 审计日志轮转 | `10MB` x 5，`0600` | 写失败双层 fail-closed | 先脱敏后截断，零明文 |
| 审批超时 | `AUDIT_TIMEOUT` 默认 `90`s | — | 禁止落在 `110`-`130`s 竞态区间 |
| 凭据审批超时 | `300`s | — | 与审计 `AUDIT_TIMEOUT` 分表 |

`GET /health` 的 `pending` 计数在审批终态（批准/拒绝/超时）即时归零：内存侧与矩阵侧 pending
在同批终态清理（`C8`，`veil-credential-flow-parity`），不依赖空闲票 `60s` 孤儿清扫延迟。

审批票回收两口径并存、不可混用（`F16`，`veil-oracle-followup-fix`）：**空闲票 60s 回收上限**——
无阻塞等待者的孤儿票按分支 TTL（审计/解锁类 `60s`）清扫；**有阻塞等待者凭据类票 300s 阻塞 TTL**——
凭据/注册/哈希变更类存在阻塞等待者的未决票在其自身 `300s` 阻塞超时前不被回收。前者是清扫延迟上限，
后者是阻塞等待保留时长，维度不同（详见 §8.4）。内存侧 `PendingApprovals` 清扫与矩阵侧同口径按记录 TTL
执行（`AUTH-9`：凭据/注册/哈希变更类阻塞票 `300s`、空闲/审计/解锁类 `60s`），不再对全部记录一律 `60s`。

`GET /health` 与 `/_admin/health` 的 `pii_custom_disabled`（只增字段）为已停用自定义规则计数
（`disabled_snapshot()` 口径，`P2`，`veil-pii-parity-closeout`）：ReDoS 守卫连续 3 次超时停用的
规则在此可见，无停用为 `0`；既有探针字段不变。

### 4.1 内部常量附录（未列即内部实现细节）

附录为可审计登记，不构成外部契约；未列出的常量均属内部实现细节，变更不视为 BREAKING。

| 符号 | 取值 | 来源 |
|:-----|:-----|:-----|
| `CREDENTIAL_RATE_WINDOW_SECS` | `2` | `src/config/env_parse.rs` |
| `REGISTER_RATE_WINDOW_SECS` | `1` | `src/config/env_parse.rs` |
| `PENDING_TTL_SECS` | `60` | `src/approval.rs` |
| `OLD_HASH_GRACE_SECS` | `3600` | `src/registry/entry.rs` |
| `RateTable::MAX_ENTRIES` | `4096` | `src/service/credential/ratelimit.rs` |
| `RateTable::SWEEP_LEN` | `1000` | `src/service/credential/ratelimit.rs` |
| `RateTable::SWEEP_SECS` | `60` | `src/service/credential/ratelimit.rs` |
| `LINE_LIMIT_BYTES` | `16KiB` | `src/config/env_parse.rs` |
| `EVENT_IDLE_TIMEOUT` | `30s` | `src/config/env_parse.rs` |
| `KEEPALIVE_INTERVAL` | `10s` | `src/config/env_parse.rs` |
| `RING_CAP` | `10000` | `src/service/metrics/aggregate.rs` |
| `METRICS_FLUSH_INTERVAL_SECS` | `60` | `src/service/metrics/store.rs` |
| `AGGS_MAX_ENTRIES` | `4096` | `src/service/metrics/aggregate.rs` |
| `AGGS_DAILY_KEEP` / `AGGS_HOURLY_KEEP` / `AGGS_FIVE_MIN_KEEP` | `32` / `170` / `1` | `src/service/metrics/aggregate.rs` |
| `ADMIN_RATE_MAX_ENTRIES` | `4096` | `src/service/admin/ratelimit.rs` |

## 5. Go 客户端对接指引

存量 Go `get` 客户端无需修改即可对接：网关保持其所用路径与方法不变。客户端源码自
`veil-audit-r2-remediation` 起内置本仓 `get/`（模块路径与二进制名不变），`202 + E_PENDING`
轮询语义与退出码约定见本节末条。

| 用途 | 方法与路径 | 鉴权 |
|:-----|:-----------|:-----|
| 取用凭据 | `POST /credential` | 三因子（`X-Get-Binary-Hash` + `X-Get-Binary-Secret`/`body.secret` + `body.auth.caller_hash`/`caller_path`） |
| 查看注册 | `GET /registrations` | 原仓经 `_require_auth` 校验 `GET_BINARY_HASH` + `GET_BINARY_SECRET`（未配置时兼容跳过）；本仓管理面鉴权（`X-Admin-Token` 或部署密钥 `X-Get-Binary-Secret`，两者皆缺/不匹配 401）；旧脚本须补凭据，Go `get list` 经部署密钥可用 |
| 注册调用方 | `POST /register-caller` | 三因子（同取用；重名 409） |
| 吊销注册 | `POST /revoke`，紧急吊销 `POST /revoke/emergency` | 常规三因子；紧急吊销管理 token/内网两者任一（见 7.5） |
| 批准哈希变更 | `POST /approve-hash-change` | 三因子 |
| LLM 代理透传 | 任意 `/{tail}`（含 `GET`；未知 admin 子路径除外） | 无（上游透传） |
| 存活探针 | `GET /health` | 无 |

```bash
# 取用（脱敏值，默认）
get credential 网易 授权码
# 取用原文（仅限脚本内调用，终端直调被 403 拒绝）
get credential 网易 授权码 --raw
# 注册 / 吊销
get register --name "check-mail" --entry "网易" --fields "授权码" --desc "检查邮件" --auto
get revoke --name "check-mail"
```

- `allow_mode` 契约（`AUTH-10`）：`POST /register-caller` 的 `allow_mode` 接受 `auto`（等价自动放行
  `true`）与 `manual`（等价转审批 `none`），与 Go `get register --auto` 及 Python 默认 `manual` 对齐；
  未知非空值回退 `auto` 布尔并记 `warn` 日志。
- 写端点部署密钥前置（`AUTH-11`，**BREAKING**）：`POST /register-caller`、`POST /revoke`、
  `POST /approve-hash-change` 要求部署已配置 `GET_BINARY_SECRET`/`CREDENTIAL_SECRET`；compat 默认
  （未配置）下三者恒 `403`（`E_AUTH`）不执行动作。存量 Go 部署迁移须配置部署密钥（Go `get` 实发
  `X-Get-Binary-Secret`，配置后无需改客户端）。`POST /credential` 取用路径不受影响。

- `POST /revoke` 异步 `202` 轮询契约（`CRD-2`）：默认模式（`CREDENTIAL_BLOCK_WAIT` 未设或非真值）下
  与 `POST /credential` 同口径——`202 + E_PENDING`（`{"error":{"code":"E_PENDING",...}}`）表示**已建单
  待审批**，**不代表吊销已完成**；调用方 SHALL 对同一请求轮询重试（建议指数退避），批准后吊销生效
  （条目 `revoked=true`/`enabled=false`），拒绝/超时返回 `403`，重试不重复建单。`CREDENTIAL_BLOCK_WAIT=1`
  时同请求阻塞返回终态、无需轮询。紧急吊销转常规审批路径同此契约。

- `POST /revoke` 定位顺序 `key → caller_path → caller_hash → name`（`C5`，`veil-credential-flow-parity`）：
  `get revoke --name "check-mail"` 命中未吊销同名条目；重名 409——未吊销条目重名注册直接拒绝，
  已吊销条目的名称释放可复用。

- 注册表存储语义（`C14`，`veil-credential-flow-parity`）：加载 fail-closed——解析失败或完整性
  sha256 失配一律拒绝加载（不回落空表放行）；落盘原子且同步——tmp 写后 `sync_all`、rename 后
  父目录 `sync_all`，保证掉电后已确认写不丢失；条目按 `BTreeMap` 键序稳定排序（完整性哈希与
  diff 可复现，不承诺原仓插入序）；`DB_DIR` 扫描排序取末位 `.kdbx`，仅当存在同名 `.key` 才配对
  （不取首个 `.key`，避免配错库）。

- 三因子字段：`X-Get-Binary-Hash` + `X-Get-Binary-Secret`（或 `body.secret`）+ `body.auth.caller_hash` /
  `caller_path`；齐全时按既有语义放行或进入审批，缺失时返回明确的鉴权失败（403），不会空响应或挂起。
- 凭据审批 `202` 轮询语义：默认（`CREDENTIAL_BLOCK_WAIT` 未设或非真值）待审请求返回
  `202 + E_PENDING` 即已建单，客户端应对同一请求轮询重试（建议指数退避），批准后重试返回凭据、
  拒绝后 `403`；`CREDENTIAL_BLOCK_WAIT=1` 时无需轮询（同请求阻塞等待，批准返回凭据、拒绝/超时 `403`）。
  超时码归并（迁移注意）：阻塞超时在本仓按拒绝返回 `403`，Python 原仓超时为 `408`——差异明示与迁移建议见 §6.7。
- Go `202` 处理（`get/`，本仓内置客户端）：`get revoke` / `get register` / `get credential` 在收到
  `202 + E_PENDING` 后按退避轮询**同一请求**（服务端经决策表幂等复用既有票，不重复建单）直至终态：
  批准 → 成功（吊销生效 / 注册生效 / 返回凭据），拒绝或超时 → `403` 报错；间隔与时限由
  `PROXY_APPROVAL_POLL`（默认 `2s`，逐次翻倍至 `10s`）与 `PROXY_APPROVAL_TIMEOUT`（默认 `300s`）控制。
  `--no-wait` 或 `PROXY_APPROVAL_WAIT=0` 时仅提交审批单并以**退出码 `2`** 表示「已受理未完成」
  （不再把 `202` 当成功）；`CREDENTIAL_BLOCK_WAIT=1` 时服务端阻塞返回终态，客户端单次调用即完成。
  错误体兼容（`ErrMessage`：网关对象取 `message`、兼容 Python 字符串错误体）与 `/credential`
  成功信封 `{"ok":true,"credential":{...}}` 不变；`202` 体不再报「解析响应失败」。
- Go 客户端环境变量（`get/`，本仓内置）：`PROXY_URL`（网关基址，默认 `http://127.0.0.1:8877`）、
  `PROXY_HTTP_TIMEOUT`（单次 HTTP 超时秒数，默认 `300`；非法值回退默认并向 stderr 告警，
  fail-closed 不回退 `30s`）、`PROXY_APPROVAL_WAIT`（默认 `1`；`0` 立即返回待审批）、
  `PROXY_APPROVAL_TIMEOUT`（审批终态总时限，默认 `300s`）、`PROXY_APPROVAL_POLL`（轮询起始间隔，
  默认 `2s`，逐次翻倍至 `10s`）。审批真实网关 E2E（`get/internal/approval_e2e_test.go`）由
  `VEIL_APPROVAL_E2E_URL`（网关基址）与 `VEIL_APPROVAL_E2E_CALLER`（一次性调用方名）共同启用，
  二者未同时设置即 `t.Skip`；该用例会向网关提交对 `VEIL_APPROVAL_E2E_CALLER` 的**真实吊销审批单**
  （破坏性，仅限可弃用调用方）。
- SSE 语义对 Go 透明：被审计阻断的流恒以终止帧闭合，客户端视为正常结束，不重试、不挂起。

## 6. 行为变更（BREAKING）与迁移

下述十处为相对原仓（Python `credential-proxy`）已发生的默认值与语义漂移，现显式为 BREAKING；
§6.3 为容量分表基线确认（非 BREAKING）。
按迁移步骤调整后可回到预期行为，无静默变严或明文落盘增量。

### 6.1 脱敏总开关默认开启（原仓默认关闭）

- 变更：`REDACTION_ENABLED` 两者皆空时默认开启；原仓默认关闭。
- 影响：旧 compose 若未显式配置，会被静默变严（请求被脱敏）。
- 迁移：沿用原仓行为请显式关闭：
  ```bash
  REDACTION_ENABLED=0
  ```

### 6.2 PII 值采样持久默认开启落盘（原仓内存-only）

- 变更：`PII_VALUE_SAMPLE_PERSIST` 默认开启（掩码 + hash 落盘 `pii_value_samples` 表，7 天滚动）；
  原仓内存-only 不落盘。注意采样总开关 `PII_VALUE_SAMPLE_ENABLED` 默认仍关闭，
  仅在其开启后持久语义才生效。
- 影响：开启采样后会产生落盘增量；未设 `PII_VALUE_SAMPLE_HMAC_KEY` 时 hash 为无盐 SHA256，
  低熵 PII 可被离线字典枚举（仅趋势参考，生产必须配置 HMAC key）。
- 迁移：回到内存-only 请显式关闭持久，或整体关闭采样（默认即关闭）：
  ```bash
  PII_VALUE_SAMPLE_PERSIST=0
  # 或
  PII_VALUE_SAMPLE_ENABLED=0
  ```
  生产启用采样时必须配置：
  ```bash
  PII_VALUE_SAMPLE_HMAC_KEY="$(openssl rand -hex 32)"
  ```

### 6.3 容量分表确认（非 BREAKING）

- 基线确认：原仓自 v0.9.6 起凭据与 PII 均已是真 LRU（`_token.py:231`、`:523-538`），
  容量凭据 `MAX_TOKEN_ENTRIES=5000`（`_token.py:102`）/PII `PII_MAX_ENTRIES=1000`（`_token.py:141`）
  与本仓一致，非行为漂移，故不计入 BREAKING。
- 基线 commit（锁定）：`46f6ff665c869b02c154c10df431c638c2177fd9`（2026-09-07，bump version v0.9.47）。
- 迁移：无配置项需改；容量分表（本仓 `MAX_TOKEN_ENTRIES=5000` / `PII_MAX_ENTRIES=1000`）与原仓一致，
  仅作容量复核锚点，不主张默认值/行为变化。
- 序号分配口径（`P5`，`veil-pii-parity-closeout`）：本仓 `PiiScope` 用游标 + 在用序号集合
  O(1) 均摊分配（到顶回卷、淘汰释放的序号可复用、满表返回 `PII_MAX_ENTRIES + 1` 并由紧随
  LRU 淘汰恢复）；与 Python 最小空洞扫描的**可见序号值差异仅影响跨实现关联性，不承诺值一致**。
  序号值非对外契约，不可预测性由 `rand8`（CSPRNG）承担。

### 6.4 流式审批挂起声明（原仓同步阻塞）

- 变更：`AUDIT_MODE=approve` 下流式网关危险调用转 pending 记录，不阻塞流、不合成阻断帧，
  不挂起等待真人 `✅/❎`；拒绝/过期语义由凭据审批链承载。原仓在流中挂起等待 Matrix 审批
 （`keepalive` + 超时默认拒绝并注入阻断帧）。
- 路径集合（`R3`，`veil-reverify-fix`）：`audit-hold` 仅插入内存 pending 记录
  （`audit_pending` 建单点迁移至 `src/handler/llm/pump/spawn/event_loop.rs::handle_event`，取符号锚不随行号漂移），**不建 Matrix 审批票**（无 tracked 发送、
  无真实 `event_id` 键建单）；审批建单路径白名单见 §6.7，规范文本见本 change spec
  「审批建单路径白名单」。
- 影响：长连接不挂起，对 Hermes 更友好；但“危险调用被拦”在流式面表现为 pending 建单
  而非阻断帧，监控须查 pending 事件环而非流内阻断帧。
- 迁移：沿用原仓语义（流中同步等待）需新 change 交付；当前行为以本条为准，e2e 以
  “pending 建单 + 不断链 + 危险原文按 pending 语义处理”断言。

### 6.5 检索调用审计口径统一（流/非流曾相反）

- 变更：`file_search_call`/`web_search_call`（含 `file_search`/`web_search`
  前缀事件与条目类型）流式与非流式统一计为 tool 调用：名按类型派生
  （`file_search`/`web_search`），参按 `arguments/input/args` 优先、
  `queries/query` 回退序列化；检索**结果**（`results`）不进审计 hold
  （体量风险，只看查询）。统一前流/非流判定相反，一方行为变化。
- verdict 口径：检索调用与其他 tool 调用同 verdict 判定通道（流/非流同调用同结论，见 `stream-protocol-parity` spec）；检索**结果**体不进审计 hold，只看查询。
- 影响：检索调用审计量可能上升（误报优于漏审）；监控检索审计量突变属预期。
- 迁移：无配置项需改；依赖旧一方漏审口径的告警阈值请按新口径重估。

### 6.6 回环免 token 未迁移（ENV=dev / ALLOW_LOOPBACK_NO_TOKEN）

- 变更：原仓 `ENV=dev` + `ALLOW_LOOPBACK_NO_TOKEN` 允许回环来源免管理 token；
  本仓**未实现**该逃生口：二进制不读取这两个变量，回环来源与外部来源同等鉴权
  （`X-Admin-Token` / Cookie / 仅 SSE 回退 query；无 token 恒 401）。
- 影响：旧 dev 环境依赖回环免 token 的脚本会收到 401；生产面不回环豁免，
  fail-closed 语义不变（`metrics-admin-parity` spec 允许「恢复或 BREAKING 声明」二选一，
  本仓选择声明）。
- 迁移：dev 环境显式补 `OBSERVABILITY_ADMIN_TOKEN` 并携带 `X-Admin-Token`；
  如需恢复回环免 token 语义，须新 change 交付并撤回本条 BREAKING。

### 6.7 凭据审批默认异步 `202`（原仓同步阻塞 `300`s）

- 变更：`CREDENTIAL_BLOCK_WAIT` 未设或非真值时，enrolled 哈希篡改/未 enrolled 待审请求立即返回
  `202` + `E_PENDING`（先经 tracked 发送取 Bot 返回的真实 Matrix event id 并以之为 pending 键建单，
  再即返回），同一请求不阻塞；原仓 Python 为同一请求内
  同步阻塞 `300`s（批准返回凭据、拒绝 `403`、超时 `408`，`_credential.py:26,445,455`）。
- 发送路由差异（`F1`，`veil-oracle-followup-fix`）：审批建单走 `NotificationSink::send_text_tracked`
  （需真实回执——真实 `event_id` 是反应回调命中 pending 的唯一键；发送失败/取不到 id 即 fail-closed
  返回 `403`，不建不可决单）；事件环/失败通知走 `notify_text` 有界 spool 的 best-effort 路径
  （可丢、不计回执）。二者共用同一 Bot，差异仅在调用点选择的方法。
- 审批建单路径白名单（`R3`）：仅产生可决 Matrix 审批票的**凭据、注册、吊销**三类路径经
  `send_text_tracked` 以真实 `event_id` 建单；`audit-hold` 仅内存 pending（见 §6.4）、`unlock`
  无建单路径、哈希变更经 best-effort `notify_text` 通知
  （`src/service/credential/approval.rs::notify_hash_change`），三者 SHALL NOT 建 Matrix 审批票。
- 轮询语义：`202 + E_PENDING` = 已建单等待 Matrix 人工审批；客户端应轮询重试同一请求
  （建议指数退避），批准后重试返回凭据、拒绝后 `403`。
- 迁移：恢复 Python 式同步阻塞请设 `CREDENTIAL_BLOCK_WAIT=1`（真值集合 `1/true/yes/on`）：
  `300`s 内批准同请求返回凭据、拒绝 `403`、超时按拒绝返回 `403` 且不悬挂。
- 超时码归并（迁移注意，BREAKING 补充）：`CREDENTIAL_BLOCK_WAIT=1` 阻塞超时在本仓与拒绝同码返回 `403`
  （`VeilError::Auth`，`src/service/credential/approval.rs`），相对 Python 原仓超时 `408`
  （`_credential.py:445`）为**有意归并**——超时与拒绝对下游同码，下游重试语义一律按拒绝处理；
  依赖 `408` 区分超时/拒绝的下游须以本条为准，恢复 `408` 须另立 change 并撤回本条。
- 影响：**第三方/未升级客户端**须自行补轮询，或用 `CREDENTIAL_BLOCK_WAIT=1` 阻塞；本仓内置 Go 客户端
  （`get/`）已按契约自动轮询，并以退出码 `2` 区分「已受理未完成」（见 §5）；恢复旧默认须新 change 并撤回本条。

注册审批链（`C1`，`veil-credential-flow-parity`）：`POST /register-caller` **不再「落盘即视为注册完成」**，
写入中立条目（`enabled=false`）后建 `MatrixBranch::Register` 审批单，复用同一双模口径：默认（`CREDENTIAL_BLOCK_WAIT`
未设或非真值）返回 `202 + E_PENDING` 抛单（后台等待落定回写）；`CREDENTIAL_BLOCK_WAIT=1` 时阻塞至 `300s`。
三态落定：`🔓` 保持 `disabled`（不激活）、`✅` 置 `enabled=true`、`❎` 与等待超时置 `revoked=true`（fail-closed）。
未获 `✅` 前条目不可用。同一未决注册请求的重试经决策表幂等（`CRD-6`）：返回同一
`202 + E_PENDING`、不重复建单、不返回 `409`；终态后重试返回终态（`✅` 放行、`❎`/超时 `403`），
与 §5 revoke `202` 轮询契约同口径。

吊销类审批 `🔓` 按拒绝处理（`T1`，`veil-revoke-reaction-fix`）：紧急吊销转常规审批票与常规吊销票口径一致——
`🔓`（`REACTION_AUTO_UNLOCK`）不执行吊销，同请求重试返回 `403` 且条目保持原状（`revoked=false`、`enabled`
不变）；`✅` 仍正常执行吊销。注册审批 `🔓` 维持 `disabled`、凭据/审计分支 `🔓` 不落定，自动放行语义不外溢。

### 6.8 三因子 `caller_path`/`caller_hash` 双必填（原仓仅强制 hash）

- 变更：`POST /credential`/`POST /register-caller` 等三因子接口要求 `body.auth.caller_hash` 与
  `body.auth.caller_path` **双必填**，缺任一返回 `403`（`Auth`，`src/service/credential/auth.rs::handle_credential`）；
  原仓 Python 仅强制 `caller_hash`，仅发 hash 的极老客户端在本仓被拒。
- 影响：仅携带 `caller_hash` 的旧客户端收到 `403`；`caller_path` 是注册表 ACL/吊销定位主键，
  且 `pending_key` 由 `caller_path:caller_hash` 构成，放宽为 hash-only 会退化审批定位与审计关联，
  与 canonical `credential-api` spec「三因子任一缺失或不一致 SHALL 返回 403」冲突。
- 迁移：调用方在 `body.auth` 补齐 `caller_path`（调用脚本的绝对路径）即可；
  Go 存量 `get` 客户端实发双因子齐全，无需改动。放宽为 hash-only 须另立 change 并同步修订 canonical spec。

### 6.9 内外网判定偏严：IP 字面量一律非内网（原仓 `is_external_host` 豁免 RFC1918）

- 变更：审计网络外传判定中，**IP 字面量一律非内网**（可能外传）——RFC1918
  `10.`/`172.16-31.`/`192.168.`、环回 `127.`/`::1`、链路本地 `169.254.`/`fe80::`、CGNAT `100.64.`
  均不豁免；空/无法提取 host 亦按非内网 fail-closed 拦截。原仓 Python `is_external_host` 对
  RFC1918/环回/链路本地返回内网、空 host 返回 `None`（非外网），故原仓放行的
  `curl 10.x --data` 在本仓被拦截。
- 影响：内网目标同样可能是外传/横向移动跳板，本仓不因私网地址放宽拦截面；依赖私网地址直连的内部
  自动化默认会被拦截（误报优于漏审）。
- 迁移：仅 `localhost`/`.local`/`.internal` 内建豁免；其余内网域名请加入策略 `AUDIT_POLICY_FILE`
  的 `internal_suffixes` 显式清单。目标为裸 IP 时无豁免手段（有意偏严），如需放宽须另立 change 并撤回本条。

### 6.10 `AUDIT_ENABLED` 真值集更宽 + 非法审计值拒启动（原仓静默保默认）

- 变更：遗留 `AUDIT_ENABLED` 真值集恒为 `1`/`true`/`yes`/`on`（trim + 大小写不敏感），宽于原仓
  （`1/true/True/yes`，无 trim/`on`）；显式非空 `AUDIT_MODE` 优先，空白 `AUDIT_MODE` 回退 `AUDIT_ENABLED`
  并映射 `block`。`AUDIT_TIMEOUT`（须 ≥1 且避开 `110-130` 竞态区间）与 `AUDIT_HOLD_MAX_BYTES`
  （须 ≥1 正整数）取值非法时拒启动，原仓非法值静默保默认。
- 影响：`AUDIT_ENABLED=on`/` ON ` 在本仓启用审计（原仓不启用）；`AUDIT_MODE`/超时/hold 非法时启动
  直接报错而非静默回落（fail-closed，防静默关闭审计）。
- 迁移：旧部署如依赖静默默认，须显式设置合法 `AUDIT_MODE=off|block|approve` 与合法超时；启动错误
  信息给出合法区间（≥1 且避开 `110-130`）。
- 登记（`A17`）：本条为既有非目标/已声明分歧的记录项，不重复修复；随变更 `veil-audit-rules-parity`
  的 design D17 与覆盖表同批登记。

### 6.11 审计策略文件 fail-closed（原仓解析失败禁用审计继续）

- 变更：`AUDIT_POLICY_FILE` 在**启动期** fail-fast 加载并注入共享运行时状态（请求路径零读盘、
  零 env 快照）；不可读、含未知键、孤立列表项、非法 `mode`、无法解析行或列表段形态错误时拒启动，
  SHALL NOT 降级为「无审计」空策略。加载早于 TPM 门禁、sqlite 初始化与后台任务。原仓 Python 策略
  文件解析失败即禁用审计并继续（fail-open）。`dangerous:` 段兼容原仓对象形
  `{pattern, reason, network}`（YAML mapping 与 JSON 对象，`network` 缺省 `false`）与字符串形，原仓
  风格文件可直接加载或经最小迁移加载。
- 策略 `mode` 生效：文件 `mode` 实际参与运行模式判定并注入运行时配置（`state.config.audit_mode`）；
  优先级为 **env 显式 > 文件 `mode` > 默认 `off`**——`AUDIT_MODE` 非空，或 `AUDIT_MODE` 缺失/空白时
  `AUDIT_ENABLED` 真值回退推导的 `block`，均属 env 显式；文件 `mode` 仅在 env 未给出审计模式时生效，
  两者显式且冲突时记 warn 并以 env 为准，不静默覆盖。
- 生效模式口径的空白名单门禁：当**最终生效模式**为 `approve`（无论来自环境变量、策略文件还是其它
  来源）且 `APPROVAL_WHITELIST` 为空时，启动以配置错误拒绝，不因来源不同而放行。
- 空白名单语义：`APPROVAL_WHITELIST` 为空或未配置时审批白名单层「不过滤」（对标 Python
  `_matrix.py:235,254`），非空时非成员 reaction 仍被忽略；审计 `approve` 空名单由上述启动门禁兜底。
- 自定义 PII 文件上限：`PII_CUSTOM_*` 文件读取前施加 1MB（`1_048_576` 字节）上限，超限具名拒绝启动，
  恰 1MB 放行。
- 审计日志权限：`DATA_DIR/audit.log` 创建即 `0600`（`OpenOptionsExt::mode`），无先创建后 chmod 的宽权限窗；
  轮转产物同样 `0600`。
- 影响：策略文件配置错误不再静默降级为「无审计」，而是显式报错；策略 `mode` 不再「只校验不生效」；
  文件 `mode: approve` + 空白名单不再绕过启动门禁。
- 迁移：修正策略文件语法/键名/`mode` 取值即可；原仓对象形 `dangerous` 无需改写；如需策略文件
  `mode` 生效请确保未显式设置 `AUDIT_MODE`/`AUDIT_ENABLED`。

## 7. 传输与兼容声明

### 7.1 逐跳（HOP）头集

网关双向过滤 RFC 9110 §7.6.1 逐跳头固定 8 项（大小写不敏感）：
`connection`、`keep-alive`、`proxy-authenticate`、`proxy-authorization`、
`te`、`trailer`、`transfer-encoding`、`upgrade`，
外加 `Connection` 头内列名的动态项。解码开启时（默认）额外剥离
`content-encoding`/`content-length`（已解码，对外统一 `identity`：如上游回
`content-encoding: gzip`，下游响应无该头与 `content-length`），
每次剥离记 `hop_filtered_total{dir}` 并打 `tracing::debug`（`header`/`dir` 字段）。与原仓差异：原仓显式剥 7 项 HOP
（`host`/`transfer-encoding`/`content-length`/`content-encoding`/`connection`/`keep-alive`/`te`，`_sse.py:19-28`）；
本仓为 RFC 9110 §7.6.1 全集 8 项 + `Connection` 头内列名的动态项
（`src/service/llm_gateway/hop.rs::HOP_HEADERS`，经 `llm_gateway/mod.rs` 重导出亦可用），
解码配对开关见同文件 `src/service/llm_gateway/hop.rs::DECODE_ENABLED`，
其中 `host` 由 `src/handler/llm/mod.rs::forward_headers` 单独剥；
A5/D9 互引：编码剥离即对外统一 `identity`，见同文件 `filter_hop_headers_counted` 内联注释与单测 `gzip_stripped_as_identity_a5`）。

解码配对补充（M1/D4）：转发上游前 `src/handler/llm/mod.rs::forward_headers` 剥离下游
`accept-encoding`，由 reqwest 注入网关支持集（`gzip`/`br`/`deflate`）；`content-encoding`
仅在 reqwest 实际解压后（tower-http 已连同 `content-length` 移除）才对外 `identity`。
上游若仍回网关不支持编码（如未启用 feature 的 `zstd`）、别名（`x-gzip`）或多值编码，
该头与 `content-length` 保留供下游自解（`src/service/llm_gateway/hop.rs::downstream_decode_enabled`），
不得出现「无编码头 + 压缩字节」；支持集内的编码解码与剥头由同一判定配对。

### 7.2 usage 口径

多源 usage 取最大值（`max` 口径，不双计）：流式增量与完成帧 usage 按
`prompt_tokens`/`completion_tokens`/`total_tokens` 三列各自取 max。
旧大盘按 `sum` 估算会虚高，迁移到新口径请以本声明为准。
`total_tokens` 显式优先与求和回退（互斥，勿混用）：若任一事件显式携带 `total_tokens`/`total`，
取显式值 `max`（保留上游声明）；若全部事件均未显式携带，最终按合并后的
`prompt_tokens_max + completion_tokens_max` **求和回退**（Anthropic `message_start` 输入 +
`message_delta` 输出必须求和而非取 max，见 `src/service/llm_gateway/usage.rs::merge_usage`）。
回退仅在无显式 total 时生效，不覆盖上游声明值。
Responses 取数顶层优先：非流按顶层 `usage` → `response.usage` → `response.response.usage`
三级回退，流式同口径（含 `response.completed` 事件）；定制双层体仍经回退命中不断链。
缓存列 `cached_read`/`cached_write` 同样按列取 max：Anthropic 取顶层
`cache_read/cache_creation_input_tokens`，Responses 取
`input_tokens_details.cached_tokens`，Chat 取
`prompt_tokens_details.cached_tokens`（细节对象 `null`/缺失归零；
非 Anthropic 的 `cached_write` 恒零）。`model` 分桶与缓存列只加不改旧列。

旧大盘对照（迁移须知）：

| 口径 | 旧大盘 | 新口径（本声明为准） |
|:-----|:-------|:---------------------|
| `prompt/completion/total_tokens` | `sum` 累加流式增量与完成帧（虚高） | 三列各自取 `max`（不双计） |
| 缓存列 | 无此列 | 新增 `cached_read`/`cached_write`，只加不改旧列 |
| `model` 分桶 | 无 | 新增，只加不改旧列 |

迁移：依赖旧 `sum` 口径的告警阈值请按 `max` 重估；缓存与分桶列为新增列，旧查询不受影响。

Chat 显式 false 即放弃流式用量，按 key 合并保留不覆写：Chat 请求自带
`stream_options={"include_usage":false}` 时转发体保留 `false`，不覆写为 `true`
（按 key 合并语义，见 `src/service/llm_gateway/protocol.rs` 与
`src/handler/llm/rewrite.rs`）；此时流式无 usage 帧，metrics 空 usage 桶为预期而非异常。
`stream_options` 三态保留（`TRN-5`，`veil-gateway-transport-fidelity`）：键**缺失**时注入
`{"include_usage":true}`；值为 `null`（用户显式第三态）时**原样保留 `null`**，不注入、不替换；
值为对象时仅在缺 `include_usage` 时按 key 合并，已含 `include_usage`（含 `false`）时原样保留；
字符串/数组等畸形形态维持 warn + 整体替换，不静默丢键。
Responses **不注入** `stream_options`（官方规范仅接受 `include_obfuscation`，无
`include_usage`；决策依据与回退条款见 change `veil-llm-proto-closeout` 的 design.md D1/R1），其流式用量一律经
`response.completed.response.usage` 三级回退记录，用户自带键逐字节保留。

中途断流终端策略（D6，`S5`/`S11`）：上游 `chunk()` 报错或异常 EOF（流未发终端即结束）时，
网关按协议收尾并记 `truncated_mode` 观测；`chunk()` 报错另记 warn（含错误与已读字节），
不静默按正常 EOF 退出。Chat 补恰一 `data: [DONE]` 并记 `open_ended`（与既有
`finish_reason` 后补发合并为同一收尾路径，`finish_reason` 后到达的 usage 尾帧照常透传
不丢；上游已发 `[DONE]` 时不重复补发）；Anthropic 不合成 `message_stop`（不伪造成功
终止），仅记 `open_ended`；Responses 已发帧时合成恰一 `response.failed` 并记
`synthesized_failed`，零帧维持真空流最小终止（见 §8.6）。三协议合成终端恒恰一
（见 `src/handler/llm/pump/spawn.rs`、`src/handler/llm/pump/synth_flush.rs`）。

SSE 出口信封保真（`TRN-1`，`veil-gateway-transport-fidelity`）：出口在 `event:` 重放基础上
保真透出 `id:`（WHATWG last-event-id——最近一次出现的 `id` 对后续无 `id` 事件持续有效，
空值 `id:` 重置）与合法整数 `retry:`（非数字值不透出）；上游把 `event:`/`id:` 与 `data:`
分置于不同块时，网关按 `event` FIFO、`id` 最近值跨块暂存并与后续含 `data` 块**同块重建**，
不产生无 `data` 的孤立 `event:` 块；跨块暂存不改事件/帧计数语义——分块信封流与同内容同块流的
`sse_event_count`、`add_sse_event()` 计数与转发帧数逐一致（见
`src/service/sse/parser.rs`、`src/handler/llm/pump/spawn.rs`）。

Anthropic `message_start` 会话/模型提取（`TRN-7`，`veil-gateway-transport-fidelity`）：会话标识
从嵌套 `message.id` 提取，模型名顶层 `model` 优先、回退 `message.model`，使 `message_start`
之后不再恒为 `unknown_model`（见 `src/service/llm_gateway/tool.rs::extract_conv_id`、
`src/handler/llm/pump/spawn.rs`）。

Anthropic 阻断帧 index 与参数累积清洁（`TRN-6`，`veil-gateway-transport-fidelity`）：阻断帧
使用触发本次阻断的**真实 content block index**（仅无法获知时回退 `0`），多块流中不再错位；
`content_block_start` 的空占位 `input`（`{}`/空串/null）不计入参数累积，避免审计参数出现
`"{}{...}"` 前缀污染，非空完整 `input` 与 `partial_json` 语义不变（见
`src/service/block_inject/frames.rs`、`src/handler/llm/pump/fragments.rs`）。

Responses 断序容忍：流中 `sequence_number` 不连续（跳号/回退）时帧原样透传、不 panic、
不丢帧，终端恰一，不因断序升级为错误日志（见 `src/handler/llm/pump/event.rs::extract_responses_seq`）。

Responses `error` 事件统一为失败终端：流中 `type:"error"` 合成恰一 `response.failed`，
不出现 `response.completed`、无重复终端（见 `src/handler/llm/pump/spawn.rs`）。

Responses 失败帧诊断字段（M2/D5 + `TRN-2`，lossy 边界）：合成 `response.failed.response.error`
兼容上游 error 事件的**两种形态**——官方 `ResponseErrorEvent`（`code`/`message`/`param`/
`sequence_number` 位于**顶层**）与既有嵌套 `error` 对象形态；嵌套字段优先，顶层
`code`/`param`/`message` 仅补缺。`sequence_number` 可得时写入合成 `response.failed`
载荷顶层。缺失 `message`（合并后为空）或 error 非对象时回退既有 `{"id","status"}` 形态；
error 对象中 `type`/`code`/`param`/`message` 之外的其余字段不保留，属已声明 lossy 范围，
下游诊断依赖须以本清单为准（见 `src/handler/llm/pump/event.rs::responses_error_object`、
`src/service/block_inject/frames.rs::responses_failed_frame`）。

空 usage 桶排查指引：观测到某模型空 usage 桶时，先查请求是否显式 `false`
（转发体保留原值即用户放弃流式用量），再判上游异常或采样缺失，不得直接按故障报修。

凭据占位符说明注入门控口径：`__VG_CRED_` 门控要求序号 `\d{6,}`（生产 token 恒 6 位），
窄于 vault 还原侧 `\d{4,}`（兼容历史 4-5 位幻觉形）；4-5 位形态不触发说明注入属**有意保守**
（注入宜漏不宜误，还原侧仍按宽松口径处理，见 `src/service/llm_gateway/placeholder.rs`）。

非流阻断与错误状态声明（E4/E6/D4，`veil-nonstream-audit-align`；N2/D6，`veil-llm-protocol-hardening`）：
非流上游为 **2xx** 且审计命中 `Block` 时，下游恒收 `200 + nonstream_block_body`（与流式恒 200 闭合对称）；
错误状态的 JSON 体（如 400 `truncation:disabled`）仍进完整后处理链
（用量记录＋审计判定＋还原），审计照记（`audit_blocks` 列 + warn 日志），但下游
**不合成阻断体**、状态码与正文保留、非字节等价为有意行为；`status>=400` 的非 JSON
错误体（429 限流文案、500 HTML、404 说明，含空体）原样透传状态码与正文字节，
不再合成 `502 E_EMPTY_BODY`（见 `src/handler/llm/nonstream.rs`）。

非流空体/非 JSON 错误码正面档（`J`，`veil-audit-r4-remediation`）：`E_EMPTY_BODY` 触发于非流对话上游
**非错误状态（`status<400`）**返回空体或非 JSON 体 → 下游 `502`（`src/error.rs:86-97` 的 `code()` 映射与
`:110` 的 `EmptyBody → BAD_GATEWAY`）。错误体的字段形态为 `{"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}}`
（网关级装配见 `src/handler/llm/mod.rs::empty_body_response`；入口级故障如上流未配置亦以同码 `502` 返回，
见 `src/handler/llm/dispatch.rs:150`）。判定先后关系：非流响应体上限（`NONSTREAM_MAX_BYTES`，超限 → `502`
`response_too_large`，见 §4 阈值表）判定**先于**空体/非 JSON 的 `E_EMPTY_BODY` 判定——有界读取先于空体
分类（`src/handler/llm/nonstream.rs:130-161`）；`status>=400` 的错误体不受二者改写，按上段透传语义保留
状态码与正文字节。注意两枚 502 错误体的字段名不同：`E_EMPTY_BODY` 用 `error.code`，超限 `response_too_large`
用 `error.type`（`src/handler/llm/nonstream.rs:582`）。

流式上游错误状态透传（S6/D7，`veil-stream-fidelity-fix`；`TRN-3`/`TRN-4`，`veil-gateway-transport-fidelity`）：
`stream:true` 请求仅在
上游 `status<400` 且响应 `content-type` 为 `text/event-stream` 时进入 SSE 泵；
上游 `status>=400`（4xx/5xx 的 JSON/HTML/空体）或 2xx 非 `text/event-stream`
正文一律按非流口径保状态与正文字节透传（hop 头过滤 + `x-veil-protocol`，受
`NONSTREAM_MAX_BYTES` 约束），不改写为 200 SSE 假流；仅非错误状态（`status<400`）
严格超限走 502 `response_too_large`（见 `src/handler/llm/dispatch.rs::stream_upstream_passthrough`）。
有界读（`TRN-3`）：透传读取先判上游 `content-length`，再按 `NONSTREAM_MAX_BYTES`
有界读，不先全量缓冲；超限 502 **严格作用于非错误状态**，4xx/5xx 错误体不因体大
改写状态或正文（有界读/流式转发仅为内存安全，错误体按透传语义不改写，与 §4
「错误体按透传语义不改写」一致）。内部头隔离（`TRN-4`）：透传前剔除上游所有
`x-veil-*` 内部头（大小写不敏感），网关自置 `x-veil-protocol`/`x-veil-normalized`
在剔除后写入，上游同名声不得覆盖或泄漏。

流式/非流超时口径（`T3`/D3，`veil-transport-fidelity-fix`）：流式（SSE）转发使用
启动期构造的独立 client，**不设**覆盖整响应体读取的总超时，故长流不因
`HTTP_TIMEOUT_SECS`（默认 `30`s）被截断；该 client 当前**不配置读空闲超时**
（默认禁用/无），失活连接依赖 TCP keepalive，如需回收另立 change 交付。
`HTTP_TIMEOUT_SECS` 仅约束非流与 NonDialog 透传路径（保持既有 fail-fast 语义）。
两类 client 均于启动期构造并注入 `AppState`（`http_client`/`http_stream_client`），
请求路径不新建 `reqwest::Client`（见 `src/state.rs::build_stream_http_client`）。

上游重试分类（`T13`/D11，`veil-transport-fidelity-fix`）：**拿头前**（`send()` 返回
`Ok` 之前）的 connect/timeout/请求层瞬断（reqwest `is_connect`/`is_timeout`/`is_request`）
统一退避重试，序列 `0.5s→1s→2s`、最多 3 次（初次 + 3 = 最多 4 次请求）；一旦拿到
响应头（`send()` 返回 `Ok`）即不重试，中段断连按上文「中途断流终端策略」（D6）
fail-closed 收尾。档位硬编码，见 `src/service/llm_gateway/mod.rs::RETRY_DELAYS_MS`
与 `MAX_RETRY_ATTEMPTS`。

非流超限观测口径（`T14`/D12，`veil-transport-fidelity-fix`）：`NONSTREAM_MAX_BYTES`
严格超限（仅 `status<400`）恒返回 502 `response_too_large`，`len == cap` 放行、
`status>=400` 错误体不改写；超限判定先于空体/非 JSON 502 生效。本仓超限分支**无独立
指标与 warning**（与 Python `_llm.py:2936-2946` 的 `metrics_ctx['status']=502` + warning
及无状态门为有意观测差异），差异记录见 change `veil-transport-fidelity-fix` design D12。

### 7.3 请求隔离声明

PII 映射**默认**按请求隔离（`Scope::pii` 请求级容器，请求结束即销毁，跨请求不互见）；
凭据 `vault` 与 PII `detector` 为进程单例只读复用（还原不断链）。口径（与
`src/service/metrics.rs` 模块文档**同字**）：**默认**请求级隔离为隐私硬要求；`PII_SCOPE_MODE=conversation`
显式启用时在**有界、非持久**窗口内允许会话级关联。与原仓差异：原仓 PII 全局复用
（跨请求同明文同 token，prompt-cache 友好但可关联），本仓默认隐私更严，代价是跨请求
prompt-cache 命中率下降，属有意权衡：命中率差异本地不测量（wont-measure）——命中率是上游
provider 侧计费指标，网关侧不可见真值，即使代价未知也不回退默认口径。

会话作用域模式（`PII_SCOPE_MODE=conversation`，默认 `request`，**非 BREAKING**）：显式启用后，
会话键成功推导时同一会话键内的同一明文跨轮铸造同一 token，使发往上游的前缀字节逐轮稳定
（缓存友好）；**凭据仍为请求级授权（B3 不变，见下段），会话级仅承载 PII**。

- 隐私增量（不得隐藏）：启用 `conversation` 后明文在 TTL 窗口（`PII_SCOPE_TTL_SECS`，默认 `1800`s）
  内常驻内存（相对「请求结束即销毁」属回归）；会话内关联可接受（上游 provider 本就关联同一
  上下文轮次）；跨会话隔离保持。
- MUST NOT 承诺清单：不承诺 provider 缓存命中率可测量的提升（wont-measure 保持）、跨会话 token
  稳定性、凭据占位符稳定性、零明文常驻、网关重启后 token 稳定、键推导含糊时的任何行为。
- 前置条件（NB-3，会话级缓存友好**当且仅当**会话键成功推导时成立）：键按四级优先级首个命中者胜——
  ① 客户端显式头 `PII_SCOPE_KEY_HEADER`（默认 `x-veil-conversation-id`，≤256 字节，且经租户命名空间
  + HMAC，原始值绝不作键）；② 协议原生键（Chat/Responses 的 `prompt_cache_key`、Responses 的
  `previous_response_id`）；③ 稳定前缀（**要求 `tools` + `system` + 首个 user turn 三者齐备**，
  对脱敏前规范化前缀做 HMAC）。级别 1/2 依赖客户端配合（显式头 / `prompt_cache_key` /
  `previous_response_id`），级别 3 依赖请求形态齐备。
- 降级行为（NB-3）：**纯多轮 `messages` 请求（无工具、无会话键头、无协议原生键）即便
  `PII_SCOPE_MODE=conversation` 亦落第 4 级逐请求**，不获跨轮 token 稳定；该降级**不报错、
  不伪造键**（缓存失配属预期降级，非缺陷）。
- 模式开关：`PII_SCOPE_MODE` 默认 `request` 即现行为，**非 BREAKING**；`PII_SCOPE_TTL_SECS`
  （默认 `1800`）、`PII_SCOPE_MAX_CONVERSATIONS`（默认 `1024`）、`PII_SCOPE_KEY_HEADER`
  （默认 `x-veil-conversation-id`）为 `conversation` 模式参数；非法值拒启动（fail-closed）。

凭据还原授权收紧（`B3`，`veil-audit-r3-remediation`，**安全修复、非兼容回归**）：响应侧凭据
还原改为**请求级授权**——仅当 token 属「本请求脱敏实际产出」（minted-set，随请求销毁）时才
调用 vault 还原；调用方自带的 `__VG_CRED_<n>__` 字面量现按未授权幻觉 token 剥离（fail-closed），
不再借进程单例的历史映射还原。字面 token 无法还原属**有意收紧**：原行为允许任意调用方以
猜测序号触达历史请求的凭据明文，属安全缺陷修复，不视为兼容回归；依赖该行为的调用方须改由
请求侧真实脱敏产出 token（契约见 canonical `openspec/specs/credential-vault-singleton/spec.md`
「响应侧凭据还原请求级授权」）。

### 7.4 遗留变量兼容表

| 遗留变量 | 状态 | 改用 |
|:---------|:-----|:-----|
| `CREDENTIAL_MASTER_PASSWORD` | 二进制不读取 | 主密码口令改走 TPM 解封（`startup_tpm_in`） |
| `CREDENTIAL_PORT` | 二进制不读取 | 宿主机端口改用 `PORT_8877/8878/8879`（仅改映射） |
| `CREDENTIAL_PROXY_DEBUG_DIR` | 二进制不读取，无四件落盘 | 如需请求落盘排障，用结构化日志 + `AUDIT_POLICY_FILE` 审计面代替；恢复落盘需新 change 交付（落盘即涉密，需配套脱敏） |
| `ENV` | 二进制不读取（置位启动 warn） | dev 环境显式配置 `OBSERVABILITY_ADMIN_TOKEN` 并携带 `X-Admin-Token`（回环免 token 未迁移，见 §6.6） |
| `ALLOW_LOOPBACK_NO_TOKEN` | 二进制不读取（置位启动 warn） | 回环免 token 未迁移：dev 环境显式配置 `OBSERVABILITY_ADMIN_TOKEN` 并携带 `X-Admin-Token`（见 §6.6） |
| `CREDENTIAL_API_PORT` | 二进制不读取（置位启动 warn） | 入口统一走 `VEIL_ENTRY_MODE` + 单端口 `8877`（见 §8.4） |

沿用旧名部署会静默不生效（环境变量全表之外的一律忽略），迁移时必须改名。

### 7.5 吊销与注册鉴权声明

- 写端点鉴权前置（`AUTH-11`，**BREAKING**）：常规吊销 `POST /revoke`、注册 `POST /register-caller`、
  哈希变更 `POST /approve-hash-change` 的三因子守卫在部署未配置部署密钥
  （`GET_BINARY_SECRET`/`CREDENTIAL_SECRET` 均空）时 fail-closed，动作前返回 `403`（`E_AUTH`）；
  迁移须配置非空部署密钥。紧急吊销 `POST /revoke/emergency` 不受此条约束（只认管理 token/内网，见下）。
- 紧急吊销 `POST /revoke/emergency`：仅认两类放行依据——有效管理 token
  （请求体 `admin_token` 或 `X-Admin-Token` 头）与内网来源；服务端
  **不接受任何客户端自证放行字段**（历史自证通道已移除，`AUTH-2`，BREAKING）。
  内网判定只认 TCP 远端地址（`ConnectInfo`），不采信 `X-Forwarded-For` 等代理头
  （防伪造绕过）。未命中两依据时转常规审批，不直接吊销。与常规吊销同注册表定位条目
  （见 `src/handler/credential.rs::emergency_revoke_handler`）。
  管理 token 源为 `OBSERVABILITY_ADMIN_TOKEN`（与 `/_admin` 同一 token，`CRD-7`）；
  `CREDENTIAL_ADMIN_TOKEN` **不再作为紧急吊销放行依据**（**BREAKING**）——仅携带旧
  `CREDENTIAL_ADMIN_TOKEN` 值且来源非内网时转常规审批，不直接吊销。迁移：将
  `OBSERVABILITY_ADMIN_TOKEN` 配置为有效值并与调用方对齐（`src/service/credential/vault_ops.rs:555-561`）。
- 紧急吊销豁免网段（`C13`，`veil-credential-flow-parity`）：内网来源覆盖
  `localhost`/`::1`/`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、
  `169.254.0.0/16`（链路本地）、`100.64.0.0/10`（CGNAT）、`fd00::/8`（ULA）、`fe80::/10`
  （IPv6 链路本地）；命中管理 token 或内网来源两者任一即直接吊销，公网来源转
  常规审批。内网判定只认 TCP 远端（`ConnectInfo`），伪造代理头无效。
- 常规吊销 `POST /revoke`（`C2`，`veil-credential-flow-parity`）：经 Matrix 审批确认后执行——
  建单（`MatrixBranch::Register` 三态映射）后仅 `✅` 置 `revoked=true` 且 `enabled=false`；
  `❎` 与等待超时**保持条目原状**（不做破坏性动作）。默认 `202` 抛单，`CREDENTIAL_BLOCK_WAIT=1`
  阻塞至 `300s`。与紧急吊销旁路（上条两通道）分工：常态吊销走审批，止损走旁路且不建审批单。
- `GET /registrations`：原仓经 `_require_auth` 校验 `GET_BINARY_HASH` + `GET_BINARY_SECRET`（未配置时兼容跳过）；本仓要求管理面鉴权（`X-Admin-Token` 或部署密钥
  `X-Get-Binary-Secret`，见 `src/handler/credential.rs::registrations_handler`），两者皆缺/不匹配 401。
  旧脚本须补凭据；Go `get list` 携带部署密钥可用（有意收敛，见 `observability-admin` spec）。
- 哈希变更 `POST /approve-hash-change`（`C3`，`veil-credential-flow-parity`）：经 Matrix 三态落定——
  `🔓` 保持现有 `allow_mode`（自动放行延续）；`✅` 降级为人工审批模式（`allow_mode` 置 `none` 语义，
  后续取用进入审批）；`❎` 与等待超时置 `enabled=false`（取用被拒绝）。三态均写入旧哈希宽限
  （`old_hash` + `old_hash_expires_at = now + 3600s`）并更新 `script_sha256`。落定入口接受
  `reg_id`/`reaction` 可选入参：`reg_id` 缺省回退 `caller_path`，`reaction` 缺省按保持自动；
  缺省不返回 `400`（仅 `reaction` 非 `🔓/✅/❎` 才 `400`）。
- 旧格式迁移（`C4`，`veil-credential-flow-parity`）：`CALLER_REGISTRY_PATH` 指向 Python 旧格式
  （`version`/`callers`/`allowed_entries` 形态）时，加载期一次性迁移——先备份 `.bak`（备份失败
  拒绝覆盖写，fail-closed），随后以新格式写回并返回内存态；新格式文件直读、不生成 `.bak`、不改写。
  只读挂载下备份失败会拒绝启动（报错指明 `.bak` 原因），调整挂载权限后重启即可，不会损坏旧文件。
- 审批消息内容（`C10`，`veil-credential-flow-parity`）：消息携带可读上下文——原因 + 调用方路径 +
  凭据场景的条目/字段元数据（如 `hash_mismatch :: /s/job.sh :: 网易/授权码`），审批人可判断批什么；
  敏感值（凭据明文、部署 Secret）不落消息，`key` 为 `caller_path:caller_hash`（哈希按既有口径呈现）。

### 7.6 非对话透传声明

- 非对话路径（`Protocol::NonDialog`，如模型列表等非 `chat/messages/responses`
  尾缀）保持字节透传： hop 头过滤后原文转发，不做用量记录、审计判定与
  凭据/PII 还原（与原仓直通语义一致）。
- 入站 query 随 path 一并转发：网关保留请求目标的原始 query 切片（`Uri::query()`），
  按「path + `?` + 原始 query」拼接上游 URL，**保序、保 `%` 编码与 `+` 形态**，
  不重排、不重编码；无 query 时不追加 `?`。该转发**不改写 body**，也不触发
  审计判定与用量记录（与 §5「LLM 代理透传任意 `/{tail}`」口径一致，消除漂移）。
  上游基址自带 query（`?x=y`）时把入站 query 以 `&` 合并到基址 query 之后，不产生双 `?`。
- 每次透传记 `GatewayMetrics.nondialog_passthrough`（流量验证用）；
  若流量验证表明该臂承载对话体需补还原/审计/用量，另立任务跟进。

### 7.7 请求归一化声明（`x-veil-normalized`，注入即声明）

- 下游响应头 `x-veil-normalized: json-whitespace` 当且仅当转发前请求体被重序列化为紧凑 JSON
  时置位；未置位时无此头（不以空值占位）。该头只发下游，不向上游转发。
- 置位条件三选一：① Chat `stream_options` 注入分支（恒经 `to_vec` 重序列化，与配置开关无关，
  无条件置位，见 `src/handler/llm/rewrite.rs`；Responses 不注入，故不因此置位）；② `NORMALIZE_JSON_WHITESPACE=1` 且请求体可解析为
  JSON（紧凑化重序列化）；③ 占位符说明注入分支（经 `to_string` 紧凑重序列化，见 D1 方案 A）。
  纯脱敏替换与原文透传口径：JSON 容器内的脱敏替换经 `json_walk` loads→walk→dumps
  紧凑重序列化（`scope.rs::redact_request`），重序列化即置位 `x-veil-normalized`
  （change `veil-gateway-fidelity-fix`（H1）已落地：`normalized_out` 随实际重序列化置位，不再有缺口）；原文透传（零替换）
  与非 JSON 字节级替换不置位。
- 响应侧字节保真与已知偏离（H1）：响应帧零替换/零命中时逐字节透传，不触发
  `loads→walk→dumps`，键序、数字表示（如 `1e3`）与空白均不改写；必须重序列化
  （响应侧新 PII 掩码）时对象键序保持原序（`serde_json` `preserve_order`），
  但数字表示与空白仍可能被 `serde_json` 规整（已知偏离，如 `1e3` → `1000.0`），
  下游做字节级比对须以此为准。
- 非流两处响应与 SSE 流响应均按同一 `normalized_out` 置位（见 `src/handler/llm/nonstream.rs`、
  `src/handler/llm/pump/event.rs::build_sse_response`，  经 `pump.rs` 与 `handler/llm/mod.rs` 重导出亦可用；D9 互引见 `arch-docs-cleanup` spec（canonical，自 `veil-arch-docs-cleanup` 归档晋升）。

### 7.8 PII 还原超集与残缺清理语义（`veil-pii-parity-closeout`）

- fuzzy 还原超集（`P4`/D5）：`PII_FUZZY_RESTORE`（默认关闭）开启时按序号回查的宽松还原属
  **有意超集**——截断/改写形（大小写漂移等）亦可还原；边界锁定为**仅请求表可还原**，
  响应表 token 与未知序号一律原样保留。开关关闭时仅精确形态还原，口径与既有行为一致。
  fuzzy 还原命中记录独立审计分类计数（`fuzzy`，与 `malformed`/`unregistered` 同管道），
  使超集使用面可观测；生产建议保持默认关闭。
- 残缺占位符剥离为**有意收窄**（`P6`/D7）：仅剥离确证残缺续段（`__PI` + 可选 `I` +
  可选 `_序号` + 可选 hex 段，且后随边界）；无序号 hex 形（如 `__PII_AB`）与后随合法
  单词字符的正文（如 `__PIXEL`/`__PII_DATA`）**不剥**，避免误删用户数据；
  完整 `__PII_<seq>_<rand8>__` 原样保留。

### 7.9 PII_HOLD_MAX 语义映射（`veil-pii-parity-closeout`）

- `PII_HOLD_MAX`（默认 `64`，须 ≥1 正整数）在本仓含义为**响应侧跨帧缝窗字符数**：缝合相邻两帧的
  尾/首窗口做跨缝 PII 检测，跨缝命中后掩码缝两侧再放行上一帧（整帧延迟一级）；检测在 JSON 信封
  过滤后的近似解码文本空间进行并映射回原帧坐标，信封字符（`{ } " [ ]`）逐字符豁免保证 JSON 恒可解析。
  `PII_RESPONSE_SIDE` 关闭时窗口归零，帧按直通语义放行（不做缝窗滞留）。
- 原仓 Python `PII_HOLD_MAX`（同名同默认 `64`）承载的是**审计 hold 尾部持有字符数**；本仓该职责由
  `AUDIT_HOLD_MAX_BYTES`（默认 `1048576` 字节）独立承载。二者维度不同（响应侧缝窗字符 vs 审计 hold 字节），
  不可互相替代；变量名与默认值保持不重命名以规避配置 BREAKING，语义差异以本映射文档吸收。

### 7.10 掩码边缘与别名（`veil-pii-parity-closeout`；`RED-3`，`veil-redaction-audit-coverage`）

- kind 别名集（`P9`/D10 + `RED-3`）：`mask_pii_value` 受理 `bankcard`（等价 `bank_card`）、
  `id_card`（与 `bank_card` 同分支）与 `apikey`（等价 `api_key`），行为与主名逐字一致，
  属已声明兼容超集；别名集以本条登记为准。
- 非 4 段 IPv4 形（`RED-3` 对齐原仓 `_pii.py:1008-1016`）：字符数 `<8` → 首 1/尾 1
  （如 `123456` → `1****6`），`>=8` → 前 4/后 4（如 `12345678` → `1234****5678`）；
  4 段形仍为 `{前}.{二}.**.**`。
- email（`RED-3` 对齐原仓 `_pii.py:989-1002`）：域名含 `.` → `***@***.<suffix>`；含 `@`
  但域名无 `.` → `***@***`（如 `a@b` → `***@***`）；无 `@` 落短值口径。
  其余分支与 64 字符截断上限不变。
- 摘要引擎兜底（`TST-8`，`veil-docs-test-parity`）：管理面事件摘要引擎 `redact_summary`
  对 IPv4（4 段形）、身份证（17 位 + 数字/`X`）、卡号（13-19 位连续数字）三类形态兜底替换为
  `[REDACTED:ipv4]`/`[REDACTED:id_card]`/`[REDACTED:bank_card]`（检出形态与 `sample_mask`
  对应分支同口径）；摘要输出不含三类明文。

### 7.11 Anthropic 扩展思考签名连续性声明（`veil-pii-conversation-cache`）

会话级 token 稳定（`PII_SCOPE_MODE=conversation` 且会话键成功推导，见 §7.3）是 Anthropic 扩展思考
（extended thinking）`signature` 连续性的**必要条件**（非充分条件）。本仓**不**承诺签名连续性——
MUST NOT 声称已实现或已验证。残余限制（四项）：① 网关**不校验**上游签名（`thinking_delta` 文本还原为
明文，`signature` 为对**占位符文本**的 opaque 签名）；② 会话条目淘汰/进程重启后 token 重新铸造；
③ 响应侧新 PII 仍产生新 token；④ 其他 provider 的签名 thinking 不在范围内。

互引（按 requirement 名互指，两处 MUST NOT 漂移）：canonical `openspec/specs/llm-protocol-hardening/spec.md`
的 requirement「Anthropic 扩展思考签名连续性限制声明」为真相源；本仓 `llm-gateway` 的 requirement
「Anthropic thinking 签名连续性（条件性收益与残余限制）」与其显式互引，已随 `veil-audit-r4-remediation`
（2026-09-16 归档）**生效**。

## 8. 遗留决策记录

本节锁定遗留决策与口径，后续 change 不得静默漂移（见 `contract-docs` spec）。

### 8.1 NonDialog 透传（F1，与 P0 联动）

- 非对话路径（`Protocol::NonDialog`）字节透传：hop 头过滤后原文转发，不做用量记录、审计判定与
  凭据/PII 还原，与原仓直通语义一致（细节见 §7.6）。
- 每次透传记 `GatewayMetrics.nondialog_passthrough`（流量验证用）；若该臂承载对话体需补
  还原/审计/用量，另立任务跟进，不扩张本 change 范围。

### 8.2 调试落盘缺失（F2）

- 本仓无请求四件落盘：`CREDENTIAL_PROXY_DEBUG_DIR` 二进制不读取（见 §7.4）。
- 排障代替指引：结构化日志 + `AUDIT_POLICY_FILE` 审计面；恢复落盘需新 change 交付，
  且落盘即涉密、须配套脱敏方案。

### 8.3 Go 对接验证（`veil-hardening` 5.x，已闭环）

- 存量 Go `get` 客户端对接指引见 §5；三项验证均已闭环：`5.1` 存量 Go 直连全链路、`5.2` 三因子
  齐全/缺失两场景、`5.3` 阻断流终止（收到终止帧且无重试挂起）。端到端 runner：
  `scripts/go_interop_e2e.py`（共 14 项、失败 0 项）。

### 8.4 入口与审批语义（F4）

- `VEIL_ENTRY_MODE` 三态：`full`（默认）/ `credential-only` / `llm-only`（另接受
  `credential-proxy-only` / `llm-proxy-only` 别名，非法值拒启动）。
- 非 `full` 入口下 `approve_hash_change` 降级为阻断（返回鉴权失败，不执行哈希变更，
  见 `src/service/credential/vault_ops.rs::approve_hash_change`）。
- Matrix `_ask` 返回 `None` 即 rejected 并清理；审批票回收两口径并存、不得混用（`F16`，`veil-oracle-followup-fix`）：
  **空闲票 60s 回收上限**——无阻塞等待者的孤儿票（审计/解锁类）按分支 TTL `60s` 清扫；
  **有阻塞等待者凭据类票 300s 阻塞 TTL**——凭据/注册/哈希变更类存在阻塞等待者的未决票，
  在其自身 `300s` 阻塞超时前不被回收（`C7`，`veil-credential-flow-parity`）；
  两口径对矩阵侧票与内存侧 `PendingApprovals` 一致适用（`AUTH-9`）。
- 文本指令 `lock`/`forget` 经网关侧清理接线（`C6`，`veil-credential-flow-parity`）：
  `lock` 清口令缓存 + KeePass 会话 + TPM 派生主密码缓存（`AUTH-5`，清除并零化，再次解锁须重新经
  TPM 解封）+ 内存/矩阵 pending；`forget` 清 token 映射并以真实条数回执。
- `AUTO_APPROVE` 三态：`true` 放行 / `false` 拒绝 / `none` 转 Matrix 审批（见 §2）。

### 8.5 测试口径注明（T-M7/T-M9，`veil-review-followup-test-gap`）

- 原仓 `scripts/sentinel_record.py` 在本仓无直接对应脚本，录制回放由 `tests/sentinel_check_tests.rs` + `tests/fixtures/` 回放覆盖（替代关系，非缺失）。
- 本仓真 SDK 一致性口径为脚本 `scripts/api_conformance.py` **24 项（脚本口径，live 实测）**，口径不同非回归缺失（脚本侧覆盖更广，含三协议 SDK 与阻断相）；原仓 `api_spec_conformance` 的 12 项为 **cargo 测试口径**（历史对照，不作为本仓脚本口径标签）。
  **已纳入 gate 步骤**（`veil-test-coverage-fill` T3）：`bash scripts/gate.sh` 第 6 步执行真 SDK 一致性
  （24 项 = 14 常规 + 4 阻断 + 5 取用 + 1 无库 503，由 gate 第 6 步 live 实测登记），第 7 步在 `get/` 内执行 Go 客户端 `go vet ./...`
  与 `go test ./...`，与 fmt/clippy/test/文档路径/文件大小五步串联为七个步骤，任一失败整体非零退出。
  前置条件（第 6 步）：Python venv（默认 `/home/keivry/项目/Python/credential-proxy/.venv/bin/python`，
  可用 `VEIL_CONFORMANCE_PYTHON` 覆盖）与 SDK pin `openai==3.5.0`/`anthropic==1.1.0` + `pykeepass`；
  无 TPM 硬件时脚本内建 `VEIL_ALLOW_MOCK_TPM=1` 回退（仅开发/CI，生产接 TPM 2.0 硬件）。
  前置条件（第 7 步）：本机 Go 工具链，在 `get/` 目录内执行；**Go 版本由 `get/go.mod`（`go 1.22`）
  在 `vet`/`test` 阶段强制**——Go ≥1.21 的 `GOTOOLCHAIN=auto` 会依 `go.mod` 自动选型/下载，
  Go <1.21 时版本指令在 `vet`/`test` 阶段明确报错并非零退出（fail-closed）。gate **SHALL NOT**
  增加版本字符串比较（会把本可成功的环境误判失败）。
  跳过语义：缺前置条件默认显式报错并非零退出；`GATE_SKIP_CONFORMANCE=1`（第 6 步）与
  `GATE_SKIP_GO=1`（第 7 步）为显式跳过并打印跳过理由与文档位置，不出现无输出的静默跳过。

### 8.6 空流三协议语义与原仓差异（P2，`veil-llm-protocol-hardening`）

- 行为：三协议真空流（零字节零残余）均补最小可解析终止——Chat 恰一 `data: [DONE]`
  （传输层终止标记，不伪造 `finish_reason`/内容/usage）；Anthropic 最小
  `message_start`+`message_stop`（空 content、null `stop_reason`、usage 全 0，不含
  `content_block_*`，不声称语义 stop_reason）；Responses 保持恰一 `response.failed` 全序列
  （失败语义，不伪造完成）。`truncated_mode` 口径保留：Chat/Anthropic 记 `open_ended`
  （metrics 观测），Responses 记 `synthesized_failed`——`open_ended` 仅余观测口径，
  不再代表「不发终止帧」。实现见 `src/service/block_inject/frames.rs::empty_stream_frames`
  与 `src/handler/llm/pump/spawn.rs` 空流合成守门；三协议对照由单测
  `vacuum_stream_three_protocol_e2e_comparison` 锁定。
- 与原仓差异：原仓 Python `_ensure_nonempty_stream`（`_llm.py:2633`）对三协议均注入最小可解析
  事件以避免下游 `JSONDecodeError` 空体；本仓现按协议最小面补终止，语义面只补线级终止，
  不伪造内容/usage/成功（Anthropic `error` 本身即终端，其后不注入 `message_stop`）。
- 口径变更声明：本条替换旧「Chat/Anthropic 真空流保持开放结尾」口径；canonical
  `openspec/specs/stream-protocol-parity/spec.md` 与 `openspec/specs/llm-proto-closeout/spec.md`
  的空流条款已在 `veil-audit-r3-remediation` apply 期同步修订（旧条款已删除、迁移声明在位），
  行为真相源以 `openspec/specs/llm-protocol-hardening/spec.md`（canonical）为准。
- 风险：Anthropic 严格 SDK 若要求 `message_delta` 才认流闭合，最小信封可能被拒收；
  以 spec「真空流最小终止」Scenario 为准，实测需要时另立 change 补帧。
- 中途断流与真空流区分（D6，`veil-stream-fidelity-fix`）：真空流（零字节零残余）走本节的
  `empty_stream_frames` 最小终止；中途断流（已发内容帧或有截断信号后异常收尾）走
  「中途断流终端策略」（见 §7.2）——Chat 补恰一 `[DONE]`、Anthropic 仅记 `open_ended`
  不合成 `message_stop`、Responses 已发帧合成恰一 `response.failed`。两路径均保持三协议
  合成终端恒恰一，`truncated_mode` 观测口径保留（Chat/Anthropic `open_ended`、
  Responses `synthesized_failed`）。
