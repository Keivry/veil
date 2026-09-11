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

| 分组 | 变量 | 默认 | 说明 |
|:-----|:-----|:-----|:-----|
| 认证 | `GET_BINARY_SECRET` / `CREDENTIAL_SECRET` | 空（兼容模式） | 三因子之部署密钥；前者优先 |
| 认证 | `GET_BINARY_HASH` | 空 | 独立生效：置位时拒绝调用方冒用 get 自身哈希的直调（`caller_hash == GET_BINARY_HASH` → 403）；为空时该检查兼容跳过，与 `GET_BINARY_SECRET` 无联动 |
| 认证 | `CREDENTIAL_ADMIN_TOKEN` | 空 | 遗留兼容项；若设置须与 `OBSERVABILITY_ADMIN_TOKEN` 不同 |
| 认证 | `AUTO_APPROVE` | `true` | `true` 放行 / `false` 拒绝 / `none` 转 Matrix 审批 |
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
| 脱敏 | `PII_CUSTOM_RULES_FILE` / `PII_RULES_FILE` / `PII_CUSTOM_RULES` | 空 | 自定义正则文件（合并文件，可与分离文件叠加；优先级按列序）；格式 JSON / 极简 YAML（`.yaml`）/ TXT 名单；已配置但缺文件/不可读/解析失败/形态非法一律拒启动，空文件仅 warn（见 `examples/pii-custom.yaml`） |
| 脱敏 | `PII_CUSTOM_PATTERNS_FILE` / `PII_CUSTOM_PATTERN_FILE` / `PII_CUSTOM_PATTERNS` | 空 | 同上（数组或 `{name: pattern}` 映射） |
| 脱敏 | `PII_CUSTOM_DICT_FILE` / `PII_DICT_FILE` / `PII_SENSITIVE_DICT_FILE` / `PII_SENSITIVE_NAMES_FILE` / `PII_CUSTOM_DICT` | 空 | 同上（字典形态；TXT 每行一名，`#` 注释忽略）；各名等价加载，列序即优先级（`PII_DICT_FILE` 相对 Python 历史名优先，与原仓一致） |
| 脱敏 | `PII_VALUE_SAMPLE_ENABLED` | 关闭 | 值级采样总开关 |
| 脱敏 | `PII_VALUE_SAMPLE_PERSIST` | 开启 | 值级采样落盘 |
| 脱敏 | `PII_VALUE_SAMPLE_HMAC_KEY` | 空 | 未设退化为 SHA256 |
| 脱敏 | `PII_PLACEHOLDER_PROMPT` | 开启 | 占位符说明注入；`0/false/no/off` 关闭 |
| 脱敏 | `PII_PLACEHOLDER_PROMPT_TEXT` | 内建默认 | 自定义文案（4KB 上限，超限截断；含合法占位符形态回退默认） |
| 脱敏 | `PII_HOLD_MAX` | `64` | PII 保持上限（须 ≥1 正整数） |
| 脱敏 | `NORMALIZE_JSON_WHITESPACE` | 关闭 | 仅 `"1"` 开启请求体空白归一 |
| 审计 | `AUDIT_MODE` | `off` | `off` / `block` / `approve`；`approve` 必须配 `APPROVAL_WHITELIST` |
| 审计 | `AUDIT_ENABLED` | 空 | 遗留回退：`AUDIT_MODE` 缺失/空白时真值 `1/true/yes/on`（trim + 大小写不敏感）→ `block`（fail-closed），显式 `AUDIT_MODE` 优先，缺省仍 `off` |
| 审计 | `AUDIT_TIMEOUT` | `90`s | 禁止落在 `110`-`130`s 竞态区间，否则拒启动 |
| 审计 | `AUDIT_HOLD_MAX_BYTES` | `1048576` | 审计 hold 上限字节（须 ≥1 正整数） |
| 审计 | `AUDIT_POLICY_FILE` | 内建默认策略 | 审计策略文件路径 |
| 审计 | `APPROVAL_WHITELIST` | 空 | 审批人 Matrix ID 逗号分隔（`@user:server`） |
| TPM | `VEIL_ALLOW_MOCK_TPM` | 未设置（硬件强制） | 仅 `=1` 放行 Mock TPM，专供无硬件开发机与 CI；生产禁用（见下方指引） |
| TPM | （硬编码）TPM 子进程单步超时 | `30s` | `tpm2_createprimary/load/unseal` 单步上限；存活探测走 `tpm2_pcrread sha256:0` 只读 PCR（不预演密封回放，差异有意，见 `src/service/tpm.rs`） |
| LLM | `LLM_UPSTREAM` | 空 | 缺省上游 URL；`scripts/api_conformance.py` 将其指向 mock 上游 |
| LLM | `LLM_<port>`（如 `LLM_8878`/`LLM_8879`） | 见 compose | 按宿主机入口端口选择上游 |
| LLM | `HTTP_TIMEOUT_SECS` | `30` | 上游转发整体超时（秒） |
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

### Mock TPM 指引（仅开发，生产禁用）

- 无 TPM 硬件的开发机/CI：设置 `VEIL_ALLOW_MOCK_TPM=1`（精确等于 `1` 才放行，其余值仍走硬件门禁 fail-closed），
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
- 无 TPM 硬件时：注释掉 `docker-compose.yml` 中 `devices` 两行，并设置 `VEIL_ALLOW_MOCK_TPM=1`（仅开发）。

### 健康检查（新人可执行）

```bash
# 存活探针（无需鉴权）
curl -fsS http://127.0.0.1:8877/health
# 期望（含超集字段 status/unlocked/pending/llm_secrets，向后兼容只增不减）：
# {"ok":true,"sqlite_ok":true,"sqlite_error":null,"status":"ok","unlocked":true,"pending":0,"llm_secrets":0}

# 管理面探针（需 X-Admin-Token）
curl -fsS -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" http://127.0.0.1:8877/_admin/health
# 期望：{"ok":true,"sqlite_ok":true,"sqlite_error":null}
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

- 服务端未配置对应调用方期望哈希（未 enrolled）时兼容放行，但 Secret 仍校验。
- `caller_hash == GET_BINARY_HASH`（终端直调而非脚本调用）拒绝 403。
- 自动放行三态：`True` 放行 / `False` 拒绝 / `None` 转 Matrix 审批（哈希不一致走 `None` 分支）。
- 管理面鉴权优先级：`X-Admin-Token` 头 > `__Host-admin_token` Cookie > `?access_token`（仅 SSE 回退）；
  非 SSE 接口以 query 携带 token 恒 401。

## 3. 限流规则

- 通用 admin 接口按源 IP 限流 `10/min`，超限返回 `429` 并携带 `Retry-After` 头（头名大小写不敏感， wire 形态为小写 `retry-after`）。
- `/_admin/health` 豁免通用 `10/min` 限流（存活探针高频；豁免集为
  `src/service/admin/ratelimit.rs::admin_rate_exempt_paths()` 唯一项），health 请求不占通用限流桶。
- `/_admin/events/stream` 按 IP 限制并发 `5`，超限拒绝新连接而不影响已建连接；
  保活 `60s` ping，`5min` 服务端强制重连。
- `10/min` 为速率维度、`5`/IP 为并发维度，两者正交且均为有意设计。
- 限流计数按 TCP 远端地址（不采信 `X-Forwarded-For` 等代理头，防伪造绕过）；
  经反代访问时所有客户端共享反代地址的同一限流桶。

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
| 非流对话响应上限 | `NONSTREAM_MAX_BYTES` 默认 `8MB` | `502` + `response_too_large` JSON 体 | 是（入口 enforcement） | 对话尾缀（chat/completions、v1/messages、v1/responses）响应体严格超限；`Protocol::NonDialog` 透传不受限；与审计 ceiling `AUDIT_SUBLIMIT_CEILING_BYTES`（子限锚点、非入口 enforcement）分属不同检查点，不可互相替代 |
| 审计类上限 | `8MB` | — | 否（纯 ceiling 锚点） | 策略子限 ceiling（`AUDIT_SUBLIMIT_CEILING_BYTES` 回归锚点：现网可配子限如 `AUDIT_HOLD_MAX_BYTES` 默认 1MB 均不得超过它）；与入口 `10MB` 属不同检查点、差异有意 |
| 审计日志轮转 | `10MB` x 5，`0600` | 写失败双层 fail-closed | 先脱敏后截断，零明文 |
| 审批超时 | `AUDIT_TIMEOUT` 默认 `90`s | — | 禁止落在 `110`-`130`s 竞态区间 |
| 凭据审批超时 | `300`s | — | 与审计 `AUDIT_TIMEOUT` 分表 |

### 4.1 内部常量附录（未列即内部实现细节）

附录为可审计登记，不构成外部契约；未列出的常量均属内部实现细节，变更不视为 BREAKING。

| 符号 | 取值 | 来源 |
|:-----|:-----|:-----|
| `CREDENTIAL_RATE_WINDOW_SECS` | `2` | `src/config/env_parse.rs` |
| `REGISTER_RATE_WINDOW_SECS` | `1` | `src/config/env_parse.rs` |
| `PENDING_TTL_SECS` | `60` | `src/approval.rs` |
| `OLD_HASH_GRACE_SECS` | `3600` | `src/registry.rs` |
| `RateTable::MAX_ENTRIES` | `4096` | `src/service/credential/ratelimit.rs` |
| `RateTable::SWEEP_LEN` | `1000` | `src/service/credential/ratelimit.rs` |
| `RateTable::SWEEP_SECS` | `60` | `src/service/credential/ratelimit.rs` |
| `LINE_LIMIT_BYTES` | `16KiB` | `src/config/env_parse.rs` |
| `EVENT_IDLE_TIMEOUT` | `30s` | `src/config/env_parse.rs` |
| `KEEPALIVE_INTERVAL` | `10s` | `src/config/env_parse.rs` |
| `RING_CAP` | `10000` | `src/service/metrics/aggregate.rs` |

## 5. Go 客户端对接指引

存量 Go `get` 客户端无需修改即可对接：网关保持其所用路径与方法不变
（凭据审批默认 `202` 的例外与 Go 处理结论见本节末条）。

| 用途 | 方法与路径 | 鉴权 |
|:-----|:-----------|:-----|
| 取用凭据 | `POST /credential` | 三因子（`X-Get-Binary-Hash` + `X-Get-Binary-Secret`/`body.secret` + `body.auth.caller_hash`/`caller_path`） |
| 查看注册 | `GET /registrations` | 管理面鉴权（`X-Admin-Token` 或部署密钥 `X-Get-Binary-Secret`；两者皆缺/不匹配 401；原仓无鉴权直读，旧脚本须补凭据，Go `get list` 经部署密钥可用） |
| 注册调用方 | `POST /register-caller` | 三因子（同取用；重名 409） |
| 吊销注册 | `POST /revoke`，紧急吊销 `POST /revoke/emergency` | 常规三因子；紧急吊销管理 token/文件在位/内网三者任一（见 7.5） |
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

- 三因子字段：`X-Get-Binary-Hash` + `X-Get-Binary-Secret`（或 `body.secret`）+ `body.auth.caller_hash` /
  `caller_path`；齐全时按既有语义放行或进入审批，缺失时返回明确的鉴权失败（403），不会空响应或挂起。
- 凭据审批 `202` 轮询语义：默认（`CREDENTIAL_BLOCK_WAIT` 未设或非真值）待审请求返回
  `202 + E_PENDING` 即已建单，客户端应对同一请求轮询重试（建议指数退避），批准后重试返回凭据、
  拒绝后 `403`；`CREDENTIAL_BLOCK_WAIT=1` 时无需轮询（同请求阻塞等待，批准返回凭据、拒绝/超时 `403`）。
- Go `202` 处理结论（`get/internal/proxy.go`）：Go `CredentialResponse` 已容忍网关错误体对象
  （`ErrMessage`：`{"error":{"code","message"}}` 取 `message`、兼容 Python 字符串错误体）与
  `/credential` 成功信封 `{"ok":true,"credential":{...}}`；`202` 体 `{"error":{"code":"E_PENDING",...}}`
  不再报「解析响应失败」。但 `FetchCredential` 仅在 `status >= 400` 报错且不向上层暴露 HTTP 状态码，
  故 `get credential` CLI 对 `202` 仍走成功分支（不打印 `E_PENDING`）；**端到端轮询需调用方在收到
  `202` 后自行重试，或部署侧用 `CREDENTIAL_BLOCK_WAIT=1` 走同请求阻塞**（见 `veil-hardening` 5.2 已闭环）。
- SSE 语义对 Go 透明：被审计阻断的流恒以终止帧闭合，客户端视为正常结束，不重试、不挂起。

## 6. 行为变更（BREAKING）与迁移

下述六处为相对原仓（Python `credential-proxy`）已发生的默认值与语义漂移，现显式为 BREAKING；
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

### 6.4 流式审批挂起声明（原仓同步阻塞）

- 变更：`AUDIT_MODE=approve` 下流式网关危险调用转 pending 记录，不阻塞流、不合成阻断帧，
  不挂起等待真人 `✅/❎`；拒绝/过期语义由凭据审批链承载。原仓在流中挂起等待 Matrix 审批
 （`keepalive` + 超时默认拒绝并注入阻断帧）。
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
  `202` + `E_PENDING`（已建单 + best-effort 发送审批即返回），同一请求不阻塞；原仓 Python 为同一请求内
  同步阻塞 `300`s（批准返回凭据、拒绝 `403`、超时 `408`，`_credential.py:26,433,455`）。
- 轮询语义：`202 + E_PENDING` = 已建单等待 Matrix 人工审批；客户端应轮询重试同一请求
  （建议指数退避），批准后重试返回凭据、拒绝后 `403`。
- 迁移：恢复 Python 式同步阻塞请设 `CREDENTIAL_BLOCK_WAIT=1`（真值集合 `1/true/yes/on`）：
  `300`s 内批准同请求返回凭据、拒绝 `403`、超时按拒绝返回 `403` 且不悬挂。
- 影响：不识别 `202` 的旧客户端须补轮询；Go 存量 `get` 已能解析 `202 + E_PENDING` 错误体
  （`ErrMessage`，见 §5），但 CLI 不自动轮询——轮询由调用方实现，或用 `CREDENTIAL_BLOCK_WAIT=1` 阻塞；
  恢复旧默认须新 change 并撤回本条。

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
Responses **不注入** `stream_options`（官方规范仅接受 `include_obfuscation`，无
`include_usage`；决策依据与回退条款见 change `veil-llm-proto-closeout` 的 design.md D1/R1），其流式用量一律经
`response.completed.response.usage` 三级回退记录，用户自带键逐字节保留。

Chat 无 `[DONE]` 收尾处理：上游以非 null `finish_reason` 结束后断流、从未发 `data: [DONE]`
时，网关在流结束处补发恰一 `data: [DONE]` 并置终端（`finish_reason` 后到达的 usage
尾帧照常透传不丢），同时保留 `truncated_mode=open_ended` 与 warn/指标观测
（见 `src/handler/llm/pump/spawn.rs`）；上游已发 `[DONE]` 时不重复补发。

Responses 断序容忍：流中 `sequence_number` 不连续（跳号/回退）时帧原样透传、不 panic、
不丢帧，终端恰一，不因断序升级为错误日志（见 `src/handler/llm/pump/event.rs::extract_responses_seq`）。

Responses `error` 事件统一为失败终端：流中 `type:"error"` 合成恰一 `response.failed`，
不出现 `response.completed`、无重复终端（见 `src/handler/llm/pump/spawn.rs`）。

Responses 失败帧诊断字段（M2/D5，lossy 边界）：合成 `response.failed.response.error`
保留上游 error 对象中存在的 `type`/`code`/`param`/`message` 四字段（缺失 `message`
或 error 非对象时回退既有 `{"id","status"}` 形态）；error 对象中这四字段之外的其余
字段不保留，属已声明 lossy 范围，下游诊断依赖须以本清单为准。

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

### 7.3 请求隔离声明

PII 映射按请求隔离（`Scope::pii` 请求级容器，请求结束即销毁，跨请求不互见）；
凭据 `vault` 与 PII `detector` 为进程单例只读复用（还原不断链）。与原仓差异：
原仓 PII 全局复用（跨请求同明文同 token，prompt-cache 友好但可关联），本仓隐私更严，
代价是跨请求 prompt-cache 命中率下降，属有意权衡：命中率差异本地不测量（wont-measure）——
命中率是上游 provider 侧计费指标，网关侧不可见真值，且请求隔离是隐私硬要求
（见 `src/service/metrics.rs` 模块文档）。

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

- 紧急吊销 `POST /revoke/emergency`：入参含 `file_present` 文件在位标记，
  管理 token 可走请求体或 `X-Admin-Token` 头；内网判定只认 TCP 远端地址
  （`ConnectInfo`），不采信 `X-Forwarded-For` 等代理头（防伪造绕过）。
  与常规吊销同注册表定位条目（见 `src/handler/credential.rs::emergency_revoke_handler`）。
- `GET /registrations`：原仓无鉴权直读；本仓要求管理面鉴权（`X-Admin-Token` 或部署密钥
  `X-Get-Binary-Secret`，见 `src/handler/credential.rs::registrations_handler`），两者皆缺/不匹配 401。
  旧脚本直读须补凭据；Go `get list` 携带部署密钥可用（有意收敛，见 `observability-admin` spec）。

### 7.6 非对话透传声明

- 非对话路径（`Protocol::NonDialog`，如模型列表等非 `chat/messages/responses`
  尾缀）保持字节透传： hop 头过滤后原文转发，不做用量记录、审计判定与
  凭据/PII 还原（与原仓直通语义一致）。
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
  `src/handler/llm/pump/event.rs::build_sse_response`，经 `pump.rs` 与 `handler/llm/mod.rs` 重导出亦可用；D9 互引见 `arch-docs-cleanup` spec（canonical，自 `veil-arch-docs-cleanup` 归档晋升）。

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
- Matrix `_ask` 返回 `None` 即 rejected 并清理；孤儿 pending 由 `60s` 清扫任务回收。
- `AUTO_APPROVE` 三态：`true` 放行 / `false` 拒绝 / `none` 转 Matrix 审批（见 §2）。

### 8.5 测试口径注明（T-M7/T-M9，`veil-review-followup-test-gap`）

- 原仓 `scripts/sentinel_record.py` 在本仓无直接对应脚本，录制回放由 `tests/sentinel_check_tests.rs` + `tests/fixtures/` 回放覆盖（替代关系，非缺失）。
- 原仓 `api_spec_conformance` 12 项（cargo）vs 本仓 `scripts/api_conformance.py` 20 项（脚本），口径不同非回归缺失（脚本侧覆盖更广，含三协议 SDK 与阻断相）。
  **已纳入 gate 步骤**（`veil-test-coverage-fill` T3）：`bash scripts/gate.sh` 第 6 步执行真 SDK 一致性
  （20 项 = 11 常规 + 3 阻断 + 5 取用 + 1 无库 503），与 fmt/clippy/test/文档路径/文件大小五步串联，任一失败整体非零退出。
  前置条件：Python venv（默认 `/home/keivry/项目/Python/credential-proxy/.venv/bin/python`，
  可用 `VEIL_CONFORMANCE_PYTHON` 覆盖）与 SDK pin `openai==3.5.0`/`anthropic==1.1.0` + `pykeepass`；
  无 TPM 硬件时脚本内建 `VEIL_ALLOW_MOCK_TPM=1` 回退（仅开发/CI，生产接 TPM 2.0 硬件）。
  跳过语义：缺前置条件默认显式报错并非零退出；`GATE_SKIP_CONFORMANCE=1` 为显式跳过
  （打印跳过理由与文档位置），不出现无输出的静默跳过。

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
- 口径变更声明：本条替换旧「Chat/Anthropic 真空流保持 open-ended」口径；既有
  `stream-protocol-parity` spec 的空流条款待随本 change 归档时同步修订，
  行为真相源以 `openspec/specs/llm-protocol-hardening/spec.md`（canonical，该 change 已归档）为准。
- 风险：Anthropic 严格 SDK 若要求 `message_delta` 才认流闭合，最小信封可能被拒收；
  以 spec「真空流最小终止」Scenario 为准，实测需要时另立 change 补帧。
