# audit-rules-parity Specification — delta

## MODIFIED Requirements

### Requirement: 内外网判定偏严声明

系统 SHALL 在审计网络外传判定中把 IP 字面量（含 RFC1918 `10.`/`172.16-31.`/`192.168.`、环回 `127.`/`::1`、链路本地 `169.254.`/`fe80::`）一律视为非内网（可能外传），仅 `localhost`、`.local`/`.internal` 启发式与策略 `internal_suffixes` 显式清单可豁免；无法提取 host（空/`None`）SHALL 视为非内网。默认 `internal_suffixes` SHALL 包含 Python 默认集，至少含 `.corp.example`；未显式配置策略时，该内置默认后缀 SHALL 与其他 `internal_suffixes` 同等豁免。该偏严语义与原仓 Python `is_external_host` 豁免 RFC1918/环回/链路本地不同，SHALL 在 README §6 显式登记为有意差异（BREAKING 声明）。

#### Scenario: RFC1918 目标拦截

- **WHEN** 参数以 `--data` 向 `http://10.x` 或 `http://192.168.x` 外发
- **THEN** 判定命中网络外传（不因 RFC1918 豁免）

#### Scenario: 环回与链路本地字面量拦截

- **WHEN** 参数向 `http://127.0.0.1` 或 `http://169.254.x` 外发
- **THEN** 判定命中网络外传；仅 `localhost` 字面量按内网豁免

#### Scenario: internal_suffixes 显式豁免

- **WHEN** 目标 host 命中策略 `internal_suffixes` 或 `.local`/`.internal`
- **THEN** 网络外传规则不拦截

#### Scenario: 空 host 不豁免

- **WHEN** 网络类命中但无法提取 host（空/`None`）
- **THEN** 按非内网处理（fail-closed 拦截）

#### Scenario: 默认内置 suffix 豁免

- **WHEN** 未显式配置 `internal_suffixes` 且目标 host 命中内置默认后缀（如 `svc.corp.example`）
- **THEN** 判定为内网豁免，不按外传拦截（与 Python 默认一致）

### Requirement: 审计策略文件兼容

系统 SHALL 保留策略文件 fail-closed 语义：`AUDIT_POLICY_FILE` 不可读、含未知键、孤立列表项或非法 `mode` 时 SHALL 拒启动。策略文件顶层 SHALL 同时接受 YAML mapping 与 JSON 对象；顶层为 JSON 对象时 SHALL 与 YAML mapping 同解析（相同键集合与 `dangerous` 对象形），fail-closed 语义不变。`dangerous:` 段 SHALL 同时接受字符串形（`pattern` 或 `pattern => reason`，后缀 `[network]`）与对象形（`pattern`/`reason`/`network` 三字段，YAML mapping 与 JSON 对象），使原仓 Python 策略文件可直接加载或经最小迁移加载；对象形 `network=true` 的命中 SHALL 走外部 host 复核。与原仓「非法策略文件 → 禁用审计并继续」的差异 SHALL 在 README §6 登记。

#### Scenario: 对象形加载

- **WHEN** 策略文件 `dangerous:` 项为 `{pattern, reason, network: true}`
- **THEN** 解析为 `DangerRule` 且命中时执行外部 host 复核

#### Scenario: 旧策略文件迁移

- **WHEN** 加载原仓 Python 形态策略文件（含对象形 dangerous 与既有键）
- **THEN** 加载成功且规则按 `pattern`/`reason`/`network` 生效

#### Scenario: fail-closed 保持

- **WHEN** 策略文件不可读、含未知键、孤儿项或非法 mode
- **THEN** 启动报错退出，不降级为禁用审计

#### Scenario: 顶层 JSON 策略文件加载

- **WHEN** `AUDIT_POLICY_FILE` 顶层为 JSON 对象（如 `{"mode":"block","dangerous":[...]}`）
- **THEN** 策略按与 YAML mapping 相同语义加载生效，未知键/非法值仍按 fail-closed 拒启动
