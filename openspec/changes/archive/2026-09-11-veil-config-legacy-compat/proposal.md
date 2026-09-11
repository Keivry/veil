## Why

六维审查确认 `veil-full-parity-fix` 声称已完成的「旧 `AUDIT_ENABLED` 兼容」实际未接线：`audit_enabled_compat`（`src/service/audit/verdict.rs:49`）生产零引用（仅自身测试 `:202/:207`），`Config::load_from`（`src/config/env_parse.rs:256-473`）只读 `AUDIT_MODE`（`:297-303`），`AUDIT_ENABLED` 也不在 `LEGACY_IGNORED_VARS`（`src/config/validate.rs:16-29`）。以 `AUDIT_ENABLED=1` 迁移部署（Python `_audit.py:590-605` 仍使其生效为 block）会静默失去审计，属安全 fail-open。另有四处兼容面缺口：`ENV`/`ALLOW_LOOPBACK_NO_TOKEN` 已在 README §7.4 文档化却不在 warn 清单，置位无提示，与同表另三个 legacy 变量不对称；该清单 3 项与 README §7.4 口径不一致；`CREDENTIAL_API_PORT`（Python `_credential.py:22`、`credential-proxy-only.py:79` 读取）被 Rust 静默忽略且两侧都未声明；`CREDENTIAL_BLOCK_WAIT` 文档写「`=1` 时」而 `parse_bool_off` 实际接受 `1/true/yes/on`。本 change 只做规划：行为变更仅限 X1 的兼容回退（fail-closed 方向），其余为 warn 与文档锁步。

## What Changes

- **修复 1（X1/D1，HIGH，行为）**：`Config::load_from` 在 `AUDIT_MODE` 缺失或空白时回退调用 `audit_enabled_compat`；真值集合 `1/true/yes/on`（trim + 小写）→ `AuditMode::Block`（fail-closed），非真值/空白不生效；`AUDIT_MODE` 显式非空时优先。补 `Config::load_from` 级集成测试与 `audit_enabled_compat` 单测；同步修正 `veil-full-parity-fix` 的 `specs/audit-parity/spec.md:9` 措辞与 `tasks.md:26` 的完成依据（apply 阶段才编辑该 change 文件），README 环境变量全表补 `AUDIT_ENABLED` 行。
- **修复 2（D6/X10/F4，LOW，warn + 文档）**：`LEGACY_IGNORED_VARS` 扩为六项（补 `ENV`、`ALLOW_LOOPBACK_NO_TOKEN`、`CREDENTIAL_API_PORT`），每项带改名指引；README §7.4 逐变量成行并与之锁步，加「集合相等」cargo 测试防单侧漂移。
- **修复 3（D7，LOW，文档）**：README 的 `CREDENTIAL_BLOCK_WAIT` 行把「`=1` 时」改为真值集合 `1/true/yes/on`（trim + 大小写不敏感，默认关闭），与 `parse_bool_off`/`is_truthy`（`src/config/env_parse.rs:423`、`src/config/validate.rs:47-52`）一致。

## Capabilities

### New Capabilities

- `config-legacy-compat`：`AUDIT_ENABLED` 回退语义（fail-closed）、遗留变量 warn 清单完整性与 README §7.4 锁步、`CREDENTIAL_BLOCK_WAIT` 真值集合文档契约。

### Modified Capabilities

- 无。既有 canonical spec 需求不被改写：`contract-docs` 的「Env table is complete」「Legacy decisions recorded」保持成立；本 change 的 warn 清单与 README 锁步作为新增契约承载。

## 发现覆盖表

| 发现 ID | 严重度 | 修复要点 | task 编号 |
|:--------|:-------|:---------|:----------|
| `X1`（同 `D1`） | HIGH | `load_from` 回退 `audit_enabled_compat`（含 `on`），`AUDIT_MODE` 显式优先；集成测试 + 旧规格措辞修正 + README 变量表 | 1.1–1.4, 3.1 |
| `D6` | LOW | `ENV`/`ALLOW_LOOPBACK_NO_TOKEN` 纳入 legacy warn 清单 | 2.1, 2.4 |
| `X10` | LOW | 清单与 README §7.4 名称集合锁步 + 断言集合的单测 | 2.3, 2.4 |
| `F4` | LOW | `CREDENTIAL_API_PORT` legacy warn + README 行（入口统一 rationale 见 §8.4） | 2.2, 2.4, 3.3 |
| `D7` | LOW | `CREDENTIAL_BLOCK_WAIT` 文档改真值集合表述 | 3.2 |

## Non-Goals（显式）

- 不恢复 `ENV=dev` 回环免 token 语义（README §6.6 BREAKING 维持，仅补启动 warn）。
- 不改 `AUDIT_MODE` 三态语义与 `APPROVAL_WHITELIST` 门禁；`AUDIT_ENABLED` 仅作缺失回退，不覆盖显式 `AUDIT_MODE`。
- 不改 `CREDENTIAL_BLOCK_WAIT` 实现（真值集合已符合，仅文档措辞）。
- 不改 `src/` 下任何实现代码；本 change 只交付规划 artifacts，实现留待 apply 阶段。
- 不改 `openspec/changes/veil-full-parity-fix/` 内任何文件（apply 阶段才修正其措辞）；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-config-legacy-compat/` 下 proposal.md、design.md、specs/config-legacy-compat/spec.md、tasks.md；apply 阶段新增/修改 `src/config/env_parse.rs`、`src/config/validate.rs`、`src/service/audit/verdict.rs`、`README.md`，并修正 `veil-full-parity-fix` 两处措辞。
- **影响系统**：启动配置加载（audit 模式 legacy 回退，唯一行为变更且方向为 fail-closed）、遗留变量可观测性（warn）、文档-代码一致性。
- **依赖**：无新增外部依赖；复用既有 `audit_enabled_compat`、`parse_bool_off`/`is_truthy` 与 `legacy_ignored_detected`。
