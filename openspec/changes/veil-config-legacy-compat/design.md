## Context

现状（见 proposal.md Why）：`audit_enabled_compat`（`src/service/audit/verdict.rs:49`）已实现，但 `Config::load_from`（`src/config/env_parse.rs:256-473`）只读 `AUDIT_MODE`（`:297-303`），生产零调用；`AUDIT_ENABLED` 也不在 `LEGACY_IGNORED_VARS`（`src/config/validate.rs:16-29`）。Python 侧 `_audit.py:590-605` 仍使 `AUDIT_ENABLED=1` 生效为 block，故当前迁移路径存在静默 fail-open。另四处为 warn/文档缺口（D6/X10/F4/D7），无行为风险。约束：本 change 只写规划 artifacts，不改 `src/`；行为变更仅限 X1 且方向为 fail-closed；不得引入 dead code 中间态；每个修复须行为可验证。

## Goals / Non-Goals

**Goals：**

- 为 X1 拍板「接线 vs 删除」并给出可实施的接线方案（含真值集合、优先级、测试点）。
- 为 warn 清单与 README §7.4 的锁步给出可回归方案，消除 X10 的双处独立维护根因。
- 明确 D7 只动文档的边界，防止把「文档滞后」误修成「改实现收窄真值集合」。

**Non-Goals：**

- 不改 `AUDIT_MODE` 三态语义、`APPROVAL_WHITELIST` 门禁与审计判定本体。
- 不恢复 `ENV=dev` 回环免 token（§6.6 BREAKING 维持）。
- 不输出逐行代码 diff，只定函数边界、取值与测试断言。

## Decisions

### D1：X1 选择「接线回退」而非「删除兼容 + BREAKING 声明」

**决策**：在 `Config::load_from` 中，`AUDIT_MODE` 缺失或空白时调用 `audit_enabled_compat(env)` 作为回退；`Some(_)` 直接采用其返回模式，`None` 仍为 `off`。`AUDIT_MODE` 显式非空时保持现值路径，不调用回退。apply 阶段同时修正 `veil-full-parity-fix` 声称已完成的措辞。

**理由**：

1. 安全方向：Python `_audit.py:590-605` 仍使 `AUDIT_ENABLED=1` 生效为 block；删除兼容等于让存量部署在迁移后静默丢失审计（fail-open），与「迁移不得静默变松」的项目原则相悖。
2. 实现面最小：`audit_enabled_compat` 已存在且已处理优先级，接线只是把生产调用点补上；若删除，则需同步删函数、删测试并改 `veil-full-parity-fix` 规格，改动同样涉及文档但换来安全降级。
3. 显式优先保证新语义可控：`AUDIT_MODE` 一经设置即完全接管，不受 legacy 变量干扰。

**备选**：

- 删除兼容并写入 README §6 BREAKING：文档成本近似，但把存量部署置于静默 fail-open，不可接受，不采用。
- 保留函数但不接线、仅文档标注：制造 dead code 中间态且安全缺口仍在，不采用。

**后果**：行为变严方向（少一处静默丢失审计）；`AUDIT_ENABLED` 成为二进制读取变量，须进 README 环境变量全表；`veil-full-parity-fix` 的 spec/task 措辞须在 apply 阶段修正并保持一致。

### D2：真值集合取 `is_truthy` 同口径（含 `on`），优先级高于「与旧实现同集合」

**决策**：`audit_enabled_compat` 真值集合由 `1/true/yes` 扩为 `1/true/yes/on`（trim + 小写），与 `parse_bool_off`/`is_truthy`（`src/config/validate.rs:47-52`）同口径。

**理由**：同仓布尔开关已接受 `on`（如 `CREDENTIAL_BLOCK_WAIT`）；真值集合多认一个常见写法只会把更多存量部署拉回 block，方向仍 fail-closed，不存在「变松」风险。

**备选**：保持 `1/true/yes`——与同仓 `is_truthy` 不对称，且 `on` 是常见写法，静默 fail-open 面更大，不采用。

### D3：warn 清单与文档锁步以「集合相等」cargo 测试锁定

**决策**：`LEGACY_IGNORED_VARS` 扩至六项并逐项带 hint；README §7.4 拆为逐变量一行；新增两个单测：固定集合断言（`legacy_ignored_vars_set_locked`）与 README 解析集合相等断言（`legacy_vars_readme_lockstep`），随 `cargo test` 门禁执行。

**理由**：X10 根因是清单与文档两处独立维护；把「锁步」变成可回归的测试行为，而非依赖评审记忆。README §7.4 逐变量成行可让解析规则简单、断言集合语义无歧义（合并行「ENV / ALLOW_LOOPBACK_NO_TOKEN」无法直接做集合比较）。

**备选**：扩展 `scripts/check_doc_paths.py` 等外部脚本——需要额外接线与文档说明；放进 `cargo test` 能复用现有门禁，不新增脚本入口，不采用外部脚本方案。

### D4：D7 只改文档，不动 `CREDENTIAL_BLOCK_WAIT` 实现

**决策**：`parse_bool_off` 与 `is_truthy` 保持原样，仅把 README 的「`=1` 时」改为真值集合表述。

**理由**：实现与全仓布尔口径一致且已有 `approval_block_wait_default_off` 测试锁定；文档滞后于实现，若反向收窄实现为「仅 `=1`」将破坏同仓 `is_truthy` 一致性，并可能让存量 `true/yes/on` 配置静默失效。

### Risks

- X1 接线后，存量环境中「误设 `AUDIT_ENABLED` 非空真值」的部署会由 `off` 变为 `block`，可能拦截其本意放行的调用；属 fail-closed 预期收紧，启动 warn 与 README 变量表已提供可发现性，回退方式是显式设置 `AUDIT_MODE=off`。
- README 锁步测试与文档措辞强耦合：§7.4 标题或表格式调整会使其失败；这是有意设计（锁步即约束），修复方式为同步更新测试与清单。
