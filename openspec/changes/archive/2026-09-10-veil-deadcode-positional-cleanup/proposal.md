## Why

六维深度审查（2026-09-10）维度 5（死代码/重复）与维度 1 确认 13 组生产零调用符号 / 残留空码 / 位置性缺陷。全仓 `#[allow(dead_code)]`、`todo!()`、`unimplemented!()` 虽零命中，但下列符号仅测试引用或零引用：

| # | 符号 | 位置 | 引用现状 | 处置 |
|---|---|---|---|---|
| 1 | `CredentialVault::contains_token` | credential_vault.rs:155 | 零引用 | 删 |
| 2 | `CredentialVault::global` | credential_vault.rs:78 | 零引用（仅自引用） | 删 |
| 3 | `CredentialVault::snapshot` + `VaultSnapshot` | credential_vault.rs:126/128/209/217 | 仅模块内测试 389-428 | 删（测试改走生产等价路径）或 `#[cfg(test)]` 收编（`version()` 引用先复核） |
| 4 | `CredentialVault::redact` | credential_vault.rs:164 | 仅 scope.rs:460 测试与 credential_vault.rs 测试 | 删 + 测试改走 `redact_with_map`/`snapshot_p2t` |
| 5 | `has_chat_terminal` | block_inject/terminal.rs:16 | 仅 block_inject.rs:154 测试 | 删 |
| 6 | `should_discard_after_terminal` | block_inject/terminal.rs:61 | 仅 block_inject.rs:238-239 测试 | 删 |
| 7 | `reject_new_dangerous_during_hold` | audit/hold.rs:293 | 仅 hold.rs:511-512 测试（注释「流泵未接线」） | 删 |
| 8 | `AUDIT_TIMEOUT_SECS` | matrix/branch.rs:8 | 仅 approval.rs:271/276/329 测试 | 删或 `#[cfg(test)]` |
| 9 | `placeholder_prompt_enabled`/`normalize_flag_enabled`/`select_request_bytes` | redaction/leaf.rs:20/27/29 | 仅 leaf.rs 测试 255-270（生产走 `Config` 同名方法——勿误伤） | `#[cfg(test)]` 收编 |
| 10 | `loopback_grace` / `observability_disabled` | admin/events.rs:90/102 | 仅测试；后者与 `router.rs:19-31` 生产逻辑重复 | 删；`load_admin_token_file` 保留（README B1.2 声明） |
| 11 | `let effective = ...; let _ = effective;` | credential/auth.rs:199-231 | 非 Allow 臂均提前 return，赋值被丢弃 | 删残留 |
| 12 | `let gateway = NoopApproval; let _ = gateway.request_approval(...)` | credential/approval.rs:28-33 | 结果被丢弃空操作 | 删 |
| 13 | `StreamInjectThen502` + `is_stream` 参数 | llm_gateway/mod.rs:151/173 | 生产唯一调用 `nonstream.rs:139` 恒 `is_stream=false`；仅单测 mod.rs:276-281 触达 | 删变体 + 分支 + 参数，注释指向 `should_synthesize_empty_stream` |
| 14 | `resolve_upstream` 缺省回退 | llm_gateway/mod.rs:189-197 | `HashMap::values().next()` 迭代序不确定 | 端口升序取首 + warn + 测试 |
| 15 | Fast 阈值 `4096` 硬编码 | sse/emit.rs:36 | 未命名常量 | 命名常量 + 注释 |

另：`ENV=dev`/`ALLOW_LOOPBACK_NO_TOKEN` 回环免 token 在 `veil-full-parity-fix` spec 要求「恢复或 BREAKING 声明」，实测生产零实现零声明（仅 events.rs 测试注释）→ **未闭环**：选择 BREAKING 声明（README §6 增 6.6 + §7.4 表行；「五处」→「六处」）。

## What Changes

- **D1 死符号删除（9 组）**：按上表处置 #1-#9。
- **D2 残留空码**：#11 auth.rs 死赋值、#12 approval.rs 丢弃调用。
- **D3 classify_empty 死分支**：#13 删变体与参数；调用与测试同步（四分支→三分支）。
- **D4 resolve_upstream 确定性**：#14。
- **D5 emit 阈值常量**：#15。
- **D6 events 测试辅助清理**：#10。
- **D7 ENV 回环声明闭合**：README §6.6 + §7.4。
- **D8 覆盖登记**：附录记录「已评估无需动作」项（audit_hold 垫片、审批三文件正交、Content-Type 分发、Chat usage 顶层、error 统一、`\d{6,}` 门控、`req_conv` 口径、Go F3 承接、README §8 既有遗留）。

## Capabilities

### New Capabilities

- `deadcode-positional-cleanup`：删除项、确定性修正与声明项的可验证场景。

### Modified Capabilities

- 无。行为变更仅 `resolve_upstream` 缺省序确定化（缺陷修正，patch 级，已由本 change 场景锁定）。

## Non-Goals（显式）

- 不删有生产用途的符号；不动审查已评估项（见附录）。
- 不改协议语义、审计 verdict、阻断帧；不提交 commit。

## Impact

- **新增文件**：本目录文档；测试更新若干。
- **影响系统**：代码面收缩；`resolve_upstream` 缺省路由确定化；README §6/§7.4 文档。
- **顺序**：与其它三 change 无文件冲突（非流面除外：D3 触 `llm_gateway/mod.rs`，与 change2 的 `protocol.rs`/`rewrite.rs` 不同文件）。
- **依赖**：`cargo test`。
