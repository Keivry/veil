## 1. 写端点三因子鉴权（`AUTH-1`/`AUTH-3`）

- [x] 1.1 `src/handler/credential.rs`：抽出与 `credential_handler` 同源的异步三因子核验守卫（`X-Get-Binary-Hash` + `X-Get-Binary-Secret`/`body.secret` + `body.auth.caller_hash`/`caller_path`），`approve_hash_change_handler` 增加 `HeaderMap` 与 `auth` 解析并接线，未鉴权返回 `401`/`403` 且不调用 `service::approve_hash_change`
  - 验证：`cargo test -p veil approve_hash_change_requires_three_factor` 通过；无三因子头/字段时错误码为 `E_AUTH`/`E_UNAUTHORIZED` 且注册表 `expected_hash` 未变
  - 验证：`grep -n "credential_headers\|HeaderMap" src/handler/credential.rs` 命中 `approve_hash_change_handler` 签名与守卫调用点
- [x] 1.2 `src/handler/credential.rs`：`register_caller_handler`（`:100-148`）与 `revoke_handler`（`:174-180`）接入同一三因子守卫，动作前失败即返回；鉴权通过保留既有 `service::register_caller_with_approval`/`revoke_caller_with_approval` 审批语义
  - 验证：`cargo test -p veil register_caller_requires_three_factor` 与 `cargo test -p veil revoke_requires_three_factor` 通过；无鉴权时动作未触发
  - 验证：`grep -n "register_caller_with_approval\|revoke_caller_with_approval" src/handler/credential.rs` 命中调用点仍在鉴权之后
- [x] 1.3 `src/router.rs:193-202`：把无鉴权头断言 200 的错误期望改为鉴权拒绝，并补三条端到端回归（`/approve-hash-change`、`/register-caller`、`/revoke` 未鉴权 → 401/403）
  - 验证：`cargo test -p veil router_credential_write_endpoints_require_auth` 通过；三端点未鉴权均非 2xx
  - 验证：`cargo test -p veil --test http_e2e_credential` 全绿（鉴权通过路径行为不变）

## 2. 紧急吊销去客户端自证（`AUTH-2`）

- [x] 2.1 `src/handler/credential.rs:182-224` 删除 `EmergencyRevokeBody.file_present`（`:193`）与下传（`:220`）；`src/service/credential/vault_ops.rs:425-459` 删除 `file_present` 形参及 `:440` 判据，保留 `admin_ok`/`net_ok` 两通道，未命中转常规审批
  - 验证：`cargo test -p veil emergency_revoke_forged_file_present_rejected` 通过；公网来源 + `{"file_present":true}` 返回 `202` 且条目未吊销
  - 验证：`grep -rn "file_present" src/` 无命中（handler 与 service 均清除）
- [x] 2.2 回归：admin token 与内网两通道仍直接吊销；伪造 `X-Forwarded-For` 不改变 TCP 远端判定
  - 验证：`cargo test -p veil emergency_revoke_network_ranges`、`cargo test -p veil forged_proxy_headers_do_not_bypass_revoke_check` 通过
  - 验证：`cargo test -p veil emergency_revoke_admin_token_only` 通过；有效管理 token 直接吊销、不建单
- [x] 2.3 README §7.5 同步：紧急吊销通道由「管理 token/文件在位/内网」改为「管理 token/内网」，移除 `file_present` 入参说明
  - 验证：`grep -n "file_present" README.md` 无命中；`grep -n "紧急吊销" README.md` 命中两通道表述
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0

## 3. 未 enrolled 默认转审批（`AUTH-4`）

- [x] 3.1 `src/service/credential/auth.rs:239-243,257-274`：未匹配任何注册条目时置 `unenrolled` 标记，限流通过后由前置检查统一转审批——`AUTO_APPROVE=Deny` 时拒绝，其余（含默认 `Allow`）走 `unenrolled_default_pending`；自动放行仅对已注册条目的 `decision` 分支生效
  - 验证：`cargo test -p veil unenrolled_defaults_to_pending` 通过；未注册且未显式配置时返回 `202 + E_PENDING` 或拒绝，不返回凭据
  - 验证：`cargo test -p veil enrolled_explicit_allow_still_passes` 通过；已注册且显式放行行为不变
- [x] 3.2 README §2 同步：删除「未 enrolled 兼容放行」表述，声明默认转审批与 BREAKING 迁移
  - 验证：`grep -n "未 enrolled\|未配置对应调用方" README.md` 命中新审批口径；无「兼容放行」残留
  - 验证：`cargo test -p veil --test http_e2e_credential` 全绿（已注册路径无回退）

## 4. lock 清除 TPM 派生主密码缓存（`AUTH-5`）

- [x] 4.1 为 TPM 主密码缓存引入可清理句柄（`src/keepass.rs:110-133` 的 `tpm_password_provider` 暴露清理点，或缓存移入 `RealKeePass` 可 `clear_cache` 触及处），`src/state.rs:189-195` 的 `lock_cleanup` 调用清理并零化
  - 验证：`cargo test -p veil lock_clears_master_password_cache` 通过；`lock` 后主密码缓存为空、凭据取用因未解锁被拒
  - 验证：`grep -n "clear_master\|fn clear_cache" src/keepass.rs src/state.rs` 命中清理点与调用
- [x] 4.2 回归：`lock` 后再次 `unlock` 经 TPM 重新解封成功、取用恢复；既有 lock 清理（口令缓存/KeePass 会话/pending）不回退
  - 验证：`cargo test -p veil unlock_after_lock_rederives_via_tpm` 通过
  - 验证：`cargo test -p veil --test http_e2e_credential` 与 `cargo test -p veil lock_cleanup_clears_vault` 全绿
- [x] 4.3 README §8.4 同步：`lock` 清理清单补「TPM 派生主密码缓存」
  - 验证：`grep -n "lock" README.md` 命中主密码缓存清理表述
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0

## 5. 注册审批发送失败原子回滚（`AUTH-6`）

- [x] 5.1 `src/service/credential/vault_ops.rs:272-311`：`submit_pending_with_branch` 失败（发送失败/取不到真实 `event_id`）时回滚已落条目，使注册表无孤儿；回滚方式与 D6 复用语义对齐（删除条目或软吊销 + 允许复用）
  - 验证：`cargo test -p veil register_send_failure_rolls_back_entry` 通过；失败后注册表无该条目残留
  - 验证：`cargo test -p veil register_can_retry_after_send_failure` 通过；同一 `caller_path` 可再次发起注册
- [x] 5.2 回归：发送成功路径三态落定行为不变；失败注入不误伤其它条目
  - 验证：`cargo test -p veil --test http_e2e_credential` 全绿
  - 验证：`cargo test -p veil register_send_success_still_pending_or_activates` 通过

## 6. 吊销后 caller_path 复用语义（`AUTH-7`）

- [x] 6.1 `src/registry/store.rs:293-303`：路径判重改为仅对未吊销条目拒绝，已吊销 `caller_path` 允许重新注册；新条目全新初始化（`enabled=false`、`revoked=false`、`old_hash` 宽限清空）
  - 验证：`cargo test -p veil revoked_caller_path_can_reregister` 通过；吊销后同路径注册成功进入审批
  - 验证：`cargo test -p veil reregister_clears_old_hash_grace` 通过；新条目无旧哈希宽限
- [x] 6.2 回归：未吊销重名/重路径仍 `409`；`name` 释放语义不回退
  - 验证：`cargo test -p veil duplicate_path_conflicts_409_same_hash_multi_path_allowed`、`cargo test -p veil register_extended_rejects_duplicate_unrevoked_name` 通过
  - 验证：`cargo test -p veil --test http_e2e_credential` 全绿

## 7. KeePass 500 对外脱敏（`AUTH-8`）

- [x] 7.1 `src/error.rs:129-148`：`VeilError::KeePass` 的 `public_message` 改为固定通用文案（不携带 `message`），错误码保留 `E_KEEPASS`（或归并 `E_INTERNAL`）；完整细节仅 `tracing::error!`
  - 验证：`cargo test -p veil keepass_error_public_message_is_generic` 通过；响应体不含 KDBX 路径/异常细节
  - 验证：`grep -n "KeePass" src/error.rs` 命中脱敏分支且无 `message.clone()` 回传
- [x] 7.2 回归：500 仍记 error 日志（细节可排障）、状态码仍 500、其它错误变体文案不变
  - 验证：`cargo test -p veil error_response_body_carries_code` 与 `cargo test -p veil four_xx_logs_warn_five_xx_logs_error` 通过
  - 验证：`cargo test -p veil keepass_internal_error_logged_not_exposed` 通过

## 8. 审批票 TTL 口径单一来源（`AUTH-9`）

- [x] 8.1 `src/approval.rs:52,84-98` 与 `src/service/credential/approval.rs:152-171`：令 60s 空闲清扫对「有活跃 waiter / 凭据阻塞类」记录豁免（或凭据类 pending 不入 60s 清扫表、由 `DecisionTable` 的 `InFlight` 承载），凭据类阻塞票保留至 `300s`
  - 验证：`cargo test -p veil credential_pending_survives_past_idle_ttl` 通过；等待未超 `300s` 时票不被 60s 回收
  - 验证：`cargo test -p veil idle_orphan_swept_at_60s` 通过；无等待者孤儿票 60s 回收、内存有界
- [x] 8.2 回归：`GET /health pending` 计数与终态即时归零口径不变；`DecisionTable` 容量上界（4096）行为不变
  - 验证：`cargo test -p veil pending_count_zeroes_on_terminal_state` 通过
  - 验证：`cargo test -p veil decision_table_capacity_bounded` 通过
- [x] 8.3 README §4/§8.4 同步：60s 空闲票与 300s 凭据阻塞票两口径与实现一致，消除「声明 300s、实现 60s 回收」矛盾
  - 验证：`grep -n "60s 回收上限\|300s 阻塞 TTL" README.md` 命中两口径；`grep -n "PENDING_TTL_SECS" README.md` 命中登记值 `60`
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0

## 9. allow_mode 接受 auto/manual（`AUTH-10`）

- [x] 9.1 `src/service/credential/register_map.rs:116-133`：在既有三态别名外接受 `auto`→`Allow`、`manual`→`Pending`；未知非空值保持兼容回退并补 `warn` 日志
  - 验证：`cargo test -p veil register_allow_mode_accepts_auto_and_manual` 通过；`auto`→放行、`manual`→审批
  - 验证：`cargo test -p veil register_map_allow_mode_invalid_falls_back_to_auto` 仍通过（未知值行为不回退）
- [x] 9.2 回归：Go 请求形态（`allow_mode:"auto"` + `auto:true`）落定生效；README §5 Go 对接列同步
  - 验证：`cargo test -p veil register_handler_auto_mode_effective` 通过；条目放行模式为自动放行
  - 验证：`grep -n "allow_mode\|--auto" README.md` 命中 `auto`/`manual` 契约说明

## 10. 门禁与归档准备

- [x] 10.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
  - 验证：`cargo test -p veil` 输出 0 failed
- [x] 10.2 `python3 scripts/check_doc_paths.py` 退出 0（README 与 spec 引用路径全部存在）
  - 验证：命令输出 `OK`，无 FAIL 项
  - 验证：`bash scripts/gate.sh` 文档路径步骤通过
- [x] 10.3 `openspec validate veil-credential-auth-hardening --strict` 0 failures
  - 验证：命令输出 `is valid`
  - 验证：`openspec status --change veil-credential-auth-hardening --json` 的 `artifacts` 全部 `done`
- [x] 10.4 README §2/§5/§7.5/§8.4 与 spec 同批终检（口径一致、无旧表述残留）
  - 验证：`grep -n "兼容放行\|文件在位\|file_present" README.md` 无旧口径残留
  - 验证：spec「发现覆盖表」的 `AUTH-1`–`AUTH-10` 与 tasks 逐项对应，无遗漏

## 11. 写端点部署密钥强制 fail-closed（`AUTH-11`，Oracle 复核补充）

- [x] 11.1 `specs/credential-auth-hardening/spec.md`：新增 Requirement「写端点部署密钥强制（fail-closed）」——三写端点在未配置部署密钥时 `403 E_AUTH` 且无动作、已配置时行为不变、`/credential` 读路径不受影响（三条 Scenario）；Purpose 同步
  - 验证：`grep -n "写端点部署密钥强制" openspec/changes/veil-credential-auth-hardening/specs/credential-auth-hardening/spec.md` 命中 Requirement 标题
  - 验证：`openspec validate veil-credential-auth-hardening --strict` 输出 `is valid`、0 failures
- [x] 11.2 `design.md`：新增 D11 决策记录 fail-closed 机制、BREAKING 性质、`GET_BINARY_SECRET`/`CREDENTIAL_SECRET` 迁移说明与相对 Python 特权写端点的有意偏离；Risks 与发布口径同步
  - 验证：`grep -n "D11" design.md` 与 `grep -n "AUTH-11" design.md` 均命中（决策、Risks、迁移口径）
  - 验证：D11 文本含部署密钥迁移（`GET_BINARY_SECRET`/`CREDENTIAL_SECRET`）与 Python parity 有意偏离声明
- [x] 11.3 `src/service/credential/auth.rs` 新增 `verify_three_factor_write`（先校验部署密钥已配置再委派 `verify_three_factor`），`src/service/credential/mod.rs` 重导出，`src/handler/credential.rs::require_three_factor` 改委派该守卫；`/credential` 读路径仍用 `verify_three_factor`
  - 验证：`cargo test -p veil write_endpoints_require_deployment_secret` 通过；三端点无部署密钥均 `403 E_AUTH`
  - 验证：无部署密钥时注册表 `expected_hash`/条目与 `pending` 均无变化（动作前失败）
- [x] 11.4 回归测试：`src/handler/credential/tests.rs` 新增 `write_endpoints_require_deployment_secret`；既有三因子成功路径用例补部署密钥后保持通过
  - 验证：`cargo test -p veil --test http_e2e_credential` 全绿（配置部署密钥路径行为不变）
  - 验证：`cargo test -p veil write_endpoints_require_deployment_secret`、`approve_hash_change_requires_three_factor`、`register_caller_requires_three_factor`、`revoke_requires_three_factor` 全绿
- [x] 11.5 README 同步：§2（三因子语义补充）、§5（Go 对接写端点前置）、§7.5（吊销/注册鉴权声明）补写端点 fail-closed 前置与迁移，移除 compat 模式可未鉴权写端点暗示
  - 验证：`grep -n "写端点部署密钥强制\|写端点部署密钥前置\|写端点鉴权前置" README.md` 命中 §2/§5/§7.5 三处
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0
- [x] 11.6 门禁：`cargo fmt`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test -p veil` 全绿
  - 验证：`cargo fmt --all -- --check` 与 `cargo clippy --tests --all-targets -- -D warnings` 退出码 0
  - 验证：`cargo test -p veil` 输出 0 failed；`openspec validate veil-credential-auth-hardening --strict` 0 failures 且 `python3 scripts/check_doc_paths.py` 退出 0
