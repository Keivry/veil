> 本 change 已 **apply 完成**（2026-09-16）：以下 35 项均以实际证据勾选；`bash scripts/gate.sh` 七步全绿（exit 0）。

## 1. 会话键分层推导（`PII-KEY`；`redaction`）

- [x] 1.1 `src/config/env_parse.rs:171-239`（`Config` 结构，脱敏字段区 `:199-205`）新增作用域开关字段：`pii_scope_mode`（`PII_SCOPE_MODE`，默认 `request`）、`pii_scope_ttl_secs`（`PII_SCOPE_TTL_SECS`，默认 `1800`）、`pii_scope_max_conversations`（`PII_SCOPE_MAX_CONVERSATIONS`，默认 `1024`）、`pii_scope_key_header`（`PII_SCOPE_KEY_HEADER`，默认 `x-veil-conversation-id`）；`PII_SCOPE_MODE` 非 `request`/`conversation` 拒启动，TTL/上限非正整数拒启动
  - 验收证据：`cargo test -p veil pii_scope_mode_defaults_to_request` 通过；默认值与现行为一致
  - 验收证据：`cargo test -p veil pii_scope_mode_invalid_rejected` 通过；非法值拒绝启动且报错列明合法值

- [x] 1.2 新增纯函数会话键推导单元（置于 `src/service/redaction/` 新子模块，如 `conversation_key.rs`；不触网络）：按 D1 四级优先级返回 `Option<ConversationKey>`；第 1 级头值 ≤256 字节且无控制字符（超长/非法不命中，继续下一级，MUST NOT 截断/哈希原始超长值）；第 3 级对**脱敏前规范化**（对象键递归升序、`tools` 按工具名稳定排序、其余数组保序）的 `tools + system + 首个 user turn` 前缀做 HMAC；第 4 级返回 `None`（由调用方回退）。**条件性**：第 3 级要求 `tools`+`system`+首个 user turn 三者齐备，纯多轮 `messages`（无工具/无键）SHALL 落第 4 级。**新增测试置于新 sibling 文件 `conversation_key_tests.rs`**（`src/service/redaction/` 目录内）（`scope_tests.rs` 已 788 行、逼近 800 行上限，MUST NOT 追加）
  - 验收证据：新增 `conversation_key_layered_precedence` 测试通过；显式头 > `prompt_cache_key` > `previous_response_id` > 稳定前缀 > `None`
  - 验收证据：新增 `conversation_key_never_uses_user_field` 测试通过；仅含 `user` 字段时返回 `None`
  - 验收证据：新增 `conversation_key_stable_prefix_deterministic` 测试通过；同输入两次同键，键序/工具序扰动后仍同键
  - 验收证据：新增 `conversation_key_header_too_long_rejected` 测试通过；>256 字节头不命中且按优先级继续（不截断、不报错）
  - 验收证据：新增 `conversation_key_plain_multiturn_falls_to_per_request` 测试通过；无 `tools` 的纯多轮 `messages` 不命中第 3 级、落第 4 级（预期降级）

- [x] 1.3 会话键 HMAC 与租户命名空间（D2；NB-2 修订）：`HMAC(secret, tenant_fingerprint || conversation_id)`；`tenant_fingerprint = HMAC(secret, 完整上游基址 || 分隔符 || 客户端凭据头归一化)`——**主判别项取完整 `upstream_base`（含 path/query，`src/handler/llm/dispatch.rs:145`），MUST NOT 仅用上游主机**（`resolve_upstream` 按入口端口选上游、端口来自可伪造 Host 头，仅用主机会把不同租户折叠进同一命名空间）；**可选次判别项**取客户端 Authorization/api-key 头 HMAC；**分隔符**为固定单一字面量；**零/多凭据归一化**确定性——零个归一为固定字面量（空串分量，**非示例**），多个去重后按字节序排序、以固定子分隔符 join，再并入 HMAC，不含凭据原文。**MUST NOT 事后回取「本请求命中的 vault 键集合」**（vault 为全局明文→token 快照、按值匹配，无每请求注入选择点；事后预扫描须先于 `src/handler/llm/dispatch.rs:160` 的作用域选择运行且随轮次改变指纹而自败）。复用既有 HMAC-SHA256 用法模式（`src/service/metrics/sample.rs:250-253`）
  - 验收证据：新增 `conversation_key_tenant_namespace_isolates` 测试通过；同客户端 id、不同完整上游基址（或可区分凭据头）→ 不同键
  - 验收证据：新增 `conversation_key_hmac_not_raw` 测试通过；派生键不等于客户端原始值
  - 验收证据：新增 `conversation_key_tenant_fingerprint_defined_zero_credential` 测试通过；零凭据头归一到固定空串分量，指纹非空且确定
  - 验收证据：新增 `conversation_key_tenant_fingerprint_multi_credential_sorted` 测试通过；多凭据去重排序后同集合恒同指纹（顺序扰动不变）
  - 验收证据：新增 `conversation_key_tenant_fingerprint_host_only_insufficient` 测试通过；仅主机相同而 path/query 不同的上游基址得不同指纹（不折叠）

- [x] 1.4 `previous_response_id` → 会话键进程内映射（D1 第 2 级）：**按租户指纹分域**（映射键 = `HMAC(secret, tenant_fingerprint || previous_response_id)`）；写入点 SHALL **仅限 `Protocol::Responses`** 的响应完成处（流式 `src/handler/llm/pump/spawn/event_loop.rs:205-210`、非流 `src/handler/llm/nonstream.rs:205-213`；两处实现为协议无关，Chat 亦产出 `chatcmpl-*`、Anthropic 产出 `msg_*`，故写入前 SHALL 先判 `Protocol::Responses`，**Chat/Anthropic 的响应 id MUST NOT 进入映射**）；读取点为请求推导；映射有界（复用 `PII_SCOPE_MAX_CONVERSATIONS` 上限），未命中返回 `None` 继续下一级
  - 验收证据：新增 `previous_response_id_map_hit_and_miss` 测试通过；命中解析为既有键、未命中继续下一级
  - 验收证据：新增 `previous_response_id_cross_tenant_not_resolved` 测试通过；租户 A 的 `response.id` 在租户 B 下不解析（映射分域）
  - 验收证据：新增 `previous_response_id_resolves_via_faithful_response_id` 测试通过；上游 `response.id` **值级不变**（含新增 PII 帧经 `loads→walk→dumps` 重序列化后其值仍不变），下一轮 `previous_response_id` 可解析
  - 验收证据（负向断言）：新增 `previous_response_id_only_responses_writes_map` 测试通过；Chat（`chatcmpl-*`）/Anthropic（`msg_*`）响应 id **不进入**映射（写入点协议门控）
  - 验收证据（辅助证据，存在性检查，非行为证据）：`grep -rn "previous_response_id" src/service/redaction/` 命中映射读写点（apply 期）

- [x] 1.5 请求体解析接线：在 `src/handler/llm/dispatch.rs:196-204`（`req_value` 快照）与 `src/handler/llm/rewrite.rs:32-58`（改写入口）取得脱敏前原文，供第 2/3 级推导；显式头从请求头读取；会话键头由网关消费且 MUST NOT 转发上游（默认头名属 `x-veil-*` 内部命名空间，由 `src/handler/llm/mod.rs:45-46` 统一剔除；自定义头名同样剔除）
  - 验收证据：新增 `conversation_key_header_ignored_when_mode_request` 测试通过；`request` 模式下不读头
  - 验收证据：新增 `conversation_key_header_not_forwarded_upstream` 测试通过；请求携带会话键头时转发头集合不含该头名/值（含自定义头名）
  - 验收证据（辅助证据，存在性检查）：`grep -n "conversation_key\|pii_scope_key_header\|x-veil-conversation-id" src/handler/llm/` 命中接线点（apply 期）

## 2. `ConversationScopeStore`（`PII-STORE`；`redaction`）

- [x] 2.1 在 `src/service/redaction/` 目录下新增 `conversation_store.rs` 子模块（或等价命名）：LRU + TTL 存储，键为 D2 派生键、值为 `Arc<PiiScope>`；容量 `PII_SCOPE_MAX_CONVERSATIONS`、空闲 TTL `PII_SCOPE_TTL_SECS`；单会话条目沿用 `PII_MAX_ENTRIES`（`src/service/pii/detector.rs:36`）
  - 验收证据：新增 `conversation_store_capacity_lru_evicts` 测试通过；超上限按 LRU 淘汰至有界
  - 验收证据：新增 `conversation_store_idle_ttl_evicts` 测试通过；超 TTL 后条目消失
  - 验收证据：新增 `conversation_store_aggregate_bound` 测试通过；条目总数 ≤ `PII_SCOPE_MAX_CONVERSATIONS` × `PII_MAX_ENTRIES` × 2（请求表 + 响应表各 `PII_MAX_ENTRIES`，`src/service/pii/scope.rs:169`、`:181`；默认 2,048,000）（聚合上界）

- [x] 2.2 原子 get-or-insert 返回共享 `Arc<PiiScope>`（D3）：同会话并发在途请求收敛到同一 token；同值复用由 `PiiScope` 内部 Mutex 原子保证（`src/service/pii/scope.rs:142-194`）
  - 验收证据：新增 `conversation_store_concurrent_same_plaintext_one_token` 测试通过；并发同明文仅产出一 token
  - 验收证据：新增 `conversation_store_get_or_insert_shared_arc` 测试通过；两次取用为同一 `Arc`（指针相等）

- [x] 2.3 锁恢复与 fail-closed：存储经 `lock_or_recover`（`src/service/lock_recover.rs:26`）承载；锁中毒不静默降级为错误结果
  - 验收证据：新增 `conversation_store_poison_recovery` 测试通过；中毒后仍返回真实结果或按声明 fail-closed
  - 验收证据（辅助证据，存在性检查）：`grep -rn "lock_or_recover" src/service/redaction/` 命中（apply 期）

- [x] 2.4 淘汰确定性可测：注入容量/TTL 后断言被淘汰者；淘汰仅致缓存失配（重新铸造 token）
  - 验收证据：新增 `conversation_store_eviction_deterministic` 测试通过；被淘汰者确定可断言
  - 验收证据：新增 `conversation_store_evicted_remints_token` 测试通过；淘汰后同明文产出新 token 且无错误

- [x] 2.5 `AppState` 装配（m3/D3）：`ConversationScopeStore` 与 `previous_response_id` → 会话键映射作为字段挂 `AppState`（`src/state.rs:37-71`），并在启动装配 `src/state.rs:88-163` 构造注入，使存储跨请求共享（`PII_SCOPE_MODE=request` 时不构造/不使用）
  - 验收证据：新增 `app_state_carries_conversation_store` 测试通过；`AppState` 装配后持有可共享的存储句柄（`Arc` 指针相等）
  - 验收证据：新增 `app_state_request_mode_no_conversation_store_use` 测试通过；默认模式下存储不被使用（零行为变化）

## 3. 授权域不对称（`PII-AUTH`；`redaction`）

- [x] 3.1 会话作用域仅承载 PII：`Scope` 构造由逐请求改为「按模式选择」——`request` 用逐请求 `PiiScope`、`conversation` 用存储返回的共享 `Arc<PiiScope>`；凭据 minted-set 仍逐请求（`src/service/redaction/scope.rs:20-40`、`:154-167`）。**新增测试置于新 sibling 文件 `conversation_scope_tests.rs`**（`src/service/redaction/` 目录内）（`scope_tests.rs` 已 788 行、逼近 800 行上限，MUST NOT 追加；遵循既有 sibling-tests 约定）
  - 验收证据：新增 `scope_conversation_shares_pii_only_not_minted` 测试通过（位于 `conversation_scope_tests.rs`）；两轮共享 PII 映射、minted-set 各自独立
  - 验收证据（辅助证据，存在性检查）：`grep -n "ConversationScopeStore\|pii_scope_mode" src/service/redaction/scope.rs src/handler/llm/dispatch.rs` 命中接线（apply 期）

- [x] 3.2 B3 不变守护：响应侧凭据还原仍仅授权本请求 minted-set；未授权凭据 token 按幻觉剥离（`src/service/redaction/scope.rs:420-446`、`:154-167`；`src/service/credential_vault.rs:335-351`）；凭据 token MUST NOT 进会话作用域。**测试置于 sibling 文件 `conversation_scope_tests.rs`**（`src/service/redaction/` 目录内）
  - 验收证据：新增 `conversation_mode_b3_request_level_unchanged` 测试通过（位于 `conversation_scope_tests.rs`）；上轮凭据 token 在本轮响应被剥离，仅本轮 minted 可还原
  - 验收证据：新增 `conversation_scope_never_holds_credentials` 测试通过（位于 `conversation_scope_tests.rs`）；会话存储不含凭据映射

- [x] 3.3 跨会话 PII 不可还原：会话键 K1 铸造的 PII token 出现在 K2 响应 → 不可还原，按未知 token 原样保留/剥离。**测试置于 sibling 文件 `conversation_scope_tests.rs`**（`src/service/redaction/` 目录内）
  - 验收证据：新增 `pii_token_cross_conversation_not_restored` 测试通过（位于 `conversation_scope_tests.rs`）；跨会话还原失败并记审计计数
  - 验收证据：`cargo test -p veil scope` 既有用例全绿（无回退）

- [x] 3.4 会话内 PII 跨轮还原：会话键内第 1 轮铸造的 PII token 在第 2 轮响应可还原（多轮正确性）。**测试置于 sibling 文件 `conversation_scope_tests.rs`**（`src/service/redaction/` 目录内）
  - 验收证据：新增 `pii_token_same_conversation_restored_next_turn` 测试通过（位于 `conversation_scope_tests.rs`）；跨轮同 token 同明文
  - 验收证据：新增 `conversation_restore_spans_json_depth_unchanged` 测试通过（位于 `conversation_scope_tests.rs`）；跨轮还原的 JSON 转义深度语义不变
  - 验收证据：新增 `conversation_scope_tests_file_under_size_limit` 守护（或 apply 期 `check_file_sizes.py` 复核）；新 sibling 文件 ≤800 行（`scope.rs` 613 行 / `scope_tests.rs` 788 行均不得追加至超限）

- [x] 3.5 默认模式零行为变化守护：`PII_SCOPE_MODE` 未设时 `Scope` 逐请求构造，行为与既有逐项一致（`src/handler/llm/dispatch.rs:160`）
  - 验收证据：新增 `scope_default_mode_per_request_unchanged` 测试通过；跨请求互不可见
  - 验收证据：`cargo test -p veil` 既有全量用例无回退（apply 期）

## 4. 上游 prompt cache 保真与注入位置（`CACHE`；`llm-gateway`）

- [x] 4.1 `cache_control` 断点存活：脱敏改写 MUST NOT 丢弃/位移/改写断点；断言改写后断点数量、位置、取值不变（Chat/Anthropic 的 `tools`/`system`/`messages` 三处）
  - 验收证据：新增 `cache_control_breakpoints_survive_redaction` 测试通过；断点数量/位置/取值逐项存活（字节表示受既有已声明偏离约束）
  - 验收证据：新增 `cache_control_not_injected_when_absent` 测试通过；无断点时系统不自行注入

- [x] 4.2 `prompt_cache_key` / `metadata` 原样转发：脱敏改写后保留原值，不新增/删除/改写
  - 验收证据：新增 `prompt_cache_key_metadata_forwarded_untouched` 测试通过
  - 验收证据：新增 `nondialog_cache_fields_byte_passthrough` 测试通过；非对话透传路径不变

- [x] 4.3 占位符说明头部注入保持（`src/service/llm_gateway/placeholder.rs:138-188`、`:244-317`）：位置为 `messages[0]`/`system`/`input|instructions`，MUST NOT 尾部注入；幂等守卫不变
  - 验收证据：新增 `placeholder_injection_remains_head_position` 测试通过；三协议均头部
  - 验收证据：`cargo test -p veil placeholder` 既有全绿

- [x] 4.4 会话内注入前缀字节一致（D9 验收）：同会话键两轮含需注入 token 时，两轮注入前缀逐字节相等
  - 验收证据：新增 `placeholder_prefix_byte_identical_across_turns` 测试通过；两轮注入前缀逐字节相等
  - 验收证据：新增 `placeholder_prefix_differs_across_conversations` 测试通过；不同会话键不误判相等

- [x] 4.5 thinking 连续性与残余限制文档化（D11）：声明 token 稳定为必要条件（非充分），列残余限制四项；不新增实现/验证声明；**与 canonical `llm-protocol-hardening` 的「Anthropic 扩展思考签名连续性限制声明」显式互引，两处 MUST NOT 漂移**。**跨 change 排序（MINOR 6，已生效）**：该条款由 `veil-audit-r4-remediation` 引入，该 change 已于 2026-09-16 归档，canonical `openspec/specs/llm-protocol-hardening/spec.md` 已含该 requirement，互引**已生效**（详见任务 6.5）
  - 验收证据：两处声明措辞一致（**文档措辞比对，非行为测试**——Momus 已认定该 `thinking_negative_matches_llm_protocol_hardening` 为 code-review 项）：README §7.11 与 canonical `llm-protocol-hardening` 同名 requirement 均含「必要条件非充分/不校验签名/不承诺无条件连续」
  - 验收证据：互引已生效——`veil-audit-r4-remediation` 已于 2026-09-16 归档，canonical `llm-protocol-hardening` 含该 requirement（已核查 README:893-895 互引段）
  - 验收证据（辅助证据，存在性检查）：`grep -n "必要条件\|残余限制\|signature\|llm-protocol-hardening" README.md openspec/specs/llm-gateway/spec.md` 命中声明（apply 期）
  - 验收证据（辅助证据，存在性检查）：无「已实现签名连续性」类断言（`grep` 无命中）

## 5. 观测（`OBS`；`observability-admin`）

- [x] 5.1 `src/service/llm_gateway/metrics.rs:66-105` 新增固定键计数：会话复用、会话淘汰、回退请求级；沿用 `KeyedCounters` 风格（`:9-51`）；`request` 模式下复用/淘汰恒 `0`
  - 验收证据：新增 `pii_scope_counters_record_reuse_and_eviction` 测试通过
  - 验收证据：新增 `pii_scope_counters_zero_in_request_mode` 测试通过

- [x] 5.2 快照装配 `src/handler/admin.rs:110-148`：新增只读项（模式 + 三计数）；既有键不变；缺失/锁不可用降级为 `0`
  - 验收证据：新增 `admin_metrics_expose_pii_scope_mode` 测试通过；响应含模式与计数
  - 验收证据：新增 `admin_metrics_existing_keys_unchanged` 测试通过；既有键集合与语义不变

- [x] 5.3 不泄露（指标 + 日志双层）：`/_admin/metrics` 与 `tracing` 日志 SHALL NOT 暴露会话键/头值/明文/token 原值
  - 验收证据：新增 `admin_metrics_scope_no_secret_leak` 测试通过；指标输出不含键/明文/token
  - 验收证据：新增 `conversation_key_not_logged` 测试通过；`conversation` 模式处理请求后，捕获的日志行（含 debug 级）不含会话键/头值/明文/token

## 6. 文档与 canonical 同步（`DOC`）

- [x] 6.1 `README.md:706-713`（§7.3 请求隔离声明）增补会话作用域模式说明：隐私增量、MUST NOT 承诺清单、默认 `request` 非 BREAKING；并在 §1 环境变量全表登记四个 `PII_SCOPE_*` 行（README 声明「未列出的变量二进制不读取」，漏登记即静默不生效）
  - 验收证据：§1 环境变量全表含 `PII_SCOPE_MODE`/`PII_SCOPE_TTL_SECS`/`PII_SCOPE_MAX_CONVERSATIONS`/`PII_SCOPE_KEY_HEADER` 四行，默认值与环境变量说明齐备
  - 验收证据（NB-3，条件性与降级）：README §7.3 明列会话级缓存友好的**前置条件**——**当且仅当**会话键成功推导（命中第 1–3 级）时成立，第 3 级要求 `tools` + `system` + 首个 user turn 三者齐备、第 1/2 级依赖客户端配合（显式头 / `prompt_cache_key` / `previous_response_id`）
  - 验收证据（NB-3，降级行为）：README §7.3 明写**降级行为**——纯多轮 `messages`（无工具、无会话键头、无协议原生键）即便 `PII_SCOPE_MODE=conversation` 亦落第 4 级逐请求、不获跨轮 token 稳定，且不报错、不伪造键
  - 验收证据（辅助证据，存在性检查）：`grep -n "PII_SCOPE_MODE\|PII_SCOPE_TTL_SECS\|PII_SCOPE_MAX_CONVERSATIONS\|PII_SCOPE_KEY_HEADER\|会话级\|MUST NOT 承诺\|前置条件\|逐请求" README.md` 命中（apply 期）
  - 验收证据：README 明确「默认 `request` 行为不变、非 BREAKING」

- [x] 6.2 归档期 canonical 晋升：本 change **五个** delta（`redaction`、`llm-gateway`、`observability-admin`、`credential-vault-singleton`、`docs-contract-resync`）经 `openspec archive` 晋升为 canonical；`request` 默认口径不变
  - 验收证据：apply 后 `openspec validate veil-pii-conversation-cache --strict` 通过
  - 验收证据：归档后 `openspec list` 无本 change；canonical 五 spec 含新增/修订 Requirement（含 `credential-vault-singleton` 两处 MODIFIED 与 `docs-contract-resync` 一处 MODIFIED）

- [x] 6.3 `src/service/metrics.rs:7-12` 模块文档与 README §7.3 **同批锁步**更新（NB-1c；`docs-contract-resync` 要求 same wording）：将「请求隔离为隐私硬要求」口径扩展为「**默认**请求级隔离为隐私硬要求 + `PII_SCOPE_MODE=conversation` 显式启用时于**有界、非持久窗口**内允许会话级关联」；两侧措辞逐义一致，MUST NOT 单侧更新致漂移（README §7.3 原 `TODO(metrics)` 归 docs change 收尾的既有声明保持）
  - 验收证据：比对 README §7.3 与 `src/service/metrics.rs:7-12`，两侧均含「默认请求级为隐私硬要求」与「有界、非持久会话级例外」同义措辞（same wording），任一侧缺失即判失败（code review 复核；辅助证据：`grep -n "请求隔离\|会话级\|隐私硬要求" README.md src/service/metrics.rs` 两侧命中同义表述）
  - 验收证据：`openspec validate --all --strict` 保持 0 failed（canonical `docs-contract-resync` 的「口径同字」scenario 在归档后仍成立）

- [x] 6.4 canonical `credential-vault-singleton` Purpose 对齐（NB-1d）：canonical `openspec/specs/credential-vault-singleton/spec.md` 的 Purpose（现行文本仍称「恢复凭据与 PII 映射的跨请求稳定性」，与 requirement 的**默认请求级**模型存在内部张力）SHALL 在对齐批内**手工修订**为「凭据映射跨请求稳定（进程单例）；PII 默认请求级隔离，并允许经另立 change 交付的有界、非持久会话级（conversation）稳定模式」
  - 机制说明：openspec `archive` 仅用 delta `## Purpose` **初始化新 spec**，对**已存在**的 canonical Purpose 会被忽略（并告警「delta Purpose ignored」），故 delta 无法覆盖——须直接编辑 canonical 文件；该编辑在 apply/归档期执行，**不由本 artifacts-only 阶段执行**
  - 验收证据：修订后 canonical Purpose 不再将「PII 跨请求稳定」表述为无条件目标；`openspec validate --all --strict` 保持 0 failed

- [x] 6.5 跨 change 排序声明（MINOR 6）：`llm-gateway` delta 对 canonical `llm-protocol-hardening`「Anthropic 扩展思考签名连续性限制声明」的互引**仅在 `veil-audit-r4-remediation` 先行归档后生效**；`veil-audit-r4-remediation` 已于 **2026-09-16 归档**，canonical `llm-protocol-hardening` 已含「Anthropic 扩展思考签名连续性限制声明」，本 change 互引**已生效**（原 in-flight 标注已解除）
  - 验收证据：本 change 文本（proposal §九 / design D11 / spec llm-gateway / 任务 4.5）原 in-flight 标注已解除，改为已生效（r4 于 2026-09-16 归档）
  - 验收证据：跨 change 排序已满足——**先归档 r4**（2026-09-16 完成）；`openspec/specs/llm-protocol-hardening/spec.md` 已含该 requirement，互引生效

## 7. 验证门禁

- [x] 7.1 `cargo fmt --check` 退出 0
  - 验收证据：命令退出码 0，无格式差异

- [x] 7.2 `cargo clippy -p veil --all-targets -- -D warnings` 退出 0
  - 验收证据：命令退出码 0，0 warning

- [x] 7.3 `cargo test -p veil` 全绿（含本 change 新增用例，无既有回退）
  - 验收证据：命令退出码 0，0 failed；新增用例名逐一通过（见 §1-§5）

- [x] 7.4 `python3 scripts/check_doc_paths.py` 退出 0（本 change 内 `src/**.rs:NNN` 锚点存在且在界内）
  - 验收证据：命令输出 OK、无 FAIL 项

- [x] 7.5 `python3 scripts/check_file_sizes.py` 退出 0（新增/外迁文件 ≤800 行）
  - 验收证据：命令输出 OK、无 FAIL 项

- [x] 7.6 `bash scripts/gate.sh` 七步全绿（exit 0）
  - 验收证据：fmt / clippy / test / doc-paths / file-sizes / api_conformance / go vet+test 均绿

- [x] 7.7 `openspec validate veil-pii-conversation-cache --strict` 通过
  - 验收证据：命令输出 `is valid`、0 failures

## 已知处置说明

1. **apply 已完成**（2026-09-16）：本 change 的 35 项已按实际证据勾选；`bash scripts/gate.sh` 七步全绿（exit 0）。
2. **默认安全**：`PII_SCOPE_MODE` 默认 `request` 即现行为；`conversation` 为 opt-in。仅当未来把默认改为 `conversation` 时才需 README/BREAKING 更新（另立 change）。
3. **B3 保持**：凭据请求级授权域（minted-set，`src/service/redaction/scope.rs:20-40`、`:420-446`）在任何模式下均不变；会话作用域仅承载 PII。
4. **依赖无新增**：`hmac`/`sha2` 已是直接依赖（`Cargo.toml:21-23`）。
5. **命中率不测量**：wont-measure 保持（`README.md:706-713`）；本 change 不承诺可测量的缓存命中率提升。
6. **证据强度分级**：任务内的 `grep` 类验收均为**辅助证据（存在性检查，非行为证据）**；行为正确性以命名行为测试为准，**每条代码任务（§1–§5）至少含一项行为测试**（§6 文档同步 / §7 门禁任务以存在性与命令证据为准，不受本句约束）。跨 change 互引：thinking 连续性声明与 canonical `llm-protocol-hardening` 互引；`veil-audit-r4-remediation` 已于 2026-09-16 归档，互引**已生效**，真相源为该 canonical 要求（见任务 6.5）。
