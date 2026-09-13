## Context

独立审计（2026-09-13）在测试覆盖与文档面确认 13 项收口项（G1–G13，见 proposal Why 与覆盖表）。现状真相源与证据锚点：

- **测试缺口**：Python 原仓 `tests/vault_stable_test.py:132-345`（fuzzy 精确/宽松/非法、三包装器 nasty 值、三校验器回退）、`tests/audit_test.py:95-242`（normalize_args 五类）、`tests/audit_env_test.py:49-257`（legacy/降级/不建任务）、`tests/observability_pii_value_test.py`（18 例采样持久化）、`tests/credential_test.py:215-721`（解锁流）、`tests/detection_hardening_test.py:48-160`（硬化矩阵）、`tests/redact_extra_test.py:176-208`（去抖/冒号）在 Rust 侧无等价或仅局部覆盖。
- **弱断言**：`src/service/sse.rs`（`push_bytes` 用例）、`src/service/json_walk.rs:177,197,261`（仅 `is_ok()`）、`src/handler/llm/dispatch.rs:384`（仅 `ok.is_ok()`）、`src/service/admin/ratelimit.rs:72,77,121,130`（happy path）、`tests/http_e2e_metrics_snapshot.rs:99`（空窗 shape）、`src/config/env_parse/tests.rs:62`（默认值 getter）。
- **文档偏差**：`README.md:26`（§1 未列出的变量二进制不读取）、`README.md:230`（§4.1 `OLD_HASH_GRACE_SECS` 来源标 `src/registry.rs`，实际 `src/registry/entry.rs:40`）、`README.md:63`（TPM 仅写 `=1`，实际 `src/service/tpm.rs:227` trim 后等于字面 `1`）、`scripts/README.md`（缺 `go_interop_e2e.py`）；未文档化行为 `src/config/env_parse.rs:99-108`（AUTO_APPROVE 别名）、`src/handler/admin.rs:55-64,117-148`（Cookie）、`src/handler/admin.rs:433-476`（SSE 过滤/回放）、`src/handler/admin.rs:463`（`Retry-After=60`）、`src/service/admin/ratelimit.rs:21`（health 豁免）；`README.md:351-359` 与 `:268`（超时码未明示 408→403）。
- **记录缺口**：`G12`/`G13` 的集中登记尚未落档。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/`、`README.md`、`scripts/`；不碰行为裁决（归 A5/A7/P11/P13/C11–C16）；不新增依赖；不提交 commit。

## Goals / Non-Goals

**Goals：**

- 为 G1–G7 给出可执行、可验证的 Rust 测试补录方案（目标文件、断言口径、与归属 change 的联动点）。
- 为 G8 给出弱断言加强标准（值断言清单），使测试从「不 panic」升级为「行为正确」。
- 为 G9–G11 给出 README/scripts 精确修正点与证据引用；为 G12 落集中登记表、G13 落逐条核验记录。
- 确保 apply 阶段可通过 `cargo test`、`check_doc_paths.py` 与 `openspec validate --strict` 收口。

**Non-Goals：**

- 不实现/不预判 A5/A7/P11/P13/C11–C16 的行为裁决；本 change 测试在归属 change 落地后锁定其结论，若先行落地则以待锁定标记并交叉引用。
- 不重复 `veil-stream-fidelity-fix` 的流式增量/多工具审计回归测试。
- 不引入新的测试框架或依赖；不改既有测试的通过前提。
- 不改 `src/`、`tests/`、`README.md`、`scripts/`（本 change 只交付规划）；不修改其他 change 目录。

## Decisions

### D1：G1 vault 稳定性测试——锁定 Rust 现行行为 + JSON 合法/还原契约

**决策**：测试分三层落地：① fuzzy 语义——`PII_FUZZY_RESTORE` 关闭时精确还原、开启时按序号回查（大小写漂移可还原），落 `src/service/redaction/scope_tests.rs`（已有 `fuzzy_restore_by_sequence_lookup`，补精确/大小写对照）；② 三包装器 nasty 值——token/PII/LLM 三条 JSON-aware 路径处理含引号密码、Unicode 转义、嵌套 stringified JSON、数组成员后输出经 `serde_json` 解析合法且还原字段值一致，落 `src/service/json_walk.rs`（测试）与 `src/service/redaction/scope_tests.rs`；③ 三校验器回退契约——`validate_json_roundtrip`（`src/service/json_walk.rs:36`）在「合法原文 + 非法输出」时回退原文、「非 JSON 原文」时回退输出，补参数化用例。

**理由**：Rust 的 fuzzy 与 json_walk 实现存在且单测部分在位（`src/service/json_walk.rs:170-279`），缺口是「契约级」断言（JSON 合法性与还原值）与 Python nasty 值矩阵的等价覆盖；非法值口径差异（Python `PII_FUZZY_RESTORE=2` 拒启动，Rust `parse_bool_off`（`src/config/validate.rs:78`）按非真值关闭）不在本 change 修行为，测试按 Rust 现行语义断言并在 Open Questions 登记，指向 A7。

**备选**：直接照搬 Python 用例并断言拒启动——与 Rust 现行语义冲突，会造成假红，不采用。

### D2：G2 审计规范化专项——与 A5 同批、不重复实现级测试

**决策**：在 `src/service/audit/normalize.rs` 与 `rules.rs` 测试模块补「输入→归一→危险判定」端到端用例五类：转义、管道优先级（逐段判定）、`../` 归一、`find` 泛洪、别名 rm（`/bin/rm` 与 `rm -rf`）。用例期望值以 A5（`veil-audit-rules-parity` 5.x）落地后的实现为准；A5 未落地前写为待锁定并显式引用其 task 号。

**理由**：A5 会改规范化管线（文本赋值挖掘/别名折叠/`..` 全管线），本 change 若先行实现测试会与 A5 实现互相追逐；边界划分是「A5 修行为、G2 保覆盖」。

### D3：G3 审计环境降级——判定入口与初始化期语义

**决策**：① legacy 回退——`audit_enabled_compat`（`src/service/audit/verdict.rs:31`）表驱动：真值集 `1/true/yes/on`、显式 `AUDIT_MODE` 优先、非真值/空白不生效；② approve 降级——`evaluate_with_whitelist`（`verdict.rs:49`）在 `Approve` 且白名单空时降级 `Block` 并 error 日志（`verdict.rs:57-60`）；③ 初始化不建任务——Rust 对等语义为「同步构造路径不 spawn 审批清扫任务」（`src/approval.rs` 的 `spawn_sweeper` 仅在异步运行路径调用），补回归测试或在 design 登记结构差异（如无法构造同步路径）。与 A7 联动：真值集与非法值 fail-closed 口径由 A7 裁决。

**理由**：`verdict.rs` 已实现 legacy 与降级，但无 `verdict.rs` 级测试（审计称仅常量测试）；三层中前两层可直接断言，第三层需按 Rust 结构验证。

### D4：G4 PII 值采样持久化——18 例映射与取证口径

**决策**：以 `tests/observability_pii_value_test.py` 的 18 例为清单（7 天滚动、`PERSIST` 热切换 1→0、跨天 topn、same-masked 合并、401 不泄漏等），映射到 `src/service/metrics/sample/tests.rs`（采样聚合）与 `src/service/metrics/store/tests.rs`（落盘/滚动/复合键 UPSERT，`persist_sample_batch`）。断言口径：持久化行仅掩码 + hash、不落明文；401 对话观测不携带请求/响应明文。与 P11（`veil-pii-parity-closeout` 12.x）联动，P11 的取证结论为本组期望值来源。

**理由**：Rust 采样设施完整（`sample.rs`/`store.rs`/`sample_flush_driver`），缺的是持久化语义回归；映射清单可对照 Python 逐例验收。

**18 例逐例映射（Python `tests/observability_pii_value_test.py`）**：

| # | Python 用例 | Rust 映射 | 结论 |
|:--|:-----------|:----------|:-----|
| 1 | `test_1h_contains_top5_and_truncated` | `sample::tests::pii_value_sample_cross_day_topn` | 等价（Rust 无 dashboard 截断面，TopN 按 hits 降序） |
| 2 | `test_1h_upstream_filter` | `sample::tests::same_value_cross_upstream_does_not_merge` + `pii_value_sample_same_masked_merge` | 等价（upstream 参与去重键） |
| 3 | `test_24h_no_persist_empty` | `sample::tests::pii_value_sample_persist_hot_switch_to_zero` | 等价（persist=0 零落盘） |
| 4 | `test_hot_switch_persist_1_to_0` | `sample::tests::pii_value_sample_persist_hot_switch_to_zero` | 等价（Rust 启动期解析，以重建采样器模拟切换） |
| 5 | `test_create_and_0600` | `store::tests::sample_upsert_rollover`（`ensure_0600` 路径） | 等价（0600 由 `ensure_0600` 覆盖） |
| 6 | `test_roll_7d` | `store::tests::pii_value_sample_roll_7d` | 等价 |
| 7 | `test_persist_0_no_table` | `sample::tests::pii_value_sample_persist_hot_switch_to_zero` | 等价（persist=0 不落盘） |
| 8 | `test_recent_events_simplify` | — | 转出（Rust 无 `recent_events` dashboard 面；内存 `top_n` 仅掩码） |
| 9 | `test_metrics_401_not_leak` | `http_e2e_admin_matrix::pii_value_sample_401_no_leak` | 等价 |
| 10 | `test_metrics_401_real_request_no_leak` | `http_e2e_admin_matrix::pii_value_sample_401_no_leak` | 等价（真 HTTP 回环） |
| 11 | `test_handle_metrics_includes_pii_when_auth` | `store::tests::sample_upsert_rollover` | 等价（授权面直读落盘表） |
| 12 | `test_kind_and_masked_overflow` | — | 转出（Rust 无每 kind 8 项 dashboard 截断） |
| 13 | `test_1h_zero_events_empty` | `sample::tests::pii_sampling_master_switch_off_means_zero_persist` | 等价（零采样空桶） |
| 14 | `test_0_event_empty_samples` | `sample::tests::empty_value_samples_as_stars_and_counts` | 等价 |
| 15 | `test_cross_day_topn_independent` | `store::tests::pii_value_sample_cross_day_buckets` | 等价（day 复合键分桶） |
| 16 | `test_24h_model_filter_approx_not_crash` | `store::tests::model_with_version_colon` | 部分等价（Rust 无近似标记面） |
| 17 | `test_same_masked_multi_hash_merge` | `sample::tests::pii_value_sample_same_masked_merge` | 差异：Rust 按 hash 分键，无 dashboard masked 聚合；hash 级去重已覆盖 |
| 18 | `test_sum_le_pii_by_type` | — | 转出（Rust 无 `pii_by_type` dashboard 汇总面） |

未映射转出项 #8/#12/#18 及 #17 的 dashboard 聚合面均依赖 Python `query_range` 聚合层，Rust 当前无对等面；如需 dashboard 值级采样明细，另立 change 交付。

### D5：G5 KeePass 解锁交互——目标层为审批/后端的契约测试

**决策**：① 解锁超时/并发单问——`src/service/credential/approval.rs`（`approval_dual_mode:64`、超时 `Auth` 分支 `:83-85`）补单问并发与超时按拒绝用例；② raw 上下文——`use_token` 语义（`src/service/credential/vault_ops.rs:27-113`）直连拒绝/脚本放行，补 handler 级或 vault_ops 级用例；③ ask 失败与双表清理——`src/approval.rs` 清扫与 `src/service/credential/approval.rs` pending 清理一致性，补失败路径用例；后端解锁行为已有 `src/keepass.rs` 测试（冷缓存单开、`cache_clear` 重开）作为底座。

**理由**：Rust 现有覆盖偏 `fetch_credential` 与 keepass 后端，「审批问询→超时/失败→清理」链路缺口最大；测试不依赖真实 Matrix，用 mock 通道。

### D6：G6 detection hardening 开关矩阵——与 P13 互引

**决策**：补「默认关/真值开/非真值关」矩阵与开启态行为（ASCII 粘连拒绝、前导零 IPv4 丢弃、CJK 边界不误伤），落 `src/service/pii/detector/tests.rs` 与 `src/config/env_parse/tests.rs`；analyzer 缓存复用以调用计数或同产物断言。非真值不拒启动为 Rust 现行行为，测试锁定；P13（`veil-pii-parity-closeout` 14.x）的归属结论为互引源。

### D7：G7 debounce/解析——差异登记而非移植去抖

**决策**：① 冒号解析——`normalize_model`（`src/service/metrics/aggregate.rs:30-41`）补 `gpt-4o:2024-08-06` 不归 `unknown_model` 用例；② flush 语义——`src/service/metrics/store/tests.rs` 补「重复 flush 覆盖式不翻倍」与「批量窗口不丢行」（`flush_to_sqlite_blocking` 与 `sample_flush_driver`）；③ Rust 无 Python `_flush_sync` 2s 去抖（事件驱动批量替代，`store.rs:488` `sample_flush_driver`），在 design 登记为等价语义而非缺失，不在 Rust 引入 2s 去抖。

**理由**：Python 去抖是写放大优化；Rust 批量驱动从机制上避免高频单行写，行为目标（不丢、不翻倍）一致；引入去抖会改变 flush 时序契约，超出本 change 范围。

### D8：G8 弱断言加强标准

**决策**：逐项加强为值/行为断言：① `src/service/sse.rs` 的 `push_bytes` 用例补重组语义（多行 data、跨块 UTF-8 拼接后的完整文本，而非仅帧数）；② `src/service/json_walk.rs:177,197,261` 在 JSON 合法之外断言替换后具体值；③ `src/handler/llm/dispatch.rs:384` 补 `to_bytes` 结果体断言；④ `src/service/admin/ratelimit.rs:72,77,121,130` 补 429 阈值、`Retry-After` 取值与窗口滚动（窗口需可推进时钟：提取纯函数或注入时钟，生产语义不变）；⑤ `tests/http_e2e_metrics_snapshot.rs:99` 补先写入已知事件后的非空窗业务值；⑥ `src/config/env_parse/tests.rs:62` 补关键转发路径（`HTTP_TIMEOUT_SECS` 等 getter 到运行时配置的映射）断言；⑦ `file_len_under_800_or_split` 元测试保留，在 `scripts/README.md` 口径注明其为文件大小守护、非行为覆盖。

**理由**：弱断言在重构后仍绿但行为已坏（假安全）；加强标准统一为「断言可观察输出值/副作用」，不引入脆弱实现细节。

### D9：G9 文档修正——三处路径/口径 + runner 补录

**决策**：① `README.md:26` 的「未列出的变量二进制不读取」追加例外注：审计规则对命令文本做 `$VAR` 与 `${VAR}` 进程 env 展开（`src/service/audit/normalize.rs:170,188`）与 `~/` 读 `HOME`（`src/service/audit/rules.rs:137`）不受该表约束；② `README.md:230` 来源由 `src/registry.rs` 更正为 `src/registry/entry.rs`（常量位于 `src/registry/entry.rs:40`）；③ `README.md:63` 与 `:98` 的 `VEIL_ALLOW_MOCK_TPM` 说明改为 trim 后等于字面 `1`（`src/service/tpm.rs:227`）；④ `scripts/README.md` 补 `go_interop_e2e.py`：用途（Go 对接 5.1–5.3 e2e）、规模（14 项）、用法与前置。

**理由**：G9 各项均为「文档与代码字面不一致」，修正保持单一行为真相源；例外注避免运维误判「审计不读 env」。

### D10：G10 未文档化行为补录范围

**决策**：补录五组：① `AUTO_APPROVE` 别名 `1/yes/0/no/pending/matrix`（`src/config/env_parse.rs:99-108`）；② 管理面 Cookie：`__Host-admin_token` 优先、回退 `admin_token`（`src/handler/admin.rs:42-64`）、Set-Cookie 签发条件（https 经 `X-Forwarded-Proto` 走 `__Host-` Secure，否则兼容 http；非法 cookie-octet 拒绝签发，`admin.rs:115-148`）；③ SSE 建连过滤 `?model=&upstream=`（`admin.rs:433-476`）与近环回放（最近 20 条、同过滤）；④ SSE 并发超限固定 `Retry-After: 60`（`admin.rs:459-463`）；⑤ `/_admin/health` 豁免实现细节（`src/service/admin/ratelimit.rs:21` 唯一豁免项、不占通用桶）。补录位置为 README §3/§7 对应小节。

**理由**：上述行为均已实现且有测试，但 README 未覆盖；补录为「已实现行为声明」，不涉行为变更（无 BREAKING）。

### D11：G11 阻塞审批超时码——408→403 归并明示与锁定

**决策**：README §5（`:268`）与 §6.7（`:351-359`）明示：`CREDENTIAL_BLOCK_WAIT=1` 阻塞超时在本仓按拒绝返回 `403`（`src/service/credential/approval.rs:83-85` 的 `VeilError::Auth`），Python 原仓为 `408`（`_credential.py:433`）；该归并列列为迁移注意项（超时与拒绝对下游同码）。测试锁定：阻塞超时用例断言 `403` 且请求不悬挂；若 credential-flow-parity 对审批链另有裁决，引用其结论并保持 `403`。

**理由**：超时 `408` 与拒绝 `403` 分开会让下游重试语义混乱；本仓归并为 fail-closed 一致码。文档差异明示避免迁移误判。

### D12：G12 有意差异登记表（核验档）

**决策**：在 design 集中登记（下表），逐项给出归属与证据；与归属 change 重复的裁决只在其处展开，本处仅交叉引用。

| # | 差异项 | 本仓语义 | 归属/引用 |
|:--|:-------|:---------|:----------|
| 1 | `CREDENTIAL_PROXY_DEBUG_DIR` 四件落盘 | 二进制不读取、无落盘（Non-Goal） | README §8.2（`README.md:521`）与 §7.4；本 change 记录 |
| 2 | 跨 TCP UTF-8 分片 | 字节级缓冲无损拼接（优于 Python 的 replace 回退） | `src/service/sse.rs` 单测 `utf8_byte_buffered_without_per_chunk_decoding`；本 change 记录 |
| 3 | 下游断连任务寿命 | `spawn_contained` 任务续跑、panic 映射 500 而非连接中断 | `src/handler/llm/dispatch.rs:368-376` 单测；本 change 记录 |
| 4 | 空 `data:` 心跳 | 丢弃（不计事件、不合成） | `src/service/sse.rs` 单测；本 change 记录 |
| 5 | NonDialog 字节透传 | 不做用量/审计/还原，计 `nondialog_passthrough` | README §7.6（`README.md:483`）；本 change 记录 |
| 6 | 限流维度 | 凭据按调用方、注册按 source（相对 Python 全局单桶） | `veil-credential-flow-parity` 的 `C11`（task 11.x） |
| 7 | 旧哈希宽限 | `old_hash_expires_at = now + 3600` 正向修正 | `veil-credential-flow-parity` 的 `C12`（task 12.x） |
| 8 | 紧急吊销网段 | 回环/IPv6/链路本地/ULA/CGNAT + `file_present` | `veil-credential-flow-parity` 的 `C13`（task 13.x） |
| 9 | `/credential` 信封 | `{ok,credential}` | `veil-credential-flow-parity` 的 `C15`（task 15.x） |
| 10 | `caller_path` 双必填 | 维持 `caller_path` 与 `caller_hash` 必填 | `veil-credential-flow-parity` 的 `C16`（task 15.2） |
| 11 | PII 语义映射 | `PII_HOLD_MAX` 跨缝窗、序号游标、残缺剥离收窄 | `veil-pii-parity-closeout` 的 `P5`/`P6`/`P7`/`P8`（task 6–9.x） |

**理由**：审计要求「LLM 核心有意差异登记（核验档）」；集中表 + 归属引用避免各 change 平行裁决漂移。

### D13：G13 README §6/§7 声明核验记录（本轮通过）

**决策**：核验方法为「逐条声明 → 代码锚点（文件:行）→ 结论」，记录入本 design；下表覆盖 README §6/§7 全部小节（§6.1–§6.11、§7.1–§7.10，共 21 条），apply/归档前按同法复核并更新到最终行号；发现不一致时按归属 change 转出，不静默修正。本轮核验结论：**通过**（下列锚点为本轮全量复核通过项）。

| README 声明 | 代码锚点（复核终稿） | 结论 |
|:------------|:---------------------|:-----|
| §6.1 脱敏默认开启 | `src/config/env_parse.rs:578-585` | 通过 |
| §6.2 采样持久默认开启 | `src/config/env_parse.rs:617` | 通过 |
| §6.3 容量分表 5000/1000 | `src/service/credential_vault.rs:22` 与 `src/service/pii/detector.rs:35` | 通过 |
| §6.4 流式审批不挂起 | `src/service/audit/verdict.rs:11-17` 与 `src/service/credential/approval.rs:122-135` | 通过 |
| §6.5 检索调用审计口径 | `src/service/llm_gateway/tool.rs:93-100` | 通过 |
| §6.6 回环免 token 未迁移 | 环境变量全表无 `ENV`/`ALLOW_LOOPBACK_NO_TOKEN` 读取（`src/config/env_parse.rs`） | 通过 |
| §6.7 默认 202 与阻塞 300s | `src/service/credential/approval.rs:122-135` | 通过 |
| §6.8 `caller_path`/`caller_hash` 双必填 | `src/service/credential/auth.rs:88-93` | 通过 |
| §6.9 IP 字面量一律非内网 | `src/service/audit/rules.rs:350-372` | 通过 |
| §6.10 `AUDIT_ENABLED` 真值集 + 非法拒启动 | `src/config/validate.rs:61-66`、`:374-475` | 通过 |
| §6.11 审计策略文件 fail-closed | `src/service/audit/policy.rs:63-78` | 通过 |
| §7.1 HOP 头集 8 项 | `src/service/llm_gateway/hop.rs:7,20,27` | 通过 |
| §7.2 usage 与 `[DONE]` 与非 JSON 错误体 | `src/handler/llm/pump/synth_flush.rs:50-51` 与 `src/handler/llm/nonstream.rs` | 通过 |
| §7.3 请求隔离 | `src/service/pii/scope.rs:61` 与 `src/service/metrics.rs:7-10` | 通过 |
| §7.4 遗留变量兼容表 | `src/config/env_parse.rs` 未读遗留名 | 通过 |
| §7.5 吊销/注册鉴权 | `src/handler/credential.rs:43,196` | 通过 |
| §7.6 NonDialog 透传 | `src/handler/llm/dispatch.rs:175-179` 与 `src/service/llm_gateway/hop.rs` | 通过 |
| §7.7 归一化声明 | `src/handler/llm/rewrite.rs:117` 与 `src/service/redaction/scope.rs` | 通过 |
| §7.8 fuzzy 还原超集与残缺收窄 | `src/service/redaction/scope.rs:44,124` | 通过 |
| §7.9 `PII_HOLD_MAX` 缝窗语义映射 | `src/service/redaction/seam.rs:3` 与 `src/handler/llm/dispatch.rs:169` | 通过 |
| §7.10 掩码边缘与别名 | `src/service/pii/detector.rs:231,259` | 通过 |

**理由**：审计要求「本轮核验通过落档，并列明核验方法（逐条引用 + 文件:行），供归档审计追溯」；表格按 README §6/§7 小节全覆盖（21/21），归档时可逐条复验、无遗漏声明。

## Risks / Trade-offs

- [G2 与 A5 顺序耦合] → 若 A5 未落地先写测试会假红；以「待锁定」标记与 A5 task 引用，A5 合入后立即补齐并去标记。
- [G3 第三层「初始化不建任务」无直接对等结构] → Rust 为同步构造 + 异步 run，若测试无稳定挂点则登记结构差异并给出等价断言（同步构造不 panic、任务仅在运行期创建）。
- [G4 18 例映射遗漏] → 以 Python 文件为唯一清单逐例勾选；映射不全时在 tasks 4.1 显式列出未映射项并转出。
- [G7 无 2s 去抖] → 以等价语义（批量驱动）登记，不引入去抖以免改变 flush 时序契约；若监控依赖 2s 窗口，另立 change。
- [G8 时钟注入改动生产代码] → 窗口滚动测试若需可推进时钟，优先提取纯函数（阈值/窗口计算）供测试，避免为测试改生产时序。
- [G9–G11 文档改动与行为 change 并发] → 本 change 只改口径描述，不改行为；与 A7/C1 等 README §6 落档存在写冲突风险，apply 时按文件段落串行合并。
- [G13 抽验行号漂移] → 表格以「声明+锚点」为单位，行号复核在 apply 终检执行，允许行号更新不允许结论漂移。
- [G13 新偏差转出] → 核验发现的 README 与代码不一致（新偏差）按归属 change 登记或转出（`veil-credential-flow-parity`/`veil-pii-parity-closeout`），不在本 change 静默修正；本轮 §6/§7 全量核验未发现新偏差，本条保留转出规则入口供归档审计复核。

## Migration Plan

1. 依赖前置：等待 `veil-audit-rules-parity`（A5/A7）与 `veil-pii-parity-closeout`（P11/P13）关键组落地。
2. 按 tasks 顺序：先 G1–G7 测试补录（每组独立 `cargo test`），再 G8 断言加强，再 G9–G11 文档修正，最后 G12/G13 记录复核与门禁。
3. 每批同步跑 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、`python3 scripts/check_doc_paths.py`。
4. 回滚策略：新增测试可按文件 revert；文档修正按段落 revert；无 schema/数据迁移、无新依赖、无部署形态变化。

## Open Questions

- `PII_FUZZY_RESTORE`（及同类默认关闭布尔开关）非法值口径是否需对齐 Python 的拒启动语义：Rust 现为「非真值即关」，归 audit-rules-parity 的 A7 真值集裁决或新 change 承接；本 change 测试按现行行为锁定并在 spec 声明差异。
- G3 第三层「初始化期不建任务」在 Rust 的稳定测试挂点（AppState 同步构造 vs 异步 run）：若无法构造则登记结构差异，转由 arch-hygiene-closeout 复核启动时序。
