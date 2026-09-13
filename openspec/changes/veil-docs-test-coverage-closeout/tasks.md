## 1. `G1` vault 稳定性等价测试

- [x] 1.1 `src/service/redaction/scope_tests.rs`：补 fuzzy 语义用例——`PII_FUZZY_RESTORE` 关闭时大小写漂移不还原（精确原样保留）、开启时按序号回查还原；对照 Python `tests/vault_stable_test.py:132-167` 两用例
  - 验证：`cargo test -p veil fuzzy_` 通过；关闭与开启两态断言与 Python 语义一致
  - 验证：`grep -n "fuzzy" src/service/redaction/scope_tests.rs` 命中新增用例名
- [x] 1.2 三包装器 nasty 值测试：token 脱敏/还原、PII 脱敏、LLM 响应还原三条 JSON-aware 路径处理含引号密码、Unicode 转义、嵌套 stringified JSON、数组成员后，输出 SHALL 经 `serde_json` 解析合法且还原字段值一致；落 `src/service/json_walk.rs`（测试）与 `src/service/redaction/scope_tests.rs`
  - 验证：`cargo test -p veil three_wrappers_nasty` 通过；每步 `serde_json::from_str` 成功且断言还原值
  - 验证：无 `unwrap()` panic 路径；非法输入回退路径有独立断言
- [x] 1.3 三校验器回退契约测试：`src/service/json_walk.rs:36` 的 `validate_json_roundtrip` 对「合法原文 + 非法输出」返回原文、「非 JSON 原文 + 任意输出」返回输出，补参数化用例
  - 验证：`cargo test -p veil validate_roundtrip_contract` 通过；两组四断言全绿
  - 验证：`PII_FUZZY_RESTORE` 非法值（非真值）口径差异在 design Open Questions 有登记并引用 A7

## 2. `G2` 审计规范化专项（联 `veil-audit-rules-parity` A5）

- [x] 2.1 `src/service/audit/normalize.rs` 与 `rules.rs` 测试模块补五类专项用例：转义、管道优先级、`../` 归一、`find` 泛洪、别名 rm（`/bin/rm` 与 `rm -rf`）；期望值以 A5（该 change task 5.x）落地实现为准，A5 未落地时以「待锁定」注释显式引用其 task
  - 验证：`cargo test -p veil normalize_args_` 通过；五类输入各有独立用例名与断言
  - 验证：`grep -rn "待锁定" src/service/audit/` 在 A5 合入后清零（A5 合入后执行）
  - 验证：与 A5 的实现测试不重复：本组只保留端到端「输入→归一→判定」用例

## 3. `G3` 审计环境降级语义（联 `veil-audit-rules-parity` A7）

- [x] 3.1 `src/service/audit/verdict.rs` 补 `audit_enabled_compat` 表驱动测试：真值集 `1/true/yes/on`（trim + 大小写不敏感）→ `Block`；显式非空 `AUDIT_MODE` 优先（返回 `None`）；非真值/空白不生效
  - 验证：`cargo test -p veil audit_enabled_compat` 通过；真值/显式优先/非真值三组断言全绿
  - 验证：`grep -n "audit_enabled_compat" src/service/audit/verdict.rs` 命中测试模块
- [x] 3.2 补 `evaluate_with_whitelist` 的 `Approve` 空白名单降级用例：降级 `Block`、审计仍启用、error 日志触发（可用 tracing 测试订阅或等价副作用断言）
  - 验证：`cargo test -p veil approve_empty_whitelist_degrades` 通过；危险工具在降级后按 `Block` 处理
  - 验证：与 A7 结论互引：A7 定启动门禁口径，本用例只锁判定入口防御
- [x] 3.3 初始化期不建任务回归：断言同步构造路径不 spawn 审批清扫任务（`src/approval.rs` 的 `spawn_sweeper` 仅在异步运行路径调用），补等价测试或在 design 登记结构差异
  - 验证：`cargo test -p veil init_no_sync_sweeper` 通过，或 design 有结构差异登记与替代断言
  - 验证：`grep -rn "spawn_sweeper" src/` 命中调用点均在异步运行路径（人工核对记录）

## 4. `G4` PII 值采样持久化取证（联 `veil-pii-parity-closeout` P11）

- [x] 4.1 以 `tests/observability_pii_value_test.py` 的 18 例为清单逐例映射到 `src/service/metrics/sample/tests.rs` 与 `src/service/metrics/store/tests.rs`：7 天滚动、`PERSIST` 热切换 1→0、跨天 topn、same-masked 合并、401 不泄漏；未映射项显式列出并转出
  - 验证：`cargo test -p veil pii_value_sample` 通过；滚动/热切换/合并/401 各有独立用例
  - 验证：持久化行断言仅掩码 + hash、不含明文（构造性断言）
  - 验证：18 例清单在 tasks 或 design 可逐例勾选；未映射项有转出记录

## 5. `G5` KeePass 解锁交互路径

- [x] 5.1 `src/service/credential/approval.rs` 补解锁超时与并发单问：`approval_dual_mode` 超时按拒绝（`VeilError::Auth`）、并发触发仅一次问询且结果复用
  - 验证：`cargo test -p veil unlock_timeout_single_ask` 通过；并发计数断言恰一问询
  - 验证：`cargo test -p veil --test http_e2e_credential_approval` 全绿
- [x] 5.2 raw 上下文与 ask 失败：`use_token` 语义直连拒绝/脚本放行；ask 发送失败不悬挂、返回按拒绝处理
  - 验证：`cargo test -p veil raw_context_and_ask_failure` 通过；两场景断言状态码与不悬挂
  - 验证：`grep -n "use_token" src/service/credential/vault_ops.rs` 命中测试覆盖调用点
- [x] 5.3 双表清理一致性：解锁被拒/超时/ask 失败后内存 pending 与矩阵 pending 两表清理一致（对照 Python `tests/credential_test.py:721`）
  - 验证：`cargo test -p veil pending_both_tables_cleanup` 通过；两表计数断言一致
  - 验证：`cargo test -p veil --test http_e2e_approval` 全绿

## 6. `G6` detection hardening 开关矩阵（联 `veil-pii-parity-closeout` P13）

- [x] 6.1 开关矩阵测试：默认关/真值开/非真值关三态探测结果对应；非真值不拒启动为 Rust 现行行为并登记
  - 验证：`cargo test -p veil hardening_toggle_matrix` 通过；三态断言全绿
  - 验证：`grep -n "PII_DETECTION_HARDENING" src/config/env_parse/tests.rs` 命中矩阵用例
- [x] 6.2 开启态行为测试：ASCII 粘连拒绝、前导零 IPv4 丢弃、CJK 边界不误伤、analyzer 缓存复用（调用计数或同产物断言）
  - 验证：`cargo test -p veil hardening_boundary_and_cache` 通过；四断言全绿
  - 验证：与 P13（该 change task 14.x）结论互引，测试期望值与其核验一致

## 7. `G7` debounce 与模型冒号解析

- [x] 7.1 `src/service/metrics/aggregate.rs` 测试补 `normalize_model` 冒号版本用例：`gpt-4o:2024-08-06` 进入模型分桶且不归 `unknown_model`（对照 Python `tests/redact_extra_test.py:194-208`）
  - 验证：`cargo test -p veil model_with_version_colon` 通过；分桶键断言精确匹配
  - 验证：既有归一用例（空归 `unknown_model`、控制字符剔除）无回退
- [x] 7.2 `src/service/metrics/store/tests.rs` 补 flush 幂等/窗口用例：重复 flush 覆盖式 UPSERT 不翻倍、批量驱动窗口不丢行；同时在 design 登记「Rust 无 Python 2s 去抖、以事件驱动批量替代」为等价语义
  - 验证：`cargo test -p veil flush_idempotent_window` 通过；两次 flush 后计数不变、窗口行数一致
  - 验证：`grep -n "2s 去抖\|去抖" openspec/changes/veil-docs-test-coverage-closeout/design.md` 命中差异登记

## 8. `G8` 弱断言测试加强

- [x] 8.1 `src/service/sse.rs`：`push_bytes` 用例补重组语义断言（多行 data 合并、跨块 UTF-8 拼接后完整文本），不再仅断言帧数/切分
  - 验证：`cargo test -p veil sse_` 通过；新增断言语义值而非长度
- [x] 8.2 `src/service/json_walk.rs:177,197,261`：在 JSON 合法断言之外补脱敏替换后的具体值断言
  - 验证：`cargo test -p veil json_walk` 通过；三处 `is_ok()` 旁均有值断言
- [x] 8.3 `src/handler/llm/dispatch.rs:384`：补 `to_bytes` 结果体断言（内容与长度），不再仅 `ok.is_ok()`
  - 验证：`cargo test -p veil oversized_body` 通过；结果体字节断言到位
- [x] 8.4 `src/service/admin/ratelimit.rs:72,77,121,130`：补 429 阈值、`Retry-After` 取值与窗口滚动断言；窗口测试优先提取纯函数或注入时钟，生产语义不变
  - 验证：`cargo test -p veil rate_limit_` 通过；第 11 次与窗口滚动断言全绿
  - 验证：生产代码无时序行为变更（diff 仅测试或纯函数提取）
- [x] 8.5 `tests/http_e2e_metrics_snapshot.rs:99`：补先写入已知事件后的非空窗业务值断言（`requests`/协议分桶），保留空窗 shape 用例
  - 验证：`cargo test -p veil --test http_e2e_metrics_snapshot` 通过；非空窗业务值精确断言
- [x] 8.6 `src/config/env_parse/tests.rs:62`：补关键转发路径断言（`HTTP_TIMEOUT_SECS` 等 getter 到运行时配置的映射）
  - 验证：`cargo test -p veil http_client_defaults` 通过；转发路径字段逐一断言
- [x] 8.7 `file_len_under_800_or_split` 元测试保留；在 `scripts/README.md` 注明其为文件大小守护、非行为覆盖
  - 验证：`grep -n "非行为覆盖\|文件大小守护" scripts/README.md` 命中
  - 验证：`cargo test -p veil file_len_under_800_or_split` 仍通过

## 9. `G9` README/scripts 路径与口径修正

- [x] 9.1 `README.md:26` §1：为「未列出的变量二进制不读取」加例外注——审计 `$VAR`/`${VAR}` 进程 env 展开（`src/service/audit/normalize.rs:170,188`）与 `~/` 读 `HOME`（`src/service/audit/rules.rs:137`）
  - 验证：`grep -n "HOME\|normalize.rs" README.md` 命中例外注与证据引用
- [x] 9.2 `README.md:230` §4.1：`OLD_HASH_GRACE_SECS` 来源由 `src/registry.rs` 更正为 `src/registry/entry.rs`
  - 验证：`grep -n "OLD_HASH_GRACE_SECS" README.md` 命中 `src/registry/entry.rs`
- [x] 9.3 `README.md:63`/`:98`：`VEIL_ALLOW_MOCK_TPM` 口径写明 trim 后等于字面 `1`（`src/service/tpm.rs:227`）
  - 验证：`grep -n "VEIL_ALLOW_MOCK_TPM" README.md` 两处均含 trim 口径
- [x] 9.4 `scripts/README.md`：补 `go_interop_e2e.py` 条目（用途/14 项规模/用法/前置）
  - 验证：`grep -n "go_interop_e2e" scripts/README.md` 命中
  - 验证：`python3 scripts/check_doc_paths.py` 退出 0

## 10. `G10` 未文档化行为补录

- [x] 10.1 README 补 `AUTO_APPROVE` 别名集（`1/yes/0/no/pending/matrix`，`src/config/env_parse.rs:99-108`）
  - 验证：`grep -n "pending\|matrix" README.md` 在 AUTO_APPROVE 段命中别名
- [x] 10.2 README 补管理面 Cookie：`__Host-admin_token` 优先、回退 `admin_token`、Set-Cookie 签发条件（`src/handler/admin.rs:42-64,115-148`）
  - 验证：`grep -n "admin_token\|Set-Cookie" README.md` 命中 Cookie 与签发说明
- [x] 10.3 README 补 SSE `?model=&upstream=` 建连过滤与近环回放（`src/handler/admin.rs:433-476`）
  - 验证：`grep -n "近环回放\|model.*upstream" README.md` 命中过滤说明
- [x] 10.4 README 补 SSE 并发超限 `Retry-After: 60`（`src/handler/admin.rs:459-463`）
  - 验证：`grep -n "Retry-After" README.md` 在 SSE 并发段命中 60
- [x] 10.5 README 补 `/_admin/health` 豁免实现细节（`src/service/admin/ratelimit.rs:21` 唯一豁免项、不占桶）
  - 验证：`grep -n "admin_rate_exempt_paths\|豁免" README.md` 命中实现细节

## 11. `G11` 阻塞审批超时码差异（BREAKING 补充）

- [x] 11.1 README §5（`:268`）与 §6.7（`:351-359`）明示 `CREDENTIAL_BLOCK_WAIT=1` 超时相对 Python 408 的 403 归并差异（`src/service/credential/approval.rs:83-85`；Python `_credential.py:433`），列入迁移注意项
  - 验证：`grep -n "408" README.md` 命中差异明示；`grep -n "超时" README.md` 在 §5/§6.7 段落含 403 归并表述
- [x] 11.2 测试锁定：阻塞超时用例断言 403 且不悬挂（复用 5.1 用例或新增）
  - 验证：`cargo test -p veil blocked_timeout_403` 通过；状态码断言为 403
  - 验证：若 credential-flow-parity 对审批链另有裁决，引用其结论并在 design 记录

## 12. `G12` 有意差异登记（核验档）

- [x] 12.1 design D12 登记表复核：11 项差异逐项可追溯（差异项/语义/归属/证据），跨 change 项只引用不重复裁决
  - 验证：`grep -n "D12" openspec/changes/veil-docs-test-coverage-closeout/design.md` 命中登记表
  - 验证：`grep -n "C11\|C12\|C13\|C15\|C16\|P5\|P6\|P7\|P8" openspec/changes/veil-docs-test-coverage-closeout/design.md` 命中交叉引用
- [x] 12.2 归属 change 引用有效性：引用的归属 change 文件与 task 号存在（`veil-credential-flow-parity` 与 `veil-pii-parity-closeout`）
  - 验证：`ls openspec/changes/veil-credential-flow-parity/tasks.md openspec/changes/veil-pii-parity-closeout/tasks.md` 均存在
  - 验证：归档审计可按登记表逐项复核，无平行裁决

## 13. `G13` README 声明核验落档

- [x] 13.1 design D13 核验表逐条复核补全：§6/§7 每条声明对应代码锚点（文件:行）与结论，apply/归档前更新到最终行号
  - 验证：`grep -n "D13" openspec/changes/veil-docs-test-coverage-closeout/design.md` 命中核验表
  - 验证：表格条目数与 README §6/§7 小节数一致，无遗漏声明
- [x] 13.2 偏差转出规则：核验发现的新偏差按归属 change 登记或转出，不静默修正
  - 验证：design 风险段含「新偏差转出」条目；如有发现，`grep -rn "转出" openspec/changes/veil-docs-test-coverage-closeout/` 命中记录

## 14. 门禁与归档准备

- [x] 14.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 14.2 `python3 scripts/check_doc_paths.py` 退出 0（README 与 spec 引用路径全部存在）
  - 验证：命令输出 OK，无 FAIL 项
- [x] 14.3 `openspec validate veil-docs-test-coverage-closeout --strict` 0 failures
  - 验证：命令输出 is valid
- [x] 14.4 README/scripts 与 spec 同批终检：G9–G11 口径一致、无旧表述残留
  - 验证：`grep -n "src/registry.rs" README.md` 在 §4.1 无 OLD_HASH 旧来源残留
  - 验证：G1–G13 每项至少一个 task 验证命令可复现
