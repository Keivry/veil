## 1. `A1` 审计日志落盘接线

- [x] 1.1 `src/service/audit/log.rs:167-245` + `src/handler/llm/pump/spawn.rs` + `src/handler/llm/nonstream.rs`：将 `AuditLogger` 接线到流式/非流式 verdict 命中与放行路径，启动期构造单例（`AppState` 持 `Arc<AuditLogger>`），写盘经 `spawn_blocking`（`log_event` 含同步 fs + 50ms sleep）；不保留零调用死码
  - 验证：`grep -rn "AuditLogger" src/ --include="*.rs"` 生产调用点 ≥1（非 `src/service/audit/log.rs` 自身与单测）；`cargo test -p veil audit_log_wired` 通过
- [x] 1.2 落盘语义回归：JSONL、先脱敏后截断、剥 `\x00-\x1f`、0600、10MB×5 轮转
  - 验证：`cargo test -p veil audit_log_mode_0600_with_breaker_count` 与新增 `cargo test -p veil audit_log_rotate_five` 通过；轮转后断言 `audit.log.1` 生成且份数上限 5
- [x] 1.3 写失败语义按 `A9`/D8 收敛（deny 保持结论 + error、allow 不阻断 + 熔断计数）
  - 验证：`cargo test -p veil audit_log_fail_semantics` 通过；两路径断言与计数阈值一致
- [x] 1.4 审计事件同步推 `AdminState` 事件环（`kind="audit"`；联动 `A10`/D9；`push_event` 生产接线补齐）
  - 验证：`cargo test -p veil audit_event_ring_visible` 通过；`query_events(Some("audit"))` 可见命中事件

## 2. `A2` PII 锁中毒交叉引用（记录，无代码改动）

- [x] 2.1 proposal Non-Goals、design D16 与覆盖表登记 A2 由 `veil-pii-parity-closeout` P14 负责，本 change 不改 `src/service/pii/`（替代实现指引 `recover_mutex`）
  - 验证：`grep -rn "veil-pii-parity-closeout" openspec/changes/veil-audit-rules-parity/` 命中；apply 阶段 `git diff --name-only` 不含 `src/service/pii/`

## 3. `A3` 摘要脱敏形态补齐

- [x] 3.1 `src/service/audit/log.rs:42-158`：补齐 Bearer（含 JWT）、私钥 PEM、身份证、手机、邮箱、`pwd`/`access_key`/`auth_key`/`secret_key`/`private_key` 键值对与 `glpat-`/`ghs_`/`ghu_` 前缀；值段不跨 JSON 字段贪吃、前后不粘数字
  - 验证：`cargo test -p veil audit_summary_forms` 通过；各形态样本输出含对应 `[REDACTED:<type>]` 且不含明文
- [x] 3.2 截断口径登记（`AUDIT_SUMMARY_TRUNCATE_CHARS` 4096 vs Python 120，R4 既有裁决不重开）并保持先脱敏后截断 + UTF-8 安全
  - 验证：`grep -n "R4" openspec/changes/veil-audit-rules-parity/design.md` 命中断口差异登记；`cargo test -p veil summary_redacts_before_truncation_utf8_safe` 通过
- [x] 3.3 零明文样本测试：手机/身份证/邮箱/Bearer/JWT/私钥六类
  - 验证：`cargo test -p veil audit_summary_zero_plaintext` 通过；断言六类样本均无明文残留

## 4. `A4` 危险规则集补齐

- [x] 4.1 `src/service/audit/rules.rs:36-88/144-154`：补 `shutdown`/`reboot`/`poweroff`、`base64`/`openssl` 解码（`-d`/`decode`/`decrypt`）、`telnet`/`ssh` 网络传输、`rm -rf` 任意目标词形、`chmod`/`chown` 系统目录形态、敏感路径 `/boot/`；维持 O(n) 子串无回溯
  - 验证：`cargo test -p veil audit_rule_parity` 通过；九条语义面逐条样本命中
- [x] 4.2 与 Python 正则近似差异（`dd ` 裸词偏严、组合近似）在 design D3 登记；逐规则独立测试
  - 验证：`cargo test -p veil audit_rules_each` 通过；`cargo test -p veil audit_rules_no_backtracking` 通过

## 5. `A5` 规范化管线等价

- [x] 5.1 `src/service/audit/normalize.rs:248-254`：管线重排为 转义 → 空白 → `..` 归一 → 单层变量（参数文本赋值挖掘，去除 `std::env::var` 隐式回退）→ 拆链 → 别名折叠（`/bin/` 前缀、`find -delete` → `rm -rf`，O(n) 定位）
  - 验证：`cargo test -p veil audit_normalize_pipeline` 通过；`CMD=rm;$CMD -rf /tmp`、`/bin/rm -rf /etc/x`、`find /tmp -delete` 三者均命中
- [x] 5.2 构造性绕过测试（≥3 类：文本赋值引用、别名折叠、`..` 全管线）
  - 验证：`cargo test -p veil audit_bypass_constructive` 通过

## 6. `A6` 内外网判定偏严声明

- [x] 6.1 保留 `src/service/audit/rules.rs:204-226` 偏严语义并用测试锁定：RFC1918/环回/链路本地字面量非内网、空/`None` host 不豁免、`localhost`/`.local`/`.internal`/`internal_suffixes` 豁免
  - 验证：`cargo test -p veil audit_internal_host_strict` 通过；四类目标断言符合 spec
- [x] 6.2 README §6 新增 BREAKING 条目（IP 字面量一律非内网，与原仓 `is_external_host` 差异 + `internal_suffixes` 豁免指引）
  - 验证：`grep -n "IP 字面量" README.md` 命中 §6 条目

## 7. `A7` 开关真值集与非法值 fail-closed

- [x] 7.1 `src/config/validate.rs:62-67` + `src/service/audit/verdict.rs:31-39`：真值集 `1/true/yes/on`（trim + 大小写不敏感）、显式非空 `AUDIT_MODE` 优先、空白回退映射 `block`；表驱动测试
  - 验证：`cargo test -p veil audit_enabled_truthy_table` 通过
- [x] 7.2 `src/config/validate.rs:217-240`：非法 `AUDIT_TIMEOUT`（0/负/110-130）与 `AUDIT_HOLD_MAX_BYTES`（0/非整数）拒启动测试
  - 验证：`cargo test -p veil audit_invalid_env_rejects` 通过
- [x] 7.3 README §6 BREAKING 登记真值集更宽与非法值拒启动差异（联动 `A17`）
  - 验证：`grep -n "AUDIT_ENABLED" README.md` 命中 §6 条目；`grep -n "110-130" README.md` 命中非法值说明

## 8. `A8` 策略文件对象形兼容

- [x] 8.1 `src/service/audit/policy.rs:52-166`：`dangerous:` 段支持对象形 `{pattern, reason, network}`（YAML mapping 与 JSON 对象，缺省 `network=false`），与字符串形并存，统一构造 `DangerRule`
  - 验证：`cargo test -p veil audit_policy_object_form` 通过；`network=true` 命中走外部 host 复核
- [x] 8.2 旧 Python 策略文件（四键 + 对象形 dangerous）加载迁移测试
  - 验证：`cargo test -p veil audit_policy_legacy_file` 通过
- [x] 8.3 fail-closed 语义保持（不可读/未知键/孤儿项/非法 mode 拒启动）并在 README §6 登记与原仓差异
  - 验证：`cargo test -p veil invalid_policy_file_fails_at_startup` 通过

## 9. `A9` 写失败双层语义

- [x] 9.1 `src/service/audit/log.rs:186-206` + 调用方：`Block`/`NeedApproval` 路径写失败保持结论 + error 告警；`Allow` 路径写失败不阻断 + 连续失败计数，达 10 次 critical 告警并重置
  - 验证：`cargo test -p veil audit_log_write_fail_semantics` 通过；两条路径断言与阈值一致
- [x] 9.2 故障注入测试（只读目录/不可写路径）覆盖 allow 与 deny 两路径及熔断计数
  - 验证：`cargo test -p veil audit_log_write_fail_injection` 通过

## 10. `A10` 审计事件内存环

- [x] 10.1 design D9 裁决落档：复用 `src/service/admin/state.rs` 事件环（`EVENT_RING_CAP=512`、FIFO、`query_events`、SSE 回放），不新增专用 100 环；接线随 1.4
  - 验证：`grep -n "EVENT_RING_CAP" openspec/changes/veil-audit-rules-parity/design.md` 命中裁决
- [x] 10.2 容量/FIFO/查询/SSE 回放测试（推入超容量事件，断言淘汰最旧、顺序保持、`query_events(kind="audit")` 与建连回放可见）
  - 验证：`cargo test -p veil admin_event_ring_capacity_order` 通过

## 11. `A11` SSE metrics 周期快照

- [x] 11.1 `src/handler/admin.rs:438-508`：流内每 15s 推 `event: metrics`，data `{range, model, upstream, metrics, series, health}`；复用 `/_admin/metrics`、`/_admin/series`、`/_admin/health` 服务口径；取数失败降级 `*_unavailable`；不中断事件推送与 60s ping
  - 验证：`cargo test -p veil admin_sse_metrics_snapshot` 通过；六键形状与过滤字段断言
- [x] 11.2 消息形状与降级测试（查询失败、无过滤、带 `model`/`upstream` 过滤三场景）
  - 验证：`cargo test -p veil admin_sse_metrics_degraded` 通过

## 12. `A12` MXID 校验拒绝多点 @

- [x] 12.1 `src/config/validate.rs:267-276` 与 `src/service/matrix/branch.rs:67-76` 同步增加「`@` 后不得再含 `@`」并保持两处语义一致；边界样本表驱动测试（`@a@b:c` 拒、`@admin:example.com` 过、缺段/空白拒）
  - 验证：`cargo test -p veil mxid_reject_multiple_at` 通过；`cargo test -p veil mxid_valid_forms` 通过

## 13. `A13` deny 优先级与注释

- [x] 13.1 `src/service/audit/rules.rs:276-282`：修正注释为「deny 精确匹配即终判、不进入危险内容判定；allow 免责仅在无危险内容时成立」（findings 标注 `verdict.rs`，以实际代码为准）
  - 验证：`grep -n "终判" src/service/audit/rules.rs` 命中；注释与 `is_dangerous` 早返实现一致
- [x] 13.2 deny 优先级锁定测试（deny+allow 同名 → deny 胜且原因为名单原因；deny 命中不因危险内容改判；allow 名单内危险内容仍拦）
  - 验证：`cargo test -p veil deny_priority_lock` 通过

## 14. `A14` `find` 预检补齐

- [x] 14.1 `src/service/audit/rules.rs:230-274`：预检覆盖 tool 名 `find` 与参数前缀 `find `/`-exec`/`-delete`/`--delete`（含 JSON 包装形）
  - 验证：`cargo test -p veil audit_precheck_find` 通过；`find /etc -exec rm` 返回 true
- [x] 14.2 误报边界测试：`find /tmp -name '*.log'` 不因普通 `find` 误暂停（无 `-exec`/`-delete` 时按既有判定）
  - 验证：`cargo test -p veil audit_precheck_find_no_false_positive` 通过

## 15. `A15` 启动校验顺序

- [x] 15.1 `src/main.rs:62-117`：显式白名单门禁前移至 TPM 门禁之前（`Config::from_env`/`env_parse.rs:485-491` 为第一真源，A12 同步修复）；保证校验失败不触盘/网
  - 验证：`cargo test -p veil startup_whitelist_fail_fast` 通过；非法白名单下断言 TPM 未调用、数据目录未创建、后台任务未启动
- [x] 15.2 校验真源与 `src/service/matrix/branch.rs::validate_whitelist_mxids` 语义一致性测试（两处同结论）
  - 验证：`cargo test -p veil whitelist_validator_parity` 通过

## 16. `A16` Cookie https 双判据

- [x] 16.1 `src/handler/admin.rs:135-148`：`X-Forwarded-Proto: https` 或 RFC 7239 `Forwarded` 内 `proto=https`（大小写不敏感）任一命中 → `__Host-admin_token; Secure; Path=/`，否则 http 兼容 `admin_token`
  - 验证：`cargo test -p veil admin_cookie_https_criteria` 通过；两判据与缺失降级三场景断言
- [x] 16.2 README 反代指引声明必须透传协议头（否则 Secure Cookie 降级为 http Cookie）
  - 验证：`grep -n "Forwarded" README.md` 命中协议头透传声明

## 17. `A17` 既有非目标与分歧登记

- [x] 17.1 design D17 与覆盖表登记不重复修复项：管理静态页 Non-Goal、流式审批同步阻塞 §6.4、轻量入口 §8.4、管理限流 §3、HOP 8 项 §7.1
  - 验证：`grep -n "A17" openspec/changes/veil-audit-rules-parity/design.md` 命中
- [x] 17.2 `AUDIT_MODE` 非法值拒启动随 `A7` 决策在 README §6 落档 BREAKING
  - 验证：`grep -n "A17" openspec/changes/veil-audit-rules-parity/proposal.md` 与 README §6 条目同批存在
- [x] 17.3 `A18` design D18 登记 metrics 时序口径等价映射（`src/service/admin/events.rs:6`：`1h→five_min`；Python `1h 分钟级 60 点/24h/7d/30d`）并补桶边界/映射回归
  - 验证：`cargo test -p veil metrics_series_timeframe_mapping` 通过；`five_min/hourly/daily` 聚合与旧 key 映射数值等价
- [x] 17.4 `A19` design D19 登记 events 过滤扩展（`src/handler/admin.rs:392-431`：新增 `since`；`verdict` 归一后按环内 kind 过滤；`model`/`upstream` 仅回显）并补 `limit` 边界与过滤语义回归
  - 验证：`cargo test -p veil admin_events_filter_semantics` 通过；`limit` 1/200 边界与 `kind/since/verdict` 组合过滤符合登记

## 18. 门禁与回归

- [x] 18.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test` 全绿
  - 验证：三条命令退出码 0；新增测试全绿、无既有测试回退
- [x] 18.2 `openspec validate veil-audit-rules-parity --strict` 0 failures
  - 验证：命令输出 `is valid`
- [x] 18.3 `python3 scripts/check_doc_paths.py` 与 `python3 scripts/check_file_sizes.py` 退出码 0
  - 验证：两条命令无 FAIL、无超 800 行文件
