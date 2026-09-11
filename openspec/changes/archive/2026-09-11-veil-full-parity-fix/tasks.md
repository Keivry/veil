## 1. 全局单例与三因子（P0）

- [x] 1.1 Vault/Detector 全局单例 + 网关快照透传 + 版本缓存，验证：同秘密跨请求同 token 且网关可还原
- [x] 1.2 三因子解耦（header/secret/caller 独立）+ 纯 body 兼容，验证：Go 正常脚本 200 而非 202
- [x] 1.3 `--raw` 补 use_token 条件 + 死分支重排（先查 enabled），验证：终端 token 取用放行、吊销拒绝可达
- [x] 1.4 凭据审批双模 `CREDENTIAL_BLOCK_WAIT` 300s 阻塞，验证：阻塞模批准同请求返回凭据、默认仍 202

## 2. 网关结构修复（P0，7 步）

- [x] 2.1 `responses.instructions` 注入 + input string|array 分流 + schema 回退，验证：instructions 含 PII 被脱敏且结构不变
- [x] 2.2 `restored_spans` 跳过防二次掩码，验证：请求明文往返不变
- [x] 2.3 非流补 tool 提取 + 审计 + block 体，验证：非流危险调用被拦
- [x] 2.4 Anthropic 取外层 index 分桶，验证：多 tool 交错不串桶
- [x] 2.5 完成标记按 index 清槽（删全局误标 + 不可达分支），验证：第二 tool 不逃逸
- [x] 2.6 BOM/DONE/残余/dedupe 终端去重，验证：BOM 流恰一终止帧
- [x] 2.7 usage 统一 max + 文档化 + json_walk 深炸弹守卫，验证：usage 不双计、超深嵌套不崩

## 3. 注册表与审批链（P1）

- [x] 3.1 空 entry/field 转审 + 同 hash 多 path 允许，验证：未知字段转审、双脚本同值均注册成功
- [x] 3.2 Python 注册表迁移工具（.bak），验证：旧格式启动后仍有效
- [x] 3.3 lock 全清 + status/forget 文案 + 注册审批链（或 BREAKING 声明），验证：lock 后无残留

## 4. 审计 parity（P1）

- [x] 4.1 allow/deny 名单 + internal_suffixes + host 提取 + precheck + MXID + AUDIT_ENABLED 兼容 + 策略全形态，验证：allow 放行、内网不判外传；`AUDIT_ENABLED` 回退接线证据：`Config::load_from`（`src/config/env_parse.rs`）在 `AUDIT_MODE` 缺失/空白时调用 `audit_enabled_compat`（`src/service/audit/verdict.rs`），真值 `1/true/yes/on` → `block`（change `veil-config-legacy-compat`）
- [x] 4.2 日志口径对齐（先脱敏后截断 + 异常占位符），验证：强化层异常零明文
- [x] 4.3 hold 判定清理 + decide 落实，验证：增量未收齐不放行

## 5. PII parity（P1）

- [x] 5.1 fuzzy 回 IGNORECASE + hardened 补 CJK/前缀/ReDoS/lru，验证：变体还原 + 保留段豁免
- [x] 5.2 自定义放宽 + 字典独立扫描 + 三槽叠加，验证：三文件同时生效
- [x] 5.3 掩码六分支 + 占位符关闭对齐，验证：bank 掩码形态正确

## 6. 指标与管理面（P1）

- [x] 6.1 桶改回 12 桶 + Usage 三列 + 表列/滚动/回填 + redact_summary + is_precise/p95，验证：曲线可比、低流量标≈
- [x] 6.2 health 豁免 + Cookie 回退/Set-Cookie + admin_token 文件 + DISABLE/dev（或 BREAKING）+ SSE 快照/过滤，验证：health 不被误伤、非 SSE query 恒 401

## 7. 入口与传输（P1）

- [x] 7.1 选路透端口上下文或删死代码 + 多端口/轻量声明，验证：8878 入口命中对应上游或文档明确
- [x] 7.2 mlockall + secret 恒时比较 + TPM 30s/stderr/探测声明 + KeePass 首条/解锁判定 + HOP/DEBUG_DIR/紧急吊销/registrations 声明，验证：mlock 失败 warn 启动、变长比较恒时

## 8. 测试闭环

- [x] 8.1 新增 3 HTTP E2E（truncation/audit_approve/sse_loop 含 CR-only/空行/多 data），验证：三文件全绿
- [x] 8.2 补空流 hold 矩阵 + 并发隔离 + 单 ask + 观测持久（滚动/0600/不建表/401），验证：对应用例全绿
- [x] 8.3 收紧 10 弱断言（ReDoS 真超时/性能秒级/is_precise/p95/帧序列/DONE 精确/嵌套强断言/采样全矩阵），验证：放水实现必红

## 9. 文档与终验

- [x] 9.1 修正三源漂移（HOP/超时/桶/限流/掩码/fuzzy/叠加/usage）+ 注释异味，验证：新人按文档启动零漂移
- [x] 9.2 全量 `cargo test` + `scripts/api_conformance.py` + 文档-契约比对，验证：三协议全过、漂移零项
