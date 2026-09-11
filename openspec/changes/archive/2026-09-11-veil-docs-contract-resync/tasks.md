> 本 change 为规划交付：以下任务在 apply 阶段执行，规划期不改 README/compose/scripts、不改 `src/`、不改既有 change、不提交 commit。验证均为只读命令或文本断言；每任务至少两条 `Verify:`。与 `veil-gateway-fidelity-fix` 重叠的 README §7.7/§7.1 同段落按「先落地者写实、后到者只读复核、不重复编辑同一行」串行合入。

## 1. DOC1：compose 注释与 README 同字

- [x] 1.1 `docker-compose.yml` 三因子注释段（当前 `:18`）改为与 `README.md:32` 同字：`GET_BINARY_HASH` 独立生效（置位时拒绝调用方冒用 get 自身哈希的直调；为空时该检查兼容跳过），与 `GET_BINARY_SECRET` 无联动；两者均为空为兼容模式。不改 README（已正确）。
  - Verify: `grep -n "须同时设置" docker-compose.yml` 零命中
  - Verify: `grep -n "独立生效" docker-compose.yml` 与 `grep -n "无联动" docker-compose.yml` 均命中三因子注释段
  - Verify: `grep -n "独立生效" README.md` 命中 `:32` 表行，两侧语义逐义一致（只读对照）

## 2. DOC2：README §7.7 文本对齐与指向（行为归 `veil-gateway-fidelity-fix`）

- [x] 2.1 改写 README §7.7：删除「纯脱敏子串替换（字节级，未重序列化）与原文透传不置位」不实表述；改为「JSON 容器内的脱敏替换经 `json_walk` loads→walk→dumps 紧凑重序列化（`scope.rs::redact_request`），重序列化即属 `x-veil-normalized` 合理置位场景；当前纯脱敏替换分支未置位的合同缺口由 change `veil-gateway-fidelity-fix`（H1）修复」；原文透传（零替换）不置位的既有语义保留。
  - Verify: `grep -Fn "字节级，未重序列化" README.md` 零命中
  - Verify: `grep -n "重序列化" README.md` 命中 §7.7，且 `grep -n "veil-gateway-fidelity-fix" README.md` 命中同一段落
  - Verify: 与 `veil-gateway-fidelity-fix` tasks 8.1 的 §7.7 同步按「先落地者写实、后到者只读复核、不重复编辑同一行」串行；若该 change 已落地并改毕 §7.7，本任务降级为只读复核（旧断言零命中 + 置位口径与实现同字 + 指向正确），不重复编辑
- [x] 2.2 design 边界复核（防双改）：确认本 change 不改 `scope.rs`/`rewrite.rs`/`json_walk.rs`，行为修复责任记录在 `design.md` D2（文本归本 change、行为归 `veil-gateway-fidelity-fix`）。
  - Verify: `grep -n "veil-gateway-fidelity-fix" openspec/changes/veil-docs-contract-resync/design.md` 命中 D2 边界声明（谁改文本、谁改行为）
  - Verify: apply 后 `git diff --name-only` 不含 `src/service/redaction/scope.rs`、`src/handler/llm/rewrite.rs`、`src/service/json_walk.rs`

## 3. DOC3：spec 引用纳入 `check_doc_paths.py` 门禁

- [x] 3.1 扩展 `scripts/check_doc_paths.py`：在 `src/*.rs` 之外新增 spec 引用校验（匹配 `openspec/(changes/<change>/specs/<capability>|specs/<capability>)/spec.md` 完整路径并断言存在；沿用 `（勘误：...）` 剔除与 `<!-- doc-paths-ignore -->` 跳过机制；输出报告 spec 引用计数）。
  - Verify: `python3 scripts/check_doc_paths.py` 退出码 0，且输出含 spec 引用校验计数（>0）
  - Verify: `grep -n "spec\\\\.md" scripts/check_doc_paths.py` 命中新增正则；`grep -n "doc-paths-ignore" scripts/check_doc_paths.py` 机制保留
- [x] 3.2 README:5/203 引用复核：`veil-hardening` 未归档期间保持完整 change-local 路径 + 「未归档」标注；登记归档后迁移为 canonical `openspec/specs/admin-ratelimit-contract/spec.md` 并由同一门禁保证不悬空。
  - Verify: `grep -n "admin-ratelimit-contract" README.md` 两处均含 `openspec/changes/veil-hardening/specs/` 完整路径与「未归档」字样，零裸名引用
  - Verify: `openspec list --json | grep -A2 '"name": "veil-hardening"'` 显示 `in-progress`（归档未发生，路径保持 change-local 为预期）
  - Verify: 负向用例：临时把 README 一份副本中的该路径改为不存在路径并跑脚本（或在脚本内加入自测断言），脚本对悬空 spec 引用非零退出；恢复后重跑退出码 0

## 4. DOC4：README §1/§3 补管理面路径语义

- [x] 4.1 README §1「管理控制台说明」增条：`/_admin`（无尾斜杠）与 `/_admin/` 注册为同一索引 handler，均返回 200 JSON 索引（`src/router.rs` 双路由注册；`/_admin/{*rest}` 未知子路径仍 404）。
  - Verify: `grep -n "无尾斜杠" README.md` 命中 §1 新增条
  - Verify: `grep -n "route(\\"/_admin" src/router.rs` 命中 `/_admin/` 与 `/_admin` 两条注册（只读证据核对）
- [x] 4.2 README §3「限流规则」增条：`/_admin/health` 豁免通用 `10/min` 限流（存活探针高频；豁免集为 `src/service/admin/ratelimit.rs::admin_rate_exempt_paths()` 唯一项），health 请求不占通用限流桶。
  - Verify: `grep -n "_admin/health" README.md` 命中 §3 新增条且含「豁免」
  - Verify: `grep -n "admin_rate_exempt_paths" README.md src/service/admin/ratelimit.rs` 双侧命中；`grep -n "debug_assert" src/handler/admin.rs` 命中 health 接线（只读证据核对）

## 5. DOC5：README §7.3 去 `TODO(metrics)`

- [x] 5.1 改写 `README.md:422`：删除「`TODO(metrics)` 以此为 wont-measure 闭环」，改为「命中率本地不测量（wont-measure）：命中率是上游 provider 侧计费指标，网关侧不可见真值，且请求隔离是隐私硬要求（见 `src/service/metrics.rs` 模块文档）」。
  - Verify: `grep -Fn "TODO(metrics)" README.md` 零命中
  - Verify: `grep -n "wont-measure" README.md` 与 `grep -n "wont-measure" src/service/metrics.rs` 双侧命中且语义同字（命中率本地不测量）

## 6. DOC6：README §4 内部常量附录

- [x] 6.1 README §4 阈值表后新增「### 4.1 内部常量附录（未列即内部实现细节）」，表列符号/取值/来源：`CREDENTIAL_RATE_WINDOW_SECS=2`、`REGISTER_RATE_WINDOW_SECS=1`、`PENDING_TTL_SECS=60`、`OLD_HASH_GRACE_SECS=3600`、`RateTable::MAX_ENTRIES=4096`、`RateTable::SWEEP_LEN=1000`、`RateTable::SWEEP_SECS=60`、`LINE_LIMIT_BYTES=16KiB`、`EVENT_IDLE_TIMEOUT=30s`、`KEEPALIVE_INTERVAL=10s`、`RING_CAP=10000`。
  - Verify: `for s in CREDENTIAL_RATE_WINDOW_SECS REGISTER_RATE_WINDOW_SECS PENDING_TTL_SECS OLD_HASH_GRACE_SECS MAX_ENTRIES SWEEP_LEN SWEEP_SECS LINE_LIMIT_BYTES EVENT_IDLE_TIMEOUT KEEPALIVE_INTERVAL RING_CAP; do grep -q "$s" README.md || exit 1; done` 退出码 0
  - Verify: 取值抽查与源码一致：`grep -n "CREDENTIAL_RATE_WINDOW_SECS: u64 = 2" src/config/env_parse.rs`、`grep -n "RING_CAP: usize = 10_000" src/service/metrics/aggregate.rs`、`grep -n "PENDING_TTL_SECS: u64 = 60" src/approval.rs` 均命中
- [x] 6.2 附录声明：「附录为可审计登记，不构成外部契约；未列出的常量均属内部实现细节，变更不视为 BREAKING」。
  - Verify: `grep -n "内部实现细节" README.md` 命中 §4 附录
  - Verify: `grep -nE "不构成.*契约|不视为.*BREAKING|不构成.*BREAKING" README.md` 命中 §4 附录声明

## 7. DOC7：README §7.1 行区间改文件+符号

- [x] 7.1 README §7.1 引用改写：`src/service/llm_gateway/hop.rs:7-16` → `src/service/llm_gateway/hop.rs::HOP_HEADERS`，并补 `::DECODE_ENABLED`（编解码配对开关）；`src/handler/llm/mod.rs:34-46` → `src/handler/llm/mod.rs::forward_headers`（`host` 剥离去向）。全 README 行区间引用清零；与 `veil-gateway-fidelity-fix` tasks 8.1 的 §7.1 增补（`accept-encoding`/解码配对）同节不同句，串行合入不重复。
  - Verify: `grep -nE "\\.rs:[0-9]+" README.md` 零命中
  - Verify: `grep -n "HOP_HEADERS" README.md`、`grep -n "DECODE_ENABLED" README.md`、`grep -n "forward_headers" README.md` 均命中 §7.1
  - Verify: `python3 scripts/check_doc_paths.py` 退出码 0（符号化引用中的文件仍存在）

## 8. 非缺陷记录：占位符门控严格子集（no-change）

- [x] 8.1 `design.md` D8 记录：`src/service/llm_gateway/placeholder.rs:25-33` 的 `\d{6,}` 注入门控为 vault 还原侧 `\d{4,}` 的严格子集（注入宜漏不宜误），与 README §7.2（`README.md:404-406`）同字，属有意设计；本 change 不改该文件。
  - Verify: `grep -n "\\d{6,}" openspec/changes/veil-docs-contract-resync/design.md` 命中 D8 记录段（含「有意严格子集」「no-change」语义）
  - Verify: `grep -n "placeholder" openspec/changes/veil-docs-contract-resync/design.md` 命中与 README §7.2 的交叉引用；apply 后 `git diff --name-only` 不含 `src/service/llm_gateway/placeholder.rs`

## 9. 门禁与回归

- [x] 9.1 `openspec validate veil-docs-contract-resync --strict` 零失败。
  - Verify: 命令输出 `is valid`（或等价 0 failures）
  - Verify: `openspec show veil-docs-contract-resync --json` 可解析且 change 名/能力路径正确
- [x] 9.2 `python3 scripts/check_doc_paths.py` 通过（规划期基线：本 change artifacts 创建前 415 处 `src/*.rs` 引用、创建后 641 处，均退出码 0；扩展后应含 spec 引用计数）。
  - Verify: 退出码 0；输出同时报告 `src/*.rs` 与 spec 引用计数，spec 计数 >0
  - Verify: 全部 tasks 勾选后重跑一次并记录计数与结果，无悬空引用
- [x] 9.3 最终断言集（覆盖 DOC1–DOC7 + 非缺陷记录）。
  - Verify: `grep -n "须同时设置" docker-compose.yml` 零命中；`grep -Fn "TODO(metrics)" README.md` 零命中；`grep -Fn "字节级，未重序列化" README.md` 零命中；`grep -nE "\\.rs:[0-9]+" README.md` 零命中
  - Verify: `grep -n "veil-gateway-fidelity-fix" README.md`、`grep -n "无尾斜杠" README.md`、`grep -n "豁免" README.md`、`grep -n "内部实现细节" README.md`、`grep -n "::" README.md` 均有命中；apply 后 `git diff --name-only` 不含 `src/`
