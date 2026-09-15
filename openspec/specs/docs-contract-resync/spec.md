# docs-contract-resync Specification

## Purpose
锁定「文档-代码合同再同步」的可验证场景：`GET_BINARY_HASH` 独立性声明同字、请求归一化声明与实现对齐并指向行为修复 change、spec 引用受路径门禁保护、管理面裸路径与限流豁免可文档化、wont-measure 口径无陈旧 TODO、内部常量附录与「未列即内部细节」声明、源码定位引用使用文件+符号，并记录占位符门控严格子集为有意设计。

## Requirements

### Requirement: GET_BINARY_HASH 独立性声明同字

README §1 环境变量表与 `docker-compose.yml` 三因子注释 SHALL 就 `GET_BINARY_HASH` 的独立性与 `GET_BINARY_SECRET` 的关系同字：`GET_BINARY_HASH` 独立生效（置位时拒绝 `caller_hash` 直调，为空时该检查兼容跳过），与 `GET_BINARY_SECRET` 无联动；两者均为空时为兼容模式。`docker-compose.yml` SHALL NOT 声称二者「须同时设置才生效」。

#### Scenario: compose 注释与 README 同字

- **WHEN** 核对 `docker-compose.yml` 三因子注释段与 `README.md:32` 变量表行
- **THEN** compose 注释含「独立生效」与「无联动」语义，零命中「须同时设置才生效」；两侧表述逐义一致

#### Scenario: 代码真相锚定

- **WHEN** 追溯 `src/config/env_parse.rs:520-523` 与 `src/service/credential/auth.rs:96-106`
- **THEN** `GET_BINARY_SECRET`/`CREDENTIAL_SECRET` 与 `GET_BINARY_HASH` 各自独立 `filter(!empty)` 取值、`get_binary_hash` 独立判定，与 README/compose 声明一致

### Requirement: 请求归一化声明与实现对齐

README §7.7 SHALL NOT 声称 JSON 容器内的脱敏替换为「字节级，未重序列化」；SHALL 记录该路径经 `json_walk` loads→walk→dumps 紧凑重序列化的事实，并将重序列化未置位 `x-veil-normalized` 的行为修复显式指向 change `veil-gateway-fidelity-fix`（H1）。本 capability SHALL NOT 修改 `src/` 的脱敏与归一化实现（`scope.rs`/`rewrite.rs`/`json_walk.rs`）。

#### Scenario: §7.7 无「未重序列化」不实表述

- **WHEN** 检索 README §7.7 原文
- **THEN** 零命中「纯脱敏子串替换（字节级，未重序列化）」；命中「重序列化」与「veil-gateway-fidelity-fix」的指向表述

#### Scenario: 行为修复边界不双改

- **WHEN** 执行本 change 的 apply 并检查 `git diff --name-only`
- **THEN** 变更集不含 `src/service/redaction/scope.rs`、`src/handler/llm/rewrite.rs`、`src/service/json_walk.rs`；上述行为修复由 `veil-gateway-fidelity-fix` 承接

### Requirement: spec 引用路径可校验

README 与 OpenSpec 制品中的 spec 路径引用 SHALL 由 `scripts/check_doc_paths.py` 校验存在性，覆盖 canonical（`openspec/specs/<capability>/spec.md`）与 change-local（`openspec/changes/<change>/specs/<capability>/spec.md`）两种完整路径形态；指向未归档 change 的 README 引用 SHALL 保留完整路径并标注「未归档」；`veil-hardening` 归档后 SHALL 更新为 canonical 且门禁保持通过。`scripts/README.md` SHALL 文档化 `check_doc_paths.py` 的 `PENDING_REFS` 例外语义：仅历史/情景性悬空引用以精确「源文件 + 引用」组合登记并打印 `PENDING`（不算失败），其余悬空引用（含 README.md 全部引用）一律 FAIL，使例外可被复核。

#### Scenario: 门禁通过并计数

- **WHEN** 运行 `python3 scripts/check_doc_paths.py`
- **THEN** 退出码 0，输出同时报告 `src/*.rs` 与 spec 引用校验计数；README:5/203 的 `admin-ratelimit-contract` change-local 路径判定存在

#### Scenario: 归档迁移触发更新

- **WHEN** `veil-hardening` 归档（或路径被移动）导致 `openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md` 不再存在<!-- doc-paths-ignore -->
- **THEN** 门禁非零退出并列出悬空引用的 `README.md` 行号，迫使同批更新为 canonical 路径；不得静默通过

#### Scenario: 未归档引用完整标注

- **WHEN** 检索 README 的 `admin-ratelimit-contract` 引用
- **THEN** 均为完整 change-local 路径 + 「未归档」标注，零裸名引用

#### Scenario: PENDING_REFS 例外已文档化

- **WHEN** 查阅 `scripts/README.md` 对 `check_doc_paths.py` 的说明
- **THEN** 命中 `PENDING_REFS` 例外语义（仅精确「源文件 + 引用」组合登记并打印 PENDING，README 引用永不登记），与脚本内注释同源

### Requirement: 管理面路径与限流豁免文档化

README SHALL 记录：`/_admin`（无尾斜杠）与 `/_admin/` 注册为同一索引 handler、均返回 200 JSON 索引；`/_admin/health` 豁免通用 `10/min` 限流（不占通用限流桶）。文档 SHALL 与 `src/router.rs` 的双路由注册及 `src/service/admin/ratelimit.rs::admin_rate_exempt_paths` 同源。

#### Scenario: 裸路径同义 200

- **WHEN** 请求 `GET /_admin`（无尾斜杠）并携带有效 `X-Admin-Token`
- **THEN** 返回 200 JSON 索引，与 `/_admin/` 响应同构；README §1 明写该同义关系

#### Scenario: health 豁免限流

- **WHEN** 同一 IP 在一分钟内多次请求 `/_admin/health`
- **THEN** 不触发 `429`（`is_rate_exempt` 恒 true）；README §3 明写豁免及豁免集 `["/_admin/health"]`

#### Scenario: 非豁免路径仍计数

- **WHEN** 同一 IP 一分钟内第 11 次请求 `/_admin/metrics`
- **THEN** 返回 `429 + Retry-After`；此前 health 请求不占用该通用限流桶

### Requirement: 指标口径声明无陈旧 TODO

README §7.3 SHALL 以「命中率本地不测量（wont-measure）」表述 prompt-cache 差异，SHALL NOT 残留 `TODO(metrics)` 字样；声明 SHALL 与 `src/service/metrics.rs` 模块文档（`:7-12`）同字。

#### Scenario: TODO 字样清零

- **WHEN** 检索 README 全文
- **THEN** 零命中 `TODO(metrics)`；零命中「TODO(metrics) 以此为 wont-measure 闭环」旧句式

#### Scenario: 口径同字

- **WHEN** 比对 README §7.3 与 `src/service/metrics.rs:7-12`
- **THEN** 两侧均表述为「命中率差异本地不测量（wont-measure）」且理由一致（上游 provider 侧计费指标不可见真值 + 请求隔离为隐私硬要求）

### Requirement: 内部常量附录与未列即内部细节声明

README §4 SHALL 提供内部常量附录，至少列出 `CREDENTIAL_RATE_WINDOW_SECS`、`REGISTER_RATE_WINDOW_SECS`、`PENDING_TTL_SECS`、`OLD_HASH_GRACE_SECS`、`RateTable::MAX_ENTRIES`、`RateTable::SWEEP_LEN`、`RateTable::SWEEP_SECS`、`LINE_LIMIT_BYTES`、`EVENT_IDLE_TIMEOUT`、`KEEPALIVE_INTERVAL`、`RING_CAP` 的符号、取值与来源；SHALL 显式声明「未列出的常量属内部实现细节，变更不视为外部契约/BREAKING」。

#### Scenario: 常量逐项可检索

- **WHEN** 在 README §4 附录检索上述符号
- **THEN** 每项命中，取值与来源文件符号一致（如 `CREDENTIAL_RATE_WINDOW_SECS=2`、`PENDING_TTL_SECS=60`、`RING_CAP=10000`、`LINE_LIMIT_BYTES=16KiB`）

#### Scenario: 非契约声明在位

- **WHEN** 查阅 README §4 附录首句或末句
- **THEN** 明写「未列即内部实现细节」及「变更不构成 BREAKING」，避免附录反向固化实现

### Requirement: 源码定位引用使用文件加符号

README 对 `src/` 的定位引用 SHALL 使用「文件 + 符号」形态（如 `src/service/llm_gateway/hop.rs::HOP_HEADERS`），SHALL NOT 使用随代码移动即漂移的行区间引用（`file.rs:start-end`）。README §7.1 的 HOP 说明 SHALL 同时覆盖 `HOP_HEADERS`（8 项全集）、`DECODE_ENABLED`（编解码配对开关）与 `forward_headers`（`host` 剥离去向）。

#### Scenario: 行区间引用清零

- **WHEN** 正则检索 README 的 `\.rs:[0-9]+(-[0-9]+)?` 引用
- **THEN** 零命中；§7.1 以 `hop.rs::HOP_HEADERS`、`hop.rs::DECODE_ENABLED`、`handler/llm/mod.rs::forward_headers` 表述

#### Scenario: 文件路径仍受门禁

- **WHEN** 运行 `python3 scripts/check_doc_paths.py`
- **THEN** 退出码 0：符号化引用中的 `src/*.rs` 文件均存在（脚本只断言文件存在，不解析符号）

### Requirement: 占位符门控严格子集为有意设计

占位符说明注入门控 `\d{6,}` SHALL 保持为 vault 还原侧 `\d{4,}` 的严格子集（注入宜漏不宜误，还原侧仍按宽松口径处理），README §7.2 的声明与 `src/service/llm_gateway/placeholder.rs` 注释 SHALL 保持同字；本 capability SHALL NOT 修改该门控。

#### Scenario: 双向文档同字

- **WHEN** 比对 README §7.2 与 `placeholder.rs:25-33` 注释
- **THEN** 两侧均声明「`\d{6,}` 窄于 `\d{4,}`、属有意保守、还原侧仍宽松」

#### Scenario: 记录不驱动实现变更

- **WHEN** 检查本 change apply 的 `git diff --name-only`
- **THEN** 不含 `src/service/llm_gateway/placeholder.rs`；该门控无行为改动，design D8 记录在位

### Requirement: 归档 change spec 历史行号指针修正

对归档 change 的 spec 中失效的历史 `path:line` 指针，系统 SHALL 以「仅修正指针、不改决策文本」为原则批量对齐到实际内容（覆盖 `docs-contract-resync`、`code-quality-cleanup` 等归档 spec），SHALL 保留归档语义与历史判定；修正后 SHALL NOT 引入与归档结论冲突的新陈述，SHALL NOT 改写需求正文或结论。指针修正的根因治理由 `docs-contract-sync`「文档行号引用可校验」承接。

#### Scenario: 归档 spec 指针对齐

- **WHEN** 扫描归档 change spec 中的 `path:line` 引用并与目标文件内容比对
- **THEN** 失效指针被修正到实际内容对应行，决策文本与归档结论逐字保留

#### Scenario: 归档语义不被改写

- **WHEN** 检查任一被修正的归档 spec 的变更集
- **THEN** 变更仅涉及指针（路径/行号），无需求正文或结论语义改动
