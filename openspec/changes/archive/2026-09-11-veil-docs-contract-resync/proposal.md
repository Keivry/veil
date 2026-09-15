## Why

docs/代码一致性复核（2026-09-11，只读 `src/` + `README.md` + `docker-compose.yml` + `scripts/check_doc_paths.py`）确认 7 项「文档声明 vs 代码真相」漂移（DOC1–DOC7），其中 2 项 High：`GET_BINARY_HASH` 独立性硬矛盾与 README §7.7 归一化声明与实现不符；其余为引用易腐、管理面路径未文档化、陈旧 `TODO(metrics)`、内部常量未声明与行号引用漂移。全部为陈述性缺陷，本 change 不新增/修复 `src/` 行为；DOC2 的行为修复归并行 change `veil-gateway-fidelity-fix`（H1），本 change 只做文本对齐与指向。

- **DOC1（High，硬矛盾）**：`README.md:32` 称 `GET_BINARY_HASH` 独立生效、「与 `GET_BINARY_SECRET` 无联动」；`docker-compose.yml:18` 注释称「`GET_BINARY_HASH` 与 `GET_BINARY_SECRET` 须同时设置才生效」。代码真相：`src/config/env_parse.rs:520-523` 两变量独立 `filter(!empty)`（`GET_BINARY_SECRET`/`CREDENTIAL_SECRET` 二选一，`GET_BINARY_HASH` 单独取值），`src/service/credential/auth.rs:96-106` 对 `get_binary_hash` 独立判定；compose 注释错误。
- **DOC2（High，合同不符）**：README §7.7（`README.md:462`）称「纯脱敏子串替换（字节级，未重序列化）与原文透传不置位」；但 `src/service/redaction/scope.rs:58-81` 的 `redact_request` 对 JSON 容器走 `json_walk::process_text` 的 loads→walk→dumps（`src/service/json_walk.rs:137-163`），发生替换即紧凑重序列化；`src/handler/llm/rewrite.rs:65-66` 纯脱敏替换分支仍以 `normalized_out=false` 转发（`x-veil-normalized` 未置位）。
- **DOC3（Medium，引用易腐）**：`README.md:5` 与 `:203` 引用 `openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md`（完整路径 + 「未归档」标注已由 `veil-docs-contract-sync` 补全）；但 `scripts/check_doc_paths.py` 只校验 `src/*.rs` 引用，该 spec 引用不受门禁保护，`veil-hardening` 归档/移动时会静默悬空。
- **DOC4（Medium，未文档化）**：`src/router.rs:35-42` 同时注册 `/_admin`（无斜杠）与 `/_admin/`（同 handler）；`src/service/admin/ratelimit.rs:21-24` 的 `admin_rate_exempt_paths()==["/_admin/health"]`（接线见 `src/handler/admin.rs:200-208`）。README §1/§3 均未写明「裸路径同义 200」与「`/_admin/health` 豁免限流」。
- **DOC5（Low，双向互引陈旧）**：`src/service/metrics.rs:7-12` 声明「本模块不再持有 TODO」「README §7.3 原 `TODO(metrics)` 标注归 docs change 收尾」，而 `README.md:422` 仍写 `TODO(metrics)`。
- **DOC6（Low，内部常量未文档化）**：`CREDENTIAL_RATE_WINDOW_SECS=2`（`src/config/env_parse.rs:138`）、`REGISTER_RATE_WINDOW_SECS=1`（`:140`）、`PENDING_TTL_SECS=60`（`src/approval.rs:51`）、`OLD_HASH_GRACE_SECS=3600`（`src/registry/entry.rs:44`）、`RateTable::MAX_ENTRIES=4096`/`SWEEP_LEN=1000`/`SWEEP_SECS=60`（`src/service/credential/ratelimit.rs:19-21`）、`LINE_LIMIT_BYTES=16KiB`（`src/config/env_parse.rs:64`）、`EVENT_IDLE_TIMEOUT=30s`（`:68`）、`KEEPALIVE_INTERVAL=10s`（`:73`）、`RING_CAP=10000`（`src/service/metrics/aggregate.rs:13`）等未在 README §4 出现，也无「未列即内部实现细节」声明。
- **DOC7（Low，行号引用漂移）**：`README.md:355` 引 `src/service/llm_gateway/hop.rs:7-16` 未覆盖同文件 `DECODE_ENABLED`（`:20`）；`README.md:356` 引 `src/handler/llm/mod.rs:34-46`（`host` 剥离去向）。行区间引用随代码移动即漂移；`scripts/check_doc_paths.py` 只校验文件存在、不校验行号。
- **非缺陷记录（no-change）**：`src/service/llm_gateway/placeholder.rs:25-33` 的注入门控 `\d{6,}` vs 还原侧 `\d{4,}` 为有意严格子集（注释与 README §7.2 `README.md:404-406` 已同字声明），design.md D8 记录澄清，不改。

真相源（只读）：`src/config/env_parse.rs`、`src/service/credential/auth.rs`、`src/service/redaction/scope.rs`、`src/service/json_walk.rs`、`src/handler/llm/rewrite.rs`、`src/router.rs`、`src/service/admin/ratelimit.rs`、`src/handler/admin.rs`、`src/service/metrics.rs`、`src/approval.rs`、`src/registry.rs`、`src/service/credential/ratelimit.rs`、`src/service/metrics/aggregate.rs`、`src/service/llm_gateway/hop.rs`、`src/handler/llm/mod.rs`、`src/service/llm_gateway/placeholder.rs`、`README.md`、`docker-compose.yml`、`scripts/check_doc_paths.py`。本 change 只交付规划 artifacts（proposal/design/spec/tasks），不改 `src/`、规划期不改 README/compose/scripts、不改既有 change、不改 `openspec/specs/`、不提交 commit。

## What Changes

- **DOC1 compose 注释对齐 README**：`docker-compose.yml:18` 注释改为与 `README.md:32` 同字的「`GET_BINARY_HASH` 独立生效（置位即拒绝 `caller_hash` 直调），与 `GET_BINARY_SECRET` 无联动；均为空为兼容模式」。
- **DOC2 §7.7 文本对齐 + 指向**：README §7.7 删除「纯脱敏子串替换（字节级，未重序列化）」不实表述，记录 JSON 容器脱敏经 `json_walk` 紧凑重序列化的事实与当前置位缺口，并显式指向行为修复 change `veil-gateway-fidelity-fix`（H1）；本 change 不改 `scope.rs`/`rewrite.rs`/`json_walk.rs`。
- **DOC3 spec 引用纳入路径门禁**：扩展 `scripts/check_doc_paths.py` 同时校验 README/`openspec`/`scripts` 中的 spec 引用（canonical `openspec/specs/**` 与 change-local `openspec/changes/**/spec.md` 两形态）；README:5/203 保持完整 change-local 路径 + 「未归档」标注；`veil-hardening` 归档后更新为 canonical，门禁保证不漏。
- **DOC4 README §1/§3 补管理面路径语义**：§1 增「`/_admin`（无尾斜杠）与 `/_admin/` 同义返回 JSON 索引（200）」；§3 增「`/_admin/health` 豁免通用 `10/min` 限流，不占通用桶；豁免集即 `admin_rate_exempt_paths()`」。
- **DOC5 README §7.3 去 `TODO(metrics)`**：改为「命中率本地不测量（wont-measure，见 `src/service/metrics.rs` 模块文档）」，与 `metrics.rs:7-12` 同字。
- **DOC6 README §4 内部常量附录**：新增附录表（符号/取值/来源），列 DOC6 常量，并声明「未列出的常量属内部实现细节，变更不视为外部契约/BREAKING」。
- **DOC7 README §7.1 符号化引用**：行区间引用改为文件+符号（`src/service/llm_gateway/hop.rs::HOP_HEADERS`、`::DECODE_ENABLED`、`src/handler/llm/mod.rs::forward_headers`），覆盖解码配对与 `host` 剥离。
- **非缺陷记录**：design.md D8 记录占位符门控严格子集为有意设计（与 README §7.2 同字），不改。

## Capabilities

### New Capabilities

- `docs-contract-resync`：文档-代码合同再同步的锁定场景——compose 注释与 README 同字、归一化声明与实现对齐并指向行为修复 change、spec 引用受路径门禁保护、管理面路径与限流豁免可文档化、wont-measure 口径无陈旧 TODO、内部常量附录（未列即内部细节）、源码定位引用用文件+符号。

### Modified Capabilities

- 无。不改 `openspec/specs/` 既有契约；DOC2 的行为修复（`scope.rs`/`rewrite.rs` 归一化置位）不在本 change 范围，归 `veil-gateway-fidelity-fix`。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| DOC1 | High（硬矛盾） | compose:18 注释改与 README:32 同字（独立生效/无联动）；代码锚 `env_parse.rs:520-523` + `auth.rs:96-106` | 1.1 |
| DOC2 | High（合同不符） | README §7.7 删不实表述、记录重序列化事实、指向 `veil-gateway-fidelity-fix`；design 边界防双改 | 2.1、2.2 |
| DOC3 | Medium | `check_doc_paths.py` 增 spec 引用存在性校验；README:5/203 完整路径 + 未归档标注；归档后 canonical 化 | 3.1、3.2 |
| DOC4 | Medium | README §1 补裸路径同义；§3 补 health 豁免；与 `router.rs:35-42`/`ratelimit.rs:21-24` 同源 | 4.1、4.2 |
| DOC5 | Low | README §7.3 改 wont-measure、去 `TODO(metrics)`；与 `metrics.rs:7-12` 同字 | 5.1 |
| DOC6 | Low | README §4 内部常量附录 + 「未列即内部实现细节」声明 | 6.1、6.2 |
| DOC7 | Low | README §7.1 行区间改文件+符号（含 `DECODE_ENABLED`、`forward_headers`） | 7.1 |
| 非缺陷 | 记录（no-change） | design D8 记录占位符门控严格子集（`placeholder.rs:25-33` vs README §7.2） | 8.1 |

## Non-Goals（显式）

- **不改 `src/` 任何实现**：DOC2 的行为修复（重序列化置位/响应侧保真）归 change `veil-gateway-fidelity-fix`（H1），本 change 不触碰 `scope.rs`/`rewrite.rs`/`json_walk.rs`；placeholder 门控（`placeholder.rs:25-33`）亦不改。
- 不改 README 中与本覆盖表无关的条目、不改 `docker-compose.yml` 非 DOC1 行、不改既有 change、不改 `openspec/specs/` canonical。
- 不给行号引用加自动化行号校验（`check_doc_paths.py` 仍只校验文件/spec 路径存在；DOC7 以符号化约定 + 文本断言收口）。
- 不改变任何运行时行为、阈值与契约取值；DOC6 附录只登记现有常量，不使其成为外部契约。
- 规划期不执行 apply 修改（README/compose/scripts 修改留 apply 阶段）；不提交 commit。

## Impact

- **新增文件**：仅 `openspec/changes/veil-docs-contract-resync/` 下 `.openspec.yaml`、`proposal.md`、`design.md`、`specs/docs-contract-resync/spec.md`、`tasks.md`。
- **apply 阶段文件**：`README.md`（§1、§3、§4、§7.1、§7.3、§7.7，逐条见覆盖表）、`docker-compose.yml`（仅注释）、`scripts/check_doc_paths.py`（spec 引用校验扩展）；不改 `src/`。
- **README 修改边界（与并行 change 互斥）**：`veil-gateway-fidelity-fix` 若同时改 README §7.7（其 tasks 8.1 含 §7.7/§7.2/§7.1 文本同步），按同段落「先落地者写实、后到者只读复核、不重复编辑同一行」串行合入，禁止互相覆盖；本 change 只负责覆盖表列出的 README 行（§7.7 编辑动作亦按此规则让位）。`veil-docs-contract-sync`（已 complete）负责的 D2–D5/D8/D9 条目本 change 不重复、不覆盖。
- **影响系统**：文档可信度（compose 与 README 同字）、归一化声明诚实性、引用防腐（门禁覆盖 spec 路径）、管理面可观测性（裸路径/health 豁免）、TODO 口径闭环、内部常量可审计、源码引用抗漂移。
- **依赖**：`openspec` CLI（`validate`）、`scripts/check_doc_paths.py`、只读源码取证；无新依赖。
