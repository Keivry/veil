## Context

docs/代码一致性复核（2026-09-11，只读）在「文档声明 vs 代码真相」面确认 7 项漂移（DOC1–DOC7）+ 1 项非缺陷记录。现状真相源（行号为复核快照，apply 时以符号/文本断言为准）：

- `GET_BINARY_HASH` 独立性：`src/config/env_parse.rs:520-523` 两变量独立 `filter(!empty)`；`src/service/credential/auth.rs:96-106` 独立判定 `get_binary_hash`（含 `caller_hash == expected_get` 直调拒绝，`:107-110`）。README:32 正确，`docker-compose.yml:18` 注释错误（DOC1）。
- 归一化声明：`src/service/redaction/scope.rs:58-81` 的 `redact_request` 经 `json_walk::process_text`（`src/service/json_walk.rs:137-163`：loads→walk→dumps + `validate_json_roundtrip` 回退）做紧凑重序列化；`src/handler/llm/rewrite.rs:65-66` 纯脱敏替换分支置 `body_bytes = redacted_text.into_bytes()` 但 `normalized_out` 保持 `false`。README §7.7（`README.md:455-464`）却称「纯脱敏子串替换（字节级，未重序列化）」（DOC2）。
- spec 引用门禁：`README.md:5`/`:203` 引 `openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md`（未归档，`veil-hardening` 13/16 in-progress）；`scripts/check_doc_paths.py` 仅匹配 `src/[A-Za-z0-9_./-]+\.rs`（`REF_RE`），spec 引用不在校验面（DOC3）。
- 管理面路径：`src/router.rs:35-42` 注册 `/_admin/` 与 `/_admin` 同 handler，另有 `/_admin/{*rest}` 兜底 404；`src/service/admin/ratelimit.rs:21-24` 豁免集 `["/_admin/health"]`，接线 `src/handler/admin.rs:200-208`；README §1/§3 未写（DOC4）。
- `TODO(metrics)`：`src/service/metrics.rs:7-12` 已声明「wont-measure、本模块不再持有 TODO、README §7.3 归 docs change 收尾」；`README.md:422` 仍写 `TODO(metrics)`（DOC5）。
- 内部常量：`src/config/env_parse.rs:138/140/64/68/73`、`src/approval.rs:51`、`src/registry/entry.rs:44`、`src/service/credential/ratelimit.rs:19-21`、`src/service/metrics/aggregate.rs:13` 的窗口/超时/容量常量未在 README §4 出现，也无「未列即内部实现细节」声明（DOC6）。
- 行号引用：README 全文仅 2 处 `.rs:<行号>` 引用，均在 §7.1（`README.md:355` `hop.rs:7-16`、`:356` `handler/llm/mod.rs:34-46`）；`hop.rs:20` 的 `DECODE_ENABLED`（编解码配对标记）未被引用覆盖（DOC7）。
- 占位符门控：`src/service/llm_gateway/placeholder.rs:25-33` 的 `match_cred_token` 要求 `\d{6,}`，为 vault 还原侧 `\d{4,}` 的严格子集；注释与 README:404-406 已同字声明，属有意保守（非缺陷）。

约束：本 change 只交付规划 artifacts，不改 `src/`、规划期不改 README/compose/scripts；不碰既有 change 与 `openspec/specs/`；不提交 commit。DOC2 的行为修复不在本 change，归并行 change `veil-gateway-fidelity-fix`（H1）。

## Goals / Non-Goals

**Goals：**

- 把 DOC1–DOC7 的文本对齐落实为可执行 task 与可独立验证的 spec Scenario，使 apply 阶段逐条落地。
- 在 design 中锁定 DOC2 的双 change 边界：本 change 只改 README §7.7 文本 + 指向，`veil-gateway-fidelity-fix` 改行为（归一化置位/响应侧保真），避免双改 `scope.rs`/`rewrite.rs`。
- 把 spec 引用纳入 `check_doc_paths.py` 门禁，消除「未归档路径静默悬空」的易腐性。
- 记录占位符门控严格子集为有意设计，防止后续 change 误判为缺陷。

**Non-Goals：**

- 不改 `src/`（含 `scope.rs`/`rewrite.rs`/`json_walk.rs`/`placeholder.rs`）；不做 `preserve_order`、字节级替换或响应侧保真的实现决策——归 `veil-gateway-fidelity-fix`。
- 不使 DOC6 附录中的内部常量成为外部契约；不改变任何阈值取值。
- 不校验行号（脚本只校验文件/spec 路径存在）；不重写 README 其他章节。
- 不改 `openspec/specs/` 与既有 change；不执行归档。

## Decisions

### D1（DOC1）：compose 注释以 README/代码为 canonical 单侧修正

**决策**：`docker-compose.yml:18` 注释改为与 `README.md:32` 同字：「`GET_BINARY_HASH` 独立生效：置位时拒绝调用方冒用 get 自身哈希的直调；为空时该检查兼容跳过，与 `GET_BINARY_SECRET` 无联动」。不反向改 README（README 已与代码一致）。

**理由**：代码真相是双独立（`env_parse.rs:520-523`）+ 独立判定（`auth.rs:96-110`）；compose 注释不是契约但会被部署者当真，属 High 硬矛盾，单侧修正即闭环。`GET_BINARY_SECRET` 与 `CREDENTIAL_SECRET` 的二选一兼容与 `GET_BINARY_HASH` 无关，compose 注释不再暗示联动。

**备选**：改 README 去迁就 compose——错误方向（README 与代码一致），不采用；改代码强制联动——行为变更，超出文档 change，不采用。

### D2（DOC2）：文本归本 change、行为归 `veil-gateway-fidelity-fix`（防双改边界）

**决策**：

- **本 change 负责**：README §7.7 删除「纯脱敏子串替换（字节级，未重序列化）」不实表述；改为如实记录「JSON 容器内的脱敏替换经 `json_walk` loads→walk→dumps 紧凑重序列化（`scope.rs::redact_request`），重序列化即属 `x-veil-normalized` 合理置位场景；当前纯脱敏替换分支未置位的合同缺口由 change `veil-gateway-fidelity-fix`（H1）修复」；并在 spec 中锁定「§7.7 不得声称未重序列化 + 行为修复不得在本 capability 实现」。
- **`veil-gateway-fidelity-fix` 负责**：`scope.rs`/`rewrite.rs`（及必要时的 `json_walk.rs`）的行为修复——重序列化时置位 `x-veil-normalized`，或按该 change 的裁决改为字节级替换（若选后者，README §7.7 由该 change 按其落地行为同步修订）；H1 的响应侧 JSON 保真（`preserve_order` 等）同归该 change。其 tasks 8.1 亦含「README §7.7/§7.2/§7.1 三节同步」记录项，与本 change 存在同段落重叠。
- **同段落双写收敛（与 `veil-gateway-fidelity-fix` tasks 8.1）**：README §7.7 的最终文本动作按「先落地者写实、后到者只读复核同一行、不重复编辑」串行——若该 change（行为 + 文本）先行落地，本 change task 2.1 降级为只读复核（旧断言零命中、置位口径与实现同字、指向正确）；若本 change 先行，其 task 2.1 在 fidelity change 落地后由该 change 按落地行为复核覆盖。README §7.1 同理：本 change 只做行区间→符号改写，fidelity 只做 `accept-encoding`/解码配对口径增补，两处句子不重叠但同节，按串行合入。
- **边界检查**：本 change apply 的 `git diff --name-only` 不得含 `src/service/redaction/scope.rs`、`src/handler/llm/rewrite.rs`、`src/service/json_walk.rs`；若 `veil-gateway-fidelity-fix` 先落地，本 change 的 README 任务改为按其落地行为写实并复核置位声明。

**理由**：同一合同缺口若两 change 各改一半，会出现「文本已改、行为未改」或反之间的二次漂移；明确「文本 vs 行为」所有权后，串行合入即可。

**备选**：本 change 直接修行为——越权且与 H1 修复重复；保持 README 原文不动——合同不符保留，不采用。

### D3（DOC3）：扩展 `check_doc_paths.py` 而非等待 canonical

**决策**：扩展 `scripts/check_doc_paths.py`，在 `src/*.rs` 之外新增 spec 引用校验：匹配 `openspec/(changes/<change>/specs/<capability>|specs/<capability>)/spec.md` 两类完整路径并断言存在；沿用既有剔除机制（`（勘误：...）` 片段、`<!-- doc-paths-ignore -->` 行）；README:5/203 在 `veil-hardening` 未归档期间保持完整 change-local 路径 + 「未归档」标注；归档后更新为 `openspec/specs/admin-ratelimit-contract/spec.md`，门禁保持通过。

**理由**：canonical `admin-ratelimit-contract` 在 `veil-hardening`（13/16）归档前不存在，无法作为路径目标；易腐性根因是「引用不在门禁面」，加校验比换路径更直接。脚本已是既有文档门禁（`veil-docs-contract-fix 1.3`），扩展与既有职责一致。

**备选**：等 `veil-hardening` 归档后统一改 canonical——期间仍无保护，且归档时仍需改 README；改用裸 capability 名——`veil-docs-contract-sync` 已裁决禁止裸名歧义，不采用。

### D4（DOC4）：README §1 补裸路径同义、§3 补 health 豁免

**决策**：§1「管理控制台说明」增一条：「`/_admin`（无尾斜杠）与 `/_admin/` 注册为同一索引 handler，均返回 200 JSON 索引（`src/router.rs` 双路由注册）」。§3 增一条：「`/_admin/health` 豁免通用 `10/min` 限流（存活探针高频；豁免集为 `src/service/admin/ratelimit.rs::admin_rate_exempt_paths()` 的唯一项），health 请求不占通用限流桶」。

**理由**：两项均为已实现且有测试/单测锚定的行为（`router.rs:35-42`、`admin/ratelimit.rs:21-24`、`admin.rs:207` 的 `debug_assert!`），缺失会让「裸路径 404」与「health 被限流」成为合理误判；文档补齐成本最低。

**备选**：改代码让裸路径 404 或 health 参与限流——行为变更且无收益，不采用。

### D5（DOC5）：README §7.3 采用 `metrics.rs` 模块文档口径

**决策**：`README.md:422` 的「`TODO(metrics)` 以此为 wont-measure 闭环」改为「命中率本地不测量（wont-measure）：命中率是上游 provider 侧计费指标，网关侧不可见真值，且请求隔离是隐私硬要求（见 `src/service/metrics.rs` 模块文档）」。不新增指标、不测量命中率。

**理由**：`metrics.rs:7-12` 已定义 wont-measure 闭环（上游 cache-hit 计费数据缺失时另立任务对账），README 残留 `TODO(metrics)` 属双向互引陈旧的最后一环；改文本即闭环，且不改行为。

**备选**：改 `metrics.rs` 保留 TODO——反向制造已声明不存在的 TODO，不采用。

### D6（DOC6）：README §4 附录登记常量 + 「未列即内部实现细节」声明

**决策**：README §4 阈值表后新增「### 4.1 内部常量附录（未列即内部实现细节）」，表列符号/取值/来源：`CREDENTIAL_RATE_WINDOW_SECS=2`、`REGISTER_RATE_WINDOW_SECS=1`、`PENDING_TTL_SECS=60`、`OLD_HASH_GRACE_SECS=3600`、`RateTable::MAX_ENTRIES=4096`、`RateTable::SWEEP_LEN=1000`、`RateTable::SWEEP_SECS=60`、`LINE_LIMIT_BYTES=16KiB`、`EVENT_IDLE_TIMEOUT=30s`、`KEEPALIVE_INTERVAL=10s`、`RING_CAP=10000`；并声明「附录为可审计登记，不构成外部契约；未列出的常量均属内部实现细节，变更不视为 BREAKING」。

**理由**：这些常量可被运维观测到（限流窗口、超时、环容量），不登记时「README 未列」与「行为可观测」矛盾；显式标记非契约既提供审计线索，又保留实现调整自由度（避免附录反向固化）。

**备选**：仅加「未列即内部实现细节」声明不列常量——可审计性差且无法 grep 验证，不采用。

### D7（DOC7）：§7.1 行区间引用改文件+符号

**决策**：README §7.1 的 `src/service/llm_gateway/hop.rs:7-16` 改为 `src/service/llm_gateway/hop.rs::HOP_HEADERS`（并补 `::DECODE_ENABLED` 覆盖编解码配对开关，`hop.rs:18-20`）；`src/handler/llm/mod.rs:34-46` 改为 `src/handler/llm/mod.rs::forward_headers`。全 README 行区间引用清零（当前仅此两处）。

**理由**：`check_doc_paths.py` 只校验文件存在，行区间不受任何门禁保护且已漂移（`hop.rs:7-16` 不含 `DECODE_ENABLED`）；符号形态随代码移动仍语义可读，且文件路径继续受门禁。与 `veil-gateway-fidelity-fix` tasks 8.1 的 §7.1 增补（`accept-encoding`/解码配对口径）同节不同句，串行合入、互不覆盖。

**备选**：补行号让门禁校验——需给脚本加行号解析与容忍规则，成本高且仍会漂移，不采用；仅修正为 `hop.rs:7-20`——下次移动再漂移，不采用。

### D8（非缺陷记录）：占位符门控严格子集 = 有意设计（no-change）

**决策**：`placeholder.rs:25-33` 的 `\d{6,}` 注入门控与还原侧 `\d{4,}` 的差异为有意严格子集（注入宜漏不宜误；生产 token 恒 6 位，历史 4-5 位幻觉形仍可还原）；README §7.2 与代码注释已同字声明。design 记录并交叉引用，不列修复 task 之外的行为改动；spec 以「记录不驱动实现变更」Scenario 锁定。

**理由**：审计曾疑为「门控/还原不一致」，核实为有意保守；记录可防止后续 change 误改门控或误把差异当缺陷报修。

**备选**：统一为 `\d{4,}`——放宽注入面、引入误注入风险，不采用；删除门控——无依据，不采用。

## Risks / Trade-offs

- [DOC2/§7.7 与 `veil-gateway-fidelity-fix`（tasks 8.1 亦含 §7.7/§7.1 文本同步）同段落双写 → 互相覆盖] → 边界声明 + 同段落「先落地者写实、后到者只读复核」串行规则；本 change 不改 `src/`，冲突面仅 README 两节各一句。
- [`veil-gateway-fidelity-fix` 未落地 → README §7.7 指向一个尚未执行的 change] → 文本明确「缺口承接方 + 当前已知偏差」而非假装已修复；该 change 落地后由其按行为复核 §7.7 并收口指向语义（本 change 的 spec 不依赖该目录存在，指向为文本事实）。
- [check_doc_paths 扩展后暴露其他既有悬空 spec 引用 → 门禁由绿转红] → 属期望的 fail-fast；apply 时同批修复覆盖表内引用，覆盖表外的悬空引用登记并最小修复（只改路径不改语义），不扩大范围则记入变更记录。
- [DOC6 附录被误当契约 → 实现调整受限] → 附录首行声明「非外部契约、未列即内部细节」；spec Scenario 同时锁定声明在位。
- [行区间清零后读者仍想要精确定位] → 符号定位（`::`）配合编辑器/LSP 跳转，优于行号；`check_doc_paths.py` 继续保证文件存在。

## Migration Plan

1. 按 tasks 顺序：先 DOC1/DOC5/DOC7 等纯文本修正，再 DOC2 文本 + 指向（若 fidelity change 已落地则按其行为写实），再 DOC3 脚本扩展与引用复核，最后 DOC4/DOC6 补充与门禁。
2. 每节独立 grep 验证；README/ compose/ scripts 修改集中一次编辑窗口，避免与并行 change 交叠；与 `veil-gateway-fidelity-fix` 的 README §7.7 冲突按「先落地者写实」串行处理。
3. 收口：`openspec validate veil-docs-contract-resync --strict` 0 failures + `python3 scripts/check_doc_paths.py` 退出码 0（规划期基线：415 处 `src/*.rs` 引用全通过，记录于 tasks 9.2）+ tasks 9.3 断言集逐条通过。
4. 回滚：本 change 只改文档/脚本注释，按节 `git restore --worktree` 对应文件即可；无 schema/数据迁移、无新依赖、无部署形态变化。

## Open Questions

- 无。DOC2 的解决方案选择（置位声明 vs 字节级替换）不影响本 change 的文本任务：本 change 只保证 README 不再撒谎并指向承接 change；最终写实形态由 `veil-gateway-fidelity-fix` 落地时复核。
