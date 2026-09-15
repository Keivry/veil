## ADDED Requirements

### Requirement: README 源码定位指针与实现一致

README 中对 `src/` 的符号/文件定位引用 SHALL 指向归档后实际存在的路径与符号：README §6.4 的流式审批内存 pending 建单指针 SHALL 指向 ARC-1 迁移后的 `src/handler/llm/pump/spawn/event_loop.rs:414`，SHALL NOT 沿用已迁移的旧路径 `spawn.rs::audit_pending`。

#### Scenario: §6.4 指针可解析

- **WHEN** 核查 README §6.4 的 `audit-hold` 内存 pending 建单指针
- **THEN** 指向 `src/handler/llm/pump/spawn/event_loop.rs:414`，该路径存在且与实现一致，零命中已迁移的 `spawn.rs::audit_pending`

### Requirement: README 测试口径标签与脚本一致

README §8.5 的真 SDK 一致性口径 SHALL 采用脚本 23 项约定（`scripts/api_conformance.py` 23 项 = 14 常规 + 3 阻断 + 5 取用 + 1 无库 503），SHALL NOT 以错位的「12 项（cargo）」标签描述本仓脚本口径，避免与脚本实际计数冲突；原仓对照如需保留历史 cargo 口径 SHALL 明确标注其归属，不与本仓脚本口径混用。

#### Scenario: 标签与脚本计数一致

- **WHEN** 对照 README §8.5 与 `scripts/api_conformance.py` 输出的项数
- **THEN** 本仓口径为 23 项且明细（14 常规 + 3 阻断 + 5 取用 + 1 无库 503）一致；「12 项（cargo）」不再作为本仓脚本口径标签出现

### Requirement: 文档行号引用可校验

`scripts/check_doc_paths.py` SHALL 在路径存在性校验之外，解析 `path:line`（含 `path:start-end`）形式的行号引用并校验其落在目标文件实际行数范围内；行号越界 SHALL 非零退出并打印悬空引用所在文件与行。该校验 SHALL 纳入 `scripts/gate.sh` 的文档路径步骤，作为文档行号漂移的根因治理；对非 `path:line` 形态的引用（如纯符号引用）SHALL 保持路径存在性校验不变。

#### Scenario: 越界行号致门禁失败

- **WHEN** 文档某 `path:line` 引用的行号超出目标文件实际行数（以临时构造的越界用例验证）
- **THEN** `scripts/check_doc_paths.py` 非零退出并列出该悬空引用，gate 文档路径步骤失败

#### Scenario: 合法行号引用通过

- **WHEN** 文档引用 `src/handler/llm/pump/spawn/event_loop.rs:414`（在文件行数范围内）
- **THEN** 校验通过、退出码 0，并报告行号引用校验计数

## MODIFIED Requirements

### Requirement: 环境变量表完整

二进制读取的每个环境变量 SHALL 在 README 环境变量表有可检索的行；新增读取 SHALL 同 change 补行；README:26 的「未列出的变量二进制不读取」断言 SHALL 在补录完成后为真。

#### Scenario: 隐藏开关被补录

- **WHEN** 核查 `OBSERVABILITY_DISABLE`（`src/config/env_parse.rs:342-347`、`src/router.rs:19-28`）
- **THEN** README 变量表含该行，语义为精确 `=1`（去空白）时 `/_admin*` 全 404 且与 token 有效性无关（`tests/http_e2e_admin_matrix.rs:252-254`）

#### Scenario: 完整性断言可复核

- **WHEN** 用 grep 从 `src/config/env_parse.rs` 提取 `get("...")` 变量名，与 README 环境变量表的反引号变量名做差集
- **THEN** 差集为空（表外无二进制读取变量）
