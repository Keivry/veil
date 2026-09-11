## 1. AUDIT_ENABLED 接线（X1/D1）

- [x] 1.1 `src/config/env_parse.rs::load_from`：`AUDIT_MODE` 缺失/空白时调用 `audit_enabled_compat(env)` 回退（`Some`→对应模式，`None`→`off`），显式非空 `AUDIT_MODE` 优先且不触发回退；回退生效时打指名 warn。验证：`cargo test --lib audit_enabled_fallback_at_config_load` 通过（用例见 1.2/1.3）
- [x] 1.2 `src/service/audit/verdict.rs::audit_enabled_compat`：真值集合扩为 `1/true/yes/on`（trim + 小写），`AUDIT_MODE` 存在但为空白按缺失处理，非真值不生效。验证：`cargo test --lib legacy_audit_enabled` 断言四种真值均 `Some(Block)`、`0/off/bogus/空白` 均 `None`、显式 `AUDIT_MODE` 时均 `None`
- [x] 1.3 新增 `Config::load_from` 级集成测试：无 `AUDIT_MODE` + `AUDIT_ENABLED=1` → `audit_mode == Block`；+ `AUDIT_ENABLED=on` → `Block`；`AUDIT_MODE=off` + `AUDIT_ENABLED=1` → `Off`；`AUDIT_MODE=approve` + `APPROVAL_WHITELIST` + `AUDIT_ENABLED=1` → `Approve`；`AUDIT_ENABLED=0` → `Off`。验证：`cargo test --lib audit_enabled_fallback_at_config_load` 全绿
- [x] 1.4 修正旧规格措辞：`openspec/changes/veil-full-parity-fix/specs/audit-parity/spec.md:9` 的「旧 `AUDIT_ENABLED` 兼容」补触发条件（`AUDIT_MODE` 缺失/空白）、真值集合与 `Config::load_from` 回退点；`tasks.md:26` 补实际接线证据。验证：`openspec validate veil-full-parity-fix --strict` 通过，且人工比对两处措辞与本 change spec 同义

## 2. legacy warn 完整性（D6/X10/F4）

- [x] 2.1 （D6）`src/config/validate.rs::LEGACY_IGNORED_VARS` 纳入 `ENV`、`ALLOW_LOOPBACK_NO_TOKEN`（hint 指向 §6.6：dev 显式配置 `OBSERVABILITY_ADMIN_TOKEN` 并携带 `X-Admin-Token`）。验证：`cargo test --lib legacy_warn_covers_env_loopback_and_api_port` 断言两变量非空置位均被 `legacy_ignored_detected` 命中、空值不命中
- [x] 2.2 （F4）同清单纳入 `CREDENTIAL_API_PORT`（hint：入口统一走 `VEIL_ENTRY_MODE` + 单端口 `8877`，见 §8.4）；现有 `load_from` warn 循环自动覆盖新增项，不得另建 dead code。验证：`cargo test --lib legacy_warn_covers_env_loopback_and_api_port` 断言该变量非空命中、空值不命中，且 `Config::load_from` 对三者成功加载、配置生效值不变
- [x] 2.3 （X10）新增集合锁单测：`LEGACY_IGNORED_VARS` 名称集合恰为六项固定集合（`CREDENTIAL_MASTER_PASSWORD`、`CREDENTIAL_PORT`、`CREDENTIAL_PROXY_DEBUG_DIR`、`ENV`、`ALLOW_LOOPBACK_NO_TOKEN`、`CREDENTIAL_API_PORT`），且每项 hint 非空。验证：`cargo test --lib legacy_ignored_vars_set_locked` 通过，删改任一变量即失败
- [x] 2.4 （D6/X10/F4）README §7.4 与清单锁步：`ENV`/`ALLOW_LOOPBACK_NO_TOKEN` 拆为逐变量一行、新增 `CREDENTIAL_API_PORT` 行；新增 `legacy_vars_readme_lockstep` 测试解析 README §7.4 首列变量名并与清单集合相等（不引入外部脚本）。验证：`cargo test --lib legacy_vars_readme_lockstep` 通过；单侧增删任一变量即失败

## 3. 文档同步（X1/D7/F4）

- [x] 3.1 （X1）README 环境变量全表审计分组新增 `AUDIT_ENABLED` 行：`AUDIT_MODE` 缺失/空白时真值 `1/true/yes/on` → `block`（fail-closed），显式 `AUDIT_MODE` 优先，缺省仍 `off`。验证：`grep -n 'AUDIT_ENABLED' README.md` 命中且在审计分组，`python3 scripts/check_doc_paths.py` 通过
- [x] 3.2 （D7）README 的 `CREDENTIAL_BLOCK_WAIT` 行改真值表述：开启条件写明 `1/true/yes/on`（trim + 大小写不敏感）且默认关闭，示例保留 `CREDENTIAL_BLOCK_WAIT=1`。验证：行内不再仅以「`=1` 时」表述开启条件，且措辞与 `cargo test --lib approval_block_wait_default_off` 口径一致
- [x] 3.3 （F4/D6）README §7.4 行文补 rationale：`CREDENTIAL_API_PORT` 注明「入口统一：`VEIL_ENTRY_MODE` + 单端口 `8877`（见 §8.4）」；`ENV`/`ALLOW_LOOPBACK_NO_TOKEN` 行补「置位启动 warn」口径。验证：人工比对 §7.4 每行与 `LEGACY_IGNORED_VARS` hint 同义，`python3 scripts/check_doc_paths.py` 通过
- [x] 3.4 全量门禁：格式化、lint、测试与 spec 校验一次跑齐。验证：`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && openspec validate veil-config-legacy-compat --strict` 全绿零失败
