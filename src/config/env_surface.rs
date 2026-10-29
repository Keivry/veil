//! 进程 env 边界收敛：环境变量白名单、迁移清单、过滤与置位告警。
//!
//! 本模块是「进程 env → 配置」路径的唯一边界层：`Config::from_env` 在收集进程
//! env 后先经 [`warn_migrated_and_legacy`]（在**原始** map 上检出、warn-before-drop），
//! 再经 [`filter_process_env`] 剔除白名单外的键，最后交文件层合并与既有校验链。
//!
//! 冻结接口（跨 agent 锁步测试依赖这些精确名字与语义）：
//! - [`CONFIG_ENV_WHITELIST`]：9 个具名环境变量；
//! - [`MIGRATED_ENV_VARS`]：49 个迁移清单变量（含全部兼容别名）；
//! - [`parse_llm_port`]：`LLM_<port>` 解析唯一实现（`load_llm` 复用同一语义）；
//! - [`filter_process_env`]：仅保留白名单名，其余（含 `LLM_<port>` 模式键）剔除；
//! - [`warn_migrated_and_legacy`]：迁移/`LLM_<port>`/遗留置位告警，绝不返回 `Err`、绝不拒启动。
//!
//! 注意：过滤只作用于**进程 env**；`Config::load_from(&HashMap)` 的注入通道
//! （测试注入与文件层「映射为规范 env 名后注入」）不被过滤，禁止另设第二套过滤。

use {super::validate, std::collections::HashMap};

/// 环境变量白名单（恰 9 个具名变量）。
///
/// 判定原则：① 引导悖论——配置文件路径本身不能来自文件（`VEIL_CONFIG_FILE`）；
/// ② 进程上下文直读——配置加载之前/之外消费；③ 密钥注入——保留「不落盘」偏好。
/// `LLM_<port>` 模式不在白名单内：其进程 env 面已关闭、置位仅告警（见
/// [`warn_migrated_and_legacy`]）；[`parse_llm_port`] 仍供 `load_llm` 解析文件值使用。
pub(crate) const CONFIG_ENV_WHITELIST: [&str; 9] = [
    // ① 引导
    "VEIL_CONFIG_FILE",
    // ② Config 外直读
    "RUST_LOG",
    "HOME",
    "VEIL_ALLOW_MOCK_TPM",
    // ③ 密钥注入
    "MATRIX_ACCESS_TOKEN",
    "OBSERVABILITY_ADMIN_TOKEN",
    "VEILCTL_SECRET",
    "VEILCTL_BINARY_HASH",
    "PII_VALUE_SAMPLE_HMAC_KEY",
];

/// 迁移清单：49 个已迁移到配置文件、不再从进程 env 读取的变量名（含全部兼容别名）。
///
/// 分组（与 `specs/config-env-surface` 及 design D11 逐项一致）：脱敏 20、
/// PII 作用域 5、审计 6、认证/入口/存储 12、LLM/限额 6。任一置位仅告警、不生效。
pub(crate) const MIGRATED_ENV_VARS: [&str; 49] = [
    // 脱敏 20（含全部兼容别名）
    "REDACTION_ENABLED",
    "PII_REDACTION_ENABLED",
    "PII_FUZZY_RESTORE",
    "PII_DETECTION_HARDENING",
    "PII_CUSTOM_RULES_FILE",
    "PII_RULES_FILE",
    "PII_CUSTOM_RULES",
    "PII_CUSTOM_PATTERNS_FILE",
    "PII_CUSTOM_PATTERN_FILE",
    "PII_CUSTOM_PATTERNS",
    "PII_CUSTOM_DICT_FILE",
    "PII_DICT_FILE",
    "PII_SENSITIVE_DICT_FILE",
    "PII_SENSITIVE_NAMES_FILE",
    "PII_CUSTOM_DICT",
    "PII_VALUE_SAMPLE_ENABLED",
    "PII_VALUE_SAMPLE_PERSIST",
    "PII_PLACEHOLDER_PROMPT",
    "PII_PLACEHOLDER_PROMPT_TEXT",
    "NORMALIZE_JSON_WHITESPACE",
    // PII 作用域 5
    "PII_SCOPE_MODE",
    "PII_SCOPE_TTL_SECS",
    "PII_SCOPE_MAX_CONVERSATIONS",
    "PII_PREV_ID_MAX_ENTRIES",
    "PII_SCOPE_KEY_HEADER",
    // 审计 6
    "AUDIT_MODE",
    "AUDIT_TIMEOUT",
    "AUDIT_HOLD_MAX_BYTES",
    "AUDIT_HOLD_MAX_FRAMES",
    "AUDIT_POLICY_FILE",
    "APPROVAL_WHITELIST",
    // 认证/入口/存储 12
    "AUTHORIZATION_TTL_SECS",
    "OBSERVABILITY_DISABLE",
    "AUTO_APPROVE",
    "CREDENTIAL_BLOCK_WAIT",
    "VEIL_ENTRY_MODE",
    "CALLER_REGISTRY_PATH",
    "DB_DIR",
    "TPM_DIR",
    "VEIL_KEEPASS_BACKEND",
    "HOMESERVER",
    "ROOM_ID",
    "DATA_DIR",
    // LLM/限额 6
    "HTTP_TIMEOUT_SECS",
    "HTTP_POOL_MAX_IDLE_PER_HOST",
    "HTTP_POOL_IDLE_TIMEOUT_SECS",
    "NONSTREAM_MAX_BYTES",
    "SSE_FRAME_HARD_BYTES",
    "LLM_UPSTREAM",
];

/// `LLM_<port>` 键解析唯一实现：`strip_prefix("LLM_")` + `parse::<u16>()`。
///
/// 与 `env_parse::load_llm` 同语义，调用方不得各写一套。注意边界 `LLM_+8878`
/// （`u16` 解析接受前导 `+`）亦成立；`LLM_abc`/`LLM_`/越界端口返回 `None`。
pub(crate) fn parse_llm_port(key: &str) -> Option<u16> {
    key.strip_prefix("LLM_")?.parse::<u16>().ok()
}

/// 进程 env 边界过滤：仅保留白名单名，剔除其余键（含 `LLM_<port>` 模式键）。
pub(crate) fn filter_process_env(mut map: HashMap<String, String>) -> HashMap<String, String> {
    map.retain(|key, _| CONFIG_ENV_WHITELIST.contains(&key.as_str()));
    map
}

/// 置位告警（warn-before-drop）：在**原始** map 上检出迁移清单、`LLM_<port>` 模式
/// 与遗留清单中非空（trim 后）置位者并各记一条 `warn!`。
///
/// 迁移项与可解析的 `LLM_<port>` 模式项指名变量并指引改用 `VEIL_CONFIG_FILE`；
/// 不可解析的 `LLM_` 键（如 `LLM_FOO`）静默。遗留项（[`validate::LEGACY_IGNORED_VARS`]）
/// 附带其中文说明。函数返回 `()`——任何路径都不返回 `Err`、不改变生效配置、不拒启动。
pub(crate) fn warn_migrated_and_legacy(map: &HashMap<String, String>) {
    for &name in MIGRATED_ENV_VARS.iter() {
        if map.get(name).is_some_and(|v| !v.trim().is_empty()) {
            tracing::warn!(
                "{name} 不再从进程 env 读取（置位已忽略）；\
                 请改用 VEIL_CONFIG_FILE 指向的 TOML 中的对应配置键"
            );
        }
    }
    for (name, value) in map {
        if parse_llm_port(name).is_some() && !value.trim().is_empty() {
            tracing::warn!(
                "{name} 不再从进程 env 读取（置位已忽略）；\
                 请改用 VEIL_CONFIG_FILE 指向的 TOML 中的对应配置键"
            );
        }
    }
    for name in validate::legacy_ignored_detected(map) {
        let hint = validate::LEGACY_IGNORED_VARS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, hint)| *hint)
            .unwrap_or("见 工程参考 §7.4");
        tracing::warn!("{name} 已置位但二进制不读取（置位已忽略）：{hint}");
    }
}

#[cfg(test)]
mod tests;
