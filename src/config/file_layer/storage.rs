//! `[storage]` 分节（自 `file_layer.rs` 拆出；`crate::config::file_layer::*`
//! 导出路径不变）。
//!
//! 承载 `[storage]` 的 schema（[`StorageSection`]）、两个文件枚举
//! （`auto_approve` / `entry_mode`）、该分节的逐键映射条目，以及两个**文件专属**
//! 标量键（`request_log_enabled` / `request_log_retention_days`）的默认值与解析产物。
//!
//! 逐键映射条目以常量形式由父模块的封闭清单 `MAPPINGS` 按原顺序收录，故 env 名集合
//! 与拆分前逐一相同。两个文件专属键以 [`MappingTarget::FileOnly`] 登记：区别于
//! `FILE_ONLY_KEYS` 的**结构键根**（`[llm.targets]` 等整表无 env 面），它们是标量键，
//! 仍需出现在封闭映射表的键集锁步里，故不进 `FILE_ONLY_KEYS`，而是映射目标本身声明
//! 「无 env 写出」——值经 [`RequestLogFileConfig`] 直达 `Config`。

use {
    super::{Coercion, MappingDef, MappingTarget, env},
    serde::{Deserialize, Serialize},
};

/// `[storage].entry_mode` 文件取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileEntryMode {
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "credential-only")]
    CredentialOnly,
    #[serde(rename = "llm-only")]
    LlmOnly,
}

/// `[storage].auto_approve` 文件取值（映射为 env 令牌 `true/false/pending`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileAutoApprove {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "pending")]
    Pending,
}

/// `[storage]`：存储/入口域。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    pub data_dir: Option<String>,
    pub db_dir: Option<String>,
    pub tpm_dir: Option<String>,
    pub caller_registry_path: Option<String>,
    pub veilctl_secret: Option<String>,
    pub veilctl_binary_hash: Option<String>,
    pub auto_approve: Option<FileAutoApprove>,
    pub entry_mode: Option<FileEntryMode>,
    pub credential_block_wait: Option<bool>,
    pub authorization_ttl_secs: Option<u64>,
    /// 请求日志总开关（文件专属，无 env 对应源）；缺省取
    /// [`REQUEST_LOG_ENABLED_DEFAULT`]。
    pub request_log_enabled: Option<bool>,
    /// 请求记录保留天数（文件专属，无 env 对应源）；`0` = 不清理，缺省取
    /// [`REQUEST_LOG_RETENTION_DAYS_DEFAULT`]。
    pub request_log_retention_days: Option<u64>,
}

/// `[storage].request_log_enabled` 内建默认值（启用请求日志）。
pub(crate) const REQUEST_LOG_ENABLED_DEFAULT: bool = true;

/// `[storage].request_log_retention_days` 内建默认值（天；`0` 表示不清理）。
pub(crate) const REQUEST_LOG_RETENTION_DAYS_DEFAULT: u64 = 7;

/// `[storage]` 两个请求日志键的生效值（缺省填充后的产物，随
/// `FileLayerOutcome` 进 `Config`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLogFileConfig {
    pub enabled: bool,
    pub retention_days: u64,
}

impl Default for RequestLogFileConfig {
    fn default() -> Self {
        Self {
            enabled: REQUEST_LOG_ENABLED_DEFAULT,
            retention_days: REQUEST_LOG_RETENTION_DAYS_DEFAULT,
        }
    }
}

impl RequestLogFileConfig {
    /// 由文件声明填充缺省；分节缺失或单键缺失均取内建默认。
    pub(crate) fn from_storage(section: Option<&StorageSection>) -> Self {
        let Some(section) = section else {
            return Self::default();
        };
        Self {
            enabled: section
                .request_log_enabled
                .unwrap_or(REQUEST_LOG_ENABLED_DEFAULT),
            retention_days: section
                .request_log_retention_days
                .unwrap_or(REQUEST_LOG_RETENTION_DAYS_DEFAULT),
        }
    }
}

// ---- `[storage]` 逐键映射条目（父模块 `MAPPINGS` 在此按原顺序收录）----

pub(super) const STORAGE_DATA_DIR: MappingDef = env("storage.data_dir", "DATA_DIR", &["DATA_DIR"]);
pub(super) const STORAGE_DB_DIR: MappingDef = env("storage.db_dir", "DB_DIR", &["DB_DIR"]);
pub(super) const STORAGE_TPM_DIR: MappingDef = env("storage.tpm_dir", "TPM_DIR", &["TPM_DIR"]);
pub(super) const STORAGE_CALLER_REGISTRY_PATH: MappingDef = env(
    "storage.caller_registry_path",
    "CALLER_REGISTRY_PATH",
    &["CALLER_REGISTRY_PATH"],
);
pub(super) const STORAGE_VEILCTL_SECRET: MappingDef = env(
    "storage.veilctl_secret",
    "VEILCTL_SECRET",
    &["VEILCTL_SECRET"],
);
pub(super) const STORAGE_VEILCTL_BINARY_HASH: MappingDef = env(
    "storage.veilctl_binary_hash",
    "VEILCTL_BINARY_HASH",
    &["VEILCTL_BINARY_HASH"],
);
pub(super) const STORAGE_AUTO_APPROVE: MappingDef = MappingDef {
    key: "storage.auto_approve",
    target: MappingTarget::Env("AUTO_APPROVE"),
    env_explicit_names: &["AUTO_APPROVE"],
    coercion: Coercion::AutoApprove,
};
pub(super) const STORAGE_ENTRY_MODE: MappingDef = env(
    "storage.entry_mode",
    "VEIL_ENTRY_MODE",
    &["VEIL_ENTRY_MODE"],
);
pub(super) const STORAGE_CREDENTIAL_BLOCK_WAIT: MappingDef = env(
    "storage.credential_block_wait",
    "CREDENTIAL_BLOCK_WAIT",
    &["CREDENTIAL_BLOCK_WAIT"],
);
pub(super) const STORAGE_AUTHORIZATION_TTL_SECS: MappingDef = env(
    "storage.authorization_ttl_secs",
    "AUTHORIZATION_TTL_SECS",
    &["AUTHORIZATION_TTL_SECS"],
);
pub(super) const STORAGE_REQUEST_LOG_ENABLED: MappingDef = MappingDef {
    key: "storage.request_log_enabled",
    target: MappingTarget::FileOnly,
    env_explicit_names: &[],
    coercion: Coercion::Plain,
};
pub(super) const STORAGE_REQUEST_LOG_RETENTION_DAYS: MappingDef = MappingDef {
    key: "storage.request_log_retention_days",
    target: MappingTarget::FileOnly,
    env_explicit_names: &[],
    coercion: Coercion::Plain,
};
