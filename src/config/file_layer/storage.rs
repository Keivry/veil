//! `[storage]` 与 `[request_log]` 分节（自 `file_layer.rs` 拆出；
//! `crate::config::file_layer::*` 导出路径不变）。
//!
//! `[storage]` 只保留路径与部署密钥（`data_dir` / `db_dir` / `tpm_dir` /
//! `caller_registry_path` / `veilctl_secret` / `veilctl_binary_hash`）：行为与策略类
//! 字段已迁至 `[credential]` / `[request_log]`（旧键经别名表承接）。
//!
//! `[request_log]` 两个**文件专属**标量键（`enabled` / `retention_days`）以
//! [`MappingTarget::FileOnly`] 登记：区别在于 `FILE_ONLY_KEYS` 是**结构键根**
//! （整表无 env 面），它们是标量键，仍需出现在封闭映射表的键集锁步里，故不进
//! `FILE_ONLY_KEYS`，而是映射目标本身声明「无 env 写出」——值经
//! [`RequestLogFileConfig`] 直达 `Config`。

use {
    super::{Coercion, MappingDef, MappingTarget, env},
    serde::{Deserialize, Serialize},
};

/// `[storage]`：路径与部署密钥域。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    pub data_dir: Option<String>,
    pub db_dir: Option<String>,
    pub tpm_dir: Option<String>,
    pub caller_registry_path: Option<String>,
    pub veilctl_secret: Option<String>,
    pub veilctl_binary_hash: Option<String>,
}

/// `[request_log].enabled` 内建默认值（启用请求日志）。
pub(crate) const REQUEST_LOG_ENABLED_DEFAULT: bool = true;

/// `[request_log].retention_days` 内建默认值（天；`0` 表示不清理）。
pub(crate) const REQUEST_LOG_RETENTION_DAYS_DEFAULT: u64 = 7;

/// `[request_log]` 两键的生效值（缺省填充后的产物，随 `FileLayerOutcome` 进 `Config`）。
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
    /// 由 `[request_log]` 声明填充缺省；分节缺失或单键缺失均取内建默认。
    pub(crate) fn from_request_log(section: Option<&super::RequestLogSection>) -> Self {
        let Some(section) = section else {
            return Self::default();
        };
        Self {
            enabled: section.enabled.unwrap_or(REQUEST_LOG_ENABLED_DEFAULT),
            retention_days: section
                .retention_days
                .unwrap_or(REQUEST_LOG_RETENTION_DAYS_DEFAULT),
        }
    }
}

// ---- `[request_log]` / `[storage]` 逐键映射条目（父模块 `MAPPINGS` 在此按原顺序收录）----

pub(super) const REQUEST_LOG_ENABLED: MappingDef = MappingDef {
    key: "request_log.enabled",
    target: MappingTarget::FileOnly,
    env_explicit_names: &[],
    coercion: Coercion::Plain,
};
pub(super) const REQUEST_LOG_RETENTION_DAYS: MappingDef = MappingDef {
    key: "request_log.retention_days",
    target: MappingTarget::FileOnly,
    env_explicit_names: &[],
    coercion: Coercion::Plain,
};
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
