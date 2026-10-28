//! 存储/入口域解析（自 `env_parse.rs` 拆出；`crate::config::env_parse::*`
//! 导出路径不变）。
//!
//! 承载 [`StorageParts`] 与 `load_storage`（目录派生、三因子密钥、入口三态、
//! 审批双模开关、授权窗口），以及授权窗口长度解析。父模块按原调用顺序引用，
//! 默认值、错误顺序与错误消息与拆分前逐项相同。

use {
    super::{AutoApprove, EntryMode},
    crate::{
        config::validate::parse_bool_off,
        error::{Result, VeilError},
    },
    std::path::PathBuf,
};

/// 存储/入口域产物（字段顺序与父模块解构一侧一致）。
pub(super) struct StorageParts {
    pub(super) data_dir: PathBuf,
    pub(super) veilctl_secret: Option<String>,
    pub(super) veilctl_binary_hash: Option<String>,
    pub(super) auto_approve: AutoApprove,
    pub(super) entry_mode: EntryMode,
    pub(super) registry_path: PathBuf,
    pub(super) db_dir: PathBuf,
    pub(super) tpm_dir: PathBuf,
    pub(super) credential_block_wait: bool,
    pub(super) authorization_ttl: Option<u64>,
}

pub(super) fn load_storage(get: &dyn Fn(&str) -> Option<String>) -> Result<StorageParts> {
    let data_dir = get("DATA_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("/data"), PathBuf::from);
    let veilctl_secret = get("VEILCTL_SECRET").filter(|v| !v.is_empty());
    let veilctl_binary_hash = get("VEILCTL_BINARY_HASH").filter(|v| !v.is_empty());
    let auto_approve: AutoApprove = match get("AUTO_APPROVE") {
        Some(v) if !v.is_empty() => v.parse().map_err(|message| VeilError::Config {
            var: "AUTO_APPROVE".to_string(),
            message,
        })?,
        _ => AutoApprove::Allow,
    };
    let entry_mode: EntryMode = match get("VEIL_ENTRY_MODE") {
        Some(v) if !v.is_empty() => v.parse().map_err(|message| VeilError::Config {
            var: "VEIL_ENTRY_MODE".to_string(),
            message,
        })?,
        _ => EntryMode::Full,
    };
    let registry_path = get("CALLER_REGISTRY_PATH")
        .filter(|v| !v.is_empty())
        .map_or_else(|| data_dir.join("caller_registry.json"), PathBuf::from);
    let db_dir = get("DB_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| data_dir.join("db"), PathBuf::from);
    let tpm_dir = get("TPM_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| data_dir.join("tpm"), PathBuf::from);
    let credential_block_wait = parse_bool_off(get, "CREDENTIAL_BLOCK_WAIT");
    let authorization_ttl = parse_authorization_ttl(get)?;
    Ok(StorageParts {
        data_dir,
        veilctl_secret,
        veilctl_binary_hash,
        auto_approve,
        entry_mode,
        registry_path,
        db_dir,
        tpm_dir,
        credential_block_wait,
        authorization_ttl,
    })
}

/// 授权窗口长度解析：缺省 `0`（无期限）；非数字/负数拒启动，`0` 归一为 `None`。
fn parse_authorization_ttl(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<u64>> {
    let raw = get("AUTHORIZATION_TTL_SECS")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "0".to_string());
    let ttl: u64 = raw.parse().map_err(|_| VeilError::Config {
        var: "AUTHORIZATION_TTL_SECS".to_string(),
        message: format!("AUTHORIZATION_TTL_SECS 非法整数: {raw:?}"),
    })?;
    Ok(crate::registry::normalize_ttl(Some(ttl)))
}
