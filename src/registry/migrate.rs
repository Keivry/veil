//! Python 旧格式注册表迁移（B6/D6 自 `registry.rs` 拆出）。
//! 生产加载期接入（`C4`/D4）：[`CallerRegistry::load_from`] 在新格式解析/完整性
//! 失败且识别到旧形态时调用 [`CallerRegistry::migrate_python_registry`]。

use {
    super::{
        entry::CallerEntry,
        store::{CallerRegistry, RegistryFile, bind_script_sha256, integrity_of},
    },
    crate::{
        config::AutoApprove,
        error::{Result, VeilError},
        fs_perm::ensure_0600,
    },
    std::{collections::BTreeMap, path::Path},
};

/// 旧格式 `allow_mode` 解析（`CRD-11`）：Python `'auto'`/`'manual'` 与布尔形态均兼容；
/// 未知/缺省返回 `None`（按全局默认，不静默改语义）。
fn legacy_allow_mode(c: &serde_json::Value) -> Option<AutoApprove> {
    let raw = c.get("allow_mode")?;
    if let Some(b) = raw.as_bool() {
        return Some(if b {
            AutoApprove::Allow
        } else {
            AutoApprove::Deny
        });
    }
    match raw.as_str()?.trim().to_ascii_lowercase().as_str() {
        "auto" | "allow" | "true" | "yes" | "1" => Some(AutoApprove::Allow),
        "manual" | "pending" | "none" | "matrix" => Some(AutoApprove::Pending),
        "deny" | "false" | "no" | "0" => Some(AutoApprove::Deny),
        _ => None,
    }
}

impl CallerRegistry {
    /// Python `caller_registry.json` 迁移（`version/callers/allowed_entries` 形态）。
    /// 成功后旧文件保留 `.bak` 备份；新格式文件直接走 [`CallerRegistry::load_from`]。
    /// 生产仅由 `load_from` 在新格式校验失败时调用（`C4`/D4）。
    pub(super) fn migrate_python_registry(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read(path).map_err(|e| VeilError::Storage {
            message: format!("注册表读取失败: {}: {e}", path.display()),
        })?;
        // 先试新格式；失败再试 Python 旧形态。
        if let Ok(file) = serde_json::from_slice::<RegistryFile>(&raw) {
            match integrity_of(&file.entries) {
                Ok(sha) if sha == file.sha256 => {
                    return Ok(Self {
                        entries: file.entries,
                    });
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        let old: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| VeilError::Storage {
                message: format!("注册表解析失败（新旧格式均不匹配）: {e}"),
            })?;
        // Python 形态判定：含 `callers` 数组即视为旧格式。
        let Some(callers) = old.get("callers").and_then(|v| v.as_array()) else {
            return Err(VeilError::Storage {
                message: "注册表解析失败（新旧格式均不匹配）".to_string(),
            });
        };
        tracing::warn!(
            "检测到 Python 旧格式注册表（含 {} 条），迁移为当前格式并保留 .bak",
            callers.len()
        );
        let mut entries = BTreeMap::new();
        for c in callers {
            let caller_path = c
                .get("script_path")
                .or_else(|| c.get("caller_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let expected_hash = c
                .get("script_hash")
                .or_else(|| c.get("caller_hash"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if caller_path.is_empty() || expected_hash.is_empty() {
                continue;
            }
            // `CRD-11`：保留旧 `reg_id`（缺省以 `caller_path` 补齐，不静默丢弃）。
            let reg_id = c
                .get("reg_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| caller_path.clone());
            // 旧条目 allowed_entries：`{"entry": ["field", ...]}` 或字符串数组。
            let mut entry_map = BTreeMap::new();
            if let Some(allowed) = c.get("allowed_entries").and_then(|v| v.as_object()) {
                for (k, v) in allowed {
                    let fields: Vec<String> = match v {
                        serde_json::Value::Array(arr) => arr
                            .iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect(),
                        serde_json::Value::String(s) => vec![s.clone()],
                        _ => Vec::new(),
                    };
                    entry_map.insert(k.clone(), fields);
                }
            }
            entries.insert(
                caller_path.clone(),
                CallerEntry {
                    caller_path: caller_path.clone(),
                    expected_hash: expected_hash.clone(),
                    script_sha256: bind_script_sha256(&caller_path, &expected_hash),
                    enabled: c.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                    revoked: false,
                    auto_approve: None,
                    name: c
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    description: String::new(),
                    entries: entry_map,
                    allow_mode: legacy_allow_mode(c),
                    old_hash: c
                        .get("script_hash_old")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    old_hash_expires_at: c.get("old_hash_expires_at").and_then(|v| v.as_u64()),
                    reg_id,
                },
            );
        }
        let migrated = Self { entries };
        // 旧文件备份 .bak（fail-closed：备份失败则拒绝覆盖写新格式）。
        let bak = path.with_extension("json.bak");
        std::fs::copy(path, &bak).map_err(|e| VeilError::Storage {
            message: format!("旧注册表备份失败（拒绝迁移覆盖）: {e}"),
        })?;
        ensure_0600(&bak);
        migrated.save_to(path)?;
        Ok(migrated)
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::AutoApprove, registry::CallerRegistry};

    #[test]
    fn legacy_python_format_migration_keeps_bak() {
        let dir = std::env::temp_dir().join(format!(
            "veil-reg-mig-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("caller_registry.json");
        let old = serde_json::json!({
            "version": 1,
            "callers": [
                {
                    "script_path": "/s/old.sh",
                    "script_hash": "hold1",
                    "name": "old-job",
                    "enabled": true,
                    "allowed_entries": {"网易": ["授权码"]}
                }
            ]
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&old).unwrap()).unwrap();
        let migrated = CallerRegistry::migrate_python_registry(&path).unwrap();
        assert_eq!(migrated.len(), 1);
        let e = migrated.lookup_by_path("/s/old.sh").unwrap();
        assert_eq!(e.expected_hash, "hold1");
        assert!(e.enabled);
        assert!(e.check_entry_allowed("网易", Some("授权码")));
        assert!(path.with_extension("json.bak").exists(), "旧文件须留 .bak");
        // 迁移后新格式可直接加载。
        let reloaded = CallerRegistry::load_from(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migration_preserves_fields() {
        // CRD-11：迁移保留 old_hash_expires_at/allow_mode/reg_id 三字段，不静默丢弃。
        let dir = std::env::temp_dir().join(format!(
            "veil-reg-mig-fields-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("caller_registry.json");
        let old = serde_json::json!({
            "version": 1,
            "callers": [{
                "reg_id": "legacy-reg-1",
                "script_path": "/s/legacy-grace.sh",
                "script_hash": "legacy-new-h",
                "script_hash_old": "legacy-old-h",
                "old_hash_expires_at": 1_900_000_000u64,
                "allow_mode": "auto",
                "name": "legacy-grace-job",
                "enabled": true,
                "allowed_entries": {"网易": ["授权码"]}
            }]
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&old).unwrap()).unwrap();
        let migrated = CallerRegistry::load_from(&path).unwrap();
        let e = migrated.lookup_by_path("/s/legacy-grace.sh").unwrap();
        assert_eq!(e.reg_id, "legacy-reg-1", "reg_id 迁移后不丢");
        assert_eq!(
            e.allow_mode,
            Some(AutoApprove::Allow),
            "allow_mode 迁移后不丢"
        );
        assert_eq!(
            e.old_hash_expires_at,
            Some(1_900_000_000),
            "old_hash_expires_at 迁移后不丢"
        );
        assert_eq!(e.old_hash.as_deref(), Some("legacy-old-h"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
