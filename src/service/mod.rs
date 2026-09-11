//! 服务层索引：仅模块声明与旧路径重导出（A1 解耦后本文件零业务逻辑）。
//!
//! 依赖方向：`state` 聚合本层类型（`state -> service`）；本层业务经
//! [`credential::AppStateParts`] trait 读态，不再命名 `crate::state`
//! （`service -> state` 边已断，单向无环）。

pub mod admin;
pub mod audit;
pub mod audit_hold;
pub mod block_inject;
pub mod credential;
/// §3 脱敏子模块（单向依赖：只读 `state` 经调用方注入，不触网络与路由）。
pub mod credential_vault;
pub mod json_walk;
pub mod llm_gateway;
pub mod matrix;
pub mod metrics;
pub mod pii;
pub mod redaction;
pub mod sse;
pub mod tpm;

/// 旧路径兼容：`crate::service::{handle_credential, RateTable, ...}`
/// 一律经本重导出解析，调用方零改。
pub use credential::*;

#[cfg(test)]
mod declaration_lock {
    // A1/D1 声明锁定：本文件头部声明（service 零 `crate::state` 命名 +
    // 零 axum 依赖，唯一例外为纯数据 `HeaderMap` 白名单）由本测试自动化证实。
    // 模式串运行期拼接，避免测试自身命中扫描。

    #[test]
    fn service_layer_declaration_matches_implementation() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        assert!(!files.is_empty(), "扫描根须存在");
        let banned = [
            format!("use crate::{}", "state"),
            format!("crate::{}::AppState", "state"),
            format!("State<{}>", "AppState"),
        ];
        let axum_use = ["use", "axum"].join(" ");
        let axum_allow = ["llm_gateway/hop.rs", "llm_gateway/mod.rs"];
        for path in files {
            let rel = path
                .strip_prefix(&root)
                .expect("子路径")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&path).expect("读取成功");
            for pat in &banned {
                assert!(
                    !src.contains(pat.as_str()),
                    "src/service/{rel} 命中禁用模式 {pat:?}（A1 层声明失真）"
                );
            }
            if src.contains(&axum_use) {
                assert!(
                    axum_allow.contains(&rel.as_str()),
                    "src/service/{rel} 出现 {axum_use}，非纯数据白名单（A1/X6）"
                );
            }
        }
    }

    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("目录可读").flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_rs(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
}
