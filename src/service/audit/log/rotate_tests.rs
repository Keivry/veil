//! 审计日志轮转与产物权限单测（`POL-4`/`A1`；独立子模块保 `log.rs` 800 行红线）：
//! 轮转生成 `.1`、备份份数上限、轮转产物创建即 `0600`。

use super::*;

fn unique_rotate_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "veil-audit-rotate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn audit_log_rotate_five() {
    // A1/1.2：以小阈值触发轮转（免写 10MB），断言 audit.log.1 生成且备份份数上限 5。
    let dir = unique_rotate_dir();
    let logger = AuditLogger::with_max_bytes(dir.clone(), 128);
    for i in 0..400 {
        logger
            .log_event(&serde_json::json!({"n": i, "kind": "block"}))
            .unwrap();
    }
    assert!(dir.join("audit.log.1").exists(), "轮转后须生成 audit.log.1");
    let backups = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
        .count();
    assert!(
        backups <= AUDIT_LOG_KEEP,
        "备份份数上限 {AUDIT_LOG_KEEP}，实际 {backups}"
    );
    for line in std::fs::read_to_string(logger.log_path()).unwrap().lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn audit_log_rotate_products_0600() {
    // `POL-4`/D4：轮转产物（当前 `audit.log` 与 `.1`）权限均为 `0600`。
    use std::os::unix::fs::PermissionsExt as _;
    let dir = unique_rotate_dir();
    let logger = AuditLogger::with_max_bytes(dir.clone(), 128);
    for i in 0..400 {
        logger
            .log_event(&serde_json::json!({"n": i, "kind": "block"}))
            .unwrap();
    }
    for name in ["audit.log", "audit.log.1"] {
        let mode = std::fs::metadata(dir.join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name} 权限须为 0600");
    }
    std::fs::remove_dir_all(&dir).ok();
}
