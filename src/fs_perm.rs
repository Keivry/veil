//! 文件权限与 sqlite WAL 单一来源（D2 合一）：库文件及 `-wal`/`-shm` 均 `0600`，
//! 打开口径 `WAL + busy_timeout=5000 + synchronous=NORMAL`。
//!
//! 调用方（`state` 启动初始化、`metrics` 聚合刷盘、`registry` 注册表落盘）MUST 复用
//! 本模块，禁止各文件自建 `chmod`/`PRAGMA` 拷贝（漂移即漏洞）；写库并发约束
//! （`spawn_blocking`）由调用方保证，本模块只做同步打开与权限。

use std::path::Path;

/// 忙等待超时（毫秒），与原仓 `busy_timeout=5000` 同值。
pub const SQLITE_BUSY_TIMEOUT_MS: i64 = 5000;

/// 库文件及 `-wal`/`-shm` 同权 `0600`（缺失兄弟文件跳过；失败仅 warn，不中断调用方）。
pub fn ensure_0600(db_path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut targets = vec![db_path.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        let mut sibling = db_path.as_os_str().to_owned();
        sibling.push(suffix);
        targets.push(Path::new(&sibling).to_path_buf());
    }
    for target in targets {
        if !target.exists() {
            continue;
        }
        if let Err(e) = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("chmod 0600 失败: {}: {e}", target.display());
        }
    }
}

/// 以统一口径打开 sqlite 库：父目录自动创建 + `WAL + busy_timeout + synchronous NORMAL` + `0600`。
pub fn open_wal(db_path: &Path) -> anyhow::Result<rusqlite::Connection> {
    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let conn = rusqlite::Connection::open(db_path)?;
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL;\
         PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};\
         PRAGMA synchronous=NORMAL;"
    ))?;
    ensure_0600(db_path);
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn open_applies_wal_with_0600_perms() {
        let dir = std::env::temp_dir().join(format!("veil-fsperm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("u.sqlite");
        let conn = open_wal(&db).unwrap();
        let journal: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal.to_lowercase(), "wal");
        let busy: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy, SQLITE_BUSY_TIMEOUT_MS);
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 1);
        drop(conn);
        assert_eq!(file_mode(&db), 0o600);
        // 兄弟文件同权：预建 -wal/-shm 空文件后复权。
        for suffix in ["-wal", "-shm"] {
            let mut sibling = db.as_os_str().to_owned();
            sibling.push(suffix);
            let p = Path::new(&sibling).to_path_buf();
            std::fs::write(&p, b"x").unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        ensure_0600(&db);
        for suffix in ["-wal", "-shm"] {
            let mut sibling = db.as_os_str().to_owned();
            sibling.push(suffix);
            assert_eq!(file_mode(Path::new(&sibling)), 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
