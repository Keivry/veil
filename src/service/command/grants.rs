//! accept-always 运行时授权：`data_dir/command_grants.json` 的加载与原子写。
//!
//! 授权文件损坏/缺失按空处理（fail-closed 回退审批）；写路径 `0600` 且
//! 先写临时文件再 `rename`，避免半截 JSON。

use {
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeSet,
        io::Write as _,
        path::{Path, PathBuf},
    },
};

/// 文件内版本号（后续撤销/列举入口可演进）。
const GRANTS_VERSION: u32 = 1;
/// 数据目录内的文件名。
pub const GRANTS_FILE_NAME: &str = "command_grants.json";

/// 授权键：（调用者身份, 命令 id, 目标 host）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantKey {
    pub caller_path: String,
    pub command: String,
    pub host: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsFile {
    version: u32,
    grants: Vec<GrantKey>,
}

/// 运行时授权表。
#[derive(Debug)]
pub struct CommandGrants {
    path: PathBuf,
    grants: tokio::sync::RwLock<BTreeSet<GrantKey>>,
    /// 落盘串行化：并发 insert 不得互相截断临时文件或丢失授权。
    write_lock: tokio::sync::Mutex<()>,
    /// 临时文件名唯一后缀（进程内单调）。
    seq: std::sync::atomic::AtomicU64,
}

impl CommandGrants {
    /// 启动期加载：缺失返回空表；不可解析按空处理并 `warn`（fail-closed 回退审批）。
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(GRANTS_FILE_NAME);
        let grants = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<GrantsFile>(&text) {
                Ok(file) => file.grants.into_iter().collect(),
                Err(err) => {
                    tracing::warn!(
                        "命令授权文件解析失败（按空授权处理）{}: {err}",
                        path.display()
                    );
                    BTreeSet::new()
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(err) => {
                tracing::warn!(
                    "命令授权文件读取失败（按空授权处理）{}: {err}",
                    path.display()
                );
                BTreeSet::new()
            }
        };
        Self {
            path,
            grants: tokio::sync::RwLock::new(grants),
            write_lock: tokio::sync::Mutex::new(()),
            seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn path(&self) -> &Path { &self.path }

    pub async fn contains(&self, caller_path: &str, command: &str, host: &str) -> bool {
        self.grants.read().await.contains(&GrantKey {
            caller_path: caller_path.to_string(),
            command: command.to_string(),
            host: host.to_string(),
        })
    }

    /// 写入新授权（幂等）；落盘失败仅 `warn`，本次放行仍成立。
    pub async fn insert(&self, caller_path: &str, command: &str, host: &str) {
        let key = GrantKey {
            caller_path: caller_path.to_string(),
            command: command.to_string(),
            host: host.to_string(),
        };
        // 先持写锁再取快照，保证「快照 + 落盘」整体串行。
        let _write = self.write_lock.lock().await;
        let mut guard = self.grants.write().await;
        if !guard.insert(key) {
            return;
        }
        let file = GrantsFile {
            version: GRANTS_VERSION,
            grants: guard.iter().cloned().collect(),
        };
        drop(guard);
        let tmp = self.path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        if let Err(err) = write_atomic(&self.path, &tmp, &file) {
            tracing::warn!(
                "命令授权文件写入失败（本次放行仍生效，重启后可能失效）{}: {err}",
                self.path.display()
            );
        }
    }

    #[cfg(test)]
    pub(crate) async fn len(&self) -> usize { self.grants.read().await.len() }
}

fn write_atomic(path: &Path, tmp: &Path, file: &GrantsFile) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec_pretty(file)
        .map_err(|err| std::io::Error::other(format!("序列化失败: {err}")))?;
    {
        let mut handle = std::fs::File::create(tmp)?;
        handle.write_all(&bytes)?;
        handle.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "veil-grants-{}-{tag}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn persists_and_reloads() {
        let dir = temp_dir("persist");
        let grants = CommandGrants::load(&dir);
        assert!(!grants.contains("/opt/ci/a.sh", "deploy", "api").await);
        grants.insert("/opt/ci/a.sh", "deploy", "api").await;
        assert!(grants.contains("/opt/ci/a.sh", "deploy", "api").await);
        assert_eq!(mode(grants.path()), 0o600);

        let reloaded = CommandGrants::load(&dir);
        assert!(reloaded.contains("/opt/ci/a.sh", "deploy", "api").await);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn insert_is_idempotent() {
        let dir = temp_dir("idem");
        let grants = CommandGrants::load(&dir);
        grants.insert("/opt/ci/a.sh", "deploy", "api").await;
        grants.insert("/opt/ci/a.sh", "deploy", "api").await;
        assert_eq!(grants.len().await, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn concurrent_inserts_keep_all_grants() {
        let dir = temp_dir("concurrent");
        let grants = std::sync::Arc::new(CommandGrants::load(&dir));
        let mut tasks = Vec::new();
        for i in 0..8 {
            let grants = grants.clone();
            tasks.push(tokio::spawn(async move {
                grants
                    .insert("/opt/ci/a.sh", &format!("cmd-{i}"), "api")
                    .await;
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(grants.len().await, 8, "并发写入不得丢授权");
        let reloaded = CommandGrants::load(&dir);
        assert_eq!(reloaded.len().await, 8, "落盘后重启须读回全部授权");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn corrupt_file_falls_back_to_empty() {
        let dir = temp_dir("corrupt");
        let path = dir.join(GRANTS_FILE_NAME);
        std::fs::write(&path, b"{not-json").unwrap();
        let grants = CommandGrants::load(&dir);
        assert!(!grants.contains("/opt/ci/a.sh", "deploy", "api").await);
        std::fs::remove_dir_all(&dir).ok();
    }
}
