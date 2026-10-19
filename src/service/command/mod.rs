//! 受控命令执行：配置、授权、执行后端、日志与运行时状态。

pub mod api;
pub mod exec;
pub mod grants;
pub mod log_store;

use {
    super::RateTable,
    crate::config::CommandConfig,
    std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    },
};
pub use {
    api::{InvokeRequest, InvokeResult, Terminal, catalog, invoke},
    exec::{CommandBackend, CommandOutput, LocalBackend},
    grants::CommandGrants,
    log_store::{CommandLogStore, InvocationLog, LogFilter, LogPage},
};

/// 待审批调用的完整上下文（幂等键对应的在途记录）。
#[derive(Debug, Clone)]
pub(crate) struct PendingInvocation {
    pub event_id: String,
    pub pending_key: String,
    pub caller_path: String,
    pub caller_hash: String,
    pub downstream: String,
    pub command_id: String,
    pub host: String,
    pub program: PathBuf,
    pub argv: Vec<String>,
    pub timeout_secs: u64,
    pub params_json: String,
}

/// 在途记录保留窗口：审批最长 300s，留余量。
const PENDING_RECORD_TTL: Duration = Duration::from_secs(600);
/// 终态记录保留窗口：窗口内重入返回同一结果，过期后视为新的独立调用。
const DONE_RECORD_TTL: Duration = Duration::from_secs(300);

/// 幂等键槽位：在途或已决终态。
#[derive(Clone, Debug)]
pub(crate) enum ExecutionEntry {
    Pending(Arc<PendingInvocation>),
    Done(Arc<Terminal>),
}

/// 带存活时间的槽位（保证内存有界且过期后可重新执行）。
#[derive(Clone, Debug)]
struct ExecutionRecord {
    entry: ExecutionEntry,
    created: Instant,
}

impl ExecutionRecord {
    fn is_expired(&self, now: Instant) -> bool {
        let ttl = match self.entry {
            ExecutionEntry::Pending(_) => PENDING_RECORD_TTL,
            ExecutionEntry::Done(_) => DONE_RECORD_TTL,
        };
        now.duration_since(self.created) >= ttl
    }
}

/// 命令面运行时（`AppState.command` 持有）。
pub struct CommandRuntime {
    pub config: Arc<CommandConfig>,
    pub log: Arc<CommandLogStore>,
    pub grants: Arc<CommandGrants>,
    pub backend: Arc<dyn CommandBackend>,
    pub hits: Arc<tokio::sync::Mutex<RateTable>>,
    executions: Mutex<HashMap<String, ExecutionRecord>>,
    locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl std::fmt::Debug for CommandRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandRuntime")
            .field("enabled", &self.config.enabled)
            .field("commands", &self.config.commands.len())
            .finish_non_exhaustive()
    }
}

impl CommandRuntime {
    /// 装配运行时：启用时才建 `commands.sqlite`；未启用零盘面副作用。
    pub fn new(config: CommandConfig, data_dir: &Path) -> anyhow::Result<Self> {
        let enabled = config.enabled;
        let log = if enabled {
            CommandLogStore::open(data_dir)?
        } else {
            CommandLogStore::unopened(data_dir)
        };
        Ok(Self {
            config: Arc::new(config),
            log: Arc::new(log),
            grants: Arc::new(CommandGrants::load(data_dir)),
            backend: Arc::new(LocalBackend::new(data_dir.join("command-work"))),
            hits: Arc::new(tokio::sync::Mutex::new(RateTable::new())),
            executions: Mutex::new(HashMap::new()),
            locks: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub fn with_backend(mut self, backend: Arc<dyn CommandBackend>) -> Self {
        self.backend = backend;
        self
    }

    /// 读取槽位：顺带清扫过期记录（内存恒有界）。
    pub(crate) fn entry(&self, key: &str) -> Option<ExecutionEntry> {
        let now = Instant::now();
        let mut guard = self.executions.lock().ok()?;
        guard.retain(|_, record| !record.is_expired(now));
        guard.get(key).map(|record| record.entry.clone())
    }

    pub(crate) fn set_pending(&self, key: &str, pending: Arc<PendingInvocation>) {
        if let Ok(mut guard) = self.executions.lock() {
            guard.insert(
                key.to_string(),
                ExecutionRecord {
                    entry: ExecutionEntry::Pending(pending),
                    created: Instant::now(),
                },
            );
        }
    }

    pub(crate) fn set_done(&self, key: &str, terminal: Terminal) {
        if let Ok(mut guard) = self.executions.lock() {
            guard.insert(
                key.to_string(),
                ExecutionRecord {
                    entry: ExecutionEntry::Done(Arc::new(terminal)),
                    created: Instant::now(),
                },
            );
        }
    }

    pub(crate) async fn key_lock(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut guard = self.locks.lock().await;
        guard
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub(crate) async fn remove_lock(&self, key: &str) { self.locks.lock().await.remove(key); }
}

#[cfg(test)]
mod tests {
    use {super::*, std::time::Duration};

    fn pending(key: &str) -> Arc<PendingInvocation> {
        Arc::new(PendingInvocation {
            event_id: "$e".to_string(),
            pending_key: key.to_string(),
            caller_path: "/opt/ci/a.sh".to_string(),
            caller_hash: "h".to_string(),
            downstream: "ci".to_string(),
            command_id: "run".to_string(),
            host: "api".to_string(),
            program: PathBuf::from("/bin/echo"),
            argv: Vec::new(),
            timeout_secs: 10,
            params_json: "{}".to_string(),
        })
    }

    fn runtime(tag: &str) -> CommandRuntime {
        let dir = std::env::temp_dir().join(format!(
            "veil-cmdruntime-{}-{tag}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        CommandRuntime::new(CommandConfig::default(), &dir).unwrap()
    }

    #[test]
    fn done_records_expire_so_new_calls_can_execute() {
        let rt = runtime("expire");
        rt.set_done(
            "k",
            Terminal::Executed {
                approval_status: "not_required".to_string(),
                approval_event_id: None,
                host: "api".to_string(),
                output: CommandOutput {
                    exit_code: Some(0),
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                    duration_ms: 1,
                    timed_out: false,
                    truncated: false,
                },
            },
        );
        assert!(rt.entry("k").is_some(), "新记录可读");
        // 手工把创建时间回拨到 TTL 之外，验证清扫。
        if let Ok(mut guard) = rt.executions.lock()
            && let Some(record) = guard.get_mut("k")
        {
            record.created = Instant::now() - DONE_RECORD_TTL - Duration::from_secs(1);
        }
        assert!(rt.entry("k").is_none(), "过期终态须被清扫");
        assert!(rt.executions.lock().unwrap().is_empty(), "清扫后表为空");
    }

    #[test]
    fn pending_records_survive_the_approval_window() {
        let rt = runtime("pending");
        rt.set_pending("k", pending("k"));
        if let Ok(mut guard) = rt.executions.lock()
            && let Some(record) = guard.get_mut("k")
        {
            record.created = Instant::now() - DONE_RECORD_TTL - Duration::from_secs(1);
        }
        assert!(rt.entry("k").is_some(), "在途记录须活过审批窗口（300s）");
    }
}
