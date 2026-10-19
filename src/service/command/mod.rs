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

/// 幂等键槽位：在途或已决终态。
#[derive(Clone, Debug)]
pub(crate) enum ExecutionEntry {
    Pending(Arc<PendingInvocation>),
    Done(Arc<Terminal>),
}

/// 命令面运行时（`AppState.command` 持有）。
pub struct CommandRuntime {
    pub config: Arc<CommandConfig>,
    pub log: Arc<CommandLogStore>,
    pub grants: Arc<CommandGrants>,
    pub backend: Arc<dyn CommandBackend>,
    pub hits: Arc<tokio::sync::Mutex<RateTable>>,
    executions: Mutex<HashMap<String, ExecutionEntry>>,
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
            backend: Arc::new(LocalBackend::new(data_dir.to_path_buf())),
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

    pub(crate) fn entry(&self, key: &str) -> Option<ExecutionEntry> {
        self.executions
            .lock()
            .ok()
            .and_then(|guard| guard.get(key).cloned())
    }

    pub(crate) fn set_pending(&self, key: &str, pending: Arc<PendingInvocation>) {
        if let Ok(mut guard) = self.executions.lock() {
            guard.insert(key.to_string(), ExecutionEntry::Pending(pending));
        }
    }

    pub(crate) fn set_done(&self, key: &str, terminal: Terminal) {
        if let Ok(mut guard) = self.executions.lock() {
            guard.insert(key.to_string(), ExecutionEntry::Done(Arc::new(terminal)));
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
