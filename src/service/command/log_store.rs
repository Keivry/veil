//! 命令调用日志：`data_dir/commands.sqlite` 的建表、写入与分页查询。
//!
//! 每次调用一条记录；`approval_status`（审批轨迹）与 `exec_status`（执行状态）
//! 分列，审批通过但执行失败可区分。参数与输出摘要入库前先经
//! `service::audit::sanitize_for_log`（脱敏 + 控制字符剥离）再截断。

use {
    rusqlite::{params_from_iter, types::Value},
    std::path::{Path, PathBuf},
};

/// 数据目录内的库文件名。
pub const COMMANDS_DB_FILE_NAME: &str = "commands.sqlite";
/// 参数/输出摘要入库上限（字符）。
pub const EXCERPT_MAX_CHARS: usize = 2048;
/// 管理面默认页大小。
pub const LOG_DEFAULT_LIMIT: usize = 50;
/// 管理面页大小上限。
pub const LOG_MAX_LIMIT: usize = 200;

/// 一次调用的完整日志记录。
#[derive(Debug, Clone)]
pub struct InvocationLog {
    pub id: String,
    pub ts_secs: i64,
    pub caller_path: String,
    pub caller_hash: String,
    pub downstream: String,
    pub command: String,
    pub host: String,
    pub params_json: String,
    pub approval_status: String,
    pub exec_status: String,
    pub approval_event_id: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// 查询过滤条件。
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub command: Option<String>,
    pub caller_path: Option<String>,
    pub approval_status: Option<String>,
    /// `range` 折算的时间下界（epoch 秒，含；`None` = 全部保留期）。
    pub since_ts: Option<i64>,
}

impl LogFilter {
    pub fn limit(&self) -> usize {
        self.limit
            .unwrap_or(LOG_DEFAULT_LIMIT)
            .clamp(1, LOG_MAX_LIMIT)
    }

    pub fn offset(&self) -> usize { self.offset.unwrap_or(0) }
}

/// 查询结果页。
#[derive(Debug, Clone)]
pub struct LogPage {
    pub items: Vec<serde_json::Value>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    /// 同 WHERE 范围内最早 `ts_secs`（无行则 `None`，供 `range` 的 `coverage_secs`）。
    pub earliest_ts: Option<i64>,
}

/// 日志存储（无常驻连接，每次 `spawn_blocking` 内打开）。
#[derive(Debug, Clone)]
pub struct CommandLogStore {
    path: PathBuf,
}

impl CommandLogStore {
    /// 启动期建库建表；失败上抛（调用方决定降级或拒绝启动）。
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(COMMANDS_DB_FILE_NAME);
        let conn = crate::fs_perm::open_wal(&path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS command_invocations (\
                 id TEXT PRIMARY KEY,\
                 ts_secs INTEGER NOT NULL,\
                 caller_path TEXT NOT NULL,\
                 caller_hash TEXT NOT NULL,\
                 downstream TEXT NOT NULL,\
                 command TEXT NOT NULL,\
                 host TEXT NOT NULL,\
                 params_json TEXT NOT NULL,\
                 approval_status TEXT NOT NULL,\
                 exec_status TEXT NOT NULL,\
                 approval_event_id TEXT,\
                 exit_code INTEGER,\
                 stdout_excerpt TEXT NOT NULL,\
                 stderr_excerpt TEXT NOT NULL,\
                 duration_ms INTEGER NOT NULL\
             );\
             CREATE INDEX IF NOT EXISTS idx_command_invocations_ts \
                 ON command_invocations(ts_secs DESC);",
        )?;
        crate::fs_perm::ensure_0600(&path);
        Ok(Self { path })
    }

    /// 未启用命令面时的惰性构造：不建库、不触盘。
    pub fn unopened(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(COMMANDS_DB_FILE_NAME),
        }
    }

    pub fn path(&self) -> &Path { &self.path }

    pub async fn insert(&self, log: InvocationLog) -> anyhow::Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || insert_blocking(&path, log)).await?
    }

    pub async fn query(&self, filter: LogFilter) -> anyhow::Result<LogPage> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || query_blocking(&path, filter)).await?
    }
}

fn mask_excerpt(text: &str) -> String {
    let masked = crate::service::audit::sanitize_for_log(text);
    masked.chars().take(EXCERPT_MAX_CHARS).collect()
}

fn insert_blocking(path: &Path, log: InvocationLog) -> anyhow::Result<()> {
    let conn = crate::fs_perm::open_wal(path)?;
    conn.execute(
        "INSERT INTO command_invocations (\
             id, ts_secs, caller_path, caller_hash, downstream, command, host, params_json,\
             approval_status, exec_status, approval_event_id, exit_code,\
             stdout_excerpt, stderr_excerpt, duration_ms\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            log.id,
            log.ts_secs,
            log.caller_path,
            log.caller_hash,
            log.downstream,
            log.command,
            log.host,
            mask_excerpt(&log.params_json),
            log.approval_status,
            log.exec_status,
            log.approval_event_id,
            log.exit_code,
            mask_excerpt(&log.stdout),
            mask_excerpt(&log.stderr),
            log.duration_ms as i64,
        ],
    )?;
    Ok(())
}

fn query_blocking(path: &Path, filter: LogFilter) -> anyhow::Result<LogPage> {
    let conn = crate::fs_perm::open_wal(path)?;
    let mut clauses: Vec<&str> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    if let Some(command) = filter.command.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("command = ?");
        values.push(Value::Text(command.to_string()));
    }
    if let Some(caller) = filter.caller_path.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("caller_path = ?");
        values.push(Value::Text(caller.to_string()));
    }
    if let Some(status) = filter.approval_status.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("approval_status = ?");
        values.push(Value::Text(status.to_string()));
    }
    if let Some(since) = filter.since_ts {
        clauses.push("ts_secs >= ?");
        values.push(Value::Integer(since));
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    let (total, earliest_ts): (i64, Option<i64>) = conn.query_row(
        &format!("SELECT COUNT(*), MIN(ts_secs) FROM command_invocations{where_sql}"),
        params_from_iter(values.iter()),
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let limit = filter.limit();
    let offset = filter.offset();
    let mut page_values = values;
    page_values.push(Value::Integer(limit as i64));
    page_values.push(Value::Integer(offset as i64));
    let select = concat!(
        "SELECT id, ts_secs, caller_path, caller_hash, downstream, command, host, params_json, ",
        "approval_status, exec_status, approval_event_id, exit_code, ",
        "stdout_excerpt, stderr_excerpt, duration_ms "
    );
    let sql = format!(
        "{select}FROM command_invocations{where_sql} ORDER BY ts_secs DESC, id DESC LIMIT ? OFFSET ?"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(page_values.iter()), |row| {
        Ok(serde_json::json!({
            "id": row.get::<_, String>(0)?,
            "ts_secs": row.get::<_, i64>(1)?,
            "caller_path": row.get::<_, String>(2)?,
            "caller_hash": row.get::<_, String>(3)?,
            "downstream": row.get::<_, String>(4)?,
            "command": row.get::<_, String>(5)?,
            "host": row.get::<_, String>(6)?,
            "params_json": row.get::<_, String>(7)?,
            "approval_status": row.get::<_, String>(8)?,
            "exec_status": row.get::<_, String>(9)?,
            "approval_event_id": row.get::<_, Option<String>>(10)?,
            "exit_code": row.get::<_, Option<i64>>(11)?,
            "stdout_excerpt": row.get::<_, String>(12)?,
            "stderr_excerpt": row.get::<_, String>(13)?,
            "duration_ms": row.get::<_, i64>(14)?,
        }))
    })?;
    let items: Vec<serde_json::Value> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(LogPage {
        items,
        total: total as usize,
        limit,
        offset,
        earliest_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "veil-cmdlog-{}-{tag}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn record(id: &str, approval: &str, exec: &str, exit_code: Option<i32>) -> InvocationLog {
        InvocationLog {
            id: id.to_string(),
            ts_secs: 1_700_000_000,
            caller_path: "/opt/ci/a.sh".to_string(),
            caller_hash: "hash".to_string(),
            downstream: "ci".to_string(),
            command: "deploy".to_string(),
            host: "api".to_string(),
            params_json: r#"{"token":"sk-secret-value"}"#.to_string(),
            approval_status: approval.to_string(),
            exec_status: exec.to_string(),
            approval_event_id: (approval != "not_required").then(|| "$evt".to_string()),
            exit_code,
            stdout: "ok sk-secret-value".to_string(),
            stderr: String::new(),
            duration_ms: 12,
        }
    }

    #[tokio::test]
    async fn insert_query_pagination_and_masking() {
        let dir = temp_dir("page");
        let store = CommandLogStore::open(&dir).unwrap();
        for i in 0..3 {
            store
                .insert(record(&format!("id-{i}"), "approved", "executed", Some(0)))
                .await
                .unwrap();
        }
        let page = store
            .query(LogFilter {
                limit: Some(2),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.limit, 2);
        for item in &page.items {
            let params = item["params_json"].as_str().unwrap();
            let stdout = item["stdout_excerpt"].as_str().unwrap();
            assert!(!params.contains("sk-secret-value"), "{params}");
            assert!(!stdout.contains("sk-secret-value"), "{stdout}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn approval_and_exec_status_are_independent() {
        let dir = temp_dir("status");
        let store = CommandLogStore::open(&dir).unwrap();
        store
            .insert(record("id-a", "approved", "failed", Some(2)))
            .await
            .unwrap();
        store
            .insert(record("id-b", "not_required", "executed", Some(0)))
            .await
            .unwrap();
        let page = store
            .query(LogFilter {
                approval_status: Some("not_required".to_string()),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0]["approval_status"], "not_required");
        assert!(page.items[0]["approval_event_id"].is_null());

        let page = store.query(LogFilter::default()).await.unwrap();
        let failed = page.items.iter().find(|item| item["id"] == "id-a").unwrap();
        assert_eq!(failed["approval_status"], "approved");
        assert_eq!(failed["exec_status"], "failed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn since_ts_filters_and_reports_earliest() {
        let dir = temp_dir("since");
        let store = CommandLogStore::open(&dir).unwrap();
        for (id, ts) in [("old", 1_600_000_000_i64), ("new", 1_700_000_000)] {
            let mut log = record(id, "not_required", "executed", Some(0));
            log.ts_secs = ts;
            store.insert(log).await.unwrap();
        }
        let all = store.query(LogFilter::default()).await.unwrap();
        assert_eq!(all.total, 2);
        assert_eq!(all.earliest_ts, Some(1_600_000_000), "无下界时取全表最早");
        // `range` 下界：只保留较新的那行，`earliest_ts` 同步收敛。
        let ranged = store
            .query(LogFilter {
                since_ts: Some(1_650_000_000),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(ranged.total, 1, "早于下界的行须被排除");
        assert_eq!(ranged.items[0]["id"], "new");
        assert_eq!(ranged.earliest_ts, Some(1_700_000_000));
        // 下界晚于全部行：空页且 `earliest_ts` 为 `None`（覆盖为 0）。
        let empty = store
            .query(LogFilter {
                since_ts: Some(1_800_000_000),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(empty.total, 0);
        assert_eq!(empty.earliest_ts, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn excerpts_truncate_after_masking() {
        let long = "x".repeat(EXCERPT_MAX_CHARS + 100);
        assert_eq!(mask_excerpt(&long).chars().count(), EXCERPT_MAX_CHARS);
    }
}
