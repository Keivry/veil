//! `llm_requests` 建表与列迁移（自 `store.rs` 拆出，守 800 行生产红线）。
//!
//! 建表幂等：`CREATE TABLE IF NOT EXISTS` 覆盖新库；存量库缺列时按 metrics 表
//! 既有模式逐列 `ALTER TABLE ... ADD COLUMN`，重复执行的 duplicate column 错误
//! 静默吞掉（列已存在即目标状态），其余错误一律上抛。

use anyhow::Context as _;

/// 判定 `ALTER TABLE ... ADD COLUMN` 的错误是否仅表示「列已存在」。
///
/// 只认 SQLite 的 duplicate column 方言（`duplicate column name: <col>`）；
/// 其余错误（只读库、磁盘满、锁超时）都必须上抛——吞掉它们会让后续 27 列
/// INSERT 每次刷盘都失败、整批请求行静默丢失，而报错点漂移到别处。
pub(super) fn is_duplicate_column_error(message: &str) -> bool {
    message.to_ascii_lowercase().contains("duplicate column")
}

/// 建表（幂等）：`llm_requests` + 两索引 + `request_model_rollup`，并补列。
pub(crate) fn ensure_tables(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS llm_requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_secs INTEGER NOT NULL,
            request_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            model TEXT NOT NULL,
            upstream TEXT,
            ingress_port INTEGER,
            stream INTEGER NOT NULL,
            is_chat INTEGER NOT NULL,
            counted_metrics INTEGER NOT NULL,
            status INTEGER,
            error_kind TEXT,
            latency_ms INTEGER NOT NULL,
            prompt_tokens INTEGER NOT NULL,
            completion_tokens INTEGER NOT NULL,
            total_tokens INTEGER NOT NULL,
            cached_read INTEGER NOT NULL,
            cached_write INTEGER NOT NULL,
            cache_input_tokens INTEGER NOT NULL,
            session_id TEXT,
            session_source TEXT NOT NULL,
            session_scope TEXT NOT NULL,
            upstream_id TEXT,
            finish_reason TEXT,
            truncated_mode TEXT,
            req_summary TEXT,
            ttft_ms INTEGER,
            tps REAL);
         CREATE INDEX IF NOT EXISTS idx_llm_requests_ts ON llm_requests(ts_secs DESC);
         CREATE INDEX IF NOT EXISTS idx_llm_requests_session
             ON llm_requests(session_id, ts_secs DESC);
         CREATE TABLE IF NOT EXISTS request_model_rollup(
            granularity TEXT NOT NULL,
            window TEXT NOT NULL,
            protocol TEXT NOT NULL,
            model TEXT NOT NULL,
            count INTEGER NOT NULL,
            prompt INTEGER NOT NULL,
            completion INTEGER NOT NULL,
            total INTEGER NOT NULL,
            cached_read INTEGER NOT NULL,
            cached_write INTEGER NOT NULL,
            cache_input INTEGER NOT NULL,
            PRIMARY KEY(granularity, window, protocol, model));",
    )?;
    // 存量库兼容：旧表缺 `ttft_ms`/`tps` 时补列。两列均可空（无 `DEFAULT`），
    // 旧行读出即 `NULL`，不伪造 0；列已存在时 SQLite 报 duplicate column，
    // 幂等跳过；其余错误（只读库/磁盘满/锁超时）必须上抛并指明表与列。
    for col in ["ttft_ms INTEGER", "tps REAL"] {
        match conn.execute(&format!("ALTER TABLE llm_requests ADD COLUMN {col}"), []) {
            Ok(_) => {}
            Err(err) if is_duplicate_column_error(&err.to_string()) => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("llm_requests 补列失败（列 {col}）：迁移不可跳过，否则后续批量 INSERT 必然失败")
                });
            }
        }
    }
    Ok(())
}

/// 逐请求行批量 INSERT（列序与 [`super::RequestRow`] 字段一一对应）。
pub(super) const INSERT_SQL: &str = "INSERT INTO llm_requests(\
     ts_secs, request_id, protocol, model, upstream, ingress_port, stream, is_chat, \
     counted_metrics, status, error_kind, latency_ms, prompt_tokens, completion_tokens, \
     total_tokens, cached_read, cached_write, cache_input_tokens, session_id, session_source, \
     session_scope, upstream_id, finish_reason, truncated_mode, req_summary, ttft_ms, tps)\
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,\
     ?22,?23,?24,?25,?26,?27)";
