//! 守卫幂等、终态补全与 `Drop` 补写 `client_aborted` 行的断言。

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("guard.rs", include_str!("../guard.rs"));
    crate::test_support::file_len_under_800_or_split("guard/tests.rs", include_str!("tests.rs"));
}

use {
    super::*,
    crate::service::{
        llm_gateway::Usage,
        request_log::{RequestFilter, RequestLog},
    },
    std::{
        path::{Path, PathBuf},
        sync::atomic::Ordering,
    },
};

fn db_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "veil-guardlog-{}-{tag}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&dir).ok();
    dir.join("metrics.sqlite")
}

fn row() -> RequestRow {
    RequestRow {
        ts_secs: 1_700_000_000,
        request_id: "req-1".to_string(),
        protocol: "chat".to_string(),
        model: "m".to_string(),
        stream: true,
        is_chat: true,
        counted_metrics: false,
        session_source: "none".to_string(),
        session_scope: "none".to_string(),
        ..RequestRow::default()
    }
}

fn plain_guard() -> StreamGuard { StreamGuard::new(row()) }

fn usage(prompt: u64, completion: u64, read: u64, write: u64) -> Usage {
    Usage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: prompt + completion,
        total_explicit: true,
        cached_read: read,
        cached_write: write,
    }
}

#[test]
fn finish_takes_row_at_most_once() {
    let guard = plain_guard();
    assert!(guard.finish(&StreamOutcome::default()).is_some());
    assert!(
        guard.finish(&StreamOutcome::default()).is_none(),
        "二次 finish 须为空"
    );
    assert!(guard.is_finished());
    assert_eq!(guard.aborted_count(), 0);
}

#[test]
fn cloned_guards_finish_writes_once() {
    let guard = plain_guard();
    let clone = guard.clone();
    assert!(clone.finish(&StreamOutcome::default()).is_some());
    assert!(guard.finish(&StreamOutcome::default()).is_none());
}

#[test]
fn finish_applies_outcome_fields() {
    let guard = plain_guard();
    let u = usage(120, 30, 40, 5);
    let outcome = StreamOutcome {
        status: Some(502),
        error_kind: Some("upstream_unreachable"),
        upstream_id: Some("chatcmpl-1"),
        finish_reason: Some("stop"),
        truncated_mode: Some("upstream_error"),
        usage: Some(&u),
        latency_ms: Some(812),
        ttft_ms: Some(112),
        counted_metrics: Some(true),
    };
    let row = guard.finish(&outcome).expect("首次 finish");
    assert_eq!(row.status, Some(502));
    assert_eq!(row.error_kind.as_deref(), Some("upstream_unreachable"));
    assert_eq!(row.upstream_id.as_deref(), Some("chatcmpl-1"));
    assert_eq!(row.finish_reason.as_deref(), Some("stop"));
    assert_eq!(row.truncated_mode.as_deref(), Some("upstream_error"));
    assert_eq!(row.latency_ms, 812);
    assert!(row.counted_metrics);
    assert_eq!(row.prompt_tokens, 120);
    assert_eq!(row.cached_read, 40);
    assert_eq!(row.cache_input_tokens, 120, "Chat 分母恒为 prompt_tokens");
    // tps = 30 tokens / ((812 - 112) ms → 0.7 s) ≈ 42.9（保留一位小数）。
    assert_eq!(row.ttft_ms, Some(112));
    assert_eq!(row.tps, Some(42.9));
}

#[test]
fn finish_recomputes_anthropic_cache_denominator() {
    let mut base = row();
    base.protocol = "anthropic".to_string();
    let guard = StreamGuard::new(base);
    let u = usage(100, 10, 30, 7);
    let row = guard
        .finish(&StreamOutcome {
            usage: Some(&u),
            ..StreamOutcome::default()
        })
        .expect("首次 finish");
    assert_eq!(row.cache_input_tokens, 137);
}

#[test]
fn drop_without_finish_counts_aborted() {
    let counter = Arc::new(AtomicU64::new(0));
    {
        let _guard = StreamGuard::with_log(row(), Arc::clone(&counter), Weak::new());
    }
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn drop_without_finish_requeues_one_client_aborted_row() {
    let log = Arc::new(RequestLog::new(db_path("guard-abort-row"), true, 0));
    let ts = 1_700_000_000;
    {
        let mut base = row();
        base.ts_secs = ts;
        let _guard = log.stream_guard(base);
    }
    assert_eq!(log.pending_len(), 1, "未 finish 须恰补写一行");
    log.flush_blocking().expect("刷盘");
    let page = log.query(&RequestFilter::default()).expect("查询");
    assert_eq!(page.total, 1);
    let written = &page.rows[0];
    assert_eq!(written.request_id, "req-1");
    assert_eq!(written.error_kind.as_deref(), Some(CLIENT_ABORTED_KIND));
    assert_eq!(written.status, None);
    let expected = (now_secs() - ts).max(0) as u64 * 1_000;
    assert!(
        written.latency_ms >= expected,
        "延迟须按 now - ts_secs 折算毫秒: {} >= {expected}",
        written.latency_ms
    );
    assert_eq!(log.aborted_total(), 1);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn dropped_clone_does_not_write_row() {
    let log = Arc::new(RequestLog::new(db_path("guard-clone"), true, 0));
    {
        let guard = log.stream_guard(row());
        let clone = guard.clone();
        drop(clone);
        assert_eq!(log.pending_len(), 0, "仍有存活克隆时不得补写");
    }
    assert_eq!(log.pending_len(), 1);
    assert_eq!(log.aborted_total(), 1);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn drop_after_finish_does_not_count() {
    let counter = Arc::new(AtomicU64::new(0));
    {
        let guard = StreamGuard::with_log(row(), Arc::clone(&counter), Weak::new());
        assert!(guard.finish(&StreamOutcome::default()).is_some());
    }
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn drop_of_surviving_clone_does_not_double_count() {
    let counter = Arc::new(AtomicU64::new(0));
    {
        let guard = StreamGuard::with_log(row(), Arc::clone(&counter), Weak::new());
        let clone = guard.clone();
        drop(clone);
        assert_eq!(counter.load(Ordering::Relaxed), 0, "仍有存活克隆时不判定");
    }
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}
