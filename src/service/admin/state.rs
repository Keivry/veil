//! 可观测聚合状态：事件环 + 广播 + 采样器持有。

use {
    super::super::metrics::{
        MetricsStore,
        PiiSamplerConfig,
        PiiValueSampler,
        SUMMARY_MAX_CHARS,
        summarize,
    },
    std::{
        collections::{HashMap, VecDeque},
        net::IpAddr,
        sync::Mutex,
    },
};

/// 事件环容量。
pub const EVENT_RING_CAP: usize = 512;

/// 管理事件（摘要落盘前已 `redact → truncate`，零明文）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminEvent {
    pub id: u64,
    pub ts_secs: i64,
    pub kind: String,
    pub summary: String,
    #[serde(default)]
    pub protocol: Option<String>,
}

/// 可观测聚合状态（`AppState` 持有，`Clone` 共享）。
pub struct AdminState {
    pub metrics: std::sync::Arc<MetricsStore>,
    pub sampler: std::sync::Arc<PiiValueSampler>,
    pub(crate) rate: Mutex<HashMap<IpAddr, Vec<std::time::Instant>>>,
    pub(crate) sse_count: std::sync::Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub(crate) events: Mutex<VecDeque<AdminEvent>>,
    pub(crate) broadcaster: tokio::sync::broadcast::Sender<String>,
    pub(crate) next_id: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState").finish()
    }
}

impl AdminState {
    /// 新建（`db_path` 与 metrics 共库；采样开关由调用方经 `Config` 传入，默认关闭）。
    pub fn new(db_path: std::path::PathBuf, sampler_cfg: PiiSamplerConfig) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            metrics: std::sync::Arc::new(MetricsStore::new(db_path.clone())),
            sampler: std::sync::Arc::new(PiiValueSampler::new(sampler_cfg, db_path)),
            rate: Mutex::new(HashMap::new()),
            sse_count: std::sync::Arc::new(Mutex::new(HashMap::new())),
            events: Mutex::new(VecDeque::with_capacity(EVENT_RING_CAP)),
            broadcaster: tx,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(db_path: std::path::PathBuf, sampler: PiiValueSampler) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            metrics: std::sync::Arc::new(MetricsStore::new(db_path.clone())),
            sampler: std::sync::Arc::new(sampler),
            rate: Mutex::new(HashMap::new()),
            sse_count: std::sync::Arc::new(Mutex::new(HashMap::new())),
            events: Mutex::new(VecDeque::with_capacity(EVENT_RING_CAP)),
            broadcaster: tx,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// 推入事件：摘要经单一路径 `redact → truncate` 后落环 + 广播。
    /// 注：§6 审计落盘后如需同步推送审计事件，可调用本函数（`kind`=`audit`）。
    pub fn push_event(
        &self,
        kind: &str,
        raw_summary: &str,
        protocol: Option<String>,
    ) -> AdminEvent {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let ev = AdminEvent {
            id,
            ts_secs,
            kind: kind.to_string(),
            summary: summarize(raw_summary, SUMMARY_MAX_CHARS),
            protocol,
        };
        if let Ok(mut ring) = self.events.lock() {
            if ring.len() >= EVENT_RING_CAP {
                ring.pop_front();
            }
            ring.push_back(ev.clone());
        }
        let _ = self
            .broadcaster
            .send(serde_json::to_string(&ev).unwrap_or_default());
        ev
    }

    /// 查询事件（`kind`/`since`/`limit` 过滤）。
    pub fn query_events(
        &self,
        kind: Option<&str>,
        since: Option<i64>,
        limit: usize,
    ) -> Vec<AdminEvent> {
        let ring = self.events.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter()
            .filter(|e| kind.is_none_or(|k| e.kind == k))
            .filter(|e| since.is_none_or(|s| e.ts_secs >= s))
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .take(limit.clamp(1, 500))
            .collect()
    }

    /// 环内是否存在该 `kind`（`verdict` 兼容过滤命中判定用）。
    pub fn has_kind(&self, kind: &str) -> bool {
        self.events
            .lock()
            .map(|ring| ring.iter().any(|e| e.kind == kind))
            .unwrap_or(false)
    }
}

/// 跨子模块测试共享（其它子模块测试经
/// `crate::service::admin::state::test_support` 复用）。
#[cfg(test)]
pub(crate) mod test_support {
    use {
        super::AdminState,
        crate::service::metrics::{PiiSamplerConfig, PiiValueSampler},
        axum::http::HeaderMap,
        std::net::IpAddr,
    };

    pub(crate) fn test_ip() -> IpAddr { IpAddr::from([127, 0, 0, 1]) }

    pub(crate) fn test_admin_state() -> AdminState {
        let dir = std::env::temp_dir().join(format!("veil-admin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let db = dir.join("metrics.sqlite");
        let sampler = PiiValueSampler::new(
            PiiSamplerConfig {
                enabled: false,
                persist: false,
                hmac_key: None,
            },
            db.clone(),
        );
        AdminState::new_for_test(db, sampler)
    }

    pub(crate) fn headers_with(token: Option<&str>, cookie: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = token {
            h.insert("x-admin-token", t.parse().unwrap());
        }
        if let Some(c) = cookie {
            h.insert("cookie", format!("__Host-admin_token={c}").parse().unwrap());
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{super::events::normalize_verdict_compat, *},
        crate::service::metrics::{SUMMARY_MAX_CHARS, summarize},
        test_support::test_admin_state,
    };

    #[test]
    fn event_summary_stored_redacted() {
        let st = test_admin_state();
        let ev = st.push_event(
            "audit",
            r#"{"password":"hunter2"} sk-abcDEF1234567890"#,
            None,
        );
        assert!(!ev.summary.contains("hunter2"), "{}", ev.summary);
        assert!(!ev.summary.contains("sk-abcDEF"), "{}", ev.summary);
        let got = st.query_events(Some("audit"), None, 10);
        assert_eq!(got.len(), 1);
        assert!(st.query_events(Some("other"), None, 10).is_empty());
    }

    #[test]
    fn verdict_compat_filters_only_on_matching_kind() {
        let st = test_admin_state();
        st.push_event("audit", "危险操作摘要", None);
        assert!(st.has_kind("audit"));
        assert!(!st.has_kind("block"));
        let norm = normalize_verdict_compat("blocked");
        assert_eq!(norm, Some("block"));
        assert!(!st.has_kind(norm.unwrap()));
        let all = st.query_events(None, None, 10);
        assert_eq!(all.len(), 1);
        assert!(st.query_events(Some("audit"), None, 10).len() == 1);
        assert!(st.query_events(Some("block"), None, 10).is_empty());
    }

    #[test]
    fn pending_events_queryable_after_creation() {
        let st = test_admin_state();
        st.push_event("pending", "危险调用待审批", None);
        st.push_event("audit", "普通审计", None);
        let pendings = st.query_events(Some("pending"), None, 100);
        assert_eq!(pendings.len(), 1, "pending 须可按 kind 查环");
        assert!(pendings[0].summary.contains("危险调用待审批"));
        let all = st.query_events(None, None, 100);
        assert_eq!(all.len(), 2);
        let gated = st.query_events(None, None, 1);
        assert_eq!(gated.len(), 1, "limit 须生效");
    }

    #[test]
    fn late_subscriber_receives_only_live_events() {
        let st = test_admin_state();
        st.push_event("audit", "历史摘要", None);
        let mut late = st.subscribe();
        assert!(late.try_recv().is_err(), "后订阅不得收到历史广播");
        let mut early = st.subscribe();
        let ev = st.push_event("audit", "实时摘要", None);
        let got_late: String = late.try_recv().expect("后订阅须收到实时事件");
        let got_early: String = early.try_recv().expect("先订阅同样收到实时事件");
        assert!(got_late.contains("实时摘要"), "{got_late}");
        assert!(got_early.contains("实时摘要"), "{got_early}");
        assert_eq!(ev.summary, summarize("实时摘要", SUMMARY_MAX_CHARS));
        assert!(late.try_recv().is_err(), "单事件不得重复投递");
    }
}
