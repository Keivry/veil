//! 日志可见性：安装 tracing 订阅者，使既有 `tracing::`
//! 调用实际可见。
//!
//! 契约：`main` 在最早一步调用 [`init`]；输出固定 stderr、关闭 ANSI；未设
//! `RUST_LOG` 默认 `warn`；非法指令回退默认过滤且不拒启动；安装失败仅 stderr
//! 一行并继续（不 panic）。库内**不得**安装全局订阅者——`test_support.rs` 依赖
//! 线程局部捕获，全局安装会污染 lib 测试进程。

use tracing_subscriber::filter::{EnvFilter, LevelFilter};

/// 日志级别输入的唯一环境变量。
const RUST_LOG: &str = "RUST_LOG";

/// `RUST_LOG` 未设置（或空白）时的默认指令：`warn` 及以上默认可见。
const DEFAULT_LEVEL: &str = "warn";

/// 构造默认过滤器（`warn` 及以上）。
fn default_filter() -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .parse_lossy(DEFAULT_LEVEL)
}

/// 解析 `RUST_LOG` 指令，返回过滤器与回退原因（无回退时为 `None`）。
///
/// `None`/空白视为未设置（默认 `warn`）；合法指令按其 per-target 语义生效；
/// 非法指令回退默认过滤并返回可读原因（由 [`init`] 打印到 stderr），不返回
/// `Err`——日志配置错误不得阻断服务。
pub fn build_filter(raw: Option<&str>) -> (EnvFilter, Option<String>) {
    match raw {
        None => (default_filter(), None),
        Some(dirs) if dirs.trim().is_empty() => (default_filter(), None),
        Some(dirs) => match EnvFilter::try_new(dirs) {
            Ok(filter) => (filter, None),
            Err(err) => (default_filter(), Some(err.to_string())),
        },
    }
}

/// 构造订阅者：人读格式、显式写 stderr（fmt 层默认 stdout，必须覆盖）、关闭 ANSI。
pub fn build_subscriber(filter: EnvFilter) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .finish()
}

/// 安装全局订阅者（`main` 启动首步调用；`try_init` 语义，重复安装安全返回 `false`）。
///
/// 返回是否安装成功；失败时打印一行 stderr 诊断并返回 `false`，绝不 panic、绝不
/// 阻断启动。非法 `RUST_LOG` 的回退原因也在此打印。
pub fn init() -> bool {
    let raw = std::env::var(RUST_LOG).ok();
    let (filter, fallback_reason) = build_filter(raw.as_deref());
    if let Some(reason) = fallback_reason {
        eprintln!("警告: RUST_LOG 指令非法（{reason}），回退默认级别 {DEFAULT_LEVEL}");
    }
    match tracing::subscriber::set_global_default(build_subscriber(filter)) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("警告: tracing 订阅者安装失败（{err}），日志不可见但进程继续启动");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::sync::{Arc, Mutex},
        tracing::span,
        tracing_subscriber::layer::SubscriberExt,
    };

    /// 记录事件的订阅者（仅记录级别与 target，不落任何输出通道）。
    #[derive(Clone, Default)]
    struct Recorder {
        events: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl Recorder {
        fn drained(&self) -> Vec<(tracing::Level, String)> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl tracing::Subscriber for Recorder {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }

        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id { span::Id::from_u64(1) }

        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((
                    *event.metadata().level(),
                    event.metadata().target().to_owned(),
                ));
        }

        fn enter(&self, _: &span::Id) {}

        fn exit(&self, _: &span::Id) {}
    }

    /// 线程局部安装「过滤器 + 记录器」执行 `emit`，返回按序记录的 `(级别, target)`。
    /// 不触碰全局订阅者（lib 测试进程安全）。
    fn capture(filter: EnvFilter, emit: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        let recorder = Recorder::default();
        let events = recorder.clone();
        tracing::subscriber::with_default(recorder.with(filter), emit);
        events.drained()
    }

    fn levels(events: &[(tracing::Level, String)]) -> Vec<tracing::Level> {
        events.iter().map(|(level, _)| *level).collect()
    }

    #[test]
    fn default_filter_is_warn() {
        let (filter, fallback) = build_filter(None);
        assert!(fallback.is_none(), "未设 RUST_LOG 不应有回退原因");
        let events = capture(filter, || {
            tracing::debug!(target: "veil::logtest::default", "debug-filtered");
            tracing::info!(target: "veil::logtest::default", "info-filtered");
            tracing::warn!(target: "veil::logtest::default", "warn-pass");
            tracing::error!(target: "veil::logtest::default", "error-pass");
        });
        assert_eq!(
            levels(&events),
            [tracing::Level::WARN, tracing::Level::ERROR]
        );
        assert!(
            events
                .iter()
                .all(|(_, target)| target == "veil::logtest::default")
        );
    }

    #[test]
    fn rust_log_debug_enables_debug() {
        let (filter, fallback) = build_filter(Some("debug"));
        assert!(fallback.is_none(), "合法指令不应有回退原因");
        let events = capture(filter, || {
            tracing::debug!(target: "veil::logtest::override", "debug-pass");
            tracing::info!(target: "veil::logtest::override", "info-pass");
        });
        assert_eq!(
            levels(&events),
            [tracing::Level::DEBUG, tracing::Level::INFO]
        );
    }

    #[test]
    fn per_target_directive_applies() {
        let (filter, fallback) = build_filter(Some("warn,veil::handler::llm=error"));
        assert!(fallback.is_none(), "合法 per-target 指令不应有回退原因");
        let events = capture(filter, || {
            tracing::warn!(target: "veil::handler::llm", "llm-warn-filtered");
            tracing::error!(target: "veil::handler::llm", "llm-error-pass");
            tracing::warn!(target: "veil::handler::other", "other-warn-pass");
        });
        assert_eq!(
            levels(&events),
            [tracing::Level::ERROR, tracing::Level::WARN]
        );
        assert_eq!(events[1].1, "veil::handler::other");
    }

    #[test]
    fn invalid_directive_falls_back_to_default() {
        let (filter, fallback) = build_filter(Some("warn=debug=error"));
        let reason = fallback.expect("非法指令须返回回退原因");
        assert!(!reason.is_empty(), "回退原因须可读");
        let events = capture(filter, || {
            tracing::info!(target: "veil::logtest::invalid", "info-filtered");
            tracing::warn!(target: "veil::logtest::invalid", "warn-pass");
        });
        assert_eq!(levels(&events), [tracing::Level::WARN]);
    }

    #[test]
    fn blank_rust_log_treated_as_unset() {
        let (filter, fallback) = build_filter(Some("   "));
        assert!(fallback.is_none(), "空白视同未设置，不应有回退原因");
        let events = capture(filter, || {
            tracing::info!(target: "veil::logtest::blank", "info-filtered");
            tracing::warn!(target: "veil::logtest::blank", "warn-pass");
        });
        assert_eq!(levels(&events), [tracing::Level::WARN]);
    }

    #[test]
    fn rust_log_off_suppresses_everything() {
        let (filter, fallback) = build_filter(Some("off"));
        assert!(fallback.is_none(), "off 为合法指令");
        let events = capture(filter, || {
            tracing::error!(target: "veil::logtest::off", "error-filtered");
        });
        assert!(events.is_empty(), "RUST_LOG=off 须显式关闭日志层");
    }
}
