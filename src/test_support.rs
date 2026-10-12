//! 共享测试支撑。
//!
//! 文件行数红线断言单一实现：各测试模块以 `include_str!` 提供目标源码，
//! 本模块只承载检查逻辑与类别判定，消除逐字复制。

use std::sync::OnceLock;

/// 生产文件红线（`src/**/*.rs` 中的非测试文件）。
const PROD_LIMIT: usize = 800;

/// 测试文件红线（末段 `tests.rs` / `*_tests.rs`，或任一路径段名为 `tests`）。
const TEST_LIMIT: usize = 1200;

/// 纯路径分类：末段为 `tests.rs`、以 `_tests.rs` 结尾，或任一路径段名等于
/// `tests`，即视为测试文件。与 `scripts/check_file_sizes.py` 分类规则完全一致。
fn is_test_file(name: &str) -> bool {
    let last = name.rsplit('/').next().unwrap_or(name);
    if last == "tests.rs" || last.ends_with("_tests.rs") {
        return true;
    }
    name.split('/').any(|segment| segment == "tests")
}

/// 目标文件的类别红线：测试文件 1200 行、生产文件 800 行。
fn budget_limit(name: &str) -> usize {
    if is_test_file(name) {
        TEST_LIMIT
    } else {
        PROD_LIMIT
    }
}

/// 断言 `src`（`include_str!` 读入的源码）总行数不超过 `name` 所属类别的红线：
/// 测试文件 1200 行、生产文件 800 行；超限 panic 并提示拆分。
pub(crate) fn file_len_under_800_or_split(name: &str, src: &str) {
    let lines = src.lines().count();
    let limit = budget_limit(name);
    let class = if is_test_file(name) {
        "测试文件"
    } else {
        "生产文件"
    };
    assert!(
        lines <= limit,
        "{name} {lines} 行超 {limit} 红线（{class}）：须拆分"
    );
}

/// 捕获窗口常驻探针：`tracing` 的 callsite interest 缓存是**进程全局**的，且
/// `tracing-core::callsite::Dispatchers::rebuilder()` 在 `has_just_one == true`
/// （全局 dispatcher 注册表仅一个条目）时走 `Rebuilder::JustOne`，改用
/// **调用线程当前的默认 dispatcher** 重新计算 interest，而非已注册的 dispatcher 集合。
///
/// 于是首次触碰某 `warn!`/`error!` callsite 的线程若没有线程局部捕获（默认回落
/// `NoSubscriber`），该 callsite 会被永久缓存为 `Interest::never`；与之并发的
/// `with_default(捕获)` 订阅者随后读取该缓存，在宏的 `!interest.is_never()` 快路径
/// 直接跳过事件，捕获恒为空（曾于全套并发下偶发）。
///
/// 进程级常驻一个 always-interested 探针 dispatcher，使其 registrar 永存活于
/// `LOCKED_DISPATCHERS`：捕获窗口内注册表条目数恒 ≥ 2，`has_just_one` 恒为 false，
/// `rebuilder()` 因而读取真实 dispatcher 集合（含当前捕获），interest 恒为 always。
/// 该探针只参与 interest 计算，不是全局默认，不改变测试语义。
static CAPTURE_PROBE: OnceLock<tracing::Dispatch> = OnceLock::new();

/// always-interested、丢弃全部事件的探针订阅者（见 `CAPTURE_PROBE`）。
struct CaptureProbe;

impl tracing::Subscriber for CaptureProbe {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// 安装线程局部捕获订阅者执行 `f`，并保证进程级常驻探针已注册（见 `CAPTURE_PROBE`）。
///
/// 所有依赖 `with_default` 捕获日志的测试 SHALL 经此入口安装，不得直接调用
/// `tracing::subscriber::with_default`，否则并发下可能命中 `Interest::never` 全局缓存。
pub(crate) fn with_capture_subscriber<S, T>(subscriber: S, f: impl FnOnce() -> T) -> T
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    CAPTURE_PROBE.get_or_init(|| tracing::Dispatch::new(CaptureProbe));
    tracing::subscriber::with_default(subscriber, f)
}

/// NonDialog `params` 豁免 warn 的进程级去重位与并行用例的竞态串行锁：
/// 任何会触发该 warn 的用例（dispatch e2e 与 nonstream 捕获用例）SHALL 持锁执行，
/// 否则「恰一次」断言可能被并行用例抢先置位而变为 flaky。
pub fn nondialog_params_warn_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
