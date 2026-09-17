//! 共享测试支撑（`DCD-8`）。
//!
//! 文件 800 行红线断言单一实现：各测试模块以 `include_str!` 提供目标源码，
//! 本模块只承载检查逻辑，消除 18 份逐字复制（`veil-arch-file-size-closeout` /
//! `hygiene-round4`）。

use std::sync::OnceLock;

/// 断言 `src`（`include_str!` 读入的源码）总行数 ≤ 800；超限 panic 并提示拆分。
pub(crate) fn file_len_under_800_or_split(name: &str, src: &str) {
    let lines = src.lines().count();
    assert!(
        lines <= 800,
        "{name} {lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
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
