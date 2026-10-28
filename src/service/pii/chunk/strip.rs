//! 残缺剥离（崩溃热修）：字面量前置的重排正则 + 按输入长度标定的回溯上界 +
//! 引擎错误 fail-safe。
//!
//! 三条不变式（`openspec/changes/harden-partial-strip-regex/design.md`
//! Decision 1–3）：
//!
//! 1. **字面量前置**：正则以 `__C` / `__PI` 起首，跨族负向后顾窗口随字面量右移 （`__C(?<!…__C)` ≡
//!    `(?<!…)__C`，后顾只多出固定 3/4 字节）。语义逐字等价，
//!    但引擎能建立字面量锚点，消除逐位置全串回溯的 O(n²)（1MiB 纯数字由外推 约 634s 降至毫秒级）。
//! 2. **按长度标定的回溯上界**：`strip_partials` **无分块**，直接作用于整段
//!    请求/响应文本，真实上限是 `GATEWAY_BODY_LIMIT_BYTES`（10MiB）而非 1MiB。
//!    重排后步数随输入长度线性增长，故任何**定值**常量都会在大输入上重新 `Err` （定值 20M 在 2–3MiB
//!    处即失败），上界必须是输入长度的一次函数。
//! 3. **`try_replacen` 而非 `replace_all`**：后者内部 `unwrap`
//!    （`fancy-regex-0.20.0/src/lib.rs:2017`），在 `[profile.release] panic = "abort"`
//!    前提下等同杀进程。引擎 `Err` 时原样返回输入并限流告警——
//!    该路径是最后一道兜底（声明上限内不可达），且残缺清理恒运行于脱敏/还原
//!    之后，入参已不含待脱敏明文，故原样返回不构成泄漏。

use {
    crate::service::lock_recover::lock_or_recover,
    fancy_regex::{Regex, RegexBuilder},
    std::{
        borrow::Cow,
        sync::{Mutex, OnceLock},
        time::{Duration, Instant},
    },
};

/// 回溯步数**地板**：小输入的基本余量。
pub(crate) const STRIP_BACKTRACK_FLOOR: u64 = 1_000_000;
/// **每字节**回溯步数系数：重排后实测步数 ≈1–3/字节，此处取 ≥2× 余量。
pub(crate) const STRIP_BACKTRACK_PER_BYTE: u64 = 8;
/// 回溯步数**硬上限**：`backtrack_limit` 是防灾难回溯的最后一道闸，无上界等于
/// 放弃这层防护。10MiB 需 ≈83.9M 步、32MiB 需 ≈268M 步，均仍在本上限覆盖内。
pub(crate) const STRIP_BACKTRACK_HARD_CAP: u64 = 268_435_456;

/// 单次残缺清理的回溯步数上界：随输入字节数**线性**增长、受硬上限封顶。
///
/// 标定规则（可核对，不是「留 2×」这类不可验证说法）：以单次调用**声明上限**
/// `GATEWAY_BODY_LIMIT_BYTES`（10MiB）的最坏输入通过，且以其**半值**
/// （`backtrack_limit_for(len) / 2`）仍通过——这才是「≥2× 余量」的可验证形式，
/// 见 `service::redaction::scope::tests::strip_partials_limits` 的余量断言。
pub(crate) fn backtrack_limit_for(input_len: usize) -> usize {
    (STRIP_BACKTRACK_FLOOR + STRIP_BACKTRACK_PER_BYTE * input_len as u64)
        .min(STRIP_BACKTRACK_HARD_CAP) as usize
}

/// 缓存实例覆盖的输入长度上界（1MiB）：典型请求/响应远小于此。
///
/// 正则编译昂贵而 `strip_partials` 在热路径上，故「小输入共用一份 `OnceLock`
/// 实例、超限才为本次长度单独编译」是最小代价形态（`OnceLock` 快路径 + 仅对
/// 超限输入按更长的上界重编译）。
pub(crate) const BACKTRACK_CACHE_MAX_LEN: usize = 1_048_576;

/// 编译期不变量：`pattern` 恒为字面常量，编译失败即代码缺陷（与既有「恒合法」
/// `expect` 同口径），**不是**运行期错误路径；运行期错误只走 [`strip_with`] 的
/// `try_replacen` 分支。
///
/// `pub(crate)`：`detector.rs` 的联合正则（整段实例与重扫窗口实例）复用同一
/// 构建口径，避免上界系数在两处各写一遍后漂移。
pub(crate) fn build_regex(pattern: &str, for_len: usize, name: &'static str) -> Regex {
    RegexBuilder::new(pattern)
        .backtrack_limit(backtrack_limit_for(for_len))
        .build()
        .expect(name)
}

/// 取带相应回溯上界的正则：`input_len <= BACKTRACK_CACHE_MAX_LEN` 走缓存实例
/// （零编译），否则按本次输入长度单独编译（超限输入属罕见路径，编译开销相对
/// 该长度的匹配可忽略）。返回 `Cow` 以便两种来源统一借用。
///
/// 长度判定 MUST 在 `get_or_init` **之前**：否则首个超限请求会先白编译一份
/// 1MiB 档缓存实例、再为真实长度编译第二份（两条编译开销）——超限路径本应
/// 完全不触碰缓存实例。
pub(crate) fn regex_for_len(
    cache: &'static OnceLock<Regex>,
    pattern: &'static str,
    name: &'static str,
    input_len: usize,
) -> Cow<'static, Regex> {
    if input_len <= BACKTRACK_CACHE_MAX_LEN {
        return Cow::Borrowed(
            cache.get_or_init(|| build_regex(pattern, BACKTRACK_CACHE_MAX_LEN, name)),
        );
    }
    Cow::Owned(build_regex(pattern, input_len, name))
}

/// 引擎错误告警场景。文案只由场景名与输入**字节数**构成，MUST NOT 包含任何
/// 请求内容；场景标签与 [`strip_with`] 的 `expect` 名分开，避免日志读成
/// 「正则恒合法却越过上界」这种自相矛盾的表述。
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WarnScene {
    PiiPartialStrip = 0,
    CredPartialStrip = 1,
    BuiltinScan = 2,
}

/// 场景槽位数（= 枚举变体数，见其后的编译期断言）。
const WARN_SCENE_COUNT: usize = 3;

const _: () = assert!((WarnScene::BuiltinScan as usize) + 1 == WARN_SCENE_COUNT);

impl WarnScene {
    fn label(self) -> &'static str {
        match self {
            Self::PiiPartialStrip => "PII 残缺剥离",
            Self::CredPartialStrip => "凭据残缺剥离",
            Self::BuiltinScan => "内置联合正则",
        }
    }
}

/// 每场景一个 60s 限流槽：定长静态数组（无 map、无增长、无分配），故同一窗口内
/// 剥离降级与扫描降级互不抑制，且每个场景仍只出 1 行/60s。
///
/// 互斥锁 MUST 经 [`lock_or_recover`] 取得（canonical：std 锁中毒不得导致
/// 持续失败），MUST NOT `unwrap()`。
pub(crate) fn warn_engine_error_rate_limited(scene: WarnScene, input_len: usize) {
    static LAST_WARN: [Mutex<Option<Instant>>; WARN_SCENE_COUNT] =
        [const { Mutex::new(None) }; WARN_SCENE_COUNT];
    let mut last = lock_or_recover(LAST_WARN[scene as usize].lock());
    let now = Instant::now();
    if last.is_some_and(|prev| now.duration_since(prev) < Duration::from_secs(60)) {
        return;
    }
    *last = Some(now);
    tracing::warn!(
        "{} 触及回溯步数上限（输入 {} 字节）：本段按已声明降级处理，不改写输入",
        scene.label(),
        input_len
    );
}

/// 残缺剥离统一入口：`try_replacen` 传播引擎错误，`Err` 时**原样返回**输入。
///
/// `name` 只用作编译期 `expect` 文案（恒合法代码缺陷口径），`scene` 只用作
/// 运行期降级告警的限流槽与场景标签——两者分离，告警不会误称「正则恒合法」。
pub(crate) fn strip_with(
    cache: &'static OnceLock<Regex>,
    pattern: &'static str,
    name: &'static str,
    scene: WarnScene,
    text: &str,
) -> String {
    match regex_for_len(cache, pattern, name, text.len()).try_replacen(text, 0, "") {
        Ok(cow) => cow.into_owned(),
        Err(_) => {
            warn_engine_error_rate_limited(scene, text.len());
            text.to_string()
        }
    }
}

/// PII 残缺形态（分片切断的前缀），对标 `_PII_PARTIAL_TOKEN_RE`：
/// `__PI` 后负向前瞻排除完整形态，使完整 token 不被误剥；
/// 剥离口径收窄至确证残缺续段（`__PI` + 可选 `I` + 可选 `_数字_hex`）且后随边界
/// （空白/标点/串尾）时剥离；后续为合法单词字符的正文（如 `__PIXEL`/`__PII_DATA`）
/// 与无序号数字段的 hex-only 形态（如 `__PII_AB`）一律不剥离。
///
/// 跨族闭合豁免：`__PI` 的两条 `_` 若实为**前一完整 token 的闭合界定**
/// （前文恰为完整 CRED `__CRED_\d{4,}` 或完整 PII `__PII_\d+_[0-9a-fA-F]{8}`），
/// 则其后的 `__PI`（如 `__CRED_000123__PI`）不得判为残缺——否则会腐蚀前一
/// 完整 token 并吞掉字面 `PI`。故在 `__PI` 前施加跨族负向后顾。
///
/// 字面量前置（`design.md` Decision 1）：字面 `__PI` 提到两条后顾之前，后顾尾部
/// 各追加 `__PI`——「位置 `p` 之前不以 `A` 结尾」≡「位置 `p+4` 之前不以
/// `A__PI` 结尾」，语义逐字等价（`A` 的定长部分只多出 4 字节）。
pub(crate) const PII_PARTIAL_PATTERN: &str = r"__PI(?<!__CRED_\d{4,}__PI)(?<!__PII_\d+_[0-9a-fA-F]{8}__PI)(?!I_\d+_[0-9a-f]{8}__)(?:I(?:_\d+(?:_[0-9a-fA-F]*)?)?)?(?:_*$|(?=\s|[^\w]))";

/// 小输入共用实例（编译为 `BACKTRACK_CACHE_MAX_LEN` 档上界）。
fn pii_partial_cache() -> &'static OnceLock<Regex> {
    static RE: OnceLock<Regex> = OnceLock::new();
    &RE
}

/// 清理 PII 残缺前缀（完整 `__PII_<seq>_<rand8>__` 原样保留）。
pub fn strip_pii_partials(text: &str) -> String {
    strip_with(
        pii_partial_cache(),
        PII_PARTIAL_PATTERN,
        "PII 残缺正则恒合法",
        WarnScene::PiiPartialStrip,
        text,
    )
}
