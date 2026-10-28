//! 内置联合正则扫描：单窗口扫描 + `Err` 时递归缩窗重扫 + 命中校验（同步/异步）。
//!
//! 引擎错误不再静默（`design.md` Decision 4）：`captures_iter` 的 `Err` 显式分支，
//! 以 ≤[`SCAN_WINDOW_MAX`] 窗口递归对半重扫至 `Ok` 或 [`SCAN_WINDOW_FLOOR`] 地板；
//! 窗口内 `bank_card` 的 64 / 16 字节上下文恒取自**原始全文**（MUST NOT 取自被裁剪
//! 的子窗口，否则 `url_query_param_re` 判定会在窗口边缘翻转），命中偏移恒为相对
//! 全额的绝对下标。

use {
    super::{
        super::detector::{
            cached_id_ok,
            cached_luhn,
            cached_reserved,
            combined_re_window,
            id_card_ok,
            is_reserved_ip,
            is_valid_ipv4,
            is_valid_ipv6,
            luhn_ok,
            strip_ip_trailing,
            url_query_param_re,
        },
        strip,
    },
    fancy_regex::Regex,
};

/// 联合正则命中分类：按命名组顺序返回 `(kind, 原文)`，未命中任一组返回 `None`。
pub(crate) fn classify_hit<'t>(
    caps: &fancy_regex::Captures<'t, str>,
) -> Option<(&'static str, &'t str)> {
    const ORDER: [&str; 7] = [
        "email",
        "phone",
        "id_card",
        "bank_card",
        "ipv4",
        "ipv6",
        "api_key",
    ];
    ORDER
        .iter()
        .find_map(|kind| caps.name(kind).map(|m| (*kind, m.as_str())))
}

/// 单窗口上限 8KiB。`Err` 阈值有两套口径，勿混用：
///
/// - **历史实测（默认 100 万步上界，即改造前）**：`'a'` ≈66K 字符、CJK ≈50K， 而 `@` / `_` 类低至
///   **10K–50K 字符**——这正是当年 `.flatten()` 静默吞 `Err` 时会导致「长叶尾部 PII 零命中」的证据。
/// - **当前构建（上界 `= 1MiB + 8n`）**：`@` / `_` 类 ≈512KiB 才 `Err`，`x` / `1` 类 ≈1MiB，CJK 在
///   1MiB 内不 `Err`。
///
/// 故 8KiB 在当前构建下距最小 `Err` 阈值（≈512KiB）仍有 ≈64× 余量。选它**不是**
/// 为了贴着阈值，而是为了给重扫窗口标定一份常数上界（见
/// [`super::super::detector::combined_re_window`]），使重扫总步数预算为 O(n)。
pub(crate) const SCAN_WINDOW_MAX: usize = 8 * 1024;
/// 递归对半的地板：到 1KiB 仍 `Err` 即限流 `warn` 并保留已得命中。
pub(crate) const SCAN_WINDOW_FLOOR: usize = 1024;
/// 相邻重扫窗口的交叠字节数。
pub(crate) const SCAN_RESCAN_OVERLAP: usize = 512;
/// 外层分块交叠：MUST ≥ 可识别**单个 token** 的实际宽度，否则跨块 token 两头都
/// 不匹配。512 覆盖全部内置形态（手机 11 / 身份证 18 / 银行卡 ≤19 / IPv6 ≤45 /
/// 邮箱与 `api_key` 的**常见**长度），但 `api_key` 的 `[A-Za-z0-9_-]{16,}`
/// 无上界，故「单个 token 长于 512 字节且恰好跨越窗口边界」仍可能漏检——该残留
/// 限制已在 `docs/engineering-reference.md` 显式声明。
pub(crate) const SCAN_CHUNK_OVERLAP: usize = SCAN_RESCAN_OVERLAP;

/// 联合正则原始命中（偏移为相对**原始全文**的绝对下标，尚未做 Luhn/保留段校验）。
pub(crate) struct RawMatch {
    pub(crate) kind: &'static str,
    pub(crate) value: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

/// 单窗口扫描：返回 `false` 表示引擎报错（`out` 中保留该窗口已得命中）。
///
/// `Err` 必须可传播：`Iterator::flatten` 会把它静默吞成「零命中」，即向上游送出
/// 未脱敏 PII（实测 70K 填充 + 尾部邮箱 → 0 命中）。
fn collect_once(full: &str, off: usize, len: usize, re: &Regex, out: &mut Vec<RawMatch>) -> bool {
    let mut iter = re.captures_iter(&full[off..off + len]);
    loop {
        let caps = match iter.next() {
            None => return true,
            Some(Err(_)) => return false,
            Some(Ok(caps)) => caps,
        };
        let Some((kind, raw)) = classify_hit(&caps) else {
            continue;
        };
        // 七个命名组各自即完整匹配体（组间为 `|` 分支），故 `m.start()` 与
        // 「组 0 终点 − raw 长」逐字节等价。
        let Some(m) = caps.get(0) else { continue };
        out.push(RawMatch {
            kind,
            value: raw.to_string(),
            start: off + m.start(),
            end: off + m.end(),
        });
    }
}

/// 联合正则扫描一个区间（递归缩窗）。
///
/// 首次尝试整段：短输入本就不会 `Err`，故「短文本结论零变化」这一不变量由
/// 「先整段、后缩窗」的次序直接保证，行为与改造前逐字节一致。`Err` 时按
/// ≤[`SCAN_WINDOW_MAX`] 窗口、[`SCAN_RESCAN_OVERLAP`] 交叠切分并逐窗递归
/// （子窗口再 `Err` 即继续对半），直到 `Ok` 或 ≤[`SCAN_WINDOW_FLOOR`]。
///
/// 传入的 `re` 是**整叶**标定实例，只用于这次首扫（首扫的 `Err` 正是触发重扫
/// 的信号）；重扫的每个子区间改用
/// [`super::super::detector::combined_re_window`]（按 [`SCAN_WINDOW_MAX`]
/// 标定），故每次递归的步数预算是常数而非「按整叶长度放大」，重扫总预算为 O(n)。
///
/// 返回 `false` 表示仍有子区间触及回溯上限（已限流 `warn`，`out` 中保留已得
/// 命中——MUST NOT 冒充「无 PII」）。
pub(crate) fn scan_range(
    full: &str,
    off: usize,
    len: usize,
    re: &Regex,
    out: &mut Vec<RawMatch>,
) -> bool {
    if collect_once(full, off, len, re, out) {
        return true;
    }
    rescan_windows(full, off, len, out)
}

/// 切分并递归重扫一个已 `Err` 的区间：所有子区间恒 ≤ [`SCAN_WINDOW_MAX`]。
fn rescan_windows(full: &str, off: usize, len: usize, out: &mut Vec<RawMatch>) -> bool {
    if len <= SCAN_WINDOW_FLOOR {
        strip::warn_engine_error_rate_limited(strip::WarnScene::BuiltinScan, len);
        return false;
    }
    // 首次重扫用 WINDOW_MAX；区间本身已 ≤ WINDOW_MAX 时直接对半（严格收缩）。
    let window = if len > SCAN_WINDOW_MAX {
        SCAN_WINDOW_MAX
    } else {
        len / 2
    };
    let overlap = SCAN_RESCAN_OVERLAP.min(window.saturating_sub(1));
    let step = window - overlap;
    let end = off + len;
    let mut all_ok = true;
    let mut start = off;
    while start < end {
        let desired = (start + window).min(end);
        let mut stop = if desired >= end {
            end
        } else {
            full.floor_char_boundary(desired)
        };
        if stop <= start {
            stop = full.ceil_char_boundary((start + 1).min(end));
        }
        if stop <= start {
            // 无法推进（理论上不可达）：守住不无限递归。
            strip::warn_engine_error_rate_limited(strip::WarnScene::BuiltinScan, len);
            return false;
        }
        all_ok &= rescan_window(full, start, stop - start, out);
        if stop >= end {
            break;
        }
        // 严格前进：`next` 恒 > `start`（`step >= 1`），越界一律收敛到 `stop`。
        let next = full.ceil_char_boundary(start + step).min(stop);
        if next <= start {
            break;
        }
        start = next;
    }
    all_ok
}

/// 重扫单个子区间：用窗口标定实例扫；仍 `Err` 则继续缩窗（不会退回整叶实例）。
fn rescan_window(full: &str, off: usize, len: usize, out: &mut Vec<RawMatch>) -> bool {
    if collect_once(full, off, len, combined_re_window(), out) {
        return true;
    }
    rescan_windows(full, off, len, out)
}

/// 形态归一（剥 IP 尾部标点）；不合法返回 `None`。
pub(crate) fn normalize_hit(m: RawMatch) -> Option<RawMatch> {
    match m.kind {
        "ipv6" => normalize_ip(m, is_valid_ipv6),
        "ipv4" => normalize_ip(m, is_valid_ipv4),
        _ => Some(m),
    }
}

/// IP 归一：句末标点剥离后合法则收敛 span，不合法直接丢弃。
fn normalize_ip(m: RawMatch, valid: fn(&str) -> bool) -> Option<RawMatch> {
    let core = strip_ip_trailing(&m.value);
    if !core.is_empty() && valid(core) {
        return Some(RawMatch {
            value: core.to_string(),
            end: m.start + core.len(),
            ..m
        });
    }
    if valid(&m.value) { Some(m) } else { None }
}

/// `bank_card` 的 64 / 16 字节上下文窗口（字符边界安全切片，避免多字节 UTF-8
/// 毗邻窗口时裸字节切片 panic）。**恒取自 `full`**：窗口化重扫时若从子窗口切片，
/// 上下文被裁会让 `url_query_param_re` 判定翻转（本该抑制的卡号反而命中）。
fn card_context(full: &str, start: usize, end: usize) -> &str {
    let cs = full.floor_char_boundary(start.saturating_sub(64));
    let ce = full.ceil_char_boundary((end + 16).min(full.len()));
    &full[cs..ce]
}

/// 同步路径的确定性校验（银行卡上下文抑制 / Luhn / 身份证校验位 / IP 保留段）。
pub(crate) fn check_hit_sync(
    kind: &str,
    full: &str,
    start: usize,
    end: usize,
    value: &str,
) -> bool {
    match kind {
        "bank_card" => {
            !url_query_param_re().is_match(card_context(full, start, end)) && luhn_ok(value)
        }
        "id_card" => id_card_ok(value),
        "ipv4" | "ipv6" => !is_reserved_ip(value, kind),
        _ => true,
    }
}

/// 异步路径的确定性校验（同 [`check_hit_sync`] 口径，走全局校验 LRU）。
pub(crate) async fn check_hit_async(
    kind: &str,
    full: &str,
    start: usize,
    end: usize,
    value: &str,
) -> bool {
    match kind {
        "bank_card" => {
            !url_query_param_re().is_match(card_context(full, start, end))
                && cached_luhn(value).await
        }
        "id_card" => cached_id_ok(value).await,
        "ipv4" | "ipv6" => !cached_reserved(value, kind).await,
        _ => true,
    }
}
