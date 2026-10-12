//! 逐跳头过滤（RFC 9110 §7.6.1 全集，双向，大小写不敏感）。

use {
    super::GatewayMetrics,
    axum::http::{HeaderMap, HeaderName},
};

/// RFC 9110 §7.6.1 逐跳头全集，双向过滤，大小写不敏感。
/// 固定集 8 项 + `Connection` 头内列名的动态项。
pub const HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// `reqwest` 编解码开关配对标记：网关 `Client` 以本常量驱动
/// `gzip/brotli/deflate` 三开关（见 handler 网关路径），对外统一 `identity`。
pub const DECODE_ENABLED: bool = true;

/// 解码配对判定（下游响应方向）：reqwest/tower-http 仅在实际解压成功后
/// 移除响应 `content-encoding`；该头仍存在 ⇒ 上游用了网关不支持的编码
/// （如未启用 feature 的 zstd）、别名（`x-gzip`）或多值编码，未解压——
/// 此时 MUST NOT 剥头透传压缩字节（否则下游收「无编码头 + 压缩字节」）。
pub fn downstream_decode_enabled(response_headers: &HeaderMap) -> bool {
    DECODE_ENABLED && !response_headers.contains_key("content-encoding")
}

/// 全集双向过滤 + 编解码配对。
/// - 先剥 hop 全集（含 `Connection` 动态项），再做编码改写（顺序固定）；
/// - `decode_enabled=true` 时剥 `content-encoding`/`content-length`（已解码，长度已变）；
/// - 每次剥离记 `hop_filtered_total{dir}`（经 `record_hop_filtered`）。
///
/// 返回剥离总数。
pub fn filter_hop_headers_counted(
    headers: &mut HeaderMap,
    dir: &str,
    decode_enabled: bool,
    metrics: Option<&GatewayMetrics>,
) -> u64 {
    debug_assert!(
        dir == "upstream" || dir == "downstream",
        "hop 过滤方向须为 upstream/downstream"
    );
    // 固定 hop 集用常量数组匹配，动态项用小 `Vec` 线性比较——
    // 不再每请求构造 `HashSet`；键快照与小 `Vec` 分配为既有成本，分配面收益
    // 为假设（待 bench），不作对外承诺（详见 `hashset_reuse_equivalence` 注释）。
    // 动态项为自由文本，保持 `String` + lower + trim。
    let dynamic: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let is_hop = |k: &str| HOP_HEADERS.contains(&k) || dynamic.iter().any(|d| d == k);
    // 键快照直接复用 `HeaderName`（`HeaderMap` 键已规范小写），
    // `remove(&k)` 直取，省去逐键 `to_string()` + `to_lowercase()` 重解析。
    let keys: Vec<HeaderName> = headers.keys().cloned().collect();
    let mut removed: u64 = 0;
    for k in keys {
        if is_hop(k.as_str()) && headers.remove(&k).is_some() {
            removed += 1;
        }
    }
    // 编码配对：解码开启则对外 `identity`，剥编码与长度（在 hop 剥离之后执行）。
    if decode_enabled {
        // 一行可观测声明——剥离即对外统一 `identity`。
        for enc in ["content-encoding", "content-length"] {
            if headers.remove(enc).is_some() {
                tracing::debug!(header = enc, dir = dir, "编码头已剥离，对外统一 identity");
                removed += 1;
            }
        }
    }
    if let Some(m) = metrics {
        m.record_hop_filtered(dir, removed);
    }
    removed
}

#[cfg(test)]
mod tests;
