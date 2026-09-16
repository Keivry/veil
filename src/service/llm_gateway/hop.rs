//! 逐跳头过滤（RFC 9110 §7.6.1 全集，双向，大小写不敏感）。

use {
    super::GatewayMetrics,
    axum::http::{HeaderMap, HeaderName},
};

/// FIX-1：RFC 9110 §7.6.1 逐跳头全集，双向过滤，大小写不敏感。
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

/// M1/D4 解码配对判定（下游响应方向）：reqwest/tower-http 仅在实际解压成功后
/// 移除响应 `content-encoding`；该头仍存在 ⇒ 上游用了网关不支持的编码
/// （如未启用 feature 的 zstd）、别名（`x-gzip`）或多值编码，未解压——
/// 此时 MUST NOT 剥头透传压缩字节（否则下游收「无编码头 + 压缩字节」）。
pub fn downstream_decode_enabled(response_headers: &HeaderMap) -> bool {
    DECODE_ENABLED && !response_headers.contains_key("content-encoding")
}

/// FIX-1 全集双向过滤 + 编解码配对。
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
    // ARH-8（7.5）：固定 hop 集用常量数组匹配，动态项用小 `Vec` 线性比较——
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
    // ARH-8：键快照直接复用 `HeaderName`（`HeaderMap` 键已规范小写），
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
        // A5/D9：一行可观测声明——剥离即对外统一 `identity`。
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
mod tests {
    use super::*;

    #[test]
    fn hop_filter_full_set_case_insensitive_with_dynamic_entries() {
        use axum::http::{HeaderMap, HeaderValue};
        let m = GatewayMetrics::default();
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("X-Custom-Hop, keep-alive"),
        );
        h.insert("x-custom-hop", HeaderValue::from_static("1"));
        h.insert("TE", HeaderValue::from_static("trailers"));
        h.insert("trailer", HeaderValue::from_static("x"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("proxy-authenticate", HeaderValue::from_static("Basic"));
        h.insert("proxy-authorization", HeaderValue::from_static("Basic x"));
        h.insert("content-encoding", HeaderValue::from_static("gzip"));
        h.insert("content-length", HeaderValue::from_static("10"));
        h.insert("x-real", HeaderValue::from_static("keep"));
        let n = filter_hop_headers_counted(&mut h, "downstream", true, Some(&m));
        assert_eq!(n, 11);
        assert!(h.get("x-real").is_some());
        assert!(h.get("connection").is_none());
        assert!(h.get("x-custom-hop").is_none());
        assert!(h.get("te").is_none());
        assert!(h.get("content-encoding").is_none());
        assert!(h.get("content-length").is_none());
        assert_eq!(m.hop_filtered_count("downstream"), 11);
    }

    #[test]
    fn gzip_stripped_as_identity_a5() {
        // A5/D9：`content-encoding: gzip` 解码开启时剥离且记数，对外统一 `identity`。
        use axum::http::{HeaderMap, HeaderValue};
        let m = GatewayMetrics::default();
        let mut h = HeaderMap::new();
        h.insert("content-encoding", HeaderValue::from_static("gzip"));
        h.insert("content-length", HeaderValue::from_static("128"));
        h.insert("x-real", HeaderValue::from_static("keep"));
        let n = filter_hop_headers_counted(&mut h, "downstream", true, Some(&m));
        assert_eq!(n, 2);
        assert!(h.get("content-encoding").is_none());
        assert!(h.get("content-length").is_none());
        assert!(h.get("x-real").is_some());
        assert_eq!(m.hop_filtered_count("downstream"), 2);
    }

    #[test]
    fn hop_filter_decode_off_preserves_encoding_with_both_dir_counts() {
        use axum::http::{HeaderMap, HeaderValue};
        let m = GatewayMetrics::default();
        let mut up = HeaderMap::new();
        up.insert("content-encoding", HeaderValue::from_static("br"));
        up.insert("x-a", HeaderValue::from_static("1"));
        let n = filter_hop_headers_counted(&mut up, "upstream", false, Some(&m));
        assert_eq!(n, 0);
        assert!(up.get("content-encoding").is_some());
        let mut dn = HeaderMap::new();
        dn.insert("connection", HeaderValue::from_static("close"));
        let n2 = filter_hop_headers_counted(&mut dn, "downstream", false, Some(&m));
        assert_eq!(n2, 1);
        assert_eq!(m.hop_filtered_count("upstream"), 0);
        assert_eq!(m.hop_filtered_count("downstream"), 1);
    }

    #[test]
    fn hop_decode_pairing_zstd() {
        // M1/D4：未启用 zstd feature 时上游仍回 `content-encoding: zstd` ⇒
        // tower-http 未解压，配对判定为 false，编码头与压缩字节保留供下游自解
        //（不得出现「无编码头 + 压缩字节」）。
        use axum::http::{HeaderMap, HeaderValue};
        let mut resp = HeaderMap::new();
        resp.insert("content-encoding", HeaderValue::from_static("zstd"));
        resp.insert("content-length", HeaderValue::from_static("64"));
        assert!(!downstream_decode_enabled(&resp), "未解压须禁用剥头");
        let m = GatewayMetrics::default();
        let mut copied = resp.clone();
        let removed = filter_hop_headers_counted(
            &mut copied,
            "downstream",
            downstream_decode_enabled(&resp),
            Some(&m),
        );
        assert_eq!(removed, 0);
        assert!(
            copied.get("content-encoding").is_some(),
            "不得无声明剥头（下游须可自解）"
        );
        assert!(copied.get("content-length").is_some(), "长度头须保留");
        // 已解压（tower-http 已移除编码头）⇒ 配对开启，对外 identity 无需再剥。
        let mut decoded = HeaderMap::new();
        decoded.insert("x-real", HeaderValue::from_static("keep"));
        let decoded_flag = downstream_decode_enabled(&decoded);
        assert!(decoded_flag);
        let removed2 =
            filter_hop_headers_counted(&mut decoded, "downstream", decoded_flag, Some(&m));
        assert_eq!(removed2, 0);
        assert!(decoded.get("x-real").is_some());
    }

    #[test]
    fn hop_encoding_multivalue_alias() {
        // M1 spec「内容编码解码配对」三 Scenario：别名（x-gzip）、多值、大小写变体
        // 均不匹配 tower-http 精确解码条件 ⇒ 未解压，编码头与压缩字节须保留。
        use axum::http::{HeaderMap, HeaderValue};
        let m = GatewayMetrics::default();
        for enc in ["x-gzip", "gzip, br", "GZIP"] {
            let mut h = HeaderMap::new();
            h.insert("content-encoding", HeaderValue::from_static(enc));
            h.insert("content-length", HeaderValue::from_static("32"));
            let flag = downstream_decode_enabled(&h);
            assert!(!flag, "{enc} 未解压须配对关闭");
            let removed = filter_hop_headers_counted(&mut h, "downstream", flag, Some(&m));
            assert_eq!(removed, 0, "{enc} 不得剥头");
            assert!(h.get("content-encoding").is_some(), "{enc} 编码头须保留");
            assert!(h.get("content-length").is_some(), "{enc} 长度头须保留");
        }
        // 支持集单值经 tower-http 解码后编码头已移除 ⇒ 对外统一 identity。
        let mut decoded = HeaderMap::new();
        decoded.insert("x-real", HeaderValue::from_static("keep"));
        assert!(downstream_decode_enabled(&decoded));
    }

    #[test]
    fn eight_hop_headers_filtered_individually_matrix() {
        use axum::http::{HeaderMap, HeaderValue};
        for hop in HOP_HEADERS {
            let m = GatewayMetrics::default();
            let mut h = HeaderMap::new();
            h.insert(hop, HeaderValue::from_static("x"));
            h.insert("x-real", HeaderValue::from_static("keep"));
            h.insert("authorization", HeaderValue::from_static("Bearer s3cr3t"));
            let n = filter_hop_headers_counted(&mut h, "upstream", false, Some(&m));
            assert_eq!(n, 1, "{hop} 须被过滤");
            assert!(h.get(hop).is_none());
            assert!(h.get("x-real").is_some(), "{hop} 不得误删业务头");
            assert!(h.get("authorization").is_some(), "端到端鉴权头须透传");
            assert_eq!(m.hop_filtered_count("upstream"), 1);
        }
    }

    #[test]
    fn hashset_reuse_equivalence() {
        // ARH-8（7.5）：常量数组 + 动态项 `Vec` 的过滤集合**行为**等价（无
        // `HashSet` 分配）；本用例只锁行为等价，**不锁分配属性**——每请求少
        // N 次 String 分配为假设（待 bench），不作对外性能承诺。
        use axum::http::{HeaderMap, HeaderValue};
        let m = GatewayMetrics::default();
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("x-hop, X-Other"));
        h.insert("x-hop", HeaderValue::from_static("1"));
        h.insert("x-other", HeaderValue::from_static("2"));
        h.insert("te", HeaderValue::from_static("trailers"));
        h.insert("x-real", HeaderValue::from_static("keep"));
        let n = filter_hop_headers_counted(&mut h, "upstream", false, Some(&m));
        assert_eq!(n, 4, "connection 自身 + 动态项 + 固定项各剥一次");
        assert!(h.get("x-hop").is_none());
        assert!(h.get("x-other").is_none());
        assert!(h.get("connection").is_none());
        assert!(h.get("te").is_none());
        assert!(h.get("x-real").is_some());
        assert_eq!(m.hop_filtered_count("upstream"), 4);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "hop 过滤方向")]
    fn service_invariant_guards() {
        // ARH-11（7.8）：服务层方向不变量以 `debug_assert` 守护，debug 下违约即暴露。
        filter_hop_headers_counted(&mut HeaderMap::new(), "bogus", false, None);
    }
}
