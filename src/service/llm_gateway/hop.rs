//! 逐跳头过滤（RFC 9110 §7.6.1 全集，双向，大小写不敏感）。

use {super::GatewayMetrics, axum::http::HeaderMap};

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

/// 兼容旧单参调用：默认按响应方向计数（`dir="downstream"`），解码配对按 [`DECODE_ENABLED`]。
pub fn filter_hop_headers(headers: &mut HeaderMap) {
    filter_hop_headers_counted(headers, "downstream", DECODE_ENABLED, None);
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
    use std::collections::HashSet;
    let mut hop: HashSet<String> = HOP_HEADERS.iter().map(|s| s.to_string()).collect();
    // `Connection` 头内动态项（逗号分隔，大小写不敏感）。
    let conn_vals: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    for t in conn_vals {
        hop.insert(t);
    }
    // 快照键后逐个移除（`HeaderMap` 键已规范小写，比较用小写）。
    let keys: Vec<String> = headers.keys().map(|k| k.as_str().to_string()).collect();
    let mut removed: u64 = 0;
    for k in keys {
        if hop.contains(&k.to_lowercase()) && headers.remove(k.as_str()).is_some() {
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
}
