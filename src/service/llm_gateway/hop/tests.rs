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
    // `content-encoding: gzip` 解码开启时剥离且记数，对外统一 `identity`。
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
    // 未启用 zstd feature 时上游仍回 `content-encoding: zstd` ⇒
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
    let removed2 = filter_hop_headers_counted(&mut decoded, "downstream", decoded_flag, Some(&m));
    assert_eq!(removed2, 0);
    assert!(decoded.get("x-real").is_some());
}

#[test]
fn hop_encoding_multivalue_alias() {
    // 「内容编码解码配对」三种形态：别名（x-gzip）、多值、大小写变体
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
    // 常量数组 + 动态项 `Vec` 的过滤集合**行为**等价（无
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
    // 服务层方向不变量以 `debug_assert` 守护，debug 下违约即暴露。
    filter_hop_headers_counted(&mut HeaderMap::new(), "bogus", false, None);
}
