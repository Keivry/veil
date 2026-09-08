use subtle::ConstantTimeEq as _;

pub fn ct_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    ab.ct_eq(bb).into()
}

/// 凭据 Secret 等长比较（HMAC-SHA256 域分隔后等长比较，不早退泄漏长度）。
/// 口径对标 `service::admin::admin_token_eq`：变长输入仍先走等长 tag 比较，
/// 再与长度门“与”合并；调用方 MUST 用本函数比较 Secret 类敏感值，
/// 不得直接用 `ct_eq`（`ct_eq` 保留给定长哈希比较）。
pub fn secret_eq(provided: &str, expected: &str) -> bool {
    use hmac::{KeyInit as _, Mac as _};
    type H = hmac::Hmac<sha2::Sha256>;
    let mut mac_p = H::new_from_slice(b"veil-credential-secret-v1").expect("HMAC key 恒合法");
    mac_p.update(provided.as_bytes());
    let mut mac_e = H::new_from_slice(b"veil-credential-secret-v1").expect("HMAC key 恒合法");
    mac_e.update(expected.as_bytes());
    let p = mac_p.finalize().into_bytes();
    let e = mac_e.finalize().into_bytes();
    let tags_eq: bool = p.ct_eq(&e).into();
    let len_eq: bool =
        provided.as_bytes().ct_eq(expected.as_bytes()).into() && provided.len() == expected.len();
    tags_eq && len_eq && provided.len() == expected.len()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(data))
}

pub fn is_private_ip(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h == "localhost" || h == "::1" {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 10
                    || o[0] == 127
                    || (o[0] == 192 && o[1] == 168)
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 169 && o[1] == 254)
                    || (o[0] == 100 && (64..=127).contains(&o[1]))
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                // fd00::/8（ULA）+ fe80::/10（链路本地）；::1 已在上分支返回。
                s[0] & 0xff00 == 0xfd00 || s[0] & 0xffc0 == 0xfe80
            }
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 时序安全比较等长才判等() {
        assert!(ct_eq("abc123", "abc123"));
        assert!(!ct_eq("abc123", "abc124"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn secret_eq与ct_eq同值且不等长判假() {
        assert!(secret_eq("s3cr3t", "s3cr3t"));
        assert!(!secret_eq("s3cr3t", "s3cr3u"));
        assert!(!secret_eq("short", "short-long"));
        assert!(!secret_eq("", "x"));
        assert!(secret_eq("", ""));
    }

    #[test]
    fn 内网识别覆盖三段() {
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("10.1.2.3"));
        assert!(is_private_ip("192.168.0.5"));
        assert!(is_private_ip("172.20.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("203.0.113.1"));
    }

    #[test]
    fn 内网识别覆盖链路本地与运营商级nat() {
        assert!(is_private_ip("169.254.10.20"));
        assert!(is_private_ip("100.64.0.1"));
        assert!(is_private_ip("100.127.255.255"));
        assert!(!is_private_ip("100.128.0.1"));
        assert!(is_private_ip("fd00::1"));
        assert!(is_private_ip("fd12:3456::1"));
        assert!(is_private_ip("fe80::1"));
        assert!(is_private_ip("[fe80::1]"));
        assert!(is_private_ip("::1"));
        assert!(!is_private_ip("2001:db8::1"));
        assert!(!is_private_ip("8.8.8.8"));
    }
}
