use subtle::ConstantTimeEq as _;

pub fn ct_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    ab.ct_eq(bb).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(data))
}

pub fn is_private_ip(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h == "localhost" || h == "127.0.0.1" || h == "::1" {
        return true;
    }
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() == 4
        && let Ok(nums) = parts
            .iter()
            .map(|p| p.parse::<u8>())
            .collect::<Result<Vec<_>, _>>()
    {
        if nums[0] == 10 {
            return true;
        }
        if nums[0] == 192 && nums[1] == 168 {
            return true;
        }
        if nums[0] == 172 && (16..=31).contains(&nums[1]) {
            return true;
        }
        if nums[0] == 127 {
            return true;
        }
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
    fn 内网识别覆盖三段() {
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("10.1.2.3"));
        assert!(is_private_ip("192.168.0.5"));
        assert!(is_private_ip("172.20.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("203.0.113.1"));
    }
}
