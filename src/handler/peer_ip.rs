//! 直连对端 IP 提取器（A1/X6：handler 层公共单一来源）。
//!
//! `PeerIp` 只读 axum `ConnectInfo` 的 TCP 对端地址，MUST NOT 读
//! `X-Forwarded-For`/`X-Real-IP` 等代理头（反伪造：代理头可由客户端伪造，
//! 采信即得内网豁免逃逸）。`ConnectInfo` 缺失时返回 `None`，回退口径由
//! 调用方决定——管理面回退本地回环（单测直调 `serve` 场景），紧急吊销
//! 保持 fail-closed 不豁免（`None` 不视为回环）；提取器本身不猜测、不回退。

use {
    axum::{
        extract::{ConnectInfo, FromRequestParts},
        http::request::Parts,
    },
    std::net::{IpAddr, SocketAddr},
};

/// 直连对端 IP（`ConnectInfo` 缺失时为 `None`）。
pub struct PeerIp(pub Option<IpAddr>);

impl<S> FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        Ok(PeerIp(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peer_ip_uses_direct_connection_ignores_proxy_headers() {
        let addr: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let req = axum::http::Request::builder()
            .header("x-forwarded-for", "198.51.100.9")
            .header("x-real-ip", "198.51.100.9")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        parts.extensions.insert(ConnectInfo(addr));
        let peer = PeerIp::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(peer.0, Some(addr.ip()), "只认直连对端，代理头不参与判定");
        // `ConnectInfo` 缺失：`None`（调用方决定回退，提取器不猜测）。
        let req2 = axum::http::Request::builder()
            .header("x-forwarded-for", "10.0.0.1")
            .body(())
            .unwrap();
        let (mut parts2, _) = req2.into_parts();
        let peer2 = PeerIp::from_request_parts(&mut parts2, &()).await.unwrap();
        assert_eq!(peer2.0, None, "无直连信息不得回退代理头");
    }
}
