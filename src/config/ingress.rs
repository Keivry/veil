//! 入口监听派生：主监听（`[server].bind`）+ 每条声明端口的专用监听。
//!
//! 一个 LLM 上游对应一条专用 TCP 监听后，「连的是哪个端口」即选路依据，
//! 多个客户端指向同一上游 URL 也能按各自接入端口区分（不再依赖 `Host` 头）。
//!
//! 单一真源：某端口是否「已声明」只由 [`Config::declares_port`] 判定，
//! 监听派生（[`Config::dedicated_listener_addrs`]）与请求期选路
//! （`handler::llm::dispatch::resolve_ingress_port`）共用该判定，两处不会漂移。

use {
    super::{Config, targets::TargetKey},
    std::net::SocketAddr,
};

impl Config {
    /// 该端口是否被声明为 LLM 入口：出现在 `[llm.upstreams]`（含 env `LLM_<port>`）
    /// 或作为 `[llm.targets]` 的端口目标键（`TargetKey::Default` 不算端口声明）。
    pub fn declares_port(&self, port: u16) -> bool {
        self.llm_upstreams.contains_key(&port)
            || self.llm_targets.contains_key(&TargetKey::Port(port))
    }

    /// 专用 LLM 监听地址（升序去重）：所有已声明端口映射到主监听 IP 上，
    /// 排除主监听自身端口（它已由主监听承载，不得重复绑定）。
    ///
    /// 候选集取自两张表的键，是否保留一律由 [`Self::declares_port`] 复核——
    /// 该判定只有一份实现，故监听派生与请求期选路不会漂移。
    /// 升序保证启动日志与绑定顺序确定（不依赖 `HashMap` 迭代序）。
    pub fn dedicated_listener_addrs(&self) -> Vec<SocketAddr> {
        let mut ports: Vec<u16> = self
            .llm_upstreams
            .keys()
            .copied()
            .chain(self.llm_targets.keys().filter_map(|key| match key {
                TargetKey::Port(port) => Some(*port),
                TargetKey::Default => None,
            }))
            .filter(|port| self.declares_port(*port) && *port != self.server_bind.port())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
            .into_iter()
            .map(|port| SocketAddr::new(self.server_bind.ip(), port))
            .collect()
    }
}

#[cfg(test)]
mod tests;
