//! 监听派生与端口声明判定单测（纯函数，无 socket）。

use {
    super::super::{
        Config,
        UpstreamOverrides,
        env_parse::test_support::base_env,
        targets::TargetKey,
    },
    std::collections::HashMap,
};

/// 测试配置：主监听 `0.0.0.0:8877`，端口上游表与目标覆盖按调用方给定。
fn config_with_ports(
    upstreams: &[(u16, &str)],
    target_ports: &[u16],
    default_upstream: Option<&str>,
) -> Config {
    let mut cfg = Config::load_from(&base_env()).expect("基准配置须可加载");
    cfg.server_bind = "0.0.0.0:8877".parse().expect("字面量须合法");
    cfg.llm_upstreams = upstreams
        .iter()
        .map(|(port, url)| (*port, (*url).to_string()))
        .collect::<HashMap<_, _>>();
    cfg.llm_default_upstream = default_upstream.map(str::to_string);
    cfg.llm_targets.clear();
    for port in target_ports {
        cfg.llm_targets
            .insert(TargetKey::Port(*port), UpstreamOverrides::default());
    }
    cfg
}

#[test]
fn dedicated_listener_addrs_ascending_without_primary_and_deduped() {
    // 8878 同时出现在上游表与目标覆盖（去重一次）；8880 仅由目标覆盖声明；
    // 8877 为上游但等于主监听端口（不得二次绑定）。
    let cfg = config_with_ports(
        &[
            (8877, "http://up-8877:1"),
            (8879, "http://up-8879:1"),
            (8878, "http://up-8878:1"),
        ],
        &[8880, 8878],
        None,
    );
    let addrs: Vec<String> = cfg
        .dedicated_listener_addrs()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        addrs,
        vec!["0.0.0.0:8878", "0.0.0.0:8879", "0.0.0.0:8880"],
        "须升序、去重、排除主监听端口"
    );
}

#[test]
fn dedicated_listener_addrs_empty_when_nothing_declared() {
    let cfg = config_with_ports(&[], &[], Some("http://up-default:1"));
    assert!(
        cfg.dedicated_listener_addrs().is_empty(),
        "仅缺省上游时不派生专用监听"
    );
}

#[test]
fn declares_port_covers_upstreams_targets_and_rejects_unknown() {
    let cfg = config_with_ports(&[(8878, "http://up-8878:1")], &[8880], None);
    assert!(cfg.declares_port(8878), "[llm.upstreams] 端口须声明");
    assert!(cfg.declares_port(8880), "[llm.targets] 端口键须声明");
    assert!(!cfg.declares_port(8877), "主监听端口未声明");
    assert!(!cfg.declares_port(9999), "未知端口不得声明");
}
