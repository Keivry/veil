//! KeePass 后端选型（自 `env_parse.rs` 拆出，保持导出路径不变）。

/// KeePass 后端选型：默认 real，显式 `VEIL_KEEPASS_BACKEND=mock` 仅 CI 逃生。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeepassBackendKind {
    #[default]
    Real,
    Mock,
}

impl std::str::FromStr for KeepassBackendKind {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "real" => Ok(Self::Real),
            "mock" => Ok(Self::Mock),
            other => Err(format!(
                "VEIL_KEEPASS_BACKEND 非法: {other:?}（取值 real/mock）"
            )),
        }
    }
}
