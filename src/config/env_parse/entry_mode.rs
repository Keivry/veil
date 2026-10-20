//! 入口语义模式（自 `env_parse.rs` 拆出，保持导出路径不变）。

/// 入口语义开关：`full`（默认）与 `llm-only`（纯代理，凭据面不可用）。
/// `CredentialOnly` 为**已废弃**取值：等价于 `Full`，仅用于兼容既有部署配置，
/// 其曾经的「`Pending` 跳过审批」豁免已删除。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntryMode {
    #[default]
    Full,
    /// 已废弃：等价于 `Full`。
    CredentialOnly,
    LlmOnly,
}

impl std::str::FromStr for EntryMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "credential-only" => Ok(Self::CredentialOnly),
            "llm-only" => Ok(Self::LlmOnly),
            other => Err(format!(
                "VEIL_ENTRY_MODE 非法: {other:?}（取值 full/credential-only/llm-only）"
            )),
        }
    }
}

/// 入口模式启动通知（纯函数，`main` 侧以裸 stderr 输出，不受 `RUST_LOG` 抑制）。
/// `Full` 无提示；`CredentialOnly` 指明其已等价于 `full` 且审批豁免已删除；
/// `LlmOnly` 说明凭据面不可用。
pub fn entry_mode_notice(entry_mode: EntryMode) -> Option<String> {
    match entry_mode {
        EntryMode::Full => None,
        EntryMode::CredentialOnly => Some(
            "[storage].entry_mode = credential-only 已等价于 full：其审批豁免已删除（Pending 条目不再跳过审批），\
             待审批条目现每次取用都会建票；需要自动放行者请把条目 allow_mode = allow（决策写入注册表可审计）"
                .to_string(),
        ),
        EntryMode::LlmOnly => Some(
            "[storage].entry_mode = llm-only：凭据面整体不可用（取用返回鉴权失败），仅 LLM 代理面可用"
                .to_string(),
        ),
    }
}
