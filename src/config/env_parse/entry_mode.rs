//! 入口语义模式（自 `env_parse.rs` 拆出，保持导出路径不变）。

/// 暴露面模式（`[server].surface_mode`，env 规范名 `VEIL_ENTRY_MODE`）。
///
/// 只有两个取值：`full`（默认，规范拼写）与 `llm_only`（纯代理，凭据面不可用）。
/// 0.1.x 的历史拼写（连字符与下划线两种写法）已随别名层在 0.2.0 移除，
/// 现按非法取值拒启动。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntryMode {
    #[default]
    Full,
    LlmOnly,
}

impl std::str::FromStr for EntryMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "llm_only" => Ok(Self::LlmOnly),
            other => Err(format!(
                "VEIL_ENTRY_MODE 非法: {other:?}（取值 full/llm_only）"
            )),
        }
    }
}

/// 暴露面模式启动通知（纯函数，`main` 侧以裸 stderr 输出，不受 `RUST_LOG` 抑制）。
/// `Full` 无提示；`LlmOnly` 说明凭据面不可用。
pub fn entry_mode_notice(entry_mode: EntryMode) -> Option<String> {
    match entry_mode {
        EntryMode::Full => None,
        EntryMode::LlmOnly => Some(
            "[server].surface_mode = llm_only：凭据面整体不可用（取用返回鉴权失败），仅 LLM 代理面可用"
                .to_string(),
        ),
    }
}
