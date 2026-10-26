//! 命令审批票面构造：把 `{command_id} @ {host}`、下游身份、argv 与超时
//! 组装为结构化上下文，排版统一由 `service::matrix::ticket` 负责。

use crate::service::matrix::{CallerIdentity, Fact, MatrixBranch, TicketContext};

pub(crate) struct CommandTicketParts {
    subject: String,
    facts: [Fact<'static>; 2],
}

pub(crate) fn command_ticket_parts(
    command_id: &str,
    host: &str,
    argv: &[String],
    timeout_secs: u64,
) -> CommandTicketParts {
    CommandTicketParts {
        subject: format!("{command_id} @ {host}"),
        facts: [
            Fact {
                label: "命令",
                value: format!("{argv:?}"),
            },
            Fact {
                label: "超时",
                value: format!("{timeout_secs}s"),
            },
        ],
    }
}

/// `known_entry` 决定票面是否标注未注册：路径命中但哈希失配的调用方仍被
/// 注册表认得，标成「（未注册）」会让审批人误判。
pub(crate) fn approval_message<'a>(
    parts: &'a CommandTicketParts,
    caller_path: &'a str,
    downstream: Option<&'a str>,
    known_entry: bool,
) -> TicketContext<'a> {
    TicketContext {
        branch: MatrixBranch::Command,
        subject: parts.subject.as_str(),
        caller: CallerIdentity {
            path: caller_path,
            name: downstream,
            desc: None,
            enrolled: known_entry,
        },
        reason: "command_invoke",
        facts: &parts.facts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(known_entry: bool) -> String {
        let argv = vec!["--target".to_string(), "api".to_string()];
        let parts = command_ticket_parts("deploy", "api", &argv, 30);
        crate::service::matrix::render_ticket(&approval_message(
            &parts,
            "/opt/ci/agent.sh",
            Some("ci-downstream"),
            known_entry,
        ))
    }

    #[test]
    fn ticket_carries_identity_command_host_argv_timeout() {
        let text = render(true);
        for want in [
            "/opt/ci/agent.sh",
            "ci-downstream",
            "deploy @ api",
            "--target",
            "超时",
            "30s",
            "♾️",
            "❎",
            "\n",
        ] {
            assert!(text.contains(want), "缺 {want}: {text}");
        }
        for forbidden in ["::", "!r:", "sha256", "（未注册）"] {
            assert!(!text.contains(forbidden), "不得含 {forbidden}: {text}");
        }
    }

    #[test]
    fn unknown_caller_is_labelled_unregistered() {
        assert!(render(false).contains("（未注册）"));
    }
}
