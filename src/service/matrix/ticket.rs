//! 审批票面/无票通知的结构化渲染（票面排版唯一收口）。
//!
//! 输入为 [`TicketContext`]（分支 + 请求对象 + 调用方展示 + 原因 + 事实行），
//! 输出为分行文本：标题行 / 调用方行 / 零至两条事实行 / 图例行（无票通知省略）。
//! 正文 SHALL NOT 含房间号与调用方哈希；唯一例外是哈希变更票的「期望 → 实际」
//! 短前缀（各 ≤8 字符）。
//!
//! 脱敏口径：`sanitize_for_log` 会剥离控制字符（含 `\n`），故 MUST 逐字段脱敏后
//! 再拼接，MUST NOT 对已拼好的整串二次调用（否则分行被抹平）。

use {
    super::branch::{MatrixBranch, REACTION_APPROVE, REACTION_APPROVE_ALWAYS, REACTION_REJECT},
    crate::service::audit::sanitize_for_log,
};

/// 未注册调用方建票的原因串（该原因的人话化归入调用方身份后缀）。
const REASON_UNENROLLED: &str = "unenrolled_default_pending";

/// 调用方展示身份：路径 + 展示名（注册名或下游标签）+ 注册状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerIdentity<'a> {
    /// 调用方路径（脚本绝对路径）。
    pub path: &'a str,
    /// 展示名（注册条目 `name` 或下游身份标签）；`None`/空表示未取到。
    pub name: Option<&'a str>,
    /// 注册条目 `description`；`None`/空表示未取到。
    pub desc: Option<&'a str>,
    /// 是否命中已注册且启用的条目。
    pub enrolled: bool,
}

/// 分支专属事实行（命令 argv/超时、注册授权窗口、哈希变更期望与实际）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact<'a> {
    pub label: &'a str,
    pub value: String,
}

/// 票面渲染的唯一输入。
#[derive(Debug, Clone)]
pub struct TicketContext<'a> {
    pub branch: MatrixBranch,
    /// 请求对象：`和风天气 / 授权码`、`Hermes`、`restart-service @ host-1`。
    /// 构造方保证非空；刻意不设回落，避免机器原因串被送上票面。
    pub subject: &'a str,
    pub caller: CallerIdentity<'a>,
    /// 机器原因串；仅用于映射可读短语，原文不进入正文。
    pub reason: &'a str,
    /// 分支专属事实行（零至两条）。
    pub facts: &'a [Fact<'a>],
}

/// 原因串 → 人话短语；未命中返回 `None`（由调用方决定是否另作说明）。
pub fn reason_phrase(reason: &str) -> Option<&'static str> {
    match reason {
        REASON_UNENROLLED => Some("未注册"),
        "hash_mismatch" => Some("脚本哈希已变更"),
        "auto_approve_none" => Some("人工审批模式"),
        "authorization_expired" => Some("授权已到期"),
        _ => None,
    }
}

/// 调用方展示身份：
/// - 有展示名 → `{name}（{path}）[（未注册）]`，`desc` 非空追加 ` · {desc}`；
/// - 无展示名且已注册 → `{path}`（不标未注册）；
/// - 无展示名且未注册 → `{path}（未注册）`。
pub fn caller_label(caller: &CallerIdentity<'_>) -> String {
    let path = sanitize_for_log(caller.path);
    let name = caller
        .name
        .map(sanitize_for_log)
        .filter(|name| !name.is_empty());
    let mut label = match name {
        Some(name) => format!("{name}（{path}）"),
        None => path,
    };
    if !caller.enrolled {
        label.push_str("（未注册）");
    }
    if let Some(desc) = caller
        .desc
        .map(sanitize_for_log)
        .filter(|desc| !desc.is_empty())
    {
        label.push_str(" · ");
        label.push_str(&desc);
    }
    label
}

/// 短哈希：先剥 `sha256:` 前缀（该前缀由 veilctl 添加），再取前 8 个字符；
/// 不足 8 字符时原样返回。
pub fn short_hash(hash: &str) -> &str {
    let stripped = hash.strip_prefix("sha256:").unwrap_or(hash);
    match stripped.char_indices().nth(8) {
        Some((end, _)) => &stripped[..end],
        None => stripped,
    }
}

/// 分支业务称谓；`HashChange`/`Audit`/`Unknown` 无建单路径，返回空串。
pub fn branch_title(branch: MatrixBranch) -> &'static str {
    match branch {
        MatrixBranch::Credential => "凭据请求",
        MatrixBranch::Register => "注册请求",
        MatrixBranch::Command => "命令请求",
        MatrixBranch::Revoke => "吊销请求",
        MatrixBranch::HashChange | MatrixBranch::Audit | MatrixBranch::Unknown => "",
    }
}

/// 无票通知的称谓：哈希变更与凭据取用失败各有专名，其余沿用业务称谓。
fn notice_title(branch: MatrixBranch) -> &'static str {
    match branch {
        MatrixBranch::HashChange => "哈希变更",
        MatrixBranch::Credential => "凭据取用失败",
        other => branch_title(other),
    }
}

/// 图例动作短句：按 `reaction_presets()` 受理矩阵派生，不受理的表情不参与。
fn legend_action(branch: MatrixBranch, key: &str) -> Option<&'static str> {
    let approved = key == REACTION_APPROVE;
    let always = key == REACTION_APPROVE_ALWAYS;
    let rejected = key == REACTION_REJECT;
    match branch {
        MatrixBranch::Register if approved => Some("批准激活（保留注册声明）"),
        MatrixBranch::Register if always => Some("激活并持久放行"),
        MatrixBranch::Register if rejected => Some("吊销"),
        MatrixBranch::Command if approved => Some("批准本次"),
        MatrixBranch::Command if always => Some("批准并持久放行"),
        MatrixBranch::Command if rejected => Some("拒绝"),
        MatrixBranch::Revoke if approved => Some("执行吊销"),
        MatrixBranch::Revoke if rejected => Some("不吊销"),
        MatrixBranch::Credential if approved => Some("批准本次"),
        MatrixBranch::Credential if rejected => Some("拒绝"),
        _ => None,
    }
}

/// 图例行：动作短句以全角空格分隔；无图例分支返回空串。
fn legend_line(branch: MatrixBranch) -> String {
    branch
        .reaction_presets()
        .iter()
        .filter_map(|key| legend_action(branch, key).map(|action| format!("{key} {action}")))
        .collect::<Vec<_>>()
        .join("\u{3000}")
}

/// 调用方行内容：展示身份 + 原因短语后缀（未注册标注已在身份内，不重复）。
fn caller_line(ctx: &TicketContext<'_>) -> String {
    let mut label = caller_label(&ctx.caller);
    if ctx.reason != REASON_UNENROLLED
        && let Some(phrase) = reason_phrase(ctx.reason)
    {
        label.push('（');
        label.push_str(phrase);
        label.push('）');
    }
    label
}

fn status_mark(branch: MatrixBranch, approved: Option<bool>) -> &'static str {
    match approved {
        Some(true) => branch.status_emoji_approved(),
        Some(false) => branch.status_emoji_rejected(),
        None => branch.status_emoji_pending(),
    }
}

/// 标题行：`{mark} {称谓}：{subject}`；`subject` 脱敏后为空时省略该段，
/// 不以原因串等替代内容充数。
fn title_line(mark: &str, title: &str, subject: &str) -> String {
    let subject = sanitize_for_log(subject);
    if subject.is_empty() {
        format!("{mark} {title}")
    } else {
        format!("{mark} {title}：{subject}")
    }
}

fn fact_lines(facts: &[Fact<'_>]) -> Vec<String> {
    facts
        .iter()
        .map(|fact| {
            format!(
                "{}：{}",
                sanitize_for_log(fact.label),
                sanitize_for_log(&fact.value)
            )
        })
        .collect()
}

/// 建单正文：标题行 + 调用方行 + 事实行 + 图例行；无建单分支返回空串。
pub fn render_ticket(ctx: &TicketContext<'_>) -> String {
    let title = branch_title(ctx.branch);
    if title.is_empty() {
        return String::new();
    }
    let mut lines = Vec::with_capacity(4 + ctx.facts.len());
    lines.push(title_line(
        ctx.branch.status_emoji_pending(),
        title,
        ctx.subject,
    ));
    lines.push(format!("👤 调用方：{}", caller_line(ctx)));
    lines.extend(fact_lines(ctx.facts));
    let legend = legend_line(ctx.branch);
    if !legend.is_empty() {
        lines.push(legend);
    }
    lines.join("\n")
}

/// 无票通知：同骨架、状态徽标按 `approved` 三态、无图例行；无通知分支返回空串。
pub fn render_notice(ctx: &TicketContext<'_>, approved: Option<bool>) -> String {
    let title = notice_title(ctx.branch);
    if title.is_empty() {
        return String::new();
    }
    let mut lines = Vec::with_capacity(3 + ctx.facts.len());
    lines.push(title_line(
        status_mark(ctx.branch, approved),
        title,
        ctx.subject,
    ));
    if !ctx.caller.path.is_empty() {
        lines.push(format!("👤 调用方：{}", caller_line(ctx)));
    }
    lines.extend(fact_lines(ctx.facts));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        branch: MatrixBranch,
        subject: &'a str,
        caller: CallerIdentity<'a>,
        reason: &'a str,
        facts: &'a [Fact<'a>],
    ) -> TicketContext<'a> {
        TicketContext {
            branch,
            subject,
            caller,
            reason,
            facts,
        }
    }

    fn unenrolled<'a>(path: &'a str) -> CallerIdentity<'a> {
        CallerIdentity {
            path,
            name: None,
            desc: None,
            enrolled: false,
        }
    }

    #[test]
    fn reason_phrase_maps_four_known_and_rejects_unknown() {
        for (raw, phrase) in [
            ("unenrolled_default_pending", "未注册"),
            ("hash_mismatch", "脚本哈希已变更"),
            ("auto_approve_none", "人工审批模式"),
            ("authorization_expired", "授权已到期"),
        ] {
            assert_eq!(reason_phrase(raw), Some(phrase), "{raw}");
        }
        assert_eq!(reason_phrase("command_invoke"), None);
        assert_eq!(reason_phrase("register审批 :: x"), None);
    }

    #[test]
    fn caller_label_renders_three_forms() {
        let named = CallerIdentity {
            path: "/s/a.sh",
            name: Some("构建脚本"),
            desc: Some("CI"),
            enrolled: true,
        };
        assert_eq!(caller_label(&named), "构建脚本（/s/a.sh） · CI");
        let bare = CallerIdentity {
            path: "/s/b.sh",
            name: None,
            desc: None,
            enrolled: true,
        };
        assert_eq!(caller_label(&bare), "/s/b.sh");
        assert!(!caller_label(&bare).contains("未注册"));
        assert_eq!(caller_label(&unenrolled("/s/c.sh")), "/s/c.sh（未注册）");
        let unregistered_named = CallerIdentity {
            name: Some("hermes"),
            ..unenrolled("/s/d.sh")
        };
        assert_eq!(
            caller_label(&unregistered_named),
            "hermes（/s/d.sh）（未注册）"
        );
    }

    #[test]
    fn short_hash_strips_prefix_and_caps_at_eight() {
        assert_eq!(short_hash("sha256:50f7f169d22f9acad"), "50f7f169");
        assert_eq!(short_hash("abc"), "abc");
        assert_eq!(short_hash(""), "");
        assert_eq!(short_hash("d58c1f7a"), "d58c1f7a");
    }

    #[test]
    fn credential_ticket_is_three_lines_and_clean() {
        let facts: &[Fact<'_>] = &[];
        let text = render_ticket(&ctx(
            MatrixBranch::Credential,
            "和风天气 / 授权码",
            unenrolled("/opt/data/cache/scratch/veil-smoke.sh"),
            "unenrolled_default_pending",
            facts,
        ));
        assert_eq!(
            text,
            "⏳ 凭据请求：和风天气 / 授权码\n\
             👤 调用方：/opt/data/cache/scratch/veil-smoke.sh（未注册）\n\
             ✅ 批准本次\u{3000}❎ 拒绝"
        );
        assert!(!text.contains("!r:example.com"), "{text}");
        assert!(!text.contains("sha256:"), "{text}");
        assert!(!text.contains("可选反应"), "{text}");
        assert!(!text.contains("unenrolled_default_pending"), "{text}");
    }

    #[test]
    fn render_notice_three_states_without_legend() {
        let facts: &[Fact<'_>] = &[];
        let base = ctx(
            MatrixBranch::HashChange,
            "/s/a.sh",
            unenrolled("/s/a.sh"),
            "hash_mismatch",
            facts,
        );
        assert!(
            render_notice(&base, None).starts_with("⏳ 哈希变更："),
            "{base:?}"
        );
        assert!(render_notice(&base, Some(true)).starts_with("✅ 哈希变更："));
        assert!(render_notice(&base, Some(false)).starts_with("❎ 哈希变更："));
        for approved in [None, Some(true), Some(false)] {
            let text = render_notice(&base, approved);
            assert!(!text.contains("✅ 批准本次"), "{text}");
            assert!(!text.contains("♾"), "{text}");
            assert_eq!(text.lines().count(), 2, "通知仅标题行 + 调用方行: {text}");
        }
    }

    #[test]
    fn fields_are_sanitized_before_assembly_keeping_newlines() {
        let facts = [Fact {
            label: "命令",
            value: "password=hunter2".to_string(),
        }];
        let text = render_ticket(&ctx(
            MatrixBranch::Command,
            "deploy @ api",
            CallerIdentity {
                path: "/s/agent.sh",
                name: None,
                desc: None,
                enrolled: true,
            },
            "command_invoke",
            &facts,
        ));
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains('\n'), "分行结构须保留: {text}");
        assert_eq!(text.lines().count(), 4, "{text}");
    }

    #[test]
    fn branch_titles_and_legends_follow_reaction_matrix() {
        assert_eq!(branch_title(MatrixBranch::Credential), "凭据请求");
        assert_eq!(branch_title(MatrixBranch::Register), "注册请求");
        assert_eq!(branch_title(MatrixBranch::Command), "命令请求");
        assert_eq!(branch_title(MatrixBranch::Revoke), "吊销请求");
        let revoke = legend_line(MatrixBranch::Revoke);
        assert!(revoke.contains('✅') && revoke.contains('❎'), "{revoke}");
        assert!(!revoke.contains('♾'), "{revoke}");
        let credential = legend_line(MatrixBranch::Credential);
        assert!(!credential.contains('♾'), "{credential}");
        assert!(legend_line(MatrixBranch::Register).contains('♾'));
        assert!(legend_line(MatrixBranch::Command).contains('♾'));
    }

    #[test]
    fn non_order_branches_render_empty_tickets() {
        let facts: &[Fact<'_>] = &[];
        for branch in [
            MatrixBranch::HashChange,
            MatrixBranch::Audit,
            MatrixBranch::Unknown,
        ] {
            let text = render_ticket(&ctx(branch, "x", unenrolled("/s/a.sh"), "x", facts));
            assert!(text.is_empty(), "{branch:?}: {text}");
        }
    }
}
