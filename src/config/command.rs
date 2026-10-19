//! `[command]` 文件专属配置：raw schema 与启动期 fail-closed 校验。
//!
//! 本模块无 env 对应源：未声明 `[command]` 时 [`CommandConfig::default`] 为
//! `enabled = false`，命令端点 404，其余面零行为变化。每层 `deny_unknown_fields`
//! 保证未知键在 TOML 解析阶段即拒绝；引用完整性与 argv 占位符校验在合并后执行，
//! 错误消息携带 TOML 键路径。

use {
    super::{file_layer::BOOTSTRAP_VAR, validate::config_error},
    crate::error::Result,
    serde::{Deserialize, Serialize},
    std::{
        collections::{BTreeMap, BTreeSet},
        path::{Path, PathBuf},
    },
};

/// `[command]` 原始 schema（所有字段可选，缺省语义在 [`validate_command`] 落定）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSection {
    pub enabled: Option<bool>,
    pub block_wait: Option<bool>,
    pub hosts: Option<BTreeMap<String, HostSection>>,
    pub groups: Option<BTreeMap<String, GroupSection>>,
    pub commands: Option<BTreeMap<String, CommandDefSection>>,
    pub downstreams: Option<BTreeMap<String, DownstreamSection>>,
}

/// `[command.hosts.<name>]`。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSection {
    pub kind: Option<String>,
    pub description: Option<String>,
}

/// `[command.groups.<name>]`。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSection {
    pub hosts: Option<Vec<String>>,
}

/// `[command.commands.<id>]`。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDefSection {
    pub program: Option<String>,
    pub args: Option<Vec<String>>,
    pub usage: Option<String>,
    pub description: Option<String>,
    pub hosts: Option<Vec<String>>,
    pub timeout_secs: Option<i64>,
    pub requires_approval: Option<bool>,
    pub parameters: Option<BTreeMap<String, ParameterSection>>,
}

/// `[command.commands.<id>.parameters.<name>]`。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterSection {
    pub kind: Option<String>,
    pub values: Option<Vec<String>>,
}

/// `[command.downstreams.<name>]`。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownstreamSection {
    pub callers: Option<Vec<String>>,
    pub allow_commands: Option<Vec<String>>,
    pub auto_approve: Option<Vec<AutoApproveRuleSection>>,
}

/// `[[command.downstreams.<name>.auto_approve]]`。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApproveRuleSection {
    pub command: Option<String>,
    pub hosts: Option<Vec<String>>,
}

/// 命令执行后端类型：本期仅本机。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommandHostKind {
    #[default]
    Local,
}

/// 校验后的 host 声明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandHost {
    pub kind: CommandHostKind,
    pub description: String,
}

/// 参数类型（`enum` 携带值域）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterKind {
    Enum(Vec<String>),
    Integer,
    String,
}

/// 校验后的参数声明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterDef {
    pub kind: ParameterKind,
}

/// 校验后的命令声明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandDef {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub usage: String,
    pub description: String,
    /// host 或分组名（命令可用范围）。
    pub hosts: Vec<String>,
    pub timeout_secs: u64,
    pub requires_approval: bool,
    pub parameters: BTreeMap<String, ParameterDef>,
}

impl CommandDef {
    /// 渲染 argv：`{param}` 占位替换为已校验参数值；未占位的参数不进入 argv。
    pub fn render_argv(&self, params: &BTreeMap<String, String>) -> Vec<String> {
        self.args
            .iter()
            .map(|template| {
                let mut out = String::with_capacity(template.len());
                let mut rest = template.as_str();
                while let Some(open) = rest.find('{') {
                    out.push_str(&rest[..open]);
                    let after = &rest[open + 1..];
                    let Some(close) = after.find('}') else {
                        out.push_str(&rest[open..]);
                        rest = "";
                        break;
                    };
                    let name = &after[..close];
                    match params.get(name) {
                        Some(value) => out.push_str(value),
                        None => {
                            out.push('{');
                            out.push_str(name);
                            out.push('}');
                        }
                    }
                    rest = &after[close + 1..];
                }
                out.push_str(rest);
                out
            })
            .collect()
    }
}

/// 自动放行静态规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApproveRule {
    pub command: String,
    /// host 或分组名。
    pub hosts: Vec<String>,
}

/// 校验后的下游绑定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downstream {
    pub callers: Vec<String>,
    /// `["*"]` 表示全部命令。
    pub allow_commands: Vec<String>,
    pub auto_approve: Vec<AutoApproveRule>,
}

impl Downstream {
    pub fn allows(&self, command: &str) -> bool {
        self.allow_commands.iter().any(|c| c == "*" || c == command)
    }

    pub fn auto_allows(&self, command: &str, host: &str, cmd_cfg: &CommandConfig) -> bool {
        self.auto_approve.iter().any(|rule| {
            rule.command == command
                && rule
                    .hosts
                    .iter()
                    .any(|scope| cmd_cfg.scope_contains_host(scope, host))
        })
    }
}

/// 校验后的 `[command]` 配置。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandConfig {
    pub enabled: bool,
    pub block_wait: bool,
    pub hosts: BTreeMap<String, CommandHost>,
    /// 分组名 → 已解析的 host 名列表。
    pub groups: BTreeMap<String, Vec<String>>,
    pub commands: BTreeMap<String, CommandDef>,
    pub downstreams: BTreeMap<String, Downstream>,
}

impl CommandConfig {
    pub fn is_group(&self, name: &str) -> bool { self.groups.contains_key(name) }

    /// 作用域（host 或分组名）是否覆盖具体 host。
    pub fn scope_contains_host(&self, scope: &str, host: &str) -> bool {
        if scope == host {
            return true;
        }
        self.groups
            .get(scope)
            .is_some_and(|members| members.iter().any(|member| member == host))
    }

    /// 命令的可用 host 展开集（去重排序）。
    pub fn allowed_hosts(&self, def: &CommandDef) -> Vec<String> {
        let mut out = BTreeSet::new();
        for scope in &def.hosts {
            match self.groups.get(scope) {
                Some(members) => {
                    for member in members {
                        out.insert(member.clone());
                    }
                }
                None => {
                    out.insert(scope.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    pub fn is_host_allowed(&self, def: &CommandDef, host: &str) -> bool {
        def.hosts
            .iter()
            .any(|scope| self.scope_contains_host(scope, host))
    }

    pub fn downstream_for(&self, caller_path: &str) -> Option<(&str, &Downstream)> {
        self.downstreams.iter().find_map(|(name, downstream)| {
            downstream
                .callers
                .iter()
                .any(|caller| caller == caller_path)
                .then_some((name.as_str(), downstream))
        })
    }
}

/// 校验入口：`None`（未声明）返回缺省禁用配置。
pub fn validate_command(section: Option<&CommandSection>) -> Result<CommandConfig> {
    let Some(section) = section else {
        return Ok(CommandConfig::default());
    };
    let mut cfg = CommandConfig {
        enabled: section.enabled.unwrap_or(false),
        block_wait: section.block_wait.unwrap_or(false),
        ..CommandConfig::default()
    };

    for (name, host) in section.hosts.iter().flatten() {
        let kind = match host.kind.as_deref().unwrap_or("local") {
            "local" => CommandHostKind::Local,
            other => {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!(
                        "command.hosts.{name}.kind = {other:?} 不受支持（本期仅 local），拒绝启动"
                    ),
                ));
            }
        };
        cfg.hosts.insert(
            name.clone(),
            CommandHost {
                kind,
                description: host.description.clone().unwrap_or_default(),
            },
        );
    }

    for (name, group) in section.groups.iter().flatten() {
        let hosts = group.hosts.as_deref().unwrap_or_default();
        if hosts.is_empty() {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("command.groups.{name}.hosts 不得为空，拒绝启动"),
            ));
        }
        for host in hosts {
            if !cfg.hosts.contains_key(host) {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!("command.groups.{name}.hosts 引用不存在的 host {host:?}，拒绝启动"),
                ));
            }
        }
        cfg.groups.insert(name.clone(), hosts.to_vec());
    }

    for (id, raw) in section.commands.iter().flatten() {
        let prefix = format!("command.commands.{id}");
        let program = required_string(raw.program.as_deref(), &format!("{prefix}.program"))?;
        let path = Path::new(&program);
        if !path.is_absolute() {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{prefix}.program 须为绝对路径（实得 {program:?}），拒绝启动"),
            ));
        }
        let usage = required_string(raw.usage.as_deref(), &format!("{prefix}.usage"))?;
        let hosts = raw.hosts.as_deref().unwrap_or_default();
        if hosts.is_empty() {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{prefix}.hosts 不得为空，拒绝启动"),
            ));
        }
        for scope in hosts {
            if !cfg.hosts.contains_key(scope) && !cfg.groups.contains_key(scope) {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!("{prefix}.hosts 引用不存在的 host/group {scope:?}，拒绝启动"),
                ));
            }
        }
        let timeout_secs = raw.timeout_secs.unwrap_or(60);
        if timeout_secs <= 0 {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{prefix}.timeout_secs 须为正整数（实得 {timeout_secs}），拒绝启动"),
            ));
        }
        let mut parameters = BTreeMap::new();
        for (name, param) in raw.parameters.iter().flatten() {
            let kind = match param.kind.as_deref() {
                Some("enum") => {
                    let values = param.values.clone().unwrap_or_default();
                    if values.is_empty() {
                        return Err(config_error(
                            BOOTSTRAP_VAR,
                            &format!(
                                "{prefix}.parameters.{name}.values 不得为空（enum 参数），拒绝启动"
                            ),
                        ));
                    }
                    ParameterKind::Enum(values)
                }
                Some("integer") => ParameterKind::Integer,
                Some("string") => ParameterKind::String,
                Some(other) => {
                    return Err(config_error(
                        BOOTSTRAP_VAR,
                        &format!(
                            "{prefix}.parameters.{name}.kind = {other:?} 非法（enum/integer/string），拒绝启动"
                        ),
                    ));
                }
                None => {
                    return Err(config_error(
                        BOOTSTRAP_VAR,
                        &format!("{prefix}.parameters.{name}.kind 必填，拒绝启动"),
                    ));
                }
            };
            parameters.insert(name.clone(), ParameterDef { kind });
        }
        let args = raw.args.clone().unwrap_or_default();
        for arg in &args {
            for name in placeholders(arg) {
                if !parameters.contains_key(name) {
                    return Err(config_error(
                        BOOTSTRAP_VAR,
                        &format!("{prefix}.args 引用未声明参数 {name:?}，拒绝启动"),
                    ));
                }
            }
        }
        if cfg.enabled {
            check_program_available(path, &format!("{prefix}.program"))?;
        }
        cfg.commands.insert(
            id.clone(),
            CommandDef {
                program: path.to_path_buf(),
                args,
                usage,
                description: raw.description.clone().unwrap_or_default(),
                hosts: hosts.to_vec(),
                timeout_secs: timeout_secs as u64,
                requires_approval: raw.requires_approval.unwrap_or(true),
                parameters,
            },
        );
    }

    for (name, raw) in section.downstreams.iter().flatten() {
        let prefix = format!("command.downstreams.{name}");
        let callers = raw.callers.as_deref().unwrap_or_default();
        if callers.is_empty() {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{prefix}.callers 不得为空，拒绝启动"),
            ));
        }
        for caller in callers {
            let path = Path::new(caller);
            if !path.is_absolute() {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!("{prefix}.callers 含非绝对路径 {caller:?}，拒绝启动"),
                ));
            }
        }
        let allow = raw.allow_commands.as_deref().unwrap_or_default();
        if allow.is_empty() {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{prefix}.allow_commands 不得为空，拒绝启动"),
            ));
        }
        for command in allow {
            if command != "*" && !cfg.commands.contains_key(command) {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!("{prefix}.allow_commands 引用不存在的命令 {command:?}，拒绝启动"),
                ));
            }
        }
        let mut rules = Vec::new();
        for (index, rule) in raw
            .auto_approve
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let command = required_string(
                rule.command.as_deref(),
                &format!("{prefix}.auto_approve[{index}].command"),
            )?;
            if !cfg.commands.contains_key(&command) {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!(
                        "{prefix}.auto_approve[{index}].command 引用不存在的命令 {command:?}，拒绝启动"
                    ),
                ));
            }
            let hosts = rule.hosts.as_deref().unwrap_or_default();
            if hosts.is_empty() {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!("{prefix}.auto_approve[{index}].hosts 不得为空，拒绝启动"),
                ));
            }
            for scope in hosts {
                if !cfg.hosts.contains_key(scope) && !cfg.groups.contains_key(scope) {
                    return Err(config_error(
                        BOOTSTRAP_VAR,
                        &format!(
                            "{prefix}.auto_approve[{index}].hosts 引用不存在的 host/group {scope:?}，拒绝启动"
                        ),
                    ));
                }
            }
            rules.push(AutoApproveRule {
                command,
                hosts: hosts.to_vec(),
            });
        }
        cfg.downstreams.insert(
            name.clone(),
            Downstream {
                callers: callers.to_vec(),
                allow_commands: allow.to_vec(),
                auto_approve: rules,
            },
        );
    }

    Ok(cfg)
}

fn required_string(value: Option<&str>, key: &str) -> Result<String> {
    let value = value.map(str::trim).filter(|v| !v.is_empty());
    value
        .map(str::to_string)
        .ok_or_else(|| config_error(BOOTSTRAP_VAR, &format!("{key} 必填且不得为空白，拒绝启动")))
}

/// argv 模板中的 `{name}` 占位名（不处理转义；未闭合的 `{` 视为字面量）。
pub(crate) fn placeholders(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        out.push(&after[..close]);
        rest = &after[close + 1..];
    }
    out
}

#[cfg(unix)]
fn check_program_available(path: &Path, key: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path).map_err(|e| {
        config_error(
            BOOTSTRAP_VAR,
            &format!("{key} 指向的程序不可访问 {}: {e}，拒绝启动", path.display()),
        )
    })?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{key} 指向的程序不是可执行文件 {}，拒绝启动",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_program_available(path: &Path, key: &str) -> Result<()> {
    if !path.is_file() {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{key} 指向的程序不存在或不是普通文件 {}，拒绝启动",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {super::*, crate::config::file_layer::FileConfig};

    fn parse(text: &str) -> Result<CommandConfig> {
        let cfg: FileConfig = toml::from_str(text).expect("TOML 须可解析");
        validate_command(cfg.command.as_ref())
    }

    fn base() -> String {
        r#"
[command]
enabled = false

[command.hosts.api]
kind = "local"
description = "api host"

[command.hosts.web]
kind = "local"

[command.groups.fleet]
hosts = ["api", "web"]

[command.commands.deploy]
program = "/bin/echo"
args = ["--target", "{target}"]
usage = "deploy --target <name>"
hosts = ["fleet"]
timeout_secs = 30
requires_approval = true

[command.commands.deploy.parameters.target]
kind = "enum"
values = ["api", "web"]

[command.downstreams.ci]
callers = ["/opt/ci/agent.sh"]
allow_commands = ["deploy"]
auto_approve = [{ command = "deploy", hosts = ["fleet"] }]
"#
        .to_string()
    }

    #[test]
    fn default_is_disabled_and_zero_behavior() {
        let cfg = validate_command(None).unwrap();
        assert!(!cfg.enabled);
        assert!(!cfg.block_wait);
        assert!(cfg.commands.is_empty());
    }

    #[test]
    fn full_section_validates_and_resolves_scopes() {
        let cfg = parse(&base()).unwrap();
        assert!(!cfg.enabled);
        let deploy = cfg.commands.get("deploy").unwrap();
        assert_eq!(cfg.allowed_hosts(deploy), vec!["api", "web"]);
        assert!(cfg.is_host_allowed(deploy, "api"));
        assert!(!cfg.is_host_allowed(deploy, "db"));
        assert_eq!(
            deploy.render_argv(&BTreeMap::from([("target".to_string(), "api".to_string())])),
            vec!["--target", "api"]
        );
        let (name, downstream) = cfg.downstream_for("/opt/ci/agent.sh").unwrap();
        assert_eq!(name, "ci");
        assert!(downstream.allows("deploy"));
        assert!(!downstream.allows("status"));
        assert!(downstream.auto_allows("deploy", "web", &cfg));
        assert!(!downstream.auto_allows("deploy", "db", &cfg));
    }

    #[test]
    fn unknown_key_rejected() {
        let text = "[command]\nenabled = false\nunknown_knob = true\n";
        assert!(toml::from_str::<FileConfig>(text).is_err());
    }

    #[test]
    fn missing_host_reference_rejected() {
        let text = base().replace("hosts = [\"fleet\"]", "hosts = [\"missing\"]");
        let err = parse(&text).unwrap_err();
        assert!(
            err.to_string().contains("command.commands.deploy.hosts"),
            "{err}"
        );
    }

    #[test]
    fn missing_group_host_reference_rejected() {
        let text = base().replace("hosts = [\"api\", \"web\"]", "hosts = [\"api\", \"ghost\"]");
        let err = parse(&text).unwrap_err();
        assert!(
            err.to_string().contains("command.groups.fleet.hosts"),
            "{err}"
        );
    }

    #[test]
    fn relative_program_rejected() {
        let text = base().replace("program = \"/bin/echo\"", "program = \"echo\"");
        let err = parse(&text).unwrap_err();
        assert!(
            err.to_string().contains("command.commands.deploy.program"),
            "{err}"
        );
    }

    #[test]
    fn unimplemented_remote_kind_rejected() {
        let text = base().replace("kind = \"local\"", "kind = \"ssh\"");
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("kind"), "{err}");
        assert!(err.to_string().contains("ssh"), "{err}");
    }

    #[test]
    fn undeclared_arg_placeholder_rejected() {
        let text = base().replace(
            "args = [\"--target\", \"{target}\"]",
            "args = [\"{other}\"]",
        );
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("other"), "{err}");
    }

    #[test]
    fn invalid_parameter_kind_and_enum_rejected() {
        let err = parse(&base().replace("kind = \"enum\"", "kind = \"float\"")).unwrap_err();
        assert!(err.to_string().contains("parameters.target.kind"), "{err}");
        let err = parse(&base().replace("values = [\"api\", \"web\"]", "values = []")).unwrap_err();
        assert!(err.to_string().contains("values"), "{err}");
    }

    #[test]
    fn unknown_allow_command_and_auto_rule_rejected() {
        let err = parse(&base().replace(
            "allow_commands = [\"deploy\"]",
            "allow_commands = [\"nope\"]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("allow_commands"), "{err}");
        let err = parse(&base().replace(
            "auto_approve = [{ command = \"deploy\", hosts = [\"fleet\"] }]",
            "auto_approve = [{ command = \"nope\", hosts = [\"fleet\"] }]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("auto_approve"), "{err}");
    }

    #[test]
    fn non_absolute_caller_rejected() {
        let err = parse(&base().replace("/opt/ci/agent.sh", "agent.sh")).unwrap_err();
        assert!(err.to_string().contains("callers"), "{err}");
    }

    #[test]
    fn enabled_requires_executable_program() {
        let err = parse(
            &base().replace("enabled = false", "enabled = true").replace(
                "program = \"/bin/echo\"",
                "program = \"/nonexistent/veil-command\"",
            ),
        )
        .unwrap_err();
        assert!(err.to_string().contains("program"), "{err}");
    }
}
