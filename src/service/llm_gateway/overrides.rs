//! `[llm.targets]` 参数覆盖的纯应用逻辑（design D4/D6/D7/D8）。
//!
//! 与配置层（`config::targets`）分离：本模块不解析配置、不触网络、无副作用，
//! 只负责「协议 → `params` 子表」映射与三段覆盖（`default` → `override` → `drop`）
//! 在 JSON 对象上的应用（含目标级冲突策略两态）；注入时序与 `normalized_out`
//! 契约由 `handler::llm::rewrite` 持有。

use {
    super::Protocol,
    crate::config::{ParamOverrides, ParamProtocol, ReplaceRule, UpstreamOverrides},
    serde_json::{Map, Value},
    std::{
        collections::{BTreeMap, BTreeSet},
        sync::atomic::{AtomicBool, Ordering},
    },
};

/// 协议 → `params` 子表的映射：仅对话三协议（`chat`/`anthropic`/`responses`）
/// 可注入参数；`NonDialog` 为字节透传协议，恒不注入（design D8）。
pub fn param_protocol(protocol: Protocol) -> Option<ParamProtocol> {
    match protocol {
        Protocol::Chat => Some(ParamProtocol::Chat),
        Protocol::Anthropic => Some(ParamProtocol::Anthropic),
        Protocol::Responses => Some(ParamProtocol::Responses),
        Protocol::NonDialog => None,
    }
}

/// 命中目标的协议级参数覆盖：`overrides` 缺失、协议非对话或未声明该协议子表时
/// 均为 `None`（调用方据此跳过注入，字节与标志保持不变）。
pub fn matched_params(
    overrides: Option<&UpstreamOverrides>,
    protocol: Protocol,
) -> Option<&ParamOverrides> {
    let protocol = param_protocol(protocol)?;
    overrides?.params.get(&protocol)
}

/// `models` 门控（body/header 共用同一实现）：省略 = 全模型生效；声明则仅当
/// 请求模型与某条**精确且大小写敏感**的条目相等时生效；模型缺失/非字符串
/// （`None`）一律跳过。空数组按防御性跳过处理（加载期已拒绝）。
pub fn models_gate_matches(models: Option<&[String]>, model: Option<&str>) -> bool {
    match models {
        None => true,
        Some(models) => model.is_some_and(|m| models.iter().any(|candidate| candidate == m)),
    }
}

/// 协议子表是否声明了任何有效覆盖（`default`/`override`/`drop`/`replace` 均算）。
///
/// 仅存在空的协议子表不算声明：NonDialog/count_tokens 的「忽略 params」告警与
/// redact-only 告警据此判定，避免空表误报、又保证 `replace`-only 配置照常告警。
pub fn params_declared(rules: &ParamOverrides) -> bool {
    !rules.default.is_empty()
        || !rules.r#override.is_empty()
        || !rules.drop.is_empty()
        || !rules.replace.is_empty()
}

/// 目标是否声明了任何有效 `params`（任一协议子表命中 [`params_declared`]）。
pub fn has_params_declaration(overrides: Option<&UpstreamOverrides>) -> bool {
    overrides.is_some_and(|o| o.params.values().any(params_declared))
}

/// 命中的单条替代（`(field, to)` 拥有化，避免与对象可变借用冲突）。
type Replacement = (String, Value);

/// 条件替换首步：基于**应用前客户端原文快照**收集全部命中，再统一写入。
///
/// 先收集后写入保证：规则顺序无关、一条规则的 `to` 不会成为另一条规则的 `from`
/// （不级联）。仅改已存在的顶层键——缺失字段不注入；`Value` 精确相等（类型 +
/// 大小写敏感）才命中；`from == to`（加载期已拒绝）在此再守一次，不报告变化。
fn collect_replacements(
    object: &Map<String, Value>,
    rules: &[ReplaceRule],
    model: Option<&str>,
) -> Vec<Replacement> {
    let mut matched: BTreeMap<String, Value> = BTreeMap::new();
    for rule in rules {
        if !models_gate_matches(rule.models.as_deref(), model) {
            continue;
        }
        let Some(current) = object.get(&rule.field) else {
            continue;
        };
        if current != &rule.from || current == &rule.to {
            continue;
        }
        // 同一字段在加载期已拒绝重复 `(field, from)`；不同 `from` 不可能同时命中
        // 单值，故此处插入至多覆盖一条无效配置，确定性由 BTreeMap 保证。
        matched.insert(rule.field.clone(), rule.to.clone());
    }
    matched.into_iter().collect()
}

/// 按 `replace` → `default` → `override` → `drop` 顺序应用覆盖，返回对象是否
/// **实际**变化。
///
/// - `replace`（design D2/D3/D4）：仅顶层精确匹配改写，先于其余三段；`model` 为
///   客户端原始模型（脱敏/改写前的快照），用于 `models` 门控。
/// - 恒胜模式（`override_existing == true`，目标缺省）：`default` 键缺失才插入； `override`
///   恒写入（值相同不做无谓改写）；`drop` 删顶层键。
/// - 合并模式（`override_existing == false`）：以**注入前客户端键快照**判定， `default` 与
///   `override` 两段仅写快照外的键（客户端已有值恒保留；值相同不重复写、 不报变化）。
/// - `drop` 两态一致，恒在最后执行；同一键出现在多段时后段生效——合并模式下后段
///   仅可覆盖前段写入的配置值，绝不覆盖客户端原文值。
pub fn apply_param_overrides(
    object: &mut Map<String, Value>,
    rules: &ParamOverrides,
    override_existing: bool,
    model: Option<&str>,
) -> bool {
    let mut changed = false;
    for (field, to) in collect_replacements(object, &rules.replace, model) {
        object.insert(field, to);
        changed = true;
    }
    if override_existing {
        for (key, value) in &rules.default {
            if !object.contains_key(key) {
                object.insert(key.clone(), value.clone());
                changed = true;
            }
        }
        for (key, value) in &rules.r#override {
            if object.get(key) != Some(value) {
                changed = true;
            }
            object.insert(key.clone(), value.clone());
        }
    } else {
        // 注入前客户端键快照（拥有化，避免与后续插入的可变借用冲突）：
        // 客户端已有值在两个配置段中均不可覆盖。
        let client_keys: BTreeSet<String> = object.keys().cloned().collect();
        for (key, value) in rules.default.iter().chain(rules.r#override.iter()) {
            if client_keys.contains(key) || object.get(key) == Some(value) {
                continue;
            }
            object.insert(key.clone(), value.clone());
            changed = true;
        }
    }
    for key in &rules.drop {
        changed |= object.remove(key).is_some();
    }
    changed
}

/// redact-only（count_tokens）忽略 `params` 的告警去重（同进程至多一次；
/// 热路径去噪，同 `resolve_target` 缺省回退告警口径）。
static REDACT_ONLY_PARAMS_IGNORED_WARNED: AtomicBool = AtomicBool::new(false);

/// redact-only 请求命中 `params` 声明（含仅 `replace` 的声明）时的告警文案；
/// 未声明返回 `None`。告警去重由 [`warn_redact_only_params_ignored_once`] 持有，
/// 判定与文案在此独立可测（不受进程级去重位影响）。
pub fn redact_only_params_ignored_message(
    overrides: Option<&UpstreamOverrides>,
) -> Option<&'static str> {
    has_params_declaration(overrides).then_some(
        "count_tokens（redact-only）命中 [llm.targets] 的 params 声明：按豁免语义忽略 params/params.replace 注入（headers/header_replace 注入照常；本进程仅提示一次）",
    )
}

/// redact-only 请求命中 `params` 声明时的单次 warn：按豁免语义忽略
/// `params`/`params.replace` 注入（headers/header_replace 注入照常，design D7）。
pub fn warn_redact_only_params_ignored_once(overrides: Option<&UpstreamOverrides>) {
    let Some(message) = redact_only_params_ignored_message(overrides) else {
        return;
    };
    if !REDACT_ONLY_PARAMS_IGNORED_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!("{message}");
    }
}

#[cfg(test)]
mod tests;
