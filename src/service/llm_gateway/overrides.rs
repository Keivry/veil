//! `[llm.targets]` 参数覆盖的纯应用逻辑（design D4/D6/D7/D8）。
//!
//! 与配置层（`config::targets`）分离：本模块不解析配置、不触网络、无副作用，
//! 只负责「协议 → `params` 子表」映射与三段覆盖（`default` → `override` → `drop`）
//! 在 JSON 对象上的应用（含目标级冲突策略两态）；注入时序与 `normalized_out`
//! 契约由 `handler::llm::rewrite` 持有。

use {
    super::Protocol,
    crate::config::{ParamOverrides, ParamProtocol, UpstreamOverrides},
    serde_json::{Map, Value},
    std::{
        collections::BTreeSet,
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

/// 按 `default` → `override` → `drop` 顺序应用三段覆盖，返回对象是否**实际**变化。
///
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
) -> bool {
    let mut changed = false;
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

/// redact-only 请求命中 `params` 声明时的单次 warn：按豁免语义忽略参数注入
/// （headers 注入照常，design D8）。
pub fn warn_redact_only_params_ignored_once(overrides: Option<&UpstreamOverrides>) {
    if overrides.is_some_and(|o| !o.params.is_empty())
        && !REDACT_ONLY_PARAMS_IGNORED_WARNED.swap(true, Ordering::Relaxed)
    {
        tracing::warn!(
            "count_tokens（redact-only）命中 [llm.targets] 的 params 声明：按豁免语义忽略参数注入（headers 注入照常；本进程仅提示一次）"
        );
    }
}

#[cfg(test)]
mod tests;
