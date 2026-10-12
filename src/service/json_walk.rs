//! json-walk：嵌套 stringified JSON 递归、顶层叶 loads→walk→dumps、
//! BOM 剥离、`p@ss"quote` / `\u` 转义安全、len>1M / depth>5 守卫回退 plain、
//! roundtrip 失败回退原串。
//!
//! 口径：
//! - `depth` 仅统计 `str→inner` 嵌套 JSON 递归层数，dict/list 裸递归不计数；
//! - `dumps` 用 `serde_json::to_string`（紧凑分隔符，不转义 CJK）；
//! - 转义安全靠 `loads` 解码成串后处理，MUST NOT 字符串级切分 `\u`；
//! - 超限（len>1M）/ 超深（depth>5）回退 plain，roundtrip 破坏回退原串。

/// 单次扫描输入上限（字节），超限走 plain 回退。
pub const SCAN_INPUT_LIMIT: usize = 1_048_576;
/// `str→inner` 嵌套 JSON 递归深度上限。
pub const DEPTH_LIMIT: u32 = 5;
/// 裸容器（dict/list）递归深度上限（深炸弹守卫）：
/// `depth` 仅计 `str→inner` 嵌套层数，裸容器层数另计；
/// 超限子树回退原样（fallback-to-original），不栈溢出。
/// 输入过长（`len > SCAN_INPUT_LIMIT`）同样回退 plain 处理；
/// 结构破坏时 [`validate_json_roundtrip`] 回退原串。
pub const CONTAINER_NEST_LIMIT: u32 = 128;

/// 剥离前导 BOM（`\ufeff`，等价 `lstrip('\ufeff')`）。
pub fn strip_bom(s: &str) -> &str { s.trim_start_matches('\u{feff}') }

/// 解析 JSON 文本（BOM 已剥离由调用方保证）。
pub fn jloads(s: &str) -> serde_json::Result<serde_json::Value> { serde_json::from_str(s) }

/// 回写 JSON（紧凑分隔符，不转义 CJK）。
pub fn jdumps(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// json-aware 后置校验：原文本是合法 JSON（object/array）而输出不是时，
/// 回退到原始文本，保证下游不收到 `JSONDecodeError`。
pub fn validate_json_roundtrip(original: &str, output: &str, _label: &str) -> String {
    let stripped = strip_bom(original).trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return output.to_string();
    }
    if jloads(strip_bom(original)).is_err() {
        return output.to_string();
    }
    if jloads(strip_bom(output)).is_ok() {
        output.to_string()
    } else {
        tracing::warn!("json-walk roundtrip 破坏，已回退原串");
        original.to_string()
    }
}

/// 同步 walk：dict/list 递归（不增加 `depth`），str 叶调 `leaf`。
///
/// str 叶若本身为 JSON 文本（剥 BOM 后 trim 再判 `{` / `[`，
/// 且可解析为 object/array），则对内层同走 walk→dumps，失败回退 plain；
/// `depth > DEPTH_LIMIT` 时直接 plain 处理该叶。
pub fn json_walk(
    value: serde_json::Value,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
    depth: u32,
) -> serde_json::Value {
    json_walk_nested(value, leaf, depth_limit, depth, 0)
}

/// 裸容器递归本体：dict/list 层数超 `CONTAINER_NEST_LIMIT` 时该子树
/// 原样返回（fallback-to-original），防恶意深嵌套栈溢出。
fn json_walk_nested(
    value: serde_json::Value,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
    depth: u32,
    nest: u32,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(walk_string_leaf(s, leaf, depth_limit, depth))
        }
        serde_json::Value::Array(items) => {
            if nest >= CONTAINER_NEST_LIMIT {
                return serde_json::Value::Array(items);
            }
            serde_json::Value::Array(
                items
                    .into_iter()
                    .map(|v| json_walk_nested(v, leaf, depth_limit, depth, nest + 1))
                    .collect(),
            )
        }
        serde_json::Value::Object(map) => {
            if nest >= CONTAINER_NEST_LIMIT {
                return serde_json::Value::Object(map);
            }
            // 键位与值位同 leaf 口径（键按纯字符串 leaf 处理，MUST NOT 走
            // `walk_string_leaf` 的 stringified-JSON 递归展开）；以原始键集合做碰撞
            // 回退——替换后键与任一原始键或已选键同名时保留原键，结果无重复键、
            // 插入序保持。
            let original: std::collections::HashSet<String> = map.keys().cloned().collect();
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let replaced = leaf(k.clone());
                let key = if replaced != k
                    && (original.contains(&replaced) || out.contains_key(&replaced))
                {
                    k
                } else {
                    replaced
                };
                out.insert(key, json_walk_nested(v, leaf, depth_limit, depth, nest + 1));
            }
            serde_json::Value::Object(out)
        }
        other => other,
    }
}

fn walk_string_leaf(
    s: String,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
    depth: u32,
) -> String {
    if depth > depth_limit {
        return leaf(s);
    }
    let inner_stripped = strip_bom(&s).trim();
    if (inner_stripped.starts_with('{') || inner_stripped.starts_with('['))
        && let Ok(inner) = jloads(inner_stripped)
        && matches!(
            inner,
            serde_json::Value::Object(_) | serde_json::Value::Array(_)
        )
    {
        let walked = json_walk(inner, leaf, depth_limit, depth + 1);
        let out = jdumps(&walked);
        // 内层合法而回写非法时回退该叶原串。
        let checked = validate_json_roundtrip(inner_stripped, &out, "json_walk");
        if checked == out {
            return out;
        }
        return s;
    }
    leaf(s)
}

/// 顶层入口：JSON 文本走 loads→walk→dumps，非 JSON / 解析失败 / 超限回退 plain。
///
/// - `text.len() > SCAN_INPUT_LIMIT` 直接 plain（不解析）；»MUST NOT 字符串级切分 `\u`«：
///   本函数永不手切转义，一律经 `loads` 解码成串后处理。
pub fn process_text(
    text: &str,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
) -> String {
    if text.len() > SCAN_INPUT_LIMIT {
        return leaf(text.to_string());
    }
    let stripped = strip_bom(text).trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return leaf(text.to_string());
    }
    let obj = match jloads(strip_bom(text)) {
        Ok(v) => v,
        Err(_) => return leaf(text.to_string()),
    };
    // 仅 object/array 走 walk，其余标量原样 plain。
    if !matches!(
        obj,
        serde_json::Value::Object(_) | serde_json::Value::Array(_)
    ) {
        return leaf(text.to_string());
    }
    let walked = json_walk(obj, leaf, depth_limit, 0);
    let out = jdumps(&walked);
    validate_json_roundtrip(text, &out, "json_walk")
}

#[cfg(test)]
mod tests;
