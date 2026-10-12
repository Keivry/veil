//! 请求级 `Scope` 脱敏外观（自 `redaction.rs` 拆出）：请求/响应双侧编排。

use {
    super::{
        super::{
            credential_vault::{CredentialVault, TOKEN_PREFIX, strip_cred_partials},
            json_walk,
            llm_gateway::Protocol,
            lock_recover::lock_or_recover,
            metrics::{SampleBinding, SampleCtx},
            pii::{PiiDetector, PiiScope},
        },
        conversation_key::{ConversationKey, ConversationWriteback, PreviousResponseMap},
        leaf::{
            RedactionTally,
            find_sub_spans,
            prescan_custom,
            redact_leaf_tracked,
            scan_token_forms,
        },
    },
    std::sync::{
        Arc,
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// 请求级铸造集：仅记录本请求**脱敏实际产出**的凭据 token（`P2tSnapshot::redact`
/// 的替换值经 `redact_leaf` 汇总），随 `Scope` 请求结束销毁；响应还原仅授权集合内 token。
#[derive(Debug, Default)]
pub(crate) struct MintedSet(std::sync::Mutex<std::collections::HashSet<String>>);

impl MintedSet {
    /// 记录一枚实际产出的 token（重复插入幂等）。
    pub(crate) fn record(&self, token: &str) {
        lock_or_recover(self.0.lock()).insert(token.to_string());
    }

    /// token 是否为本请求脱敏实际产出（还原授权判据）。
    pub(crate) fn contains(&self, token: &str) -> bool {
        lock_or_recover(self.0.lock()).contains(token)
    }

    /// 授权集合快照（凭据 token 还原授权过滤用）。
    fn snapshot(&self) -> std::collections::HashSet<String> {
        lock_or_recover(self.0.lock()).clone()
    }
}

/// 请求级作用域：PII 映射只活在本 Scope 内，请求结束即销毁，
/// 跨请求 MUST NOT 互见；PII 还原只查本 Scope。
pub struct Scope {
    /// `request` 模式逐请求新建；`conversation` 模式为存储共享的 `Arc`。
    pii: Arc<PiiScope>,
    fuzzy_restore: bool,
    /// 本请求脱敏实际产出的凭据 token（响应还原授权域，恒逐请求）。
    minted: MintedSet,
    /// 会话写回上下文：仅 `conversation` 模式且键推导成功时存在。
    conversation: Option<ConversationWriteback>,
    /// side-channel 失败标志：脱敏链中 rand8 熵源/内部故障置位；
    /// 调用方据此 fail-closed（`502 + E_PII_UNAVAILABLE`），MUST NOT 转发未脱敏正文。
    pii_unavailable: AtomicBool,
    /// 值级采样绑定：dispatch 单一装配点构造后一次性写入（`OnceLock`，读侧零锁）；
    /// 请求与响应两侧叶内核复用同一绑定。未接线（测试态）恒 `None`，零开销零行为变化。
    sample: OnceLock<SampleBinding>,
}

/// 手工 `Debug`（FIX 2）：会话写回上下文（会话键/租户指纹/HMAC 密钥）不得经
/// `{:?}` 泄漏，仅暴露是否存在；其余字段保持既有呈现。
impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("pii", &self.pii)
            .field("fuzzy_restore", &self.fuzzy_restore)
            .field("minted", &self.minted)
            .field(
                "conversation",
                &self.conversation.as_ref().map(|_| "[redacted]"),
            )
            .field("pii_unavailable", &self.pii_unavailable())
            .field("sample_configured", &self.sample.get().is_some())
            .finish()
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            pii: Arc::new(PiiScope::new()),
            fuzzy_restore: false,
            minted: MintedSet::default(),
            conversation: None,
            pii_unavailable: AtomicBool::new(false),
            sample: OnceLock::new(),
        }
    }
}

impl Scope {
    /// 新建请求作用域（每请求一个）。
    pub fn new() -> Self { Self::default() }

    /// 按 `Config` 语义开关构造：`fuzzy_restore` 开时残缺/宽松形态 token
    /// 按序号回查还原。
    pub fn with_opts(fuzzy_restore: bool) -> Self {
        Self {
            pii: Arc::new(PiiScope::new()),
            fuzzy_restore,
            minted: MintedSet::default(),
            conversation: None,
            pii_unavailable: AtomicBool::new(false),
            sample: OnceLock::new(),
        }
    }

    /// 会话级作用域：PII 映射来自存储共享的 `Arc<PiiScope>`（跨轮复用），
    /// 凭据 minted-set 仍逐请求独立。
    pub fn with_shared_pii(pii: Arc<PiiScope>, fuzzy_restore: bool) -> Self {
        Self {
            pii,
            fuzzy_restore,
            minted: MintedSet::default(),
            conversation: None,
            pii_unavailable: AtomicBool::new(false),
            sample: OnceLock::new(),
        }
    }

    /// 挂载会话写回上下文：响应完成处据本会话键把上游响应 id 写入映射。
    pub fn with_conversation(
        mut self,
        key: ConversationKey,
        tenant_fingerprint: String,
        secret: Arc<[u8]>,
        previous_map: Arc<PreviousResponseMap>,
    ) -> Self {
        self.conversation = Some(ConversationWriteback::new(
            key,
            tenant_fingerprint,
            secret,
            previous_map,
        ));
        self
    }

    /// 响应完成写回（仅 `Protocol::Responses` 写入映射；无写回上下文时 no-op）。
    pub fn record_response_id(&self, protocol: Protocol, response_id: &str) -> bool {
        self.conversation
            .as_ref()
            .is_some_and(|wb| wb.record(protocol, response_id))
    }

    /// 脱敏链是否发生 rand8 熵源/内部故障（调用方据此 fail-closed）。
    pub fn pii_unavailable(&self) -> bool { self.pii_unavailable.load(Ordering::Relaxed) }

    /// 一次性写入采样绑定（dispatch 单一装配点调用；重复写入为 no-op）。
    pub fn configure_sampling(&self, binding: SampleBinding) { let _ = self.sample.set(binding); }

    /// 叶内核采样上下文：未接线时返回零开销 [`SampleCtx::disabled`]。
    fn sample_ctx(&self) -> SampleCtx<'_> {
        self.sample
            .get()
            .map_or_else(SampleCtx::disabled, SampleBinding::ctx)
    }

    /// 是否挂载了会话写回上下文（仅 `conversation` 模式且键推导成功）。
    /// 只暴露「有无」，MUST NOT 泄露会话键或租户指纹。
    pub fn has_conversation(&self) -> bool { self.conversation.is_some() }

    /// 底层的请求级 PII 容器（高级用法/断言）。
    #[cfg(test)]
    pub(crate) fn pii_scope(&self) -> &PiiScope { self.pii.as_ref() }

    /// 请求侧脱敏：凭据优先 → PII（内置+字典同步，自定义预扫异步）→ json-walk。
    /// 输出末尾统一 `_strip_partials` 残缺清理。
    /// 保字节：全叶零替换时返回原文（不走 dumps 重排）。
    #[cfg(test)]
    pub(crate) async fn redact_request(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        self.redact_request_with_report(vault, detector, text)
            .await
            .0
    }

    /// 请求侧脱敏（报告变体）：返回 `(脱敏文本, 是否经 loads→walk→dumps 重序列化)`。
    /// 重序列化判定 = 有替换命中（含自定义预扫）且输入为可 walk 的 JSON 容器；
    /// 非 JSON 字节级替换与原文透传返回 `false`（对齐 工程参考 §7.7 置位口径）。
    pub async fn redact_request_with_report(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> (String, bool) {
        let (text, reserialized, _) = self
            .redact_request_with_report_and_counts(vault, detector, text)
            .await;
        (text, reserialized)
    }

    /// 请求侧脱敏（计数报告）：在 [`Scope::redact_request_with_report`]
    /// 基础上追加三项请求侧计数（内置/字典 PII hits/miss + 凭据替换次数）。
    /// 计数仅请求侧对称产出；零替换或未启用脱敏时为默认零值。
    pub async fn redact_request_with_report_and_counts(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> (String, bool, RedactionTally) {
        let sample = self.sample_ctx();
        let cred_map = vault.p2t_snapshot();
        // 自定义正则先在原文上预扫并注册（值→token 快照供叶回调复用）。
        let custom_snapshot = prescan_custom(
            detector,
            &self.pii,
            text,
            cred_map.map(),
            &self.pii_unavailable,
        )
        .await;
        let replaced = std::cell::Cell::new(false);
        let mut tally = RedactionTally::default();
        let mut leaf = |s: String| {
            let r = redact_leaf_tracked(
                &self.pii,
                detector,
                &cred_map,
                &custom_snapshot,
                &self.minted,
                Some(&mut tally),
                &sample,
                s.clone(),
                &self.pii_unavailable,
            );
            if r != s {
                replaced.set(true);
            }
            r
        };
        let out = json_walk::process_text(text, &mut leaf, json_walk::DEPTH_LIMIT);
        if replaced.get() || !custom_snapshot.is_empty() {
            (strip_partials(&out), is_json_container(text), tally)
        } else {
            (strip_partials(text), false, tally)
        }
    }

    /// 请求侧 plain 脱敏（非 JSON / 已超限输入的直通路径，同样全量扫描）。
    #[cfg(test)]
    pub(crate) async fn redact_request_plain(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        let cred_map = vault.p2t_snapshot();
        let custom_snapshot = prescan_custom(
            detector,
            &self.pii,
            text,
            cred_map.map(),
            &self.pii_unavailable,
        )
        .await;
        let redacted = redact_leaf_tracked(
            &self.pii,
            detector,
            &cred_map,
            &custom_snapshot,
            &self.minted,
            None,
            &self.sample_ctx(),
            text.to_string(),
            &self.pii_unavailable,
        );
        strip_partials(&redacted)
    }

    /// 响应侧还原：凭据 token（**仅本请求脱敏实际产出者**）→ PII 请求 token →
    /// 残缺清理。未注册/未授权完整 token 原样透传（不再遮蔽/移除）。
    /// `fuzzy_restore` 开启时追加宽松形态按序号回查。
    /// 本函数为内部步骤，唯一公开还原入口为
    /// [`Scope::restore_response_with_spans`]（生产调用方均经该入口）；
    /// 可见性收敛为模块内，单测同文件可达。
    fn restore_response(&self, vault: &CredentialVault, text: &str) -> String {
        let minted = self.minted.snapshot();
        let step1 = restore_cred_tokens(vault, text, &minted);
        let step2 = self.pii.restore_with_fuzzy(&step1, self.fuzzy_restore);
        strip_partials(&step2)
    }

    /// 单 token 回查：凭据 token 经 `CredentialVault::restore_one`
    /// 直查（不克隆全表、不重建 alternation 正则）；非凭据 token 原样进入
    /// PII 回查。其余步骤与 [`Scope::restore_response`] 同序（PII 还原 →
    /// 残缺清理），保证 span 明文与全量还原结果一致。
    /// 凭据 token 非本请求脱敏产出（未授权）者 **SHALL NOT** 还原，原样返回；
    /// PII token 授权由请求级 `PiiScope`（本 Scope 内）自理，不适用铸造集。
    fn restore_response_one(&self, vault: &CredentialVault, token: &str) -> String {
        if token.starts_with(TOKEN_PREFIX) && !self.minted.contains(token) {
            return token.to_string();
        }
        let step1 = vault
            .restore_one(token)
            .unwrap_or_else(|| token.to_string());
        let step2 = self.pii.restore_with_fuzzy(&step1, self.fuzzy_restore);
        strip_partials(&step2)
    }

    /// 响应还原（含 span 透传）：
    /// 返回 `(还原文本, 还原明文区间)`；区间为还原文本中的字节下标。
    /// 不触 handler 接线：纯库函数，零网络副作用。
    pub fn restore_response_with_spans(
        &self,
        vault: &CredentialVault,
        text: &str,
    ) -> (String, Vec<(usize, usize)>) {
        let forms = scan_token_forms(text);
        if forms.is_empty() {
            return (self.restore_response(vault, text), Vec::new());
        }
        // 逐出现点定位——把每个可还原 token 出现点替换为唯一哨兵，
        // 经同一还原管线后按哨兵位置回填明文；MUST NOT 以明文子串全量查找后整段
        // skip，否则响应侧独立同值明文会被漏掩码。
        let mut restorations: Vec<(String, String)> = Vec::with_capacity(forms.len());
        let mut masked = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for (s, e, token) in &forms {
            if *s < cursor {
                continue;
            }
            // 逐 token 直查（不触全量快照）：未注册/未授权/残缺形态回查不变，直接跳过。
            let plain = self.restore_response_one(vault, token);
            if plain.is_empty() || plain == *token {
                continue;
            }
            masked.push_str(&text[cursor..*s]);
            let sentinel = skip_sentinel(restorations.len(), text);
            masked.push_str(&sentinel);
            restorations.push((sentinel, plain));
            cursor = *e;
        }
        if restorations.is_empty() {
            return (self.restore_response(vault, text), Vec::new());
        }
        masked.push_str(&text[cursor..]);
        let restored = self.restore_response(vault, &masked);
        let mut placed: Vec<(usize, String, String)> = restorations
            .into_iter()
            .filter_map(|(sentinel, plain)| {
                find_sub_spans(&restored, &sentinel)
                    .into_iter()
                    .next()
                    .map(|(pos, _)| (pos, sentinel, plain))
            })
            .collect();
        placed.sort_by_key(|(pos, ..)| *pos);
        let mut out = String::with_capacity(restored.len());
        let mut spans: Vec<(usize, usize)> = Vec::with_capacity(placed.len());
        let mut cursor = 0usize;
        for (pos, sentinel, plain) in placed {
            if pos < cursor {
                continue;
            }
            out.push_str(&restored[cursor..pos]);
            let start = out.len();
            out.push_str(&plain);
            spans.push((start, out.len()));
            cursor = pos + sentinel.len();
        }
        out.push_str(&restored[cursor..]);
        (out, spans)
    }

    /// 响应还原（JSON 字符串上下文变体）：与
    /// [`Scope::restore_response_with_spans`] 同还原语义（凭据还原、PII 还原与残缺清理），
    /// 写回明文按 RFC 8259 转义（`"`→`\"`、`\`→`\\`、控制字符转义），
    /// 保证「还原前可解析」的 JSON 帧「还原后仍可解析」；返回的 span 为
    /// 转义后文本中的还原明文区间。
    /// 非 JSON 帧（plain 分支）MUST NOT 走本入口（保持字节级原样还原）。
    pub fn restore_response_with_spans_json(
        &self,
        vault: &CredentialVault,
        text: &str,
    ) -> (String, Vec<(usize, usize)>) {
        let (restored, spans) = self.restore_response_with_spans(vault, text);
        if spans.is_empty() {
            return (restored, spans);
        }
        // 按明文实际所在 JSON 字符串嵌套深度转义写回。工具参数常为
        // stringified JSON（字符串值本身是 JSON 文档），内层明文需比外层多一层
        // 转义；仅按外层单层转义会以内层视角产生非法裸 `"`、破内层结构。
        let mut depths = token_restore_depths(text, |tok| self.restore_response_one(vault, tok));
        let mut out = String::with_capacity(restored.len());
        let mut escaped_spans: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        let mut cursor = 0usize;
        for (s, e) in spans {
            out.push_str(&restored[cursor..s]);
            let start = out.len();
            let plain = &restored[s..e];
            // 按 span 实际所在深度逐点转义（不聚合该明文的全局 max），
            // 深度按文档序逐出现点取用；同明文跨深度时浅层不得被过度转义。
            let depth = depths
                .get_mut(plain)
                .and_then(std::collections::VecDeque::pop_front)
                .unwrap_or(1);
            out.push_str(&escape_json_depth(plain, depth));
            escaped_spans.push((start, out.len()));
            cursor = e;
        }
        out.push_str(&restored[cursor..]);
        (out, escaped_spans)
    }
}

/// 跳过区间代位占位符：纯 ASCII 且不落入 `__CRED_`/`__PII_` 残缺
/// 剥离前缀；与原文冲突时追加非 `_` 字符直至全局唯一。
/// `restore_response_with_spans` 以之逐出现点定位还原明文。
///
/// 后缀免疫：尾字符恒非 `_`（`Z`），使 `<哨兵>C`/`<哨兵>PI` 分别得 `ZC`/`ZPI`
/// 而非 `__C`/`__PI`，免于被残缺清理误剥（否则 `__VEILSKIP…__` + `C` 的闭合
/// `__` 会被当作残缺前缀消费，致哨兵定位失败、内部哨兵泄漏且漏还原）。
/// 碰撞消解追加字符亦须非 `_`，否则追加出的尾 `__` 会重新引入该缺陷。
fn skip_sentinel(idx: usize, text: &str) -> String {
    let mut s = format!("__VEILSKIP{idx:08}Z");
    while text.contains(&s) {
        s.push('Z');
    }
    s
}

/// 凭据 token 逐 token 直查重建：仅对 `scan_token_forms` 命中的完整形态
/// 调 `CredentialVault::restore_one`，未注册形态原样保留；与全量 alternation
/// 替换逐字节等价（还原只做 token→明文，不重序列化）。
/// 仅授权集合内（本请求脱敏实际产出）的 token 还原，其余原样保留。
fn restore_cred_tokens(
    vault: &CredentialVault,
    text: &str,
    minted: &std::collections::HashSet<String>,
) -> String {
    let forms = scan_token_forms(text);
    if forms.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end, token) in forms {
        out.push_str(&text[cursor..start]);
        let plain = if minted.contains(&token) {
            vault.restore_one(&token)
        } else {
            None
        };
        match plain {
            Some(plain) => out.push_str(&plain),
            None => out.push_str(&token),
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// `json_walk::process_text` 是否会对该输入走 `loads→walk→dumps`
/// （长度未超限、BOM 剥离 trim 后以 `{`/`[` 开头且可解析为 object/array）。
fn is_json_container(text: &str) -> bool {
    if text.len() > json_walk::SCAN_INPUT_LIMIT {
        return false;
    }
    let stripped = json_walk::strip_bom(text).trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return false;
    }
    matches!(
        json_walk::jloads(json_walk::strip_bom(text)),
        Ok(serde_json::Value::Object(_) | serde_json::Value::Array(_))
    )
}

/// RFC 8259 字符串上下文转义（JSON 帧还原写回用）：`"`/`\`/控制字符转义。
/// 复用 `serde_json` 的字符串序列化实现，保证与 JSON 解析器严格互逆。
fn json_escape_plain(s: &str) -> String {
    let quoted = serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""));
    quoted
        .strip_prefix('"')
        .and_then(|q| q.strip_suffix('"'))
        .map_or_else(|| s.to_string(), str::to_string)
}

/// 按 JSON 字符串嵌套深度转义明文（顶层字符串值=1，stringified JSON
/// 内层每层 +1），保证「还原前可解析」的帧「还原后仍可解析」。
fn escape_json_depth(plain: &str, depth: u32) -> String {
    let mut out = plain.to_string();
    for _ in 0..depth.max(1) {
        out = json_escape_plain(&out);
    }
    out
}

/// 统计各还原明文在 JSON 帧中的字符串嵌套深度，**按出现点文档序**
/// 逐点入队（明文 → 深度队列），供 [`Scope::restore_response_with_spans_json`]
/// 按 span 实际深度逐点转义。`plain_of` 返回 token 还原明文；非 token 明文不计入。
fn token_restore_depths(
    text: &str,
    plain_of: impl Fn(&str) -> String,
) -> std::collections::HashMap<String, std::collections::VecDeque<u32>> {
    let mut depths: std::collections::HashMap<String, std::collections::VecDeque<u32>> =
        std::collections::HashMap::new();
    if let Ok(v) = json_walk::jloads(json_walk::strip_bom(text))
        && matches!(
            v,
            serde_json::Value::Object(_) | serde_json::Value::Array(_)
        )
    {
        collect_token_depths(&v, 1, frame_fragment_carrier(&v), &plain_of, &mut depths);
    }
    if depths.is_empty() {
        for (_, _, tok) in scan_token_forms(text) {
            let plain = plain_of(&tok);
            if !plain.is_empty() && plain != tok {
                depths.entry(plain).or_default().push_back(1);
            }
        }
    }
    depths
}

/// 帧级片段载体判定：Responses `response.function_call_arguments.delta` 帧，
/// 或 Anthropic `content_block_delta` 且 `delta.type == "input_json_delta"` 帧。
/// 其余帧由子树键名（`partial_json`/`arguments`）逐层标记载体上下文。
fn frame_fragment_carrier(v: &serde_json::Value) -> bool {
    match v.get("type").and_then(serde_json::Value::as_str) {
        Some("response.function_call_arguments.delta") => true,
        Some("content_block_delta") => {
            v.get("delta")
                .and_then(|d| d.get("type"))
                .and_then(serde_json::Value::as_str)
                == Some("input_json_delta")
        }
        _ => false,
    }
}

fn collect_token_depths(
    value: &serde_json::Value,
    depth: u32,
    fragment_ctx: bool,
    plain_of: &impl Fn(&str) -> String,
    depths: &mut std::collections::HashMap<String, std::collections::VecDeque<u32>>,
) {
    match value {
        serde_json::Value::String(s) => {
            collect_string_depths(s, depth, fragment_ctx, plain_of, depths)
        }
        serde_json::Value::Array(items) => {
            for v in items {
                collect_token_depths(v, depth, fragment_ctx, plain_of, depths);
            }
        }
        serde_json::Value::Object(map) => {
            // 对象 key 与字符串值同深度口径——键位凭据深度不得漏算。
            for (k, v) in map {
                // 子树键名 `partial_json`/`arguments` 即片段载体上下文。
                let child_ctx = fragment_ctx || matches!(k.as_str(), "partial_json" | "arguments");
                collect_string_depths(k, depth, fragment_ctx, plain_of, depths);
                collect_token_depths(v, depth, child_ctx, plain_of, depths);
            }
        }
        _ => {}
    }
}

/// 单个字符串节点的深度统计：stringified JSON 容器只按内层 +1 递归（容器内
/// token 的深度属内层，不得按外层重复计入），非容器字符串统计自身当前深度；
/// 载体上下文中以 `{`/`[` 开头但整体不可解析的片段按 `depth + 1` 计入
/// （token 将随片段拼接进入内层 JSON），载体外普通字符串（如 `delta.text`）
/// **SHALL NOT** 加一。
fn collect_string_depths(
    s: &str,
    depth: u32,
    fragment_ctx: bool,
    plain_of: &impl Fn(&str) -> String,
    depths: &mut std::collections::HashMap<String, std::collections::VecDeque<u32>>,
) {
    let inner = json_walk::strip_bom(s).trim();
    if (inner.starts_with('{') || inner.starts_with('['))
        && let Ok(v) = json_walk::jloads(inner)
        && matches!(
            v,
            serde_json::Value::Object(_) | serde_json::Value::Array(_)
        )
    {
        collect_token_depths(&v, depth + 1, fragment_ctx, plain_of, depths);
        return;
    }
    let scan_depth = if fragment_ctx && (inner.starts_with('{') || inner.starts_with('[')) {
        depth + 1
    } else {
        depth
    };
    for (_, _, tok) in scan_token_forms(s) {
        let plain = plain_of(&tok);
        if !plain.is_empty() && plain != tok {
            depths.entry(plain).or_default().push_back(scan_depth);
        }
    }
}

/// 全出口残缺清理：凭据 + PII 两套半截形态统一入口。
/// 两侧完整形态均由各自负向前瞻豁免得以原样保留（响应期未注册完整 token
/// 原样透传语义）；仅残缺形态被剥离。
pub fn strip_partials(text: &str) -> String {
    super::super::pii::strip_pii_partials(&strip_cred_partials(text))
}

/// 聚合测试共享：`tests`（含 `tests/` 主题子模块）经 `super::test_support` 复用。
#[cfg(test)]
pub(crate) mod test_support {
    use super::{CredentialVault, PiiDetector, Scope};

    /// 经真实请求侧脱敏铸造凭据 token（响应侧仅授权本请求实际产出）。
    pub(crate) async fn mint_cred(scope: &Scope, vault: &CredentialVault, secret: &str) {
        let _ = scope
            .redact_request(vault, &PiiDetector::new(), secret)
            .await;
    }
}

#[cfg(test)]
mod tests;
