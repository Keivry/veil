//! 请求级 `Scope` 脱敏外观（D2 自 `redaction.rs` 拆出）：请求/响应双侧编排。

use {
    super::{
        super::{
            credential_vault::{CredentialVault, TOKEN_PREFIX, strip_cred_partials},
            json_walk,
            llm_gateway::Protocol,
            lock_recover::lock_or_recover,
            pii::{PiiDetector, PiiScope},
        },
        conversation_key::{ConversationKey, ConversationWriteback, PreviousResponseMap},
        leaf::{
            find_sub_spans,
            prescan_custom,
            prescan_custom_response,
            redact_leaf_response,
            redact_leaf_tracked,
            scan_token_forms,
        },
    },
    std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// B3 请求级铸造集：仅记录本请求**脱敏实际产出**的凭据 token（`P2tSnapshot::redact`
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

    /// 授权集合快照（`CredentialVault::strip_hallucinated` 过滤用）。
    fn snapshot(&self) -> std::collections::HashSet<String> {
        lock_or_recover(self.0.lock()).clone()
    }
}

/// 请求级作用域：PII 映射只活在本 Scope 内，请求结束即销毁，
/// 跨请求 MUST NOT 互见；PII 还原只查本 Scope。
pub struct Scope {
    /// `request` 模式逐请求新建；`conversation` 模式为存储共享的 `Arc`。
    pii: Arc<PiiScope>,
    response_side: bool,
    fuzzy_restore: bool,
    /// B3：本请求脱敏实际产出的凭据 token（响应还原授权域，恒逐请求）。
    minted: MintedSet,
    /// 会话写回上下文：仅 `conversation` 模式且键推导成功时存在。
    conversation: Option<ConversationWriteback>,
    /// R5-14/D5 side-channel 失败标志：脱敏链中 rand8 熵源/内部故障置位；
    /// 调用方据此 fail-closed（`502 + E_PII_UNAVAILABLE`），MUST NOT 转发未脱敏正文。
    pii_unavailable: AtomicBool,
}

/// 手工 `Debug`（FIX 2）：会话写回上下文（会话键/租户指纹/HMAC 密钥）不得经
/// `{:?}` 泄漏，仅暴露是否存在；其余字段保持既有呈现。
impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("pii", &self.pii)
            .field("response_side", &self.response_side)
            .field("fuzzy_restore", &self.fuzzy_restore)
            .field("minted", &self.minted)
            .field(
                "conversation",
                &self.conversation.as_ref().map(|_| "[redacted]"),
            )
            .field("pii_unavailable", &self.pii_unavailable())
            .finish()
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            pii: Arc::new(PiiScope::new()),
            response_side: true,
            fuzzy_restore: false,
            minted: MintedSet::default(),
            conversation: None,
            pii_unavailable: AtomicBool::new(false),
        }
    }
}

impl Scope {
    /// 新建请求作用域（每请求一个）。
    pub fn new() -> Self { Self::default() }

    /// 按 `Config` 语义开关构造：`response_side` 关时响应新检出不再脱敏，
    /// `fuzzy_restore` 开时残缺/宽松形态 token 按序号回查还原。
    pub fn with_opts(response_side: bool, fuzzy_restore: bool) -> Self {
        Self {
            pii: Arc::new(PiiScope::new()),
            response_side,
            fuzzy_restore,
            minted: MintedSet::default(),
            conversation: None,
            pii_unavailable: AtomicBool::new(false),
        }
    }

    /// 会话级作用域：PII 映射来自存储共享的 `Arc<PiiScope>`（跨轮复用），
    /// 凭据 minted-set 仍逐请求独立（B3 不变）。
    pub fn with_shared_pii(pii: Arc<PiiScope>, response_side: bool, fuzzy_restore: bool) -> Self {
        Self {
            pii,
            response_side,
            fuzzy_restore,
            minted: MintedSet::default(),
            conversation: None,
            pii_unavailable: AtomicBool::new(false),
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

    /// R5-14/D5：脱敏链是否发生 rand8 熵源/内部故障（调用方据此 fail-closed）。
    pub fn pii_unavailable(&self) -> bool { self.pii_unavailable.load(Ordering::Relaxed) }

    /// R5-09/D10：是否挂载了会话写回上下文（仅 `conversation` 模式且键推导成功）。
    /// 只暴露「有无」，MUST NOT 泄露会话键或租户指纹。
    pub fn has_conversation(&self) -> bool { self.conversation.is_some() }

    /// 底层的请求级 PII 容器（高级用法/断言）。
    #[cfg(test)]
    pub(crate) fn pii_scope(&self) -> &PiiScope { self.pii.as_ref() }

    /// 请求侧脱敏：凭据优先 → PII（内置+字典同步，自定义预扫异步）→ json-walk。
    /// 输出末尾统一 `_strip_partials` 残缺清理。
    /// FIX-5 保字节：全叶零替换时返回原文（不走 dumps 重排）。
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

    /// 请求侧脱敏（H1/D3 报告变体）：返回 `(脱敏文本, 是否经 loads→walk→dumps 重序列化)`。
    /// 重序列化判定 = 有替换命中（含自定义预扫）且输入为可 walk 的 JSON 容器；
    /// 非 JSON 字节级替换与原文透传返回 `false`（对齐 README §7.7 置位口径）。
    pub async fn redact_request_with_report(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> (String, bool) {
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
        let mut leaf = |s: String| {
            let r = redact_leaf_tracked(
                &self.pii,
                detector,
                &cred_map,
                &custom_snapshot,
                &self.minted,
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
            (strip_partials(&out), is_json_container(text))
        } else {
            (text.to_string(), false)
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
            text.to_string(),
            &self.pii_unavailable,
        );
        strip_partials(&redacted)
    }

    /// 响应侧还原：凭据 token（**仅本请求脱敏实际产出者**，B3）→ PII 请求 token →
    /// 幻觉/未授权剥离 → 残缺清理。
    /// PII 完整形态一律保留（响应期新 token 原样保留语义）。
    /// `fuzzy_restore` 开启时追加宽松形态按序号回查。
    /// R7：本函数为内部步骤，唯一公开还原入口为
    /// [`Scope::restore_response_with_spans`]（生产调用方均经该入口）；
    /// 可见性收敛为模块内，单测同文件可达。
    fn restore_response(&self, vault: &CredentialVault, text: &str) -> String {
        let minted = self.minted.snapshot();
        let step1 = restore_cred_tokens(vault, text, &minted);
        let step2 = self.pii.restore_with_fuzzy(&step1, self.fuzzy_restore);
        let step3 = vault.strip_hallucinated(&step2, Some(&minted));
        strip_partials(&step3)
    }

    /// 单 token 回查（X3/D4）：凭据 token 经 `CredentialVault::restore_one`
    /// 直查（不克隆全表、不重建 alternation 正则）；非凭据 token 原样进入
    /// PII 回查。其余步骤与 [`Scope::restore_response`] 同序（PII 还原 →
    /// 幻觉剥离 → 残缺清理），保证 span 明文与全量还原结果一致。
    /// B3：凭据 token 非本请求脱敏产出（未授权）者 **SHALL NOT** 还原，原样返回，
    /// 由 [`Scope::restore_response`] 的授权剥离阶段统一清理；PII token 授权
    /// 由请求级 `PiiScope`（本 Scope 内）自理，不适用铸造集。
    fn restore_response_one(&self, vault: &CredentialVault, token: &str) -> String {
        if token.starts_with(TOKEN_PREFIX) && !self.minted.contains(token) {
            return token.to_string();
        }
        let step1 = vault
            .restore_one(token)
            .unwrap_or_else(|| token.to_string());
        let step2 = self.pii.restore_with_fuzzy(&step1, self.fuzzy_restore);
        let step3 = vault.strip_hallucinated(&step2, None);
        strip_partials(&step3)
    }

    /// 响应还原（含 span 透传，§2.2）：
    /// 返回 `(还原文本, 还原明文区间)`；区间为还原文本中的字节下标。
    /// 调用方做响应侧新检出时须经 [`Scope::redact_response_new_pii_with_skip`]
    /// 跳过这些区间，否则刚还原的请求明文会被二次掩码为响应 token。
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
        // APP-5/D19：逐出现点定位——把每个可还原 token 出现点替换为唯一哨兵，
        // 经同一还原管线后按哨兵位置回填明文；MUST NOT 以明文子串全量查找后整段
        // skip，否则响应侧独立同值明文会被漏掩码。
        let mut restorations: Vec<(String, String)> = Vec::with_capacity(forms.len());
        let mut masked = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for (s, e, token) in &forms {
            if *s < cursor {
                continue;
            }
            // 逐 token 直查（不触全量快照）：未注册/幻觉形态回查不变或清空，直接跳过。
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

    /// 响应还原（JSON 字符串上下文变体，H2/D1）：与
    /// [`Scope::restore_response_with_spans`] 同还原语义（PII/凭据/幻觉/残缺），
    /// 写回明文按 RFC 8259 转义（`"`→`\"`、`\`→`\\`、控制字符转义），
    /// 保证「还原前可解析」的 JSON 帧「还原后仍可解析」；返回的 span 为
    /// 转义后文本中的还原明文区间（供
    /// [`Scope::redact_response_new_pii_with_skip`] 跳过二次掩码）。
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
        // RED-1：按明文实际所在 JSON 字符串嵌套深度转义写回。工具参数常为
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
            // NLP-4/D13：按 span 实际所在深度逐点转义（不聚合该明文的全局 max），
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

    /// 响应侧新检出：响应中出现的新 PII 注册进响应表（不进请求还原表），
    /// 以新占位符呈现，不还原为明文。
    /// `PII_RESPONSE_SIDE=0` 时直接返回原文（响应侧脱敏关闭）。
    pub async fn redact_response_new_pii(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        if !self.response_side {
            return text.to_string();
        }
        self.redact_response_new_pii_tracked(vault, detector, text)
            .await
            .0
    }

    /// 响应侧新检出追踪内核（H1/D2，对齐请求侧 FIX-5 `replaced` Cell）：
    /// 返回 `(输出, 是否发生替换)`；全程零替换且无自定义预扫命中时返回原文
    /// （跳过 `json_walk::process_text` 的 `jdumps` 重排，逐字节透传）。
    async fn redact_response_new_pii_tracked(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> (String, bool) {
        if !self.response_side {
            return (text.to_string(), false);
        }
        let cred_map = vault.p2t_snapshot();
        let custom_snapshot = prescan_custom_response(
            detector,
            &self.pii,
            text,
            cred_map.map(),
            &self.pii_unavailable,
        )
        .await;
        let replaced = std::cell::Cell::new(false);
        let mut leaf = |s: String| {
            let r = redact_leaf_response(
                &self.pii,
                detector,
                &cred_map,
                &custom_snapshot,
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
            (strip_partials(&out), true)
        } else {
            (strip_partials(text), false)
        }
    }

    /// 响应侧新检出（跳过还原区间，§2.2）：
    /// 与 [`Scope::redact_response_new_pii`] 同语义，但 `skip`
    /// （[`Scope::restore_response_with_spans`] 返回值）覆盖的原文区间原样保留，
    /// 刚还原的请求明文保持明文。按区间切段后仅对非跳过段做新检出，
    /// 再按原序拼接（跳过段字节级原样，坐标天然对齐）。
    pub async fn redact_response_new_pii_with_skip(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
        skip: &[(usize, usize)],
    ) -> String {
        if !self.response_side {
            return text.to_string();
        }
        let mut spans: Vec<(usize, usize)> = skip
            .iter()
            .filter(|(s, e)| {
                *s < *e
                    && *e <= text.len()
                    && text.is_char_boundary(*s)
                    && text.is_char_boundary(*e)
            })
            .copied()
            .collect();
        if spans.is_empty() {
            return self.redact_response_new_pii(vault, detector, text).await;
        }
        spans.sort_unstable();
        // T8/D8：跳过区间以唯一占位符代位，还原文本保持整体 JSON 结构，
        // `process_text` 因此可递归 walk 嵌套 stringified JSON（工具参数等，
        // 含与还原切分点错位的段）；完成 JSON-aware 新 PII 检测后再把占位符
        // 原位换回还原明文——跳过区间既不被扫描也不被改写（字节级原样）。
        let mut masked = String::with_capacity(text.len());
        let mut restorations: Vec<(String, &str)> = Vec::new();
        let mut cursor = 0usize;
        for (s, e) in spans {
            if s < cursor {
                continue;
            }
            masked.push_str(&text[cursor..s]);
            let sentinel = skip_sentinel(restorations.len(), text);
            masked.push_str(&sentinel);
            restorations.push((sentinel, &text[s..e]));
            cursor = e;
        }
        if restorations.is_empty() {
            return self.redact_response_new_pii(vault, detector, text).await;
        }
        masked.push_str(&text[cursor..]);
        let (scanned, _) = self
            .redact_response_new_pii_tracked(vault, detector, &masked)
            .await;
        let mut out = scanned;
        for (sentinel, original) in restorations {
            out = out.replace(&sentinel, original);
        }
        out
    }
}

/// 跳过区间代位占位符（T8/D8）：纯 ASCII 且不落入 `__VG_`/`__PII_` 残缺
/// 剥离前缀；与原文冲突时追加下划线直至全局唯一。
fn skip_sentinel(idx: usize, text: &str) -> String {
    let mut s = format!("__VEILSKIP{idx:08}__");
    while text.contains(&s) {
        s.push('_');
    }
    s
}

/// 凭据 token 逐 token 直查重建（B2/D2）：仅对 `scan_token_forms` 命中的完整形态
/// 调 `CredentialVault::restore_one`，未注册形态原样保留；与全量 alternation
/// 替换逐字节等价（还原只做 token→明文，不重序列化）。
/// B3：仅授权集合内（本请求脱敏实际产出）的 token 还原，其余原样保留。
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

/// RED-1：按 JSON 字符串嵌套深度转义明文（顶层字符串值=1，stringified JSON
/// 内层每层 +1），保证「还原前可解析」的帧「还原后仍可解析」。
fn escape_json_depth(plain: &str, depth: u32) -> String {
    let mut out = plain.to_string();
    for _ in 0..depth.max(1) {
        out = json_escape_plain(&out);
    }
    out
}

/// RED-1/NLP-4/B4：统计各还原明文在 JSON 帧中的字符串嵌套深度，**按出现点文档序**
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

/// B4 帧级片段载体判定：Responses `response.function_call_arguments.delta` 帧，
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
            // NLP-3/D12：对象 key 与字符串值同深度口径——键位凭据深度不得漏算。
            for (k, v) in map {
                // B4：子树键名 `partial_json`/`arguments` 即片段载体上下文。
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
/// B4：载体上下文中以 `{`/`[` 开头但整体不可解析的片段按 `depth + 1` 计入
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
/// 凭据完整形态同样被清理（还原须先行）；PII 完整形态由前瞻排除得以保留
/// （响应期新 token 原样保留语义）。
pub fn strip_partials(text: &str) -> String {
    super::super::pii::strip_pii_partials(&strip_cred_partials(text))
}

/// 响应出口统一清理：幻觉完整凭据 token 剥离 + 残缺清理接全出口。
/// 真实 token 应先经 `restore_response` 还原，未还原的完整形态必是幻觉。
#[cfg(test)]
pub(crate) fn strip_token_forms(vault: &CredentialVault, text: &str) -> String {
    strip_partials(&vault.strip_hallucinated(text, None))
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod scope_tests;

#[cfg(test)]
#[path = "scope_p2_tests.rs"]
mod scope_p2_tests;
