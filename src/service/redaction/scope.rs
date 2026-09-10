//! 请求级 `Scope` 脱敏外观（D2 自 `redaction.rs` 拆出）：请求/响应双侧编排。

use super::{
    super::{
        credential_vault::{CredentialVault, strip_cred_partials},
        json_walk,
        pii::{PiiDetector, PiiScope},
    },
    leaf::{
        find_sub_spans,
        prescan_custom,
        prescan_custom_response,
        redact_leaf,
        redact_leaf_response,
        scan_token_forms,
    },
};

/// 请求级作用域：PII 映射只活在本 Scope 内，请求结束即销毁，
/// 跨请求 MUST NOT 互见；PII 还原只查本 Scope。
#[derive(Debug)]
pub struct Scope {
    pii: PiiScope,
    response_side: bool,
    fuzzy_restore: bool,
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            pii: PiiScope::new(),
            response_side: true,
            fuzzy_restore: false,
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
            pii: PiiScope::new(),
            response_side,
            fuzzy_restore,
        }
    }

    /// 底层的请求级 PII 容器（高级用法/断言）。
    pub fn pii_scope(&self) -> &PiiScope { &self.pii }

    /// 请求侧脱敏：凭据优先 → PII（内置+字典同步，自定义预扫异步）→ json-walk。
    /// 输出末尾统一 `_strip_partials` 残缺清理。
    /// FIX-5 保字节：全叶零替换时返回原文（不走 dumps 重排）。
    pub async fn redact_request(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        let cred_map = vault.snapshot_p2t();
        // 自定义正则先在原文上预扫并注册（值→token 快照供叶回调复用）。
        let custom_snapshot = prescan_custom(detector, &self.pii, text, &cred_map).await;
        let replaced = std::cell::Cell::new(false);
        let mut leaf = |s: String| {
            let r = redact_leaf(&self.pii, detector, &cred_map, &custom_snapshot, s.clone());
            if r != s {
                replaced.set(true);
            }
            r
        };
        let out = json_walk::process_text(text, &mut leaf, json_walk::DEPTH_LIMIT);
        if replaced.get() || !custom_snapshot.is_empty() {
            strip_partials(&out)
        } else {
            strip_partials(text)
        }
    }

    /// 请求侧 plain 脱敏（非 JSON / 已超限输入的直通路径，同样全量扫描）。
    pub async fn redact_request_plain(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        let cred_map = vault.snapshot_p2t();
        let custom_snapshot = prescan_custom(detector, &self.pii, text, &cred_map).await;
        let redacted = redact_leaf(
            &self.pii,
            detector,
            &cred_map,
            &custom_snapshot,
            text.to_string(),
        );
        strip_partials(&redacted)
    }

    /// 响应侧还原：凭据 token → PII 请求 token → 幻觉剥离 → 残缺清理。
    /// PII 完整形态一律保留（响应期新 token 原样保留语义）。
    /// `fuzzy_restore` 开启时追加宽松形态按序号回查。
    /// R7：本函数为内部步骤，唯一公开还原入口为
    /// [`Scope::restore_response_with_spans`]（生产调用方均经该入口）；
    /// 可见性收敛为模块内，单测同文件可达。
    fn restore_response(&self, vault: &CredentialVault, text: &str) -> String {
        let step1 = vault.restore(text);
        let step2 = self.pii.restore_with_fuzzy(&step1, self.fuzzy_restore);
        let step3 = vault.strip_hallucinated(&step2);
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
        let restored = self.restore_response(vault, text);
        let mut spans = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (_, _, token) in scan_token_forms(text) {
            if !seen.insert(token.clone()) {
                continue;
            }
            // 经公开还原路径单 token 回查明文：未注册/幻觉形态回查不变或清空，直接跳过。
            let plain = self.restore_response(vault, &token);
            if plain.is_empty() || plain == token {
                continue;
            }
            for (s, e) in find_sub_spans(&restored, &plain) {
                spans.push((s, e));
            }
        }
        spans.sort_unstable();
        // 重叠区间保留最长者（短明文嵌在长明文内时只留长区间）。
        let mut dedup: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (s, e) in spans {
            if let Some((ls, le)) = dedup.last_mut() {
                if s < *le && e > *le {
                    *ls = (*ls).min(s);
                    *le = e;
                    continue;
                }
                if s < *le {
                    continue;
                }
            }
            dedup.push((s, e));
        }
        (restored, dedup)
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
        let cred_map = vault.snapshot_p2t();
        let custom_snapshot = prescan_custom_response(detector, &self.pii, text, &cred_map).await;
        let mut leaf =
            |s: String| redact_leaf_response(&self.pii, detector, &cred_map, &custom_snapshot, s);
        let out = json_walk::process_text(text, &mut leaf, json_walk::DEPTH_LIMIT);
        strip_partials(&out)
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
            .filter(|(s, e)| *s < *e && *s <= text.len() && *e <= text.len())
            .copied()
            .collect();
        if spans.is_empty() {
            return self.redact_response_new_pii(vault, detector, text).await;
        }
        spans.sort_unstable();
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for (s, e) in spans {
            if s < cursor {
                continue;
            }
            if s > cursor {
                out.push_str(
                    &self
                        .redact_response_new_pii(vault, detector, &text[cursor..s])
                        .await,
                );
            }
            // 跳过段原样保留：还原出的请求明文不得二次掩码。
            out.push_str(&text[s..e]);
            cursor = e.max(cursor);
        }
        if cursor < text.len() {
            out.push_str(
                &self
                    .redact_response_new_pii(vault, detector, &text[cursor..])
                    .await,
            );
        }
        strip_partials(&out)
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
pub fn strip_token_forms(vault: &CredentialVault, text: &str) -> String {
    strip_partials(&vault.strip_hallucinated(text))
}

#[cfg(test)]
mod scope_tests {
    use {
        super::*,
        crate::service::{credential_vault::redact_with_map, pii::apply_spans},
    };

    fn vault_with_secret(secret: &str) -> CredentialVault {
        let v = CredentialVault::new();
        v.register(secret).unwrap();
        v
    }

    #[tokio::test]
    async fn request_redact_response_restore() {
        let vault = vault_with_secret("my-secret-001");
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = r#"{"pwd":"my-secret-001","phone":"13812345678"}"#;
        let redacted = scope.redact_request(&vault, &detector, req).await;
        assert!(!redacted.contains("my-secret-001"), "{redacted}");
        assert!(!redacted.contains("13812345678"), "{redacted}");
        assert!(redacted.contains("__VG_CRED_"), "{redacted}");
        assert!(redacted.contains("__PII_"), "{redacted}");
        // JSON 语义等价：仍可解析，键名层级不变。
        let v: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert!(v.get("pwd").is_some() && v.get("phone").is_some());
        let restored = scope.restore_response(&vault, &redacted);
        assert!(restored.contains("my-secret-001"), "{restored}");
        assert!(restored.contains("13812345678"), "{restored}");
    }

    #[tokio::test]
    async fn response_new_pii_not_restored() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        // 请求期未注册的新 PII：响应侧以新占位符呈现。
        let resp = scope
            .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
            .await;
        assert!(!resp.contains("8.8.8.8"), "{resp}");
        assert!(resp.contains("__PII_"), "{resp}");
        // 请求还原表不含该 token：restore 原样保留。
        let again = scope.restore_response(&vault, &resp);
        assert!(again.contains("__PII_"), "{again}");
    }

    #[tokio::test]
    async fn same_secret_reuse_single_register_rebuild_consistent() {
        let vault = vault_with_secret("cache-secret-xyz");
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = r#"{"a":"cache-secret-xyz","b":"cache-secret-xyz"}"#;
        let once = scope.redact_request(&vault, &detector, req).await;
        let twice = scope.redact_request(&vault, &detector, req).await;
        assert_eq!(once, twice, "同秘密重复脱敏须复用一致");
        assert_eq!(vault.len(), 1, "同一秘密只注册一次");
        // 重建一致：还原后结构与原文一致。
        let rebuilt = scope.restore_response(&vault, &once);
        let v_orig: serde_json::Value = serde_json::from_str(req).unwrap();
        let v_back: serde_json::Value = serde_json::from_str(&rebuilt).unwrap();
        assert_eq!(v_orig, v_back);
    }

    #[tokio::test]
    async fn cross_request_pii_not_restorable() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let a = Scope::new();
        let b = Scope::new();
        let redacted = a
            .redact_request(&vault, &detector, "电话 13812345678")
            .await;
        assert!(redacted.contains("__PII_"));
        // B 持有 A 的占位符：还原失败并原样保留。
        let restored_by_b = b.restore_response(&vault, &redacted);
        assert!(restored_by_b.contains("__PII_"), "{restored_by_b}");
        assert!(!restored_by_b.contains("13812345678"));
    }

    #[tokio::test]
    async fn nested_tool_calls_roundtrip() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = r#"{"tool_calls":[{"name":"login","arguments":"{\"user\":\"admin\",\"key\":\"p@ss\\\"quote\",\"code\":\"\\u0031\"}"}]}"#;
        let redacted = scope.redact_request(&vault, &detector, req).await;
        // 无 PII/凭据命中时结构原样（roundtrip 保证可解析）。
        let v: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        let args: serde_json::Value =
            serde_json::from_str(v["tool_calls"][0]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["key"], "p@ss\"quote");
        assert_eq!(args["code"], "1");
    }

    #[tokio::test]
    async fn nonstream_and_stream_tail_partials_cleaned() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        // 残缺前缀在出口被清理，不泄漏半截占位符。
        let dirty = "正文 __VG_CRED_000 与 __PII_2_ab 结尾";
        let cleaned = scope.redact_request_plain(&vault, &detector, dirty).await;
        assert!(!cleaned.contains("__VG_CRED_000"), "{cleaned}");
        assert!(!cleaned.contains("__PII_2_ab"), "{cleaned}");
        let restored = scope.restore_response(&vault, "ok __VG_CRED_12");
        assert!(!restored.contains("__VG_CRED_12"), "{restored}");
    }

    #[tokio::test]
    async fn response_side_disabled_passes_through() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::with_opts(false, false);
        let resp = scope
            .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
            .await;
        assert!(resp.contains("8.8.8.8"), "{resp}");
        assert!(!resp.contains("__PII_"), "{resp}");
        let open = Scope::with_opts(true, false);
        let masked = open
            .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
            .await;
        assert!(!masked.contains("8.8.8.8"), "{masked}");
    }

    #[test]
    fn fuzzy_restore_by_sequence_lookup() {
        let vault = CredentialVault::new();
        let plain = "13812345678";
        let exact = Scope::with_opts(true, false);
        let token = exact.pii_scope().register(plain, false).unwrap();
        let seq: usize = token
            .strip_prefix("__PII_")
            .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
            .flatten()
            .expect("token 恒带序号");
        let fuzzy_tok = format!("__PII_{seq}_zzzz__");
        // 精确模式保留宽松形态。
        assert!(
            exact
                .restore_response(&vault, &format!("回拨 {fuzzy_tok}"))
                .contains(&fuzzy_tok)
        );
        // 宽松模式按序号还原明文。
        let scope2 = Scope::with_opts(true, true);
        let token2 = scope2.pii_scope().register(plain, false).unwrap();
        let seq2: usize = token2
            .strip_prefix("__PII_")
            .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
            .flatten()
            .unwrap();
        let restored = scope2.restore_response(&vault, &format!("回拨 __PII_{seq2}_zzzz__"));
        assert!(restored.contains(plain), "{restored}");
        assert!(!restored.contains("__PII_"), "{restored}");
    }

    #[test]
    fn strip_partial_and_token_fn_semantics() {
        let vault = CredentialVault::new();
        assert_eq!(strip_partials("a __VG_CRED_00 b"), "a  b");
        assert_eq!(strip_partials("a __PII_3_ab b"), "a  b");
        assert_eq!(strip_token_forms(&vault, "x __VG_CRED_123456__ y"), "x  y");
        // PII 完整形态保留（响应期新 token 语义）。
        assert!(strip_token_forms(&vault, "x __PII_1_ab12cd34__ y").contains("__PII_1_ab12cd34__"));
    }

    #[tokio::test]
    async fn multiline_faithful_roundtrip_bytes_identical() {
        let vault = vault_with_secret("my-secret-001");
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = "第一行 电话 13812345678 📞\n第二行 密钥 my-secret-001 ✅\n第三行 纯文本无敏感";
        let redacted = scope.redact_request_plain(&vault, &detector, req).await;
        assert!(!redacted.contains("13812345678"), "{redacted}");
        assert!(!redacted.contains("my-secret-001"), "{redacted}");
        assert!(redacted.contains("第三行 纯文本无敏感"), "{redacted}");
        let restored = scope.restore_response(&vault, &redacted);
        assert_eq!(restored, req, "往返须字节一致");
    }

    #[tokio::test]
    async fn restore_spans_skip_prevents_remask() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let redacted = scope
            .redact_request(&vault, &detector, r#"{"phone":"13812345678"}"#)
            .await;
        assert!(redacted.contains("__PII_"), "{redacted}");
        let (restored, spans) = scope.restore_response_with_spans(&vault, &redacted);
        assert!(restored.contains("13812345678"), "{restored}");
        assert!(!spans.is_empty());
        assert!(
            spans
                .iter()
                .any(|(s, e)| &restored[*s..*e] == "13812345678"),
            "{spans:?}"
        );
        // 带 skip：还原明文保持明文。
        let kept = scope
            .redact_response_new_pii_with_skip(&vault, &detector, &restored, &spans)
            .await;
        assert!(kept.contains("13812345678"), "{kept}");
        // 对照（不带 skip）：同一明文被套上响应 token，证明 skip 生效。
        let masked = scope
            .redact_response_new_pii(&vault, &detector, &restored)
            .await;
        assert!(!masked.contains("13812345678"), "{masked}");
        assert!(masked.contains("__PII_"), "{masked}");
    }

    #[test]
    fn credential_restore_spans_cover_plaintext() {
        let vault = CredentialVault::new();
        vault.register("my-secret-001").expect("注册恒成功");
        let scope = Scope::new();
        let masked = redact_with_map("密码 my-secret-001 结束", &vault.snapshot_p2t());
        assert!(!masked.contains("my-secret-001"), "{masked}");
        let (restored, spans) = scope.restore_response_with_spans(&vault, &masked);
        assert_eq!(restored, "密码 my-secret-001 结束");
        assert_eq!(spans.len(), 1);
        assert_eq!(&restored[spans[0].0..spans[0].1], "my-secret-001");
        // 未知 token 不产生 span。
        let (unchanged, empty) = scope.restore_response_with_spans(&vault, "纯文本无 token");
        assert_eq!(unchanged, "纯文本无 token");
        assert!(empty.is_empty());
    }

    #[test]
    fn span_apply_dedup_semantics() {
        let out = apply_spans(
            "hello world",
            &[(6, 11, "W".to_string()), (6, 11, "W".to_string())],
            true,
        );
        assert_eq!(out, "hello W");
    }

    #[test]
    fn restore_idempotent_unknown_passthrough() {
        let vault = vault_with_secret("my-secret-001");
        let scope = Scope::new();
        let tok = scope.pii_scope().register("13812345678", false).unwrap();
        let mixed = format!("回拨 {tok} 与 __PII_9_ab12cd34__ 及 my-secret-001");
        let once = scope.restore_response(&vault, &mixed);
        assert!(once.contains("13812345678"), "{once}");
        assert!(once.contains("__PII_9_ab12cd34__"), "{once}");
        assert!(once.contains("my-secret-001"), "明文直通不改写: {once}");
        let twice = scope.restore_response(&vault, &once);
        assert_eq!(twice, once, "二次还原须与一次一致");
    }

    #[tokio::test]
    async fn dict_5000_no_combined_regex_blowup_time_anchor() {
        let detector = PiiDetector::new();
        let dict: Vec<(String, String)> = (0..5000)
            .map(|i| (format!("合成姓名{i:05}号"), "name".to_string()))
            .collect();
        detector.load_dict(&dict);
        let vault = CredentialVault::new();
        let scope = Scope::new();
        let text = "正文含 合成姓名01234号 ok 与其余文字混合".to_string();
        let start = std::time::Instant::now();
        let out = scope.redact_request(&vault, &detector, &text).await;
        let elapsed = start.elapsed();
        assert!(!out.contains("合成姓名01234号"), "{out}");
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "5000 字典单次扫描须远低于宽松上界（防 13.8ms 爆炸回归），实测 {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn incremental_scan_time_anchor_loose_bound() {
        let vault = vault_with_secret("anchor-secret-007");
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let start = std::time::Instant::now();
        for i in 0..100 {
            let text = format!("{{\"k{i}\":\"v{i} anchor-secret-007 13812345678\"}}");
            let out = scope.redact_request(&vault, &detector, &text).await;
            assert!(!out.contains("anchor-secret-007"), "{out}");
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "100 次增量扫描须远低于宽松上界，实测 {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn scope_request_isolation_concurrent_invisible() {
        let detector = std::sync::Arc::new(PiiDetector::new());
        let mut handles = Vec::new();
        for i in 0..4 {
            let d = std::sync::Arc::clone(&detector);
            handles.push(tokio::spawn(async move {
                let vault = CredentialVault::new();
                let secret = format!("隔离密钥-{i:02}");
                vault.register(&secret).unwrap();
                let scope = Scope::new();
                let text = format!("{{\"s\":\"{secret}\"}}");
                scope.redact_request(&vault, &d, &text).await
            }));
        }
        let mut outs = Vec::new();
        for h in handles {
            outs.push(h.await.expect("隔离任务不得失败"));
        }
        for (i, out) in outs.iter().enumerate() {
            for j in 0..4 {
                assert!(
                    !out.contains(&format!("隔离密钥-{j:02}")),
                    "scope{i} 不得透出任何明文密钥（含自身注册前形态）: {out}"
                );
            }
        }
    }

    #[tokio::test]
    async fn t12_scope_registration_isolated_across_tasks() {
        let vault = std::sync::Arc::new(CredentialVault::new());
        let detector = std::sync::Arc::new(PiiDetector::new());
        let a = tokio::spawn({
            let (vault, detector) = (vault.clone(), detector.clone());
            async move {
                let scope = Scope::new();
                scope
                    .redact_request(&vault, &detector, "号码 13800138000 结束")
                    .await
            }
        });
        let b = tokio::spawn({
            let (vault, detector) = (vault.clone(), detector.clone());
            async move {
                let scope = Scope::new();
                scope
                    .redact_request(&vault, &detector, "号码 13800138000 结束")
                    .await
            }
        });
        let (out_a, out_b) = tokio::join!(a, b);
        let (out_a, out_b) = (out_a.expect("任务 A 须成功"), out_b.expect("任务 B 须成功"));
        assert!(out_a.contains("__PII_"), "A 须脱敏");
        assert!(out_b.contains("__PII_"), "B 须脱敏");
        assert_ne!(out_a, out_b, "独立 Scope 的 rand8 须不同（请求隔离）");
    }

    #[test]
    fn t12_restore_only_own_scope_tokens() {
        let vault = CredentialVault::new();
        let scope_a = Scope::new();
        let scope_b = Scope::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("单线程运行时须可用");
        let out_a = rt.block_on(scope_a.redact_request(
            &vault,
            &PiiDetector::new(),
            "号码 13800138000 结束",
        ));
        let out_b = rt.block_on(scope_b.redact_request(
            &vault,
            &PiiDetector::new(),
            "号码 13800138000 结束",
        ));
        assert_ne!(out_a, out_b);
        assert!(scope_a.restore_response(&vault, &out_b).contains("__PII_"));
        assert!(scope_b.restore_response(&vault, &out_a).contains("__PII_"));
        assert!(
            scope_a
                .restore_response(&vault, &out_a)
                .contains("13800138000")
        );
    }
}
