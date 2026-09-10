#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../sample.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "sample.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "sample/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
}

use {
    super::{
        super::{
            store::{ensure_tables, persist_sample_batch},
            summarize::test_support::tmp_db,
        },
        *,
    },
    crate::fs_perm::open_wal,
};

#[test]
fn pii_sampling_disabled_counts_only() {
    let cfg = PiiSamplerConfig::for_test(false, true, None);
    let s = PiiValueSampler::new(cfg, tmp_db("pii-off"));
    assert!(s.sample("phone", "13812345678", true, "").is_none());
    let (sampled, disabled, _) = s.stats();
    assert_eq!((sampled, disabled), (0, 1));
    assert!(s.top_n(10).is_empty());
}

#[test]
fn pii_sampling_enabled_masks_top_n_with_hmac() {
    let cfg = PiiSamplerConfig::for_test(true, false, Some("test-hmac-key-0123456789".to_string()));
    let s = PiiValueSampler::new(cfg, tmp_db("pii-on"));
    // 非 chat 不触发。
    assert!(s.sample("phone", "13812345678", false, "").is_none());
    let (_, _, non_chat) = s.stats();
    assert_eq!(non_chat, 1);
    let (mask, hash) = s.sample("phone", "13812345678", true, "").unwrap();
    // 掩码当场生成，明文不出作用域：mask/hash 均不含明文。
    assert!(!mask.contains("13812345678") && !hash.contains("13812345678"));
    assert!(mask.starts_with('1') && mask.ends_with('8') && mask.contains("***"));
    // HMAC 口径可复算（16hex：完整 HMAC-SHA256 hex 前 16 字符）。
    use hmac::{KeyInit as _, Mac as _};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test-hmac-key-0123456789").unwrap();
    mac.update(b"13812345678");
    let full = hex::encode(mac.finalize().into_bytes());
    assert_eq!(hash, full[..16]);
    // TopN hover 展示掩码。
    s.sample("phone", "13812345678", true, "");
    let top = s.top_n(5);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].hits, 2);
    assert!(!top[0].mask.contains("13812345678"));
}

#[test]
fn sample_mask_varies_by_kind() {
    use super::PiiValueSampler as S;
    // 对标原仓 `pii_value_samples_test.py::TestMaskPiiValue` 向量。
    assert_eq!(S::sample_mask("phone", "13812348000"), "138****8000");
    assert_eq!(
        S::sample_mask("phone", "__PII_82_8f6a798b__"),
        "__P****8b__"
    );
    assert_eq!(S::sample_mask("email", "user@example.com"), "***@***.com");
    assert_eq!(S::sample_mask("email", "user@domain"), "***@***");
    assert_eq!(
        S::sample_mask("bank", "6225880123456789"),
        "**** **** **** 6789"
    );
    assert_eq!(
        S::sample_mask("bank_card", "6225880123456789"),
        "**** **** **** 6789"
    );
    assert_eq!(S::sample_mask("ipv4", "192.168.1.10"), "192.168.**.**");
    assert!(S::sample_mask("ipv6", "2001:db8::1").contains("****"));
    assert_eq!(S::sample_mask("api_key", "abcd1234"), "abcd****1234");
    assert_eq!(S::sample_mask("api_key", "abc12"), "a****2");
    assert_eq!(S::sample_mask("other", "hello_world"), "hel****rld");
    assert_eq!(S::sample_mask("other", ""), "***");
    // 同一明文不同 kind 掩码分叉（M1 核心断言）。
    assert_ne!(
        S::sample_mask("phone", "13812348000"),
        S::sample_mask("other", "13812348000")
    );
}

#[test]
fn pii_sampling_without_hmac_falls_back_to_sha256() {
    let cfg = PiiSamplerConfig::for_test(true, false, None);
    let s = PiiValueSampler::new(cfg, tmp_db("pii-degrade"));
    let (_, hash) = s.sample("email", "a@b.com", true, "").unwrap();
    let full = crate::auth::sha256_hex(b"a@b.com");
    assert_eq!(hash, full[..16]);
}

#[test]
fn hash_value_is_16hex_keyed_and_degraded() {
    let is_hex16 = |h: &str| h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit());
    // 无 key 退化 SHA256[:16]。
    let plain = PiiValueSampler::new(
        PiiSamplerConfig::for_test(true, false, None),
        tmp_db("hash-plain"),
    );
    let h_plain = plain.hash_value("__PII_7_12345678__");
    assert!(is_hex16(&h_plain));
    // 有 key 时 HMAC[:16]，与无盐不同且同 key 同值稳定。
    let keyed = PiiValueSampler::new(
        PiiSamplerConfig::for_test(true, false, Some("test-salt-123".to_string())),
        tmp_db("hash-hmac"),
    );
    let h_hmac = keyed.hash_value("__PII_7_12345678__");
    assert!(is_hex16(&h_hmac));
    assert_ne!(h_hmac, h_plain);
    assert_eq!(keyed.hash_value("__PII_7_12345678__"), h_hmac);
}

#[test]
fn mask_truncates_at_64_chars_utf8_safe() {
    use super::PiiValueSampler as S;
    // 100 字符 email：掩码恒 `<= 64` 字符（M3 场景）。
    let long_email = format!("{}@b.com", "a".repeat(100));
    let masked = S::sample_mask("email", &long_email);
    assert!(masked.chars().count() <= 64, "{masked}");
    // CJK 长值：按字符边界截断，不断裂 `char`。
    let masked = S::sample_mask("other", &"中".repeat(100));
    assert!(masked.chars().count() <= 64);
    assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
    // 短掩码原样保留。
    assert_eq!(S::sample_mask("phone", "13812348000"), "138****8000");
}

#[test]
fn empty_value_samples_as_stars_and_counts() {
    // M4 场景：空串采样为 `***` 并计数，永不跳过为 `None`。
    let s = PiiValueSampler::new(
        PiiSamplerConfig::for_test(true, false, None),
        tmp_db("empty-sample"),
    );
    let (mask, hash) = s.sample("other", "", true, "").unwrap();
    assert_eq!(mask, "***");
    assert_eq!(hash.len(), 16);
    let (sampled, ..) = s.stats();
    assert_eq!(sampled, 1);
    assert_eq!(s.top_n(5).len(), 1);
}

#[test]
fn top_n_orders_by_hits_and_truncates() {
    // Top5 口径：6 个不同值按频次 6..1 采样，Top3 按 hits 降序且截断。
    let s = PiiValueSampler::new(
        PiiSamplerConfig::for_test(true, false, None),
        tmp_db("topn"),
    );
    let values = [
        "13800000001",
        "13800000002",
        "13800000003",
        "13800000004",
        "13800000005",
        "13800000006",
    ];
    for (i, v) in values.iter().enumerate() {
        for _ in 0..(6 - i) {
            s.sample("phone", v, true, "").unwrap();
        }
    }
    let top3 = s.top_n(3);
    assert_eq!(top3.len(), 3);
    assert_eq!((top3[0].hits, top3[1].hits, top3[2].hits), (6, 5, 4));
    assert_eq!(s.top_n(10).len(), 6);
    // 非对话不采样且计入 `skipped_non_chat`。
    assert!(s.sample("phone", values[0], false, "").is_none());
    let (.., non_chat) = s.stats();
    assert_eq!(non_chat, 1);
}

#[test]
fn concurrent_sampling_is_isolated_and_lossless() {
    // 并发隔离（对标原仓 `test_concurrency_isolation`）：8 线程各采 25 个不同值，
    // 计数 200 且条目无丢失无合并。
    use std::sync::Arc;
    let s = Arc::new(PiiValueSampler::new(
        PiiSamplerConfig::for_test(true, false, None),
        tmp_db("concurrent"),
    ));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                for i in 0..25 {
                    let v = format!("139{t:02}{i:04}");
                    s.sample("phone", &v, true, "").unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("采样线程恒成功");
    }
    let (sampled, ..) = s.stats();
    assert_eq!(sampled, 200);
    assert_eq!(s.top_n(500).len(), 200);
}

#[test]
fn same_plaintext_different_kinds_do_not_merge() {
    // M5 场景：同明文以 phone 与 bank 各采样一次 → 两条独立条目，hits 互不干扰。
    let s = PiiValueSampler::new(
        PiiSamplerConfig::for_test(true, false, None),
        tmp_db("cross-kind"),
    );
    let value = "13812348000";
    let (_, h_phone) = s.sample("phone", value, true, "").unwrap();
    let (_, h_bank) = s.sample("bank", value, true, "").unwrap();
    assert_eq!(h_phone, h_bank, "同明文 hash 相同，去重须靠 kind 区分");
    s.sample("phone", value, true, "");
    let top = s.top_n(5);
    assert_eq!(top.len(), 2);
    let phone = top.iter().find(|v| v.kind == "phone").unwrap();
    let bank = top.iter().find(|v| v.kind == "bank").unwrap();
    assert_eq!((phone.hits, bank.hits), (2, 1));
}

#[test]
fn same_value_cross_upstream_does_not_merge() {
    // 同 kind 同明文分属两上游 → 两条独立条目，hits 互不干扰。
    let s = PiiValueSampler::new(
        PiiSamplerConfig::for_test(true, false, None),
        tmp_db("cross-upstream"),
    );
    let value = "13812348000";
    let (_, h_a) = s.sample("phone", value, true, "https://a.example").unwrap();
    let (_, h_b) = s.sample("phone", value, true, "https://b.example").unwrap();
    assert_eq!(h_a, h_b, "同明文 hash 相同，去重须靠 upstream 区分");
    s.sample("phone", value, true, "https://a.example");
    let top = s.top_n(5);
    assert_eq!(top.len(), 2);
    let a = top
        .iter()
        .find(|v| v.upstream == "https://a.example")
        .unwrap();
    let b = top
        .iter()
        .find(|v| v.upstream == "https://b.example")
        .unwrap();
    assert_eq!((a.hits, b.hits), (2, 1));
}

#[test]
fn persist_upsert_keys_on_day_upstream_kind_hash() {
    // SQL 层：同 hash 不同 kind 落两行；同四元组重复落库合并 hits。
    let db = tmp_db("composite-upsert");
    let _ = std::fs::remove_file(&db);
    let row = |kind: &str| SampleRow {
        day: "2026-09-09".to_string(),
        upstream: String::new(),
        hash: "0123456789abcdef".to_string(),
        kind: kind.to_string(),
        mask: "***".to_string(),
        seen: 1,
    };
    persist_sample_batch(&db, &[row("phone"), row("bank"), row("phone")]).unwrap();
    let conn = open_wal(&db).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 2);
    let hits: i64 = conn
        .query_row(
            "SELECT hits FROM pii_value_samples WHERE day='2026-09-09' AND kind='phone'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hits, 2);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn legacy_single_key_table_rebuilds_to_composite() {
    // 迁移场景：存量单键旧表在 ensure_tables 后重建为复合键表，旧行清理。
    let db = tmp_db("legacy-migrate");
    let _ = std::fs::remove_file(&db);
    let conn = open_wal(&db).unwrap();
    conn.execute_batch(
        "CREATE TABLE pii_value_samples(hash TEXT PRIMARY KEY, kind TEXT NOT NULL,\
             mask TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 1,\
             first_seen INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0);\
             INSERT INTO pii_value_samples(hash,kind,mask,hits,first_seen,last_seen)\
             VALUES ('aa','phone','***',1,0,0);",
    )
    .unwrap();
    drop(conn);
    let conn = open_wal(&db).unwrap();
    ensure_tables(&conn).unwrap();
    let has_day: bool = conn
        .prepare("PRAGMA table_info(pii_value_samples)")
        .map(|mut stmt| {
            stmt.query_map([], |row| row.get::<_, String>(1))
                .map(|rows| rows.flatten().any(|name| name == "day"))
                .unwrap_or(false)
        })
        .unwrap_or(false);
    assert!(has_day);
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    drop(conn);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn pii_value_mask_merge_and_count_query() {
    let cfg = PiiSamplerConfig::for_test(true, false, None);
    let s = PiiValueSampler::new(cfg, tmp_db("pii-query"));
    let (m1, h1) = s.sample("phone", "13812345678", true, "").unwrap();
    assert!(m1.starts_with('1') && m1.ends_with('8'));
    s.sample("phone", "13812345678", true, "");
    s.sample("email", "a@b.com", true, "");
    let top = s.top_n(5);
    assert_eq!(top.iter().find(|v| v.hash == h1).unwrap().hits, 2);
    assert_eq!(top.len(), 2);
    let (sampled, disabled, non_chat) = s.stats();
    assert_eq!((sampled, disabled, non_chat), (3, 0, 0));
    assert!(s.sample("phone", "13812345678", false, "").is_none());
    assert_eq!(PiiValueSampler::sample_mask("other", "ab"), "a****b");
}

#[tokio::test(flavor = "current_thread")]
async fn sampling_background_flush_persists() {
    let db = tmp_db("pii-flush");
    let _ = std::fs::remove_file(&db);
    let cfg = PiiSamplerConfig::for_test(true, true, None);
    let s = PiiValueSampler::new(cfg, db.clone());
    let (mask, hash) = s.sample("phone", "13812345678", true, "").unwrap();
    assert!(mask.contains("***"));
    // 后台驱动批量落盘：轮询等行落库（让出后驱动运行，2s 内必达）。
    let mut rows = 0;
    for _ in 0..200 {
        if let Ok(conn) = open_wal(&db) {
            rows = conn
                .query_row(
                    "SELECT COUNT(*) FROM pii_value_samples WHERE hash=?1",
                    [hash.clone()],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0);
            if rows >= 1 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows, 1, "后台 flush 须把采样行写入 pii_value_samples");
    assert_eq!(s.dropped_total(), 0);
    let _ = std::fs::remove_file(&db);
}

#[tokio::test(flavor = "current_thread")]
async fn sampling_full_queue_drops_oldest_queryable() {
    let db = tmp_db("pii-full");
    let _ = std::fs::remove_file(&db);
    let cfg = PiiSamplerConfig::for_test(true, true, None);
    let s = PiiValueSampler::new(cfg, db.clone());
    // 同步紧循环无让出点：单线程运行时驱动不得交错，512 缓冲 + 10 滞后精确可复算。
    for i in 0..(SAMPLE_QUEUE_CAP + 10) {
        let v = format!("1380000{i:04}");
        let _ = s.sample("phone", &v, true, "");
    }
    assert_eq!(s.pending_len(), SAMPLE_QUEUE_CAP);
    // 让出后驱动排空：滞后 10 计 dropped，512 行落库。
    for _ in 0..200 {
        if s.dropped_total() >= 10 && s.pending_len() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(s.dropped_total(), 10, "满队列须丢最老 10 行并计数");
    assert_eq!(s.pending_len(), 0);
    // 通道见底不等于落库完成（`spawn_blocking` 批量写仍在途）：轮询等行落库（2s 内必达）。
    let mut rows = 0;
    for _ in 0..200 {
        if let Ok(conn) = open_wal(&db) {
            rows = conn
                .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap_or(0);
            if rows >= SAMPLE_QUEUE_CAP as i64 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows, SAMPLE_QUEUE_CAP as i64);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn sampling_config_from_struct_not_env() {
    use std::collections::HashMap;
    let base: HashMap<String, String> = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
    ]);
    let cfg = PiiSamplerConfig::from_config(&crate::config::Config::load_from(&base).unwrap());
    assert!(!cfg.enabled && cfg.persist && cfg.hmac_key.is_none());
    let mut env = base;
    env.insert("PII_VALUE_SAMPLE_ENABLED".to_string(), "1".to_string());
    env.insert("PII_VALUE_SAMPLE_PERSIST".to_string(), "0".to_string());
    env.insert(
        "PII_VALUE_SAMPLE_HMAC_KEY".to_string(),
        "k-0123456789".to_string(),
    );
    let cfg = PiiSamplerConfig::from_config(&crate::config::Config::load_from(&env).unwrap());
    assert!(cfg.enabled && !cfg.persist);
    assert_eq!(cfg.hmac_key.as_deref(), Some("k-0123456789"));
}

#[test]
fn unsalted_sampling_warns_predicate() {
    assert!(PiiSamplerConfig::for_test(true, true, None).needs_hmac_warn());
    assert!(PiiSamplerConfig::for_test(true, true, Some(String::new())).needs_hmac_warn());
    assert!(!PiiSamplerConfig::for_test(true, true, Some("k".to_string())).needs_hmac_warn());
    assert!(!PiiSamplerConfig::for_test(false, true, None).needs_hmac_warn());
    assert!(!PiiSamplerConfig::for_test(false, false, None).needs_hmac_warn());
}

#[test]
fn sampling_master_switch_off_means_zero_persist() {
    let cfg = PiiSamplerConfig::for_test(false, true, None);
    let s = PiiValueSampler::new(cfg, tmp_db("sample-off"));
    assert!(s.sample("phone", "13812345678", true, "").is_none());
    assert!(s.sample("phone", "13812345678", true, "").is_none());
    let (sampled, disabled, _) = s.stats();
    assert_eq!((sampled, disabled), (0, 2), "关闭时只记跳过不采样");
    assert!(s.top_n(5).is_empty(), "零落盘：无样本可查");
}
