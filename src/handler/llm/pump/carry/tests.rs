//! 跨帧占位符缝合 carry 单测（自 `carry.rs` 拆出；测试名与断言不变）。

use super::*;

fn v(frame: &str) -> Value { serde_json::from_str(frame).expect("测试帧须为合法 JSON") }

fn prep(c: &mut TokenCarry, frame: &str) -> String {
    let parsed = v(frame);
    c.prepare(frame, &parsed).into_owned()
}

fn prep_term(c: &mut TokenCarry, frame: &str) -> String {
    let parsed = v(frame);
    c.prepare_terminal(frame, &parsed).into_owned()
}

/// 路径末位键名（释放载体判定用）。
fn last_key(path: &[Seg]) -> Option<&str> {
    path.iter().rev().find_map(|s| match s {
        Seg::Key(k) => Some(k.as_str()),
        Seg::Idx(_) => None,
    })
}

/// 逐帧处理 `content` 分段，返回（下游拼接文本，是否仍持有残段）。
fn simulate_segments(segments: &[&str]) -> (String, bool) {
    let mut c = TokenCarry::new();
    let mut text = String::new();
    for seg in segments {
        let frame = format!(r#"{{"content":"{seg}"}}"#);
        let parsed = v(&frame);
        let out = c.prepare(&frame, &parsed).into_owned();
        let pv: Value = serde_json::from_str(&out).expect("每帧须为合法 JSON");
        text.push_str(pv["content"].as_str().unwrap_or(""));
    }
    (text, c.has_pending())
}

#[test]
fn absorb_then_stitch_cred_across_valid_json_frames() {
    let mut c = TokenCarry::new();
    let f1 = prep(&mut c, r#"{"choices":[{"delta":{"content":"__CRE"}}]}"#);
    assert_eq!(f1, r#"{"choices":[{"delta":{"content":""}}]}"#);
    assert_eq!(
        c.pending_literal_for(&[
            Seg::Key("choices".into()),
            Seg::Idx("#0".into()),
            Seg::Key("delta".into()),
            Seg::Key("content".into())
        ]),
        Some("__CRE")
    );
    let f2 = prep(
        &mut c,
        r#"{"choices":[{"delta":{"content":"D_000001__"}}]}"#,
    );
    assert_eq!(
        f2, r#"{"choices":[{"delta":{"content":"__CRED_000001__"}}]}"#,
        "续段须与 carry 拼回完整 token"
    );
    assert!(!c.has_pending(), "成功缝合后 carry 须清空");
}

#[test]
fn absorb_ignores_complete_token_and_mid_value_partial() {
    let mut c = TokenCarry::new();
    let full = prep(&mut c, r#"{"text":"__CRED_000001__"}"#);
    assert_eq!(full, r#"{"text":"__CRED_000001__"}"#);
    assert!(!c.has_pending(), "完整 token 不 absorb");
    let mid = prep(&mut c, r#"{"text":"x __CRE y"}"#);
    assert_eq!(mid, r#"{"text":"x __CRE y"}"#);
    assert!(!c.has_pending(), "正文中间残缺不 absorb");
}

#[test]
fn pii_partial_absorbed_and_stitched() {
    let mut c = TokenCarry::new();
    let f1 = prep(&mut c, r#"{"content":"__PII_1_ab"}"#);
    assert_eq!(f1, r#"{"content":""}"#);
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__PII_1_ab")
    );
    let f2 = prep(&mut c, r#"{"content":"12cd34__"}"#);
    assert_eq!(f2, r#"{"content":"__PII_1_ab12cd34__"}"#);
    assert!(!c.has_pending());
}

#[test]
fn repro_responses_tail_prefix5_absorbed_and_stitched() {
    // 复刻实测 Responses 帧序列：帧 A 摘入裸 `__PII` 建立持有，帧 B 既补全该
    // 持有（touched）又在尾部挂新残缺 `__PII_`——尾部须被摘入新持有、绝不
    // 随补全结果泄漏；帧 C 续段拼回完整 token。
    let mut c = TokenCarry::new();
    let mk = |delta: &str| {
        format!(
            r#"{{"type":"response.output_text.delta","sequence_number":7,"output_index":1,"content_index":0,"item_id":"msg_x","delta":"{delta}","logprobs":[]}}"#
        )
    };
    let o0 = prep(&mut c, &mk("我的手机号是__PII"));
    assert_eq!(
        serde_json::from_str::<Value>(&o0).unwrap()["delta"],
        "我的手机号是"
    );
    let email = "__PII_2_c25465ef__";
    let o1 = prep(
        &mut c,
        &mk(&format!("_1_09526f8b__，邮箱是{}", &email[..6])),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&o1).unwrap()["delta"],
        "__PII_1_09526f8b__，邮箱是",
        "补全既有持有后，帧尾新残缺 `__PII_` 须被摘入新持有"
    );
    let o2 = prep(&mut c, &mk(&format!("{}，密钥是", &email[6..])));
    assert_eq!(
        serde_json::from_str::<Value>(&o2).unwrap()["delta"],
        "__PII_2_c25465ef__，密钥是",
        "续段须拼回完整 token"
    );
    assert!(!c.has_pending());
}

#[test]
fn no_emitted_frame_ends_with_partial_token_for_any_split() {
    // 参数化性质：任意切点下，经 stitch 补全既有持有的帧也不得残留帧尾半截
    // 前缀；完整 token 须在某一帧内拼回、无残留持有。
    let prior = "__PII_1_09526f8b__";
    let target = "__PII_2_c25465ef__";
    let mk = |delta: &str| {
        format!(
            r#"{{"type":"response.output_text.delta","output_index":1,"content_index":0,"item_id":"msg_x","delta":"{delta}","logprobs":[]}}"#
        )
    };
    for i in 1..=target.len() {
        let mut c = TokenCarry::new();
        let mut emitted = Vec::new();
        for delta in [
            format!("我的手机号是{}", &prior[..5]),
            format!("{}，邮箱是{}", &prior[5..], &target[..i]),
            format!("{}，尾", &target[i..]),
        ] {
            let out = prep(&mut c, &mk(&delta));
            let v: Value = serde_json::from_str(&out).unwrap();
            emitted.push(v["delta"].as_str().unwrap().to_string());
        }
        for value in &emitted {
            assert!(
                candidate_suffix_in(value).is_none(),
                "切点 {i} 泄漏帧尾半截前缀: {value:?}"
            );
        }
        assert_eq!(
            emitted.concat(),
            format!("我的手机号是{prior}，邮箱是{target}，尾"),
            "切点 {i} 须完整拼回 token"
        );
        assert!(!c.has_pending(), "切点 {i} 不得残留持有");
    }
}

#[test]
fn ascii_separated_tail_partial_absorbed_after_completed_token() {
    // 同帧先补全既有持有、再挂以 ASCII（`[A-Za-z0-9_]`）分隔的新残缺 `__PII_`：
    // 不得因整段含完整 token 而放弃吸收，须摘入新持有；任何已发帧不得残留帧尾半截。
    let mut c = TokenCarry::new();
    let o0 = prep(&mut c, r#"{"content":"__PII_1_aabb"}"#);
    assert_eq!(serde_json::from_str::<Value>(&o0).unwrap()["content"], "");
    let o1 = prep(&mut c, r#"{"content":"ccdd__word__PII_"}"#);
    let v1: Value = serde_json::from_str(&o1).unwrap();
    assert_eq!(
        v1["content"], "__PII_1_aabbccdd__word",
        "补全持有后的帧尾新残缺须被摘入持有（不得泄漏 `__PII_`）"
    );
    assert!(
        candidate_suffix_in(v1["content"].as_str().unwrap()).is_none(),
        "已发帧尾不得残留候选半截"
    );
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__PII_")
    );
    let o2 = prep(&mut c, r#"{"content":"2_c25465ef__"}"#);
    assert_eq!(
        serde_json::from_str::<Value>(&o2).unwrap()["content"],
        "__PII_2_c25465ef__"
    );
    assert!(!c.has_pending());
}

#[test]
fn adjacent_tail_partial_absorbed_after_completed_token() {
    // `__PII_1_aabbccdd____PII_`：完整 token 收尾 `__` 与新媒体前缀 `__PII_` 相邻合并为
    // `____PII_`——须自新前缀起摘入持有；完整 token 自身（含其收尾 `__`）不被误摘。
    let mut c = TokenCarry::new();
    let _ = prep(&mut c, r#"{"content":"__PII_1_aabb"}"#);
    let o1 = prep(&mut c, r#"{"content":"ccdd____PII_"}"#);
    assert_eq!(
        serde_json::from_str::<Value>(&o1).unwrap()["content"],
        "__PII_1_aabbccdd__",
        "完整 token 须原样保留、新媒体前缀须摘入持有"
    );
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__PII_")
    );
    let o2 = prep(&mut c, r#"{"content":"2_c25465ef__"}"#);
    assert_eq!(
        serde_json::from_str::<Value>(&o2).unwrap()["content"],
        "__PII_2_c25465ef__"
    );
    assert!(!c.has_pending());
}

#[test]
fn complete_token_suffix_still_not_absorbed() {
    // 反向护栏：run 内仅含完整 token（无其后新候选）时不得摘入任何残段
    //（含 token 自身收尾 `__`）。
    let mut c = TokenCarry::new();
    let frame = r#"{"content":"x__PII_1_ab12cd34__"}"#;
    let out = prep(&mut c, frame);
    assert_eq!(out, frame, "完整 token 及其中间 `_` 不得被摘入 carry");
    assert!(!c.has_pending());
}

#[test]
fn drain_returns_residual_payload() {
    let mut c = TokenCarry::new();
    let _ = prep(&mut c, r#"{"content":"prefix __CRE"}"#);
    assert_eq!(c.pending_count(), 1);
    let residuals = c.drain();
    assert_eq!(residuals.len(), 1);
    assert_eq!(residuals[0].literal, "__CRE");
    assert_eq!(last_key(&residuals[0].path), Some("content"));
    assert!(c.drain().is_empty(), "无 pending 须返回空");
}

#[test]
fn marker_prefix_runs_are_candidates() {
    for run in [
        "_", "__", "__P", "__PI", "__PII", "__PII_", "__PII_1", "__C", "__CR", "__CRE", "__CRED",
        "__CRED_0",
    ] {
        assert!(is_candidate_run(run), "`{run}` 须为候选");
    }
    for full in ["__CRED_000001__", "__PII_1_ab12cd34__"] {
        assert!(!is_candidate_run(full), "完整 token `{full}` 不得为候选");
    }
}

#[test]
fn non_candidate_runs_rejected() {
    let mut c = TokenCarry::new();
    for value in [
        "foo__bar",
        "snake_case_x",
        "__PIXEL",
        "__PII_DATA",
        "**__bold__**",
    ] {
        let frame = format!(r#"{{"content":"{value}"}}"#);
        let out = prep(&mut c, &frame);
        assert_eq!(out, frame, "非候选须逐字节透传: {value}");
        assert!(!c.has_pending(), "非候选不得持有: {value}");
    }
    let mid = prep(&mut c, r#"{"content":"x __CRE y"}"#);
    assert_eq!(mid, r#"{"content":"x __CRE y"}"#);
    assert!(!c.has_pending());
}

#[test]
fn bare_underscore_tail_candidate() {
    let mut c = TokenCarry::new();
    let f1 = prep(&mut c, r#"{"content":"我的手机号是__"}"#);
    assert_eq!(f1, r#"{"content":"我的手机号是"}"#);
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__")
    );
    let f2 = prep(&mut c, r#"{"content":"PII_1_ab12cd34__"}"#);
    assert_eq!(f2, r#"{"content":"__PII_1_ab12cd34__"}"#);
    assert!(!c.has_pending());
}

#[test]
fn non_candidate_tail_never_held_byte_conserved() {
    let mut c = TokenCarry::new();
    assert_eq!(
        prep(&mut c, r#"{"content":"foo__bar"}"#),
        r#"{"content":"foo__bar"}"#
    );
    assert!(!c.has_pending());
    assert_eq!(prep(&mut c, r#"{"content":"baz"}"#), r#"{"content":"baz"}"#);
}

#[test]
fn trailing_underscore_false_positive_released_byte_conserved() {
    let (text, pending) = simulate_segments(&["foo__", "bar"]);
    assert_eq!(text, "foo__bar");
    assert!(!pending);
    let (text2, pending2) = simulate_segments(&["snake_case_", "x"]);
    assert_eq!(text2, "snake_case_x");
    assert!(!pending2);
}

#[test]
fn marker_preceded_by_alnum_still_stitched() {
    let mut c = TokenCarry::new();
    let f1 = prep(&mut c, r#"{"content":"id__CRE"}"#);
    assert_eq!(f1, r#"{"content":"id"}"#);
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__CRE")
    );
    let f2 = prep(&mut c, r#"{"content":"D_000001__"}"#);
    assert_eq!(f2, r#"{"content":"__CRED_000001__"}"#);
    assert!(!c.has_pending());
}

#[test]
fn fail_open_release_into_same_path() {
    let mut c = TokenCarry::new();
    let f1 = prep(&mut c, r#"{"content":"foo __"}"#);
    assert_eq!(f1, r#"{"content":"foo "}"#);
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__")
    );
    let f2 = prep(&mut c, r#"{"content":"bar"}"#);
    assert_eq!(f2, r#"{"content":"__bar"}"#, "残段须前置回同路径值");
    assert!(!c.has_pending());
    assert!(
        serde_json::from_str::<Value>(&f2).is_ok(),
        "释放后须仍为合法 JSON"
    );
}

#[test]
fn fail_open_keeps_pending_when_same_path_absent() {
    // fail-open 收敛为「仅路径精确相等」：无同路径值时不回吐到其他字段，维持持有。
    let mut c = TokenCarry::new();
    let _ = prep(&mut c, r#"{"content":"tail __PI"}"#);
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__PI")
    );
    let f2 = prep(
        &mut c,
        r#"{"choices":[{"delta":{"reasoning":"x"}}],"index":0}"#,
    );
    assert!(
        f2.contains("\"reasoning\":\"x\""),
        "不得改写信封/异路径字段: {f2}"
    );
    assert!(c.has_pending(), "同路径缺席须维持持有");
}

#[test]
fn fail_open_release_skips_envelope_key() {
    let mut c = TokenCarry::new();
    let _ = prep(&mut c, r#"{"content":"tail __PI"}"#);
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__PI")
    );
    let f2 = prep(&mut c, r#"{"index":0,"delta":{},"finish_reason":"stop"}"#);
    assert_eq!(
        f2, r#"{"index":0,"delta":{},"finish_reason":"stop"}"#,
        "不得改写信封字段"
    );
    assert!(c.has_pending(), "无安全落点须维持持有");
}

#[test]
fn overlong_prefix_not_held() {
    let mut c = TokenCarry::new();
    let long = format!("__PII_1_{}", "a".repeat(60));
    assert!(long.len() > PENDING_MAX);
    let frame = format!(r#"{{"content":"{long}"}}"#);
    let out = prep(&mut c, &frame);
    assert_eq!(out, frame, "超长前缀须原样保留");
    assert!(!c.has_pending());
}

#[test]
fn byte_split_token_stitch_parameterized() {
    for token in ["__PII_1_09526f8b__", "__CRED_000001__"] {
        for i in 1..token.len() {
            let (head, tail) = token.split_at(i);
            let (text, pending) = simulate_segments(&[head, tail]);
            assert_eq!(text, token, "两分裂 {i} 须缝合完整 token: {token}");
            assert!(!pending);
        }
        for i in 1..token.len() {
            for j in (i + 1)..token.len() {
                let (head, rest) = token.split_at(i);
                let (mid, tail) = rest.split_at(j - i);
                let (text, pending) = simulate_segments(&[head, mid, tail]);
                assert_eq!(text, token, "三分裂 {i},{j} 须缝合完整 token: {token}");
                assert!(!pending);
            }
        }
        for split in [[2, 5, 8, token.len()], [1, 3, 9, token.len()]] {
            let a = token.split_at(split[0]);
            let b = a.1.split_at(split[1] - split[0]);
            let c = b.1.split_at(split[2] - split[1]);
            let segs = [a.0, b.0, c.0, c.1];
            let (text, pending) = simulate_segments(&segs);
            assert_eq!(text, token, "四分裂 {split:?} 须缝合完整 token: {token}");
            assert!(!pending);
        }
    }
}

#[test]
fn drain_strips_residual_and_clears() {
    let mut c = TokenCarry::new();
    let _ = prep(&mut c, r#"{"content":"prefix __CRE"}"#);
    assert_eq!(c.pending_count(), 1);
    let residuals = c.drain();
    assert_eq!(
        residuals.len(),
        1,
        "drain 须返回载荷（调用方决定释放/剥离）"
    );
    assert!(!c.has_pending(), "流末残余须清空");
}

#[test]
fn prepare_terminal_stitches_without_absorbing() {
    // 终止帧只补全既有 carry，SHALL NOT 从终止帧吸收新候选。
    let mut c = TokenCarry::new();
    let out = prep_term(
        &mut c,
        r#"{"response":{"output":[{"content":[{"type":"output_text","text":"tail__"}]}]}}"#,
    );
    assert!(
        out.contains("\"text\":\"tail__\""),
        "终止帧内容须逐字节透传: {out}"
    );
    assert!(!c.has_pending(), "终止帧不得建立新持有");
}

fn content_path(choice: &str) -> Vec<Seg> {
    vec![
        Seg::Key("choices".into()),
        Seg::Idx(format!("i={choice}")),
        Seg::Key("delta".into()),
        Seg::Key("content".into()),
    ]
}

fn reasoning_text_path(choice: &str) -> Vec<Seg> {
    vec![
        Seg::Key("choices".into()),
        Seg::Idx(format!("i={choice}")),
        Seg::Key("delta".into()),
        Seg::Key("reasoning_details".into()),
        Seg::Idx("i=0".into()),
        Seg::Key("text".into()),
    ]
}

fn tc_args_path(choice: &str, tc: &str) -> Vec<Seg> {
    vec![
        Seg::Key("choices".into()),
        Seg::Idx(format!("i={choice}")),
        Seg::Key("delta".into()),
        Seg::Key("tool_calls".into()),
        Seg::Idx(format!("i={tc}")),
        Seg::Key("function".into()),
        Seg::Key("arguments".into()),
    ]
}

fn tc_name_path(choice: &str, tc: &str) -> Vec<Seg> {
    vec![
        Seg::Key("choices".into()),
        Seg::Idx(format!("i={choice}")),
        Seg::Key("delta".into()),
        Seg::Key("tool_calls".into()),
        Seg::Idx(format!("i={tc}")),
        Seg::Key("function".into()),
        Seg::Key("name".into()),
    ]
}

#[test]
fn a4_duplicate_reasoning_fields_stitch_independently() {
    // 同帧 `delta.reasoning` + `delta.reasoning_details[0].text` 各半 token，
    // 下帧各自续写 → 两字段均缝合为完整 token（无 `__PII_N_hash` 残片）。
    let mut c = TokenCarry::new();
    let f1 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"reasoning":"__PII_1_ab","reasoning_details":[{"index":0,"text":"__PII_2_cd"}]}}]}"#,
    );
    assert_eq!(c.pending_count(), 2, "两重复字段须各自独立持有");
    let v1: Value = serde_json::from_str(&f1).unwrap();
    assert_eq!(v1["choices"][0]["delta"]["reasoning"], "");
    assert_eq!(
        v1["choices"][0]["delta"]["reasoning_details"][0]["text"],
        ""
    );
    let f2 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"reasoning":"12ef34__","reasoning_details":[{"index":0,"text":"56ab78__"}]}}]}"#,
    );
    let v2: Value = serde_json::from_str(&f2).unwrap();
    assert_eq!(v2["choices"][0]["delta"]["reasoning"], "__PII_1_ab12ef34__");
    assert_eq!(
        v2["choices"][0]["delta"]["reasoning_details"][0]["text"],
        "__PII_2_cd56ab78__"
    );
    assert!(!c.has_pending());
}

#[test]
fn complete_field_does_not_create_stale_pending() {
    // 仅一个重复字段被切开、另一字段本帧完整（完整 token）时不建立 stale 持有，
    // 下帧不被旧残段回吐/污染。
    let mut c = TokenCarry::new();
    let f1 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"reasoning":"__PII_1_ab12cd34__","reasoning_details":[{"index":0,"text":"__PII_2_cd"}]}}]}"#,
    );
    assert_eq!(c.pending_count(), 1, "完整 token 字段不得建立持有");
    assert_eq!(
        c.pending_literal_for(&reasoning_text_path("0")),
        Some("__PII_2_cd")
    );
    assert!(
        serde_json::from_str::<Value>(&f1).unwrap()["choices"][0]["delta"]["reasoning"]
            == "__PII_1_ab12cd34__",
        "完整字段值须原样保留"
    );
    let f2 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"reasoning":"new","reasoning_details":[{"index":0,"text":"56ab78__"}]}}]}"#,
    );
    let v2: Value = serde_json::from_str(&f2).unwrap();
    assert_eq!(v2["choices"][0]["delta"]["reasoning"], "new");
    assert_eq!(
        v2["choices"][0]["delta"]["reasoning_details"][0]["text"],
        "__PII_2_cd56ab78__"
    );
    assert!(!c.has_pending());
}

#[test]
fn a2_interleaved_tool_call_arguments_stitch_per_index() {
    // 两 `tool_calls[index]` arguments 交错分片：各 index 独立缝合，无跨实例串位。
    let mut c = TokenCarry::new();
    let f1 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":\"__PII_1_ab"}},{"index":1,"function":{"arguments":"{\"b\":\"__PII_2_cd"}}]}}]}"#,
    );
    assert_eq!(c.pending_count(), 2);
    let f2 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"12ef34__\"}"}},{"index":0,"function":{"arguments":"56ab78__\"}"}}]}}]}"#,
    );
    let arg_at = |frame: &str, tc: u64| -> String {
        let v: Value = serde_json::from_str(frame).unwrap();
        v["choices"][0]["delta"]["tool_calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["index"] == tc)
            .unwrap()["function"]["arguments"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // 跨帧拼接后各 index 完整还原为合法 JSON，无串位。
    assert_eq!(
        format!("{}{}", arg_at(&f1, 0), arg_at(&f2, 0)),
        r#"{"a":"__PII_1_ab56ab78__"}"#
    );
    assert_eq!(
        format!("{}{}", arg_at(&f1, 1), arg_at(&f2, 1)),
        r#"{"b":"__PII_2_cd12ef34__"}"#
    );
    assert!(!c.has_pending());
}

#[test]
fn a1_multi_choices_stitch_independently() {
    // `n>1` choices 互不覆盖。
    let mut c = TokenCarry::new();
    let _ = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"content":"__PII_1_ab"}},{"index":1,"delta":{"content":"__PII_2_cd"}}]}"#,
    );
    assert_eq!(c.pending_count(), 2);
    let f2 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"content":"12ef34__"}},{"index":1,"delta":{"content":"56ab78__"}}]}"#,
    );
    let v2: Value = serde_json::from_str(&f2).unwrap();
    assert_eq!(v2["choices"][0]["delta"]["content"], "__PII_1_ab12ef34__");
    assert_eq!(v2["choices"][1]["delta"]["content"], "__PII_2_cd56ab78__");
    assert!(!c.has_pending());
}

#[test]
fn a3_multi_output_index_paths_are_distinct() {
    // 多 output_index 各自独立持有，互不覆盖；释放路径可派生原索引（见 release 单测）。
    let mut c = TokenCarry::new();
    let _ = prep(
        &mut c,
        r#"{"type":"response.output_text.delta","output_index":1,"content_index":0,"item_id":"m1","delta":"__PII_1_ab"}"#,
    );
    let _ = prep(
        &mut c,
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"item_id":"m0","delta":"__PII_2_cd"}"#,
    );
    assert_eq!(c.pending_count(), 2);
    let f3 = prep(
        &mut c,
        r#"{"type":"response.output_text.delta","output_index":1,"content_index":0,"item_id":"m1","delta":"12ef34__"}"#,
    );
    let v3: Value = serde_json::from_str(&f3).unwrap();
    assert_eq!(v3["delta"], "__PII_1_ab12ef34__");
    assert_eq!(c.pending_count(), 1, "output_index 0 的持有须保留");
    assert_eq!(
        c.pending_literal_for(&[
            Seg::Idx("t=response.output_text.delta".into()),
            Seg::Idx("o=0".into()),
            Seg::Idx("c=0".into()),
            Seg::Idx("m=m0".into()),
            Seg::Key("delta".into()),
        ]),
        Some("__PII_2_cd")
    );
}

#[test]
fn duplicate_keys_degrade_to_key_only_without_panic() {
    // 重复键使路径数与值数不等 → 全帧 key-only 降级，best-effort 且不 panic。
    let mut c = TokenCarry::new();
    let frame = r#"{"content":"x","content":"__PII_1_ab"}"#;
    let out = prep(&mut c, frame);
    assert!(
        serde_json::from_str::<Value>(&out).is_ok(),
        "降级后仍须为合法 JSON: {out}"
    );
    assert_eq!(c.pending_count(), 1, "key-only 路径仍建立持有");
    assert_eq!(
        c.pending_literal_for(&[Seg::Key("content".into())]),
        Some("__PII_1_ab")
    );
}

#[test]
fn entries_bound_holds_sixteen_and_counts_overflow() {
    // 17 个不同路径候选：前 16 建立持有，第 17 超限不持有（原地保留）并计数。
    let mut c = TokenCarry::new();
    let fields: Vec<String> = (0..17).map(|i| format!(r#""f{i}":"__PII_1_ab""#)).collect();
    let frame = format!(r#"{{{}}}"#, fields.join(","));
    let out = prep(&mut c, &frame);
    assert_eq!(c.pending_count(), PENDING_MAX_ENTRIES);
    assert_eq!(c.take_over_limit_dropped(), 1, "超限候选须计一次");
    assert_eq!(c.take_over_limit_dropped(), 0, "take 须清零");
    assert!(out.contains(r#""f16":"__PII_1_ab""#), "超限候选须原地保留");
    assert!(out.contains(r#""f0":"""#), "前 16 候选须摘入持有");
}

#[test]
fn anthropic_multi_content_block_interleaved() {
    // Anthropic 多 `content_block` 交错：按根 `index` 区分，各块独立缝合。
    let mut c = TokenCarry::new();
    let b0a = prep(
        &mut c,
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"a\":\"__PII_1_ab"}}"#,
    );
    let b1a = prep(
        &mut c,
        r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"b\":\"__PII_2_cd"}}"#,
    );
    assert_eq!(c.pending_count(), 2);
    let b1b = prep(
        &mut c,
        r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"12ef34__\"}"}}"#,
    );
    let b0b = prep(
        &mut c,
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"56ab78__\"}"}}"#,
    );
    let pj = |frame: &str| -> String {
        serde_json::from_str::<Value>(frame).unwrap()["delta"]["partial_json"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        format!("{}{}", pj(&b1a), pj(&b1b)),
        r#"{"b":"__PII_2_cd12ef34__"}"#
    );
    assert_eq!(
        format!("{}{}", pj(&b0a), pj(&b0b)),
        r#"{"a":"__PII_1_ab56ab78__"}"#
    );
    assert!(!c.has_pending());
}

#[test]
fn distinct_paths_do_not_pollute_arguments_or_content() {
    // 不同路径互不污染：`function.name` 残段独立持有；`tool_calls[].id`（信封）不参与；
    // arguments/content 均不被污染。
    let mut c = TokenCarry::new();
    let f1 = prep(
        &mut c,
        r#"{"choices":[{"index":0,"delta":{"content":"hello","tool_calls":[{"index":0,"id":"__C","function":{"name":"__PII_","arguments":""}}]}}]}"#,
    );
    let v1: Value = serde_json::from_str(&f1).unwrap();
    assert_eq!(v1["choices"][0]["delta"]["content"], "hello");
    assert!(c.pending_literal_for(&content_path("0")).is_none());
    assert!(c.pending_literal_for(&tc_args_path("0", "0")).is_none());
    assert_eq!(
        c.pending_literal_for(&tc_name_path("0", "0")),
        Some("__PII_")
    );
}

#[test]
fn logprobs_token_trailing_underscore_does_not_pollute_content() {
    // Chat `logprobs.content[].token` 尾 `_` 走独立路径持有/回吐，不污染 content。
    let mut c = TokenCarry::new();
    let mk = |content: &str, tok: &str| {
        format!(
            r#"{{"choices":[{{"index":0,"delta":{{"content":"{content}"}},"logprobs":{{"content":[{{"token":"{tok}","logprob":-1.0}}]}}}}]}}"#
        )
    };
    let f1 = prep(&mut c, &mk("hello", "foo_"));
    assert_eq!(
        serde_json::from_str::<Value>(&f1).unwrap()["choices"][0]["delta"]["content"],
        "hello"
    );
    assert!(c.pending_literal_for(&content_path("0")).is_none());
    let f2 = prep(&mut c, &mk("world", "bar"));
    let v2: Value = serde_json::from_str(&f2).unwrap();
    assert_eq!(v2["choices"][0]["delta"]["content"], "world");
    assert_eq!(v2["choices"][0]["logprobs"]["content"][0]["token"], "_bar");
    assert!(!c.has_pending());
}
