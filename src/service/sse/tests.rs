use super::*;

#[test]
fn whatwg_line_splitting_with_comment_passthrough() {
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"event: message\ndata: {\"a\":1}\n\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type.as_deref(), Some("message"));
    assert_eq!(evs[0].data, "{\"a\":1}");
    let crlf = p.push_bytes(b"data: x\r\ndata: y\r\n\n");
    assert_eq!(crlf[0].data, "x\ny");
    let cr = p.push_bytes(b"data: z\r\r");
    assert_eq!(cr[0].data, "z");
    let comment = p.push_bytes(b": ping\n\n");
    assert!(comment[0].is_comment_only);
    let before = p.sse_event_count;
    let _ = p.push_bytes(b": keepalive\n\n");
    assert_eq!(p.sse_event_count, before);
}

#[test]
fn crlf_split_across_chunks() {
    // N3：块末孤立 `\r` 与下一块首字节 `\n` 合并为单个 CRLF 行终止，
    // `event:` 与 `data:` 归属同一事件，不提前分发。
    let mut p = SseParser::new();
    assert!(
        p.push_bytes(b"event: x\r").is_empty(),
        "块末孤立 CR 不得提前分发"
    );
    let evs = p.push_bytes(b"\ndata: y\r\n\r\n");
    assert_eq!(evs.len(), 1, "跨块 CRLF 恰一事件: {evs:?}");
    assert_eq!(evs[0].event_type.as_deref(), Some("x"));
    assert_eq!(evs[0].data, "y");
}

#[test]
fn parser_crlf_across_chunk_boundaries() {
    // 块末 CR + 下一块首字节非 LF：按孤立 CR 终止，字段归属不变。
    let mut p = SseParser::new();
    assert!(p.push_bytes(b"data: z\r").is_empty());
    let evs = p.push_bytes(b"data: w\r\n\r\n");
    assert_eq!(evs.len(), 1, "两 data 行同属一事件: {evs:?}");
    assert_eq!(evs[0].data, "z\nw");
    // `data: z\r` + `\r` 跨块：孤立 CR 为行终止，空行照常分发。
    let mut q = SseParser::new();
    assert!(q.push_bytes(b"data: z\r").is_empty());
    let evs_q = q.push_bytes(b"\r\n\r\n");
    assert_eq!(evs_q.len(), 1, "跨块 CR/CRLF 组合恰一事件: {evs_q:?}");
    assert_eq!(evs_q[0].data, "z");
    // 连续 CRLF 跨块：吞掉的 LF 不得触发空行提前分发。
    let mut r = SseParser::new();
    assert!(r.push_bytes(b"data: a\r").is_empty());
    assert!(r.push_bytes(b"\n").is_empty(), "被吞 LF 不得产生空行分发");
    let evs_r = r.push_bytes(b"\r\n");
    assert_eq!(evs_r.len(), 1, "块结束行仍照常分发: {evs_r:?}");
    assert_eq!(evs_r[0].data, "a");
    // 末尾 CR 后 EOF：无事件、无残余（与 LF 收尾语义一致，块未闭合）。
    let mut t = SseParser::new();
    assert!(t.push_bytes(b"data: e\r").is_empty());
    assert!(t.residual_json_aware().is_empty());
}

#[test]
fn bare_data_line() {
    // P11/D9：无冒号 `data` 行按空值字段处理：`data\ndata: x\n\n` → `data=="\nx"`。
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"data\ndata: x\n\n");
    assert_eq!(evs.len(), 1, "恰一事件: {evs:?}");
    assert_eq!(evs[0].data, "\nx");
}

#[test]
fn parser_bare_data() {
    // P11/D9 边界：裸 `data`、`data:` 空值、混合形态合并；其他无冒号行维持忽略。
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"data\ndata:\ndata: x\n\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].data, "\n\nx", "空值字段须参与 \\n 合并");
    let mut q = SseParser::new();
    assert!(
        q.push_bytes(b"data\n\n").is_empty(),
        "单裸 data 得空值 data 帧，无其他字段时按既有空帧语义丢弃"
    );
    let mut r = SseParser::new();
    let evs_r = r.push_bytes(b"event\ndata: v\n\n");
    assert_eq!(evs_r.len(), 1);
    assert_eq!(evs_r[0].event_type, None, "无冒号 event 行仍忽略");
    assert_eq!(evs_r[0].data, "v");
}

#[test]
fn retry_all_digits_and_data_single_space_stripped() {
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"retry: 3000\ndata:  hello\n\n");
    assert_eq!(evs[0].retry, Some(3000));
    assert_eq!(evs[0].data, " hello");
    let bad = p.push_bytes(b"retry: 3x\ndata: v\n\n");
    assert_eq!(bad[0].retry, None);
}

#[test]
fn double_space_data_json_parses() {
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"data:  {\"a\":1}\n\n");
    assert_eq!(evs.len(), 1);
    let v: serde_json::Value =
        serde_json::from_str(&evs[0].data).expect("双空格残留须被 serde_json 容忍");
    assert_eq!(v["a"], 1);
}

#[test]
fn utf8_byte_buffered_without_per_chunk_decoding() {
    let mut buf = Utf8ByteBuffer::new();
    let ch = "中".as_bytes();
    let first = buf.push(&ch[..1]);
    assert_eq!(first, "");
    assert_eq!(buf.pending_len(), 1);
    let second = buf.push(&ch[1..]);
    assert_eq!(second, "中");
    assert_eq!(buf.pending_len(), 0);
    let mut p = SseParser::new();
    let a = "data: ".as_bytes();
    let b = "中文".as_bytes();
    let mut evs = p.push_bytes(a);
    assert!(evs.is_empty());
    evs = p.push_bytes(&b[..2]);
    assert!(evs.is_empty());
    evs = p.push_bytes(&b[2..]);
    assert!(evs.is_empty());
    evs = p.push_bytes(b"\n\n");
    assert_eq!(evs[0].data, "中文");
}

#[test]
fn utf8_buffer_invalid_bytes_progress() {
    // D2/STP-2：连续无效字节须每轮消费推进（errors='replace'），pending 有界。
    let mut buf = Utf8ByteBuffer::new();
    for _ in 0..64 {
        let out = buf.push(&[0xff]);
        assert!(!out.is_empty(), "无效字节须产出替换字符而非停滞");
        assert!(
            buf.pending_len() <= 3,
            "无效字节不得滞留 pending: {}",
            buf.pending_len()
        );
    }
    let out = buf.push("data: 中".as_bytes());
    assert!(out.ends_with('中'), "无效字节后续合法文本须保留: {out:?}");
    // 截断的多字节前缀（error_len None）仍须保留待拼接，且其前合法字节须先放行。
    let mut prefix = Utf8ByteBuffer::new();
    let ch = "中".as_bytes();
    let mut with_prefix = b"ab".to_vec();
    with_prefix.extend_from_slice(&ch[..1]);
    assert_eq!(
        prefix.push(&with_prefix),
        "ab",
        "不完整前缀前的合法字节须先放行"
    );
    assert_eq!(prefix.pending_len(), 1, "不完整前缀须保留待拼接");
    assert_eq!(prefix.push(&ch[1..]), "中", "续段到达后须拼出完整字符");
}

#[test]
fn sse_parser_invalid_utf8_eof_replace() {
    // D2/STP-2：中途无效字节按替换语义消费后仍解析后续合法事件。
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"data: \xff\xfeok\n\n");
    assert_eq!(evs.len(), 1, "无效字节后须继续解析: {evs:?}");
    assert!(
        evs[0].data.ends_with("ok"),
        "后续合法文本不得丢: {:?}",
        evs[0].data
    );
    // EOF 残余（截断的多字节序列）按同一替换语义处理，不乱码、不挂起。
    let mut q = SseParser::new();
    assert!(q.push_bytes(b"data: ").is_empty());
    assert!(q.push_bytes(&[0xe4, 0xb8]).is_empty());
    let residual = q.residual_json_aware();
    assert!(
        residual.contains('\u{fffd}'),
        "EOF 残余须按替换语义: {residual:?}"
    );
}

#[test]
fn sse_parser_invalid_stream_bounded() {
    // D2/STP-2：持续无效字节且不发行终止，text_carry 受总上限约束不无界增长。
    let mut p = SseParser::new();
    let chunk = vec![0xffu8; 4096];
    for _ in 0..64 {
        let _ = p.push_bytes(&chunk);
    }
    assert!(
        p.text_carry_len() <= LINE_LIMIT_BYTES,
        "text_carry 超上限无界: {}",
        p.text_carry_len()
    );
    // 超限后仍须推进解析，不卡死。
    let evs = p.push_bytes(b"\n\ndata: ok\n\n");
    assert!(
        evs.iter().any(|e| e.data.contains("ok")),
        "超限后仍须推进解析: {evs:?}"
    );
}

#[test]
fn push_bytes_reassembles_multiline_and_split_utf8_before_dispatch() {
    // G8.1：`push_bytes` 重组语义——多行 data 跨块合并且 UTF-8 跨块拼接后
    // 分发完整文本，而非仅断言帧数/切分。
    let mut p = SseParser::new();
    assert!(p.push_bytes("data: 第一行\n".as_bytes()).is_empty());
    assert!(p.push_bytes("data: 第二行\n".as_bytes()).is_empty());
    let evs = p.push_bytes(b"\n");
    assert_eq!(evs.len(), 1, "空行到达方分发: {evs:?}");
    assert_eq!(evs[0].data, "第一行\n第二行", "多行 data 须以 \\n 合并");
    // 跨块 UTF-8：逐字节喂入多字节字符，任何切点都不得丢字节或提前分发。
    let mut q = SseParser::new();
    assert!(q.push_bytes("data: ".as_bytes()).is_empty());
    for byte in "跨越分片的中文".as_bytes() {
        assert!(q.push_bytes(&[*byte]).is_empty(), "字符中途不得提前分发");
    }
    let evs = q.push_bytes(b"\n\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].data, "跨越分片的中文", "跨块 UTF-8 须拼出完整文本");
}

#[test]
fn line_buffer_16kb_truncates_with_counter_and_mark() {
    // C11：超长行改丢弃为截断——头 16KB 保留分发审计，尾部计数，
    // 事件带截断标记；后续正常帧不受影响。
    let mut p = SseParser::new();
    let big = "x".repeat(LINE_LIMIT_BYTES + 10);
    let mut frame = b"data: ".to_vec();
    frame.extend_from_slice(big.as_bytes());
    frame.extend_from_slice(b"\n\n");
    let evs = p.push_bytes(&frame);
    assert_eq!(evs.len(), 1, "截断头须分发，不得静默整块丢");
    assert!(evs[0].truncated, "截断事件须带标记");
    assert!(p.line_overflow);
    assert_eq!(
        evs[0].data.len(),
        LINE_LIMIT_BYTES - "data: ".len(),
        "头 16KB（含前缀）保留"
    );
    assert_eq!(
        p.take_truncated_line_dropped_bytes(),
        (big.len() + "data: ".len() - LINE_LIMIT_BYTES) as u64,
        "尾部字节须计数"
    );
    assert_eq!(p.take_truncated_line_dropped_bytes(), 0, "取出后清零");
    let ok = p.push_bytes(b"data: fine\n\n");
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].data, "fine");
    assert!(!ok[0].truncated, "正常帧不得带截断标记");
}

#[test]
fn overlong_tool_fragment_stays_auditable_with_mark() {
    // C11 超长 tool 分片：20KB 工具参数头截断后仍分发（审计可见），
    // 尾部字节计数，标记随事件。
    let mut p = SseParser::new();
    let args = "y".repeat(20 * 1024);
    let payload = format!("{{\"type\":\"tool_use\",\"partial_json\":\"{args}\"}}");
    let frame = format!("data: {payload}\n\n");
    let evs = p.push_bytes(frame.as_bytes());
    assert_eq!(evs.len(), 1);
    assert!(evs[0].truncated);
    assert!(
        evs[0].data.starts_with("{\"type\":\"tool_use\""),
        "头部须保留可审计"
    );
    assert!(evs[0].data.len() < payload.len(), "尾部须被截断");
    assert!(p.take_truncated_line_dropped_bytes() > 0);
}

#[test]
fn keepalive_aligned_without_counting_events() {
    let p = SseParser::new();
    assert_eq!(p.sse_event_count, 0);
    let f = keepalive_frame();
    assert_eq!(f, ": keepalive\n\n");
}

#[test]
fn truncation_three_states_with_responses_restriction() {
    let mut meta = StreamMeta::default();
    assert!(set_truncated(
        &mut meta,
        Protocol::Responses,
        TruncatedMode::SynthesizedFailed,
        None
    ));
    assert_eq!(meta.truncated_mode, Some(TruncatedMode::SynthesizedFailed));
    let mut m2 = StreamMeta::default();
    assert!(!set_truncated(
        &mut m2,
        Protocol::Chat,
        TruncatedMode::SynthesizedFailed,
        None
    ));
    assert!(set_truncated(
        &mut m2,
        Protocol::Chat,
        TruncatedMode::SilentDiscard,
        None
    ));
    assert!(set_truncated(
        &mut m2,
        Protocol::Anthropic,
        TruncatedMode::OpenEnded,
        None
    ));
    let gm = GatewayMetrics::default();
    let mut m3 = StreamMeta::default();
    assert!(set_truncated(
        &mut m3,
        Protocol::Responses,
        TruncatedMode::OpenEnded,
        Some(&gm)
    ));
    assert_eq!(gm.truncated_count("open_ended"), 1);
}

#[test]
fn slow_fast_dispatch_semantics() {
    let mut buf = "hello。".to_string();
    assert!(select_emit(&mut buf, Speed::Slow).is_some());
    let mut buf2 = "hello".to_string();
    assert!(select_emit(&mut buf2, Speed::Fast).is_none());
    buf2.push('。');
    assert!(select_emit(&mut buf2, Speed::Fast).is_some());
}

#[test]
fn truncation_real_data_utf8_fragments_reassembled_single_terminal() {
    let mut buf = Utf8ByteBuffer::new();
    let raw = "data: {\"content\":\"中文回复。\"}\n\n".as_bytes();
    let mut text = String::new();
    for chunk in raw.chunks(3) {
        text.push_str(&buf.push(chunk));
    }
    text.push_str(&buf.flush_text());
    assert!(text.contains("中文回复"));
    let mut p = SseParser::new();
    let mut evs = Vec::new();
    for chunk in raw.chunks(5) {
        evs.extend(p.push_bytes(chunk));
    }
    assert_eq!(evs.len(), 1);
    assert!(evs[0].data.contains("中文回复"));
    let mut meta = StreamMeta::default();
    assert!(set_truncated(
        &mut meta,
        Protocol::Chat,
        TruncatedMode::OpenEnded,
        None
    ));
    assert_eq!(meta.truncated_mode, Some(TruncatedMode::OpenEnded));
}

#[test]
fn data_line_level_json_aware_restore() {
    // H1/D2：JSON 合法即逐字节透传（不再二次序列化/叶变换）；非 JSON 走闭包。
    let raw = "{\"a\": \"v1\"}";
    let out = json_aware_line(raw, |s| s.replace("v1", "v2"));
    assert_eq!(out, raw, "合法 JSON 须返回输入字节");
    let plain = json_aware_line("plain token", |s| s.to_uppercase());
    assert_eq!(plain, "PLAIN TOKEN");
}

#[test]
fn json_aware_line_no_second_pass() {
    // H1/D2：已处理帧再入 `json_aware_line` 输出与输入字节一致
    //（不再触发第二次 `dumps`，数字/键序/空白零改写）。
    let processed = r#"{"z":1e3,"a":"已脱敏 __PII_1_ab12cd34__"}"#;
    assert_eq!(json_aware_line(processed, |s| s), processed);
    let array = r#"[1e3,{"b":2,"a":1}]"#;
    assert_eq!(json_aware_line(array, |s| s), array);
}

#[test]
fn fast_debounce_accumulates_until_punctuation_or_threshold() {
    let mut agg = String::new();
    agg.push_str("hello");
    assert!(select_emit(&mut agg, Speed::Fast).is_none());
    agg.push_str(" world");
    assert!(select_emit(&mut agg, Speed::Fast).is_none());
    assert_eq!(agg, "hello world");
    agg.push('。');
    assert_eq!(
        select_emit(&mut agg, Speed::Fast).as_deref(),
        Some("hello world。")
    );
    assert!(agg.is_empty());
    // 空缓冲恒 None，两档一致。
    assert!(select_emit(&mut agg, Speed::Fast).is_none());
    assert!(select_emit(&mut agg, Speed::Slow).is_none());
    // 4KB 阈值无标点也吐（长文本不饿死）。
    agg.push_str(&"x".repeat(4096));
    assert_eq!(select_emit(&mut agg, Speed::Fast).unwrap().len(), 4096);
    // 阈值差一字节仍缓冲。
    agg.push_str(&"y".repeat(4095));
    assert!(select_emit(&mut agg, Speed::Fast).is_none());
}

#[test]
fn bom_done_residue_discarded_single_terminal() {
    assert!(is_done_payload("\u{feff}[DONE]"));
    assert!(is_done_payload("  [DONE]  "));
    assert!(is_done_payload("data: [DONE]"));
    assert!(is_done_payload("data:[DONE]"));
    assert!(is_done_payload("\u{feff}data: [DONE]"));
    assert!(!is_done_payload("[DONE] extra"));
    assert!(!is_done_payload("{\"a\":1}"));
    assert!(classify_residue("").is_none());
    assert!(classify_residue("   ").is_none());
    assert!(classify_residue("\u{feff}data: [DONE]").is_none());
    assert!(classify_residue("\u{feff}[DONE]").is_none());
    // JSON 残余保留还原（断连半帧不断链）。
    let kept = classify_residue("data: {\"a\": 1").expect("半帧残余须保留");
    assert!(kept.contains("\"a\""));
    // BOM+JSON 正常解析，不当残余转发；H1/D2：合法 JSON 字节透传（含 BOM 输入）。
    let raw = "\u{feff}{\"a\": \"v1\"}";
    let out = json_aware_line(raw, |s| s.replace("v1", "v2"));
    assert_eq!(out, raw, "合法 JSON 须返回输入字节");
    // 残余 DONE 经 parser 直接丢弃，不 data: 转发。
    let mut q = SseParser::new();
    let _ = q.push_bytes("\u{feff}[DONE]".as_bytes());
    assert!(q.residual_json_aware().is_empty());
    // BOM 流经终端去重后恰一终止帧。
    let frames = super::super::block_inject::dedupe_terminal_frames(
        vec![
            "event: message\ndata: {\"a\":1}\n\n".to_string(),
            "data: [DONE]\n\n".to_string(),
            "\u{feff}data: [DONE]\n\n".to_string(),
        ],
        "chat",
    );
    assert_eq!(
        super::super::block_inject::count_done(&frames),
        1,
        "BOM+重复 DONE 去重后恰一终止"
    );
    assert!(
        frames
            .last()
            .is_some_and(|f| super::super::block_inject::is_done_frame(f))
    );
}

#[test]
fn multiline_data_ordered_passthrough_preserving_event_name() {
    let mut p = SseParser::new();
    let evs = p.push_bytes("event: message\ndata: 第一行\ndata: 第二行\n\n".as_bytes());
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type.as_deref(), Some("message"));
    assert_eq!(evs[0].data, "第一行\n第二行");
    // 多行中文分包到达仍完整组装。
    let mut q = SseParser::new();
    assert!(q.push_bytes("data: 甲".as_bytes()).is_empty());
    assert!(q.push_bytes("乙\n".as_bytes()).is_empty());
    let evs = q.push_bytes("data: 丙\n\n".as_bytes());
    assert_eq!(evs[0].data, "甲乙\n丙");
}

#[test]
fn empty_retry_and_comment_lines_ignored_without_event_count() {
    let mut p = SseParser::new();
    let before = p.sse_event_count;
    let evs = p.push_bytes(b"retry:\ndata: v\n\n");
    assert_eq!(evs[0].retry, None, "空 retry 不得解析出数值");
    assert_eq!(evs[0].data, "v");
    let c1 = p.push_bytes(b": comment-a\n\n");
    assert!(c1[0].is_comment_only);
    let c2 = p.push_bytes(b": comment-b\n\n");
    assert!(c2[0].is_comment_only);
    assert_eq!(
        p.sse_event_count,
        before + 1,
        "纯注释帧透传但不计入事件（comment 不计）"
    );
}

#[test]
fn refusal_three_fragments_reassembled_single_event() {
    let mut p = SseParser::new();
    let full = "data: {\"choices\":[{\"delta\":{\"refusal\":\"合成拒绝文\"}}]}\n\n";
    let a = full.floor_char_boundary(full.len() / 3);
    let b = full.floor_char_boundary(2 * full.len() / 3);
    assert!(p.push_bytes(&full.as_bytes()[..a]).is_empty());
    assert!(p.push_bytes(&full.as_bytes()[a..b]).is_empty());
    let evs = p.push_bytes(&full.as_bytes()[b..]);
    assert_eq!(evs.len(), 1, "三片段须重组为单事件单次还原");
    assert!(evs[0].data.contains("合成拒绝文"));
    assert_eq!(p.sse_event_count, 1, "幂等哨兵：单事件只计一次");
}

#[test]
fn flush_text_idempotent_without_double_restore() {
    let mut buf = Utf8ByteBuffer::new();
    assert_eq!(buf.push("甲".as_bytes()), "甲");
    let first = buf.flush_text();
    assert!(first.is_empty(), "无残余时 flush 为空");
    let second = buf.flush_text();
    assert!(second.is_empty(), "重复 flush 不得二次产出（无双还原）");
    let mut p = SseParser::new();
    assert!(p.push_bytes(b"data: {\"a\":1}\n").is_empty());
    let evs = p.push_bytes(b"\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].data, "{\"a\":1}");
}

#[test]
fn bom_prefixed_frames_parse_like_non_bom() {
    // C12：行内 BOM 先剥离再解析——BOM 前缀帧与非 BOM 等价分发。
    // R1：经 `json_walk::strip_bom` 唯一来源断言（`strip_sse_bom` 已删）。
    assert_eq!(
        super::super::json_walk::strip_bom("\u{feff}data: x"),
        "data: x"
    );
    assert_eq!(
        super::super::json_walk::strip_bom("\u{feff}\u{feff}data: x"),
        "data: x"
    );
    let mut p = SseParser::new();
    let evs = p.push_bytes("\u{feff}data: {\"b\":2}\n\n".as_bytes());
    assert_eq!(evs.len(), 1, "BOM 数据行须产出事件");
    assert_eq!(evs[0].data, "{\"b\":2}");
    assert!(!evs[0].truncated);
    let mut q = SseParser::new();
    let evs_q = q.push_bytes("data: {\"b\":2}\n\n".as_bytes());
    assert_eq!(evs_q[0].data, evs[0].data, "BOM 与非 BOM 等价");
    // BOM 事件名前缀同样识别；BOM 终止帧照常为 `[DONE]` 数据。
    let mut r = SseParser::new();
    let evs_r = r.push_bytes("\u{feff}event: message\n\u{feff}data: {\"b\":3}\n\n".as_bytes());
    assert_eq!(evs_r.len(), 1);
    assert_eq!(evs_r[0].event_type.as_deref(), Some("message"));
    assert_eq!(evs_r[0].data, "{\"b\":3}");
    let mut d = SseParser::new();
    let evs_d = d.push_bytes("\u{feff}data: [DONE]\n\n".as_bytes());
    assert_eq!(evs_d.len(), 1);
    assert!(is_done_payload(&evs_d[0].data));
    // 纯注释帧仍透传。
    let c = p.push_bytes(b": note\n\n");
    assert_eq!(c.len(), 1, "注释帧须透传");
    assert!(c[0].is_comment_only);
}

#[test]
fn sse_cross_block_event_pairs_with_data() {
    // TRN-1：`event:` 与 `data:` 分块时暂存 event，与后续 data 同事件配对，
    // 不产生空 data 的孤立 event 块。
    let mut p = SseParser::new();
    assert!(
        p.push_bytes(b"event: content_block_delta\n\n").is_empty(),
        "无 data 的 event 块不得单独分发"
    );
    let evs = p.push_bytes(b"data: {\"type\":\"content_block_delta\"}\n\n");
    assert_eq!(evs.len(), 1, "配对后恰一事件: {evs:?}");
    assert_eq!(evs[0].event_type.as_deref(), Some("content_block_delta"));
    assert_eq!(evs[0].data, "{\"type\":\"content_block_delta\"}");
}

#[test]
fn sse_cross_block_event_fifo() {
    // TRN-1：多个无 data 的 `event:` 块按 FIFO 与后续 data 块逐次配对。
    let mut p = SseParser::new();
    assert!(p.push_bytes(b"event: a\n\nevent: b\n\n").is_empty());
    let evs = p.push_bytes(b"data: 1\n\ndata: 2\n\n");
    assert_eq!(evs.len(), 2, "两 data 块各得一暂存 event: {evs:?}");
    assert_eq!(evs[0].event_type.as_deref(), Some("a"));
    assert_eq!(evs[1].event_type.as_deref(), Some("b"));
}

#[test]
fn pending_events_hard_cap_drops_oldest() {
    // D2：连续 >8 个 `event:`-only 块丢**最旧**（FIFO 窗口保留最新 8 个），
    // 计数经 `take_*` 观测并清零；消费点语义不变（存活窗口仍按 FIFO 配对）。
    let mut p = SseParser::new();
    for i in 0..10usize {
        assert!(
            p.push_bytes(format!("event: e{i}\n\n").as_bytes())
                .is_empty(),
            "纯信封块不得单独分发"
        );
    }
    assert_eq!(p.take_pending_events_dropped(), 2, "10-8=2 个最旧被丢");
    assert_eq!(p.take_pending_events_dropped(), 0, "take 后清零");
    for i in 2..10usize {
        let evs = p.push_bytes(b"data: x\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event_type.as_deref(), Some(format!("e{i}").as_str()));
        assert_eq!(evs[0].data, "x");
    }
    assert_eq!(p.sse_event_count, 8, "丢弃不改事件计数口径");
    // 未超限（恰 8 个）不丢不计数。
    let mut q = SseParser::new();
    for i in 0..8usize {
        assert!(
            q.push_bytes(format!("event: f{i}\n\n").as_bytes())
                .is_empty()
        );
    }
    assert_eq!(q.take_pending_events_dropped(), 0, "恰 8 个不丢");
}

#[test]
fn sse_last_event_id_persists() {
    // TRN-1：WHATWG last-event-id——最近 `id` 对后续无 `id` 事件持续生效，
    // 空值 `id:` 重置。
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"id: 42\ndata: a\n\n");
    assert_eq!(evs[0].id.as_deref(), Some("42"));
    let evs = p.push_bytes(b"data: b\n\n");
    assert_eq!(evs[0].id.as_deref(), Some("42"), "最近 id 须持续透出");
    let evs = p.push_bytes(b"id:\ndata: c\n\n");
    assert_eq!(evs[0].id, None, "空 id 须重置 last-event-id");
    let evs = p.push_bytes(b"data: d\n\n");
    assert_eq!(evs[0].id, None, "重置后不得回填旧 id");
}

#[test]
fn sse_split_envelope_parser_count_unchanged() {
    // TRN-1：分块信封流与同内容同块流的事件计数逐一致。
    let split: &[u8] = b"event: x\n\ndata: {\"a\":1}\n\ndata: {\"b\":2}\n\n";
    let whole: &[u8] = b"event: x\ndata: {\"a\":1}\n\ndata: {\"b\":2}\n\n";
    let count = |raw: &[u8]| {
        let mut p = SseParser::new();
        let mut emitted = 0;
        for chunk in raw.chunks(4) {
            emitted += p.push_bytes(chunk).len();
        }
        (emitted, p.sse_event_count)
    };
    assert_eq!(count(split), count(whole), "分块须与非分块逐一致");
    assert_eq!(count(split), (2, 2), "恰两事件且计数为二");
}

#[test]
fn sse_chunked_envelope_counts_match_unchunked() {
    // D2/TRN-1：信封与 data 分置不同块的流，与同内容同块流的**事件数/
    // `sse_event_count`/转发字段**逐项等价（`event` FIFO + `id` 最近值）。
    let whole: &[u8] = b"event: a\nid: 11\ndata: 1\n\nevent: b\ndata: 2\n\nid: 12\ndata: 3\n\n";
    let chunked: &[u8] =
        b"event: a\nid: 11\n\ndata: 1\n\nevent: b\n\ndata: 2\n\nid: 12\n\ndata: 3\n\n";
    let parse = |raw: &[u8]| {
        let mut p = SseParser::new();
        let events = p.push_bytes(raw);
        (events, p.sse_event_count)
    };
    let (whole_events, whole_count) = parse(whole);
    let (chunked_events, chunked_count) = parse(chunked);
    assert_eq!(chunked_count, whole_count, "两侧 sse_event_count 须一致");
    assert_eq!(whole_count, 3, "恰三事件");
    assert_eq!(chunked_events.len(), whole_events.len(), "事件数须一致");
    for (c, w) in chunked_events.iter().zip(whole_events.iter()) {
        assert_eq!(
            (
                c.event_type.as_deref(),
                c.data.as_str(),
                c.id.as_deref(),
                c.retry
            ),
            (
                w.event_type.as_deref(),
                w.data.as_str(),
                w.id.as_deref(),
                w.retry
            ),
            "分块与非分块字段须逐项一致"
        );
    }
}

#[test]
fn sse_id_and_retry_fields_captured() {
    // TRN-1：出口重建依赖解析侧 `id`/`retry` 完整捕获，非数字 retry 丢弃。
    let mut p = SseParser::new();
    let evs = p.push_bytes(b"id: 42\nretry: 3000\ndata: {\"a\":1}\n\n");
    assert_eq!(evs[0].id.as_deref(), Some("42"));
    assert_eq!(evs[0].retry, Some(3000));
    let bad = p.push_bytes(b"retry: 3x\ndata: v\n\n");
    assert_eq!(bad[0].retry, None, "非数字 retry 不得解析");
}

#[test]
fn sse_data_frame_multiline_split() {
    // A-5/F-07：出口含换行载荷拆为多条带前缀行、无裸行，且与解析侧
    // WHATWG 单 `\n` 连接严格互逆（逐字节还原原载荷）。
    let frame = data_frame("event: message\n", "第一行\n第二行");
    assert_eq!(
        frame, "event: message\ndata: 第一行\ndata: 第二行\n\n",
        "信封前缀原样透出、data 按行拆分、尾部恰一空行"
    );
    assert!(
        frame
            .lines()
            .all(|l| l.is_empty() || l.starts_with("data: ") || l.starts_with("event: ")),
        "不得输出无前缀裸行: {frame:?}"
    );

    let mut p = SseParser::new();
    let evs = p.push_bytes(frame.as_bytes());
    assert_eq!(evs.len(), 1, "拆分行重组恰一事件: {evs:?}");
    assert_eq!(evs[0].event_type.as_deref(), Some("message"));
    assert_eq!(evs[0].data, "第一行\n第二行", "出口拆分与解析连接互逆");

    // 单行/空载荷与既有 format 构造逐字节等价。
    assert_eq!(data_frame("", "{\"a\":1}"), "data: {\"a\":1}\n\n");
    assert_eq!(data_frame("", ""), "data: \n\n");
    assert_eq!(data_frame("id: 7\n", "x"), "id: 7\ndata: x\n\n");
}

#[test]
fn sse_multiline_data_roundtrip() {
    // A-5/F-07 + 11.3（覆盖缺口）：出口 `data_frame` 按 `\n` 拆多条 `data:` 行与
    // 解析侧 WHATWG 单 `\n` 连接严格互逆——多行载荷（含首尾/连续换行）逐字节还原；
    // `event:`/`id:`/`retry:` 信封不参与拆分、字段原样回读。
    // 注：拆分单元为 `\n`（A-5 定义），载荷内裸 `\r` 不属本互逆口径（WHATWG 视 CR 为行终止）。
    let prefix = "event: message\nid: abc\nretry: 3000\n";
    for payload in [
        "第一行\n第二行",
        "a\n\nb",
        "trailing\n",
        "\nleading",
        "l1\nl2\nl3\nl4",
        "{\"k\":\"v\"}\n{}",
    ] {
        let frame = data_frame(prefix, payload);
        for line in frame.lines() {
            assert!(
                line.is_empty()
                    || line.starts_with("data: ")
                    || line.starts_with("event: ")
                    || line.starts_with("id: ")
                    || line.starts_with("retry: "),
                "不得输出无前缀裸行: {frame:?}"
            );
        }
        let mut p = SseParser::new();
        let evs = p.push_bytes(frame.as_bytes());
        assert_eq!(evs.len(), 1, "拆分行须重组恰一事件: {frame:?}");
        assert_eq!(
            evs[0].data, payload,
            "出口拆分与解析连接须逐字节互逆: {frame:?}"
        );
        assert_eq!(evs[0].event_type.as_deref(), Some("message"));
        assert_eq!(evs[0].id.as_deref(), Some("abc"));
        assert_eq!(evs[0].retry, Some(3000));
        assert_eq!(p.sse_event_count, 1, "恰一数据事件计数");
    }
    // 无信封前缀的多行载荷同样互逆。
    let frame = data_frame("", "x\ny");
    assert_eq!(frame, "data: x\ndata: y\n\n");
    let mut p = SseParser::new();
    assert_eq!(p.push_bytes(frame.as_bytes())[0].data, "x\ny");
}
