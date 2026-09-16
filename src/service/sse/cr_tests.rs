use super::*;

#[test]
fn pending_events_overflow_clears_queue() {
    // Q4/M：连续 >8 个 `event:`-only 块触发溢出时**清空整队**（fail-safe：
    // 宁缺信封不错标）——已暂存事件与本次触发事件一并丢弃，后续 data 帧**无**
    // `event:` 标签；计数按丢弃项数累计并经 `take_*` 观测清零；未超限不丢。
    let mut p = SseParser::new();
    for i in 0..9usize {
        assert!(
            p.push_bytes(format!("event: e{i}\n\n").as_bytes())
                .is_empty(),
            "纯信封块不得单独分发"
        );
    }
    assert_eq!(
        p.take_pending_events_dropped(),
        9,
        "清空 8 个已暂存 + 丢弃触发事件 = 9"
    );
    assert_eq!(p.take_pending_events_dropped(), 0, "take 后清零");
    let evs = p.push_bytes(b"data: x\n\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type, None, "清空后 data 帧不得带错配 event 名");
    assert_eq!(evs[0].data, "x");
    assert_eq!(p.sse_event_count, 1, "丢弃不改消费/计数口径");
    // 未超限（恰 8 个）不丢不计数，后续 data 帧仍按 FIFO 取首个。
    let mut q = SseParser::new();
    for i in 0..8usize {
        assert!(
            q.push_bytes(format!("event: f{i}\n\n").as_bytes())
                .is_empty()
        );
    }
    assert_eq!(q.take_pending_events_dropped(), 0, "恰 8 个不丢");
    let evs_q = q.push_bytes(b"data: y\n\n");
    assert_eq!(
        evs_q[0].event_type.as_deref(),
        Some("f0"),
        "未溢出仍按 FIFO 配对"
    );
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

#[test]
fn sse_data_frame_cr_roundtrip() {
    // E/Q6/B-3：出口按行终止集合 `\n`/`\r\n`/`\r` 拆分，SHALL NOT 把裸 CR
    // 留在单条 `data:` 行内；解析侧单 `\n` 连接为锁定行为，含裸 CR/CRLF 载荷为
    // **已声明 LF 归一**（如 `a\rb` → `a\nb`）——**不**断言逐字节恒等。
    let prefix = "event: message\nid: abc\nretry: 3000\n";
    for (payload, normalized) in [
        ("a\rb", "a\nb"),
        ("a\r\nb", "a\nb"),
        ("x\r", "x\n"),
        ("\ry", "\ny"),
        ("l1\rl2\r\nl3\nl4", "l1\nl2\nl3\nl4"),
        ("a\revent: bogus", "a\nevent: bogus"),
    ] {
        let frame = data_frame(prefix, payload);
        assert!(
            !frame.contains('\r'),
            "出口 SHALL NOT 留裸 CR 于单条 data 行: {frame:?}"
        );
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
            evs[0].data, normalized,
            "CR/CRLF 载荷须按已声明 LF 归一: {frame:?}"
        );
        assert_eq!(
            evs[0].event_type.as_deref(),
            Some("message"),
            "载荷内 CR 不得错配信封名: {frame:?}"
        );
        assert_eq!(evs[0].id.as_deref(), Some("abc"));
        assert_eq!(evs[0].retry, Some(3000));
        assert_eq!(p.sse_event_count, 1, "恰一数据事件计数");
    }
}
