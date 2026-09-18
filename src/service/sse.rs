//! SSE 门面（H1.1 三切拆分，D1）：常量转发 + 子模块重导出，对外 `service::sse::*` 路径不变。
//!
//! 子模块划分：`meta` 截断元数据（`TruncatedMode/StreamMeta/set_truncated`），
//! `parser` 切行解析 + 超长行截断 + 残余分类（`SseParser/Utf8ByteBuffer/SseEvent`），
//! `emit` 保活帧 + 快慢径发送（`keepalive_frame/Speed/select_emit`）。
//! 单测：解析门面测试外迁兄弟文件 `tests.rs`（`super::*` 经重导出解析），
//! 快慢径测试留门面，各文件均 ≤800。

/// 单测经 `super::*` 取 `GatewayMetrics/Protocol`，生产构建不引入（防 unused 警告）。
#[cfg(test)]
use super::llm_gateway::{GatewayMetrics, Protocol};
/// SSE 三常量唯一定义归属 `config`（D5 下沉，只搬不改值），此处原位转发防外部引用断裂。
pub use crate::config::{EVENT_IDLE_TIMEOUT, KEEPALIVE_INTERVAL, LINE_LIMIT_BYTES};
/// D5：`KeepaliveTracker`（时间戳自检形态，生产零接线）已删除，保活唯一实现为
/// `RequestKeepalive`（`service::audit::RequestKeepalive::spawn_gated` 接线，接线点
/// `src/handler/llm/pump/spawn/setup.rs`，间隔消费 `KEEPALIVE_INTERVAL` 10s）。
pub mod emit;
pub mod meta;
pub mod parser;

pub use {emit::*, meta::*, parser::*};

#[cfg(test)]
mod tests;

/// CR/行终止与溢出清队测试外迁兄弟文件（`tests.rs` 超 800 行拆分，纯搬不改逻辑）。
#[cfg(test)]
#[path = "sse/cr_tests.rs"]
mod cr_tests;

/// T4 快慢径/delta 切分回补：`select_emit` 两档语义 + 解析器分包等价。
#[cfg(test)]
mod speed_split_parity_tests {
    use {
        super::{Speed, SseParser, is_punct_boundary, select_emit},
        crate::{config::LINE_LIMIT_BYTES, service::llm_gateway::GatewayMetrics},
    };

    #[test]
    fn t4_slow_emits_immediately_fast_holds() {
        let mut slow = "hello".to_string();
        assert_eq!(
            select_emit(&mut slow, Speed::Slow).as_deref(),
            Some("hello")
        );
        assert!(slow.is_empty());
        let mut fast = "hello".to_string();
        assert!(select_emit(&mut fast, Speed::Fast).is_none());
        assert_eq!(fast, "hello");
    }

    #[test]
    fn speed_fast_batching_effective() {
        // STP-6/2.18：SSE 聚合缓冲尾恒 `\n\n`，Fast 不再每帧即吐而是真正攒批；
        // 达 4KB 阈值才下发，内容字节不变。
        let mut agg = String::new();
        agg.push_str("data: {\"a\":1}\n\n");
        assert!(
            select_emit(&mut agg, Speed::Fast).is_none(),
            "单帧须攒批不吐: {agg:?}"
        );
        agg.push_str("data: {\"b\":2}\n\n");
        assert!(select_emit(&mut agg, Speed::Fast).is_none());
        assert_eq!(agg.matches("data:").count(), 2, "两帧仍在攒批: {agg:?}");
        agg.push_str(&"x".repeat(4096));
        let out = select_emit(&mut agg, Speed::Fast).expect("达阈值须下发");
        assert!(out.contains("data: {\"a\":1}") && out.contains("data: {\"b\":2}"));
        assert!(agg.is_empty());
    }

    #[test]
    fn speed_batching_semantics_unchanged() {
        // STP-6/2.18：非 Fast（Slow）路径逐产出即吐；Fast 的内容标点边界仍生效。
        let mut slow = "data: {\"a\":1}\n\n".to_string();
        assert_eq!(
            select_emit(&mut slow, Speed::Slow).as_deref(),
            Some("data: {\"a\":1}\n\n")
        );
        assert!(slow.is_empty());
        let mut punct = "hello。".to_string();
        assert!(select_emit(&mut punct, Speed::Fast).is_some(), "标点须吐");
        assert!(!is_punct_boundary("data: {\"a\":1}\n\n"));
    }

    #[test]
    fn t4_fast_slow_converge_on_punctuation() {
        for tail in ["。", ".", "!", "?", ",", "，", ";", "："] {
            assert!(is_punct_boundary(&format!("x{tail}")), "{tail:?}");
            let mut buf = format!("text{tail}");
            assert_eq!(
                select_emit(&mut buf, Speed::Fast).as_deref(),
                Some(format!("text{tail}").as_str())
            );
        }
        assert!(!is_punct_boundary("hello"));
        assert!(!is_punct_boundary(""));
    }

    #[test]
    fn t4_fast_slow_final_output_identical() {
        let full = "第一句。第二句！第三句？尾";
        let mut slow_out = String::new();
        let mut buf = String::new();
        for ch in full.chars() {
            buf.push(ch);
            if let Some(chunk) = select_emit(&mut buf, Speed::Slow) {
                slow_out.push_str(&chunk);
            }
        }
        slow_out.push_str(&buf);
        let mut fast_out = String::new();
        let mut buf = String::new();
        for ch in full.chars() {
            buf.push(ch);
            if let Some(chunk) = select_emit(&mut buf, Speed::Fast) {
                fast_out.push_str(&chunk);
            }
        }
        fast_out.push_str(&buf);
        assert_eq!(slow_out, full);
        assert_eq!(fast_out, full);
    }

    #[test]
    fn t4_delta_byte_splits_reassemble_identically() {
        let raw =
            "data: {\"choices\":[{\"delta\":{\"content\":\"你好世界\"}}]}\n\ndata: [DONE]\n\n";
        let whole: Vec<String> = {
            let mut p = SseParser::new();
            p.push_bytes(raw.as_bytes())
                .iter()
                .map(|e| e.data.clone())
                .collect()
        };
        for at in [1usize, 7, 13, 29, 53] {
            let at = raw.floor_char_boundary(at.min(raw.len()));
            let mut p = SseParser::new();
            let mut got = Vec::new();
            got.extend(
                p.push_bytes(&raw.as_bytes()[..at])
                    .iter()
                    .map(|e| e.data.clone()),
            );
            got.extend(
                p.push_bytes(&raw.as_bytes()[at..])
                    .iter()
                    .map(|e| e.data.clone()),
            );
            assert_eq!(got, whole, "切分点 {at} 须与整体等价");
        }
    }

    #[test]
    fn t4_delta_char_streaming_single_event() {
        let raw = "data: {\"delta\":{\"content\":\"abc\"}}\n\n";
        let mut p = SseParser::new();
        let mut events = 0;
        for chunk in raw.as_bytes().chunks(3) {
            events += p.push_bytes(chunk).len();
        }
        assert_eq!(events, 1, "逐片投喂须重组为单事件");
    }

    #[test]
    fn t4_fast_threshold_bytes_not_chars() {
        let mut buf = "中".repeat(1366);
        assert!(
            select_emit(&mut buf, Speed::Fast).is_some(),
            "4098 字节≥阈值应吐"
        );
        let mut buf2 = "x".repeat(4095);
        assert!(select_emit(&mut buf2, Speed::Fast).is_none());
    }

    #[test]
    fn multi_data_line_joined_with_newline() {
        // MSP-2/2.26：同一事件多条 `data:` 行按 WHATWG 以单个 `\n` 连接，不压平。
        let mut p = SseParser::new();
        let evs = p.push_bytes(b"data: a\ndata: b\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "a\nb", "多行 data 须以 \\n 连接");
        let mut p2 = SseParser::new();
        let evs2 = p2.push_bytes(b"data: a\ndata:\ndata: b\n\n");
        assert_eq!(evs2[0].data, "a\n\nb", "空 data 行按空串参与连接");
        let mut p3 = SseParser::new();
        let evs3 = p3.push_bytes(b"data: solo\n\n");
        assert_eq!(evs3[0].data, "solo", "单行 data 不追加换行");
    }

    #[test]
    fn t9_sse_event_count_per_block() {
        let mut p = SseParser::new();
        assert_eq!(p.sse_event_count, 0);
        let evs = p.push_bytes(b"data: a\n\ndata: b\n\ndata: c\n\n");
        assert_eq!(evs.len(), 3);
        assert_eq!(p.sse_event_count, 3, "每数据块计一次");
        let comments = p.push_bytes(b": note\n\n");
        assert_eq!(comments.len(), 1);
        assert!(comments[0].is_comment_only);
        assert_eq!(p.sse_event_count, 3, "纯注释块不计入事件");
    }

    #[test]
    fn sse_comment_frame_fidelity() {
        // STP-7：块内注释与数据同块时随块分发，不丢失、不拆为独立事件。
        let mut p = SseParser::new();
        let evs = p.push_bytes(b": lead\ndata: {\"a\":1}\n\n");
        assert_eq!(evs.len(), 1, "注释与数据同块恰一事件: {evs:?}");
        assert!(!evs[0].is_comment_only);
        assert_eq!(evs[0].comments, vec![" lead".to_string()]);
        assert_eq!(evs[0].data, "{\"a\":1}");
        assert_eq!(p.sse_event_count, 1, "注释不改计数口径");
        // 行内注释（数据行之后）同样保真且归属不变。
        let evs = p.push_bytes(b"data: {\"b\":2}\n: trailing\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "{\"b\":2}");
        assert_eq!(evs[0].comments, vec![" trailing".to_string()]);
    }

    #[test]
    fn sse_lead_comment_not_split() {
        // STP-7：块首行注释不与块内数据拆分——不出独立注释事件。
        let mut p = SseParser::new();
        let evs = p.push_bytes(b": note-a\n: note-b\ndata: v\n\n");
        assert_eq!(evs.len(), 1, "首注释不得被拆为独立事件: {evs:?}");
        assert!(!evs[0].is_comment_only);
        assert_eq!(
            evs[0].comments,
            vec![" note-a".to_string(), " note-b".to_string()]
        );
        assert_eq!(evs[0].data, "v");
        // 纯注释块仍聚合为恰一注释事件（不计入事件数）。
        let before = p.sse_event_count;
        let c = p.push_bytes(b": only-a\n: only-b\n\n");
        assert_eq!(c.len(), 1, "相邻注释须聚合为恰一注释事件: {c:?}");
        assert!(c[0].is_comment_only);
        assert_eq!(
            c[0].comments,
            vec![" only-a".to_string(), " only-b".to_string()]
        );
        assert_eq!(p.sse_event_count, before, "注释不计入事件数");
    }

    #[test]
    fn text_carry_total_bound() {
        // STP-8：无行终止的畸形流下 text_carry 受总上限约束、内存有界。
        let mut p = SseParser::new();
        let chunk = vec![b'x'; 8192];
        for _ in 0..64 {
            let _ = p.push_bytes(&chunk);
        }
        assert!(
            p.text_carry_len() <= LINE_LIMIT_BYTES,
            "text_carry 超上限: {}",
            p.text_carry_len()
        );
        assert!(p.line_overflow, "超限须置位 line_overflow");
        assert!(p.take_truncated_line_dropped_bytes() > 0, "超限丢弃须计数");
    }

    #[test]
    fn sse_event_count_consistency() {
        // D4（R8-10/R8-14）：解析计数仅统计解析路径数据事件；注入合成帧按
        // `stream-fidelity-fix`「SSE 事件计数口径一致」显式排除，其生产计数
        // 唯一为 `add_sse_event`。本用例锁定声明差值，不断言两口径逐帧相等。
        let mut p = SseParser::new();
        let _ = p.push_bytes(b"data: a\n\ndata: b\n\n");
        assert_eq!(p.sse_event_count, 2);
        let m = GatewayMetrics::default();
        for _ in 0..3 {
            m.add_sse_event();
        }
        assert_eq!(m.sse_event_total(), 3, "生产指标覆盖下游实际发出的全部帧");
        assert_eq!(
            m.sse_event_total() - p.sse_event_count,
            1,
            "合成帧仅计入生产指标，解析计数显式排除"
        );
    }
}
