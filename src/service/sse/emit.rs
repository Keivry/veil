//! SSE 保活帧 + 快慢径发送（H1.1 三切）。
//!
//! - `keepalive_frame` 流内保活唯一帧形态（`: keepalive`，注释帧，不计事件）。
//! - `Speed::Slow` 见文即吐，`Speed::Fast` 攒至标点边界或 4KB 阈值再吐（T4）。
//! - 对外路径不变：经 `super`（`service::sse`）重导出，调用方零改。

pub fn keepalive_frame() -> String { ": keepalive\n\n".to_string() }

/// A-5/F-07：SSE 出口 `data:` 帧唯一构造——按行终止集合 `\n`/`\r\n`/`\r` 拆分
/// 载荷，每行各补 `data: ` 前缀后补块终止空行；与解析侧行终止集合相关
/// （`parser.rs::push_text` 同集合切行、多 `data:` 行以单 `\n` 连接，
/// `parser.rs::dispatch_block`），SHALL NOT 把裸 CR 留在单条 `data:` 行内。
/// 含裸 CR/CRLF 载荷按**已声明 LF 归一**（如 `a\rb` → `a\nb`），SHALL NOT
/// 声称逐字节恒等。`prefix` 为 `event:`/`id:`/`retry:` 信封前缀（原样透出，
/// 不受拆分影响），SHALL NOT 输出无前缀裸行（否则消费者静默截断到首行）。
pub(crate) fn data_frame(prefix: &str, data: &str) -> String {
    let terms = data.matches(['\n', '\r']).count();
    let mut out = String::with_capacity(prefix.len() + data.len() + terms + 8);
    out.push_str(prefix);
    for line in split_line_terminators(data) {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}

/// 按 SSE 行终止集合（`\n`/`\r\n`/`\r`）切分载荷为不含终止符的行序列；
/// `\r\n` 视为单个终止符，与解析侧 `parser.rs` 行切分集合一致（切点恒落在
/// ASCII 终止符字节边界，切片安全）。
fn split_line_terminators(data: &str) -> Vec<&str> {
    let bytes = data.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                lines.push(&data[start..i]);
                if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
                start = i;
            }
            b'\n' => {
                lines.push(&data[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    lines.push(&data[start..]);
    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Slow,
    Fast,
}

/// Fast 径攒批阈值（字节）：攒至标点边界或该阈值即吐出（T4）。
/// 硬编码理由：经验值平衡首字延迟与 SSE 帧数，调整须同步复核续跑测试。
pub const FAST_EMIT_THRESHOLD_BYTES: usize = 4096;

/// STP-6/2.18：标点边界判定不含 `\n`——SSE 聚合缓冲（`agg`）尾恒为帧终止
/// `\n\n`，若把 `\n` 计入边界会使 `Speed::Fast` 每帧即吐、攒批恒不生效。
pub fn is_punct_boundary(text: &str) -> bool {
    text.chars().last().is_some_and(|c| {
        matches!(
            c,
            '。' | '！' | '？' | '.' | '!' | '?' | ',' | '，' | ';' | '；' | ':' | '：'
        )
    })
}

pub fn select_emit(buffer: &mut String, speed: Speed) -> Option<String> {
    match speed {
        Speed::Slow => {
            if buffer.is_empty() {
                None
            } else {
                Some(std::mem::take(buffer))
            }
        }
        Speed::Fast => {
            if buffer.is_empty() {
                None
            } else if is_punct_boundary(buffer) || buffer.len() >= FAST_EMIT_THRESHOLD_BYTES {
                Some(std::mem::take(buffer))
            } else {
                None
            }
        }
    }
}
