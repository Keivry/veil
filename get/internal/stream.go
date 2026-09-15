// Package internal — SSE 消费 helper（LLM 网关流式协议）
package internal

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrSSEIncomplete 表示 SSE 连接在收到终止帧前被服务端关闭。
var ErrSSEIncomplete = errors.New("SSE 流在终止帧前结束")

// sseClient SSE 专用 HTTP 客户端：显式禁用总超时（Timeout=0），
// 避免 LLM 长流被共享 httpClient 的 PROXY_HTTP_TIMEOUT（默认 300s）总超时截断。
// 超时与取消由调用方 ctx 控制，调用方应传入带 deadline 的 ctx。
var sseClient = &http.Client{Timeout: 0}

// sseTerminalTypes 三协议终止帧的 event 名 / data JSON type 集合。
var sseTerminalTypes = map[string]bool{
	"message_stop":        true, // Anthropic
	"response.completed":  true, // Responses
	"response.failed":     true, // Responses（阻断/截断）
	"response.incomplete": true, // Responses
}

// ConsumeSSE 消费 url 的 SSE 流（GET 入口，保持既有签名与语义不变），
// 读到一个终止帧即正常返回 (true, nil)：
//   - Chat:      data: [DONE]
//   - Anthropic: event: message_stop / data: {"type":"message_stop"}
//   - Responses: data: {"type":"response.completed"|"response.failed"|"response.incomplete"}
//
// 服务端在终止帧前关闭连接（EOF）时返回 ErrSSEIncomplete，明确失败不挂起、不重试；
// ctx 取消或超时立即返回对应错误。ctx 为 nil 时等价 context.Background()。
func ConsumeSSE(ctx context.Context, url string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("创建 SSE 请求失败: %w", err)
	}
	return ConsumeSSEWithRequest(ctx, req)
}

// ConsumeSSEWithRequest 消费 req 指定的 SSE 流，支持任意 HTTP 方法、请求体与头部，
// 用于 LLM 流式端点这类非 GET 入口（如 `POST /v1/chat/completions`）。
// 终止帧判定与错误语义与 ConsumeSSE 完全一致：
//   - 命中终止帧返回 (true, nil)；
//   - 终止帧前 EOF 返回 ErrSSEIncomplete；
//   - ctx 取消/超时立即返回对应错误；
//   - status >= 400 返回错误（含状态码与截断后的响应体）。
//
// ctx 非 nil 时覆盖 req 既有 context；ctx 为 nil 时沿用 req.Context()。
// req.Header 为 nil 时自动初始化；Accept 头未设置时补 "text/event-stream"
// （已设置则尊重调用方）。req 为 nil 返回错误。
//
// 请求使用无总超时的 sseClient 发出，长流不会被截断；超时与取消由 ctx 控制。
func ConsumeSSEWithRequest(ctx context.Context, req *http.Request) (bool, error) {
	if req == nil {
		return false, errors.New("SSE 请求为空")
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	} else {
		ctx = req.Context()
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/event-stream")
	}

	resp, err := sseClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("SSE 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("SSE 请求失败: 状态 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return consumeSSEReader(ctx, resp.Body)
}

// consumeSSEReader 从 r 逐行消费 SSE 帧：空行（或 EOF）派发已积累的帧，
// 命中终止帧返回 true；读到 EOF 仍无终止帧返回 ErrSSEIncomplete。
func consumeSSEReader(ctx context.Context, r io.Reader) (bool, error) {
	br := bufio.NewReader(r)
	var (
		event     string
		dataLines []string
	)
	dispatch := func() bool {
		terminal := isTerminalFrame(event, strings.Join(dataLines, "\n"))
		event = ""
		dataLines = dataLines[:0]
		return terminal
	}

	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		line, readErr := br.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimPrefix(line, "\uFEFF")
		switch {
		case line == "":
			if len(dataLines) > 0 || event != "" {
				if dispatch() {
					return true, nil
				}
			}
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data := strings.TrimPrefix(line, "data:")
			data = strings.TrimPrefix(data, " ")
			dataLines = append(dataLines, data)
		}
		if readErr == nil {
			continue
		}
		if readErr != io.EOF {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, ctxErr
			}
			return false, fmt.Errorf("%w: %v", ErrSSEIncomplete, readErr)
		}
		// EOF：仍有未派发帧则先判定，随后按「未见终止帧」报明确错误。
		if len(dataLines) > 0 || event != "" {
			if dispatch() {
				return true, nil
			}
		}
		return false, ErrSSEIncomplete
	}
}

// isTerminalFrame 判定终止帧：Chat 为 data: [DONE]（网关恒为裸帧），
// Anthropic/Responses 为 event 名或 data JSON 的 type 命中终止集合。
func isTerminalFrame(event, data string) bool {
	payload := strings.TrimSpace(data)
	if payload == "[DONE]" {
		return true
	}
	if sseTerminalTypes[event] {
		return true
	}
	if payload == "" {
		return false
	}
	var v struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(payload), &v) != nil {
		return false
	}
	return sseTerminalTypes[v.Type]
}
