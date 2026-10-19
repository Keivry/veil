// Package internal — SSE 消费真实网关 E2E（环境变量门控）
package internal

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestConsumeSSEAgainstGatewayE2E 消费真实网关 SSE 并断言终止帧。
// 需设置 VEIL_SSE_E2E_URL（如被审计阻断的流式端点）；未设置时跳过。
// 若同时设置 VEIL_SSE_E2E_BODY，则用 POST + 该 JSON 请求体
// （Content-Type: application/json，用于 LLM `POST /v1/chat/completions` 流式端点）；
// 否则退回 GET（保持既有入口）。
// 例: VEIL_SSE_E2E_URL=http://127.0.0.1:8877/v1/chat/completions go test -run E2E ./internal/
func TestConsumeSSEAgainstGatewayE2E(t *testing.T) {
	url := os.Getenv("VEIL_SSE_E2E_URL")
	if url == "" {
		t.Skip("未设置 VEIL_SSE_E2E_URL，跳过真实网关 SSE E2E")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		terminal bool
		err      error
	)
	if body := os.Getenv("VEIL_SSE_E2E_BODY"); body != "" {
		req, reqErr := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		if reqErr != nil {
			t.Fatalf("创建 SSE POST 请求失败: %v", reqErr)
		}
		req.Header.Set("Content-Type", "application/json")
		terminal, err = ConsumeSSEWithRequest(ctx, req)
	} else {
		terminal, err = ConsumeSSE(ctx, url)
	}
	if err != nil {
		t.Fatalf("消费 SSE 失败: %v", err)
	}
	if !terminal {
		t.Fatal("期望收到终止帧（terminal=true）")
	}
}
