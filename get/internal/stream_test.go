// Package internal — SSE 消费 helper 单测
package internal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// sseTestServer 起一个按给定帧序列回放的 SSE httptest 服务。
func sseTestServer(t *testing.T, frames ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for _, f := range frames {
			if _, err := io.WriteString(w, f); err != nil {
				return
			}
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConsumeSSEChatDone(t *testing.T) {
	srv := sseTestServer(t,
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
		"data: [DONE]\n\n",
	)

	terminal, err := ConsumeSSE(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if !terminal {
		t.Fatal("expected terminal=true for chat [DONE]")
	}
}

func TestConsumeSSEAnthropicMessageStop(t *testing.T) {
	srv := sseTestServer(t,
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	)

	terminal, err := ConsumeSSE(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if !terminal {
		t.Fatal("expected terminal=true for anthropic message_stop")
	}
}

func TestConsumeSSEResponsesFailed(t *testing.T) {
	srv := sseTestServer(t,
		"event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"r1\",\"status\":\"failed\"}}\n\n",
	)

	terminal, err := ConsumeSSE(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if !terminal {
		t.Fatal("expected terminal=true for responses response.failed")
	}
}

func TestConsumeSSEResponsesCompletedAndIncomplete(t *testing.T) {
	for _, typ := range []string{"response.completed", "response.incomplete"} {
		t.Run(typ, func(t *testing.T) {
			srv := sseTestServer(t,
				"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n",
				"event: "+typ+"\ndata: {\"type\":\""+typ+"\",\"response\":{\"id\":\"r1\"}}\n\n",
			)

			terminal, err := ConsumeSSE(context.Background(), srv.URL)
			if err != nil {
				t.Fatalf("consume failed: %v", err)
			}
			if !terminal {
				t.Fatalf("expected terminal=true for %s", typ)
			}
		})
	}
}

func TestConsumeSSEIncompleteWithoutTerminal(t *testing.T) {
	cases := []struct {
		name   string
		frames []string
	}{
		{
			name: "完整非终止帧后断流",
			frames: []string{
				"event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
			},
		},
		{
			name: "半帧中途断流",
			frames: []string{
				"event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
				"data: {\"partial\"",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := sseTestServer(t, tc.frames...)

			terminal, err := ConsumeSSE(context.Background(), srv.URL)
			if terminal {
				t.Fatal("expected terminal=false when no terminal frame")
			}
			if !errors.Is(err, ErrSSEIncomplete) {
				t.Fatalf("expected ErrSSEIncomplete, got %v", err)
			}
		})
	}
}

func TestConsumeSSEWithRequestPost(t *testing.T) {
	const body = `{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}`
	var (
		gotMethod string
		gotBody   string
		gotCT     string
		gotAccept string
		gotCustom string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotCustom = r.Header.Get("X-Test-Trace")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: {\"choices\":[]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Trace", "trace-post")

	terminal, err := ConsumeSSEWithRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("consume POST failed: %v", err)
	}
	if !terminal {
		t.Fatal("expected terminal=true for POST chat [DONE]")
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST upstream, got %s", gotMethod)
	}
	if gotBody != body {
		t.Fatalf("body not preserved: %q", gotBody)
	}
	if gotCT != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", gotCT)
	}
	if gotAccept != "text/event-stream" {
		t.Fatalf("expected Accept defaulted to text/event-stream, got %q", gotAccept)
	}
	if gotCustom != "trace-post" {
		t.Fatalf("expected custom header forwarded, got %q", gotCustom)
	}
}

func TestConsumeSSEWithRequestNilRequest(t *testing.T) {
	if _, err := ConsumeSSEWithRequest(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestConsumeSSEWithRequestNilHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	req := &http.Request{Method: http.MethodGet, URL: u}
	if req.Header != nil {
		t.Fatal("precondition: expected req.Header == nil")
	}

	terminal, err := ConsumeSSEWithRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("consume with nil header failed: %v", err)
	}
	if !terminal {
		t.Fatal("expected terminal=true for nil-header GET [DONE]")
	}
	if gotAccept != "text/event-stream" {
		t.Fatalf("expected Accept defaulted to text/event-stream, got %q", gotAccept)
	}
}

func TestSSEClientHasNoTotalTimeout(t *testing.T) {
	if sseClient.Timeout != 0 {
		t.Fatalf("sseClient must not set a total timeout (would truncate LLM long streams), got %v", sseClient.Timeout)
	}
}

func TestConsumeSSEStillGETCompatible(t *testing.T) {
	var gotMethod, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)

	terminal, err := ConsumeSSE(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("consume GET failed: %v", err)
	}
	if !terminal {
		t.Fatal("expected terminal=true for GET [DONE]")
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("expected GET upstream (backward compatible), got %s", gotMethod)
	}
	if gotAccept != "text/event-stream" {
		t.Fatalf("expected Accept text/event-stream, got %q", gotAccept)
	}
}

func TestConsumeSSEContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	terminal, err := ConsumeSSE(ctx, srv.URL)
	if terminal {
		t.Fatal("expected terminal=false on context timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestConsumeSSEHTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":{"code":"E_UNAVAILABLE","message":"KeePass 未解锁"},"error_detail":"KeePass 未解锁"}`)
	}))
	t.Cleanup(srv.Close)

	terminal, err := ConsumeSSE(context.Background(), srv.URL)
	if terminal {
		t.Fatal("expected terminal=false on HTTP error status")
	}
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "KeePass 未解锁") {
		t.Fatalf("expected status/message in error, got %v", err)
	}
}
