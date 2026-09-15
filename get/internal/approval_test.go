// Package internal — 审批轮询（202 + E_PENDING）行为测试。
package internal

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const pendingBody = `{"error":{"code":"E_PENDING","message":"已转 Matrix 人工审批"}}`

type scriptedResponse struct {
	status int
	body   string
}

// approvalTestEnv 快进轮询并恢复被覆盖的包级变量。
func approvalTestEnv(t *testing.T) {
	t.Helper()
	origURL, origWait := ProxyURL, ApprovalWait
	origTimeout, origInterval, origSleep := approvalTimeout, approvalPollInterval, sleepFn
	t.Cleanup(func() {
		ProxyURL, ApprovalWait = origURL, origWait
		approvalTimeout, approvalPollInterval, sleepFn = origTimeout, origInterval, origSleep
	})
	ApprovalWait = true
	approvalTimeout = time.Minute
	approvalPollInterval = time.Millisecond
	sleepFn = func(time.Duration) {}
}

// newScriptedServer 按序返回脚本化响应（超出后重复末条），并记录每次请求体。
func newScriptedServer(t *testing.T, responses []scriptedResponse) (*httptest.Server, func() []string, func() int) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		idx := len(bodies) - 1
		mu.Unlock()
		if idx >= len(responses) {
			idx = len(responses) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(responses[idx].status)
		_, _ = io.WriteString(w, responses[idx].body)
	}))
	t.Cleanup(srv.Close)
	return srv,
		func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), bodies...) },
		func() int { mu.Lock(); defer mu.Unlock(); return len(bodies) }
}

func TestErrCodeAndIsPending(t *testing.T) {
	if got := errCode([]byte(pendingBody)); got != PendingCode {
		t.Fatalf("errCode = %q, want %q", got, PendingCode)
	}
	if !isPending(http.StatusAccepted, []byte(`{}`)) {
		t.Fatal("202 应判定为待审批")
	}
	if !isPending(http.StatusOK, []byte(pendingBody)) {
		t.Fatal("错误码 E_PENDING 应判定为待审批")
	}
	if isPending(http.StatusOK, []byte(`{"value":"v"}`)) {
		t.Fatal("普通成功不得判定为待审批")
	}
	if isPending(http.StatusForbidden, []byte(`{"error":{"code":"E_AUTH","message":"拒绝"}}`)) {
		t.Fatal("业务错误不得判定为待审批")
	}
}

func TestRevokeCallerWaitsForApprovalTerminalSuccess(t *testing.T) {
	approvalTestEnv(t)
	srv, bodies, count := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, pendingBody},
		{http.StatusOK, `{"status":"revoked","name":"check-mail"}`},
	})
	ProxyURL = srv.URL

	if err := RevokeCaller("check-mail"); err != nil {
		t.Fatalf("批准后应返回 nil，实际: %v", err)
	}
	if n := count(); n != 2 {
		t.Fatalf("应轮询 2 次，实际 %d", n)
	}
	list := bodies()
	if len(list) != 2 || list[0] != list[1] {
		t.Fatalf("轮询必须重发同一请求体（幂等复用既有票），实际: %v", list)
	}
}

func TestRevokeCallerPendingTimeoutDoesNotHang(t *testing.T) {
	approvalTestEnv(t)
	approvalTimeout = 0
	srv, _, count := newScriptedServer(t, []scriptedResponse{{http.StatusAccepted, pendingBody}})
	ProxyURL = srv.URL

	if err := RevokeCaller("check-mail"); !errors.Is(err, ErrPendingApproval) {
		t.Fatalf("超时应返回 ErrPendingApproval，实际: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("超时不得继续轮询，实际请求 %d 次", n)
	}
}

func TestRevokeCallerNoWaitSubmitsOnce(t *testing.T) {
	approvalTestEnv(t)
	ApprovalWait = false
	srv, _, count := newScriptedServer(t, []scriptedResponse{{http.StatusAccepted, pendingBody}})
	ProxyURL = srv.URL

	if err := RevokeCaller("check-mail"); !errors.Is(err, ErrPendingApproval) {
		t.Fatalf("关闭等待应返回 ErrPendingApproval，实际: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("关闭等待不得轮询，实际请求 %d 次", n)
	}
}

func TestRevokeCallerDeniedAfterPendingIsTerminalError(t *testing.T) {
	approvalTestEnv(t)
	srv, _, _ := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, pendingBody},
		{http.StatusForbidden, `{"error":{"code":"E_AUTH","message":"吊销审批被拒绝"}}`},
	})
	ProxyURL = srv.URL

	err := RevokeCaller("check-mail")
	if err == nil || !strings.Contains(err.Error(), "吊销审批被拒绝") {
		t.Fatalf("拒绝应报错并携带服务端消息，实际: %v", err)
	}
	if errors.Is(err, ErrPendingApproval) {
		t.Fatal("拒绝是终态，不得报告为待审批")
	}
}

func TestBlockingModeSingleRequest(t *testing.T) {
	approvalTestEnv(t)
	srv, _, count := newScriptedServer(t, []scriptedResponse{{http.StatusOK, `{"status":"revoked","name":"n"}`}})
	ProxyURL = srv.URL

	if err := RevokeCaller("n"); err != nil {
		t.Fatalf("阻塞模式应一次成功，实际: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("阻塞模式不得轮询，实际请求 %d 次", n)
	}
}

func TestFetchCredentialWaitsForApproval(t *testing.T) {
	approvalTestEnv(t)
	srv, _, count := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, pendingBody},
		{http.StatusOK, `{"ok":true,"credential":{"value":"secret-token"}}`},
	})
	ProxyURL = srv.URL

	res, err := FetchCredential("网易", "password", true, nil)
	if err != nil {
		t.Fatalf("批准后应成功，实际: %v", err)
	}
	if res.Value != "secret-token" {
		t.Fatalf("value = %q, want secret-token", res.Value)
	}
	if n := count(); n != 2 {
		t.Fatalf("应轮询 2 次，实际 %d", n)
	}
}

func TestRegisterCallerKeepsRegIDAfterApproval(t *testing.T) {
	approvalTestEnv(t)
	srv, _, _ := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, `{"reg_id":"reg-001","status":"pending","error":{"code":"E_PENDING","message":"注册已转 Matrix 人工审批"}}`},
		{http.StatusOK, `{"type":"script","name":"check-mail","allow_mode":"auto","enabled":true}`},
	})
	ProxyURL = srv.URL

	regID, err := RegisterCaller(&RegisterCallerRequest{
		Name:       "check-mail",
		ScriptPath: "/tmp/x.py",
		ScriptHash: "sha256:abc",
		Entries:    map[string][]string{"网易": {}},
	})
	if err != nil {
		t.Fatalf("批准后应成功，实际: %v", err)
	}
	if regID != "reg-001" {
		t.Fatalf("终态响应无 reg_id 时应回退受理单 ID，实际 %q", regID)
	}
}

func TestRegisterCallerPendingReturnsRegIDAndSentinel(t *testing.T) {
	approvalTestEnv(t)
	ApprovalWait = false
	srv, _, _ := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, `{"reg_id":"reg-002","status":"pending","error":{"code":"E_PENDING","message":"注册已转 Matrix 人工审批"}}`},
	})
	ProxyURL = srv.URL

	regID, err := RegisterCaller(&RegisterCallerRequest{
		Name:       "check-mail",
		ScriptPath: "/tmp/x.py",
		ScriptHash: "sha256:abc",
	})
	if !errors.Is(err, ErrPendingApproval) {
		t.Fatalf("应返回 ErrPendingApproval，实际: %v", err)
	}
	if regID != "reg-002" {
		t.Fatalf("待审批应保留受理单 ID，实际 %q", regID)
	}
}

func TestDurationAndBoolEnvParsing(t *testing.T) {
	t.Setenv("TEST_DUR", "5m")
	if got := parseDurationEnv("TEST_DUR", "1", time.Second); got != 5*time.Minute {
		t.Fatalf("Duration 格式解析错误: %v", got)
	}
	t.Setenv("TEST_DUR", "45")
	if got := parseDurationEnv("TEST_DUR", "1", time.Second); got != 45*time.Second {
		t.Fatalf("纯秒数解析错误: %v", got)
	}
	t.Setenv("TEST_DUR", "garbage")
	if got := parseDurationEnv("TEST_DUR", "1", 7*time.Second); got != 7*time.Second {
		t.Fatalf("非法输入应回退默认值: %v", got)
	}

	t.Setenv("TEST_BOOL", "off")
	if parseBoolEnv("TEST_BOOL", true) {
		t.Fatal("off 应解析为假")
	}
	t.Setenv("TEST_BOOL", "YES")
	if !parseBoolEnv("TEST_BOOL", false) {
		t.Fatal("非关闭值应解析为真")
	}
}

func TestApprovalPollIntervalClamped(t *testing.T) {
	approvalTestEnv(t)
	approvalPollInterval = 0
	approvalTimeout = 50 * time.Millisecond
	sleepFn = time.Sleep
	srv, _, count := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, pendingBody},
	})
	ProxyURL = srv.URL

	if err := RevokeCaller("check-mail"); !errors.Is(err, ErrPendingApproval) {
		t.Fatalf("超时未决应返回 ErrPendingApproval，实际: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("非正间隔必须被钳制为安全下界（不得紧循环重发），实际请求数 %d", n)
	}
}
