// Package internal — 审批轮询（202 + E_PENDING）行为测试。
package internal

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestRegisterCallerRust202ShapeTerminal(t *testing.T) {
	approvalTestEnv(t)
	srv, _, count := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, pendingBody},
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
	if n := count(); n != 2 {
		t.Fatalf("应轮询 2 次，实际 %d", n)
	}
	if regID != "" {
		t.Fatalf("真实 Rust 202 形状与终态视图均无 reg_id，应为空串，实际 %q", regID)
	}
}

func TestRegisterCallerRust202ShapePendingNoWait(t *testing.T) {
	approvalTestEnv(t)
	ApprovalWait = false
	srv, _, count := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, pendingBody},
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
	if n := count(); n != 1 {
		t.Fatalf("关闭等待不得轮询，实际请求 %d 次", n)
	}
	if regID != "" {
		t.Fatalf("真实 Rust 202 形状无 reg_id，应为空串，实际 %q", regID)
	}
}

// TestRegisterCallerPythonBaselineRegIDFallback 覆盖 Python 基线（顶层 reg_id）回退路径（proxy.go 回退分支）；
// 该分支对 Rust 服务器恒不命中，仅保留兼容。
func TestRegisterCallerPythonBaselineRegIDFallback(t *testing.T) {
	approvalTestEnv(t)
	srv, _, _ := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, `{"reg_id":"reg-python-001","status":"pending","error":{"code":"E_PENDING","message":"注册已转 Matrix 人工审批"}}`},
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
	if regID != "reg-python-001" {
		t.Fatalf("Python 基线应回退受理响应顶层 reg_id，实际 %q", regID)
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

// TestParseDurationEnvFallbackWarns300s 锁定 H-1：非法时长按文档默认回退 300s，并向 stderr 告警（非 fail-fast）。
func TestParseDurationEnvFallbackWarns300s(t *testing.T) {
	t.Setenv("TEST_DUR_INVALID", "5min")

	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建 stderr 管道失败: %v", err)
	}
	os.Stderr = w
	got := parseDurationEnv("TEST_DUR_INVALID", "300", 300*time.Second)
	os.Stderr = origStderr
	if err := w.Close(); err != nil {
		t.Fatalf("关闭 stderr 管道失败: %v", err)
	}
	out, _ := io.ReadAll(r)

	if got != 300*time.Second {
		t.Fatalf("非法时长应回退文档默认 300s，实际 %v", got)
	}
	if !strings.Contains(string(out), "TEST_DUR_INVALID") {
		t.Fatalf("非法时长回退应输出 stderr 告警（含变量名），实际: %q", string(out))
	}
}

// TestApprovalPollIntervalClamped 锁定 approval.go 的非正轮询间隔钳制：
// 长超时下非正间隔必须被钳制为 2s 下界——恰好一次休眠且休眠参数为 2s。
// 若钳制被删，休眠参数退化为 0（slept[0] == 0）而失败，具备判别力。
func TestApprovalPollIntervalClamped(t *testing.T) {
	approvalTestEnv(t)
	approvalPollInterval = 0
	approvalTimeout = 30 * time.Second

	var slept []time.Duration
	sleepFn = func(d time.Duration) { slept = append(slept, d) }

	srv, _, count := newScriptedServer(t, []scriptedResponse{
		{http.StatusAccepted, pendingBody},
		{http.StatusOK, `{"status":"revoked","name":"check-mail"}`},
	})
	ProxyURL = srv.URL

	if err := RevokeCaller("check-mail"); err != nil {
		t.Fatalf("批准后应返回 nil，实际: %v", err)
	}
	if n := count(); n != 2 {
		t.Fatalf("应轮询 2 次，实际请求数 %d", n)
	}
	if len(slept) != 1 {
		t.Fatalf("应恰好休眠一次，实际 %d 次: %v", len(slept), slept)
	}
	if slept[0] != 2*time.Second {
		t.Fatalf("非正间隔必须钳制为 2s 下界（approval.go 钳制），实际休眠 %v", slept[0])
	}
}
