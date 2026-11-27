// Package internal — unit tests for the KeePass reload client
package internal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withReloadServer 起一个 httptest 服务并临时覆盖 ProxyURL，测试结束自动还原。
func withReloadServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	orig := ProxyURL
	srv := httptest.NewServer(handler)
	t.Cleanup(func() {
		srv.Close()
		ProxyURL = orig
	})
	ProxyURL = srv.URL
	return srv
}

func TestReloadSuccess(t *testing.T) {
	var gotMethod, gotToken string
	withReloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotToken = r.Header.Get("X-Admin-Token")
		w.Header().Set("Content-Type", "application/json")
		// nolint:errcheck, ignore write error on test server
		_, _ = io.WriteString(w, `{"ok":true,"db_path":"/data/db/vault.kdbx","tokens_invalidated":7,"elapsed_ms":42}`)
	})

	setenv(t, ReloadAdminTokenEnv, "secret-admin-token")
	defer unsetenv(t, ReloadAdminTokenEnv)

	res, err := Reload()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected method POST, got %q", gotMethod)
	}
	if gotToken != "secret-admin-token" {
		t.Errorf("expected X-Admin-Token header, got %q", gotToken)
	}
	if !res.Ok {
		t.Errorf("expected ok=true, got false")
	}
	if res.DBPath == nil || *res.DBPath != "/data/db/vault.kdbx" {
		t.Errorf("expected db_path=/data/db/vault.kdbx, got %v", res.DBPath)
	}
	if res.TokensInvalidated != 7 {
		t.Errorf("expected tokens_invalidated=7, got %d", res.TokensInvalidated)
	}
	if res.ElapsedMs != 42 {
		t.Errorf("expected elapsed_ms=42, got %d", res.ElapsedMs)
	}
}

func TestReloadSuccessMockNullDBPath(t *testing.T) {
	withReloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// nolint:errcheck, ignore write error on test server
		_, _ = io.WriteString(w, `{"ok":true,"db_path":null,"tokens_invalidated":0,"elapsed_ms":1}`)
	})

	setenv(t, ReloadAdminTokenEnv, "secret-admin-token")
	defer unsetenv(t, ReloadAdminTokenEnv)

	res, err := Reload()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !res.Ok {
		t.Errorf("expected ok=true, got false")
	}
	if res.DBPath != nil {
		t.Errorf("expected db_path=null (nil), got %q", *res.DBPath)
	}
	if res.TokensInvalidated != 0 {
		t.Errorf("expected tokens_invalidated=0, got %d", res.TokensInvalidated)
	}
	if res.ElapsedMs != 1 {
		t.Errorf("expected elapsed_ms=1, got %d", res.ElapsedMs)
	}
}

func TestReloadHTTPErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "401 未鉴权",
			status: http.StatusUnauthorized,
			body:   `{"error":{"code":"E_UNAUTHORIZED","message":"鉴权失败：X-Admin-Token 缺失或无效"},"error_detail":"鉴权失败：X-Admin-Token 缺失或无效"}`,
			want:   "鉴权失败",
		},
		{
			name:   "409 多库或并发",
			status: http.StatusConflict,
			body:   `{"error":{"code":"E_CONFLICT","message":"多个密码库文件，候选: a.kdbx, b.kdbx"},"error_detail":"多个密码库文件，候选: a.kdbx, b.kdbx"}`,
			want:   "多个密码库文件",
		},
		{
			name:   "429 限流",
			status: http.StatusTooManyRequests,
			body:   `{"error":{"code":"E_RATE_LIMITED","message":"请求过于频繁，请稍后重试"},"error_detail":"请求过于频繁，请稍后重试"}`,
			want:   "请求过于频繁",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withReloadServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				// nolint:errcheck, ignore write error on test server
				_, _ = io.WriteString(w, tc.body)
			})

			setenv(t, ReloadAdminTokenEnv, "secret-admin-token")
			defer unsetenv(t, ReloadAdminTokenEnv)

			res, err := Reload()
			if err == nil {
				t.Fatalf("expected error on %d, got result %+v", tc.status, res)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error text to carry %q, got %v", tc.want, err)
			}
		})
	}
}

func TestReloadNetworkError(t *testing.T) {
	orig := ProxyURL
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ProxyURL = srv.URL
	srv.Close()
	defer func() { ProxyURL = orig }()

	setenv(t, ReloadAdminTokenEnv, "secret-admin-token")
	defer unsetenv(t, ReloadAdminTokenEnv)

	if _, err := Reload(); err == nil {
		t.Fatal("expected network error after server closed")
	}
}

func TestReloadMissingAdminToken(t *testing.T) {
	hit := false
	withReloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		hit = true
		t.Error("server must not be hit when PROXY_ADMIN_TOKEN is missing")
		w.WriteHeader(http.StatusOK)
	})

	unsetenv(t, ReloadAdminTokenEnv)

	if _, err := Reload(); err == nil {
		t.Fatal("expected error when PROXY_ADMIN_TOKEN is missing")
	} else if !strings.Contains(err.Error(), ReloadAdminTokenEnv) {
		t.Fatalf("expected error to name %s, got %v", ReloadAdminTokenEnv, err)
	}
	if hit {
		t.Fatal("server was hit despite missing PROXY_ADMIN_TOKEN")
	}
}
