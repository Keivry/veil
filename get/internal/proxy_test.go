// Package internal — unit tests for Proxy HTTP client
package internal

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestGetEnvDefault(t *testing.T) {
	os.Unsetenv("TEST_PROXY_VAR")
	result := getEnv("TEST_PROXY_VAR", "fallback_val")
	if result != "fallback_val" {
		t.Fatalf("expected fallback, got %q", result)
	}
}

func TestGetEnvOverride(t *testing.T) {
	os.Setenv("TEST_PROXY_VAR", "override_val")
	defer os.Unsetenv("TEST_PROXY_VAR")

	result := getEnv("TEST_PROXY_VAR", "fallback")
	if result != "override_val" {
		t.Fatalf("expected override_val, got %q", result)
	}
}

func TestGetEnvEmptyFallback(t *testing.T) {
	os.Unsetenv("TEST_PROXY_VAR_EMPTY")
	result := getEnv("TEST_PROXY_VAR_EMPTY", "")
	if result != "" {
		t.Fatalf("expected empty, got %q", result)
	}
}

func TestGetEnvEmptyEnvVar(t *testing.T) {
	os.Setenv("TEST_PROXY_VAR_EMPTY2", "")
	defer os.Unsetenv("TEST_PROXY_VAR_EMPTY2")

	result := getEnv("TEST_PROXY_VAR_EMPTY2", "fallback")
	if result != "fallback" {
		t.Fatalf("expected fallback for empty env, got %q", result)
	}
}

func TestProxyURLDefault(t *testing.T) {
	orig := ProxyURL
	defer func() { ProxyURL = orig }()

	os.Unsetenv("PROXY_URL")
	ProxyURL = getEnv("PROXY_URL", "http://127.0.0.1:8877")
	if ProxyURL != "http://127.0.0.1:8877" {
		t.Fatalf("unexpected default ProxyURL: %q", ProxyURL)
	}
}

func TestProxyURLOverride(t *testing.T) {
	orig := ProxyURL
	defer func() { ProxyURL = orig }()

	os.Setenv("PROXY_URL", "http://custom:9999")
	defer os.Unsetenv("PROXY_URL")

	ProxyURL = getEnv("PROXY_URL", "http://127.0.0.1:8877")
	if ProxyURL != "http://custom:9999" {
		t.Fatalf("expected override, got %q", ProxyURL)
	}
}

func TestCredentialRequestMarshal(t *testing.T) {
	req := CredentialRequest{
		Entry: "test_entry",
		Field: "password",
		Token: true,
		Auth:  map[string]string{"caller_hash": "sha256:abc"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed["entry"] != "test_entry" {
		t.Errorf("expected test_entry, got %v", parsed["entry"])
	}
	if parsed["field"] != "password" {
		t.Errorf("expected password, got %v", parsed["field"])
	}
	if parsed["token"] != true {
		t.Errorf("expected token=true, got %v", parsed["token"])
	}
}

func TestCredentialResponseUnmarshal(t *testing.T) {
	jsonStr := `{"value":"__VG_CRED_0001__","title":"网易"}`
	var resp CredentialResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Value != "__VG_CRED_0001__" {
		t.Errorf("expected __VG_CRED_0001__, got %q", resp.Value)
	}
	if resp.Title != "网易" {
		t.Errorf("expected 网易, got %q", resp.Title)
	}
}

func TestCredentialResponseUnmarshalGatewayEnvelope(t *testing.T) {
	jsonStr := `{"ok":true,"credential":{"title":"网易","username":"mail-user","password":"__VG_CRED_000002__","url":"https://mail.example.com","custom_properties":{"授权码":"__VG_CRED_000001__","备注":"plain-note"}}}`
	var resp CredentialResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Title != "网易" {
		t.Errorf("expected 网易, got %q", resp.Title)
	}
	if resp.Username != "mail-user" {
		t.Errorf("expected mail-user, got %q", resp.Username)
	}
	if resp.Password != "__VG_CRED_000002__" {
		t.Errorf("expected password placeholder, got %q", resp.Password)
	}
	if resp.URL != "https://mail.example.com" {
		t.Errorf("expected url, got %q", resp.URL)
	}
	if resp.CustomProperties["授权码"] != "__VG_CRED_000001__" {
		t.Errorf("expected 授权码 placeholder, got %q", resp.CustomProperties["授权码"])
	}
	if resp.CustomProperties["备注"] != "plain-note" {
		t.Errorf("expected 备注 plain-note, got %q", resp.CustomProperties["备注"])
	}
	if resp.Error != "" {
		t.Errorf("expected empty error on success envelope, got %q", resp.Error)
	}
}

func TestCredentialResponseUnmarshalGatewayEnvelopeSingleField(t *testing.T) {
	jsonStr := `{"ok":true,"credential":{"value":"authcode-abc-123"}}`
	var resp CredentialResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Value != "authcode-abc-123" {
		t.Errorf("expected raw value, got %q", resp.Value)
	}
}

func TestRegisterCallerRequestMarshal(t *testing.T) {
	req := RegisterCallerRequest{
		Name:       "test-script",
		ScriptPath: "/tmp/test.py",
		ScriptHash: "sha256:def456",
		Entries:    map[string][]string{"网易": {"password"}},
		AllowMode:  "auto",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed["name"] != "test-script" {
		t.Errorf("expected test-script, got %v", parsed["name"])
	}
	if parsed["allow_mode"] != "auto" {
		t.Errorf("expected auto, got %v", parsed["allow_mode"])
	}
}

func TestRevokeRequestMarshal(t *testing.T) {
	req := RevokeRequest{Name: "test-script"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["name"] != "test-script" {
		t.Errorf("expected test-script, got %v", parsed["name"])
	}
}

func TestRevokeResponseUnmarshal(t *testing.T) {
	jsonStr := `{"status":"revoked","name":"test-script"}`
	var resp RevokeResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Status != "revoked" {
		t.Errorf("expected revoked, got %q", resp.Status)
	}
	if resp.Name != "test-script" {
		t.Errorf("expected test-script, got %q", resp.Name)
	}
}

func TestErrMessageUnmarshal(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want ErrMessage
	}{
		{"字符串形态（Python 基线）", `"鉴权失败"`, "鉴权失败"},
		{"对象形态取 message", `{"code":"E_AUTH","message":"调用方冒用 get 自身哈希直调，拒绝"}`, "调用方冒用 get 自身哈希直调，拒绝"},
		{"对象缺 message 回退 code", `{"code":"E_AUTH"}`, "E_AUTH"},
		{"null 保持空", `null`, ""},
		{"空对象留空待结构级兜底", `{}`, ""},
		{"非法形态给占位", `123`, "unknown error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got ErrMessage
			if err := json.Unmarshal([]byte(tc.raw), &got); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func errorField(v interface{}) ErrMessage {
	switch r := v.(type) {
	case *CredentialResponse:
		return r.Error
	case *RegisterCallerResponse:
		return r.Error
	case *RevokeResponse:
		return r.Error
	case *ListResponse:
		return r.Error
	case *ProxyStatus:
		return r.Error
	default:
		return ""
	}
}

func TestResponseErrorBodyTolerance(t *testing.T) {
	gatewayBody := `{"error":{"code":"E_AUTH","message":"调用方冒用 get 自身哈希直调，拒绝"},"error_detail":"调用方冒用 get 自身哈希直调，拒绝"}`
	pythonBody := `{"error":"旧版字符串错误"}`

	targets := []struct {
		name   string
		target interface{}
	}{
		{"CredentialResponse", &CredentialResponse{}},
		{"RegisterCallerResponse", &RegisterCallerResponse{}},
		{"RevokeResponse", &RevokeResponse{}},
		{"ListResponse", &ListResponse{}},
		{"ProxyStatus", &ProxyStatus{}},
	}
	for _, tc := range targets {
		t.Run(tc.name+"/网关对象错误体", func(t *testing.T) {
			if err := json.Unmarshal([]byte(gatewayBody), tc.target); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got := errorField(tc.target); got != "调用方冒用 get 自身哈希直调，拒绝" {
				t.Fatalf("got %q, want gateway message", got)
			}
		})
		t.Run(tc.name+"/Python 字符串错误体", func(t *testing.T) {
			if err := json.Unmarshal([]byte(pythonBody), tc.target); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got := errorField(tc.target); got != "旧版字符串错误" {
				t.Fatalf("got %q, want 旧版字符串错误", got)
			}
		})
	}
}

func TestResponseErrorDetailFallback(t *testing.T) {
	cases := []struct {
		name string
		body string
		want ErrMessage
	}{
		{"error 空对象回退 error_detail", `{"error":{},"error_detail":"顶层详情镜像"}`, "顶层详情镜像"},
		{"error 空串回退 error_detail", `{"error":"","error_detail":"顶层详情镜像"}`, "顶层详情镜像"},
		{"对象缺 message 时 detail 优先于 code", `{"error":{"code":"E_AUTH"},"error_detail":"Secret 校验失败"}`, "Secret 校验失败"},
		{"对象仅有 code 时用 code 兜底", `{"error":{"code":"E_AUTH"}}`, "E_AUTH"},
		{"空对象无 detail 给占位", `{"error":{}}`, "unknown error"},
		{"成功响应无 error 保持空", `{"value":"v1"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp CredentialResponse
			if err := json.Unmarshal([]byte(tc.body), &resp); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if resp.Error != tc.want {
				t.Fatalf("got %q, want %q", resp.Error, tc.want)
			}
		})
	}
}

func TestFetchCredentialErrorBodyCompat(t *testing.T) {
	orig := ProxyURL
	defer func() { ProxyURL = orig }()

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "网关对象错误体",
			body: `{"error":{"code":"E_AUTH","message":"调用方冒用 get 自身哈希直调，拒绝"},"error_detail":"调用方冒用 get 自身哈希直调，拒绝"}`,
			want: "调用方冒用 get 自身哈希直调，拒绝",
		},
		{
			name: "Python 字符串错误体",
			body: `{"error":"请输入 master password"}`,
			want: "请输入 master password",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			ProxyURL = srv.URL

			result, err := FetchCredential("网易", "password", false, nil)
			if err == nil {
				t.Fatal("expected error on 403")
			}
			if result == nil || result.Error != ErrMessage(tc.want) {
				t.Fatalf("expected Error=%q, got %+v", tc.want, result)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error text to carry %q, got %v", tc.want, err)
			}
		})
	}
}
