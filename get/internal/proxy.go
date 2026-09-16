// Package internal — Proxy HTTP 客户端
package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ProxyURL 默认 Proxy 地址
var ProxyURL = getEnv("PROXY_URL", "http://127.0.0.1:8877")

// httpClientTimeoutSeconds 单次 HTTP 超时，可通过 PROXY_HTTP_TIMEOUT 环境变量覆盖。
// 支持 "300"（秒）或 "5m"（Go Duration 格式）两种输入；非法值回退文档默认 300s 并告警。
var httpClientTimeoutSeconds = parseDurationEnv("PROXY_HTTP_TIMEOUT", "300", 300*time.Second)

// httpClient 带超时的共享 HTTP 客户端
var httpClient = &http.Client{
	Timeout: httpClientTimeoutSeconds,
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ErrMessage 错误消息：容忍 Python 基线的字符串错误体与 Rust 网关的对象错误体。
//
// 网关错误体形如:
//
//	{"error":{"code":"E_AUTH","message":"..."},"error_detail":"..."}
//
// Python 基线形如:
//
//	{"error":"字符串"}
//
// 具名 string 类型保证既有 `result.Error != ""` 判断与 `%v`/`%s` 打印继续可用。
type ErrMessage string

// UnmarshalJSON 兼容解析两种错误体形态：
//   - 字符串：原样取值（Python 基线；null → 空串）；
//   - 对象：取 message，message 缺失时回退 code；两者皆空则留空，
//     由 normalizeErrorMessage 用顶层 error_detail 或占位兜底。
//
// 无法识别的形态（数字/数组等）不阻断整体响应解析，给 "unknown error" 占位保证可诊断。
func (e *ErrMessage) UnmarshalJSON(data []byte) error {
	// 形态一：JSON 字符串
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*e = ErrMessage(s)
		return nil
	}
	// 形态二：对象 {"code","message"}
	var obj struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		msg := obj.Message
		if msg == "" {
			msg = obj.Code
		}
		*e = ErrMessage(msg)
		return nil
	}
	*e = ErrMessage("unknown error")
	return nil
}

// normalizeErrorMessage 在业务字段解析后按原始报文重算错误消息，优先级：
// 对象形态 message → 顶层 error_detail → code → "unknown error"；
// 字符串空串同样回退 error_detail，再退占位。
// error 字段缺失或为 null（成功响应）时保持空串，不影响 2xx 正常路径。
func normalizeErrorMessage(raw []byte, msg *ErrMessage) {
	var env struct {
		Error       json.RawMessage `json:"error"`
		ErrorDetail string          `json:"error_detail"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return
	}
	if len(env.Error) == 0 || string(env.Error) == "null" {
		*msg = ""
		return
	}
	// 形态一：字符串（非空即为准）
	var s string
	if json.Unmarshal(env.Error, &s) != nil {
		// 形态二：对象，按 message → error_detail → code 回退
		var obj struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(env.Error, &obj) == nil {
			switch {
			case obj.Message != "":
				*msg = ErrMessage(obj.Message)
				return
			case env.ErrorDetail != "":
				*msg = ErrMessage(env.ErrorDetail)
				return
			case obj.Code != "":
				*msg = ErrMessage(obj.Code)
				return
			default:
				*msg = ErrMessage("unknown error")
				return
			}
		}
	} else if s != "" {
		*msg = ErrMessage(s)
		return
	}
	// 空串或非法形态：回退 error_detail；ErrMessage 已给的占位则保留
	if env.ErrorDetail != "" {
		*msg = ErrMessage(env.ErrorDetail)
		return
	}
	if *msg == "" {
		*msg = ErrMessage("unknown error")
	}
}

// CredentialRequest 向 Proxy 发送凭据请求
type CredentialRequest struct {
	Entry string            `json:"entry"`
	Field string            `json:"field,omitempty"`
	Token bool              `json:"token"`
	Auth  map[string]string `json:"auth,omitempty"`
}

// CredentialResponse Proxy 响应
type CredentialResponse struct {
	Value string     `json:"value,omitempty"`
	Error ErrMessage `json:"error,omitempty"`
	// 完整条目模式
	Title            string            `json:"title,omitempty"`
	Username         string            `json:"username,omitempty"`
	Password         string            `json:"password,omitempty"`
	URL              string            `json:"url,omitempty"`
	CustomProperties map[string]string `json:"custom_properties,omitempty"`
}

// UnmarshalJSON 解析响应并归一化错误消息：
//   - Rust 网关成功响应包成 {"ok":true,"credential":{...}}，取内层 credential；
//   - Python 基线为扁平 {"value":...}/{"title":...}，内层缺失时按扁平解析。
//
// 错误消息统一从顶层 error/error_detail 归一（兼容网关对象与 Python 字符串错误体）。
func (r *CredentialResponse) UnmarshalJSON(data []byte) error {
	payload := data
	var env struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal(data, &env); err == nil &&
		len(env.Credential) > 0 && string(env.Credential) != "null" {
		payload = env.Credential
	}
	type plain CredentialResponse
	var p plain
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	*r = CredentialResponse(p)
	normalizeErrorMessage(data, &r.Error)
	return nil
}

// FetchCredential 获取凭据。
//
// 默认模式下未放行调用方会转人工审批：首次返回 `202 + E_PENDING`（已建单待审批），
// 此时按退避轮询同一请求直至终态（批准 → 凭据，拒绝/超时 → `403`）；
// 关闭等待（`PROXY_APPROVAL_WAIT=0` / `--no-wait`）或超时未决返回 ErrPendingApproval。
func FetchCredential(entry, field string, raw bool, auth map[string]string) (*CredentialResponse, error) {
	body := CredentialRequest{
		Entry: entry,
		Token: !raw,
	}
	if field != "" {
		body.Field = field
	}
	if auth != nil {
		body.Auth = auth
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	res, perr := postJSON(ProxyURL+"/credential", data)

	var result CredentialResponse
	if len(res.Body) > 0 {
		if uerr := json.Unmarshal(res.Body, &result); uerr != nil && perr == nil {
			return nil, fmt.Errorf("解析响应失败: %w", uerr)
		}
	}
	if perr != nil {
		return &result, perr
	}
	if res.Status >= 400 {
		return &result, fmt.Errorf("状态 %d: %s", res.Status, result.Error)
	}

	return &result, nil
}

// RegisterCallerRequest 注册调用者
type RegisterCallerRequest struct {
	Name          string              `json:"name"`
	Description   string              `json:"description,omitempty"`
	ScriptPath    string              `json:"script_path"`
	ScriptHash    string              `json:"script_hash"`
	Entries       map[string][]string `json:"entries"`
	AllowMode     string              `json:"allow_mode"`
	CanAutoUnlock bool                `json:"can_auto_unlock,omitempty"`
	Auth          map[string]string   `json:"auth,omitempty"`
}

// RegisterCallerResponse Proxy 注册响应
type RegisterCallerResponse struct {
	RegID  string     `json:"reg_id"`
	Status string     `json:"status"`
	Error  ErrMessage `json:"error"`
}

// UnmarshalJSON 解析响应并归一化错误消息（兼容网关对象与 Python 字符串错误体）。
func (r *RegisterCallerResponse) UnmarshalJSON(data []byte) error {
	type plain RegisterCallerResponse
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*r = RegisterCallerResponse(p)
	normalizeErrorMessage(data, &r.Error)
	return nil
}

// RegisterCaller 注册调用者，返回注册单 ID。
//
// 默认模式下注册转人工审批：首次返回 `202 + E_PENDING`（已建单待审批），
// 此时按退避轮询同一请求直至终态（批准 → 注册生效，拒绝/超时 → `403`）；
// 关闭等待（`PROXY_APPROVAL_WAIT=0` / `--no-wait`）或超时未决返回 ErrPendingApproval。
//
// 受理单 ID 仅 Python 基线受理响应顶层携带 `reg_id`；Rust 网关 202 体为
// `{"error":{"code":"E_PENDING",…}}`，无 ID，此时返回空串。终态响应为注册视图
// （不含 `reg_id`）时回退 Python 基线受理响应中的 ID（该回退对 Rust 服务器恒不命中）；
// 服务端阻塞模式（`CREDENTIAL_BLOCK_WAIT=1`）下终态直接返回、无受理单，此时 ID 为空串。
func RegisterCaller(req *RegisterCallerRequest) (string, error) {
	req.Auth = BuildAuth()
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("序列化失败: %w", err)
	}

	res, perr := postJSON(ProxyURL+"/register-caller", data)

	var result RegisterCallerResponse
	if len(res.Body) > 0 {
		if uerr := json.Unmarshal(res.Body, &result); uerr != nil && perr == nil {
			return "", fmt.Errorf("解析响应失败: %w", uerr)
		}
	}
	regID := result.RegID
	if regID == "" && len(res.Pending) > 0 {
		// Python 基线兼容回退：受理单 ID 仅出现在受理响应顶层 `reg_id`。
		// Rust 服务器 202 体为 `{"error":{"code":"E_PENDING",…}}`，无 `reg_id`，
		// 故本回退对 Rust 服务器恒不命中，仅为 Python 基线保留。
		var accepted RegisterCallerResponse
		if json.Unmarshal(res.Pending, &accepted) == nil {
			regID = accepted.RegID
		}
	}
	if perr != nil {
		return regID, perr
	}
	if res.Status >= 400 {
		return "", fmt.Errorf("注册失败 (%d): %s", res.Status, result.Error)
	}
	return regID, nil
}

// RevokeRequest 吊销请求
type RevokeRequest struct {
	Name string            `json:"name"`
	Auth map[string]string `json:"auth,omitempty"`
}

// RevokeResponse 吊销响应
type RevokeResponse struct {
	Status string     `json:"status"`
	Name   string     `json:"name"`
	Error  ErrMessage `json:"error,omitempty"`
}

// UnmarshalJSON 解析响应并归一化错误消息（兼容网关对象与 Python 字符串错误体）。
func (r *RevokeResponse) UnmarshalJSON(data []byte) error {
	type plain RevokeResponse
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*r = RevokeResponse(p)
	normalizeErrorMessage(data, &r.Error)
	return nil
}

// RevokeCaller 吊销注册。
//
// 默认模式下吊销转人工审批：首次返回 `202 + E_PENDING`（已建单待审批），
// 此时按退避轮询同一请求直至终态（批准 → 吊销生效，拒绝/超时 → `403`）；
// 关闭等待（`PROXY_APPROVAL_WAIT=0` / `--no-wait`）或超时未决返回 ErrPendingApproval——
// **`202` 不代表吊销已完成**，调用方须据此重试或提示等待审批。
func RevokeCaller(name string) error {
	auth := BuildAuth()
	data, err := json.Marshal(RevokeRequest{Name: name, Auth: auth})
	if err != nil {
		return fmt.Errorf("序列化失败: %w", err)
	}

	res, perr := postJSON(ProxyURL+"/revoke", data)

	var result RevokeResponse
	if len(res.Body) > 0 {
		if uerr := json.Unmarshal(res.Body, &result); uerr != nil && perr == nil {
			return fmt.Errorf("解析响应失败: %w", uerr)
		}
	}
	if perr != nil {
		return perr
	}
	if res.Status >= 400 {
		return fmt.Errorf("吊销失败 (%d): %s", res.Status, result.Error)
	}
	return nil
}

// ListRegistrations 列出注册
type RegistrationItem struct {
	Name      string              `json:"name"`
	Type      string              `json:"type"`
	Entries   map[string][]string `json:"entries,omitempty"`
	AllowMode string              `json:"allow_mode"`
	Enabled   bool                `json:"enabled"`
}

type ListResponse struct {
	Registrations []RegistrationItem `json:"registrations,omitempty"`
	Error         ErrMessage         `json:"error,omitempty"`
}

// UnmarshalJSON 解析响应并归一化错误消息（兼容网关对象与 Python 字符串错误体）。
func (r *ListResponse) UnmarshalJSON(data []byte) error {
	type plain ListResponse
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*r = ListResponse(p)
	normalizeErrorMessage(data, &r.Error)
	return nil
}

func ListRegistrations() ([]RegistrationItem, error) {
	url := ProxyURL + "/registrations"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	for k, v := range AuthHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	var result ListResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("查询失败 (%d): %s", resp.StatusCode, result.Error)
	}
	return result.Registrations, nil
}

// ProxyStatus Proxy /health 响应
type ProxyStatus struct {
	Status     string     `json:"status"`
	Unlocked   bool       `json:"unlocked"`
	Pending    int        `json:"pending"`
	LlmSecrets int        `json:"llm_secrets"`
	Error      ErrMessage `json:"error,omitempty"`
}

// UnmarshalJSON 解析响应并归一化错误消息（兼容网关对象与 Python 字符串错误体）。
func (r *ProxyStatus) UnmarshalJSON(data []byte) error {
	type plain ProxyStatus
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*r = ProxyStatus(p)
	normalizeErrorMessage(data, &r.Error)
	return nil
}

func FetchStatus() (*ProxyStatus, error) {
	url := ProxyURL + "/health"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	for k, v := range AuthHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	var result ProxyStatus
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("查询失败 (%d): %s", resp.StatusCode, result.Error)
	}
	return &result, nil
}
