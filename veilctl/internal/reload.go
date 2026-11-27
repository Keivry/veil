// Package internal — KeePass 库热重载客户端。
package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// ReloadAdminTokenEnv 管理面 token 环境变量名。
//
// 仅属于 veilctl 客户端，与服务端 env 白名单互不相干；值原样写入
// `X-Admin-Token` 请求头，SHALL NOT 打印。
const ReloadAdminTokenEnv = "PROXY_ADMIN_TOKEN"

// ReloadResponse POST /reload 成功响应。
//
// DBPath 用指针：Mock 后端无持久库时服务端返回 null，需与「空路径」区分。
type ReloadResponse struct {
	Ok                bool       `json:"ok"`
	DBPath            *string    `json:"db_path"`
	TokensInvalidated int        `json:"tokens_invalidated"`
	ElapsedMs         int        `json:"elapsed_ms"`
	Error             ErrMessage `json:"error,omitempty"`
}

// UnmarshalJSON 解析响应并归一化错误消息（兼容网关对象与 Python 字符串错误体）。
func (r *ReloadResponse) UnmarshalJSON(data []byte) error {
	type plain ReloadResponse
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*r = ReloadResponse(p)
	normalizeErrorMessage(data, &r.Error)
	return nil
}

// Reload 触发 Proxy 的 KeePass 库热重载（POST /reload，无请求体）。
//
// 鉴权仅取 ReloadAdminTokenEnv 环境变量：为空时在发起任何请求前返回错误，
// 避免把无鉴权请求打到网上。非 2xx 返回错误并携带网关错误消息。
func Reload() (*ReloadResponse, error) {
	token := os.Getenv(ReloadAdminTokenEnv)
	if token == "" {
		return nil, fmt.Errorf("未设置 %s 环境变量（用于 X-Admin-Token 鉴权），拒绝发送重载请求", ReloadAdminTokenEnv)
	}

	req, err := http.NewRequest(http.MethodPost, ProxyURL+"/reload", nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("X-Admin-Token", token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close() // nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var result ReloadResponse
	if len(respBody) > 0 {
		if uerr := json.Unmarshal(respBody, &result); uerr != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil, fmt.Errorf("解析响应失败: %w", uerr)
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := result.Error
		if msg == "" {
			msg = ErrMessage(http.StatusText(resp.StatusCode))
		}
		return nil, fmt.Errorf("重载失败 (%d): %s", resp.StatusCode, msg)
	}

	return &result, nil
}
