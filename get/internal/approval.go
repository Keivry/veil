// Package internal — 审批轮询机制。
//
// 服务端契约（与 Rust 网关 `credential-flow-parity` 一致）：
//
//   - 默认模式（未设 `CREDENTIAL_BLOCK_WAIT`）下需要人工审批的写操作返回
//     `202 + E_PENDING`，表示**已受理待审批**，不代表动作已完成；
//   - 未决期间重试同一请求经决策表幂等复用（不重复建单、不误 409）；
//   - 终态后重试返回终态：批准 → 成功；拒绝/超时 → `403`。
//
// 因此客户端在收到 `202 + E_PENDING` 后按退避轮询同一请求直至终态。
// `CREDENTIAL_BLOCK_WAIT=1` 时服务端直接阻塞返回终态，本机制自动退化为单次调用。
package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// PendingCode 服务端「已受理待审批」错误码。
const PendingCode = "E_PENDING"

// ErrPendingApproval 表示请求已受理但未在等待时限内落定终态。
//
// 语义：**受理 ≠ 完成**。调用方可稍后重试同一请求（服务端幂等复用既有票）；
// 批准后重试返回终态成功，拒绝/超时返回 `403`。
var ErrPendingApproval = errors.New("已受理待审批（202 + E_PENDING），未落定终态")

// ApprovalWait 是否轮询等待审批终态。
//
// 默认 `true`；`PROXY_APPROVAL_WAIT=0|false|no|off` 关闭；CLI `--no-wait` 亦覆盖。
// 关闭后首次收到待审批即返回 ErrPendingApproval。
var ApprovalWait = parseBoolEnv("PROXY_APPROVAL_WAIT", true)

// approvalTimeout 等待终态的总时限（`PROXY_APPROVAL_TIMEOUT`，默认 300s）。
var approvalTimeout = parseDurationEnv("PROXY_APPROVAL_TIMEOUT", "300", 30*time.Second)

// approvalPollInterval 轮询起始间隔（`PROXY_APPROVAL_POLL`，默认 2s，逐次翻倍）。
var approvalPollInterval = parseDurationEnv("PROXY_APPROVAL_POLL", "2", 2*time.Second)

// approvalPollMaxInterval 轮询间隔上限（退避封顶）。
const approvalPollMaxInterval = 10 * time.Second

// sleepFn 轮询休眠；测试可覆盖以消除真实等待。
var sleepFn = time.Sleep

// approvalResult 轮询结果。
type approvalResult struct {
	// Status 终态（或关闭等待/超时时的待审批态）HTTP 状态码。
	Status int
	// Body 最后一次响应体。
	Body []byte
	// Pending 首个 `202 + E_PENDING` 响应体；未经历待审批时为 nil。
	// 供调用方回退提取仅在受理响应中出现的字段（如注册 `reg_id`）。
	Pending []byte
}

// parseDurationEnv 解析时长类环境变量，支持 Go Duration（`1m30s`）与纯秒数（`300`）两种输入；
// 均无法解析时返回 def。
func parseDurationEnv(key, fallback string, def time.Duration) time.Duration {
	s := getEnv(key, fallback)
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	if d, err := time.ParseDuration(s + "s"); err == nil {
		return d
	}
	return def
}

// parseBoolEnv 解析布尔类环境变量：`0/false/no/off`（大小写与空白不敏感）为假，其余为真。
func parseBoolEnv(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// errCode 提取顶层 `error.code`（对象形态）；字符串形态或缺失时返回空串。
// ErrMessage 仅承载人类可读消息，错误码需独立提取方可判定 E_PENDING。
func errCode(raw []byte) string {
	var env struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Error) == 0 {
		return ""
	}
	var obj struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(env.Error, &obj); err != nil {
		return ""
	}
	return obj.Code
}

// isPending 判定响应是否为「已受理待审批」：状态码 `202` 或错误码 `E_PENDING`。
func isPending(status int, raw []byte) bool {
	return status == http.StatusAccepted || errCode(raw) == PendingCode
}

// postOnce 发送一次 JSON POST，返回状态码与完整响应体。
func postOnce(url string, data []byte) (int, []byte, error) {
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("读取响应失败: %w", err)
	}
	return resp.StatusCode, body, nil
}

// postJSON 发送 JSON POST 并按服务端审批契约轮询：
// 命中 `202 + E_PENDING` 且启用等待时，按退避重发**同一请求体**（幂等复用既有票）
// 直至终态或超出 approvalTimeout；关闭等待或超时未决返回 ErrPendingApproval。
//
// 仅传输层错误（连接/读取失败）返回非 ErrPendingApproval 的错误；
// 业务错误（`>=400`）由调用方按返回的状态码与响应体自行报告。
func postJSON(url string, data []byte) (approvalResult, error) {
	deadline := time.Now().Add(approvalTimeout)
	interval := approvalPollInterval
	if interval <= 0 {
		// 守护：非正间隔（如 `PROXY_APPROVAL_POLL=0` 或负值）会使休眠立即返回并紧循环重发，
		// 钳制回默认 2s 下界（仍受 deadline 约束）。
		interval = 2 * time.Second
	}
	var firstPending []byte

	for {
		status, body, err := postOnce(url, data)
		if err != nil {
			return approvalResult{}, err
		}
		if !isPending(status, body) {
			return approvalResult{Status: status, Body: body, Pending: firstPending}, nil
		}
		if firstPending == nil {
			firstPending = body
		}
		if !ApprovalWait {
			return approvalResult{Status: status, Body: body, Pending: firstPending}, ErrPendingApproval
		}
		// 下一次休眠将越过等待时限：不再空等，交回待审批态。
		if !time.Now().Add(interval).Before(deadline) {
			return approvalResult{Status: status, Body: body, Pending: firstPending}, ErrPendingApproval
		}
		sleepFn(interval)
		if interval < approvalPollMaxInterval {
			interval *= 2
			if interval > approvalPollMaxInterval {
				interval = approvalPollMaxInterval
			}
		}
	}
}
