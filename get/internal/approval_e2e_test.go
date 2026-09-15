// Package internal — 审批流程真实网关 E2E（环境变量门控）。
package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
)

// TestApprovalRevokeAgainstGatewayE2E 校验默认 `202 + E_PENDING` 审批语义对真实网关的判别力。
//
// 破坏性声明：本用例会向网关提交对 `VEIL_APPROVAL_E2E_CALLER` 的**真实吊销审批单**
// （等价 `get revoke --name <caller>`），只可指向一次性/预发注册；请勿指向生产条目。
//
// 判别方式：先以客户端相同的请求体与 `Content-Type: application/json` 裸发一次
// `POST /revoke` 取得原始状态码，再关闭等待（`ApprovalWait=false`）调用公开的
// `RevokeCaller`，按原始状态码断言：
//   - 原始 `202` → 客户端必须返回 `ErrPendingApproval`（`202` 不代表吊销完成），不得为 nil；
//   - 其他 `2xx` → 客户端必须返回 nil；
//   - `>= 400` → 客户端必须返回非 nil 业务错误，且不得是 `ErrPendingApproval`。
//
// 旧缺陷（把 `202` 当成功返回 nil）会在 `202` 分支失败，故本用例可对旧行为判别。
// 例: VEIL_APPROVAL_E2E_URL=http://127.0.0.1:8877 \
//
//	VEIL_APPROVAL_E2E_CALLER=e2e-disposable go test -run ApprovalRevokeAgainstGatewayE2E ./internal/
func TestApprovalRevokeAgainstGatewayE2E(t *testing.T) {
	base := os.Getenv("VEIL_APPROVAL_E2E_URL")
	caller := os.Getenv("VEIL_APPROVAL_E2E_CALLER")
	if base == "" || caller == "" {
		t.Skip("未同时设置 VEIL_APPROVAL_E2E_URL 与 VEIL_APPROVAL_E2E_CALLER，跳过审批流程真实网关 E2E")
	}

	origURL, origWait := ProxyURL, ApprovalWait
	t.Cleanup(func() { ProxyURL, ApprovalWait = origURL, origWait })
	ProxyURL = base

	data, err := json.Marshal(RevokeRequest{Name: caller, Auth: BuildAuth()})
	if err != nil {
		t.Fatalf("构造吊销请求体失败: %v", err)
	}
	raw, err := http.Post(base+"/revoke", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("裸发吊销请求失败: %v", err)
	}
	defer raw.Body.Close()
	rawStatus := raw.StatusCode

	ApprovalWait = false
	clientErr := RevokeCaller(caller)

	switch {
	case rawStatus == http.StatusAccepted:
		if !errors.Is(clientErr, ErrPendingApproval) {
			t.Fatalf("原始 %d → 客户端必须返回 ErrPendingApproval（202 不代表完成），实际: %v", rawStatus, clientErr)
		}
	case rawStatus >= 200 && rawStatus < 300:
		if clientErr != nil {
			t.Fatalf("原始 %d → 客户端应返回 nil，实际: %v", rawStatus, clientErr)
		}
	case rawStatus >= 400:
		if clientErr == nil {
			t.Fatalf("原始 %d → 客户端应返回业务错误，实际 nil", rawStatus)
		}
		if errors.Is(clientErr, ErrPendingApproval) {
			t.Fatalf("原始 %d 为业务错误，不得报告为 ErrPendingApproval，实际: %v", rawStatus, clientErr)
		}
	default:
		t.Fatalf("原始状态码非预期: %d", rawStatus)
	}
}
