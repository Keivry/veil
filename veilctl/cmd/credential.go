// Package cmd — veilctl credential 子命令
package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"veilctl/internal"
)

// Credential 获取凭据
// Usage: veilctl credential <条目> [字段] [--raw] [--no-wait]
func Credential(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "用法: veilctl credential <条目> [字段] [--raw] [--no-wait]")
		os.Exit(1)
	}

	entry := args[0]
	field := ""
	raw := false

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--raw":
			raw = true
		case "--no-wait":
			internal.ApprovalWait = false
		default:
			if field == "" {
				field = args[i]
			}
		}
	}

	// 构建 auth 对象
	auth := internal.BuildAuth()

	// ── 安全：禁止终端直接调用 --raw ──
	// 当 caller_hash == veilctl_binary_hash 时，表示 veilctl 被终端/bash 直接调用
	// （而不是从脚本中通过 subprocess.run 调用）。此时 --raw 应被拒绝，
	// 强制用户通过脚本文件获取原始凭据，防止 LLM 上下文直接接触明文。
	if raw {
		callerHash := auth["caller_hash"]
		binaryHash := auth["veilctl_binary_hash"]
		if callerHash != "" && callerHash == binaryHash {
			fmt.Fprintln(os.Stderr, "错误: --raw 只允许在脚本文件中使用。")
			fmt.Fprintln(os.Stderr, "请在脚本内通过 subprocess.run 调用 get，而不是直接在终端输入。")
			os.Exit(1)
		}
	}

	result, err := internal.FetchCredential(entry, field, raw, auth)
	if err != nil {
		if errors.Is(err, internal.ErrPendingApproval) {
			fmt.Fprintln(os.Stderr, "⌛ 取用已转人工审批：", err)
			fmt.Fprintln(os.Stderr, "   在 Matrix 批准后重试同一命令即可（服务端幂等复用既有单据，不重复建单）。")
			os.Exit(2)
		}
		if result != nil && result.Error != "" {
			fmt.Fprintln(os.Stderr, "错误:", result.Error)
		} else {
			fmt.Fprintln(os.Stderr, "错误:", err)
		}
		os.Exit(1)
	}

	if field != "" {
		fmt.Println(result.Value)
	} else {
		// 完整条目模式
		fmt.Printf("标题: %s\n", result.Title)
		fmt.Printf("用户名: %s\n", result.Username)
		fmt.Printf("密码: %s\n", result.Password)
		fmt.Printf("URL: %s\n", result.URL)
		keys := make([]string, 0, len(result.CustomProperties))
		for k := range result.CustomProperties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%s: %s\n", k, result.CustomProperties[k])
		}
	}
}
