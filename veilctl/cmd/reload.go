// Package cmd — veilctl reload 子命令
package cmd

import (
	"fmt"
	"os"

	"veilctl/internal"
)

// Reload 触发 Proxy 的 KeePass 库热重载
// Usage: veilctl reload
func Reload(args []string) {
	_ = args // 本子命令无参数，不提供 --token（token 只走 PROXY_ADMIN_TOKEN）

	res, err := internal.Reload()
	if err != nil {
		fmt.Fprintln(os.Stderr, "重载失败:", err)
		os.Exit(1)
	}

	dbPath := "null（Mock 后端无持久库）"
	if res.DBPath != nil {
		dbPath = *res.DBPath
	}
	fmt.Println("✅ 重载完成")
	fmt.Printf("  ok: %t\n", res.Ok)
	fmt.Printf("  库文件: %s\n", dbPath)
	fmt.Printf("  作废 token: %d\n", res.TokensInvalidated)
	fmt.Printf("  耗时: %d ms\n", res.ElapsedMs)
}
