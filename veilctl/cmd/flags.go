// Package cmd — 子命令参数解析统一口径。
package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// newFlagSet 创建 `flag.ContinueOnError` 模式的子命令 FlagSet。
//
// 相对 `flag.ExitOnError`：解析错误不再由 flag 包直接以退出码 2 退出，
// 消除与「已受理未完成」（202 + E_PENDING）退出码 2 的语义冲突；
// 退出码统一由 parseFlags 决定。
func newFlagSet(name, usageLine string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, usageLine)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags 解析子命令参数并统一退出码：
//   - `-h`/`--help`（flag.ErrHelp）→ 退出 0（帮助是正常请求）；
//   - 其余解析错误 → 打印用法后退出 1；
//   - 退出码 2 专用于「已受理未完成」，SHALL NOT 用于参数错误。
//
// 解析失败时 flag 包已先输出错误消息并调用 fs.Usage 打印用法，无需重复打印。
func parseFlags(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}
}
