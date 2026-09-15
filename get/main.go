// Package main — CLI 入口：get credential <entry> [field]
package main

import (
	"fmt"
	"os"

	"github.com/keivry/credential-proxy/get/cmd"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	switch subcommand {
	case "credential":
		cmd.Credential(args)
	case "register":
		cmd.Register(args)
	case "revoke":
		cmd.Revoke(args)
	case "list":
		cmd.ListRegistrations(args)
	case "status":
		cmd.Status(args)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `用法:
  get credential <条目> [字段] [--raw] [--no-wait]    获取凭据
  get register --name <名称> --entry <条目> [--desc <描述>] [--auto] [--fields <字段,字段>] [--script-path <路径>] [--no-wait]  注册脚本
  get revoke --name <名称> [--no-wait]      吊销注册
  get list                                  列出注册
  get status                                Proxy 状态

环境变量:
  PROXY_URL                Proxy 地址（默认 http://127.0.0.1:8877）
  PROXY_HTTP_TIMEOUT       单次 HTTP 超时秒数（默认 300）
  PROXY_APPROVAL_WAIT      是否等待审批终态（默认 1；0 立即返回待审批）
  PROXY_APPROVAL_TIMEOUT   等待审批终态总时限（默认 300s，支持 5m / 300 两种写法）
  PROXY_APPROVAL_POLL      审批轮询起始间隔（默认 2s，逐次翻倍至 10s）

退出码:
  0  动作已完成
  1  失败（含审批被拒绝/超时）
  2  已受理待审批（202 + E_PENDING，动作未完成；重试同一命令幂等复用既有单据）
`)
}
