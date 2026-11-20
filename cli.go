package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	reqPeekdata    = 2
	reqPokedata    = 5
	reqGetregs     = 12
	reqSetregs     = 13
	reqDetach      = 17
	reqSyscall     = 24
	reqSetoptions  = 0x4200
	reqGeteventmsg = 0x4201
	reqSeize       = 0x4206
	reqInterrupt   = 0x4207
	reqSyscallinfo = 0x420e

	optTracesysgood = 0x00000001
	optTracefork    = 0x00000002
	optTracevfork   = 0x00000004
	optTraceclone   = 0x00000008
	optTraceexec    = 0x00000010
	optExitkill     = 0x00100000

	evFork  = 1
	evVfork = 2
	evClone = 3
	evExec  = 4
	evStop  = 128

	sysOpen         = 2
	sysOpenat       = 257
	sysOpenat2      = 437
	sysOpenByHandle = 304
	pathMax         = 4096
	sysConnect      = 42
	sysSendto       = 44
	sysSendmsg      = 46
	sysSendmmsg     = 307
	sysExecve       = 59
	sysExecveat     = 322
	eacces          = 13
	eperm           = 1
	enoent          = 2
	enetunreach     = 101
)

var (
	logOnly   bool
	mainOnly  bool
	attachPid int
	debug     = os.Getenv("SH_DEBUG") != ""
	hits      int
	blocked   int
	fakeGot   int
	fdLeaks   int

	// 假 flag：默认关闭，--fake-flag <被保护路径> --decoy <诱饵文件>
	fakeFlags []string
	decoyPath string

	// 按进程名 attach
	attachNames []string

	// 出网限制：默认关闭，--block-out 开启，--allow-cidr 加白名单（回环永远放行）
	blockOut  bool
	allowNets []*net.IPNet
	learnSecs int
	allowFile string
	learning  bool
	learned   = map[string]bool{}
	learnMu   sync.Mutex

	mu   sync.Mutex
	tids = map[int]bool{}
)

// parseOpts 吃掉前导选项，返回剩下的位置参数

func parseOpts(args []string) []string {
	var rest []string
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
		os.Exit(2)
	}
	for len(args) > 0 {
		tok := args[0]
		need := func() string {
			if len(args) < 2 {
				fail("选项 %s 缺少参数", tok)
			}
			return args[1]
		}
		switch tok {
		case "--":
			return append(rest, args[1:]...)
		case "-h", "--help":
			help()
		case "--log-only":
			logOnly = true
			args = args[1:]
		case "--main-only":
			mainOnly = true
			args = args[1:]
		case "--block-out":
			blockOut = true
			args = args[1:]
		case "--name":
			attachNames = append(attachNames, need())
			args = args[2:]
		case "--pid":
			v, err := strconv.Atoi(need())
			if err != nil || v <= 0 {
				fail("--pid 需要正整数")
			}
			attachPid = v
			args = args[2:]
		case "--fake-flag":
			fakeFlags = append(fakeFlags, need())
			args = args[2:]
		case "--learn-secs":
			v, err := strconv.Atoi(need())
			if err != nil || v < 0 {
				fail("--learn-secs 需要非负整数")
			}
			learnSecs = v
			args = args[2:]
		case "--allow-file":
			allowFile = need()
			args = args[2:]
		case "--allow-cidr":
			if _, n, err := net.ParseCIDR(need()); err != nil {
				fail("非法 CIDR: %s", args[1])
			} else {
				allowNets = append(allowNets, n)
			}
			args = args[2:]
		case "--decoy":
			decoyPath = need()
			args = args[2:]
		default:
			if strings.HasPrefix(tok, "-") {
				fail("未知选项: %s", tok)
			}
			rest = append(rest, tok)
			args = args[1:]
		}
	}
	return rest
}

const version = "0.4.0"

func help() {
	fmt.Printf(`shellhook %s —— AWD 场景下的 execve / openat / 出网拦截器

用法:
  shellhook run    [选项] -- <程序> [参数...]
  shellhook attach [选项] --pid <pid>
  shellhook attach [选项] --name <进程名>
  shellhook check
  shellhook -h | --help
  shellhook -v | --version

模式:
  run      自己拉起目标进程，从 execve 之前接管
  attach   挂到已在运行的进程（默认遍历它的全部线程）
  check    自检当前机器：权限、yama 闸门、run/attach 能不能用

选项:
  --pid <pid>          attach 的目标进程号（仅 attach）
  --name <进程名>      按 comm 名挂，可重复；nginx 这类会连 master 和 worker 一起挂
  --log-only           只记录不拦截
  --main-only          attach 时只挂主线程（仅对 --pid 生效，--name 恒为全线程）
  --fake-flag <路径>   把对该路径的 open/openat/openat2 重定向到诱饵，可重复
  --decoy <文件>       诱饵文件；不存在会自动生成
  --block-out          拦截对外 connect / sendto / sendmsg / sendmmsg
  --allow-cidr <cidr>  出网白名单，可重复；回环永远放行
  --allow-file <文件>  白名单文件，一行一个 IP 或 CIDR，学习结果也追加到这里
  --learn-secs <N>     前 N 秒放行并记录目的地址，之后自动切拦截
  -h, --help           显示本帮助
  -v, --version        显示版本

关于 -- :
  单独的两个横线是一个分隔符，不是选项。它后面的内容原样交给被启动的程序，
  这样程序自己的参数（比如 ./victim -b 0.0.0.0 -p 9999）才不会被 shellhook 当成自己的选项。
  选项用长格式（--block-out），短格式只有 -h 和 -v。

示例:
  shellhook check
  shellhook run -- ./victim
  shellhook run --log-only -- ./victim
  shellhook attach --pid 1234 --fake-flag /flag --decoy /tmp/.d/flag
  shellhook attach --name nginx
  shellhook attach --name php-fpm8.4 --log-only
  shellhook run --block-out --learn-secs 60 --allow-file /tmp/sh_allow -- ./victim
  shellhook run --block-out --allow-cidr 10.0.0.0/8 -- ./victim

Ctrl-C 只 detach，不动被保护的服务。`, version)
	os.Exit(0)
}

func usage() {
	fmt.Fprintln(os.Stderr, "用法见: shellhook -h")
	os.Exit(2)
}
