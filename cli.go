package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
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

	optTracefork  = 0x00000002
	optTracevfork = 0x00000004
	optTraceclone = 0x00000008
	optTraceexec  = 0x00000010
	optExitkill   = 0x00100000

	evFork  = 1
	evVfork = 2
	evClone = 3
	evExec  = 4
	evStop  = 128

	sysOpen     = 2
	sysOpenat   = 257
	sysOpenat2  = 437
	sysConnect  = 42
	sysSendto   = 44
	sysSendmsg  = 46
	sysSendmmsg = 307
	sysExecve   = 59
	sysExecveat = 322
	eacces      = 13
	enoent      = 2
	enetunreach = 101
)

var (
	logOnly   bool
	mainOnly  bool
	attachPid int
	debug     = os.Getenv("SH_DEBUG") != ""
	hits      int
	blocked   int
	fakeGot   int

	// 假 flag：默认关闭，--fake-flag <被保护路径> --decoy <诱饵文件>
	fakeFlags []string
	decoyPath string

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
	for len(args) > 0 {
		switch args[0] {
		case "-h", "--help":
			help()
		case "--log-only":
			logOnly = true
			args = args[1:]
		case "--main-only":
			mainOnly = true
			args = args[1:]
		case "--pid":
			if len(args) < 2 {
				usage()
			}
			attachPid, _ = strconv.Atoi(args[1])
			args = args[2:]
		case "--fake-flag":
			if len(args) < 2 {
				usage()
			}
			fakeFlags = append(fakeFlags, args[1])
			args = args[2:]
		case "--block-out":
			blockOut = true
			args = args[1:]
		case "--learn-secs":
			if len(args) < 2 {
				usage()
			}
			learnSecs, _ = strconv.Atoi(args[1])
			args = args[2:]
		case "--allow-file":
			if len(args) < 2 {
				usage()
			}
			allowFile = args[1]
			args = args[2:]
		case "--allow-cidr":
			if len(args) < 2 {
				usage()
			}
			if _, n, err := net.ParseCIDR(args[1]); err == nil {
				allowNets = append(allowNets, n)
			} else {
				fmt.Fprintf(os.Stderr, "非法 CIDR: %s\n", args[1])
				os.Exit(2)
			}
			args = args[2:]
		case "--decoy":
			if len(args) < 2 {
				usage()
			}
			decoyPath = args[1]
			args = args[2:]
		case "--":
			return args[1:]
		default:
			return args
		}
	}
	return args
}

const version = "0.1.0"

func help() {
	fmt.Printf(`shellhook %s —— AWD 场景下的 execve / openat / 出网拦截器

用法:
  shellhook run    [选项] -- <程序> [参数...]
  shellhook attach [选项] --pid <pid>
  shellhook -h | --help
  shellhook -v | --version

模式:
  run      自己拉起目标进程，从 execve 之前接管
  attach   挂到已在运行的进程（默认遍历它的全部线程）

选项:
  --pid <pid>          attach 的目标进程号（仅 attach）
  --log-only           只记录不拦截
  --main-only          attach 时只挂主线程
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
  shellhook run -- ./victim
  shellhook run --log-only -- ./victim
  shellhook attach --pid 1234 --fake-flag /flag --decoy /tmp/.d/flag
  shellhook run --block-out --learn-secs 60 --allow-file /tmp/sh_allow -- ./victim
  shellhook run --block-out --allow-cidr 10.0.0.0/8 -- ./victim

Ctrl-C 只 detach，不动被保护的服务。`, version)
	os.Exit(0)
}

func usage() {
	fmt.Fprintln(os.Stderr, "用法见: shellhook -h")
	os.Exit(2)
}
