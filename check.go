package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const reqKill = 8

const capSysPtraceBit = 19

// cmdCheck 自检当前机器能不能跑 shellhook，以及两种模式各自能不能用
func cmdCheck() {
	fmt.Println("shellhook check")
	fmt.Println()

	uid, euid := os.Getuid(), os.Geteuid()
	root := uid == 0 || euid == 0
	fmt.Printf("uid/euid       : %d/%d %s\n", uid, euid, pick(root, "(root)", "(non-root)"))

	cap := hasCapSysPtrace()
	fmt.Printf("CAP_SYS_PTRACE : %s\n", pick(cap, "yes", "no"))

	scope := readYamaScope()
	fmt.Printf("yama scope     : %s\n", yamaDesc(scope))

	runOK := probeRunMode()
	fmt.Printf("run mode       : %s\n", pick(runOK, "OK  (can fork + trace a child)", "FAILED"))

	ok, note := attachVerdict(root, cap, scope)
	fmt.Printf("attach mode    : %s  (%s)\n", pick(ok, "likely OK", "restricted"), note)

	fmt.Println()
	if runOK {
		fmt.Println("结论：run 模式可用。")
	} else {
		fmt.Println("结论：run 模式都跑不起来，检查内核是否允许 ptrace。")
		os.Exit(1)
	}
}

func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// hasCapSysPtrace 从 /proc/self/status 的 CapEff 里看第 19 位
func hasCapSysPtrace() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return false
		}
		v, err := strconv.ParseUint(f[1], 16, 64)
		if err != nil {
			return false
		}
		return v&(1<<capSysPtraceBit) != 0
	}
	return false
}

// readYamaScope 读不到返回 -1（说明内核没开 YAMA）
func readYamaScope() int {
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return v
}

func yamaDesc(v int) string {
	switch v {
	case -1:
		return "n/a  (YAMA 未启用)"
	case 0:
		return "0    (unrestricted)"
	case 1:
		return "1    (children only)"
	case 2:
		return "2    (admin only)"
	case 3:
		return "3    (disabled)"
	}
	return fmt.Sprintf("%d    (unknown)", v)
}

// probeRunMode 真的 fork 一个 /bin/true 并跟一次，验证 run 模式链路
func probeRunMode() bool {
	attr := &syscall.ProcAttr{
		Dir:   "", // 继承当前目录，避免 chdir 到无权限路径失败
		Env:   os.Environ(),
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Ptrace: true},
	}
	pid, err := syscall.ForkExec("/bin/true", []string{"/bin/true"}, attr)
	if err != nil {
		return false
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return false
	}
	_ = ptrace(reqKill, pid, 0, 0)
	_, _ = syscall.Wait4(pid, &ws, 0, nil)
	return true
}

func attachVerdict(root, cap bool, scope int) (bool, string) {
	switch scope {
	case 0:
		return true, "scope=0，同 uid 的目标可直接挂"
	case 1:
		if root || cap {
			return true, "scope=1，但有 root/CAP_SYS_PTRACE，可直接挂"
		}
		return false, "scope=1，只能挂自己 fork 的子进程；挂已在跑的服务要 root 或 echo 0 > /proc/sys/kernel/yama/ptrace_scope"
	case 2:
		if root || cap {
			return true, "scope=2，但有 root/CAP_SYS_PTRACE，可直接挂"
		}
		return false, "scope=2，只有 root 能 attach"
	case 3:
		return false, "scope=3，attach 被完全禁止"
	}
	return true, "未启用 YAMA，按普通权限规则判断"
}
