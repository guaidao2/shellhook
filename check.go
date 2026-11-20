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
var syscallInfoOK bool

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

	blockOK := probeBlock()
	fmt.Printf("block test     : %s\n", pick(blockOK, "OK  (execve really blocked)", "FAILED (execve went through)"))
	fmt.Printf("syscall-info   : %s\n", pick(syscallInfoOK, "yes (内核直接告知入口/出口)", "no  (用相位交替 + 校准)"))

	ok, note := attachVerdict(root, cap, scope)
	fmt.Printf("attach mode    : %s  (%s)\n", pick(ok, "likely OK", "restricted"), note)

	fmt.Println()
	if runOK && !blockOK {
		fmt.Println("结论：能跟踪，但 execve 拦截没生效，检查相位判据。")
		os.Exit(1)
	}
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

// probeBlock 真的拦一次 execve：起一个 sh，让它 exec /bin/true，
// 我们跟住并拒掉那次 execve。如果看到 EV_EXEC 说明拦截没生效。
func probeBlock() bool {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	defer devnull.Close()
	attr := &syscall.ProcAttr{
		Dir:   "",
		Env:   os.Environ(),
		Files: []uintptr{0, 1, devnull.Fd()},
		Sys:   &syscall.SysProcAttr{Ptrace: true},
	}
	pid, err := syscall.ForkExec("/bin/sh", []string{"/bin/sh", "-c", "exec /bin/true"}, attr)
	if err != nil {
		return false
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return false
	}
	opts := optTracesysgood | optTraceexec | optExitkill
	if err := ptrace(reqSetoptions, pid, 0, uintptr(opts)); err != nil {
		return false
	}
	resume(pid, 0)

	entry := true
	blocked := 0
	pendingBlock := false
	status := -1
	for i := 0; i < 20000; i++ {
		wpid, err := syscall.Wait4(-1, &ws, syscall.WALL, nil)
		if err != nil {
			break
		}
		if ws.Exited() || ws.Signaled() {
			if wpid == pid {
				if ws.Exited() {
					status = ws.ExitStatus()
				}
				break
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}
		sig := int(ws.StopSignal())
		ev := (int(ws) >> 16) & 0xff
		if ev != 0 {
			if ev == evExec {
				_ = ptrace(reqKill, wpid, 0, 0)
				return false // exec 真的发生了
			}
			resume(wpid, 0)
			continue
		}
		if sig != int(syscall.SIGTRAP)|0x80 {
			resume(wpid, sig)
			continue
		}
		regs, err := getRegs(wpid)
		if err != nil {
			resume(wpid, 0)
			continue
		}
		if !syscallInfoOK {
			if op := syscallOp(wpid); op == 1 || op == 2 {
				syscallInfoOK = true
			}
		}
		if entry {
			a := classify(wpid, regs)
			if a.isExecve() {
				regs.Orig_rax = ^uint64(0)
				if err := setRegs(wpid, regs); err == nil {
					blocked++
					pendingBlock = true
				}
			}
		} else if pendingBlock {
			// 出口回填 EACCES，验证用户态真的收到 -EACCES
			pendingBlock = false
			regs.Rax = ^uint64(eacces - 1)
			_ = setRegs(wpid, regs)
		}
		entry = !entry
		resume(wpid, 0)
	}
	// sh 的 exec 失败退出码是 126
	return blocked > 0 && status == 126
}
