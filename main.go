// shellhook —— AWD 场景下的 execve / openat / 出网拦截器（小 EDR 内核雏形）
//
//	shellhook run    [选项] -- <程序> [参数...]
//	shellhook attach [选项] --pid <pid>
//
// 机制：目标进程被 ptrace 跟住，在 syscall 入口改写号或参数，出口回填 errno。
// 它不阻止漏洞被利用，只让利用之后的每一种兑现方式都落空。
package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
)

func main() {
	// ptrace 的追踪者身份绑定在具体线程上，goroutine 一旦迁移就会 ESRCH
	runtime.LockOSThread()
	args := os.Args[1:]
	if len(args) < 1 {
		usage()
	}
	switch args[0] {
	case "run":
		cmdRun(args[1:])
	case "attach":
		cmdAttach(args[1:])
	case "check":
		cmdCheck()
	case "-h", "--help", "help":
		help()
	case "-v", "--version", "version":
		fmt.Println("shellhook " + version)
		os.Exit(0)
	default:
		usage()
	}
}

func cmdRun(args []string) {
	args = parseOpts(args)
	if len(args) < 1 {
		usage()
	}
	prepareDecoy()
	preparePolicy()

	attr := &syscall.ProcAttr{
		Dir:   "", // 继承当前目录，避免 chdir 到无权限路径失败
		Env:   os.Environ(),
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Ptrace: true},
	}
	pid, err := syscall.ForkExec(args[0], args, attr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fork/exec failed: %v\n", err)
		os.Exit(1)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		fmt.Fprintf(os.Stderr, "wait failed: %v\n", err)
		os.Exit(1)
	}
	opts := optTracefork | optTracevfork | optTraceclone | optTraceexec | optExitkill
	if err := ptrace(reqSetoptions, pid, 0, uintptr(opts)); err != nil {
		fmt.Fprintf(os.Stderr, "setoptions failed: %v\n", err)
		os.Exit(1)
	}
	if err := ptrace(reqSyscall, pid, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "continue failed: %v\n", err)
		os.Exit(1)
	}

	addTid(pid)
	mode := "BLOCK"
	if logOnly {
		mode = "LOG-ONLY"
	}
	logf("launched pid=%d mode=%s target=%v", pid, mode, args)

	trace(map[int]bool{pid: true}, false, pid)
}

func cmdAttach(args []string) {
	rest := parseOpts(args)
	if attachPid == 0 && len(rest) > 0 {
		attachPid, _ = strconv.Atoi(rest[0])
	}
	pid := attachPid
	if pid <= 0 {
		usage()
	}
	prepareDecoy()
	preparePolicy()

	targets := []int{pid}
	if !mainOnly {
		targets = threadIDs(pid)
	}

	opts := optTracefork | optTracevfork | optTraceclone | optTraceexec
	states := map[int]bool{}
	attached := 0
	for _, tid := range targets {
		if err := ptrace(reqSeize, tid, 0, uintptr(opts)); err != nil {
			logf("seize tid=%d failed: %v", tid, err)
			continue
		}
		// 先看它是否卡在 syscall 里，决定第一次停算入口还是出口
		states[tid] = !inSyscallNow(tid)
		if err := ptrace(reqInterrupt, tid, 0, 0); err != nil {
			logf("interrupt tid=%d failed: %v", tid, err)
			continue
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(tid, &ws, syscall.WALL, nil); err != nil {
			logf("wait tid=%d failed: %v", tid, err)
			continue
		}
		if err := ptrace(reqSyscall, tid, 0, 0); err != nil {
			logf("continue tid=%d FAILED: %v", tid, err)
			continue
		}
		addTid(tid)
		attached++
	}
	if attached == 0 {
		fmt.Fprintln(os.Stderr, "attach failed: no thread seized")
		os.Exit(1)
	}

	mode := "BLOCK"
	if logOnly {
		mode = "LOG-ONLY"
	}
	logf("attached pid=%d threads=%d mode=%s", pid, attached, mode)

	installDetachHandler()
	trace(states, true, 0)
}

// installDetachHandler 让 Ctrl-C / SIGTERM 只断开 ptrace，不连累被保护的服务

func installDetachHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		t := snapshotTids()
		for _, tid := range t {
			_ = ptrace(reqDetach, tid, 0, 0)
		}
		logf("detached %d thread(s), service left alive", len(t))
		os.Exit(0)
	}()
}

// writeBytes 往 tracee 地址空间写一段字节（PTRACE_POKEDATA，按 8 字节对齐写）
