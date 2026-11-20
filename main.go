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
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
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
	prog := args[0]
	if !strings.ContainsRune(prog, '/') {
		if p, err := exec.LookPath(prog); err == nil {
			prog = p
		} else {
			fmt.Fprintf(os.Stderr, "找不到程序 %q: %v\n", args[0], err)
			os.Exit(1)
		}
	}
	pid, err := syscall.ForkExec(prog, args, attr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fork/exec failed: %v\n", err)
		os.Exit(1)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		fmt.Fprintf(os.Stderr, "wait failed: %v\n", err)
		os.Exit(1)
	}
	opts := optTracesysgood | optTracefork | optTracevfork | optTraceclone | optTraceexec | optExitkill
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
	logf("config: mode=%s fake-flag=%v decoy=%q block-out=%v allow-cidr=%d learn-secs=%d",
		mode, fakeFlags, decoyPath, blockOut, len(allowNets), learnSecs)
	logf("launched pid=%d target=%v", pid, args)

	trace(map[int]bool{pid: true}, false, pid)
}

func cmdAttach(args []string) {
	rest := parseOpts(args)
	if attachPid == 0 && len(rest) == 1 {
		v, err := strconv.Atoi(rest[0])
		if err != nil || v <= 0 {
			fmt.Fprintf(os.Stderr, "attach 需要一个合法 pid: %q\n", rest[0])
			os.Exit(2)
		}
		attachPid = v
	}
	if attachPid == 0 && len(rest) > 1 {
		fmt.Fprintln(os.Stderr, "attach 只能接一个 pid")
		os.Exit(2)
	}
	if attachPid == 0 && len(attachNames) == 0 {
		usage()
	}
	prepareDecoy()
	preparePolicy()

	opts := optTracesysgood | optTracefork | optTracevfork | optTraceclone | optTraceexec
	states := map[int]bool{}
	attached := 0

	// 按 pid：把这个进程的所有线程都挂上
	if attachPid > 0 {
		targets := []int{attachPid}
		if !mainOnly {
			t, err := threadIDs(attachPid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "读取 %d 的线程列表失败: %v（可用 --main-only 接受降级）\n", attachPid, err)
				os.Exit(1)
			}
			targets = t
		}
		for _, tid := range targets {
			if seizeOne(tid, opts, states) {
				attached++
			}
		}
	}

	// 按名字：/proc 里每个 tid 都会列出来，直接逐个挂
	for _, name := range attachNames {
		pids := findPidsByName(name)
		logf("--name %s 匹配到 %d 个 tid", name, len(pids))
		for _, p := range pids {
			// 命中的可能只是一个线程，把它所在的整个线程组展开，
			// 否则改过名的线程（JVM/GC、prctl(PR_SET_NAME)）会漏
			tgid := threadGroup(p)
			targets := []int{tgid}
			if !mainOnly {
				if t, err := threadIDs(tgid); err == nil {
					targets = t
				}
			}
			for _, tid := range targets {
				if _, ok := stGet(states, tid); ok {
					continue
				}
				if seizeOne(tid, opts, states) {
					attached++
				}
			}
		}
	}

	if attached == 0 {
		fmt.Fprintln(os.Stderr, "attach failed: no thread seized")
		os.Exit(1)
	}

	mode := "BLOCK"
	if logOnly {
		mode = "LOG-ONLY"
	}
	logf("attached %d thread(s) mode=%s names=%v", attached, mode, attachNames)

	installDetachHandler()
	trace(states, true, 0)
}

// seizeOne 完整接管一个 tid：SEIZE → INTERRUPT → 等停 → 定相位 → 继续
func seizeOne(tid, opts int, states map[int]bool) bool {
	if err := ptrace(reqSeize, tid, 0, uintptr(opts)); err != nil {
		logf("seize tid=%d failed: %v", tid, err)
		return false
	}
	if err := ptrace(reqInterrupt, tid, 0, 0); err != nil {
		logf("interrupt tid=%d failed: %v（已 detach）", tid, err)
		_ = ptrace(reqDetach, tid, 0, 0)
		return false
	}
	// INTERRUPT 的 trap 在返回用户态时才处理，卡在不可中断睡眠的进程可能等不到；
	// 这里加超时，避免把整个 tracer 拖住。
	var ws syscall.WaitStatus
	deadline := time.Now().Add(1500 * time.Millisecond)
	for {
		w, err := syscall.Wait4(tid, &ws, syscall.WALL|syscall.WNOHANG, nil)
		if err != nil {
			logf("wait tid=%d failed: %v（已 detach）", tid, err)
			_ = ptrace(reqDetach, tid, 0, 0)
			return false
		}
		if w == tid {
			break
		}
		if time.Now().After(deadline) {
			logf("tid=%d INTERRUPT 后 1.5s 没停下（可能卡在不可中断睡眠），放弃", tid)
			_ = ptrace(reqDetach, tid, 0, 0)
			return false
		}
		time.Sleep(1 * time.Millisecond)
	}
	inSys := inSyscallNow(tid)
	if err := ptrace(reqSyscall, tid, 0, 0); err != nil {
		logf("continue tid=%d FAILED: %v（已 detach）", tid, err)
		_ = ptrace(reqDetach, tid, 0, 0)
		return false
	}
	stSet(states, tid, !inSys)
	if debug {
		logf("tid=%d 相位初始化: in_syscall=%v 下一次停=%s", tid, inSys, phaseName(!inSys))
	}
	addTid(tid)
	return true
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
		logf("stats: execve hits=%d blocked=%d decoy-served=%d fd-leaks=%d", hits, blocked, fakeGot, fdLeaks)
		logf("detached %d thread(s), service left alive", len(t))
		os.Exit(0)
	}()
}

// writeBytes 往 tracee 地址空间写一段字节（PTRACE_POKEDATA，按 8 字节对齐写）
