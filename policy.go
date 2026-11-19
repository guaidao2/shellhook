package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[shellhook %s] ", time.Now().Format("15:04:05.000"))
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

func isProtected(path string) bool {
	for _, f := range fakeFlags {
		if path == f || filepath.Clean(path) == filepath.Clean(f) {
			return true
		}
	}
	return false
}

// redirectOpen 把 open 的路径改写成诱饵文件。
// 短路径原地改；诱饵更长时写到栈下方的空余区，再把寄存器指过去。

func redirectOpen(pid int, regs *syscall.PtraceRegs, nr int, pathPtr uintptr, orig string) bool {
	if decoyPath == "" {
		return false
	}
	want := append([]byte(decoyPath), 0)

	if len(want) <= len(orig)+1 {
		if err := writeBytes(pid, pathPtr, want); err != nil {
			return false
		}
		return true
	}

	scratch := uintptr(regs.Rsp) - 1024
	if err := writeBytes(pid, scratch, want); err != nil {
		logf("scratch write failed: %v", err)
		return false
	}
	if debug {
		logf("scratch=%#x readback=%q", scratch, readCString(pid, scratch, 128))
	}
	if nr == sysOpen {
		regs.Rdi = uint64(scratch)
	} else {
		regs.Rsi = uint64(scratch)
	}
	if err := setRegs(pid, regs); err != nil {
		logf("setRegs failed: %v", err)
		return false
	}
	if debug {
		if r2, e := getRegs(pid); e == nil {
			logf("after setregs rdi=%#x rsi=%#x", r2.Rdi, r2.Rsi)
		}
	}
	return true
}

// readSockaddr 从 tracee 内存里解析 sockaddr_in / sockaddr_in6

func allowedOut(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return true
	}
	learnMu.Lock()
	if learning {
		learned[ip.String()] = true
		learnMu.Unlock()
		return true
	}
	seen := learned[ip.String()]
	learnMu.Unlock()
	if seen {
		return true
	}
	for _, n := range allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// msgNamePtr 取 msghdr / mmsghdr 的 msg_name 指针

func loadAllowFile() {
	if allowFile == "" {
		return
	}
	b, err := os.ReadFile(allowFile)
	if err != nil {
		return
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			if _, netw, e := net.ParseCIDR(line); e == nil {
				allowNets = append(allowNets, netw)
				n++
			}
		} else if ip := net.ParseIP(line); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			allowNets = append(allowNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			n++
		}
	}
	logf("allow-file: 载入 %d 条", n)
}

// startLearning 学习期放行一切并把目的地址记下来，结束后写进 allow-file

func startLearning() {
	if learnSecs <= 0 {
		return
	}
	learning = true
	logf("learning mode: %ds", learnSecs)
	time.AfterFunc(time.Duration(learnSecs)*time.Second, func() {
		learnMu.Lock()
		learning = false
		ips := make([]string, 0, len(learned))
		for ip := range learned {
			ips = append(ips, ip)
		}
		learnMu.Unlock()
		logf("learning done: %d destination(s) %v", len(ips), ips)
		if allowFile != "" && len(ips) > 0 {
			f, err := os.OpenFile(allowFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err == nil {
				for _, ip := range ips {
					fmt.Fprintln(f, ip)
				}
				f.Close()
				logf("learned destinations appended to %s", allowFile)
			}
		}
	})
}

func preparePolicy() {
	loadAllowFile()
	startLearning()
}

// prepareDecoy 确保诱饵文件存在，没有就造一个

func prepareDecoy() {
	if len(fakeFlags) == 0 {
		return
	}
	if decoyPath == "" {
		fmt.Fprintln(os.Stderr, "--fake-flag 需要配合 --decoy <诱饵文件> 使用")
		os.Exit(2)
	}
	if _, err := os.Stat(decoyPath); err == nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(decoyPath), 0o755)
	content := fmt.Sprintf("flag{shellhook_decoy_%08x}\n", uint32(time.Now().UnixNano()))
	if err := os.WriteFile(decoyPath, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "创建诱饵失败: %v\n", err)
		os.Exit(1)
	}
	logf("created decoy %s", decoyPath)
}

// trace 主循环。attachMode=false 时以主进程退出为结束条件
