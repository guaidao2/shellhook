package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

func addTid(pid int) {
	mu.Lock()
	tids[pid] = true
	mu.Unlock()
}

func delTid(pid int) {
	mu.Lock()
	delete(tids, pid)
	mu.Unlock()
}

func snapshotTids() []int {
	mu.Lock()
	defer mu.Unlock()
	out := make([]int, 0, len(tids))
	for t := range tids {
		out = append(out, t)
	}
	return out
}

// inSyscallNow 判断目标此刻是否正卡在一个 syscall 里。
// attach 之后第一次 syscall 停是入口还是出口，靠这个区分。

func inSyscallNow(tid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", tid))
	if err != nil || len(b) == 0 {
		return true
	}
	s := string(b)
	if len(s) >= 7 && s[:7] == "running" {
		return false
	}
	for _, c := range s {
		if c == ' ' {
			return true
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// 目前 states 只有主循环访问；保留这把锁，是为了以后真要加并发时不用改所有调用点
var stateMu sync.Mutex

func stGet(m map[int]bool, k int) (bool, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	v, ok := m[k]
	return v, ok
}

func stSet(m map[int]bool, k int, v bool) {
	stateMu.Lock()
	m[k] = v
	stateMu.Unlock()
}

func stDel(m map[int]bool, k int) {
	stateMu.Lock()
	delete(m, k)
	stateMu.Unlock()
}

func stLen(m map[int]bool) int {
	stateMu.Lock()
	defer stateMu.Unlock()
	return len(m)
}

// phaseName 只用于调试日志
func phaseName(nextIsEntry bool) string {
	if nextIsEntry {
		return "entry"
	}
	return "exit"
}

func threadIDs(pid int) ([]int, error) {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(ents))
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = append(out, pid)
	}
	return out, nil
}

// findPidsByName 按 comm 找进程。Linux 的 comm 最多 15 字节，
// 过长的名字会被截断，这里按截断后的形式比较。
func findPidsByName(name string) []int {
	if name == "" {
		return nil
	}
	want := name
	if len(want) > 15 {
		want = want[:15]
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	self := os.Getpid()
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		comm := strings.TrimRight(string(b), "\n")
		if comm != want {
			continue
		}
		// 僵尸进程永远挂不上，跳过，否则每轮扫描都会重试一次
		if zombie(e.Name()) {
			continue
		}
		// 绝不挂自己（含自己的线程），否则自己跟住自己会直接卡死
		if pid == self || sameThreadGroup(e.Name(), self) {
			continue
		}
		out = append(out, pid)
	}
	return out
}

// zombie 读 /proc/<pid>/stat 的进程状态，Z 表示僵尸
func zombie(pidDir string) bool {
	b, err := os.ReadFile("/proc/" + pidDir + "/stat")
	if err != nil {
		return false
	}
	// 格式: pid (comm) state ...，comm 里可能有空格和括号，取最后一个 ')' 之后
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	return s[i+2] == 'Z'
}

// sameThreadGroup 判断 /proc/<pid> 是否属于 tgid 这个进程（含主线程与子线程）
func sameThreadGroup(pidDir string, tgid int) bool {
	b, err := os.ReadFile("/proc/" + pidDir + "/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Tgid:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return false
		}
		v, err := strconv.Atoi(f[1])
		return err == nil && v == tgid
	}
	return false
}

// threadGroup 返回 tid 所属线程组的 tgid
func threadGroup(tid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return tid
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Tgid:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return tid
		}
		if v, err := strconv.Atoi(f[1]); err == nil {
			return v
		}
	}
	return tid
}
