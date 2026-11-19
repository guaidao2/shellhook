package main

import (
	"fmt"
	"os"
	"strconv"
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

func threadIDs(pid int) []int {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return []int{pid}
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
	return out
}
