package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// fileID 用 (dev, ino) 唯一标识一个文件，绕过路径写法差异
type fileID struct {
	dev uint64
	ino uint64
}

var (
	protectedIDs  = map[fileID]bool{}
	protectedBase = map[string]bool{}
)

// loadProtectedIDs 记录每个受保护文件的 inode，以及文件名用于预筛
func loadProtectedIDs() {
	for _, p := range fakeFlags {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			fmt.Fprintf(os.Stderr, "受保护路径 %s 无法 stat: %v\n", p, err)
			os.Exit(1)
		}
		logf("受保护: %s dev=%d ino=%d", p, st.Dev, st.Ino)
		protectedIDs[fileID{uint64(st.Dev), st.Ino}] = true
		protectedBase[filepath.Base(p)] = true
	}
}

func idOf(fi os.FileInfo) (fileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{uint64(st.Dev), st.Ino}, true
}

// mightBeProtected 便宜的预筛：路径里任一段等于受保护文件名才去做 inode 判定
func mightBeProtected(p string) bool {
	for _, comp := range strings.Split(p, "/") {
		if comp != "" && protectedBase[comp] {
			return true
		}
	}
	return false
}

// resolveTracee 按 tracee 的 root / cwd / dirfd 把路径解析成追踪者视角的宿主路径
func resolveTracee(pid int, dirfd int64, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	var base string
	switch {
	case strings.HasPrefix(path, "/"):
		base = fmt.Sprintf("/proc/%d/root", pid)
	case dirfd == -100: // AT_FDCWD
		base = fmt.Sprintf("/proc/%d/cwd", pid)
	default:
		base = fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)
	}
	// 不能用 filepath.Join：它会按宿主字符串语义 Clean 掉 ".."，
	// 而 ".." 应该由内核在 tracee 的 namespace 里解析。直接拼接交给内核。
	full := base + "/" + path
	return full, true
}

// statTraceeFile 在 tracee 的命名空间里解析路径并比对 inode
func statTraceeFile(pid int, dirfd int64, path string) bool {
	if len(protectedIDs) == 0 {
		return false
	}
	full, ok := resolveTracee(pid, dirfd, path)
	if !ok {
		return false
	}
	fi, err := os.Stat(full)
	if err != nil {
		return false
	}
	id, ok := idOf(fi)
	if !ok {
		return false
	}
	return protectedIDs[id]
}

var permWarn sync.Once

func permWarnOnce() {
	permWarn.Do(func() {
		logf("警告：无权读取 /proc/<pid>/fd，出口 inode 复核对该进程失效（后续同类错误不再提示）")
	})
}

// fdIsProtected 检查 tracee 的 fd 是否指向受保护 inode（兜住所有路径写法）。
// 第二个返回值表示"能否确认"：false 时调用方应按命中处理（fail-closed）。
func fdIsProtected(pid, fd int) (bool, bool) {
	if len(protectedIDs) == 0 || fd < 0 {
		return false, true
	}
	fi, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		if os.IsPermission(err) {
			permWarnOnce()
			return false, true // 看不到 fd 内容，但不因此把服务打死
		}
		return false, false // 其它错误按命中处理
	}
	id, ok := idOf(fi)
	if !ok {
		return false, false
	}
	return protectedIDs[id], true
}
