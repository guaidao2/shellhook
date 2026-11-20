package main

import (
	"syscall"
	"unsafe"
)

func trace(states map[int]bool, attachMode bool, waitPid int) {
	pendingRet := map[int]uint64{}
	skipped := map[int]bool{}
	openPending := map[int]bool{}
	type injectState struct {
		rip   uint64
		nr    int
		miss  int
		saved syscall.PtraceRegs
	}
	injecting := map[int]*injectState{}
	phaseChecked := map[int]bool{}
	first := true

	// forceBlock 把 syscall 号改 -1；只有在 SETREGS 连续失败（基本等于
	// tracee 已经死了）时才杀，注意 SIGKILL 是整个进程组。
	forceBlock := func(pid int, regs *syscall.PtraceRegs, errno int) bool {
		regs.Orig_rax = ^uint64(0)
		for i := 0; i < 2; i++ {
			if err := setRegs(pid, regs); err == nil {
				pendingRet[pid] = ^uint64(errno - 1)
				skipped[pid] = true
				return true
			}
		}
		logf("pid=%d SETREGS 连续失败，终止该 tracee 以免放行", pid)
		_ = ptrace(reqKill, pid, 0, 0)
		return false
	}

	for {
		var st syscall.WaitStatus
		wpid, err := syscall.Wait4(-1, &st, syscall.WALL, nil)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			break
		}
		if wpid <= 0 {
			continue
		}
		if st.Exited() || st.Signaled() {
			stDel(states, wpid)
			delete(pendingRet, wpid)
			delete(skipped, wpid)
			delete(openPending, wpid)
			delete(injecting, wpid)
			delete(phaseChecked, wpid)
			delTid(wpid)
			if !attachMode && wpid == waitPid {
				logf("target exited, execve hits=%d blocked=%d decoy-served=%d fd-leaks=%d", hits, blocked, fakeGot, fdLeaks)
				break
			}
			// attach 模式下所有 tracee 都没了就退出
			if attachMode && stLen(states) == 0 {
				logf("all tracees gone, execve hits=%d blocked=%d decoy-served=%d fd-leaks=%d", hits, blocked, fakeGot, fdLeaks)
				break
			}
			continue
		}
		if !st.Stopped() {
			continue
		}

		sig := int(st.StopSignal())
		ev := (int(st) >> 16) & 0xff

		if _, ok := stGet(states, wpid); !ok {
			stSet(states, wpid, true)
			addTid(wpid)
			if !first {
				logf("new tracee pid=%d", wpid)
			}
		}
		if first {
			first = false
			if attachMode {
				logf("first stop pid=%d sig=%d ev=%d", wpid, sig, ev)
			}
		}

		if ev != 0 {
			var msg uint64
			if err := ptrace(reqGeteventmsg, wpid, 0, uintptr(unsafe.Pointer(&msg))); err != nil {
				logf("pid=%d GETEVENTMSG 失败: %v，跳过该事件", wpid, err)
				resume(wpid, 0)
				continue
			}
			switch ev {
			case evFork, evVfork, evClone:
				cp := int(msg)
				stSet(states, cp, true)
				addTid(cp)
				logf("fork: pid=%d -> child=%d", wpid, cp)
			case evExec:
				// exec 成功之后还有一次 execve 的出口停，相位是确定的；
				// 同时清掉校准标记，让这条 tid 重新校准一次（换 tid 场景）
				stSet(states, wpid, false)
				delete(phaseChecked, wpid)
				logf("exec succeeded: pid=%d", wpid)
			case evStop:
				// PTRACE_INTERRUPT 产生的停，直接继续
			}
			// 不要在这里动相位：入口停时已经把它置成 false（下一次是出口），
			// 子进程的相位在 fork 事件里置过 true。这里再写会把 SEIZE 下
			// 新子进程（PTRACE_EVENT_STOP 起停）的相位翻反。
			resume(wpid, 0)
			continue
		}

		// 开了 TRACESYSGOOD 之后，syscall 停的信号是 SIGTRAP|0x80；
		// 其余 SIGTRAP（int3、别人 kill 过来的）都当普通信号原样回注。
		if sig != int(syscall.SIGTRAP)|0x80 {
			if sig == int(syscall.SIGSTOP) {
				resume(wpid, 0)
			} else {
				resume(wpid, sig)
			}
			continue
		}

		regs, err := getRegs(wpid)
		if err != nil {
			resume(wpid, 0)
			continue
		}
		// 我们刚把某个 syscall 的号改成 -1，那下一个停必然是它的出口停，
		// 此时 rax 也是 -ENOSYS，靠 rax 判会误认成入口，所以先在这里截住
		if skipped[wpid] {
			skipped[wpid] = false
			stSet(states, wpid, true) // 跳过的那条已经出口，下一个停是入口
			if v, ok := pendingRet[wpid]; ok {
				delete(pendingRet, wpid)
				regs.Rax = v
				_ = setRegs(wpid, regs)
				logf("pid=%d -> returned errno=%d", wpid, int64(v))
			}
			resume(wpid, 0)
			continue
		}

		// 相位校准：GET_SYSCALL_INFO 能用就直接采信并锁存；
		// 不能用时，rax==-ENOSYS 只说明"可能是入口"，要等到看见一个
		// 非 -ENOSYS 的停（确定是出口）才锁存，之前每次停都允许重纠。
		if !phaseChecked[wpid] {
			cur, _ := stGet(states, wpid)
			if op := syscallOp(wpid); op == 1 || op == 2 {
				phaseChecked[wpid] = true
				if want := op == 1; cur != want {
					logf("pid=%d 相位纠正（syscall-info）: %v -> %v", wpid, cur, want)
					stSet(states, wpid, want)
				}
			} else {
				// rax==-ENOSYS 只说明"可能是入口"，不足以锁存；
				// 只有看到非 -ENOSYS 的停（确定是出口）才把相位定死。
				want := regs.Rax == ^uint64(37)
				if cur != want {
					logf("pid=%d 相位纠正（rax 判据）: %v -> %v", wpid, cur, want)
					stSet(states, wpid, want)
				}
				if !want {
					phaseChecked[wpid] = true
				}
			}
		}

		var entry bool
		switch op := syscallOp(wpid); op {
		case 1:
			entry = true
		case 2:
			entry = false
		default:
			// 本内核 PTRACE_GET_SYSCALL_INFO 不填 op，用 per-tid 相位严格交替。
			// 相位初值在 attach 的 INTERRUPT 停之后、或 run 的首停之后确定。
			entry, _ = stGet(states, wpid)
		}
		stSet(states, wpid, !entry)

		// 正在为"出口命中受保护 inode"补一次 close。注入期间可能有信号处理器
		// 插进来跑别的 syscall，所以必须核对这次停确实是我们注入的那条。
		if st, ok := injecting[wpid]; ok {
			if uint64(regs.Rip) == st.rip && int(regs.Orig_rax) == st.nr {
				if !entry {
					saved := st.saved
					saved.Rax = ^uint64(enoent - 1)
					if err := setRegs(wpid, &saved); err != nil {
						logf("pid=%d 注入 close 后恢复寄存器失败: %v", wpid, err)
					}
					delete(injecting, wpid)
				}
				resume(wpid, 0)
				continue
			}
			// 不是我们注入的那次停：正常往下走，保留注入状态等它到来
			if entry {
				st.miss++
			}
			if st.miss > 64 {
				logf("pid=%d 注入的 close 迟迟没到（%d），放弃回填：调用方可能拿到 close 的返回值、寄存器未恢复",
					wpid, st.miss)
				delete(injecting, wpid)
				delete(openPending, wpid)
			}
		}

		if entry {
			a := classify(wpid, regs)
			if debug {
				logf("pid=%d enter compat=%v nr=%d a0=%#x a1=%#x", wpid, a.compat, a.nr, a.a0, a.a1)
			}

			// open 系列：命中保护路径就改写成诱饵；路径读不出来按可疑处理
			if len(fakeFlags) > 0 && a.isOpen() {
				ptr := a.openPath()
				path, readable := readCString(wpid, ptr, pathMax)
				hit := readable && isProtected(path)
				if !hit && readable {
					// 32 位目标不能依赖出口注入（sysenter），每个 open 都在入口按 inode 判；
					// 64 位只在路径里出现受保护文件名时才解析，省开销。
					if a.compat || mightBeProtected(path) {
						hit = statTraceeFile(wpid, a.dirfd(), path)
					}
				}
				switch {
				case hit && readable && redirectOpen(wpid, regs, a, ptr, path):
					fakeGot++
					logf("pid=%d open(%q) -> decoy %q", wpid, path, decoyPath)
				case hit || !readable:
					if forceBlock(wpid, regs, enoent) {
						logf("pid=%d open(%q, readable=%v, hit=%v) -> DENIED", wpid, path, readable, hit)
					}
				case a.compat:
					// 入口已按 inode 判过，放行；不挂出口复核
				default:
					// 路径没命中，出口再按 inode 复核一次，兜住软链
					openPending[wpid] = true
				}
			}

			// 按 inode handle 打开：没有路径字符串可匹配，开了假 flag 就直接拒
			if len(fakeFlags) > 0 && a.isOpenByHandle() {
				if forceBlock(wpid, regs, eperm) {
					logf("pid=%d open_by_handle_at -> DENIED (no path to inspect)", wpid)
				}
			}

			if blockOut {
				if dest := a.netDest(wpid); dest != 0 {
					ip, port, fam, err := readSockaddr(wpid, dest)
					allow := false
					switch {
					case err != nil:
						allow = false // 解析失败一律按未授权
					case fam == 1: // AF_UNIX
						allow = true
					case fam == 2 || fam == 10:
						allow = allowedOut(ip)
					default:
						allow = false // AF_PACKET / AF_NETLINK 等一律不放
					}
					if !allow {
						if forceBlock(wpid, regs, enetunreach) {
							logf("pid=%d net op nr=%d fam=%d (%s:%d) -> BLOCKED", wpid, a.nr, fam, ip, port)
						}
					} else if debug {
						logf("pid=%d net op nr=%d fam=%d (%s:%d) allowed", wpid, a.nr, fam, ip, port)
					}
				}
			}

			if a.isExecve() {
				path, readable := readCString(wpid, a.execPath(), pathMax)
				if !readable {
					path += " (unreadable)"
				}
				hits++
				if logOnly {
					logf("pid=%d exec(%q)  (allowed)", wpid, path)
				} else if forceBlock(wpid, regs, eacces) {
					blocked++
					logf("pid=%d exec(%q)  -> BLOCKED", wpid, path)
				}
			}
		} else if openPending[wpid] {
			delete(openPending, wpid)
			fd := int(regs.Rax)
			if int64(regs.Rax) >= 0 {
				hit, known := fdIsProtected(wpid, fd)
				if !known {
					hit = true // 判不了就按命中处理
					logf("pid=%d fd=%d 的属主无法确认，按命中处理", wpid, fd)
				}
				if hit {
					if _, busy := injecting[wpid]; busy {
						// 这里已经是出口停，改 Orig_rax 没用，必须改 Rax
						regs.Rax = ^uint64(enoent - 1)
						if err := setRegs(wpid, regs); err != nil {
							logf("pid=%d 拒绝 fd=%d 时 SETREGS 失败: %v（fd 仍可用）", wpid, fd, err)
						}
						fdLeaks++
						logf("pid=%d fd=%d 命中受保护 inode，已有注入在途：已回填 ENOENT，该 fd 仍打开且可被扫到", wpid, fd)
					} else {
						exitA := classify(wpid, regs)
						orig := *regs // 必须在 injectClose 改寄存器之前保存
						if injectClose(wpid, regs, exitA, fd) {
							// 注意：这里不能 continue，要落到末尾的 resume 让注入的 close 跑起来
							// 注入后 regs.Rip 指向 syscall 指令本身，而停回报的是指令之后 2 字节
							injecting[wpid] = &injectState{rip: regs.Rip + 2, nr: int(regs.Orig_rax), saved: orig}
							fakeGot++
							logf("pid=%d fd=%d 指向受保护 inode，注入 close 后返回 ENOENT", wpid, fd)
						} else {
							// 先保证调用方拿到 -ENOENT，再放弃注入。
							// 这里刻意不 kill：SIGKILL 会打死整个线程组，等于给对手一个
							// 用一次软链读就能打挂服务的 DoS。残留 fd 只在 32 位
							// sysenter 这类注入不了的情况下出现，记日志留证据。
							regs.Rax = ^uint64(enoent - 1)
							_ = setRegs(wpid, regs)
							fdLeaks++
							logf("pid=%d fd=%d 无法注入 close（可能走 sysenter），已回填 ENOENT，该 fd 仍打开且可被扫到", wpid, fd)
						}
					}
				}
			}
		}
		resume(wpid, 0)
	}
}
