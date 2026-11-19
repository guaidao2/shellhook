package main

import (
	"syscall"
	"unsafe"
)

func trace(states map[int]bool, attachMode bool, waitPid int) {
	pendingRet := map[int]uint64{}
	skipped := map[int]bool{}
	first := true

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
			delete(states, wpid)
			delete(pendingRet, wpid)
			delTid(wpid)
			if !attachMode && wpid == waitPid {
				logf("target exited, execve hits=%d blocked=%d decoy-served=%d", hits, blocked, fakeGot)
				break
			}
			if attachMode && len(states) == 0 {
				logf("all tracees gone, execve hits=%d blocked=%d decoy-served=%d", hits, blocked, fakeGot)
				break
			}
			continue
		}
		if !st.Stopped() {
			continue
		}

		sig := int(st.StopSignal())
		ev := (int(st) >> 16) & 0xff

		if _, ok := states[wpid]; !ok {
			states[wpid] = true
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
			_ = ptrace(reqGeteventmsg, wpid, 0, uintptr(unsafe.Pointer(&msg)))
			switch ev {
			case evFork, evVfork, evClone:
				cp := int(msg)
				states[cp] = true
				addTid(cp)
				logf("fork: pid=%d -> child=%d", wpid, cp)
			case evExec:
				logf("exec succeeded: pid=%d", wpid)
			case evStop:
				// PTRACE_INTERRUPT 产生的停，直接继续
			}
			states[wpid] = false // 事件停之后还会来一次 syscall 出口停
			resume(wpid, 0)
			continue
		}

		if sig != int(syscall.SIGTRAP) {
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
			if v, ok := pendingRet[wpid]; ok {
				delete(pendingRet, wpid)
				regs.Rax = v
				_ = setRegs(wpid, regs)
				logf("pid=%d -> returned errno=%d", wpid, int64(v))
			}
			resume(wpid, 0)
			continue
		}

		var entry bool
		switch op := syscallOp(wpid); op {
		case 1:
			entry = true
		case 2:
			entry = false
		default:
			// 本内核 PTRACE_GET_SYSCALL_INFO 不填 op；入口停时内核把 rax 置成 -ENOSYS
			entry = regs.Rax == ^uint64(37)
		}

		if entry {
			nr := int(regs.Orig_rax)
			if debug {
				logf("pid=%d enter nr=%d rdi=%#x rsi=%#x", wpid, nr, regs.Rdi, regs.Rsi)
			}
			if len(fakeFlags) > 0 && (nr == sysOpen || nr == sysOpenat || nr == sysOpenat2) {
				ptr := uintptr(regs.Rdi)
				if nr != sysOpen {
					ptr = uintptr(regs.Rsi)
				}
				path := readCString(wpid, ptr, 512)
				if isProtected(path) {
					if redirectOpen(wpid, regs, nr, ptr, path) {
						fakeGot++
						logf("pid=%d open(%q) -> decoy %q", wpid, path, decoyPath)
					} else {
						// 改不动就让它"文件不存在"，绝不能把真 flag 放出去
						regs.Orig_rax = ^uint64(0)
						if setRegs(wpid, regs) == nil {
							pendingRet[wpid] = ^uint64(enoent - 1)
							skipped[wpid] = true
							logf("pid=%d open(%q) -> BLOCKED (rewrite failed)", wpid, path)
						}
					}
				}
			}
			if blockOut {
				var dest uintptr
				switch nr {
				case sysConnect:
					dest = uintptr(regs.Rsi)
				case sysSendto:
					dest = uintptr(regs.R8) // sendto 的第 5 个参数是 dest_addr
				case sysSendmsg:
					dest = msgNamePtr(wpid, uintptr(regs.Rsi))
				case sysSendmmsg:
					dest = msgNamePtr(wpid, uintptr(regs.Rsi)) // 只看第一条
				}
				if dest != 0 {
					ip, port, fam, err := readSockaddr(wpid, dest)
					if err == nil && fam != 0 && !allowedOut(ip) {
						regs.Orig_rax = ^uint64(0)
						if setRegs(wpid, regs) == nil {
							pendingRet[wpid] = ^uint64(enetunreach - 1)
							skipped[wpid] = true
							logf("pid=%d net op nr=%d (%s:%d) -> BLOCKED", wpid, nr, ip, port)
						}
					} else if debug && err == nil && fam != 0 {
						logf("pid=%d net op nr=%d (%s:%d) allowed", wpid, nr, ip, port)
					}
				}
			}
			if nr == sysExecve || nr == sysExecveat {
				pathAddr := uintptr(regs.Rdi)
				if nr == sysExecveat {
					pathAddr = uintptr(regs.Rsi)
				}
				path := readCString(wpid, pathAddr, 256)
				hits++
				if logOnly {
					logf("pid=%d exec(%q)  (allowed)", wpid, path)
				} else {
					regs.Orig_rax = ^uint64(0)
					if e := setRegs(wpid, regs); e == nil {
						pendingRet[wpid] = ^uint64(eacces - 1)
						skipped[wpid] = true
						blocked++
						logf("pid=%d exec(%q)  -> BLOCKED", wpid, path)
					}
				}
			}
		}
		resume(wpid, 0)
	}
}
