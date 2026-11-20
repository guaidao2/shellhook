package main

import "syscall"

// 用户态代码段选择子：64 位是 0x33，走 int 0x80 的 32 位兼容 ABI 是 0x23
const csCompat32 = 0x23

// 32 位兼容 ABI 的 syscall 号（i386 表），和 64 位那套完全不同
const (
	c32Execve         = 11
	c32Open           = 5
	c32Openat         = 295
	c32Openat2        = 437
	c32Execveat       = 358
	c32Socketcall     = 102
	c32OpenByHandleAt = 342
)

// socketcall 的子调用号
const (
	scConnect  = 3
	scSendto   = 11
	scSendmsg  = 16
	scSendmmsg = 20
)

// abi 把一次 syscall 停的寄存器和 ABI 形态收敛成一个结构，
// 后面所有 hook 都只看它，不再直接碰寄存器。
type abi struct {
	compat bool
	nr     int
	a0     uint64
	a1     uint64
	a2     uint64
	a3     uint64
	a4     uint64
}

// isInt80 判断刚执行的指令是不是 int 0x80（cd 80）。
// 64 位代码里发 int 0x80 时 CS 仍是 0x33，所以必须看指令本身。
func isInt80(pid int, rip uintptr) bool {
	if rip < 2 {
		return false
	}
	b0, ok0 := readByte(pid, rip-2)
	b1, ok1 := readByte(pid, rip-1)
	return ok0 && ok1 && b0 == 0xcd && b1 == 0x80
}

// interestingCompatNr 只对这几个 32 位号做指令判别，避免每个 syscall 都多读两次内存
func interestingCompatNr(nr int) bool {
	switch nr {
	case c32Execve, c32Execveat, c32Open, c32Openat, c32Openat2, c32Socketcall, c32OpenByHandleAt:
		return true
	}
	return false
}

func classify(pid int, regs *syscall.PtraceRegs) abi {
	// 64 位代码里发 int 0x80 时 CS 仍是 0x33，不能只看 CS，
	// 还要看 RIP-2 处的指令是不是 cd 80。
	compat := regs.Cs == csCompat32
	if !compat && interestingCompatNr(int(regs.Orig_rax)) {
		compat = isInt80(pid, uintptr(regs.Rip))
	}
	if compat {
		// 32 位 ABI：参数在 ebx/ecx/edx/esi/edi
		return abi{
			compat: true,
			nr:     int(regs.Orig_rax),
			a0:     uint64(uint32(regs.Rbx)),
			a1:     uint64(uint32(regs.Rcx)),
			a2:     uint64(uint32(regs.Rdx)),
			a3:     uint64(uint32(regs.Rsi)),
			a4:     uint64(uint32(regs.Rdi)),
		}
	}
	return abi{
		compat: false,
		nr:     int(regs.Orig_rax),
		a0:     regs.Rdi,
		a1:     regs.Rsi,
		a2:     regs.Rdx,
		a3:     regs.R10,
		a4:     regs.R8,
	}
}

func (a abi) isExecve() bool {
	if a.compat {
		return a.nr == c32Execve || a.nr == c32Execveat
	}
	return a.nr == sysExecve || a.nr == sysExecveat
}

func (a abi) execPath() uintptr {
	if a.compat {
		if a.nr == c32Execveat {
			return uintptr(uint32(a.a1))
		}
		return uintptr(uint32(a.a0))
	}
	if a.nr == sysExecveat {
		return uintptr(a.a1)
	}
	return uintptr(a.a0)
}

func (a abi) isOpen() bool {
	if a.compat {
		return a.nr == c32Open || a.nr == c32Openat || a.nr == c32Openat2
	}
	return a.nr == sysOpen || a.nr == sysOpenat || a.nr == sysOpenat2
}

// openPath 返回路径指针；openat/openat2 的路径在第二个参数
func (a abi) openPath() uintptr {
	if a.compat {
		if a.nr == c32Open {
			return uintptr(uint32(a.a0))
		}
		return uintptr(uint32(a.a1))
	}
	if a.nr == sysOpen {
		return uintptr(a.a0)
	}
	return uintptr(a.a1)
}

// dirfd 返回 openat 系列的 dirfd；open 固定是 AT_FDCWD
func (a abi) dirfd() int64 {
	if a.compat {
		if a.nr == c32Open {
			return -100
		}
		return int64(int32(a.a0))
	}
	if a.nr == sysOpen {
		return -100
	}
	return int64(a.a0)
}

// openNr 归一化成 64 位号，redirectOpen 用它决定改哪个寄存器
func (a abi) openNr() int {
	if a.compat {
		if a.nr == c32Open {
			return sysOpen
		}
		return sysOpenat
	}
	return a.nr
}

func (a abi) isOpenByHandle() bool {
	if a.compat {
		return a.nr == c32OpenByHandleAt
	}
	return a.nr == sysOpenByHandle
}

// netDest 返回本次 syscall 试图连接/发送的目的地址指针；0 表示无
func (a abi) netDest(pid int) uintptr {
	if a.compat {
		if a.nr != c32Socketcall {
			return 0
		}
		call := int(a.a0)
		argsPtr := uintptr(uint32(a.a1))
		switch call {
		case scConnect: // connect(fd, addr, len)
			return uintptr(readU32(pid, argsPtr+4))
		case scSendto: // sendto(fd, buf, len, flags, addr, addrlen)
			return uintptr(readU32(pid, argsPtr+16))
		case scSendmsg: // sendmsg(fd, msghdr, flags)
			return msgNamePtr32(pid, uintptr(readU32(pid, argsPtr+4)))
		case scSendmmsg: // sendmmsg(fd, mmsghdr, vlen, flags)
			return msgNamePtr32(pid, uintptr(readU32(pid, argsPtr+4)))
		}
		return 0
	}
	switch a.nr {
	case sysConnect:
		return uintptr(a.a1)
	case sysSendto:
		return uintptr(a.a4)
	case sysSendmsg, sysSendmmsg:
		return msgNamePtr(pid, uintptr(a.a1))
	}
	return 0
}

// injectClose 在 syscall 出口停上把 RIP 退回两个字节，重新执行一次 close(fd)。
// 这样出口命中受保护 inode 时，真 fd 会被真正关掉，而不是只改返回值。
func injectClose(pid int, regs *syscall.PtraceRegs, a abi, fd int) bool {
	rip := uintptr(regs.Rip)
	if rip < 2 {
		return false
	}
	b0, ok0 := readByte(pid, rip-2)
	b1, ok1 := readByte(pid, rip-1)
	if !ok0 || !ok1 {
		return false
	}
	isSyscall := b0 == 0x0f && b1 == 0x05
	isInt80 := b0 == 0xcd && b1 == 0x80
	if !isSyscall && !isInt80 {
		return false
	}
	regs.Rip = uint64(rip - 2)
	if a.compat || isInt80 {
		regs.Orig_rax = 6 // i386 close
		regs.Rax = 6
		regs.Rbx = uint64(uint32(fd))
	} else {
		regs.Orig_rax = 3 // x86-64 close
		regs.Rax = 3
		regs.Rdi = uint64(fd)
	}
	return setRegs(pid, regs) == nil
}
