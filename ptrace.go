package main

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"
)

func ptrace(req, pid int, addr, data uintptr) error {
	_, _, e := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(req), uintptr(pid), addr, data, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

func peek(pid int, addr uintptr) (uint64, error) {
	var word uint64
	if err := ptrace(reqPeekdata, pid, addr, uintptr(unsafe.Pointer(&word))); err != nil {
		return 0, err
	}
	return word, nil
}

// readCString 从 tracee 读 NUL 结尾字符串。
// ok=false 表示读失败或超过上限——调用方必须按"不可信"处理，不能当成没命中。
func readCString(pid int, addr uintptr, max int) (string, bool) {
	out := make([]byte, 0, 64)
	// 按 8 字节对齐读，避免字符串落在页尾时跨页 EIO 被误判成不可读
	aligned := addr &^ 7
	off := int(addr & 7)
	for len(out) < max {
		w, err := peek(pid, aligned)
		if err != nil {
			return string(out), false
		}
		b := (*[8]byte)(unsafe.Pointer(&w))[:]
		for ; off < 8 && len(out) < max; off++ {
			c := b[off]
			if c == 0 {
				return string(out), true
			}
			out = append(out, c)
		}
		aligned += 8
		off = 0
	}
	return string(out), false // 超过上限仍未结束
}

// readByte 读 tracee 里的一个字节
func readByte(pid int, addr uintptr) (byte, bool) {
	aligned := addr &^ 7
	w, err := peek(pid, aligned)
	if err != nil {
		return 0, false
	}
	return byte(w >> (8 * (addr & 7))), true
}

// readU32 读 tracee 里的一个 32 位小端值（用于 32 位 ABI 的指针参数）
func readU32(pid int, addr uintptr) uint32 {
	aligned := addr &^ 7
	w, err := peek(pid, aligned)
	if err != nil {
		return 0
	}
	shift := 8 * (addr & 7)
	return uint32(w >> shift)
}

func getRegs(pid int) (*syscall.PtraceRegs, error) {
	var r syscall.PtraceRegs
	if err := ptrace(reqGetregs, pid, 0, uintptr(unsafe.Pointer(&r))); err != nil {
		return nil, err
	}
	return &r, nil
}

func setRegs(pid int, r *syscall.PtraceRegs) error {
	return ptrace(reqSetregs, pid, 0, uintptr(unsafe.Pointer(r)))
}

// syscallOp 返回 1=入口 2=出口 0=内核不提供（退回奇偶推断）

func syscallOp(pid int) uint8 {
	var buf [80]byte
	if err := ptrace(reqSyscallinfo, pid, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0]))); err != nil {
		return 0
	}
	return buf[0]
}

func resume(pid, sig int) {
	if err := ptrace(reqSyscall, pid, 0, uintptr(sig)); err != nil {
		logf("resume pid=%d sig=%d FAILED: %v", pid, sig, err)
	}
}

func writeBytes(pid int, addr uintptr, data []byte) error {
	for i := 0; i < len(data); i += 8 {
		var word uint64
		end := i + 8
		if end > len(data) {
			w, err := peek(pid, addr+uintptr(i))
			if err != nil {
				return err
			}
			word = w
			copy((*[8]byte)(unsafe.Pointer(&word))[:], data[i:])
		} else {
			copy((*[8]byte)(unsafe.Pointer(&word))[:], data[i:end])
		}
		// 注意：POKEDATA 的 data 参数是"值"本身，不是指针
		if err := ptrace(reqPokedata, pid, addr+uintptr(i), uintptr(word)); err != nil {
			return err
		}
	}
	return nil
}

// readSockaddr 按 family 读对应长度的 sockaddr。
// 读失败返回 error，调用方必须按"未授权"处理，不能放行。
func readSockaddr(pid int, addr uintptr) (net.IP, int, int, error) {
	b0, ok0 := readByte(pid, addr)
	b1, ok1 := readByte(pid, addr+1)
	if !ok0 || !ok1 {
		return nil, 0, 0, errors.New("读 sockaddr family 失败")
	}
	fam := int(b0) | int(b1)<<8

	var size int
	switch fam {
	case 2: // AF_INET
		size = 16
	case 10: // AF_INET6
		size = 24 // 只读到 addr 结束，scope_id 用不到，少读 4 字节避免越界
	default:
		return nil, 0, fam, nil
	}

	buf := make([]byte, size)
	for i := 0; i < size; i += 8 {
		w, err := peek(pid, addr+uintptr(i))
		if err != nil {
			return nil, 0, fam, err
		}
		copy(buf[i:], (*[8]byte)(unsafe.Pointer(&w))[:])
	}
	port := int(binary.BigEndian.Uint16(buf[2:4]))
	if fam == 2 {
		return net.IPv4(buf[4], buf[5], buf[6], buf[7]), port, fam, nil
	}
	return net.IP(append([]byte(nil), buf[8:24]...)), port, fam, nil
}

func msgNamePtr(pid int, hdr uintptr) uintptr {
	w, err := peek(pid, hdr)
	if err != nil {
		return 0
	}
	return uintptr(w)
}

// msgNamePtr32 32 位 msghdr 的 msg_name 只有 4 字节，不能按 8 字节读
func msgNamePtr32(pid int, hdr uintptr) uintptr {
	return uintptr(readU32(pid, hdr))
}

// loadAllowFile 读取白名单文件，一行一个 IP 或 CIDR
