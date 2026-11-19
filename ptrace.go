package main

import (
	"encoding/binary"
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

func readCString(pid int, addr uintptr, max int) string {
	out := make([]byte, 0, 64)
	for i := 0; i < max; i += 8 {
		w, err := peek(pid, addr+uintptr(i))
		if err != nil {
			break
		}
		b := (*[8]byte)(unsafe.Pointer(&w))[:]
		for _, c := range b {
			if c == 0 {
				return string(out)
			}
			out = append(out, c)
		}
	}
	return string(out)
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

func readSockaddr(pid int, addr uintptr) (net.IP, int, int, error) {
	buf := make([]byte, 28)
	for i := 0; i < len(buf); i += 8 {
		w, err := peek(pid, addr+uintptr(i))
		if err != nil {
			return nil, 0, 0, err
		}
		copy(buf[i:], (*[8]byte)(unsafe.Pointer(&w))[:])
	}
	fam := int(binary.LittleEndian.Uint16(buf[0:2]))
	switch fam {
	case 2: // AF_INET
		return net.IPv4(buf[4], buf[5], buf[6], buf[7]), int(binary.BigEndian.Uint16(buf[2:4])), fam, nil
	case 10: // AF_INET6
		return net.IP(append([]byte(nil), buf[8:24]...)), int(binary.BigEndian.Uint16(buf[2:4])), fam, nil
	}
	return nil, 0, fam, nil
}

func msgNamePtr(pid int, hdr uintptr) uintptr {
	w, err := peek(pid, hdr)
	if err != nil {
		return 0
	}
	return uintptr(w)
}

// loadAllowFile 读取白名单文件，一行一个 IP 或 CIDR
