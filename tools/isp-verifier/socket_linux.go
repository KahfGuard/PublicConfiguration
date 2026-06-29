//go:build linux

package main

import (
	"net"
	"syscall"
)

// enableICMPErrors sets IP_RECVERR on a connected UDP socket so that ICMP
// unreachable messages sent by the router's REJECT rule surface as read errors
// rather than silently timing out (Linux-specific requirement).
func enableICMPErrors(conn net.Conn) {
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVERR, 1)
	})
}
