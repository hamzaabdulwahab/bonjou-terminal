//go:build windows

package network

import "syscall"

func setBroadcastOption(fd uintptr) {
	_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
