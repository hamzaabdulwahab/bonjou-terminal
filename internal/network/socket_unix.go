//go:build !windows

package network

import "syscall"

func setBroadcastOption(fd uintptr) {
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
