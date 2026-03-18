//go:build !windows

package network

import (
	"strconv"
	"syscall"
)

func setBroadcastOption(fd uintptr) {
	parsed, err := strconv.ParseInt(strconv.FormatUint(uint64(fd), 10), 10, 64)
	if err != nil {
		return
	}
	fdInt := int(parsed)
	_ = syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
