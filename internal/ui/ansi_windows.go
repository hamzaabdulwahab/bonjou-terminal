//go:build windows

package ui

import (
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

var ansiOnce sync.Once

func enableANSI() {
	ansiOnce.Do(func() {
		setMode := func(file *os.File, flags uint32) {
			if file == nil {
				return
			}
			handle := windows.Handle(file.Fd())
			var mode uint32
			if err := windows.GetConsoleMode(handle, &mode); err != nil {
				return
			}
			mode |= flags
			_ = windows.SetConsoleMode(handle, mode)
		}

		outFlags := uint32(windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.ENABLE_PROCESSED_OUTPUT)
		inFlags := uint32(windows.ENABLE_VIRTUAL_TERMINAL_INPUT | windows.ENABLE_PROCESSED_INPUT)

		setMode(os.Stdout, outFlags)
		setMode(os.Stderr, outFlags)
		setMode(os.Stdin, inFlags)
	})
}
