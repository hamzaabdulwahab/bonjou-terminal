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
		handles := []*os.File{os.Stdout, os.Stderr}
		for _, f := range handles {
			if f == nil {
				continue
			}
			handle := windows.Handle(f.Fd())
			var mode uint32
			if err := windows.GetConsoleMode(handle, &mode); err != nil {
				continue
			}
			mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
			mode |= windows.ENABLE_PROCESSED_OUTPUT
			_ = windows.SetConsoleMode(handle, mode)
		}
	})
}
