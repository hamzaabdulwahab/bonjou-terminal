//go:build windows

package main

import (
	"os"
	"os/signal"
)

func notifySignals(sigs chan os.Signal) {
	signal.Notify(sigs, os.Interrupt)
}
