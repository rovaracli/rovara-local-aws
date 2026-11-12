//go:build linux

package main

import (
	"runtime"
	"syscall"
)

// childAttrs: the engine dies with the front, whatever way the front dies.
func childAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// Pdeathsig is tied to the OS THREAD that forked the child, not to the process: if that thread exits, the child is
// killed. Go retires threads freely, so every start runs on one dedicated thread that is locked for the life of the
// process and never exits.
var spawnQueue = make(chan func())

func init() {
	go func() {
		runtime.LockOSThread()
		for f := range spawnQueue {
			f()
		}
	}()
}

func onSpawnThread(f func()) {
	done := make(chan struct{})
	spawnQueue <- func() { defer close(done); f() }
	<-done
}
