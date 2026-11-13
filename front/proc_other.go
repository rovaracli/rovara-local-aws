//go:build !linux

package main

import "syscall"

func childAttrs() *syscall.SysProcAttr { return nil }

func onSpawnThread(f func()) { f() }
