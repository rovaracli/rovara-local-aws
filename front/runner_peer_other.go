//go:build !linux

package main

import "net"

// Development builds only (the front runs on Linux in the image): no peer credentials, no free-space check.
func peerAllowed(c net.Conn) bool { return true }

func freeBytes(path string) (int64, bool) { return 0, false }
