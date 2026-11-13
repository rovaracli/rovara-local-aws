//go:build linux

package main

import (
	"net"
	"os"
	"syscall"
)

// peerAllowed: the process on the other end of the runner socket runs as the front's own user (or root): `docker exec` into the helper starts
// the worker's pipe as the container's user. The kernel supplies the credentials (SO_PEERCRED); the peer cannot choose them.
func peerAllowed(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	sc, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := sc.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil || cred == nil {
		return false
	}
	return int(cred.Uid) == os.Getuid() || cred.Uid == 0
}

// freeBytes: the space available to this user on the file system holding path.
func freeBytes(path string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
