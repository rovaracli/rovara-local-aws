//go:build linux

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// reaper collects the exit status of the runtime process. When the agent is PID 1 it also reaps
// every orphan that gets re-parented to it (a function that forks and exits would otherwise
// leave zombies behind), and since it then has to use wait4(-1) it is the only waiter. When the
// agent is not PID 1 it waits for the one pid only, so it never steals statuses from other
// children of the process (this matters for tests).
//
// Only the status of the pid registered through Start is kept. Every other reaped status is
// discarded, so a pid that is reused later cannot inherit a stale one.
type reaper struct {
	pid1 bool
	stop chan struct{} // closed to end the reaping loop (tests)

	// startMu is held for writing while Start forks and registers the child, and for reading
	// while the loop reaps. A child that exits at once therefore cannot be reaped before its
	// watch is registered, and an orphan can never be mistaken for it.
	startMu sync.RWMutex

	mu      sync.Mutex
	watch   map[int]chan syscall.WaitStatus
	started bool
}

func newReaper() *reaper {
	return &reaper{
		pid1:  os.Getpid() == 1,
		stop:  make(chan struct{}),
		watch: map[int]chan syscall.WaitStatus{},
	}
}

// Start runs fork (which must start exactly one child and return its pid) and returns a
// channel that receives that child's exit status once.
func (r *reaper) Start(fork func() (int, error)) (int, <-chan syscall.WaitStatus, error) {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	pid, err := fork()
	if err != nil {
		return 0, nil, err
	}
	ch := make(chan syscall.WaitStatus, 1)
	if !r.pid1 {
		go func() {
			var ws syscall.WaitStatus
			for {
				_, err := syscall.Wait4(pid, &ws, 0, nil)
				if err == syscall.EINTR {
					continue
				}
				if err != nil {
					ws = syscall.WaitStatus(0xff00) // exit status 255: status unknown
				}
				break
			}
			ch <- ws
		}()
		return pid, ch, nil
	}
	r.mu.Lock()
	r.watch[pid] = ch
	if !r.started {
		r.started = true
		go r.loop()
	}
	r.mu.Unlock()
	return pid, ch, nil
}

func (r *reaper) loop() {
	sig := make(chan os.Signal, 8)
	signal.Notify(sig, syscall.SIGCHLD)
	defer signal.Stop(sig)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		r.drain()
		select {
		case <-sig:
		case <-tick.C:
		case <-r.stop:
			return
		}
	}
}

func (r *reaper) drain() {
	r.startMu.RLock()
	defer r.startMu.RUnlock()
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return
		}
		r.mu.Lock()
		if ch, ok := r.watch[pid]; ok {
			delete(r.watch, pid)
			ch <- ws
		}
		r.mu.Unlock()
	}
}

// hardenSelf makes the agent non-dumpable. The runtime runs as the same user as the agent, and
// a dumpable process exposes /proc/<pid>/fd, environ and mem (and ptrace) to same-user
// processes. Without this the function's code could open /proc/1/fd/1 and write forged frames
// to the worker, read /proc/1/fd/0 to take invoke frames, or read /proc/1/environ. The setting
// is per process and is reset by execve, so the runtime itself stays dumpable.
func hardenSelf() error {
	const prSetDumpable = 4
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); e != 0 {
		return e
	}
	return nil
}

// startProcess starts argv[0] in its own process group with the given environment, working
// directory and stdio (stdin, stdout, stderr file descriptors). If uid is not zero the child
// runs as uid:gid.
func startProcess(argv, env []string, dir string, stdin, out uintptr, uid, gid int) (int, error) {
	if len(argv) == 0 {
		return 0, fmt.Errorf("empty command")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		dir = "/"
	}
	sys := &syscall.SysProcAttr{Setpgid: true}
	if uid != 0 {
		sys.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true}
	}
	return syscall.ForkExec(argv[0], argv, &syscall.ProcAttr{
		Dir:   dir,
		Env:   env,
		Files: []uintptr{stdin, out, out},
		Sys:   sys,
	})
}

// killGroup sends SIGKILL to the runtime's process group. When the agent is PID 1 it also kills
// every other process in the sandbox (the kernel never delivers kill(-1) to init itself), which
// catches children that left the group with setsid.
func killGroup(pgid int) {
	if pgid > 1 {
		syscall.Kill(-pgid, syscall.SIGKILL)
	}
	if os.Getpid() == 1 {
		syscall.Kill(-1, syscall.SIGKILL)
	}
}

// groupRSS sums the resident set size (VmRSS) of every live process in the process group.
// gVisor does not report VmHWM, so the agent samples RSS itself to find a peak.
func groupRSS(pgid int) int64 {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(stat)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 3 {
			continue
		}
		if g, _ := strconv.Atoi(f[2]); g != pgid {
			continue
		}
		total += vmRSS(pid)
	}
	return total
}

func vmRSS(pid int) int64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line[6:])
			if len(f) >= 1 {
				kb, _ := strconv.ParseInt(f[0], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func describeStatus(ws syscall.WaitStatus) (code int, sig string, msg string) {
	switch {
	case ws.Signaled():
		sg := ws.Signal()
		return -1, sg.String(), "signal: " + strings.ToLower(sg.String())
	case ws.Exited():
		return ws.ExitStatus(), "", "exit status " + strconv.Itoa(ws.ExitStatus())
	}
	return -1, "", "unknown status"
}
