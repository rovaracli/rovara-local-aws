package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// logSink collects everything the runtime writes to stdout and stderr. Both go to one pipe, so
// the order is the order of the writes, as in a CloudWatch log stream. The agent keeps its own
// copy of the pipe's write end open for the life of the process, so the pipe never reports EOF;
// that lets it write a barrier marker into the stream and learn when everything the runtime
// wrote before that point has reached the ring.
type logSink struct {
	ring  *ring
	rfd   int
	wfd   int
	debug io.Writer

	mu       sync.Mutex
	barriers map[uint32]chan struct{}
	nextID   uint32
}

var barrierPrefix = []byte("\x00RVBAR")

const barrierLen = 6 + 8 + 1 // prefix, 8 hex digits, NUL

func newLogSink(r *ring, debug io.Writer) (*logSink, error) {
	var fds [2]int
	if err := syscall.Pipe2(fds[:], syscall.O_CLOEXEC); err != nil {
		return nil, err
	}
	l := &logSink{ring: r, rfd: fds[0], wfd: fds[1], debug: debug, barriers: map[uint32]chan struct{}{}}
	go l.pump()
	return l, nil
}

func (l *logSink) pump() {
	f := os.NewFile(uintptr(l.rfd), "runtime-log")
	buf := make([]byte, 64<<10)
	var pend []byte
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if l.debug != nil {
				l.debug.Write(buf[:n])
			}
			pend = l.consume(append(pend, buf[:n]...))
		}
		if err != nil {
			return
		}
	}
}

// consume writes data to the ring, resolving barrier markers, and returns the bytes it keeps
// back because they might be the start of a marker.
func (l *logSink) consume(data []byte) []byte {
	for {
		i := bytes.Index(data, barrierPrefix)
		if i < 0 {
			keep := partialPrefix(data)
			l.ring.Write(data[:len(data)-keep])
			return append([]byte(nil), data[len(data)-keep:]...)
		}
		if len(data)-i < barrierLen {
			l.ring.Write(data[:i])
			return append([]byte(nil), data[i:]...)
		}
		l.ring.Write(data[:i])
		if id, err := strconv.ParseUint(string(data[i+6:i+14]), 16, 32); err == nil && data[i+14] == 0 {
			l.mu.Lock()
			if ch, ok := l.barriers[uint32(id)]; ok {
				close(ch)
				delete(l.barriers, uint32(id))
			}
			l.mu.Unlock()
			data = data[i+barrierLen:]
		} else {
			// Not one of ours: keep the bytes.
			l.ring.Write(data[i : i+len(barrierPrefix)])
			data = data[i+len(barrierPrefix):]
		}
	}
}

// partialPrefix returns the length of the longest suffix of data that is a proper prefix of
// barrierPrefix.
func partialPrefix(data []byte) int {
	max := len(barrierPrefix) - 1
	if len(data) < max {
		max = len(data)
	}
	for k := max; k > 0; k-- {
		if bytes.Equal(data[len(data)-k:], barrierPrefix[:k]) {
			return k
		}
	}
	return 0
}

// Barrier returns once everything the runtime wrote before the call is in the ring, or after
// the timeout.
func (l *logSink) Barrier(timeout time.Duration) bool {
	id := atomic.AddUint32(&l.nextID, 1)
	ch := make(chan struct{})
	l.mu.Lock()
	l.barriers[id] = ch
	l.mu.Unlock()
	if _, err := syscall.Write(l.wfd, []byte(fmt.Sprintf("%s%08x\x00", barrierPrefix, id))); err != nil {
		l.mu.Lock()
		delete(l.barriers, id)
		l.mu.Unlock()
		return false
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		l.mu.Lock()
		delete(l.barriers, id)
		l.mu.Unlock()
		return false
	}
}

// Emit writes agent-generated lines (START, END, REPORT, timeout notice) into the log, on lines
// of their own.
func (l *logSink) Emit(s string) {
	if !l.ring.EndsWithNewline() {
		l.ring.Write([]byte("\n"))
	}
	l.ring.Write([]byte(s))
}
