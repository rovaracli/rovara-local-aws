package main

import (
	"fmt"
	"syscall"
	"testing"
	"time"
)

func writeRuntime(t *testing.T, l *logSink, s string) {
	t.Helper()
	if _, err := syscall.Write(l.wfd, []byte(s)); err != nil {
		t.Fatal(err)
	}
}

func TestBarrierOrdersLogs(t *testing.T) {
	l, err := newLogSink(newRing(1<<16), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		mark := l.ring.Mark()
		writeRuntime(t, l, fmt.Sprintf("line %d\npartial", i))
		if !l.Barrier(2 * time.Second) {
			t.Fatalf("barrier %d timed out", i)
		}
		got, _ := l.ring.Since(mark, 1000)
		if want := fmt.Sprintf("line %d\npartial", i); string(got) != want {
			t.Fatalf("iteration %d: got %q want %q", i, got, want)
		}
		l.Emit("END\n") // goes on a line of its own after the partial line
		after, _ := l.ring.Since(mark, 1000)
		if want := fmt.Sprintf("line %d\npartial\nEND\n", i); string(after) != want {
			t.Fatalf("iteration %d: got %q want %q", i, after, want)
		}
	}
}

func TestConsumeSplitMarkerAndLookalikes(t *testing.T) {
	l := &logSink{ring: newRing(1 << 10), barriers: map[uint32]chan struct{}{}}
	ch := make(chan struct{})
	l.barriers[0x2a] = ch
	marker := fmt.Sprintf("%s%08x\x00", barrierPrefix, 0x2a)
	// Feed one byte at a time, with ordinary text around it, and a NUL-R lookalike.
	stream := "ab\x00Rcd" + marker + "tail"
	var pend []byte
	for i := 0; i < len(stream); i++ {
		pend = l.consume(append(pend, stream[i]))
	}
	select {
	case <-ch:
	default:
		t.Fatal("barrier not signalled")
	}
	got, _ := l.ring.Since(0, 100)
	// "tail" is fully flushed; nothing of the marker leaks into the log.
	if string(got) != "ab\x00Rcdtail" {
		t.Fatalf("got %q", got)
	}
	if len(pend) != 0 {
		t.Fatalf("held back %q", pend)
	}
}

func TestLargeWritesDoNotStall(t *testing.T) {
	l, err := newLogSink(newRing(1<<16), nil)
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 3<<20)
	for i := range big {
		big[i] = 'a' + byte(i%26)
	}
	done := make(chan struct{})
	go func() {
		for off := 0; off < len(big); {
			n, err := syscall.Write(l.wfd, big[off:])
			if err != nil {
				return
			}
			off += n
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writer stalled")
	}
	if !l.Barrier(5 * time.Second) {
		t.Fatal("barrier timed out")
	}
	got, tr := l.ring.Since(0, 1<<20)
	if len(got) != 1<<16 || !tr {
		t.Fatalf("got %d bytes truncated=%v", len(got), tr)
	}
}
