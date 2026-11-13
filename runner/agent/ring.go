package main

import "sync"

// ring is a bounded byte buffer that keeps the newest cap bytes of everything written to it.
// total counts every byte ever written, so an offset taken with Mark stays meaningful (or is
// detected as overwritten) later.
type ring struct {
	mu    sync.Mutex
	buf   []byte
	pos   int // next write index
	total int64
	last  byte
}

func newRing(capacity int) *ring {
	if capacity < 1 {
		capacity = 1
	}
	return &ring{buf: make([]byte, capacity)}
}

func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	r.total += int64(n)
	r.last = p[n-1]
	c := len(r.buf)
	if n >= c {
		copy(r.buf, p[n-c:])
		r.pos = 0
		return n, nil
	}
	k := copy(r.buf[r.pos:], p)
	if k < n {
		copy(r.buf, p[k:])
	}
	r.pos = (r.pos + n) % c
	if r.pos == 0 && n > 0 {
	}
	return n, nil
}

// Mark returns the offset of the next byte to be written.
func (r *ring) Mark() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// EndsWithNewline reports whether the buffer is empty or its last byte is '\n'.
func (r *ring) EndsWithNewline() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total == 0 || r.last == '\n'
}

// Since returns the bytes written from offset mark to now, limited to the newest max bytes and
// to what the ring still holds. truncated is true when older bytes were dropped.
func (r *ring) Since(mark int64, max int) (data []byte, truncated bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mark < 0 {
		mark = 0
	}
	held := int64(len(r.buf))
	if r.total < held {
		held = r.total
	}
	oldest := r.total - held
	start := mark
	if start < oldest {
		start = oldest
		truncated = true
	}
	if max >= 0 && r.total-start > int64(max) {
		start = r.total - int64(max)
		truncated = true
	}
	n := int(r.total - start)
	if n <= 0 {
		return nil, truncated
	}
	out := make([]byte, n)
	c := len(r.buf)
	// index of the byte at absolute offset start
	idx := ((r.pos-int(r.total-start))%c + c) % c
	k := copy(out, r.buf[idx:])
	if k < n {
		copy(out[k:], r.buf[:n-k])
	}
	return out, truncated
}
