package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// The runner's package store: where the front keeps the real code of the functions it took over (and, small, of the ones it did not, so a
// later change to the function's configuration can still move it to the runner) and the layers it saw published. Content-addressed by
// SHA-256, reference counted, bounded: a package that does not fit is refused, never half kept. One directory per front process, removed
// at reset and at exit; nothing here is ever served except to the worker over the runner pipe and, signed, as Code.Location.

var errStoreFull = errors.New("the function package store is full")

type blobInfo struct {
	size int64
	refs int
}

type runnerStore struct {
	mu       sync.Mutex
	dir      string
	max      int64
	used     int64 // bytes held, plus bytes reserved by puts in flight
	blobs    map[string]*blobInfo
	tmpCount int
}

func newRunnerStore(dir string, max int64) (*runnerStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &runnerStore{dir: dir, max: max, blobs: map[string]*blobInfo{}}, nil
}

func (st *runnerStore) path(sha string) string { return filepath.Join(st.dir, sha+".zip") }

// put reads r (at most limit bytes; more is an error), keeps it under its SHA-256 and returns one reference to it. A blob already held is
// not written again. The caller releases the reference with unref when it no longer needs the bytes.
func (st *runnerStore) put(r io.Reader, limit int64) (sha string, size int64, err error) {
	st.mu.Lock()
	if limit > st.max-st.used {
		limit = st.max - st.used
	}
	if limit <= 0 {
		st.mu.Unlock()
		return "", 0, errStoreFull
	}
	reserved := limit
	st.used += reserved
	st.tmpCount++
	tmp := filepath.Join(st.dir, fmt.Sprintf(".incoming-%d", st.tmpCount))
	st.mu.Unlock()
	settle := func(actual int64) { // gives back what was reserved beyond what is kept
		st.mu.Lock()
		st.used -= reserved - actual
		st.mu.Unlock()
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		settle(0)
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, limit+1))
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = errStoreFull
	}
	if err != nil {
		os.Remove(tmp)
		settle(0)
		return "", 0, err
	}
	sha = hex.EncodeToString(h.Sum(nil))
	st.mu.Lock()
	defer st.mu.Unlock()
	if b := st.blobs[sha]; b != nil { // the same bytes again: keep one copy
		b.refs++
		st.used -= reserved
		os.Remove(tmp)
		return sha, b.size, nil
	}
	if err := os.Rename(tmp, st.path(sha)); err != nil {
		os.Remove(tmp)
		st.used -= reserved
		return "", 0, err
	}
	st.used -= reserved - n
	st.blobs[sha] = &blobInfo{size: n, refs: 1}
	return sha, n, nil
}

// ref adds a reference to a blob that is held. False when it is not.
func (st *runnerStore) ref(sha string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	b := st.blobs[sha]
	if b == nil {
		return false
	}
	b.refs++
	return true
}

// unref drops one reference; the file goes with the last one.
func (st *runnerStore) unref(sha string) {
	if sha == "" {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	b := st.blobs[sha]
	if b == nil {
		return
	}
	b.refs--
	if b.refs <= 0 {
		os.Remove(st.path(sha))
		st.used -= b.size
		delete(st.blobs, sha)
	}
}

func (st *runnerStore) size(sha string) (int64, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if b := st.blobs[sha]; b != nil {
		return b.size, true
	}
	return 0, false
}

// open returns the blob's file for reading. The caller closes it.
func (st *runnerStore) open(sha string) (*os.File, int64, error) {
	st.mu.Lock()
	b := st.blobs[sha]
	st.mu.Unlock()
	if b == nil {
		return nil, 0, os.ErrNotExist
	}
	f, err := os.Open(st.path(sha))
	if err != nil {
		return nil, 0, err
	}
	return f, b.size, nil
}

// wipe removes everything (a reset, or the end of the process).
func (st *runnerStore) wipe() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for sha := range st.blobs {
		os.Remove(st.path(sha))
	}
	st.blobs = map[string]*blobInfo{}
	st.used = 0
}

func (st *runnerStore) stats() (used, max int64, count int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.used, st.max, len(st.blobs)
}
