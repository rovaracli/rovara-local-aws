package main

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRingBasics(t *testing.T) {
	r := newRing(8)
	r.Write([]byte("abc"))
	m := r.Mark()
	r.Write([]byte("def"))
	d, tr := r.Since(m, 100)
	if string(d) != "def" || tr {
		t.Fatalf("got %q %v", d, tr)
	}
	d, tr = r.Since(0, 100)
	if string(d) != "abcdef" || tr {
		t.Fatalf("got %q %v", d, tr)
	}
	r.Write([]byte("ghijk")) // 11 bytes written, 8 kept: "defghijk"
	d, tr = r.Since(0, 100)
	if string(d) != "defghijk" || !tr {
		t.Fatalf("got %q %v", d, tr)
	}
	d, tr = r.Since(0, 3)
	if string(d) != "ijk" || !tr {
		t.Fatalf("got %q %v", d, tr)
	}
	d, tr = r.Since(r.Mark(), 3)
	if len(d) != 0 || tr {
		t.Fatalf("empty window gave %q %v", d, tr)
	}
	r.Write(bytes.Repeat([]byte("x"), 20)) // larger than the ring
	d, _ = r.Since(0, 100)
	if string(d) != "xxxxxxxx" {
		t.Fatalf("got %q", d)
	}
}

func TestRingMatchesNaive(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 200; iter++ {
		capacity := 1 + rng.Intn(40)
		r := newRing(capacity)
		var all []byte
		marks := []int64{0}
		for i := 0; i < 30; i++ {
			chunk := make([]byte, rng.Intn(25))
			rng.Read(chunk)
			r.Write(chunk)
			all = append(all, chunk...)
			marks = append(marks, r.Mark())
		}
		for _, m := range marks {
			max := rng.Intn(60)
			got, tr := r.Since(m, max)
			want := all[m:]
			wantTr := false
			if len(want) > capacity {
				want, wantTr = want[len(want)-capacity:], true
			}
			if len(want) > max {
				want, wantTr = want[len(want)-max:], true
			}
			if !bytes.Equal(got, want) || tr != wantTr {
				t.Fatalf("cap %d mark %d max %d: got %q/%v want %q/%v", capacity, m, max, got, tr, want, wantTr)
			}
		}
	}
}

func TestRingNewline(t *testing.T) {
	r := newRing(4)
	if !r.EndsWithNewline() {
		t.Fatal("empty ring should count as ending with a newline")
	}
	r.Write([]byte("a"))
	if r.EndsWithNewline() {
		t.Fatal("no newline yet")
	}
	r.Write([]byte("b\n"))
	if !r.EndsWithNewline() {
		t.Fatal("newline expected")
	}
}
