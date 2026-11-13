package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := invokeMsg{Type: "invoke", RequestID: "r-1", Payload: "e30=", TimeoutMs: 3000, FunctionArn: "arn:aws:lambda:us-east-1:000000000000:function:f"}
	if err := writeFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if n := binary.BigEndian.Uint32(raw[:4]); int(n) != len(raw)-4 {
		t.Fatalf("length prefix %d, body %d", n, len(raw)-4)
	}
	body, err := readFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"requestId":"r-1"`) || !strings.Contains(string(body), `"type":"invoke"`) {
		t.Fatalf("body %s", body)
	}
	if _, err := readFrame(&buf); err != io.EOF {
		t.Fatalf("want io.EOF at a frame boundary, got %v", err)
	}
}

func TestFrameTruncated(t *testing.T) {
	var buf bytes.Buffer
	writeFrame(&buf, map[string]string{"type": "x"})
	full := buf.Bytes()
	for _, cut := range []int{1, 3, 4, 6, len(full) - 1} {
		_, err := readFrame(bytes.NewReader(full[:cut]))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("cut at %d: want ErrUnexpectedEOF, got %v", cut, err)
		}
	}
}

func TestFrameLimits(t *testing.T) {
	var hdr [4]byte
	if _, err := readFrame(bytes.NewReader(hdr[:])); !errors.Is(err, errFrameEmpty) {
		t.Errorf("zero length: %v", err)
	}
	binary.BigEndian.PutUint32(hdr[:], maxFrameBytes+1)
	if _, err := readFrame(bytes.NewReader(hdr[:])); !errors.Is(err, errFrameTooLarge) {
		t.Errorf("declared too large: %v", err)
	}
	// Exactly at the limit is accepted by the reader.
	binary.BigEndian.PutUint32(hdr[:], maxFrameBytes)
	body := append(hdr[:], bytes.Repeat([]byte{' '}, maxFrameBytes)...)
	if b, err := readFrame(bytes.NewReader(body)); err != nil || len(b) != maxFrameBytes {
		t.Errorf("at limit: %d %v", len(b), err)
	}
	if err := writeFrame(io.Discard, map[string]string{"x": strings.Repeat("a", maxFrameBytes)}); !errors.Is(err, errFrameTooLarge) {
		t.Errorf("write too large: %v", err)
	}
}

func TestFrameConcurrentWritersStayWhole(t *testing.T) {
	var buf bytes.Buffer
	fw := &frameWriter{w: &buf}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fw.send(map[string]string{"type": "t", "pad": strings.Repeat("z", 5000)})
		}()
	}
	wg.Wait()
	n := 0
	for {
		b, err := readFrame(&buf)
		if err == io.EOF {
			break
		}
		if err != nil || !strings.HasPrefix(string(b), `{"`) {
			t.Fatalf("frame %d: %v", n, err)
		}
		n++
	}
	if n != 50 {
		t.Fatalf("read %d frames", n)
	}
}
