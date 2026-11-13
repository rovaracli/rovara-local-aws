package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Wire framing between the worker and the agent (protocol "agent/1"), carried on the agent's
// stdin (worker to agent) and stdout (agent to worker). See PROTOCOL.md.
//
// A frame is a 4-byte big-endian unsigned length N followed by N bytes holding one UTF-8 JSON
// object. N must be between 2 and maxFrameBytes. Every object has a "type" string.

const (
	protoVersion  = "agent/1"
	agentVersion  = "0.1.0"
	maxFrameBytes = 16 << 20 // 16 MiB: a 6 MiB payload as base64 plus the envelope, with headroom

	// AWS Lambda's synchronous invoke limit in each direction.
	maxPayloadBytes = 6291556

	// Caps on error strings that come from the runtime, applied before they are encoded.
	maxErrorTypeBytes    = 256
	maxErrorMessageBytes = 64 << 10
)

var (
	errFrameTooLarge = errors.New("frame exceeds the 16 MiB limit")
	errFrameEmpty    = errors.New("frame has a zero length")
)

// writeFrame marshals v and writes it as one frame with a single Write call.
func writeFrame(w io.Writer, v any) error {
	var jb bytes.Buffer
	enc := json.NewEncoder(&jb)
	enc.SetEscapeHTML(false) // "<" must stay one byte, not become \u003c
	if err := enc.Encode(v); err != nil {
		return err
	}
	b := bytes.TrimSuffix(jb.Bytes(), []byte("\n"))
	if len(b) > maxFrameBytes {
		return errFrameTooLarge
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}

// readFrame reads one frame body. It returns io.EOF only when the stream ends exactly between
// frames; a stream that ends inside a frame gives io.ErrUnexpectedEOF.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, errFrameEmpty
	}
	if n > maxFrameBytes {
		return nil, fmt.Errorf("%w (declared %d bytes)", errFrameTooLarge, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
}

// frameWriter serialises frames from several goroutines onto one stream.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (f *frameWriter) send(v any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return writeFrame(f.w, v)
}

// ---- messages ----

// Worker to agent.

type invokeMsg struct {
	Type            string `json:"type"`
	RequestID       string `json:"requestId"`
	Payload         string `json:"payload"` // base64 (standard alphabet)
	TimeoutMs       int64  `json:"timeoutMs,omitempty"`
	DeadlineMs      int64  `json:"deadlineMs,omitempty"` // epoch ms; used only when timeoutMs is absent
	FunctionArn     string `json:"functionArn"`
	TraceID         string `json:"traceId,omitempty"`
	ClientContext   string `json:"clientContext,omitempty"`
	CognitoIdentity string `json:"cognitoIdentity,omitempty"`
	FunctionVersion string `json:"functionVersion,omitempty"`
	MemorySizeMb    int    `json:"memorySizeMb,omitempty"`
	LogBytes        int    `json:"logBytes,omitempty"`
}

// Agent to worker.

type helloMsg struct {
	Type    string   `json:"type"`
	Proto   string   `json:"proto"`
	Agent   string   `json:"agent"`
	Version string   `json:"version"`
	Pid     int      `json:"pid"`
	Listen  string   `json:"listen"`
	Command []string `json:"command"`
}

type readyMsg struct {
	Type           string  `json:"type"`
	InitDurationMs float64 `json:"initDurationMs"`
	LogTail        string  `json:"logTail"`
}

type initErrorMsg struct {
	Type           string  `json:"type"`
	Reason         string  `json:"reason"` // runtime_reported | exited | timeout | start_failed
	ErrorType      string  `json:"errorType"`
	ErrorMessage   string  `json:"errorMessage"`
	Payload        string  `json:"payload"` // base64 of the error document
	LogTail        string  `json:"logTail"`
	InitDurationMs float64 `json:"initDurationMs"`
}

type runtimeExitMsg struct {
	Type     string `json:"type"`
	ExitCode int    `json:"exitCode"`
	Signal   string `json:"signal,omitempty"`
	Message  string `json:"message"`
	LogTail  string `json:"logTail"`
}

type resultMsg struct {
	Type             string  `json:"type"`
	RequestID        string  `json:"requestId"`
	Status           string  `json:"status"` // ok | function_error | init_error | timeout | crash | rejected
	Payload          string  `json:"payload"`
	PayloadTruncated bool    `json:"payloadTruncated,omitempty"` // the payload was dropped to fit one frame
	ErrorType        string  `json:"errorType,omitempty"`
	ErrorMessage     string  `json:"errorMessage,omitempty"`
	LogTail          string  `json:"logTail"`
	LogTruncated     bool    `json:"logTruncated,omitempty"`
	DurationMs       float64 `json:"durationMs"`
	BilledDurationMs int64   `json:"billedDurationMs"`
	InitDurationMs   float64 `json:"initDurationMs,omitempty"`
	MaxMemoryUsed    int64   `json:"maxMemoryUsed"` // bytes
}

type fatalMsg struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

const (
	statusOK            = "ok"
	statusFunctionError = "function_error"
	statusInitError     = "init_error"
	statusTimeout       = "timeout"
	statusCrash         = "crash"
	statusRejected      = "rejected"
)
