package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

// The runner pipe, protocol runner/2 (designs-2026-10-30/slice4-function-runner-design.md, section 1).
//
// The Cloud worker keeps one `docker exec -i <local-aws> <front> runner-pipe` per helper. `runner-pipe` joins its stdin and stdout to the
// front's unix socket (ROVARA_AWS_RUNNER_SOCKET, mode 0600), so there is no TCP port and no control token: only whoever can `docker exec`
// into the helper (the worker) can speak to the front, and the front never sees anything but frames. Everything below is the byte
// stream of that socket. The front is the server of the protocol (it asks, the worker answers), the worker is the one that dials.
//
// Framing is agent/1's (runner/agent/PROTOCOL.md): a 4-byte big-endian length N, then N bytes of one UTF-8 JSON object with a string
// "type", 2 <= N <= 16 MiB. Binary data is base64 (standard alphabet, padded); field names are camelCase. A frame with an unknown
// "type" is ignored by both sides. A frame that is not a JSON object, a bad length, or a known type that does not parse is a protocol
// error: the receiver sends `error` when it can and closes the stream.
//
//	front -> worker                     worker -> front
//	hello   {proto, front, version}     hello   {proto, worker, version, runtimes?}      one each, first frame of each side
//	register {id, fn}                   need     {id, packages: [sha256...]}              fn: see regFn; need may be empty
//	package  {id, sha256, kind, size}   registered {id, ok, error?}                       after every needed package arrived
//	chunk    {id, sha256, seq, data, last}
//	invoke   {id, name, version, ...}   result   {id, status, ...}                        exactly one per invoke
//	unregister {id, name, version?}     unregistered {id}
//	stop_all {id}                       stopped  {id}                                     every environment of the run is gone
//	                                    error    {id?, message}
//
// Code. The front keeps every package (a function's zip, a layer's zip) in its own bounded store and sends one only when the worker does
// not hold its SHA-256: `register` carries the digests, the worker answers `need` with the ones it lacks, and the front streams each as
// `package` then `chunk` frames (raw chunks of at most runnerChunkBytes, in order, seq from 0, `last` true on the final one). The worker
// counts the bytes, checks the exact size and digest, judges and unpacks the zip, and only then answers `registered`. A package refused
// (not a zip, a bomb, over its budget, an architecture it cannot run) is `registered` with ok false and an error {type, message}; the
// front turns that into the function's own error (the type is kept: Rovara.Unsupported, InvalidParameterValueException ...).
//
// Invoke. One `invoke` per call, from either path (the stub's request on the hidden queue, or a direct Invoke the front answers itself).
// The front registers the function version on the connection first (once per version and configuration hash), so the worker never sees
// an invoke for a function it was not told about; an invoke the worker does not know comes back status "unavailable" reason
// "not_registered". payload is the event as base64 (at most 6,291,556 bytes); timeoutMs is the deadline this call runs under (the
// function's Timeout, or less when the engine's 30 s ceiling applies to the stub path). The worker answers `result` with the agent's
// statuses (ok, function_error, init_error, timeout, crash, rejected) or its own (throttled, unavailable); see runnerResult.
//
// Versions. register's fn.version is "$LATEST" or a published version number; the front sends a new `register` for the same name and
// version when the configuration or code changed (the worker replaces the function's pool, retiring warm environments of the old one).
// `unregister` without a version removes every version; `stop_all` is the reset barrier: it is answered only after every environment of
// the run is confirmed gone, and no invoke is sent before the front has the answer.
//
// Disconnect. When the stream closes the front fails every pending request (a pending invoke becomes a Rovara.RunnerUnavailable error for
// its caller), forgets what it registered on that connection, and registers again, on first use, on the next one. The worker treats
// closing the stream as "stop everything of this run".
const (
	runnerProto      = "runner/2"
	maxRunnerFrame   = 16 << 20
	runnerChunkBytes = 512 << 10
	maxPayloadBytes  = 6291556 // Lambda's invoke and response limit, as the agent enforces it (decoded bytes)
)

// frame types
const (
	ftHello        = "hello"
	ftRegister     = "register"
	ftNeed         = "need"
	ftPackage      = "package"
	ftChunk        = "chunk"
	ftRegistered   = "registered"
	ftInvoke       = "invoke"
	ftResult       = "result"
	ftUnregister   = "unregister"
	ftUnregistered = "unregistered"
	ftStopAll      = "stop_all"
	ftStopped      = "stopped"
	ftError        = "error"
)

var errFrameTooLarge = errors.New("runner frame over 16 MiB")

// frameWriter writes frames to one stream; safe for concurrent use.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (fw *frameWriter) write(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxRunnerFrame {
		return errFrameTooLarge
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	fw.mu.Lock()
	defer fw.mu.Unlock()
	_, err = fw.w.Write(buf)
	return err
}

// frameReader reads frames from one stream.
type frameReader struct{ r *bufio.Reader }

func newFrameReader(r io.Reader) *frameReader { return &frameReader{r: bufio.NewReaderSize(r, 64<<10)} }

// next returns the next frame's type and bytes. io.EOF only at a frame boundary.
func (fr *frameReader) next() (string, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return "", nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 2 || n > maxRunnerFrame {
		return "", nil, fmt.Errorf("bad runner frame length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(fr.r, b); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return "", nil, err
	}
	var t struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.Type == "" {
		return "", nil, errors.New("a runner frame that is not a JSON object with a type")
	}
	return t.Type, b, nil
}

// ---- front to worker

type helloFrame struct {
	Type     string   `json:"type"`
	Proto    string   `json:"proto"`
	Front    string   `json:"front,omitempty"`
	Worker   string   `json:"worker,omitempty"`
	Version  string   `json:"version,omitempty"`
	Runtimes []string `json:"runtimes,omitempty"` // worker: the runtimes it can run (informational)
}

type pkgRef struct {
	Arn       string `json:"arn,omitempty"` // a layer's version ARN
	SHA256    string `json:"sha256"`        // lower-case hex of the whole zip
	SizeBytes int64  `json:"sizeBytes"`
}

// regFn is one function version as the worker runs it. Every field the real Lambda configuration holds that a sandbox needs is here;
// the stub in the engine never appears.
type regFn struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	Arn            string            `json:"arn"`
	Runtime        string            `json:"runtime"`
	Handler        string            `json:"handler"`
	MemoryMb       int               `json:"memoryMb"`
	TimeoutSeconds int               `json:"timeoutSeconds"`
	EphemeralMb    int               `json:"ephemeralMb"`
	Env            map[string]string `json:"env"`
	Region         string            `json:"region"`
	Architectures  []string          `json:"architectures,omitempty"`
	PackageType    string            `json:"packageType"` // "Zip" or "Image"
	ImageURI       string            `json:"imageUri,omitempty"`
	Package        *pkgRef           `json:"package,omitempty"`
	Layers         []pkgRef          `json:"layers,omitempty"` // in order: later layers win
	ConfigHash     string            `json:"configHash"`
}

type registerFrame struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Fn   regFn  `json:"fn"`
}

type packageFrame struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	SHA256    string `json:"sha256"`
	Kind      string `json:"kind"` // "function" or "layer"
	SizeBytes int64  `json:"sizeBytes"`
}

type chunkFrame struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Seq    int    `json:"seq"`
	Data   string `json:"data"` // base64
	Last   bool   `json:"last"`
}

type invokeFrame struct {
	Type            string `json:"type"`
	ID              string `json:"id"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	RequestID       string `json:"requestId"`
	Payload         string `json:"payload"` // base64
	TimeoutMs       int64  `json:"timeoutMs"`
	FunctionArn     string `json:"functionArn,omitempty"`
	TraceID         string `json:"traceId,omitempty"`
	ClientContext   string `json:"clientContext,omitempty"`
	CognitoIdentity string `json:"cognitoIdentity,omitempty"`
	LogBytes        int    `json:"logBytes,omitempty"`
	Source          string `json:"source"` // "direct" (the front answered an Invoke itself) or "stub" (the engine's stub asked)
}

type unregisterFrame struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type stopAllFrame struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ---- worker to front

type needFrame struct {
	ID       string   `json:"id"`
	Packages []string `json:"packages"`
}

type frameError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type registeredFrame struct {
	ID    string      `json:"id"`
	OK    bool        `json:"ok"`
	Error *frameError `json:"error,omitempty"`
}

// runnerResult is the worker's answer to one invoke.
type runnerResult struct {
	ID               string  `json:"id"`
	Status           string  `json:"status"`           // ok function_error init_error timeout crash rejected throttled unavailable
	Reason           string  `json:"reason,omitempty"` // throttled: concurrency|memory; unavailable: not_registered|closed|start_failed|protocol_error|stopped|invalid_request
	Detail           string  `json:"detail,omitempty"`
	Payload          string  `json:"payload,omitempty"` // base64: the response (ok) or the error document
	ErrorType        string  `json:"errorType,omitempty"`
	ErrorMessage     string  `json:"errorMessage,omitempty"`
	LogTail          string  `json:"logTail,omitempty"`
	LogTruncated     bool    `json:"logTruncated,omitempty"`
	DurationMs       flexInt `json:"durationMs,omitempty"`
	BilledDurationMs flexInt `json:"billedDurationMs,omitempty"`
	InitDurationMs   flexInt `json:"initDurationMs,omitempty"`
	MaxMemoryUsed    flexInt `json:"maxMemoryUsed,omitempty"` // bytes
	Cold             bool    `json:"cold,omitempty"`
	MemoryClamped    bool    `json:"memoryClamped,omitempty"`
}

type idFrame struct {
	ID string `json:"id"`
}

type errorFrame struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Message string `json:"message"`
}

// flexInt is a whole number that is read from a fractional one too (rounded): a timing or a size the worker reports as 12.6 must not turn the
// whole result into a protocol error.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		return nil
	}
	var n int64
	if json.Unmarshal(b, &n) == nil {
		*f = flexInt(n)
		return nil
	}
	var x float64
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return errors.New("not a number")
	}
	*f = flexInt(math.Round(x))
	return nil
}
