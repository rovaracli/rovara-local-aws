package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"sync"
)

// The AWS event stream encoding (content type application/vnd.amazon.eventstream), written by the front for the operations whose
// answer is a stream of events: SageMaker InvokeEndpointWithResponseStream now, Bedrock's ConverseStream and
// InvokeModelWithResponseStream later (the Bedrock route reuses this file as it is).
//
// A message is
//
//	total length   uint32 big endian   the whole message, prelude and trailer included
//	headers length uint32 big endian
//	prelude CRC    uint32 big endian   CRC-32 (IEEE) of the first 8 bytes
//	headers        a run of: name length uint8, name, value type uint8, value
//	payload
//	message CRC    uint32 big endian   CRC-32 (IEEE) of every byte before it
//
// Header value types: 0 true, 1 false (no value bytes), 2 byte, 3 int16, 4 int32, 5 int64, 6 bytes (uint16 length), 7 string (uint16
// length, UTF-8), 8 timestamp (int64 milliseconds since the epoch), 9 UUID (16 bytes). The three message kinds are told apart by the
// `:message-type` header: "event" (with `:event-type` and `:content-type`), "exception" (with `:exception-type` and `:content-type`)
// and "error" (with `:error-code` and `:error-message`, no payload). Nothing here is specific to a service.

// Limits of the framing (the SDKs refuse more): 128 KiB of headers, 16 MiB of payload.
const (
	eventStreamMaxHeaders  = 128 << 10
	eventStreamMaxPayload  = 16 << 20
	eventStreamContentType = "application/vnd.amazon.eventstream"
)

// header value types
const (
	esTrue      byte = 0
	esFalse     byte = 1
	esByte      byte = 2
	esInt16     byte = 3
	esInt32     byte = 4
	esInt64     byte = 5
	esBytes     byte = 6
	esString    byte = 7
	esTimestamp byte = 8
	esUUID      byte = 9
)

// esHeader is one header. Value is by type: bool for esTrue/esFalse (the type is taken from it), int8 for esByte, int16, int32, int64
// (esInt64 and esTimestamp), []byte (esBytes), string (esString), [16]byte (esUUID).
type esHeader struct {
	Name  string
	Type  byte
	Value any
}

func esStringHeader(name, value string) esHeader {
	return esHeader{Name: name, Type: esString, Value: value}
}
func esBoolHeader(name string, v bool) esHeader {
	t := esFalse
	if v {
		t = esTrue
	}
	return esHeader{Name: name, Type: t, Value: v}
}
func esBytesHeader(name string, v []byte) esHeader {
	return esHeader{Name: name, Type: esBytes, Value: v}
}
func esInt32Header(name string, v int32) esHeader {
	return esHeader{Name: name, Type: esInt32, Value: v}
}
func esInt64Header(name string, v int64) esHeader {
	return esHeader{Name: name, Type: esInt64, Value: v}
}
func esTimestampHeader(name string, ms int64) esHeader {
	return esHeader{Name: name, Type: esTimestamp, Value: ms}
}

var errEventStream = errors.New("event stream: the message cannot be encoded")

func encodeHeaders(headers []esHeader) ([]byte, error) {
	var b bytes.Buffer
	for _, h := range headers {
		if len(h.Name) == 0 || len(h.Name) > 255 {
			return nil, errEventStream
		}
		b.WriteByte(byte(len(h.Name)))
		b.WriteString(h.Name)
		b.WriteByte(h.Type)
		switch h.Type {
		case esTrue, esFalse:
		case esByte:
			v, ok := h.Value.(int8)
			if !ok {
				return nil, errEventStream
			}
			b.WriteByte(byte(v))
		case esInt16:
			v, ok := h.Value.(int16)
			if !ok {
				return nil, errEventStream
			}
			b.Write(binary.BigEndian.AppendUint16(nil, uint16(v)))
		case esInt32:
			v, ok := h.Value.(int32)
			if !ok {
				return nil, errEventStream
			}
			b.Write(binary.BigEndian.AppendUint32(nil, uint32(v)))
		case esInt64, esTimestamp:
			v, ok := h.Value.(int64)
			if !ok {
				return nil, errEventStream
			}
			b.Write(binary.BigEndian.AppendUint64(nil, uint64(v)))
		case esBytes, esString:
			var data []byte
			switch v := h.Value.(type) {
			case []byte:
				if h.Type != esBytes {
					return nil, errEventStream
				}
				data = v
			case string:
				if h.Type != esString {
					return nil, errEventStream
				}
				data = []byte(v)
			default:
				return nil, errEventStream
			}
			if len(data) > 0xffff {
				return nil, errEventStream
			}
			b.Write(binary.BigEndian.AppendUint16(nil, uint16(len(data))))
			b.Write(data)
		case esUUID:
			v, ok := h.Value.([16]byte)
			if !ok {
				return nil, errEventStream
			}
			b.Write(v[:])
		default:
			return nil, errEventStream
		}
		if b.Len() > eventStreamMaxHeaders {
			return nil, errEventStream
		}
	}
	return b.Bytes(), nil
}

// encodeEventStreamMessage frames one message.
func encodeEventStreamMessage(headers []esHeader, payload []byte) ([]byte, error) {
	hb, err := encodeHeaders(headers)
	if err != nil || len(payload) > eventStreamMaxPayload {
		return nil, errEventStream
	}
	total := 12 + len(hb) + len(payload) + 4
	msg := make([]byte, 0, total)
	msg = binary.BigEndian.AppendUint32(msg, uint32(total))
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(hb)))
	msg = binary.BigEndian.AppendUint32(msg, crc32.ChecksumIEEE(msg[:8]))
	msg = append(msg, hb...)
	msg = append(msg, payload...)
	msg = binary.BigEndian.AppendUint32(msg, crc32.ChecksumIEEE(msg))
	return msg, nil
}

// eventStreamEvent frames an event: `:event-type`, `:content-type` and `:message-type: event`, in the order AWS writes them.
func eventStreamEvent(eventType, contentType string, payload []byte) ([]byte, error) {
	return encodeEventStreamMessage([]esHeader{
		esStringHeader(":event-type", eventType),
		esStringHeader(":content-type", contentType),
		esStringHeader(":message-type", "event"),
	}, payload)
}

// eventStreamException frames a modeled exception (for example SageMaker's ModelStreamError): the payload is the exception's JSON.
func eventStreamException(exceptionType, contentType string, payload []byte) ([]byte, error) {
	return encodeEventStreamMessage([]esHeader{
		esStringHeader(":exception-type", exceptionType),
		esStringHeader(":content-type", contentType),
		esStringHeader(":message-type", "exception"),
	}, payload)
}

// eventStreamError frames an unmodeled error: no payload; the SDKs raise it with the code and the message.
func eventStreamError(code, message string) ([]byte, error) {
	return encodeEventStreamMessage([]esHeader{
		esStringHeader(":error-code", code),
		esStringHeader(":error-message", message),
		esStringHeader(":message-type", "error"),
	}, nil)
}

// eventStreamWriter writes framed messages to a response, flushing each one so a client sees it as it is written. It is safe for one
// goroutine at a time; the mutex only keeps a late write from interleaving with a close.
type eventStreamWriter struct {
	mu      sync.Mutex
	w       io.Writer
	flusher http.Flusher
	err     error
	closed  bool
}

func newEventStreamWriter(w io.Writer) *eventStreamWriter {
	ew := &eventStreamWriter{w: w}
	if f, ok := w.(http.Flusher); ok {
		ew.flusher = f
	}
	return ew
}

func (e *eventStreamWriter) write(msg []byte, err error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return io.ErrClosedPipe
	}
	if e.err != nil {
		return e.err
	}
	if err != nil {
		e.err = err
		return err
	}
	if _, werr := e.w.Write(msg); werr != nil {
		e.err = werr
		return werr
	}
	if e.flusher != nil {
		e.flusher.Flush()
	}
	return nil
}

func (e *eventStreamWriter) Event(eventType, contentType string, payload []byte) error {
	return e.write(eventStreamEvent(eventType, contentType, payload))
}

func (e *eventStreamWriter) Exception(exceptionType, contentType string, payload []byte) error {
	return e.write(eventStreamException(exceptionType, contentType, payload))
}

func (e *eventStreamWriter) Error(code, message string) error {
	return e.write(eventStreamError(code, message))
}

// Close stops further writes (a stream ends when the response ends; there is no end marker in the framing).
func (e *eventStreamWriter) Close() {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}
