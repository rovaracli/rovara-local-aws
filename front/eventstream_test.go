package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// goldenFrames are known-good frames from an independent encoder (front/tools/eventstream_check.py gold: struct and zlib only), which
// botocore's event stream parser accepts (it checks both CRCs). The Go encoder must write exactly these bytes.
var goldenFrames = map[string]string{
	"payload_part":       "00000074000000597bc770360b3a6576656e742d7479706507000b5061796c6f6164506172740d3a636f6e74656e742d747970650700186170706c69636174696f6e2f6f637465742d73747265616d0d3a6d6573736167652d747970650700056576656e7468656c6c6f20776f726c648e26478f",
	"empty_part":         "0000006900000059e3b723050b3a6576656e742d7479706507000b5061796c6f6164506172740d3a636f6e74656e742d747970650700186170706c69636174696f6e2f6f637465742d73747265616d0d3a6d6573736167652d747970650700056576656e74139da204",
	"model_stream_error": "000000a70000005e2bf6e01c0f3a657863657074696f6e2d747970650700104d6f64656c53747265616d4572726f720d3a636f6e74656e742d747970650700106170706c69636174696f6e2f6a736f6e0d3a6d6573736167652d74797065070009657863657074696f6e7b224d657373616765223a227468652073747265616d2062726f6b65222c224572726f72436f6465223a2253747265616d42726f6b656e227de18db430",
	"error":              "0000005e0000004e7365c2540b3a6572726f722d636f6465070013496e7465726e616c5365727665724572726f720e3a6572726f722d6d657373616765070004626f6f6d0d3a6d6573736167652d747970650700056572726f72ada60efe",
	"all_types":          "0000006a00000059a41759d5017400016601016202fb017303fb2e01690400011170016c05ffffff00000000000562797465730600030001ff0373747207000668c3a96c6c6f027473080000018bcfe5687b017509000102030405060708090a0b0c0d0e0f78b98148b3",
}

func goldenInputs() map[string][]byte {
	uuid := [16]byte{}
	for i := range uuid {
		uuid[i] = byte(i)
	}
	mk := func(h []esHeader, p []byte) []byte {
		b, err := encodeEventStreamMessage(h, p)
		if err != nil {
			panic(err)
		}
		return b
	}
	part := func(p []byte) []byte {
		b, err := eventStreamEvent("PayloadPart", "application/octet-stream", p)
		if err != nil {
			panic(err)
		}
		return b
	}
	exc, _ := eventStreamException("ModelStreamError", "application/json", []byte(`{"Message":"the stream broke","ErrorCode":"StreamBroken"}`))
	er, _ := eventStreamError("InternalServerError", "boom")
	return map[string][]byte{
		"payload_part":       part([]byte("hello world")),
		"empty_part":         part(nil),
		"model_stream_error": exc,
		"error":              er,
		"all_types": mk([]esHeader{esBoolHeader("t", true), esBoolHeader("f", false), {Name: "b", Type: esByte, Value: int8(-5)},
			{Name: "s", Type: esInt16, Value: int16(-1234)}, esInt32Header("i", 70000), esInt64Header("l", -(1 << 40)),
			esBytesHeader("bytes", []byte{0, 1, 0xff}), esStringHeader("str", "h\u00e9llo"), esTimestampHeader("ts", 1700000000123),
			{Name: "u", Type: esUUID, Value: uuid}}, []byte("x")),
	}
}

func TestEventStreamKnownFrames(t *testing.T) {
	got := goldenInputs()
	for name, want := range goldenFrames {
		if h := hex.EncodeToString(got[name]); h != want {
			t.Errorf("%s: frame differs from the known-good one\n got  %s\n want %s", name, h, want)
		}
	}
}

// decodedMessage is a decoded frame, for the round-trip tests.
type decodedMessage struct {
	headers map[string]any
	payload []byte
}

// decodeEventStream reads every message of b, checking both CRCs and the lengths.
func decodeEventStream(b []byte) ([]decodedMessage, error) {
	var out []decodedMessage
	for len(b) > 0 {
		if len(b) < 16 {
			return nil, errors.New("short message")
		}
		total, hlen := binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint32(b[4:8])
		if crc32.ChecksumIEEE(b[:8]) != binary.BigEndian.Uint32(b[8:12]) {
			return nil, errors.New("prelude CRC")
		}
		if int(total) > len(b) || int(total) < 16+int(hlen) {
			return nil, errors.New("length")
		}
		m := b[:total]
		if crc32.ChecksumIEEE(m[:total-4]) != binary.BigEndian.Uint32(m[total-4:]) {
			return nil, errors.New("message CRC")
		}
		hs := m[12 : 12+hlen]
		d := decodedMessage{headers: map[string]any{}, payload: m[12+hlen : total-4]}
		for len(hs) > 0 {
			n := int(hs[0])
			name := string(hs[1 : 1+n])
			typ := hs[1+n]
			hs = hs[2+n:]
			var v any
			switch typ {
			case esTrue:
				v = true
			case esFalse:
				v = false
			case esByte:
				v, hs = int8(hs[0]), hs[1:]
			case esInt16:
				v, hs = int16(binary.BigEndian.Uint16(hs)), hs[2:]
			case esInt32:
				v, hs = int32(binary.BigEndian.Uint32(hs)), hs[4:]
			case esInt64, esTimestamp:
				v, hs = int64(binary.BigEndian.Uint64(hs)), hs[8:]
			case esBytes:
				l := int(binary.BigEndian.Uint16(hs))
				v, hs = append([]byte(nil), hs[2:2+l]...), hs[2+l:]
			case esString:
				l := int(binary.BigEndian.Uint16(hs))
				v, hs = string(hs[2:2+l]), hs[2+l:]
			case esUUID:
				var u [16]byte
				copy(u[:], hs[:16])
				v, hs = u, hs[16:]
			default:
				return nil, errors.New("header type")
			}
			d.headers[name] = v
		}
		out = append(out, d)
		b = b[total:]
	}
	return out, nil
}

func TestEventStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	for _, name := range []string{"payload_part", "empty_part", "model_stream_error", "error", "all_types"} {
		buf.Write(goldenInputs()[name])
	}
	msgs, err := decodeEventStream(buf.Bytes())
	if err != nil || len(msgs) != 5 {
		t.Fatalf("decode: %v (%d messages)", err, len(msgs))
	}
	if msgs[0].headers[":event-type"] != "PayloadPart" || string(msgs[0].payload) != "hello world" || len(msgs[1].payload) != 0 {
		t.Errorf("events: %+v %+v", msgs[0], msgs[1])
	}
	if msgs[2].headers[":message-type"] != "exception" || msgs[2].headers[":exception-type"] != "ModelStreamError" {
		t.Errorf("exception: %+v", msgs[2])
	}
	if msgs[3].headers[":error-code"] != "InternalServerError" || msgs[3].headers[":error-message"] != "boom" || len(msgs[3].payload) != 0 {
		t.Errorf("error: %+v", msgs[3])
	}
	h := msgs[4].headers
	if h["t"] != true || h["f"] != false || h["b"] != int8(-5) || h["s"] != int16(-1234) || h["i"] != int32(70000) || h["l"] != int64(-(1<<40)) ||
		h["str"] != "h\u00e9llo" || h["ts"] != int64(1700000000123) || !bytes.Equal(h["bytes"].([]byte), []byte{0, 1, 0xff}) {
		t.Errorf("all header types: %+v", h)
	}
}

func TestEventStreamLimitsAndBadHeaders(t *testing.T) {
	if _, err := encodeEventStreamMessage(nil, make([]byte, eventStreamMaxPayload+1)); err == nil {
		t.Error("a payload over 16 MiB is refused")
	}
	if _, err := encodeEventStreamMessage([]esHeader{esStringHeader("", "x")}, nil); err == nil {
		t.Error("an empty header name is refused")
	}
	if _, err := encodeEventStreamMessage([]esHeader{esStringHeader(strings.Repeat("n", 256), "x")}, nil); err == nil {
		t.Error("a header name over 255 bytes is refused")
	}
	if _, err := encodeEventStreamMessage([]esHeader{esStringHeader("v", strings.Repeat("v", 0x10000))}, nil); err == nil {
		t.Error("a header value over 65535 bytes is refused")
	}
	if _, err := encodeEventStreamMessage([]esHeader{{Name: "x", Type: esInt32, Value: "not an int"}}, nil); err == nil {
		t.Error("a value that does not match its type is refused")
	}
	var many []esHeader
	for i := 0; i < 8; i++ {
		many = append(many, esStringHeader(fmt.Sprintf("h%d", i), strings.Repeat("v", 0xffff)))
	}
	if _, err := encodeEventStreamMessage(many, nil); err == nil {
		t.Error("headers over 128 KiB are refused")
	}
}

func TestEventStreamWriterFlushesEachMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newEventStreamWriter(rec)
	if err := w.Event("PayloadPart", "application/octet-stream", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if !rec.Flushed {
		t.Error("each message is flushed")
	}
	if err := w.Exception("ModelStreamError", "application/json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := w.Error("X", "y"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if err := w.Event("PayloadPart", "application/octet-stream", []byte("late")); err == nil {
		t.Error("nothing is written after Close")
	}
	msgs, err := decodeEventStream(rec.Body.Bytes())
	if err != nil || len(msgs) != 3 {
		t.Fatalf("%v %d", err, len(msgs))
	}
}

// TestEventStreamDump writes the frames to the file named by ROVARA_ES_DUMP (one `name hex` per line) for
// front/tools/eventstream_check.py decode, which has botocore parse them.
func TestEventStreamDump(t *testing.T) {
	path := os.Getenv("ROVARA_ES_DUMP")
	if path == "" {
		t.Skip("ROVARA_ES_DUMP is not set")
	}
	var b strings.Builder
	for name, raw := range goldenInputs() {
		fmt.Fprintf(&b, "%s %s\n", name, hex.EncodeToString(raw))
	}
	// a long stream of parts in one buffer, as a response carries them
	var stream bytes.Buffer
	for i := 0; i < 50; i++ {
		m, _ := eventStreamEvent("PayloadPart", "application/octet-stream", bytes.Repeat([]byte{byte('a' + i%26)}, i*7))
		stream.Write(m)
	}
	fmt.Fprintf(&b, "part_stream %s\n", hex.EncodeToString(stream.Bytes()))
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
