package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http"
	"strconv"
)

// The error bodies the front writes itself, in the shapes the fork writes them.

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// cborText encodes a CBOR text string (major type 3) of up to 65535 bytes.
func cborText(s string) []byte {
	n := len(s)
	var head []byte
	switch {
	case n < 24:
		head = []byte{0x60 | byte(n)}
	case n < 256:
		head = []byte{0x78, byte(n)}
	default:
		head = []byte{0x79, byte(n >> 8), byte(n)}
	}
	return append(head, s...)
}

// cborError is {"__type": code, "message": message} as an indefinite-length CBOR map, which is what the fork sends.
func cborError(code, message string) []byte {
	var b bytes.Buffer
	b.WriteByte(0xbf)
	b.Write(cborText("__type"))
	b.Write(cborText(code))
	b.Write(cborText("message"))
	b.Write(cborText(message))
	b.WriteByte(0xff)
	return b.Bytes()
}

func writeBody(w http.ResponseWriter, status int, ctype string, body []byte) {
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	w.Write(body)
}

// writeAWSError writes an error in the wire protocol of the request, with the AWS-style code and message.
// Headers that the fork adds to an error of that protocol are added too.
func writeAWSError(w http.ResponseWriter, p proto, status int, code, message, jsonCType string) {
	writeAWSErrorH(w, p, status, code, message, jsonCType, true)
}

// writeAWSErrorH: errorTypeHeader says whether JSON errors carry X-Amzn-Errortype (the fork's unknown-target answer does not).
func writeAWSErrorH(w http.ResponseWriter, p proto, status int, code, message, jsonCType string, errorTypeHeader bool) {
	h := w.Header()
	h.Set("x-amzn-RequestId", newUUID())
	switch p {
	case protoCBOR:
		h.Set("smithy-protocol", "rpc-v2-cbor")
		h.Set("x-amzn-query-error", code+";Sender")
		writeBody(w, status, "application/cbor", cborError(code, message))
	case protoJSON, protoRestJSON:
		if jsonCType == "" {
			jsonCType = "application/json"
		}
		if errorTypeHeader {
			h.Set("X-Amzn-Errortype", code)
		}
		h.Set("x-amzn-query-error", code+";Sender")
		writeBody(w, status, jsonCType, []byte(`{"__type":"`+jsonEscape(code)+`","message":"`+jsonEscape(message)+`"}`))
	default: // Query and REST-XML
		xml := "<ErrorResponse><Error><Type>Sender</Type><Code>" + xmlEscape(code) + "</Code><Message>" + xmlEscape(message) +
			"</Message></Error><RequestId>" + newUUID() + "</RequestId></ErrorResponse>"
		writeBody(w, status, "application/xml", []byte(xml))
	}
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '"':
			b.WriteString("&quot;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// writeDisabled: the answer for a service that is switched off, the fork's ServiceNotAvailableException (400).
func writeDisabled(w http.ResponseWriter, p proto, serviceKey string) {
	writeAWSError(w, p, http.StatusBadRequest, "ServiceNotAvailableException", "Service "+serviceKey+" is not enabled.", "")
}

// writeUnknown: a request for a service or operation the catalog does not have (the fork's 404 UnknownOperationException).
func writeUnknown(w http.ResponseWriter, id identified, method, path string) {
	switch id.Reason {
	case refuseUnknownTarget:
		target := id.Target
		if len(target) > 200 {
			target = target[:200]
		}
		writeAWSErrorH(w, id.Proto, http.StatusNotFound, "UnknownOperationException", "Unknown operation: "+target,
			"application/x-amz-json-1.1;charset=UTF-8", false)
	default:
		p := path
		if len(p) > 200 {
			p = p[:200]
		}
		writeAWSError(w, id.Proto, http.StatusNotFound, "UnknownOperationException", "Unknown operation: "+method+" "+p, "")
	}
}

// writeUnavailable: the engine is resetting, not started or failed.
func writeUnavailable(w http.ResponseWriter, p proto, state engineState) {
	w.Header().Set("Retry-After", "1")
	msg := "The local AWS emulator is " + state.String() + "."
	writeAWSError(w, p, http.StatusServiceUnavailable, "ServiceUnavailable", msg, "")
}
