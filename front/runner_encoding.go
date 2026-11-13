package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Content-Encoding, before the guard looks at anything. The engine decodes `aws-chunked` for every service (a header-gated strip of the
// framing) and gunzips the bodies of the RPC protocols; the guard must read what the ENGINE reads, so for every service but S3 (whose bodies
// are objects) the front decodes both itself, forwards the decoded body with the encoding header gone, and refuses any encoding it does
// not decode. S3 keeps its encodings: an object stored with Content-Encoding: gzip is data. (An S3 call whose body the guard has to read,
// a bucket notification configuration, is refused when it is encoded.)

const maxDecodedBody = runnerBodyCap

// encodingTokens: every Content-Encoding value, split, lower-cased, in the order the client wrote them.
func encodingTokens(h http.Header) []string {
	var out []string
	for _, v := range h.Values("Content-Encoding") {
		for _, t := range strings.Split(v, ",") {
			if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

func hasToken(tokens []string, want string) bool {
	for _, t := range tokens {
		if t == want {
			return true
		}
	}
	return false
}

// dechunk decodes aws-chunked framing: <hex size>[;extensions]\r\n<data>\r\n ... 0\r\n[trailers]\r\n.
func dechunk(b []byte, max int64) ([]byte, error) {
	br := bufio.NewReader(bytes.NewReader(b))
	var out bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, errors.New("aws-chunked body ends inside a chunk header")
		}
		line = strings.TrimRight(line, "\r\n")
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		n, err := strconv.ParseUint(strings.TrimSpace(line), 16, 32)
		if err != nil {
			return nil, errors.New("aws-chunked: bad chunk size")
		}
		if n == 0 {
			// trailers, up to the blank line
			for {
				t, err := br.ReadString('\n')
				if err != nil || strings.TrimRight(t, "\r\n") == "" {
					return out.Bytes(), nil
				}
			}
		}
		if int64(out.Len())+int64(n) > max {
			return nil, errors.New("decoded body too large")
		}
		if _, err := io.CopyN(&out, br, int64(n)); err != nil {
			return nil, errors.New("aws-chunked body ends inside a chunk")
		}
		if crlf, err := br.ReadString('\n'); err != nil || strings.TrimRight(crlf, "\r\n") != "" {
			return nil, errors.New("aws-chunked: a chunk is not followed by CRLF")
		}
	}
}

func gunzip(b []byte, max int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(zr, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > max {
		return nil, errors.New("decoded body too large")
	}
	return out, nil
}

func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("body too large")
	}
	return b, nil
}

// setBody replaces the request's body (what every later step reads) and its length.
func setBody(r *http.Request, b []byte) {
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	r.TransferEncoding = nil
	r.Header.Del("Content-Length")
}

// runnerDecodeChunked removes aws-chunked framing from a request that is not S3's (by its SigV4 scope), whatever the service turns out to
// be: the engine strips it for every one. status 0 is success.
func (s *Server) runnerDecodeChunked(r *http.Request) (status int, msg string) {
	if sc, _ := requestScope(r.Header, r.URL.RawQuery); sc != nil && (sc.Service == "s3" || sc.Service == "s3express" || sc.Service == "execute-api") {
		return 0, ""
	}
	if runnerDataPlane(r, "", "") {
		return 0, "" // a call to an API Gateway endpoint or a function URL: the app's own body
	}
	tokens := encodingTokens(r.Header)
	if !hasToken(tokens, "aws-chunked") {
		return 0, ""
	}
	raw, err := readCapped(r.Body, maxDecodedBody)
	if err != nil {
		return http.StatusRequestEntityTooLarge, "the request body is too large"
	}
	dec, err := dechunk(raw, maxDecodedBody)
	if err != nil {
		return http.StatusBadRequest, err.Error()
	}
	var rest []string
	for _, t := range tokens {
		if t != "aws-chunked" {
			rest = append(rest, t)
		}
	}
	r.Header.Del("Content-Encoding")
	if len(rest) > 0 {
		r.Header.Set("Content-Encoding", strings.Join(rest, ", "))
	}
	for _, h := range []string{"X-Amz-Decoded-Content-Length", "X-Amz-Trailer"} {
		r.Header.Del(h)
	}
	if v := r.Header.Get("X-Amz-Content-Sha256"); strings.HasPrefix(strings.ToUpper(v), "STREAMING-") {
		r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	}
	setBody(r, dec)
	return 0, ""
}

// runnerDecodeGzip handles what is left of Content-Encoding once the service is known and is not S3: gzip is decoded, identity dropped,
// anything else refused. A form body (a Query service) is never decoded by the engine, so an encoded one is refused too.
func (s *Server) runnerDecodeGzip(r *http.Request, formRead bool) (status int, msg string) {
	tokens := encodingTokens(r.Header)
	if len(tokens) == 0 {
		return 0, ""
	}
	gz := false
	for _, t := range tokens {
		switch {
		case t == "identity":
		case strings.Contains(t, "gzip"): // the engine's own test is a substring test
			gz = true
		default:
			return http.StatusUnsupportedMediaType, fmt.Sprintf("Content-Encoding %q is not supported by this service", t)
		}
	}
	if gz && formRead {
		return http.StatusUnsupportedMediaType, "an encoded form body is not supported"
	}
	if gz {
		raw, err := readCapped(r.Body, maxDecodedBody)
		if err != nil {
			return http.StatusRequestEntityTooLarge, "the request body is too large"
		}
		dec, err := gunzip(raw, maxDecodedBody)
		if err != nil {
			return http.StatusBadRequest, "the gzip body could not be decoded"
		}
		setBody(r, dec)
	}
	r.Header.Del("Content-Encoding")
	return 0, ""
}
