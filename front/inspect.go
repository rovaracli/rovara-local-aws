package main

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// What the front reads of a request or of an object, to look at it (the Lambda detector, the CloudFormation and target recorders),
// is bounded three ways: a byte budget for everything buffered at once (a request that does not fit is looked at by its head only
// and reported unchecked; nothing ever waits for the budget, so a slow client cannot hold up another request), a size cap per
// read, and a time limit on every read from the engine.

const inspectBudgetMax = 64 << 20

type inspectBudget struct {
	mu   sync.Mutex
	used int64
	max  int64 // 0: inspectBudgetMax (the function runner raises it: it reads whole packages)
}

func (b *inspectBudget) reserve(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.max
	if limit == 0 {
		limit = inspectBudgetMax
	}
	if b.used+n > limit {
		return false
	}
	b.used += n
	return true
}

func (b *inspectBudget) release(n int64) {
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
}

// readForInspection reads the head of a request body: all of it when it is (or turns out to be) at most limit bytes, else the first
// 64 KiB and truncated=true. The caller forwards what was read in front of the rest of the body, and calls release when the request
// is over (the bytes are held until then).
func (s *Server) readForInspection(body io.Reader, length, limit int64) (head []byte, truncated bool, release func()) {
	n := limit
	if length >= 0 && length < n {
		n = length // never reserve more than the body can be: a crowd of small requests must not exhaust the budget
	}
	if length > limit {
		n, truncated = 64<<10, true
	}
	if !s.budget.reserve(n) {
		if n > 64<<10 {
			n, truncated = 64<<10, true
		}
		if !s.budget.reserve(n) {
			n = 0 // the budget is gone: look at nothing, forward everything
			truncated = true
		}
	}
	reserved := n
	if n > 0 {
		head, _ = io.ReadAll(io.LimitReader(body, n+1))
		if int64(len(head)) > n {
			truncated = true
		}
	} else if length != 0 {
		truncated = true
	}
	return head, truncated, func() { s.budget.release(reserved) }
}

// engineFetchTimeout bounds every read the front makes from the engine for its own purposes.
var engineFetchTimeout = 10 * time.Second

// safeObjectPath: whether path (as it will be sent, still escaped) is the path of an S3 OBJECT: /<bucket>/<key>, a bucket name that
// is a bucket name, no reserved first segment (the engine's data planes live under /_aws/), no empty, `.` or `..` segment in any
// spelling, no encoded slash or backslash. Anything else is not fetched.
func safeObjectPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00?#") {
		return false
	}
	segs := strings.Split(path[1:], "/")
	if len(segs) < 2 {
		return false
	}
	for i, seg := range segs {
		low := strings.ToLower(seg)
		if seg == "" || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") || strings.Contains(low, "%00") {
			return false
		}
		un, err := url.PathUnescape(seg)
		if err != nil || un == "." || un == ".." || strings.ContainsAny(un, "/\\\x00") {
			return false
		}
		if i == 0 {
			if strings.HasPrefix(un, "_") || len(un) < 3 || len(un) > 63 || strings.ToLower(un) != un {
				return false
			}
			for _, c := range un {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
					return false
				}
			}
		}
	}
	return true
}

// engineObject reads an object of the engine's own S3 over loopback (path is /<bucket>/<key>, already escaped), at most limit bytes,
// within engineFetchTimeout. Only an S3 object path is fetched (safeObjectPath).
func (s *Server) engineObject(path string, limit int64) ([]byte, bool) {
	if !safeObjectPath(path) {
		return nil, false
	}
	gen, _, err := s.engine.current()
	if err != nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), engineFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(gen.port)+path, nil)
	if err != nil {
		return nil, false
	}
	req.Host = "127.0.0.1:" + strconv.Itoa(gen.port)
	req.Header.Set("Authorization", syntheticAuthorization("s3", s.cfg.Region))
	req.Header.Set("User-Agent", "rovara-aws-front-inspect")
	resp, err := gen.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > limit {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, false
	}
	return b, true
}

// zipDirectoryTooBig reads the end-of-central-directory record of a zip (and the zip64 one when there is one) and says whether the
// directory declares more entries, or is bigger, than the judge will look at. Done before zip.NewReader, which would build a
// structure for every entry first. found is false when there is no such record (the zip reader refuses it anyway).
func zipDirectoryTooBig(b []byte) (tooBig, found bool) {
	const eocd = 22
	if len(b) < eocd {
		return false, false
	}
	start := len(b) - eocd
	lowest := len(b) - eocd - 0xFFFF
	if lowest < 0 {
		lowest = 0
	}
	for i := start; i >= lowest; i-- {
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 5 && b[i+3] == 6 {
			entries := uint64(binary.LittleEndian.Uint16(b[i+10:]))
			cdSize := uint64(binary.LittleEndian.Uint32(b[i+12:]))
			if (entries == 0xFFFF || cdSize == 0xFFFFFFFF) && i >= 20 && b[i-20] == 'P' && b[i-19] == 'K' && b[i-18] == 6 && b[i-17] == 7 {
				off := binary.LittleEndian.Uint64(b[i-12:])
				if off+56 <= uint64(len(b)) && b[off] == 'P' && b[off+1] == 'K' && b[off+2] == 6 && b[off+3] == 6 {
					entries = binary.LittleEndian.Uint64(b[off+32:])
					cdSize = binary.LittleEndian.Uint64(b[off+40:])
				}
			}
			return entries > zipMaxEntries || cdSize > zipMaxDirectory, true
		}
	}
	return false, false
}
