package main

import (
	"context"
	"strconv"
	"strings"
	"unicode/utf8"
)

// jsonEscape escapes a string for the inside of a JSON string literal.
func jsonEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == utf8.RuneError {
				b.WriteString(`\u`)
				h := strconv.FormatInt(int64(r), 16)
				b.WriteString(strings.Repeat("0", 4-len(h)) + h)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// slots is a counting semaphore: how many large buffered responses may be held in memory at once.
type slots chan struct{}

func newSlots(n int) slots { return make(slots, n) }

// acquire waits for a slot; false when the request was cancelled first.
func (s slots) acquire(ctx context.Context) bool {
	select {
	case s <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s slots) release() { <-s }
