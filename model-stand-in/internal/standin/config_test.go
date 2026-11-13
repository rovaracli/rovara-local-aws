package standin

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func newLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func TestConfigRefusals(t *testing.T) {
	ok := `{"kind":"fixed","body":"x"}`
	cases := map[string]string{
		"not json":                   `{`,
		"two documents":              one(ok) + one(ok),
		"unknown top-level field":    `{"version":1,"endpoints":{"ep":{"model":` + ok + `}},"typo":1}`,
		"unknown model field":        one(`{"kind":"fixed","body":"x","lateny_ms":5}`),
		"wrong version":              `{"version":2,"endpoints":{"ep":{"model":` + ok + `}}}`,
		"no endpoints":               `{"version":1,"endpoints":{}}`,
		"bad endpoint name":          `{"version":1,"endpoints":{"bad_name":{"model":` + ok + `}}}`,
		"endpoint without a model":   `{"version":1,"endpoints":{"ep":{}}}`,
		"unknown kind":               one(`{"kind":"magic"}`),
		"a field of another kind":    one(`{"kind":"fixed","body":"x","size":3}`),
		"fixed needs one of two":     one(`{"kind":"fixed"}`),
		"fixed with both":            one(`{"kind":"fixed","body":"x","json":1}`),
		"negative latency":           one(`{"kind":"fixed","body":"x","latency_ms":-1}`),
		"latency over the cap":       one(`{"kind":"fixed","body":"x","latency_ms":31000}`),
		"error rate over one":        one(`{"kind":"fixed","body":"x","error_rate":1.5}`),
		"error status 200":           one(`{"kind":"fixed","body":"x","fail_first":1,"error_status":200}`),
		"stream with no chunks":      one(`{"kind":"fixed","body":"x","stream":{"chunks":0}}`),
		"stream too slow":            one(`{"kind":"fixed","body":"x","stream":{"chunks":100,"delay_ms":1000}}`),
		"vector without size":        one(`{"kind":"vector"}`),
		"scalar with size 2":         one(`{"kind":"vector","size":2,"scalar":true}`),
		"min above max":              one(`{"kind":"vector","size":1,"min":2,"max":1}`),
		"label without labels":       one(`{"kind":"label"}`),
		"repeated label":             one(`{"kind":"label","labels":["a","a"]}`),
		"csv with both":              one(`{"kind":"csv","columns":2,"labels":["a"]}`),
		"csv with neither":           one(`{"kind":"csv"}`),
		"csv header mismatch":        one(`{"kind":"csv","columns":2,"header":["a"]}`),
		"schema pattern":             one(`{"kind":"schema","schema":{"type":"string","pattern":"^a+$"}}`),
		"schema unknown keyword":     one(`{"kind":"schema","schema":{"type":"string","dependencies":{}}}`),
		"schema bad type":            one(`{"kind":"schema","schema":{"type":"strng"}}`),
		"schema bad format":          one(`{"kind":"schema","schema":{"type":"string","format":"hostname"}}`),
		"schema too deep":            one(`{"kind":"schema","schema":` + strings.Repeat(`{"type":"array","items":`, 10) + `{"type":"string"}` + strings.Repeat(`}`, 10) + `}`),
		"schema min above max":       one(`{"kind":"schema","schema":{"type":"number","minimum":3,"maximum":1}}`),
		"unplain field name":         one(`{"kind":"json_echo","wrap":"a b"}`),
		"content type not a media":   one(`{"kind":"fixed","body":"x","content_type":"nope"}`),
		"custom attributes newline":  one(`{"kind":"fixed","body":"x","custom_attributes":"a\nb"}`),
		"listen on a named host":     `{"version":1,"listen":"example.com:8080","endpoints":{"ep":{"model":` + ok + `}}}`,
		"listen under 1024":          `{"version":1,"listen":":80","endpoints":{"ep":{"model":` + ok + `}}}`,
		"port under 1024":            `{"version":1,"endpoints":{"ep":{"port":80,"model":` + ok + `}}}`,
		"port repeated":              `{"version":1,"endpoints":{"a":{"port":9000,"model":` + ok + `},"b":{"port":9000,"model":` + ok + `}}}`,
		"port equals listen":         `{"version":1,"endpoints":{"a":{"port":8080,"model":` + ok + `}}}`,
		"five listeners":             `{"version":1,"endpoints":{"a":{"port":9001,"model":` + ok + `},"b":{"port":9002,"model":` + ok + `},"c":{"port":9003,"model":` + ok + `},"d":{"port":9004,"model":` + ok + `}}}`,
		"default is not an endpoint": `{"version":1,"default_endpoint":"x","endpoints":{"ep":{"model":` + ok + `}}}`,
		"empty target model":         `{"version":1,"endpoints":{"ep":{"models":{"":` + ok + `}}}}`,
		"a null model":               `{"version":1,"endpoints":{"ep":{"models":{"a":null}}}}`,
		"over 1 MiB":                 one(`{"kind":"fixed","body":"` + strings.Repeat("a", MaxConfigBytes) + `"}`),
	}
	for name, cfg := range cases {
		if _, err := ParseConfig([]byte(cfg)); err == nil {
			t.Errorf("%s: the config was accepted", name)
		}
	}
}

func TestConfigAcceptsTheDocumentedShapes(t *testing.T) {
	for name, cfg := range map[string]string{
		"minimal":      one(`{"kind":"fixed","body":"x"}`),
		"every option": `{"version":1,"listen":":8080","seed":"run-1","default_endpoint":"a","endpoints":{"a":{"port":9001,"model":{"kind":"vector","size":2,"min":0,"max":5,"decimals":2,"latency_ms":5,"jitter_ms":5,"error_rate":0.1,"fail_first":1,"error_status":503,"stream":{"chunks":2,"delay_ms":1},"accepts":["application/json"]}},"b":{"models":{"m1.tar.gz":{"kind":"label","labels":["x","y"]}}}}}`,
	} {
		if _, err := ParseConfig([]byte(cfg)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The stand-in must not be able to make an outgoing connection: no dialling, no HTTP client, no DNS lookups, no process, no unsafe, in any non-test source.
func TestNoOutboundNetworkInTheSource(t *testing.T) {
	forbidden := regexp.MustCompile(`\b(http\.(Get|Post|PostForm|Head|DefaultClient|Client|Transport|NewRequest)|net\.(Dial|DialTimeout|Lookup\w*|DefaultResolver|Dialer)|exec\.|syscall\.Exec|"os/exec"|"unsafe"|"plugin"|"net/rpc"|"crypto/tls"|"net/smtp")\b`)
	files, _ := filepath.Glob("*.go")
	more, _ := filepath.Glob("../../cmd/model-stand-in/*.go")
	for _, f := range append(files, more...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if c := strings.Index(code, "//"); c >= 0 {
				code = code[:c]
			}
			if forbidden.MatchString(code) {
				t.Errorf("%s:%d: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	// the imports are the standard library, and nothing else
	for _, f := range append(files, more...) {
		b, _ := os.ReadFile(f)
		for _, m := range regexp.MustCompile(`(?m)^\s+"([^"]+)"$`).FindAllStringSubmatch(string(b), -1) {
			if strings.Contains(strings.Split(m[1], "/")[0], ".") {
				t.Errorf("%s imports %s, which is not the standard library", f, m[1])
			}
		}
	}
}
