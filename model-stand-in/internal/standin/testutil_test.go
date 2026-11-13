package standin

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type env struct {
	t    *testing.T
	logs *bytes.Buffer
	srv  *Server
}

func newEnv(t *testing.T, cfgJSON string) *env {
	t.Helper()
	cfg, err := ParseConfig([]byte(cfgJSON))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	logs := &bytes.Buffer{}
	return &env{t: t, logs: logs, srv: New(cfg, slog.New(slog.NewTextHandler(logs, nil)))}
}

type resp struct {
	status int
	body   string
	header http.Header
}

// call sends a request to the primary listener (fixed == "") or to the listener of one endpoint.
func (e *env) call(fixed, method, path, body string, headers map[string]string) resp {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.srv.handler(fixed).ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return resp{status: rec.Code, body: string(b), header: rec.Result().Header}
}

func (e *env) invoke(body string, headers map[string]string) resp {
	return e.call("", "POST", "/invocations", body, headers)
}

func one(model string) string {
	return `{"version":1,"endpoints":{"ep":{"model":` + model + `}}}`
}
