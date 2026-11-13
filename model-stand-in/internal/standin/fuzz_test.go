package standin

import "testing"

// Neither the config nor a request body can make the process panic or hang; the seeds run as ordinary tests, `go test -fuzz` explores further.
func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(one(`{"kind":"schema","schema":{"type":"object","properties":{"a":{"type":"integer","minimum":1,"maximum":2}}}}`)))
	f.Add([]byte(one(`{"kind":"csv","columns":2}`)))
	f.Add([]byte(`{"version":1,"endpoints":{"a":{"models":{"x":{"kind":"label","labels":["p"]}}}}}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseConfig(data) })
}

func FuzzInvoke(f *testing.F) {
	f.Add(`{"instances":[[1,2],[3]]}`)
	f.Add("a,b\n1,2\n")
	f.Add(`[`)
	f.Add("")
	models := []string{
		`{"kind":"json_echo"}`, `{"kind":"vector","size":3}`, `{"kind":"label","labels":["a","b"],"with_probabilities":true}`, `{"kind":"csv","columns":2,"skip_header":true}`,
		`{"kind":"schema","schema":{"type":"object","properties":{"n":{"type":"integer","minimum":-5,"maximum":5},"s":{"type":"string","maxLength":3,"minLength":1},"a":{"type":"array","items":{"type":"number"}}}}}`,
	}
	envs := make([]*env, len(models))
	f.Fuzz(func(t *testing.T, body string) {
		for i, m := range models {
			if envs[i] == nil {
				envs[i] = newEnv(t, one(m))
			}
			envs[i].t = t
			r := envs[i].invoke(body, nil)
			if r.status != 200 && r.status != 400 {
				t.Fatalf("model %d: status %d for a plain body", i, r.status)
			}
		}
	})
}
