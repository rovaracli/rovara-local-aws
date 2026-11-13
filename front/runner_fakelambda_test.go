package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// A just-enough Lambda control plane for the fake engine (the test binary plays AWS Emulator): functions, versions, aliases, the answers
// the runner reads, and a record of what the "engine" was actually sent, so a test can say what the front forwarded.

type fakeFn struct {
	cfg  map[string]interface{}
	code []byte
}

type fakeLambdaState struct {
	mu         sync.Mutex
	fns        map[string]*fakeFn
	versions   map[string]map[string]*fakeFn
	aliases    map[string]string // name:alias -> version
	nextVer    map[string]int
	invokes    []string
	esm        []map[string]interface{}
	esmDeleted []string
}

var fakeLambda = &fakeLambdaState{fns: map[string]*fakeFn{}, versions: map[string]map[string]*fakeFn{}, aliases: map[string]string{}, nextVer: map[string]int{}}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	b, _ := json.Marshal(m)
	var out map[string]interface{}
	json.Unmarshal(b, &out)
	return out
}

func fakeCodeInfo(zipb64 string) ([]byte, int, string) {
	b, _ := base64.StdEncoding.DecodeString(zipb64)
	h := sha256.Sum256(b)
	return b, len(b), base64.StdEncoding.EncodeToString(h[:])
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

// fakeLambdaHandle serves the paths it knows; false means the fake engine's own routes go on.
func fakeLambdaHandle(w http.ResponseWriter, r *http.Request, body []byte) bool {
	p := r.URL.Path
	if strings.HasPrefix(p, "/__fake/lambda/") {
		name := strings.TrimPrefix(p, "/__fake/lambda/")
		fakeLambda.mu.Lock()
		defer fakeLambda.mu.Unlock()
		if name == "" {
			var names []string
			for n := range fakeLambda.fns {
				names = append(names, n)
			}
			sort.Strings(names)
			writeJSON(w, 200, map[string]interface{}{"functions": names, "invokes": fakeLambda.invokes})
			return true
		}
		f := fakeLambda.fns[name]
		if f == nil {
			w.WriteHeader(404)
			return true
		}
		writeJSON(w, 200, map[string]interface{}{"config": f.cfg, "codeB64": base64.StdEncoding.EncodeToString(f.code)})
		return true
	}
	if strings.HasPrefix(p, "/__fake/esm") || strings.HasPrefix(p, "/2015-03-31/event-source-mappings/") {
		fakeLambda.mu.Lock()
		defer fakeLambda.mu.Unlock()
		switch {
		case p == "/__fake/esm" && r.Method == "POST": // the test sets what the engine "has"
			var l []map[string]interface{}
			json.Unmarshal(body, &l)
			fakeLambda.esm = l
			w.WriteHeader(204)
		case p == "/2015-03-31/event-source-mappings/" && r.Method == "GET":
			if fakeLambda.esm == nil {
				return false
			}
			writeJSON(w, 200, map[string]interface{}{"EventSourceMappings": fakeLambda.esm})
		case strings.HasPrefix(p, "/2015-03-31/event-source-mappings/") && r.Method == "DELETE":
			id := strings.TrimPrefix(p, "/2015-03-31/event-source-mappings/")
			var kept []map[string]interface{}
			for _, m := range fakeLambda.esm {
				if m["UUID"] != id {
					kept = append(kept, m)
				}
			}
			fakeLambda.esm = kept
			fakeLambda.esmDeleted = append(fakeLambda.esmDeleted, id)
			writeJSON(w, 202, map[string]string{"UUID": id})
		case p == "/__fake/esm" && r.Method == "GET":
			writeJSON(w, 200, map[string]interface{}{"left": fakeLambda.esm, "deleted": fakeLambda.esmDeleted})
		default:
			return false
		}
		return true
	}
	if !strings.HasPrefix(p, "/2015-03-31/functions") {
		return false
	}
	segs := splitPath(p)
	fakeLambda.mu.Lock()
	defer fakeLambda.mu.Unlock()
	lam := fakeLambda
	notFound := func() bool {
		writeJSON(w, 404, map[string]string{"__type": "ResourceNotFoundException", "Message": "Function not found"})
		return true
	}
	if len(segs) == 2 {
		switch r.Method {
		case "POST":
			var req map[string]interface{}
			json.Unmarshal(body, &req)
			name, _ := req["FunctionName"].(string)
			if !strings.HasPrefix(name, "fl-") {
				return false // only the runner tests' functions (named fl-*) are played; every other test sees the fake engine's plain answers
			}
			cfg := map[string]interface{}{"FunctionName": name, "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:" + name, "Version": "$LATEST",
				"Runtime": req["Runtime"], "Handler": req["Handler"], "Role": req["Role"], "MemorySize": 128, "Timeout": 3, "PackageType": "Zip",
				"Architectures": []string{"x86_64"}, "State": "Active", "Description": ""}
			for _, k := range []string{"MemorySize", "Timeout", "Environment", "Layers", "Architectures", "Description"} {
				if v, ok := req[k]; ok {
					cfg[k] = v
				}
			}
			if l, ok := req["Layers"].([]interface{}); ok {
				var ls []interface{}
				for _, a := range l {
					ls = append(ls, map[string]interface{}{"Arn": a, "CodeSize": 1})
				}
				cfg["Layers"] = ls
			}
			f := &fakeFn{cfg: cfg}
			if c, ok := req["Code"].(map[string]interface{}); ok {
				if z, ok := c["ZipFile"].(string); ok {
					var size int
					var sha string
					f.code, size, sha = fakeCodeInfo(z)
					cfg["CodeSize"], cfg["CodeSha256"] = size, sha
				}
			}
			if _, exists := lam.fns[name]; exists {
				writeJSON(w, 409, map[string]string{"__type": "ResourceConflictException", "Message": "Function already exist: " + name})
				return true
			}
			lam.fns[name] = f
			if pub, _ := req["Publish"].(bool); pub {
				lam.publish(name)
				cfg["Version"] = fmt.Sprint(lam.nextVer[name])
			}
			writeJSON(w, 201, cfg)
			return true
		case "GET":
			if len(lam.fns) == 0 {
				return false
			}
			var fs []interface{}
			var names []string
			for n := range lam.fns {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				fs = append(fs, lam.fns[n].cfg)
			}
			writeJSON(w, 200, map[string]interface{}{"Functions": fs})
			return true
		}
		return false
	}
	name := segs[2]
	if !strings.HasPrefix(name, "fl-") {
		return false
	}
	f := lam.fns[name]
	rest := segs[3:]
	switch {
	case len(rest) == 0 && r.Method == "GET":
		if f == nil {
			return notFound()
		}
		writeJSON(w, 200, map[string]interface{}{"Configuration": f.cfg, "Code": map[string]interface{}{"RepositoryType": "S3", "Location": "https://awslambda-fake.s3.amazonaws.com/" + name}})
		return true
	case len(rest) == 0 && r.Method == "DELETE":
		if f == nil {
			return notFound()
		}
		if q := r.URL.Query().Get("Qualifier"); q != "" {
			delete(lam.versions[name], q)
		} else {
			delete(lam.fns, name)
			delete(lam.versions, name)
		}
		w.WriteHeader(204)
		return true
	case len(rest) == 1 && rest[0] == "configuration" && r.Method == "GET":
		if f == nil {
			return notFound()
		}
		writeJSON(w, 200, f.cfg)
		return true
	case len(rest) == 1 && rest[0] == "configuration" && r.Method == "PUT":
		if f == nil {
			return notFound()
		}
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		for k, v := range req {
			if k == "Layers" {
				var ls []interface{}
				for _, a := range v.([]interface{}) {
					ls = append(ls, map[string]interface{}{"Arn": a, "CodeSize": 1})
				}
				v = ls
			}
			f.cfg[k] = v
		}
		writeJSON(w, 200, f.cfg)
		return true
	case len(rest) == 1 && rest[0] == "code" && r.Method == "PUT":
		if f == nil {
			return notFound()
		}
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if z, ok := req["ZipFile"].(string); ok {
			var size int
			var sha string
			f.code, size, sha = fakeCodeInfo(z)
			f.cfg["CodeSize"], f.cfg["CodeSha256"] = size, sha
		}
		if pub, _ := req["Publish"].(bool); pub {
			lam.publish(name)
			out := cloneMap(f.cfg)
			out["Version"] = fmt.Sprint(lam.nextVer[name])
			writeJSON(w, 200, out)
			return true
		}
		writeJSON(w, 200, f.cfg)
		return true
	case len(rest) == 1 && rest[0] == "versions" && r.Method == "POST":
		if f == nil {
			return notFound()
		}
		lam.publish(name)
		out := cloneMap(f.cfg)
		out["Version"] = fmt.Sprint(lam.nextVer[name])
		writeJSON(w, 201, out)
		return true
	case len(rest) == 1 && rest[0] == "versions" && r.Method == "GET":
		if f == nil {
			return notFound()
		}
		vs := []interface{}{cloneMap(f.cfg)}
		var keys []string
		for k := range lam.versions[name] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := cloneMap(lam.versions[name][k].cfg)
			c["Version"] = k
			vs = append(vs, c)
		}
		writeJSON(w, 200, map[string]interface{}{"Versions": vs})
		return true
	case len(rest) == 1 && rest[0] == "aliases" && r.Method == "POST":
		var req map[string]string
		json.Unmarshal(body, &req)
		lam.aliases[name+":"+req["Name"]] = req["FunctionVersion"]
		writeJSON(w, 201, map[string]string{"Name": req["Name"], "FunctionVersion": req["FunctionVersion"]})
		return true
	case len(rest) == 2 && rest[0] == "aliases" && r.Method == "GET":
		v, ok := lam.aliases[name+":"+rest[1]]
		if !ok {
			return notFound()
		}
		writeJSON(w, 200, map[string]string{"Name": rest[1], "FunctionVersion": v})
		return true
	case len(rest) == 1 && rest[0] == "invocations" && r.Method == "POST":
		lam.invokes = append(lam.invokes, name)
		w.Header().Set("X-Fake-Engine-Ran", name)
		writeJSON(w, 200, map[string]string{"engine": "ran", "name": name})
		return true
	}
	io.WriteString(io.Discard, "")
	return false
}

func (l *fakeLambdaState) publish(name string) {
	l.nextVer[name]++
	v := fmt.Sprint(l.nextVer[name])
	if l.versions[name] == nil {
		l.versions[name] = map[string]*fakeFn{}
	}
	f := l.fns[name]
	l.versions[name][v] = &fakeFn{cfg: cloneMap(f.cfg), code: append([]byte(nil), f.code...)}
}
