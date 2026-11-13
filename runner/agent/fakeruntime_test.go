package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The test binary doubles as a fake Lambda runtime: when FAKE_RUNTIME=1 it speaks the Runtime
// API instead of running tests. The agent starts it exactly as it would start a bootstrap.

func fakeRuntimeMain() {
	api := os.Getenv("AWS_LAMBDA_RUNTIME_API")
	base := "http://" + api + "/2018-06-01/runtime/"
	post := func(path string, body []byte, hdr map[string]string) {
		req, _ := http.NewRequest("POST", base+path, bytes.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
	switch os.Getenv("FAKE_INIT") {
	case "error":
		fmt.Println("importing handler")
		post("init/error", []byte(`{"errorMessage":"Unable to import module 'app'","errorType":"Runtime.ImportModuleError"}`),
			map[string]string{"Lambda-Runtime-Function-Error-Type": "Runtime.ImportModuleError"})
		os.Exit(1)
	case "exit":
		fmt.Fprintln(os.Stderr, "boom at startup")
		os.Exit(2)
	case "hang":
		time.Sleep(time.Hour)
	}
	if v := os.Getenv("FAKE_INIT_DELAY_MS"); v != "" {
		n, _ := strconv.Atoi(v)
		time.Sleep(time.Duration(n) * time.Millisecond)
	}
	fmt.Println("init done")
	for {
		resp, err := http.Get(base + "invocation/next")
		if err != nil {
			os.Exit(9)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		id := resp.Header.Get("Lambda-Runtime-Aws-Request-Id")
		var ev struct {
			Op   string `json:"op"`
			N    int    `json:"n"`
			Text string `json:"text"`
		}
		json.Unmarshal(body, &ev)
		switch ev.Op {
		case "echo":
			post("invocation/"+id+"/response", body, nil)
		case "pid":
			post("invocation/"+id+"/response", []byte(strconv.Itoa(os.Getpid())), nil)
		case "headers":
			h := map[string]string{}
			for k, v := range resp.Header {
				if strings.HasPrefix(k, "Lambda-Runtime-") {
					h[k] = v[0]
				}
			}
			b, _ := json.Marshal(h)
			post("invocation/"+id+"/response", b, nil)
		case "log":
			fmt.Println("out: " + ev.Text)
			fmt.Fprintln(os.Stderr, "err: "+ev.Text)
			for i := 0; i < ev.N; i++ {
				fmt.Printf("filler line %d %s\n", i, strings.Repeat("x", 60))
			}
			fmt.Print("no newline at end")
			post("invocation/"+id+"/response", []byte(`"logged"`), nil)
		case "error":
			post("invocation/"+id+"/error", []byte(`{"errorMessage":"kaboom","errorType":"ValueError","stackTrace":["a","b"]}`),
				map[string]string{"Lambda-Runtime-Function-Error-Type": "Unhandled"})
		case "sleep":
			time.Sleep(time.Duration(ev.N) * time.Millisecond)
			post("invocation/"+id+"/response", []byte(`"slept"`), nil)
		case "crash":
			fmt.Println("about to crash")
			os.Exit(3)
		case "bigerror":
			// built by hand: json.Marshal would turn each "<" into six bytes
			doc := `{"errorMessage":"` + strings.Repeat("<", ev.N) + `","errorType":"` + strings.Repeat("T", 10000) + `"}`
			post("invocation/"+id+"/error", []byte(doc), nil)
		case "big":
			post("invocation/"+id+"/response", bytes.Repeat([]byte{'a'}, ev.N), nil)
		case "spawn":
			c := exec.Command("sleep", "300")
			c.Start()
			post("invocation/"+id+"/response", []byte(strconv.Itoa(c.Process.Pid)), nil)
		case "mem":
			b := make([]byte, ev.N<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			post("invocation/"+id+"/response", []byte(strconv.Itoa(len(b))), nil)
		case "shutdown_after":
			post("invocation/"+id+"/response", []byte(`"bye"`), nil)
			os.Exit(0)
		default:
			post("invocation/"+id+"/response", []byte(`"?"`), nil)
		}
	}
}
