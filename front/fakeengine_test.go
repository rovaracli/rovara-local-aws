package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fake engine for the tests that need a child process: the test binary itself, started through a wrapper script, plays
// AWS Emulator closely enough for the front (the startup line, the CA file, /__admin/health, a few API answers).
// Real AWS Emulator is exercised by scripts/front-compat.sh in the VM.

const fakeEngineEnv = "ROVARA_FRONT_TEST_FAKE_ENGINE"

func TestMain(m *testing.M) {
	if os.Getenv(fakeEngineEnv) == "1" {
		runFakeEngine()
		return
	}
	localAddrs = func() []net.IP { return nil } // the machine's own interfaces say nothing about the tests' addresses; a test that needs some sets its own
	if os.Getenv(runMainEnv) == "1" {
		main() // the test binary playing the front itself (sink_main_test.go)
		return
	}
	os.Exit(m.Run())
}

func runFakeEngine() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake engine"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	home := os.Getenv("HOME")
	dir := filepath.Join(home, ".aws", "emulator", fmt.Sprint(port))
	os.MkdirAll(dir, 0o700)
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	fmt.Printf(`{"timestamp":"x","level":"INFO","fields":{"message":"emulator server information","endpoint_url":"https://127.0.0.1:%d","ca_file":%q},"target":"fake"}`+"\n", port, caFile)

	var mu sync.Mutex
	var smMu sync.Mutex
	smObjects, smTypes := map[string][]byte{}, map[string]string{}
	var snsPublishes, smCalls []string
	var pathsMu sync.Mutex
	var paths []string
	queues := []string{}
	last := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Fake-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Fake-Host", strings.Replace(r.Host, ":", "_", 1))
		w.Header().Set("X-Fake-Path", r.URL.RequestURI())
		w.Header().Set("X-Fake-Fwd", r.Header.Get("X-Forwarded-Host")+"|"+r.Header.Get("X-Rovara-Control-Token"))
		if r.URL.Path == "/__admin/health" {
			io.WriteString(w, "ok")
			return
		}
		pathsMu.Lock()
		paths = append(paths, r.Method+" "+r.URL.RequestURI())
		pathsMu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/rovara-heavy-payloads-") && (strings.HasSuffix(r.URL.Path, "/req/bigobj") || strings.HasSuffix(r.URL.Path, "/req/hugeobj")) && r.Method == "GET" {
			// an event object bigger than any call can carry (the front must not read it all): 10 MiB, or 20 MiB
			chunk := make([]byte, 1<<20)
			n := 10
			if strings.HasSuffix(r.URL.Path, "/req/hugeobj") {
				n = 20
			}
			for i := 0; i < n; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			return
		}
		if fakeLambdaHandle(w, r, body) {
			return
		}
		if r.URL.Path == "/__fake/paths" {
			pathsMu.Lock()
			io.WriteString(w, strings.Join(paths, "\n"))
			pathsMu.Unlock()
			return
		}
		if strings.HasPrefix(r.URL.Path, "/slowbkt/") {
			time.Sleep(3 * time.Second)
			io.WriteString(w, `{"Resources":{}}`)
			return
		}
		if r.Header.Get("X-Amz-Target") == "AWSStepFunctions.DescribeExecution" {
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			io.WriteString(w, `{"status":"SUCCEEDED","output":"{\"QueueUrl\":\"https://sqs.us-east-1.amazonaws.com/000000000000/made-by-sfn\"}"}`)
			return
		}
		if r.URL.Path == "/__fake/last" {
			mu.Lock()
			io.WriteString(w, last)
			mu.Unlock()
			return
		}
		if t := r.Header.Get("X-Amz-Target"); strings.HasPrefix(t, "AmazonSQS.") && t != "AmazonSQS.ListQueues" {
			mu.Lock()
			last = t + " " + string(body)
			mu.Unlock()
		}
		if r.URL.Path == "/__fake/env" {
			json.NewEncoder(w).Encode(map[string]interface{}{"env": os.Environ(), "args": os.Args[1:], "pid": os.Getpid()})
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSQS.CreateQueue":
			var req map[string]string
			json.Unmarshal(body, &req)
			mu.Lock()
			queues = append(queues, req["QueueName"])
			mu.Unlock()
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			fmt.Fprintf(w, `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/%s"}`, req["QueueName"])
			return
		case "AmazonSQS.ListQueues":
			mu.Lock()
			urls := []string{}
			for _, q := range queues {
				urls = append(urls, `"https://sqs.us-east-1.amazonaws.com/000000000000/`+q+`"`)
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			fmt.Fprintf(w, `{"QueueUrls":[%s]}`, strings.Join(urls, ","))
			return
		case "AmazonSQS.SendMessageBatch":
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			io.WriteString(w, `{"Successful":[{"Id":"a","MessageId":"m1","MD5OfMessageBody":"x"}],"Failed":[{"Id":"b","SenderFault":true,"Code":"InvalidParameterValue","Message":"bad"}]}`)
			return
		case "AmazonSQS.GetQueueUrl":
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.Header().Set("x-amzn-query-error", "AWS.SimpleQueueService.NonExistentQueue;Sender")
			w.WriteHeader(400)
			io.WriteString(w, `{"__type":"QueueDoesNotExist","message":"The specified queue does not exist."}`)
			return
		case "AmazonSQS.NopeOp":
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.WriteHeader(501)
			io.WriteString(w, `{"__type":"NotImplemented","message":"operation NopeOp is not implemented in this emulator"}`)
			return
		case "AmazonSQS.ReceiveMessage":
			env := `{"Type":"Notification","MessageId":"m","TopicArn":"arn:aws:sns:us-east-1:000000000000:t","Message":"hello","UnsubscribeURL":"https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=a"}`
			plain := `https://sqs.us-east-1.amazonaws.com/000000000000/user-text`
			b1, _ := json.Marshal(env)
			b2, _ := json.Marshal(plain)
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			fmt.Fprintf(w, `{"Messages":[{"MessageId":"1","MD5OfBody":"old","Body":%s},{"MessageId":"2","MD5OfBody":"keep","Body":%s}]}`, b1, b2)
			return
		}
		// the SageMaker shim's own calls: an object store for async input and output, SNS publishes, and the control-plane calls
		if strings.HasPrefix(r.URL.Path, "/smbkt/") || strings.HasPrefix(r.URL.Path, "/nobkt/") {
			smMu.Lock()
			defer smMu.Unlock()
			switch {
			case strings.HasPrefix(r.URL.Path, "/nobkt/"):
				w.WriteHeader(404)
				io.WriteString(w, `<Error><Code>NoSuchBucket</Code><Message>no such bucket</Message></Error>`)
			case r.Method == "PUT":
				smObjects[r.URL.Path] = body
				smTypes[r.URL.Path] = r.Header.Get("Content-Type")
			case r.Method == "GET" && smObjects[r.URL.Path] != nil:
				w.Write(smObjects[r.URL.Path])
			default:
				w.WriteHeader(404)
			}
			return
		}
		if r.URL.Path == "/__fake/smobject" {
			smMu.Lock()
			defer smMu.Unlock()
			io.WriteString(w, string(smObjects[r.URL.Query().Get("p")])+"\n"+smTypes[r.URL.Query().Get("p")])
			return
		}
		if r.URL.Path == "/__fake/sns" {
			smMu.Lock()
			defer smMu.Unlock()
			io.WriteString(w, strings.Join(snsPublishes, "\n"))
			return
		}
		if r.URL.Path == "/__fake/smcalls" {
			smMu.Lock()
			defer smMu.Unlock()
			io.WriteString(w, strings.Join(smCalls, "\n"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.Header.Get("Authorization"), "/cloudformation/aws4_request") && strings.Contains(string(body), "Action=DescribeStackResources") {
			// the engine's physical ids: <stack>-<LogicalId>-<12 hex>; a stack named nophys has none yet
			form, _ := url.ParseQuery(string(body))
			var members string
			if st := form.Get("StackName"); st != "nophys" {
				for _, l := range []string{"Model", "Config", "Endpoint", "Unnamed", "Hidden"} {
					members += "<member><LogicalResourceId>" + l + "</LogicalResourceId><PhysicalResourceId>" + st + "-" + l + "-0123456789AB</PhysicalResourceId></member>"
				}
			}
			w.Header().Set("Content-Type", "text/xml")
			io.WriteString(w, "<DescribeStackResourcesResponse><DescribeStackResourcesResult><StackResources>"+members+"</StackResources></DescribeStackResourcesResult></DescribeStackResourcesResponse>")
			return
		}
		if r.Method == "POST" && strings.Contains(r.Header.Get("Authorization"), "/sns/aws4_request") {
			form, _ := url.ParseQuery(string(body))
			smMu.Lock()
			snsPublishes = append(snsPublishes, form.Get("TopicArn")+" "+form.Get("Message"))
			smMu.Unlock()
			w.Header().Set("Content-Type", "text/xml")
			io.WriteString(w, `<PublishResponse><PublishResult><MessageId>m1</MessageId></PublishResult></PublishResponse>`)
			return
		}
		if t := r.Header.Get("X-Amz-Target"); strings.HasPrefix(t, "SageMaker.") {
			smMu.Lock()
			smCalls = append(smCalls, t+" "+string(body))
			smMu.Unlock()
			if strings.Contains(string(body), `"REFUSE"`) {
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(400)
				io.WriteString(w, `{"__type":"ValidationException","message":"refused"}`)
				return
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			io.WriteString(w, `{}`)
			return
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/zipbkt/") {
			// packages for the heavy-function detector, taken from the "S3"
			switch strings.TrimPrefix(r.URL.Path, "/zipbkt/") {
			case "heavy.zip", "layer.zip":
				w.Write(testZip(zent{"index.py", []byte("def handler(e, c): return 1")}, zent{"lib/native.so", testELF(elfMachineAArch64)}))
			case "light.zip":
				w.Write(testZip(zent{"index.py", []byte("def handler(e, c): return 1")}))
			default:
				w.WriteHeader(404)
			}
			return
		}
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/2018-10-31/layers/") && strings.HasSuffix(r.URL.Path, "/versions") {
			name := strings.Split(r.URL.Path, "/")[3]
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"LayerVersionArn":"arn:aws:lambda:us-east-1:000000000000:layer:%s:1","Version":1}`, name)
			return
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/tplbkt/") {
			// templates for the CloudFormation recorder
			switch strings.TrimPrefix(r.URL.Path, "/tplbkt/") {
			case "m.json": // a state machine definition
				io.WriteString(w, `{"StartAt":"T","States":{"T":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:sqs:createQueue","End":true}}}`)
			case "t.json":
				io.WriteString(w, `{"Resources":{"Q":{"Type":"AWS::SQS::Queue"},"K":{"Type":"AWS::KMS::Key"},"F":{"Type":"AWS::Lambda::Function"}}}`)
			case "hidden.json":
				io.WriteString(w, `{"Resources":{"P":{"Type":"AWS::SQS::QueuePolicy","Properties":{"Queues":["http://aws:4566/000000000000/rovara-heavy-req"]}}}}`)
			case "nested.json":
				io.WriteString(w, `{"Resources":{"N":{"Type":"AWS::CloudFormation::Stack","Properties":{"TemplateURL":"https://x/y"}}}}`)
			case "big.json":
				w.Header().Set("Content-Length", fmt.Sprint(2<<20))
				w.Write(make([]byte, 2<<20))
			default:
				w.WriteHeader(404)
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "/boom") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			io.WriteString(w, `{"__type":"InternalFailure","message":"boom"}`)
			return
		}
		if r.URL.Query().Has("uploadId") && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Location>https://bkt.s3.us-east-1.amazonaws.com/some/key</Location><Bucket>bkt</Bucket></CompleteMultipartUploadResult>`)
			return
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/bkt/object") {
			// an object whose bytes look like an engine address and a queue URL: must pass through untouched
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"q":"https://sqs.us-east-1.amazonaws.com/000000000000/q","self":"https://127.0.0.1:1"}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/bkt/self") {
			// bytes and metadata that happen to name the engine's own address: data, never rewritten
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("x-amz-meta-origin", "https://127.0.0.1:"+fmt.Sprint(port)+"/m")
			fmt.Fprintf(w, `{"url":"https://127.0.0.1:%d/x","x-amz-crc32":"1"}`, port)
			return
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://127.0.0.1:"+fmt.Sprint(port)+"/elsewhere")
			w.WriteHeader(307)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		io.WriteString(w, `{}`)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	// the real engine exits on SIGTERM and removes its keys
	sig := make(chan os.Signal, 1)
	notifyTerm(sig)
	<-sig
	os.RemoveAll(dir)
}

// fakeEngineBin writes the wrapper script that starts the test binary as the fake engine.
func fakeEngineBin(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "aws-emulator")
	body := "#!/bin/sh\n" + fakeEngineEnv + "=1 exec " + exe + " \"$@\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}
