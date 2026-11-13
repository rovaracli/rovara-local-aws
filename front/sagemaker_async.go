package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// InvokeEndpointAsync. The engine answers 202 and never does the work: nothing is written to S3 and nothing is published. The front
// answers 202 with the locations (<S3OutputPath>/<InferenceId>.out, <S3FailurePath>/<InferenceId>-error.out), then, after a short delay
// (the backing's asyncDelayMs), reads the input object from the engine's own S3, asks the backing for the answer, writes it to the output
// location (or the error text to the failure location) and publishes the notification to the endpoint config's success or error topic.
// All of it goes to the engine over loopback; none of it leaves the run.
//
// The shim reads and writes S3 and publishes to SNS on the code's behalf. When the plan does not name s3 or sns, each async call
// records the call as out of plan under that service (operation sagemaker-runtime:<service>:<action>), without blocking it.

const (
	smMaxAsyncInput = 16 << 20 // the largest input object the shim reads (SageMaker allows 1 GB; the shim keeps it in memory)
	// smAsyncBudget is the memory all the asynchronous jobs may hold at once. A job holds its input (up to 16 MiB) and its answer (up to
	// 6 MiB) while it runs, so it reserves 22 MiB and two run at a time; the rest wait. The front's private memory is gated at 256 MiB.
	smAsyncBudget    = 48 << 20
	smAsyncJobMem    = smMaxAsyncInput + smMaxReplyBytes
	smDefaultAsyncMs = 100
)

// byteBudget is a counting semaphore in bytes.
type byteBudget struct {
	mu   sync.Mutex
	cond *sync.Cond
	left int64
}

func newByteBudget(n int64) *byteBudget {
	b := &byteBudget{left: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *byteBudget) acquire(n int64) {
	b.mu.Lock()
	for b.left < n {
		b.cond.Wait()
	}
	b.left -= n
	b.mu.Unlock()
}

// tryAcquire is acquire that never waits: false when the budget has less than n left. (A request that waits for the budget before it has
// read its body is not watched by the server, so a client that left would not end the wait.)
func (b *byteBudget) tryAcquire(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.left < n {
		return false
	}
	b.left -= n
	return true
}

func (b *byteBudget) release(n int64) {
	b.mu.Lock()
	b.left += n
	b.mu.Unlock()
	b.cond.Broadcast()
}

var smBucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// parseS3URI splits s3://bucket/key.
func parseS3URI(u string) (bucket, key string, ok bool) {
	rest, found := strings.CutPrefix(u, "s3://")
	if !found {
		return "", "", false
	}
	bucket, key, found = strings.Cut(rest, "/")
	if !found || key == "" || !smBucketRe.MatchString(bucket) || len(key) > 1024 {
		return "", "", false
	}
	return bucket, key, true
}

func s3ObjectPath(bucket, key string) (string, bool) {
	p := "/" + bucket + "/" + s3PathEscape(key)
	return p, safeObjectPath(p)
}

// smAsyncInvoke answers the 202 and starts the work.
func (s *Server) smAsyncInvoke(w http.ResponseWriter, r *http.Request, inv *smInv, cfg *smConfig, entry *ledgerEntry, done func(int, bool)) {
	m := s.sm
	fail := func(msg string) {
		writeSMError(w, smValidation(msg))
		done(http.StatusBadRequest, false)
	}
	if cfg == nil || cfg.Async == nil || cfg.Async.OutputPath == "" {
		fail("Endpoint " + inv.name + " is not configured for asynchronous inference.")
		return
	}
	if _, _, ok := parseS3URI(inv.inputLoc); !ok {
		fail("InputLocation must be an s3:// URI of an object.")
		return
	}
	id := inv.inferenceID
	if id == "" {
		id = newUUID()
	} else if len(id) > 64 || strings.ContainsAny(id, "/\r\n\x00 ") {
		fail("InferenceId is not valid.")
		return
	}
	inv.inferenceID = id
	a := cfg.Async
	outBase, failBase := strings.TrimRight(a.OutputPath, "/"), strings.TrimRight(a.FailurePath, "/")
	if failBase == "" {
		failBase = outBase
	}
	outLoc, failLoc := outBase+"/"+id+".out", failBase+"/"+id+"-error.out"
	// no backing: refused now, before anything is accepted, so the code sees the refusal at once and no output or error file is waited for
	m.mu.Lock()
	none := m.effectiveBacking(inv.name).Mode == smModeNone
	m.mu.Unlock()
	if none {
		res := smNoAnswerResult(inv.name)
		m.record(inv.name, smOpAsync, res)
		s.ledger.mark(entry, smNoAnswerMarker)
		writeSMError(w, res.err)
		done(smErrorStatus[res.err.Code], false)
		return
	}
	select {
	case m.asyncSlots <- struct{}{}:
	default:
		writeSMError(w, &smErrorSpec{Code: "ServiceUnavailable", Message: "Too many asynchronous invocations are waiting."})
		done(http.StatusServiceUnavailable, false)
		return
	}
	// the calls the shim makes for the code, recorded when the plan does not name the service
	s.smRecordIfOutOfPlan("s3", "GetObject")
	s.smRecordIfOutOfPlan("s3", "PutObject")
	if a.SuccessTopic != "" || a.ErrorTopic != "" {
		s.smRecordIfOutOfPlan("sns", "Publish")
	}
	m.mu.Lock()
	back := m.effectiveBacking(inv.name)
	delay := time.Duration(back.AsyncDelayMs) * time.Millisecond
	if back.AsyncDelayMs == 0 {
		delay = smDefaultAsyncMs * time.Millisecond
	}
	m.mu.Unlock()
	label, _ := smLabel(back)
	s.ledger.mark(entry, label+"; asynchronous, answered after the call returned")
	m.asyncWG.Add(1)
	go func() {
		defer m.asyncWG.Done()
		defer func() { <-m.asyncSlots }()
		s.smRunAsync(inv, a, outLoc, failLoc, delay)
	}()
	h := w.Header()
	h["x-amzn-sagemaker-outputlocation"] = []string{outLoc}
	h["x-amzn-sagemaker-failurelocation"] = []string{failLoc}
	h["x-amzn-RequestId"] = []string{newUUID()}
	b, _ := json.Marshal(map[string]string{"InferenceId": id})
	writeBody(w, http.StatusAccepted, "application/json", b)
	done(http.StatusAccepted, false)
}

func (s *Server) smRecordIfOutOfPlan(key, action string) {
	if s.cfg.Planned != nil && !s.cfg.Planned[key] {
		s.ledger.recordOutOfPlan(key, "sagemaker-runtime:"+key+":"+action)
	}
}

// smRunAsync does one asynchronous invocation's work.
func (s *Server) smRunAsync(inv *smInv, a *smAsync, outLoc, failLoc string, delay time.Duration) {
	m := s.sm
	m.asyncBytes.acquire(smAsyncJobMem) // the input and the answer are held until the job is done
	defer m.asyncBytes.release(smAsyncJobMem)
	received := time.Now().UTC()
	reason := ""
	var res *smResult
	ctx := context.Background()
	if bucket, key, ok := parseS3URI(inv.inputLoc); !ok {
		reason = "InputLocation is not an s3:// URI of an object"
	} else if path, ok := s3ObjectPath(bucket, key); !ok {
		reason = "InputLocation is not an object path the shim reads"
	} else if resp, err := s.engineRaw("s3", http.MethodGet, path, nil, nil, engineFetchTimeout, smMaxAsyncInput); err != nil {
		reason = "the input object could not be read: " + err.Error()
	} else if resp.Status != http.StatusOK {
		reason = fmt.Sprintf("the input object could not be read (status %d)", resp.Status)
	} else if len(resp.Body) > smMaxAsyncInput {
		reason = "the input object is larger than the 16 MiB the shim reads"
	} else {
		inv.body = resp.Body
	}
	if reason == "" {
		res = s.smProduce(ctx, inv, false)
		defer res.close()
		m.record(inv.name, smOpAsync, res)
		if res.err != nil {
			reason = res.err.Code + ": " + res.err.Message
		}
	} else {
		m.mu.Lock()
		st := m.statsFor(inv.name)
		st.Calls++
		st.Async++
		st.Errors++
		m.mu.Unlock()
	}
	time.Sleep(delay)
	now := time.Now().UTC()
	req := map[string]any{"contentType": mediaType(inv.contentType), "endpointName": inv.name, "inputLocation": inv.inputLoc}
	if inv.custom != "" {
		req["customAttributes"] = inv.custom
	}
	event := map[string]any{"awsRegion": s.cfg.Region, "eventTime": now.Format("2006-01-02T15:04:05.000Z"),
		"receivedTime": received.Format("2006-01-02T15:04:05.000Z"), "requestParameters": req, "inferenceId": inv.inferenceID,
		"eventDetails": map[string]any{"eventVersion": "1.0"}}
	if reason == "" {
		if err := s.smPutObject(outLoc, res.ctype, res.data); err != nil {
			reason = "the output could not be written: " + err.Error()
		}
	}
	if reason == "" {
		event["invocationStatus"] = "Completed"
		event["responseParameters"] = map[string]any{"contentType": res.ctype, "outputLocation": outLoc}
		if a.InclSuccess && len(res.data) <= 128<<10 {
			event["responseBody"] = string(res.data)
		}
		s.smNotify(inv.name, a.SuccessTopic, event)
		m.mu.Lock()
		m.statsFor(inv.name).AsyncDone++
		m.mu.Unlock()
		return
	}
	event["invocationStatus"] = "Failed"
	event["failureReason"] = reason
	// the failure object holds the error text, as SageMaker writes it
	if err := s.smPutObject(failLoc, "text/plain", []byte(reason)); err != nil {
		event["failureReason"] = reason + "; the failure object could not be written: " + err.Error()
	}
	s.smNotify(inv.name, a.ErrorTopic, event)
	m.mu.Lock()
	m.statsFor(inv.name).AsyncFailed++
	m.mu.Unlock()
}

// smPutObject writes an object to the engine's S3 at an s3:// URI.
func (s *Server) smPutObject(loc, ctype string, data []byte) error {
	bucket, key, ok := parseS3URI(loc)
	if !ok {
		return fmt.Errorf("%q is not an s3:// URI of an object", loc)
	}
	path, ok := s3ObjectPath(bucket, key)
	if !ok {
		return fmt.Errorf("%q is not an object path", loc)
	}
	if data == nil {
		data = []byte{}
	}
	resp, err := s.engineRaw("s3", http.MethodPut, path, map[string]string{"Content-Type": ctype}, data, engineFetchTimeout, 1<<20)
	if err != nil {
		return err
	}
	if resp.Status >= 300 {
		return failure("PutObject", resp)
	}
	return nil
}

// smNotify publishes the event to a topic through the engine's SNS. A topic that is not set is skipped; a failure is counted.
func (s *Server) smNotify(name, topic string, event map[string]any) {
	if topic == "" {
		return
	}
	msg, _ := json.Marshal(event)
	form := url.Values{"Action": {"Publish"}, "Version": {"2010-03-31"}, "TopicArn": {topic}, "Message": {string(msg)}}
	resp, err := s.engineRaw("sns", http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode()), engineFetchTimeout, 1<<20)
	if err != nil || resp.Status >= 300 {
		s.sm.mu.Lock()
		s.sm.statsFor(name).NotifyFailures++
		s.sm.mu.Unlock()
	}
}
