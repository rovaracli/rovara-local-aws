package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Tests for the review of the sink (findings M1, M2, L1 to L4). Each fails on the code the review read and passes on the fix.

// ---- M1: a body the engine decodes must be decoded before the wall looks at it

func TestReviewEncodedBodiesDoNotBypassTheTapWall(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	tapName := sinkQueueNameOf(sub.tapQueueURL)
	tapURL := "https://sqs.us-east-1.amazonaws.com/000000000000/" + tapName
	for _, op := range []string{"DeleteQueue", "PurgeQueue", "ReceiveMessage", "GetQueueAttributes"} {
		plain := []byte(`{"QueueUrl":"` + tapURL + `"}`)
		for name, c := range map[string]struct {
			body []byte
			enc  string
		}{
			"gzip":                   {sink_gz(plain), "gzip"},
			"aws-chunked":            {sink_awsChunked(plain), "aws-chunked"},
			"aws-chunked then gzip":  {sink_awsChunked(sink_gz(plain)), "aws-chunked, gzip"},
			"a gzip value in a list": {sink_gz(plain), "identity, x-gzip"},
		} {
			if code, out := r.sqsRaw(op, c.body, map[string]string{"Content-Encoding": c.enc}); code != 400 || !strings.Contains(out, "QueueDoesNotExist") {
				t.Errorf("%s %s: %d %s", op, name, code, out)
			}
		}
	}
	if names := r.aws.queueNames(); len(names) != 1 || names[0] != tapName {
		t.Fatalf("the tap queue was touched: %v", names)
	}
	r.publish(topic, "still flowing")
	sink_waitFor(t, "the delivery", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	// an encoding the front does not decode, a body that is not what it says, and a bomb are refused
	for name, c := range map[string]struct {
		body []byte
		enc  string
		want int
	}{
		"brotli":                  {[]byte(`{}`), "br", 415},
		"deflate":                 {[]byte(`{}`), "deflate", 415},
		"a made-up encoding":      {[]byte(`{}`), "gzip, rot13", 415},
		"garbage as gzip":         {[]byte("not gzip at all"), "gzip", 400},
		"garbage as aws-chunked":  {[]byte("zz\r\nnope"), "aws-chunked", 400},
		"a truncated aws-chunked": {[]byte("10\r\nshort"), "aws-chunked", 400},
		"a gzip bomb":             {sink_gz(bytes.Repeat([]byte("A"), 100<<20)), "gzip", 400}, // the shared decoder answers a bomb as an undecodable body
		"an aws-chunked bomb":     {sink_awsChunked(bytes.Repeat([]byte("A"), 80<<20)), "aws-chunked", 413},
	} {
		if code, out := r.sqsRaw("ReceiveMessage", c.body, map[string]string{"Content-Encoding": c.enc}); code != c.want {
			t.Errorf("%s: %d %.100s", name, code, out)
		}
	}
	// an encoded body to an ordinary queue still works, decoded before it is forwarded (the engine is never given the encoding)
	if code, out := r.sqsRaw("CreateQueue", sink_gz([]byte(`{"QueueName":"mine"}`)), map[string]string{"Content-Encoding": "gzip"}); code != 200 || !strings.Contains(out, "/mine") {
		t.Errorf("a gzip CreateQueue: %d %s", code, out)
	}
	if code, out := r.sqsRaw("CreateQueue", sink_awsChunked([]byte(`{"QueueName":"mine2"}`)), map[string]string{"Content-Encoding": "aws-chunked"}); code != 200 || !strings.Contains(out, "/mine2") {
		t.Errorf("an aws-chunked CreateQueue: %d %s", code, out)
	}
	// SNS: a form body is never decoded by the engine, so an encoded one is refused; an aws-chunked one is decoded and judged like any other
	form := "Action=Subscribe&Version=2010-03-31&TopicArn=" + topic + "&Protocol=http&Endpoint=http%3A%2F%2F169.254.169.254%2F"
	if code, _, out := r.do("POST", "/", merge(snsAuth, map[string]string{"Content-Encoding": "gzip"}), string(sink_gz([]byte(form)))); code != 415 {
		t.Errorf("a gzip form: %d %s", code, out)
	}
	if code, _, out := r.do("POST", "/", merge(snsAuth, map[string]string{"Content-Encoding": "aws-chunked"}), string(sink_awsChunked([]byte(form)))); code != 400 || !strings.Contains(out, "InvalidParameter") {
		t.Errorf("an aws-chunked SSRF Subscribe: %d %s", code, out)
	}
	if n := len(r.subRows()); n != 1 {
		t.Errorf("%d subscriptions", n)
	}
}

// ---- M1: a tap that disappears is noticed, counted and rebuilt

func TestReviewALostTapIsNoticedCountedAndRebuilt(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true; s.TapVerifyEvery = 100 * time.Millisecond })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	first := sinkQueueNameOf(sub.tapQueueURL)
	tapLost := func() float64 {
		for _, row := range r.subRows() {
			if st, ok := row["stats"].(map[string]interface{}); ok {
				if n, ok := st["TapLost"].(float64); ok {
					return n
				}
			}
		}
		return 0
	}
	// 1. the tap queue is deleted behind the front's back
	r.aws.mu.Lock()
	delete(r.aws.queues, first)
	r.aws.mu.Unlock()
	sink_waitFor(t, "the lost tap to be counted", 5*time.Second, func() bool { return tapLost() >= 1 })
	sink_waitFor(t, "a new tap queue", 5*time.Second, func() bool {
		n := r.aws.queueNames()
		return len(n) == 1 && n[0] != first
	})
	tapOK := func() bool { // the rebuild is finished: the subscription says its tap is fine, and the topic has the tap's subscription
		for _, row := range r.subRows() {
			if row["tap"] != "ok" {
				return false
			}
		}
		r.aws.mu.Lock()
		defer r.aws.mu.Unlock()
		for _, s := range r.aws.subs {
			if s.protocol == "sqs" {
				return true
			}
		}
		return false
	}
	sink_waitFor(t, "the rebuild to finish", 5*time.Second, tapOK)
	r.publish(topic, "after the queue was lost")
	sink_waitFor(t, "the delivery", 5*time.Second, func() bool { return len(r.hook.got()) == 1 })
	// 2. the tap's subscription is removed from the topic (the queue is still there)
	r.srv.sink.mu.Lock()
	tapArn := sub.tapArn
	r.srv.sink.mu.Unlock()
	r.aws.mu.Lock()
	var keep []*fakeSub
	for _, s := range r.aws.subs {
		if s.arn != tapArn {
			keep = append(keep, s)
		}
	}
	r.aws.subs = keep
	r.aws.mu.Unlock()
	sink_waitFor(t, "the lost tap subscription to be counted", 5*time.Second, func() bool { return tapLost() >= 2 })
	sink_waitFor(t, "the tap to be subscribed again", 5*time.Second, tapOK)
	r.publish(topic, "after the subscription was lost")
	sink_waitFor(t, "the second delivery", 5*time.Second, func() bool { return len(r.hook.got()) == 2 })
	// 3. what the control read says while it was broken is never "confirmed with nothing flowing": the count and a record say what happened
	var lost bool
	for _, a := range r.attempts(sub.arn) {
		if a.Outcome == "tap lost" {
			lost = true
		}
	}
	if !lost {
		t.Error("the capture has no record of the lost tap")
	}
	if sum := func() string { _, b := r.control("/_rovara/sns/summary"); return b }(); !strings.Contains(sum, "TapLost") {
		t.Errorf("the summary does not count lost taps: %s", sum)
	}
}

// ---- M2: the engine is told who is calling and where

func TestReviewTheEngineIsToldTheCallersRegionKeyAndToken(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	_, body := r.snsAs("eu-west-1", "AKCALLER", "sess-token", "CreateTopic", "Name", "eu")
	topic := regexp.MustCompile(`<TopicArn>([^<]+)</TopicArn>`).FindStringSubmatch(body)[1]
	if code, out := r.snsAs("eu-west-1", "AKCALLER", "sess-token", "Subscribe", "TopicArn", topic, "Protocol", "http", "Endpoint", hookURL(r.hook, "web", "/h")); code != 200 {
		t.Fatalf("Subscribe: %d %s", code, out)
	}
	r.snsAs("eu-west-1", "AKCALLER", "sess-token", "ListSubscriptionsByTopic", "TopicArn", topic)
	r.snsAs("eu-west-1", "AKCALLER", "sess-token", "GetTopicAttributes", "TopicArn", topic)
	log := r.aws.authLog()
	has := func(want string) bool {
		for _, l := range log {
			if l == want {
				return true
			}
		}
		return false
	}
	// what the caller asked for is forwarded as the caller, in the caller's region
	if !has("sns Subscribe eu-west-1 AKCALLER sess-token") || !has("sns ListSubscriptionsByTopic eu-west-1 AKCALLER sess-token") {
		t.Errorf("forwarded calls: %v", log)
	}
	// what the sink does for itself (the tap) is made in the topic's region, as the front, never as the caller
	for _, l := range log {
		f := strings.Fields(l)
		if len(f) >= 4 && strings.HasPrefix(f[1], "SetQueueAttributes") || len(f) >= 2 && (f[1] == "CreateQueue" || f[1] == "ReceiveMessage") {
			if f[2] != "eu-west-1" || f[3] == "AKCALLER" {
				t.Errorf("a tap call: %s", l)
			}
		}
	}
	sub := r.onlySub()
	if !strings.Contains(sub.tapQueueArn, ":sqs:eu-west-1:") || !strings.Contains(sub.arn, ":sns:eu-west-1:") {
		t.Errorf("arns: %s %s", sub.tapQueueArn, sub.arn)
	}
	// a link (no credential) acts in the topic's region
	r2 := newSinkRig(t, nil)
	_, b2 := r2.snsAs("ap-south-1", "", "", "CreateTopic", "Name", "ap")
	t2 := regexp.MustCompile(`<TopicArn>([^<]+)</TopicArn>`).FindStringSubmatch(b2)[1]
	r2.snsAs("ap-south-1", "", "", "Subscribe", "TopicArn", t2, "Protocol", "http", "Endpoint", hookURL(r2.hook, "web", "/h"))
	r2.confirm(r2.hook)
	r2.snsAs("ap-south-1", "", "", "Publish", "TopicArn", t2, "Message", "m")
	sink_waitFor(t, "the delivery in another region", 3*time.Second, func() bool { return len(r2.hook.got()) == 2 })
}

// ---- L1: what comes off the tap is checked, and the front's clock decides

func TestReviewAnEnvelopeForAnotherTopicIsDroppedAndItsTimestampIsNotTrusted(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	other := r.topic("other")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	tap := sinkQueueNameOf(sub.tapQueueURL)
	env := func(topicArn, ts, msg string) string {
		b, _ := json.Marshal(map[string]interface{}{"Type": "Notification", "MessageId": newUUID(), "TopicArn": topicArn, "Message": msg, "Timestamp": ts})
		return string(b)
	}
	r.aws.inject(tap, env(other, time.Now().UTC().Format(time.RFC3339Nano), "from another topic"))
	r.aws.inject(tap, env(topic, "2001-01-01T00:00:00Z", "an old stamp"))
	sink_waitFor(t, "the delivery of the one that counts", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	time.Sleep(150 * time.Millisecond)
	got := r.hook.got()
	if len(got) != 1 || !strings.Contains(got[0].Body, "an old stamp") {
		t.Fatalf("deliveries: %v", got)
	}
	var dropped bool
	for _, a := range r.attempts(sub.arn) {
		if a.Outcome == "dropped" && strings.Contains(a.Error, "another topic") {
			dropped = true
		}
	}
	if !dropped {
		t.Errorf("the envelope for another topic left no record: %+v", r.attempts(sub.arn))
	}
	// a subscription to a tap queue's arn is refused, not hidden
	if code, body := r.subscribe(other, "sqs", sub.tapQueueArn); code != 400 {
		t.Errorf("Subscribe of a tap arn: %d %s", code, body)
	}
}

func TestReviewAMessageReceivedBeforeConfirmationIsDropped(t *testing.T) {
	r := newSinkRig(t, nil)
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	r.publish(topic, "too early")
	sub := r.onlySub()
	sink_waitFor(t, "the early message to be dropped", 3*time.Second, func() bool {
		for _, a := range r.attempts(sub.arn) {
			if a.Outcome == "dropped" {
				return true
			}
		}
		return false
	})
	r.confirm(r.hook)
	r.publish(topic, "in time")
	sink_waitFor(t, "the notification", 3*time.Second, func() bool { return len(r.hook.got()) == 2 })
	if !strings.Contains(r.hook.got()[1].Body, "in time") {
		t.Errorf("deliveries: %v", r.hook.got())
	}
}

// ---- L2: a batch larger than the read cap is not lost, and a message too large to read is counted

func TestReviewALargeBatchIsNotLostAndAnUnreadableMessageIsCounted(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	r.aws.mu.Lock()
	r.aws.hugeBody = 450000 // twelve of these are more than 4 MiB in one ReceiveMessage of ten
	r.aws.mu.Unlock()
	for i := 0; i < 12; i++ {
		r.publish(topic, "x")
	}
	sink_waitFor(t, "all twelve", 10*time.Second, func() bool { return len(r.hook.got()) == 12 })
	// ten messages that together are more than one answer may hold arrive one at a time, and each is judged on its own (too large to hold: counted)
	for i := 0; i < 10; i++ {
		r.aws.inject(sinkQueueNameOf(sub.tapQueueURL), strings.Repeat("z", 900<<10))
	}
	sink_waitFor(t, "each of the ten to be counted on its own", 10*time.Second, func() bool {
		n := 0
		for _, a := range r.attempts(sub.arn) {
			if a.Outcome == "dropped" && strings.Contains(a.Error, "larger than the sink holds") {
				n++
			}
		}
		return n == 10
	})
	// a message the read cap cannot hold is dropped and counted, and the next one still arrives
	r.aws.inject(sinkQueueNameOf(sub.tapQueueURL), strings.Repeat("y", 9<<20))
	sink_waitFor(t, "the unreadable message to be counted", 10*time.Second, func() bool {
		for _, row := range r.subRows() {
			if st, ok := row["stats"].(map[string]interface{}); ok && st["Dropped"].(float64) >= 1 {
				return true
			}
		}
		return false
	})
	r.aws.mu.Lock()
	r.aws.hugeBody = 0
	r.aws.mu.Unlock()
	r.publish(topic, "after the big one")
	sink_waitFor(t, "the next delivery", 5*time.Second, func() bool { return len(r.hook.got()) == 13 })
}

func TestReviewTheBodyReadersAreLimitedAndReleased(t *testing.T) {
	r := newSinkRig(t, nil)
	k := r.srv.sink
	done := make(chan struct{})
	for i := 0; i < 40; i++ {
		go func() {
			k.snsQuery(context.Background(), ambientAs("sns", "us-east-1"), "ListTopics", nil)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 40; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("engine calls are stuck behind the body limit")
		}
	}
	if len(k.bodySlots) != 0 || cap(k.bodySlots) != snsBodySlots {
		t.Errorf("slots: %d of %d held", len(k.bodySlots), cap(k.bodySlots))
	}
}

// ---- L3: non-Query SNS is refused while the sink is on

func TestReviewNonQuerySNSIsRefused(t *testing.T) {
	r := newSinkRig(t, nil)
	topic := r.topic("t")
	for _, target := range []string{"SNS_20100331.Subscribe", "AmazonSimpleNotificationService.Subscribe"} {
		code, body := r.sqsLikeJSON(target, `{"TopicArn":"`+topic+`","Protocol":"http","Endpoint":"http://web/x"}`)
		if code != 400 && code != 404 {
			t.Errorf("JSON SNS %s: %d %s", target, code, body)
		}
	}
	req, _ := http.NewRequest("POST", r.ts.URL+"/service/SNS/operation/Subscribe", strings.NewReader("\xbf\xff"))
	req.Header.Set("smithy-protocol", "rpc-v2-cbor")
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Authorization", snsAuth["Authorization"])
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("CBOR SNS: %d", resp.StatusCode)
	}
	for _, c := range r.aws.callLog() {
		if c == "sns:" {
			t.Errorf("a non-Query SNS call reached the engine: %v", r.aws.callLog())
		}
	}
}

func (r *sinkRig) sqsLikeJSON(target, body string) (int, string) {
	code, _, out := r.do("POST", "/", map[string]string{"X-Amz-Target": target, "Content-Type": "application/x-amz-json-1.0",
		"Authorization": snsAuth["Authorization"]}, body)
	return code, out
}

// ---- L4

func TestReviewTopicCountsLeaveOutTheTapsAndCountTheFrontsSubscriptions(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	counts := func() (string, string) {
		_, b := r.sns("GetTopicAttributes", "TopicArn", topic)
		g := func(k string) string {
			return regexp.MustCompile(`<key>` + k + `</key><value>([0-9]+)</value>`).FindStringSubmatch(b)[1]
		}
		return g("SubscriptionsConfirmed"), g("SubscriptionsPending")
	}
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/a"))
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/b"))
	if c, p := counts(); c != "2" || p != "0" {
		t.Errorf("two confirmed subscriptions: confirmed %s pending %s", c, p)
	}
	var arn string
	for _, row := range r.subRows() {
		arn = row["subscriptionArn"].(string)
	}
	r.sns("Unsubscribe", "SubscriptionArn", arn)
	if c, p := counts(); c != "1" || p != "0" {
		t.Errorf("after an unsubscribe: confirmed %s pending %s", c, p)
	}
	// a subscription of the engine's own (sqs) is counted as the engine counts it
	r.aws.mu.Lock()
	r.aws.queues["mine"] = nil
	r.aws.mu.Unlock()
	r.subscribe(topic, "sqs", "arn:aws:sqs:us-east-1:000000000000:mine")
	if c, _ := counts(); c != "2" {
		t.Errorf("with an sqs subscription: confirmed %s", c)
	}
}

func TestReviewConfigRefusesEveryAddressOfTheFront(t *testing.T) {
	old := localAddrs
	lookupOld := lookupIPs
	defer func() { localAddrs, lookupIPs = old, lookupOld }()
	localAddrs = func() []net.IP { return []net.IP{net.ParseIP("172.30.5.6"), net.ParseIP("10.20.30.40")} }
	lookupIPs = func(host string) ([]net.IP, error) {
		if host == "front.internal" {
			return []net.IP{net.ParseIP("172.30.5.2")}, nil
		}
		return nil, fmt.Errorf("no")
	}
	for _, host := range []string{"front.internal", "172.30.5.2", "0.0.0.0"} {
		for _, v := range []string{"172.30.5.6", "10.20.30.40", "172.30.5.2"} {
			if host == "172.30.5.2" && v != "172.30.5.6" && v != "10.20.30.40" && v != "172.30.5.2" {
				continue
			}
			c := &Config{Host: host, Planned: map[string]bool{"sns": true}}
			if host == "0.0.0.0" && v == "172.30.5.2" {
				continue // an unspecified bind names no address of its own; the interfaces are what is checked
			}
			if sc, err := parseSinkConfig(mapEnv(map[string]string{envSNSRoutes: "web=" + v}), c); err == nil {
				t.Errorf("host %s, route %s accepted: %+v", host, v, sc)
			}
			if sc, err := parseSinkConfig(mapEnv(map[string]string{envSNSSinkAddr: v}), c); err == nil {
				t.Errorf("host %s, sink %s accepted: %+v", host, v, sc)
			}
		}
	}
	// and the dial wall refuses them too
	n := newSinkNet(nil, "", nil, time.Second)
	n.local = localAddrs()
	if _, err := n.dial(withTarget(context.Background(), dialTarget{addr: "172.30.5.6:80"}), "tcp4", ""); err != errNoDialTarget {
		t.Errorf("dial to an interface address: %v", err)
	}
	// another private address is still fine
	c := &Config{Host: "front.internal", Planned: map[string]bool{"sns": true}}
	if _, err := parseSinkConfig(mapEnv(map[string]string{envSNSRoutes: "web=172.30.5.3"}), c); err != nil {
		t.Errorf("a sandbox address: %v", err)
	}
}

func TestReviewASubscribeThatRacesAResetLeavesNothingBehind(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.aws.afterSubscribe = func() { r.srv.sink.reset() } // the reset lands between the engine's answer and the front's record
	code, body := r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	r.aws.afterSubscribe = nil
	if code != 503 {
		t.Errorf("Subscribe across a reset: %d %s", code, body)
	}
	if n := len(r.subRows()); n != 0 {
		t.Errorf("%d subscriptions survived the reset", n)
	}
	sink_waitFor(t, "the tap of the dropped subscription to go", 3*time.Second, func() bool { return len(r.aws.queueNames()) == 0 })
}

func TestReviewThePasswordOfAnEndpointIsMasked(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	ep := fmt.Sprintf("web:%d/h?x=1", r.hook.port())
	r.subscribe(topic, "http", "http://user:hunter2@"+ep)
	sub := r.onlySub()
	_, attrs := r.sns("GetSubscriptionAttributes", "SubscriptionArn", sub.arn)
	_, list := r.sns("ListSubscriptionsByTopic", "TopicArn", topic)
	_, all := r.sns("ListSubscriptions")
	for name, text := range map[string]string{"attributes": attrs, "topic list": list, "list": all} {
		if strings.Contains(text, "hunter2") || !strings.Contains(text, "user:****@"+ep) {
			t.Errorf("%s: %s", name, text)
		}
	}
	// the delivery itself still carries the credential, as basic auth
	r.publish(topic, "m")
	sink_waitFor(t, "the delivery", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	if !strings.HasPrefix(r.hook.got()[0].Header.Get("Authorization"), "Basic ") {
		t.Error("no basic auth")
	}
}
