package main

import (
	"context"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func realRig(t *testing.T, mutate func(*SinkConfig)) *sinkRig {
	t.Helper()
	bin := os.Getenv("ROVARA_REAL_ENGINE_BIN")
	if bin == "" {
		t.Skip("ROVARA_REAL_ENGINE_BIN is not set")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("the engine binary is not here")
	}
	engine := newEngine(bin, t.TempDir())
	if err := engine.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(engine.Stop)
	r := &sinkRig{t: t, hook: newHook(t), sink: newHook(t), mail: newSMTP(t)}
	sc := &SinkConfig{Routes: map[string]net.IP{"web": net.ParseIP("127.0.0.1")}, SinkIP: net.ParseIP("127.0.0.1"), SinkHTTPPort: r.sink.port(), SinkHTTPSPort: r.sink.port(),
		SMTP: r.mail.addr(), RetryBase: 5 * time.Millisecond, AttemptTimeout: 2 * time.Second, privateCheck: loopbackOrPrivate}
	if mutate != nil {
		mutate(sc)
	}
	cfg := &Config{Host: "10.9.9.9", Port: 4566, BaseURL: "http://aws:4566", Hostname: "aws", Token: rigToken, Region: "us-east-1", Disabled: map[string]bool{},
		WorkDir: t.TempDir(), LedgerMax: 500, Planned: map[string]bool{"sns": true, "sqs": true, "iam": true}, PlannedKeys: []string{"sns", "sqs", "iam"}, SNS: sc}
	r.cfg = cfg
	r.srv = newServer(cfg, engine)
	r.ts = newTestServer(t, r.srv)
	t.Cleanup(func() { r.srv.sink.reset() })

	return r
}

// The sink against the REAL engine (AWS Emulator), for the shapes the fake engine only imitates: what Subscribe answers, what the lists say,
// the SNS envelope on the tap queue, the policy the engine needs. Skipped unless ROVARA_REAL_ENGINE_BIN names an engine binary that exists
// (in the aws-emu-spike VM it is /usr/bin/aws-emulator). The engine is the front's own child, on loopback; nothing here leaves the machine.
func TestRealEngineSink(t *testing.T) {
	r := realRig(t, nil)
	topic := r.topic("real")
	code, body := r.subscribe(topic, "http", hookURL(r.hook, "web", "/real"), "FilterPolicy", `{"k":["v"]}`)
	if code != 200 || !strings.Contains(body, "pending confirmation") {
		t.Fatalf("Subscribe: %d %s", code, body)
	}
	r.subscribe(topic, "email", "bob@example.com")
	_, list := r.sns("ListSubscriptionsByTopic", "TopicArn", topic)
	if strings.Count(list, "<SubscriptionArn>PendingConfirmation</SubscriptionArn>") != 2 || strings.Contains(list, snsTapPrefix) || strings.Contains(list, "<Protocol>sqs</Protocol>") {
		t.Fatalf("the list the engine gives, after the sink's rewrite: %s", list)
	}
	r.confirm(r.hook)
	_, list = r.sns("ListSubscriptions")
	if !regexp.MustCompile(`<SubscriptionArn>arn:aws:sns:us-east-1:000000000000:real:[0-9a-f-]{36}</SubscriptionArn>`).MatchString(list) || strings.Contains(list, snsTapPrefix) {
		t.Fatalf("after the confirmation: %s", list)
	}
	attr := func(v string) []string {
		return []string{"MessageAttributes.entry.1.Name", "k", "MessageAttributes.entry.1.Value.DataType", "String", "MessageAttributes.entry.1.Value.StringValue", v}
	}
	r.publish(topic, "filtered out", attr("zzz")...)
	r.publish(topic, "through the engine", append(attr("v"), "Subject", "real subject")...)
	sink_waitFor(t, "the notification", 10*time.Second, func() bool { return len(r.hook.got()) == 2 })
	n := r.hook.got()[1]
	for _, want := range []string{`"Message":"through the engine"`, `"Subject":"real subject"`, `"MessageAttributes":{"k":{"Type":"String","Value":"v"}}`, `"UnsubscribeURL":"http://aws:4566/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:000000000000:real:`} {
		if !strings.Contains(n.Body, want) {
			t.Errorf("the body lacks %s:\n%s", want, n.Body)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if len(r.hook.got()) != 2 {
		t.Errorf("the filter let %d messages through", len(r.hook.got())-1)
	}
	// the email subscription is pending: nothing is mailed until it is confirmed (the confirmation mail itself is the one message)
	sink_waitFor(t, "the confirmation mail", 5*time.Second, func() bool { return len(r.mail.msgs()) == 1 })
	if !strings.Contains(r.mail.msgs()[0], "Subscription Confirmation") {
		t.Errorf("the first mail: %s", r.mail.msgs()[0])
	}
	// the tap queue exists in the engine, and the customer cannot see it
	_, qs := r.do2("POST", "/", map[string]string{"X-Amz-Target": "AmazonSQS.ListQueues", "Content-Type": "application/x-amz-json-1.0",
		"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00"}, "{}")
	if strings.Contains(qs, snsTapPrefix) {
		t.Errorf("ListQueues shows a tap: %s", qs)
	}
	var arn string
	for _, row := range r.subRows() {
		if row["protocol"] == "http" {
			arn = row["subscriptionArn"].(string)
		}
	}
	if code, b := r.sns("Unsubscribe", "SubscriptionArn", arn); code != 200 {
		t.Fatalf("Unsubscribe: %d %s", code, b)
	}
	r.publish(topic, "after the unsubscribe", attr("v")...)
	time.Sleep(500 * time.Millisecond)
	if len(r.hook.got()) != 2 {
		t.Errorf("a message was delivered after the unsubscribe")
	}
	_, list = r.sns("ListSubscriptionsByTopic", "TopicArn", topic)
	if strings.Contains(list, "/real") || strings.Contains(list, snsTapPrefix) {
		t.Errorf("the list after the unsubscribe: %s", list)
	}
}

// ---- the review's findings, against the real engine

func rawSQS(t *testing.T, r *sinkRig, region, op string, body []byte, enc string) (int, string) {
	t.Helper()
	h := map[string]string{"X-Amz-Target": "AmazonSQS." + op, "Content-Type": "application/x-amz-json-1.0",
		"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/" + region + "/sqs/aws4_request, SignedHeaders=host, Signature=00"}
	if enc != "" {
		h["Content-Encoding"] = enc
	}
	code, _, out := r.do("POST", "/", h, string(body))
	return code, out
}

// M1: the real engine gunzips an SQS JSON body, so a gzip DeleteQueue or PurgeQueue of a tap used to work and silently ended every delivery.
func TestRealEngineEncodedBodiesCannotTouchATapAndALostTapIsRebuilt(t *testing.T) {
	r := realRig(t, func(s *SinkConfig) { s.AutoConfirm = true; s.TapVerifyEvery = 200 * time.Millisecond })
	topic := r.topic("real")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	tapURL := sub.tapQueueURL
	for _, op := range []string{"PurgeQueue", "DeleteQueue"} {
		body := []byte(`{"QueueUrl":"` + tapURL + `"}`)
		for name, c := range map[string]struct {
			b   []byte
			enc string
		}{"gzip": {sink_gz(body), "gzip"}, "aws-chunked": {sink_awsChunked(body), "aws-chunked"}} {
			if code, out := rawSQS(t, r, "us-east-1", op, c.b, c.enc); code != 400 || !strings.Contains(out, "QueueDoesNotExist") {
				t.Errorf("%s %s: %d %s", op, name, code, out)
			}
		}
	}
	r.publish(topic, "the tap is intact")
	sink_waitFor(t, "the delivery", 10*time.Second, func() bool { return len(r.hook.got()) == 1 })
	// a tap that is deleted anyway (the engine's own API, as the front: not reachable by the customer) is noticed and rebuilt
	if _, err := r.srv.sink.sqsCall(context.Background(), ambientAs("sqs", "us-east-1"), "DeleteQueue", map[string]interface{}{"QueueUrl": tapURL}); err != nil {
		t.Fatal(err)
	}
	sink_waitFor(t, "the lost tap to be counted", 10*time.Second, func() bool {
		for _, row := range r.subRows() {
			if st, ok := row["stats"].(map[string]interface{}); ok && st["TapLost"].(float64) >= 1 {
				return true
			}
		}
		return false
	})
	sink_waitFor(t, "a delivery through the new tap", 10*time.Second, func() bool {
		r.publish(topic, "after the rebuild")
		time.Sleep(300 * time.Millisecond)
		return len(r.hook.got()) >= 2
	})
}

// M2: another region, and a caller whose policy does not allow Subscribe.
func TestRealEngineRegionsAndIdentity(t *testing.T) {
	r := realRig(t, func(s *SinkConfig) { s.AutoConfirm = true })
	_, body := r.snsAs("eu-west-1", "", "", "CreateTopic", "Name", "eu")
	euTopic := regexp.MustCompile(`<TopicArn>([^<]+)</TopicArn>`).FindStringSubmatch(body)[1]
	if code, out := r.snsAs("eu-west-1", "", "", "Subscribe", "TopicArn", euTopic, "Protocol", "http", "Endpoint", hookURL(r.hook, "web", "/eu")); code != 200 {
		t.Fatalf("Subscribe in eu-west-1: %d %s", code, out)
	}
	r.snsAs("eu-west-1", "", "", "Publish", "TopicArn", euTopic, "Message", "in the other region")
	sink_waitFor(t, "the delivery from eu-west-1", 10*time.Second, func() bool { return len(r.hook.got()) == 1 })
	_, eu := r.snsAs("eu-west-1", "", "", "ListSubscriptionsByTopic", "TopicArn", euTopic)
	if !regexp.MustCompile(`<SubscriptionArn>arn:aws:sns:eu-west-1:000000000000:eu:[0-9a-f-]{36}</SubscriptionArn>`).MatchString(eu) || strings.Contains(eu, snsTapPrefix) {
		t.Errorf("the list in eu-west-1: %s", eu)
	}
	_, us := r.snsAs("us-east-1", "", "", "ListSubscriptions")
	if strings.Contains(us, "eu-west-1") {
		t.Errorf("the list in us-east-1 shows another region: %s", us)
	}
	// an IAM user whose policy allows only ListTopics may not subscribe: the engine's refusal reaches the caller and nothing is attached
	iam := func(action string, kv ...string) string {
		v := url.Values{"Action": {action}, "Version": {"2010-05-08"}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		_, _, out := r.do("POST", "/", map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=00",
			"Content-Type": "application/x-www-form-urlencoded"}, v.Encode())
		return out
	}
	iam("CreateUser", "UserName", "limited")
	key := regexp.MustCompile(`<AccessKeyId>([^<]+)</AccessKeyId>`).FindStringSubmatch(iam("CreateAccessKey", "UserName", "limited"))
	if key == nil {
		t.Fatal("no access key")
	}
	iam("PutUserPolicy", "UserName", "limited", "PolicyName", "p", "PolicyDocument", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:ListTopics","Resource":"*"}]}`)
	before := len(r.subRows())
	code, out := r.snsAs("eu-west-1", key[1], "", "Subscribe", "TopicArn", euTopic, "Protocol", "http", "Endpoint", hookURL(r.hook, "web", "/denied"))
	if code != 403 || !strings.Contains(out, "not authorized") {
		t.Errorf("a restricted identity subscribed: %d %s", code, out)
	}
	if n := len(r.subRows()); n != before {
		t.Errorf("a refused Subscribe left a subscription: %d -> %d", before, n)
	}
	// and one whose policy allows it can, as itself
	iam("CreateUser", "UserName", "allowed")
	key2 := regexp.MustCompile(`<AccessKeyId>([^<]+)</AccessKeyId>`).FindStringSubmatch(iam("CreateAccessKey", "UserName", "allowed"))
	iam("PutUserPolicy", "UserName", "allowed", "PolicyName", "p", "PolicyDocument", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sns:Subscribe","sns:ListSubscriptionsByTopic"],"Resource":"*"}]}`)
	if code, out := r.snsAs("eu-west-1", key2[1], "", "Subscribe", "TopicArn", euTopic, "Protocol", "http", "Endpoint", hookURL(r.hook, "web", "/allowed")); code != 200 {
		t.Errorf("an allowed identity: %d %s", code, out)
	}
}

// L2: a batch of large messages is more than one ReceiveMessage answer may hold.
func TestRealEngineLargeMessagesAreNotLost(t *testing.T) {
	r := realRig(t, func(s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("real")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/big"))
	big := strings.Repeat(`"`, 150000) // each quote is escaped twice on the way, 600 KB a message in the receive answer
	// the tap is held still (its loop takes the sink's lock to read its queue) while twelve are published, so that the next poll finds a batch
	r.srv.sink.mu.Lock()
	for i := 0; i < 12; i++ {
		r.publish(topic, big)
	}
	r.srv.sink.mu.Unlock()
	sink_waitFor(t, "all twelve", 30*time.Second, func() bool { return len(r.hook.got()) == 12 })
}

// L4: the engine counts the taps in the topic's subscriptions; the sink does not.
func TestRealEngineTopicCounts(t *testing.T) {
	r := realRig(t, func(s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("real")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/a"))
	r.subscribe(topic, "email", "a@example.com")
	_, b := r.sns("GetTopicAttributes", "TopicArn", topic)
	for k, want := range map[string]string{"SubscriptionsConfirmed": "2", "SubscriptionsPending": "0"} {
		if m := regexp.MustCompile(`<key>` + k + `</key><value>([0-9]+)</value>`).FindStringSubmatch(b); m == nil || m[1] != want {
			t.Errorf("%s: %v (want %s)", k, m, want)
		}
	}
}
