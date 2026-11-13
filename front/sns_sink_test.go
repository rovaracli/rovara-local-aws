package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func hookURL(h *hook, host, path string) string {
	return fmt.Sprintf("http://%s:%d%s", host, h.port(), path)
}

func TestSubscribeConfirmDeliverNotification(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.ServeCert = true })
	topic := r.topic("orders")
	code, body := r.subscribe(topic, "http", hookURL(r.hook, "localhost", "/sns?x=1"))
	if code != 200 || !strings.Contains(body, "<SubscriptionArn>pending confirmation</SubscriptionArn>") {
		t.Fatalf("Subscribe: %d %s", code, body)
	}
	// a Publish before the confirmation is dropped, as on AWS
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
	// the confirmation request is what AWS posts
	conf := r.hook.got()[0]
	if conf.Method != "POST" || conf.URI != "/sns?x=1" || conf.Header.Get("x-amz-sns-message-type") != "SubscriptionConfirmation" ||
		conf.Header.Get("x-amz-sns-topic-arn") != topic || conf.Header.Get("Content-Type") != "text/plain; charset=UTF-8" || conf.Host != fmt.Sprintf("localhost:%d", r.hook.port()) {
		t.Errorf("confirmation request: %+v", conf)
	}
	r.publish(topic, "hello <world> & more", "Subject", "greeting", "MessageAttributes.entry.1.Name", "k", "MessageAttributes.entry.1.Value.DataType", "String", "MessageAttributes.entry.1.Value.StringValue", "v")
	sink_waitFor(t, "the notification", 3*time.Second, func() bool { return len(r.hook.got()) == 2 })
	n := r.hook.got()[1]
	if n.Header.Get("x-amz-sns-message-type") != "Notification" || n.Header.Get("x-amz-sns-subscription-arn") != sub.arn || n.Header.Get("x-amz-sns-topic-arn") != topic ||
		n.Header.Get("User-Agent") != "Amazon Simple Notification Service Agent" || n.Header.Get("x-amz-sns-message-id") == "" {
		t.Errorf("notification headers: %v", n.Header)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(n.Body), &doc); err != nil {
		t.Fatalf("body: %v\n%s", err, n.Body)
	}
	for k, want := range map[string]string{"Type": "Notification", "TopicArn": topic, "Message": "hello <world> & more", "Subject": "greeting", "SignatureVersion": "2"} {
		if doc[k] != want {
			t.Errorf("%s = %v, want %v", k, doc[k], want)
		}
	}
	if !strings.HasPrefix(doc["UnsubscribeURL"].(string), "http://aws:4566/?Action=Unsubscribe&SubscriptionArn=") || !strings.HasSuffix(doc["UnsubscribeURL"].(string), sub.arn) {
		t.Errorf("UnsubscribeURL: %v", doc["UnsubscribeURL"])
	}
	if strings.Contains(n.Body, ":"+snsTapPrefix) {
		t.Errorf("the tap's subscription arn leaked: %s", n.Body)
	}
	attrs := doc["MessageAttributes"].(map[string]interface{})["k"].(map[string]interface{})
	if attrs["Type"] != "String" || attrs["Value"] != "v" {
		t.Errorf("attributes: %v", attrs)
	}
	// the signature verifies against the certificate the run serves (opt-in), and a tampered message does not
	certURL := doc["SigningCertURL"].(string)
	if !regexp.MustCompile(`^http://aws:4566/SimpleNotificationService-[0-9a-f]{16}\.pem$`).MatchString(certURL) {
		t.Fatalf("SigningCertURL: %s", certURL)
	}
	_, _, certPEM := r.do("GET", strings.TrimPrefix(certURL, "http://aws:4566"), nil, "")
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatalf("the signing certificate is not served: %q", certPEM)
	}
	cert, _ := x509.ParseCertificate(blk.Bytes)
	verify := func(msg string) bool {
		toSign := "Message\n" + msg + "\nMessageId\n" + doc["MessageId"].(string) + "\nSubject\ngreeting\nTimestamp\n" + doc["Timestamp"].(string) + "\nTopicArn\n" + topic + "\nType\nNotification\n"
		sig, _ := base64.StdEncoding.DecodeString(doc["Signature"].(string))
		sum := sha256.Sum256([]byte(toSign))
		return rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], sig) == nil
	}
	if !verify("hello <world> & more") {
		t.Error("the signature does not verify against the served certificate")
	}
	if verify("hello <world> & more!") {
		t.Error("a tampered message verified")
	}
	// the tap is attached with the policy the engine needs
	if !strings.Contains(strings.Join(r.aws.callLog(), " "), "sqs:SetQueueAttributes") {
		t.Error("no queue policy was set")
	}
	// the control read shows what happened
	got := r.attempts(sub.arn)
	delivered := 0
	for _, a := range got {
		if a.Outcome == "delivered" {
			delivered++
		}
	}
	if delivered != 2 { // the confirmation and the notification
		t.Errorf("delivered = %d: %+v", delivered, got)
	}
}

func TestSigningCertIsNotServedByDefault(t *testing.T) {
	r := newSinkRig(t, nil)
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	r.confirm(r.hook)
	var doc map[string]interface{}
	sink_waitFor(t, "a message", time.Second, func() bool { return len(r.hook.got()) > 0 })
	r.publish(topic, "m")
	sink_waitFor(t, "the notification", 3*time.Second, func() bool { return len(r.hook.got()) == 2 })
	json.Unmarshal([]byte(r.hook.got()[1].Body), &doc)
	certURL := doc["SigningCertURL"].(string)
	code, _, body := r.do("GET", strings.TrimPrefix(certURL, "http://aws:4566"), nil, "")
	if code == 200 || strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Errorf("the certificate is served without the opt-in: %d", code)
	}
}

func TestAutoConfirmDeliversAtOnceWithoutAConfirmationMessage(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	code, body := r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	if code != 200 || !strings.Contains(body, "arn:aws:sns:us-east-1:000000000000:t:") {
		t.Fatalf("auto-confirmed Subscribe should answer the arn: %d %s", code, body)
	}
	r.publish(topic, "now")
	sink_waitFor(t, "the notification", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	if r.hook.got()[0].Header.Get("x-amz-sns-message-type") != "Notification" {
		t.Errorf("first message: %v", r.hook.got()[0].Header)
	}
}

func TestRawDelivery(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"), "RawMessageDelivery", "true")
	r.publish(topic, `{"a":1}`)
	sink_waitFor(t, "the notification", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	n := r.hook.got()[0]
	if n.Body != `{"a":1}` || n.Header.Get("x-amz-sns-rawdelivery") != "true" || n.Header.Get("x-amz-sns-message-type") != "Notification" {
		t.Errorf("raw delivery: %q %v", n.Body, n.Header)
	}
}

func TestFilterPolicyIsCopiedToTheTapAndFollowsSetSubscriptionAttributes(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"), "FilterPolicy", `{"k":["v"]}`)
	attr := func(v string) []string {
		return []string{"MessageAttributes.entry.1.Name", "k", "MessageAttributes.entry.1.Value.DataType", "String", "MessageAttributes.entry.1.Value.StringValue", v}
	}
	r.publish(topic, "no", attr("other")...)
	r.publish(topic, "yes", attr("v")...)
	sink_waitFor(t, "one delivery", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	time.Sleep(200 * time.Millisecond)
	if n := len(r.hook.got()); n != 1 || !strings.Contains(r.hook.got()[0].Body, `"Message":"yes"`) {
		t.Fatalf("filter: %d deliveries %v", n, r.hook.got())
	}
	// change the policy through the API: the tap follows
	sub := r.onlySub()
	if code, body := r.sns("SetSubscriptionAttributes", "SubscriptionArn", sub.arn, "AttributeName", "FilterPolicy", "AttributeValue", `{"k":["other"]}`); code != 200 {
		t.Fatalf("SetSubscriptionAttributes: %d %s", code, body)
	}
	r.publish(topic, "now-other", attr("other")...)
	sink_waitFor(t, "the second delivery", 3*time.Second, func() bool { return len(r.hook.got()) == 2 })
	if !strings.Contains(r.hook.got()[1].Body, `"Message":"now-other"`) {
		t.Errorf("after the change: %v", r.hook.got()[1].Body)
	}
	_, body := r.sns("GetSubscriptionAttributes", "SubscriptionArn", sub.arn)
	if !strings.Contains(body, "<key>FilterPolicy</key><value>{&quot;k&quot;:[&quot;other&quot;]}</value>") || !strings.Contains(body, "<key>PendingConfirmation</key><value>false</value>") {
		t.Errorf("GetSubscriptionAttributes: %s", body)
	}
}

func TestRetriesAreCompressedAndLimited(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.hook.statuses = []int{500, 503}
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	r.publish(topic, "retry me")
	sub := r.onlySub()
	sink_waitFor(t, "the third attempt to succeed", 3*time.Second, func() bool { return len(r.hook.got()) == 3 })
	sink_waitFor(t, "the record", 3*time.Second, func() bool { return len(r.attempts(sub.arn)) == 3 })
	a := r.attempts(sub.arn)
	if a[0].Outcome != "retrying" || a[1].Outcome != "retrying" || a[2].Outcome != "delivered" || a[0].Status != 500 {
		t.Errorf("attempts: %+v", a)
	}
	// a delivery policy limits the retries; an endpoint that always fails ends "failed"
	r2 := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic2 := r2.topic("t")
	r2.hook.def = 500
	r2.subscribe(topic2, "http", hookURL(r2.hook, "web", "/h"), "DeliveryPolicy", `{"healthyRetryPolicy":{"numRetries":1}}`)
	r2.publish(topic2, "x")
	sub2 := r2.onlySub()
	sink_waitFor(t, "the failure", 3*time.Second, func() bool {
		a := r2.attempts(sub2.arn)
		return len(a) == 2 && a[1].Outcome == "failed"
	})
	if n := len(r2.hook.got()); n != 2 {
		t.Errorf("a policy of one retry made %d attempts", n)
	}
}

func TestA4xxAnswerIsNotRetriedAndARedirectIsNotFollowed(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.hook.def = 404
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	r.publish(topic, "x")
	sub := r.onlySub()
	sink_waitFor(t, "the answer", 3*time.Second, func() bool { return len(r.attempts(sub.arn)) == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := len(r.hook.got()); n != 1 {
		t.Errorf("a 404 was retried: %d requests", n)
	}
	a := r.attempts(sub.arn)[0]
	if a.Outcome != "delivered" || a.Status != 404 || !strings.Contains(a.Error, "SNS counts 200-499") {
		t.Errorf("attempt: %+v", a)
	}
}

func TestListsShowTheRealStateAndHideTheTaps(t *testing.T) {
	r := newSinkRig(t, nil)
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/one"))
	r.subscribe(topic, "email", "a@example.com")
	r.subscribe(topic, "https", "https://hooks.example.com/x")
	_, body := r.sns("ListSubscriptionsByTopic", "TopicArn", topic)
	if strings.Count(body, "<SubscriptionArn>PendingConfirmation</SubscriptionArn>") != 3 || strings.Contains(body, snsTapPrefix) || strings.Contains(body, "<Protocol>sqs</Protocol>") {
		t.Fatalf("pending list: %s", body)
	}
	r.confirm(r.hook)
	_, body = r.sns("ListSubscriptions")
	if strings.Count(body, "<SubscriptionArn>PendingConfirmation</SubscriptionArn>") != 2 || !regexp.MustCompile(`<SubscriptionArn>arn:aws:sns:us-east-1:000000000000:t:[0-9a-f-]{36}</SubscriptionArn>`).MatchString(body) {
		t.Fatalf("after one confirm: %s", body)
	}
	// unsubscribing hides the engine's stale entry
	var arn string
	for _, row := range r.subRows() {
		if row["protocol"] == "http" {
			arn = row["subscriptionArn"].(string)
		}
	}
	r.srv.sink.mu.Lock()
	ended := r.srv.sink.subs[arn]
	r.srv.sink.mu.Unlock()
	if code, b := r.sns("Unsubscribe", "SubscriptionArn", arn); code != 200 {
		t.Fatalf("Unsubscribe: %d %s", code, b)
	}
	if ended == nil || ended.ctx.Err() == nil {
		t.Error("the unsubscribed subscription's goroutines were not stopped")
	}
	_, body = r.sns("ListSubscriptionsByTopic", "TopicArn", topic)
	if strings.Contains(body, "/one") || strings.Count(body, "<member") != 2 {
		t.Errorf("after unsubscribe: %s", body)
	}
	if code, body := r.sns("GetSubscriptionAttributes", "SubscriptionArn", arn); code == 200 && strings.Contains(body, "Endpoint") {
		t.Errorf("an unsubscribed subscription still has attributes: %s", body)
	}
	// subscribing the same endpoint again brings it back, with a new arn
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/one"))
	_, body = r.sns("ListSubscriptionsByTopic", "TopicArn", topic)
	if !strings.Contains(body, "/one") {
		t.Errorf("re-subscribed entry missing: %s", body)
	}
}

func TestUnsubscribeQueueIsCleanedAndDeleteTopicEndsSubscriptions(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	if n := len(r.aws.queueNames()); n != 1 {
		t.Fatalf("tap queues: %v", r.aws.queueNames())
	}
	if code, b := r.sns("DeleteTopic", "TopicArn", topic); code != 200 {
		t.Fatalf("DeleteTopic: %d %s", code, b)
	}
	sink_waitFor(t, "the subscription to end", 3*time.Second, func() bool { return len(r.subRows()) == 0 })
	sink_waitFor(t, "the tap queue to go", 3*time.Second, func() bool { return len(r.aws.queueNames()) == 0 })
}

func TestEmailGoesToTheMailCatcher(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "email", "alice@example.com")
	r.publish(topic, "Dear Alice,\n.\nthis line is a dot above", "Subject", "Order shipped")
	sink_waitFor(t, "the mail", 3*time.Second, func() bool { return len(r.mail.msgs()) == 1 })
	m := r.mail.msgs()[0]
	for _, want := range []string{"To: alice@example.com\r\n", "From: no-reply@sns.amazonaws.com\r\n", "Subject: Order shipped\r\n", "Dear Alice,\r\n", "this line is a dot above", "Action=Unsubscribe"} {
		if !strings.Contains(m, want) {
			t.Errorf("the message lacks %q:\n%s", want, m)
		}
	}
	tr := strings.Join(r.mail.lines(), "|")
	if !strings.Contains(tr, "RCPT TO:<alice@example.com>") || !strings.Contains(tr, "MAIL FROM:<no-reply@sns.amazonaws.com>") {
		t.Errorf("transcript: %s", tr)
	}
	// email-json carries the JSON body
	r2 := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic2 := r2.topic("t")
	r2.subscribe(topic2, "email-json", "bob@example.com")
	r2.publish(topic2, "json please")
	sink_waitFor(t, "the mail", 3*time.Second, func() bool { return len(r2.mail.msgs()) == 1 })
	if !strings.Contains(r2.mail.msgs()[0], `"Type":"Notification"`) || !strings.Contains(r2.mail.msgs()[0], `"Message":"json please"`) {
		t.Errorf("email-json: %s", r2.mail.msgs()[0])
	}
}

func TestEmailWithoutAMailCatcherIsHeldInTheCaptureOnly(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true; s.SMTP = "" })
	topic := r.topic("t")
	r.subscribe(topic, "email", "alice@example.com")
	r.publish(topic, "kept here")
	sub := r.onlySub()
	sink_waitFor(t, "the capture", 3*time.Second, func() bool { return len(r.attempts(sub.arn)) == 1 })
	a := r.attempts(sub.arn)[0]
	if a.Outcome != "held" || !strings.Contains(a.Body, "kept here") || !strings.Contains(a.Error, "no mail catcher") {
		t.Errorf("attempt: %+v", a)
	}
	if strings.Contains(a.Target, "alice") {
		t.Errorf("the capture shows the mailbox: %s", a.Target)
	}
}

func TestNoHTTPSinkRecordsTheDeliveryOnly(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true; s.SinkIP = nil })
	topic := r.topic("t")
	r.subscribe(topic, "http", "http://hooks.example.com/x")
	r.publish(topic, "m")
	sub := r.onlySub()
	sink_waitFor(t, "the record", 3*time.Second, func() bool { return len(r.attempts(sub.arn)) == 1 })
	if a := r.attempts(sub.arn)[0]; a.Outcome != "held" || !strings.Contains(a.Error, "no HTTP sink") {
		t.Errorf("attempt: %+v", a)
	}
	if n := len(r.sink.got()) + len(r.hook.got()); n != 0 {
		t.Errorf("something was sent: %d", n)
	}
}

func TestSinkBoundDeliveryGoesToTheSinkWithTheEndpointsHost(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", "http://user:pw@hooks.example.com:8443/path/x?token=secret&b=2")
	r.publish(topic, "to the sink")
	sink_waitFor(t, "the sink to be called", 3*time.Second, func() bool { return len(r.sink.got()) == 1 })
	g := r.sink.got()[0]
	if g.Host != "hooks.example.com:8443" || g.URI != "/path/x?token=secret&b=2" || !strings.HasPrefix(g.Header.Get("Authorization"), "Basic ") {
		t.Errorf("sink request: %+v", g)
	}
	sub := r.onlySub()
	leaks := func(text string) bool {
		return strings.Contains(text, "secret") || strings.Contains(text, "user:pw") || strings.Contains(text, "//user@") || strings.Contains(text, "token=s")
	}
	for _, row := range r.subRows() {
		if leaks(fmt.Sprint(row)) {
			t.Errorf("the subscription list shows a secret: %v", row)
		}
	}
	_, all := r.control("/_rovara/sns/deliveries?subscription=" + url.QueryEscape(sub.arn))
	_, sum := r.control("/_rovara/sns/summary")
	if leaks(all + sum) {
		t.Errorf("the capture shows a secret: %s %s", all, sum)
	}
}

func TestResetEndsTheSinkAndSeedAdoptsSubscriptions(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	if len(r.subRows()) != 1 {
		t.Fatal("no subscription")
	}
	before := r.onlySub()
	r.srv.sink.reset()
	if len(r.subRows()) != 0 {
		t.Error("a reset left subscriptions")
	}
	if before.ctx.Err() == nil {
		t.Error("a reset left the subscription's goroutines running")
	}
	// a subscription made inside the engine (CloudFormation, a seed) is adopted before the next Publish
	r.aws.mu.Lock()
	r.aws.subs = []*fakeSub{} // the engine's state went with the reset
	r.aws.subs = append(r.aws.subs, &fakeSub{topic: topic, protocol: "http", endpoint: hookURL(r.hook, "web", "/cfn"), attrs: map[string]string{}})
	r.aws.mu.Unlock()
	r.srv.sink.mayHaveUnseen.Store(true)
	r.publish(topic, "after the stack")
	sink_waitFor(t, "an adopted subscription", 3*time.Second, func() bool { return len(r.subRows()) == 1 })
	if r.subRows()[0]["state"] != "confirmed" {
		t.Errorf("adopted state: %v", r.subRows()[0])
	}
}

func TestControlReadsNeedTheTokenAndOneSubscription(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	for _, p := range []string{"/_rovara/sns/subscriptions", "/_rovara/sns/deliveries?subscription=x", "/_rovara/sns/summary"} {
		if code, _, _ := r.do("GET", p, nil, ""); code != 403 {
			t.Errorf("%s without the token: %d", p, code)
		}
	}
	if code, _ := r.control("/_rovara/sns/deliveries"); code != 400 {
		t.Errorf("deliveries without a subscription: %d", code)
	}
}

// SNS decides at Publish; the front's own clock (when it took the message off the tap) stands in for that, and the envelope's timestamp
// decides nothing.
func TestAMessageTakenOffTheTapBeforeConfirmationIsDroppedWhenevertheFrontGetsToIt(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	before := time.Now().Add(-time.Hour)
	after := time.Now().Add(time.Second)
	// the envelope's own timestamp is old for both: it is not looked at
	r.srv.sink.process(sub, &snsDelivery{kind: "Notification", messageID: "old", message: "old", timestamp: "2001-01-01T00:00:00Z", received: before})
	r.srv.sink.process(sub, &snsDelivery{kind: "Notification", messageID: "new", message: "new", timestamp: "2001-01-01T00:00:00Z", received: after})
	if got := r.hook.got(); len(got) != 1 || !strings.Contains(got[0].Body, `"Message":"new"`) {
		t.Errorf("deliveries: %v", got)
	}
	a := r.attempts(sub.arn)
	if len(a) != 2 || a[0].Outcome != "dropped" || !strings.Contains(a[0].Error, "before the subscription was confirmed") {
		t.Errorf("attempts: %+v", a)
	}
}
