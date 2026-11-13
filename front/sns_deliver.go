package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/smtp"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Delivery: what the front sends for a subscription it owns (sns_sink.go), and what it keeps of it.
//
//   - HTTP(S): POST, in the shape AWS sends (x-amz-sns-* headers, AWS's JSON body, or the raw message for a raw subscription). A 2xx, 3xx or 4xx
//     answer ends the delivery (SNS counts 200-499 as delivered; a redirect is NOT followed); a 5xx, a refused or timed-out connection is
//     retried. Retries are COMPRESSED (the nth retry waits n times ROVARA_AWS_SNS_RETRY_DELAY_MS, 200 ms by default; AWS's own default is
//     20 s apart) and limited (the subscription's delivery policy numRetries, at most 5, default 3).
//   - email and email-json: one message to the mail catcher over SMTP (never to the internet). The recipient is a plain mailbox (judged at
//     Subscribe), the subject has no control character, and the headers are the front's own.
//   - SIGNATURE: SignatureVersion 2 (SHA-256) over AWS's string-to-sign, with a per-run RSA key made in the front's memory. The key does not
//     verify against anything AWS: SigningCertURL has an AWS-looking host and is NOT served unless ROVARA_AWS_SNS_SERVE_SIGNING_CERT=1, so a
//     verifier that fetches it fails honestly. The evidence says "signature not verified (faked)".
//   - Caps: 100 deliveries held per subscription, 32 MiB held in all, a message over 512 KiB dropped, an answer read for at most 4 KiB, an
//     attempt at most 15 s. Everything over a cap is counted ("dropped") and never silent.

// snsDefaultAttemptTimeout bounds one attempt (SinkConfig.AttemptTimeout; AWS's own is 15 s).
const snsDefaultAttemptTimeout = 15 * time.Second

const (
	snsRingSize     = 50
	snsPreviewBytes = 8 << 10
	snsAnswerRead   = 4 << 10
)

type snsStats struct {
	Delivered, Failed, Dropped, Held, Attempts int64
	// TapLost counts the times the sub's tap was found gone or broken (and rebuilt)
	TapLost int64
}

// snsAttempt is one line of the capture: one attempt to deliver, or one delivery dropped before any attempt.
type snsAttempt struct {
	Seq          int64  `json:"seq"`
	At           int64  `json:"at"`
	Subscription string `json:"subscription"`
	Protocol     string `json:"protocol"`
	Kind         string `json:"kind"`
	MessageID    string `json:"messageId,omitempty"`
	Attempt      int    `json:"attempt"`
	Outcome      string `json:"outcome"` // delivered, retrying, failed, dropped, held
	Status       int    `json:"status,omitempty"`
	Target       string `json:"target"`
	Error        string `json:"error,omitempty"`
	BodyBytes    int    `json:"bodyBytes"`
	Body         string `json:"body,omitempty"`
}

func (k *snsSink) record(sub *snsSub, a snsAttempt) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seq++
	a.Seq, a.At = k.seq, time.Now().UnixMilli()
	a.Subscription, a.Protocol = sub.arn, sub.protocol
	if sub.target != nil {
		a.Target = sub.target.Display
	} else {
		a.Target = "mailto:" + hostOfEmail(sub.email)
	}
	if len(a.Body) > snsPreviewBytes {
		a.Body = a.Body[:snsPreviewBytes]
	}
	if len(sub.ring) >= snsRingSize {
		sub.ring = append(sub.ring[:0], sub.ring[1:]...)
	}
	sub.ring = append(sub.ring, a)
}

func hostOfEmail(a string) string {
	if i := strings.LastIndex(a, "@"); i >= 0 {
		return "***@" + a[i+1:]
	}
	return "***"
}

func (k *snsSink) recordDrop(sub *snsSub, kind, id, reason string) {
	k.mu.Lock()
	sub.stats.Dropped++
	k.mu.Unlock()
	k.record(sub, snsAttempt{Kind: kind, MessageID: id, Outcome: "dropped", Error: reason})
}

// ---- the per-subscription goroutine

func (k *snsSink) next(sub *snsSub) *snsDelivery {
	for {
		k.mu.Lock()
		if len(sub.queue) > 0 {
			d := sub.queue[0]
			sub.queue = sub.queue[1:]
			sub.queueBytes -= d.size
			k.pending -= d.size
			k.mu.Unlock()
			return d
		}
		k.mu.Unlock()
		select {
		case <-sub.ctx.Done():
			return nil
		case <-sub.wake:
		}
	}
}

func (k *snsSink) deliverLoop(sub *snsSub) {
	for {
		d := k.next(sub)
		if d == nil {
			return
		}
		k.process(sub, d)
	}
}

func (k *snsSink) process(sub *snsSub, d *snsDelivery) {
	k.mu.Lock()
	state, raw, retries, confirmedAt := sub.state, sub.raw, sub.retries, sub.confirmedAt
	k.mu.Unlock()
	if d.kind == "Notification" {
		// SNS decides at Publish; the front can only know when it took the message off the tap, and uses its own clock for that (the
		// envelope's own timestamp is the sender's and decides nothing).
		switch {
		case state != subConfirmed:
			k.recordDrop(sub, d.kind, d.messageID, "the subscription is not confirmed (SNS drops these too)")
			return
		case d.received.Before(confirmedAt):
			k.recordDrop(sub, d.kind, d.messageID, "published before the subscription was confirmed (SNS drops these too)")
			return
		}
	}
	switch sub.protocol {
	case "http", "https":
		k.deliverHTTP(sub, d, raw, retries)
	default:
		k.deliverEmail(sub, d, retries)
	}
}

// finish updates the counters after the last attempt.
func (k *snsSink) finish(sub *snsSub, outcome string) {
	k.mu.Lock()
	switch outcome {
	case "delivered":
		sub.stats.Delivered++
	case "held":
		sub.stats.Held++
	default:
		sub.stats.Failed++
	}
	k.mu.Unlock()
}

// wait sleeps before the nth retry (compressed), unless the subscription ends first.
func (k *snsSink) wait(sub *snsSub, n int) bool {
	select {
	case <-sub.ctx.Done():
		return false
	case <-time.After(time.Duration(n) * k.cfg.RetryBase):
		return true
	}
}

// ---- HTTP(S)

func (k *snsSink) deliverHTTP(sub *snsSub, d *snsDelivery, raw bool, retries int) {
	t := sub.target
	if t.Dial.addr == "" {
		k.mu.Lock()
		sub.stats.Held++
		k.mu.Unlock()
		k.record(sub, snsAttempt{Kind: d.kind, MessageID: d.messageID, Attempt: 1, Outcome: "held",
			Error: "this run has no HTTP sink: nothing was sent, the delivery is only recorded"})
		return
	}
	body, header := k.httpMessage(sub, d, raw)
	for i := 1; i <= 1+retries; i++ {
		status, err := k.postOnce(sub, t, body, header)
		k.mu.Lock()
		sub.stats.Attempts++
		k.mu.Unlock()
		ok := err == nil && status >= 200 && status < 500
		outcome, last := "delivered", i == 1+retries
		switch {
		case !ok && last:
			outcome = "failed"
		case !ok:
			outcome = "retrying"
		}
		a := snsAttempt{Kind: d.kind, MessageID: d.messageID, Attempt: i, Outcome: outcome, Status: status, BodyBytes: len(body), Body: string(body)}
		if err != nil {
			a.Error = err.Error()
		} else if status >= 300 {
			a.Error = fmt.Sprintf("the endpoint answered %d (SNS counts 200-499 as delivered; a redirect is not followed)", status)
		}
		if !ok {
			a.Error = shortError(a.Error, status)
		}
		k.record(sub, a)
		if ok {
			k.finish(sub, "delivered")
			return
		}
		if last || !k.wait(sub, i) {
			k.finish(sub, "failed")
			return
		}
	}
}

func shortError(e string, status int) string {
	if e == "" && status >= 500 {
		return "the endpoint answered " + strconv.Itoa(status)
	}
	return e
}

func (k *snsSink) postOnce(sub *snsSub, t *endpointTarget, body []byte, header http.Header) (int, error) {
	hostport := t.Host
	if (t.Scheme == "http" && t.Port != 80) || (t.Scheme == "https" && t.Port != 443) {
		hostport = t.Host + ":" + strconv.Itoa(t.Port)
	}
	ctx, cancel := context.WithTimeout(withTarget(sub.ctx, t.Dial), k.cfg.AttemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Scheme+"://"+hostport+t.RequestURI, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("the request could not be made")
	}
	req.Host = hostport
	req.Header = header.Clone()
	if t.HasUser {
		req.SetBasicAuth(t.User, t.Pass)
	}
	resp, err := k.net.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s", cleanTransportError(err))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, snsAnswerRead))
	return resp.StatusCode, nil
}

var urlInError = regexp.MustCompile(`https?://\S+`)

// cleanTransportError keeps the failure kind and drops the URL (it can carry user-info and query secrets) and anything long.
func cleanTransportError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "\n"); i >= 0 {
		msg = msg[:i]
	}
	msg = urlInError.ReplaceAllString(msg, "<endpoint>")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// ---- the message (AWS's shape)

func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimRight(b.String(), "\n")
}

// httpMessage makes the request body and the headers of one delivery. Every header value is a constant or a value the front checked
// (an id, an ARN it made); nothing of the caller's request is copied.
func (k *snsSink) httpMessage(sub *snsSub, d *snsDelivery, raw bool) ([]byte, http.Header) {
	h := http.Header{}
	h.Set("Content-Type", "text/plain; charset=UTF-8")
	h.Set("User-Agent", "Amazon Simple Notification Service Agent")
	h.Set("x-amz-sns-message-type", d.kind)
	h.Set("x-amz-sns-message-id", d.messageID)
	h.Set("x-amz-sns-topic-arn", sub.topicArn)
	if d.kind == "Notification" {
		h.Set("x-amz-sns-subscription-arn", sub.arn)
		if raw {
			h.Set("x-amz-sns-rawdelivery", "true")
			return []byte(d.message), h
		}
	}
	return k.jsonBody(sub, d), h
}

// jsonBody is the JSON AWS posts, with the run-key signature.
func (k *snsSink) jsonBody(sub *snsSub, d *snsDelivery) []byte {
	sg := k.getSigner()
	certURL := k.publicBase(sub.region) + "/SimpleNotificationService-" + k.runID + ".pem"
	var b strings.Builder
	var toSign strings.Builder
	field := func(name, value string) { toSign.WriteString(name + "\n" + value + "\n") }
	kv := func(name, value string) { b.WriteString(jsonString(name) + ":" + jsonString(value) + ",") }
	b.WriteString("{")
	kv("Type", d.kind)
	kv("MessageId", d.messageID)
	if d.kind == "SubscriptionConfirmation" {
		kv("Token", sub.token)
	}
	kv("TopicArn", sub.topicArn)
	if d.hasSubject {
		kv("Subject", d.subject)
	}
	kv("Message", d.message)
	if d.kind == "SubscriptionConfirmation" {
		kv("SubscribeURL", k.subscribeURL(sub))
	}
	kv("Timestamp", d.timestamp)
	// the string AWS signs: the fields in name order, each as name, newline, value, newline
	field("Message", d.message)
	field("MessageId", d.messageID)
	if d.kind == "SubscriptionConfirmation" {
		field("SubscribeURL", k.subscribeURL(sub))
	} else if d.hasSubject {
		field("Subject", d.subject)
	}
	field("Timestamp", d.timestamp)
	if d.kind == "SubscriptionConfirmation" {
		field("Token", sub.token)
	}
	field("TopicArn", sub.topicArn)
	field("Type", d.kind)
	kv("SignatureVersion", "2")
	kv("Signature", sg.sign(toSign.String()))
	kv("SigningCertURL", certURL)
	if d.kind == "Notification" {
		kv("UnsubscribeURL", k.unsubscribeURL(sub))
		if len(d.attrs) > 0 && d.attrs[0] == '{' && json.Valid(d.attrs) {
			b.WriteString(`"MessageAttributes":` + string(d.attrs) + ",")
		}
	}
	out := strings.TrimSuffix(b.String(), ",") + "}"
	return []byte(out)
}

// ---- the signing key

type snsSigner struct {
	once    sync.Once
	key     *rsa.PrivateKey
	certPEM []byte
}

func (k *snsSink) getSigner() *snsSigner {
	k.mu.Lock()
	if k.signer == nil {
		k.signer = &snsSigner{}
	}
	sg := k.signer
	k.mu.Unlock()
	sg.once.Do(func() {
		sg.key, _ = rsa.GenerateKey(rand.Reader, 2048)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Rovara test run SNS signing key (faked, not AWS)"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if sg.key != nil {
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &sg.key.PublicKey, sg.key)
			if err == nil {
				sg.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			}
		}
	})
	return sg
}

func (sg *snsSigner) sign(s string) string {
	if sg.key == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	sig, err := rsa.SignPKCS1v15(rand.Reader, sg.key, crypto.SHA256, sum[:])
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(sig)
}

var signingCertPath = regexp.MustCompile(`^/SimpleNotificationService-([0-9a-f]{16})\.pem$`)

// serveSigningCert answers GET /SimpleNotificationService-<run id>.pem when the opt-in is on, and only then.
func (k *snsSink) serveSigningCert(w http.ResponseWriter, r *http.Request) bool {
	if !k.cfg.ServeCert || r.Method != http.MethodGet {
		return false
	}
	m := signingCertPath.FindStringSubmatch(r.URL.Path)
	if m == nil || m[1] != k.runID {
		return false
	}
	sg := k.getSigner()
	if sg.certPEM == nil {
		return false
	}
	writeBody(w, 200, "application/x-pem-file", sg.certPEM)
	return true
}

// ---- email

var subjectBad = regexp.MustCompile(`[\x00-\x1f\x7f]+`)

func cleanSubject(s string) string {
	s = strings.TrimSpace(subjectBad.ReplaceAllString(s, " "))
	if len(s) > 100 {
		s = strings.ToValidUTF8(s[:100], "")
	}
	if s == "" {
		return "AWS Notification Message"
	}
	return s
}

const mailFrom = "no-reply@sns.amazonaws.com"

// emailMessage makes the whole RFC 5322 message of one email delivery.
func (k *snsSink) emailMessage(sub *snsSub, d *snsDelivery) string {
	var subject, text string
	switch {
	case d.kind == "SubscriptionConfirmation":
		subject = "AWS Notification - Subscription Confirmation"
		text = "You have chosen to subscribe to the topic:\n" + sub.topicArn + "\n\nTo confirm this subscription, click or visit the link below (If this was in error no action is necessary):\n" +
			k.subscribeURL(sub) + "\n\nPlease do not reply directly to this email.\n"
	case sub.protocol == "email-json":
		subject = cleanSubject(d.subject)
		text = string(k.jsonBody(sub, d))
	default:
		subject = cleanSubject(d.subject)
		text = d.message + "\n\n--\nIf you wish to stop receiving notifications from this topic, please click or visit the link below to unsubscribe:\n" +
			k.unsubscribeURL(sub) + "\n\nPlease do not reply directly to this email.\n"
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	var b strings.Builder
	b.WriteString("From: " + mailFrom + "\n")
	b.WriteString("To: " + sub.email + "\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\n")
	b.WriteString("Message-ID: <" + d.messageID + "@sns.amazonaws.com>\n")
	b.WriteString("MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n")
	b.WriteString(text)
	return b.String()
}

func (k *snsSink) deliverEmail(sub *snsSub, d *snsDelivery, retries int) {
	msg := k.emailMessage(sub, d)
	if k.cfg.SMTP == "" {
		k.mu.Lock()
		sub.stats.Held++
		k.mu.Unlock()
		k.record(sub, snsAttempt{Kind: d.kind, MessageID: d.messageID, Attempt: 1, Outcome: "held", BodyBytes: len(msg), Body: msg,
			Error: "this run has no mail catcher: the message is kept in this capture only"})
		return
	}
	for i := 1; i <= 1+retries; i++ {
		err := k.smtpOnce(sub, msg)
		k.mu.Lock()
		sub.stats.Attempts++
		k.mu.Unlock()
		outcome, last := "delivered", i == 1+retries
		if err != nil {
			outcome = "retrying"
			if last {
				outcome = "failed"
			}
		}
		a := snsAttempt{Kind: d.kind, MessageID: d.messageID, Attempt: i, Outcome: outcome, BodyBytes: len(msg), Body: msg}
		if err != nil {
			a.Error = cleanTransportError(err)
		}
		k.record(sub, a)
		if err == nil {
			k.finish(sub, "delivered")
			return
		}
		if last || !k.wait(sub, i) {
			k.finish(sub, "failed")
			return
		}
	}
}

// smtpOnce hands one message to the mail catcher: the address is the one the plan named (the only one the sink's dial lets through).
func (k *snsSink) smtpOnce(sub *snsSub, msg string) error {
	ctx, cancel := context.WithTimeout(withTarget(sub.ctx, dialTarget{addr: k.cfg.SMTP}), k.cfg.AttemptTimeout)
	defer cancel()
	conn, err := k.net.dial(ctx, "tcp4", "")
	if err != nil {
		return fmt.Errorf("the mail catcher did not take the connection")
	}
	conn.SetDeadline(time.Now().Add(k.cfg.AttemptTimeout))
	c, err := smtp.NewClient(conn, "mailcatcher")
	if err != nil {
		conn.Close()
		return fmt.Errorf("the mail catcher did not greet")
	}
	defer c.Close()
	if err := c.Hello("sns.amazonaws.com"); err != nil {
		return fmt.Errorf("the mail catcher refused the greeting")
	}
	if err := c.Mail(mailFrom); err != nil {
		return fmt.Errorf("the mail catcher refused the sender")
	}
	if err := c.Rcpt(sub.email); err != nil {
		return fmt.Errorf("the mail catcher refused the recipient")
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("the mail catcher refused the message")
	}
	if _, err := io.WriteString(w, msg); err != nil {
		return fmt.Errorf("the mail catcher did not take the message")
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("the mail catcher did not accept the message")
	}
	c.Quit()
	return nil
}

// ---- what the control surface shows

func (k *snsSink) subscriptionsJSON() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	type row struct {
		Arn      string   `json:"subscriptionArn"`
		Topic    string   `json:"topicArn"`
		Protocol string   `json:"protocol"`
		Target   string   `json:"target"`
		State    string   `json:"state"`
		Raw      bool     `json:"raw"`
		Pending  int      `json:"queued"`
		Tap      string   `json:"tap"`
		Stats    snsStats `json:"stats"`
	}
	rows := []row{}
	for _, sub := range k.subs {
		t := "mailto:" + hostOfEmail(sub.email)
		if sub.target != nil {
			t = sub.target.Display
		}
		st := "pending"
		if sub.state == subConfirmed {
			st = "confirmed"
		}
		tap := "ok"
		if sub.tapLost {
			tap, st = "lost", "tap lost" // never "confirmed" with nothing flowing
		}
		rows = append(rows, row{sub.arn, sub.topicArn, sub.protocol, t, st, sub.raw, len(sub.queue), tap, sub.stats})
	}
	sortRows := func(i, j int) bool { return rows[i].Arn < rows[j].Arn }
	sort.Slice(rows, sortRows)
	out, _ := json.Marshal(map[string]interface{}{"subscriptions": rows})
	return out
}

func (k *snsSink) deliveriesJSON(subscription string, after int64, limit int) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	all := []snsAttempt{}
	for _, sub := range k.subs {
		if subscription != "" && sub.arn != subscription {
			continue
		}
		for _, a := range sub.ring {
			if a.Seq > after {
				all = append(all, a)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	if len(all) > limit {
		all = all[:limit]
	}
	out, _ := json.Marshal(map[string]interface{}{"deliveries": all})
	return out
}

// summaryJSON is the evidence: counts by protocol and by redacted target host, and the words the card needs.
func (k *snsSink) summaryJSON() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	type row struct {
		Protocol string `json:"protocol"`
		Target   string `json:"target"`
		snsStats
	}
	byKey := map[string]*row{}
	for _, sub := range k.subs {
		t := "mailto:" + hostOfEmail(sub.email)
		if sub.target != nil {
			t = sub.target.Host
		}
		key := sub.protocol + "\x00" + t
		r := byKey[key]
		if r == nil {
			r = &row{Protocol: sub.protocol, Target: t}
			byKey[key] = r
		}
		r.Delivered += sub.stats.Delivered
		r.Failed += sub.stats.Failed
		r.Dropped += sub.stats.Dropped
		r.Held += sub.stats.Held
		r.Attempts += sub.stats.Attempts
		r.TapLost += sub.stats.TapLost
	}
	rows := []*row{}
	for _, r := range byKey {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Protocol+rows[i].Target < rows[j].Protocol+rows[j].Target })
	out, _ := json.Marshal(map[string]interface{}{"subscriptions": len(k.subs), "targets": rows, "signature": "faked", "signingCertServed": k.cfg.ServeCert,
		"retryTiming": "compressed", "retryBaseMs": k.cfg.RetryBase.Milliseconds()})
	return out
}
