package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SNS delivery sink (lane DS3; design beyond-emulator-delivery-sink-db-helpers.md, "Half 1"). The engine accepts an http, https or email
// subscription and then does nothing: it never posts, it never sends, and its ConfirmSubscription can never succeed (it does not even give the
// subscription an ARN). The front therefore OWNS these four protocols. SQS and Lambda subscriptions stay with the engine.
//
// For each http, https, email or email-json subscription the front
//
//  1. forwards the Subscribe to the engine (so the engine validates the topic and the caller as ever), then allocates the subscription's own
//     ARN, token and state (pending, or confirmed at once with ROVARA_AWS_SNS_AUTO_CONFIRM);
//  2. attaches a hidden TAP: an SQS queue rovara-sns-tap-<random> subscribed to the topic (with the subscription's FilterPolicy and scope; never
//     RawMessageDelivery, so the envelope keeps the attributes) and a policy that lets SNS send to it. The engine does the filtering and the
//     fan-out; the tap queue is the front's own and is hidden: ListQueues and the subscription lists never show it, and a request that names it
//     is refused;
//  3. polls the tap on loopback and delivers from a bounded per-subscription queue: an http(s) POST in the shape AWS sends, or an email handed
//     to the mail catcher, with the confirmation handshake, the retries and the run-key signature (sns_deliver.go);
//  4. answers, itself, what the engine cannot: ConfirmSubscription, Unsubscribe, GetSubscriptionAttributes and SetSubscriptionAttributes for its
//     own subscriptions, and the subscription lists with its subscriptions' real state (a confirmed one shows its ARN, an unsubscribed one is
//     gone, the taps are not there).
//
// What the customer's code is: HOSTILE. So the endpoint is judged at Subscribe and at every delivery (sink_route.go), nothing is ever dialled
// but an address the run's plan chose (sink_net.go), every queue and every body has a cap, the confirmation token is an HMAC under a per-run
// secret that is not the control token, and no delivery is ever shown to anything but the control read (token required). The control token
// is never part of anything the sink sends or stores.

const (
	snsTapPrefix        = "rovara-sns-tap-"
	snsMaxSubscriptions = 64
	snsMaxHidden        = 4096 // ended subscriptions the lists must keep hiding (the engine keeps its pending entry for ever)
	snsMaxControlBody   = 64 << 10
	snsMaxPending       = 100       // deliveries held per subscription
	snsMaxPendingBytes  = 32 << 20  // deliveries held by all subscriptions
	snsMaxMessageBytes  = 512 << 10 // a message larger than this (SNS allows 256 KiB) is dropped, counted
	snsNS               = "http://sns.amazonaws.com/doc/2010-03-31/"
)

var sinkProtocols = map[string]bool{"http": true, "https": true, "email": true, "email-json": true}

// snsOps are the SNS operations the sink answers or post-processes.
var snsOps = map[string]bool{"Subscribe": true, "Unsubscribe": true, "ConfirmSubscription": true, "GetSubscriptionAttributes": true,
	"SetSubscriptionAttributes": true, "ListSubscriptions": true, "ListSubscriptionsByTopic": true, "DeleteTopic": true, "GetTopicAttributes": true}

var (
	topicArnShape = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:sns:([a-z0-9-]{3,25}):([0-9]{12}):([A-Za-z0-9_.-]{1,256})$`)
	subArnShape   = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:sns:[a-z0-9-]{3,25}:[0-9]{12}:[A-Za-z0-9_.-]{1,256}:[0-9a-f-]{36}$`)
	memberRe      = regexp.MustCompile(`(?s)<member\b[^>]*>.*?</member>`)
	subArnXMLRe   = regexp.MustCompile(`<SubscriptionArn>([^<]*)</SubscriptionArn>`)
)

type snsSubState int

const (
	subPending snsSubState = iota
	subConfirmed
)

type snsSub struct {
	arn, topicArn, protocol, endpoint string
	region, account                   string
	tuple                             string
	state                             snsSubState
	confirmedAt                       time.Time // when it was confirmed: a message published before that is dropped, as on AWS
	raw                               bool
	filterPolicy, filterScope         string
	deliveryPolicy                    string
	retries                           int
	target                            *endpointTarget // http, https
	email                             string          // email, email-json
	token                             string
	tapQueueURL, tapQueueArn, tapArn  string
	tapLost                           bool // the tap is broken and being rebuilt: the subscription is not confirmed-and-flowing
	repairing                         bool
	queue                             []*snsDelivery
	queueBytes                        int64
	wake                              chan struct{}
	ctx                               context.Context
	cancel                            context.CancelFunc
	created                           time.Time
	stats                             snsStats
	ring                              []snsAttempt
}

type snsDelivery struct {
	kind       string // Notification, SubscriptionConfirmation
	messageID  string
	subject    string
	hasSubject bool
	message    string
	timestamp  string
	attrs      json.RawMessage
	size       int64
	received   time.Time // when the front took it off the tap: its own clock decides what was published before the confirmation
}

type snsSink struct {
	s   *Server
	cfg *SinkConfig
	rt  *routeTable
	net *sinkNet

	mu            sync.Mutex
	subs          map[string]*snsSub
	byTuple       map[string]*snsSub
	hidden        map[string]bool // tuples of engine entries whose subscription the front has ended
	tapArns       map[string]bool
	secret        []byte
	runID         string
	pending       int64
	seq           int64
	mayHaveUnseen atomic.Bool
	baseCtx       context.Context
	cancel        context.CancelFunc
	signer        *snsSigner
	events        []snsAttempt // attempts that belong to no subscription (the ring of dropped-at-the-door things)
	// bodySlots: how many engine answers are decoded in memory at once
	bodySlots slots
	// regions: the regions the sink has seen a topic in (a call with no caller of its own asks in each)
	regions map[string]bool
}

const snsBodySlots = 4

func newSNSSink(s *Server, cfg *SinkConfig, n *sinkNet, selfTLS string) *snsSink {
	k := &snsSink{s: s, cfg: cfg, net: n, rt: &routeTable{cfg: cfg, selfTLS: selfTLS}, bodySlots: newSlots(snsBodySlots)}
	k.secret = randBytes(32)
	k.runID = hex.EncodeToString(randBytes(8))
	k.resetLocked()
	return k
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (k *snsSink) resetLocked() {
	k.subs, k.byTuple, k.hidden, k.tapArns = map[string]*snsSub{}, map[string]*snsSub{}, map[string]bool{}, map[string]bool{}
	k.pending = 0
	k.regions = map[string]bool{}
	k.baseCtx, k.cancel = context.WithCancel(context.Background())
}

// reset ends every subscription and every goroutine (the engine's state is gone: POST /_rovara/reset). The counters of the ledger stay
// with the ledger; the captures go (they are the round's).
func (k *snsSink) reset() {
	k.mu.Lock()
	old := k.cancel
	k.resetLocked()
	k.mu.Unlock()
	old()
}

// clear is DELETE /_rovara/ledger: the captures and counters go, the subscriptions stay.
func (k *snsSink) clear() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, sub := range k.subs {
		sub.ring, sub.stats = nil, snsStats{}
	}
}

// partitionOf: "arn:aws" (or "arn:aws-cn") from a topic ARN that already has the shape.
func partitionOf(arn string) string {
	if i := strings.Index(arn, ":sns:"); i > 0 {
		return arn[:i]
	}
	return "arn:aws"
}

func tupleKey(topic, protocol, endpoint string) string {
	return topic + "\x00" + protocol + "\x00" + endpoint
}

// ---- the engine, as the sink calls it (loopback, bounded)
//
// Every call says who is calling. What the caller asked for (Subscribe, DeleteTopic, the lists) is forwarded AS THE CALLER, with the caller's own
// key, session token and region, so the engine's own authorization and region apply to it exactly as they do to a request that does not pass
// the sink. What the sink does for itself (the tap queue and its subscription, the checks, the adoption of a subscription) is made as the
// front's own credential, in the REGION OF THE TOPIC.

const snsEngineReadMax = 4 << 20

// snsReceiveReadMax is what one ReceiveMessage answer may be: one message (SQS allows 1 MiB) is at most 6 MiB written as JSON inside JSON.
const snsReceiveReadMax = 8 << 20

type callAs struct{ authorization, token string }

// ambientAs is the front's own credential for a service, in a region.
func ambientAs(svcKey, region string) callAs {
	return callAs{authorization: syntheticAuthorization(byKey[svcKey].SigningName, region)}
}

// callerAs is the identity of the request being forwarded: its key, date and region, and its session token.
func callerAs(id identified, r *http.Request) callAs {
	return callAs{authorization: engineAuthorization(id), token: r.Header.Get("X-Amz-Security-Token")}
}

var errSinkAnswerTooLarge = errors.New("the engine's answer is larger than the sink reads")

func (k *snsSink) engineCall(ctx context.Context, as callAs, method, path string, headers map[string]string, body []byte, limit int64) (int, []byte, http.Header, error) {
	gen, _, err := k.s.engine.current()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("the engine is not ready")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "https://127.0.0.1:"+strconv.Itoa(gen.port)+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Host = "127.0.0.1:" + strconv.Itoa(gen.port)
	req.Header.Set("Authorization", as.authorization)
	if as.token != "" {
		req.Header.Set("X-Amz-Security-Token", as.token)
	}
	req.Header.Set("User-Agent", "rovara-aws-front-sns-sink")
	for h, v := range headers {
		req.Header.Set(h, v)
	}
	resp, err := gen.client.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("the engine did not answer")
	}
	defer resp.Body.Close()
	// the answer is held in memory only while one of a few slots is held, so many polls cannot decode large answers at the same time
	if !k.bodySlots.acquire(ctx) {
		return 0, nil, nil, fmt.Errorf("the engine did not answer")
	}
	defer k.bodySlots.release()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(b)) > limit {
		return resp.StatusCode, nil, resp.Header, errSinkAnswerTooLarge
	}
	return resp.StatusCode, b, resp.Header, nil
}

// snsQuery calls an SNS action on the engine with the given parameters.
func (k *snsSink) snsQuery(ctx context.Context, as callAs, action string, params url.Values) (int, []byte, http.Header, error) {
	v := url.Values{}
	for key, vals := range params {
		v[key] = vals
	}
	v.Set("Action", action)
	v.Set("Version", "2010-03-31")
	return k.engineCall(ctx, as, http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(v.Encode()), snsEngineReadMax)
}

// sqsError is an SQS answer that is not a success.
type sqsError struct {
	action string
	status int
	code   string
}

func (e *sqsError) Error() string { return fmt.Sprintf("%s answered %d", e.action, e.status) }

// queueGone: the engine says the queue is not there.
func queueGone(err error) bool {
	var se *sqsError
	return errors.As(err, &se) && (se.code == "QueueDoesNotExist" || strings.HasSuffix(se.code, "NonExistentQueue"))
}

// sqsCall calls an SQS action on the engine (JSON protocol).
func (k *snsSink) sqsCall(ctx context.Context, as callAs, action string, req map[string]interface{}) (map[string]interface{}, error) {
	body, _ := json.Marshal(req)
	limit := int64(snsEngineReadMax)
	if action == "ReceiveMessage" {
		limit = snsReceiveReadMax
	}
	status, out, _, err := k.engineCall(ctx, as, http.MethodPost, "/", map[string]string{"X-Amz-Target": "AmazonSQS." + action, "Content-Type": "application/x-amz-json-1.0"}, body, limit)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		var e struct {
			Type string `json:"__type"`
		}
		json.Unmarshal(out, &e)
		if i := strings.LastIndex(e.Type, "#"); i >= 0 {
			e.Type = e.Type[i+1:]
		}
		return nil, &sqsError{action, status, e.Type}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil && len(bytes.TrimSpace(out)) > 0 {
		return nil, fmt.Errorf("%s answered something that is not JSON", action)
	}
	return m, nil
}

// ---- the requests the sink answers

// snsRequestID is the RequestId of an answer the sink writes.
func snsXML(w http.ResponseWriter, status int, body string) {
	writeBody(w, status, "text/xml", []byte(body))
}

func snsResponse(action, result string) string {
	return `<` + action + `Response xmlns="` + snsNS + `">` + result + `<ResponseMetadata><RequestId>` + newUUID() + `</RequestId></ResponseMetadata></` + action + `Response>`
}

func snsFail(w http.ResponseWriter, status int, code, message string) {
	writeAWSError(w, protoQuery, status, code, message, "")
}

// attrEntries reads the Query map `<name>.entry.N.key` / `.value`.
func attrEntries(p url.Values, name string) map[string]string {
	out := map[string]string{}
	for i := 1; i <= 50; i++ {
		key := p.Get(fmt.Sprintf("%s.entry.%d.key", name, i))
		if key == "" {
			if i > 1 && p.Get(fmt.Sprintf("%s.entry.%d.value", name, i)) == "" {
				break
			}
			continue
		}
		out[key] = p.Get(fmt.Sprintf("%s.entry.%d.value", name, i))
	}
	return out
}

// paramsOf merges the query string and the form body (the form wins), as the engine reads a Query request.
func paramsOf(q, form url.Values) url.Values {
	p := url.Values{}
	for k, v := range q {
		p[k] = append([]string(nil), v...)
	}
	for k, v := range form {
		p[k] = append([]string(nil), v...)
	}
	return p
}

// handle answers one SNS request when the sink is responsible for it, and reports whether it wrote the answer. params is the merged Query
// parameters; r is only read for its size and method.
func (k *snsSink) handle(w http.ResponseWriter, r *http.Request, op string, params url.Values, as callAs) bool {
	if !snsOps[op] {
		return false
	}
	size := 0
	for key, vs := range params {
		size += len(key)
		for _, v := range vs {
			size += len(v)
		}
	}
	if r.ContentLength > snsMaxControlBody || size > snsMaxControlBody {
		snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: the request is too large")
		return true
	}
	switch op {
	case "Subscribe":
		return k.subscribe(w, r, params, as)
	case "ConfirmSubscription":
		k.confirmRequest(w, params)
		return true
	case "Unsubscribe":
		return k.unsubscribe(w, r, params)
	case "GetSubscriptionAttributes":
		return k.getAttributes(w, params)
	case "SetSubscriptionAttributes":
		return k.setAttributes(w, r, params)
	case "ListSubscriptions", "ListSubscriptionsByTopic":
		k.list(w, r, op, params, as)
		return true
	case "GetTopicAttributes":
		k.topicAttributes(w, r, params, as)
		return true
	case "DeleteTopic":
		return k.deleteTopic(w, r, params, as)
	}
	return false
}

// forward sends the caller's own request to the engine and returns its answer.
func (k *snsSink) forward(r *http.Request, op string, params url.Values, as callAs) (int, []byte, http.Header, error) {
	return k.snsQuery(r.Context(), as, op, params)
}

// writeEngineAnswer relays an engine answer unchanged (an error, for example).
func writeEngineAnswer(w http.ResponseWriter, status int, body []byte, h http.Header) {
	ct := "text/xml"
	if h != nil && h.Get("Content-Type") != "" {
		ct = h.Get("Content-Type")
	}
	writeBody(w, status, ct, body)
}

func (k *snsSink) subscribe(w http.ResponseWriter, r *http.Request, p url.Values, as callAs) bool {
	protocol, endpoint, topicArn := p.Get("Protocol"), p.Get("Endpoint"), p.Get("TopicArn")
	if lower := strings.ToLower(protocol); lower != protocol && sinkProtocols[lower] {
		// protocol names are lower case: another case is not passed to the engine (which would keep it pending for ever)
		snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: Protocol")
		return true
	}
	if protocol == "sqs" && strings.Contains(endpoint, ":"+snsTapPrefix) {
		// the front's own queues are not a place a caller can send a topic to (the tap would then hold the caller's messages)
		snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: Endpoint")
		return true
	}
	if !sinkProtocols[protocol] {
		return false // sqs, lambda, sms, firehose, application: the engine's own
	}
	m := topicArnShape.FindStringSubmatch(topicArn)
	if m == nil {
		snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: TopicArn")
		return true
	}
	t, email, err := k.judgeEndpoint(protocol, endpoint)
	if err != nil {
		snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: Endpoint Reason: "+strings.TrimPrefix(err.Error(), "endpoint: "))
		k.s.ledger.recordUnsupported("sns", "sink:endpoint-refused", protocol)
		return true
	}
	for name, value := range attrEntries(p, "Attributes") {
		if err := (&snsSub{}).applyAttribute(name, value); err != nil {
			snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: AttributeName")
			return true
		}
	}
	tuple := tupleKey(topicArn, protocol, endpoint)
	k.mu.Lock()
	if existing := k.byTuple[tuple]; existing != nil {
		arn, state := existing.arn, existing.state
		k.mu.Unlock()
		k.subscribeAnswer(w, arn, state, p)
		return true
	}
	if len(k.subs) >= snsMaxSubscriptions || len(k.hidden) >= snsMaxHidden {
		k.mu.Unlock()
		snsFail(w, http.StatusForbidden, "SubscriptionLimitExceeded", "Subscription limit exceeded")
		return true
	}
	gen := k.baseCtx // the generation this subscription belongs to: a reset in the meantime ends it
	k.regions[m[1]] = true
	k.mu.Unlock()
	status, body, h, err := k.forward(r, "Subscribe", p, as)
	if err != nil {
		snsFail(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The local AWS emulator did not answer.")
		return true
	}
	if status >= 300 {
		writeEngineAnswer(w, status, body, h)
		return true
	}
	sub, err := k.createSub(r.Context(), gen, topicArn, protocol, endpoint, m, t, email, attrEntries(p, "Attributes"))
	if errors.Is(err, errSinkReset) {
		snsFail(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The local AWS emulator was reset.")
		return true
	}
	if err != nil {
		snsFail(w, http.StatusInternalServerError, "InternalFailure", "The delivery sink could not attach to the topic.")
		return true
	}
	k.mu.Lock()
	arn, state := sub.arn, sub.state
	k.mu.Unlock()
	k.subscribeAnswer(w, arn, state, p)
	return true
}

func (k *snsSink) judgeEndpoint(protocol, endpoint string) (*endpointTarget, string, error) {
	if protocol == "email" || protocol == "email-json" {
		if emailProblem(endpoint) != "" {
			return nil, "", epProblem("not a plain email address")
		}
		return nil, endpoint, nil
	}
	t, err := k.rt.classify(protocol, endpoint)
	return t, "", err
}

func (k *snsSink) subscribeAnswer(w http.ResponseWriter, arn string, state snsSubState, p url.Values) {
	shown := "pending confirmation"
	if state == subConfirmed || strings.EqualFold(p.Get("ReturnSubscriptionArn"), "true") {
		shown = arn
	}
	snsXML(w, 200, snsResponse("Subscribe", "<SubscribeResult><SubscriptionArn>"+xmlEscape(shown)+"</SubscriptionArn></SubscribeResult>"))
}

// createSub makes the front's record of one subscription, its tap and its goroutines. The engine already holds the subscription.
var errSinkReset = errors.New("the sink was reset")

func (k *snsSink) createSub(ctx context.Context, gen context.Context, topicArn, protocol, endpoint string, m []string, t *endpointTarget, email string, attrs map[string]string) (*snsSub, error) {
	region, account, topicName := m[1], m[2], m[3]
	id := newUUID()
	sub := &snsSub{
		arn: partitionOf(topicArn) + ":sns:" + region + ":" + account + ":" + topicName + ":" + id, topicArn: topicArn, protocol: protocol, endpoint: endpoint,
		region: region, account: account, tuple: tupleKey(topicArn, protocol, endpoint), target: t, email: email,
		wake: make(chan struct{}, 1), created: time.Now(), retries: 3,
	}
	sub.token = k.tokenFor(sub.arn)
	for name, value := range attrs {
		if err := sub.applyAttribute(name, value); err != nil {
			return nil, err
		}
	}
	info, err := k.attachTap(ctx, sub)
	if err != nil {
		return nil, err
	}
	sub.tapQueueURL, sub.tapQueueArn, sub.tapArn = info.queueURL, info.queueArn, info.subArn
	k.mu.Lock()
	if k.baseCtx != gen {
		// a reset came between the engine's answer and now: the engine's state this subscription was made in is gone
		k.mu.Unlock()
		k.dropTap(sub)
		return nil, errSinkReset
	}
	if k.byTuple[sub.tuple] != nil || len(k.subs) >= snsMaxSubscriptions {
		k.mu.Unlock()
		k.dropTap(sub)
		if existing := k.lookupTuple(sub.tuple); existing != nil {
			return existing, nil
		}
		return nil, fmt.Errorf("too many subscriptions")
	}
	sub.ctx, sub.cancel = context.WithCancel(gen)
	k.regions[region] = true
	k.subs[sub.arn], k.byTuple[sub.tuple] = sub, sub
	k.tapArns[sub.tapArn] = true
	delete(k.hidden, sub.tuple)
	if k.cfg.AutoConfirm {
		sub.state, sub.confirmedAt = subConfirmed, sub.created
	}
	k.mu.Unlock()
	go k.tapLoop(sub)
	go k.deliverLoop(sub)
	if !k.cfg.AutoConfirm {
		k.enqueue(sub, k.confirmationFor(sub))
	}
	return sub, nil
}

func (k *snsSink) lookupTuple(t string) *snsSub {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.byTuple[t]
}

// applyAttribute sets one subscription attribute (the ones SNS lets a subscriber set) and refuses any other.
func (sub *snsSub) applyAttribute(name, value string) error {
	switch name {
	case "RawMessageDelivery":
		if value != "true" && value != "false" {
			return fmt.Errorf("bad RawMessageDelivery")
		}
		sub.raw = value == "true"
	case "FilterPolicy":
		if len(value) > 256<<10 || (value != "" && !json.Valid([]byte(value))) {
			return fmt.Errorf("bad FilterPolicy")
		}
		sub.filterPolicy = value
	case "FilterPolicyScope":
		if value != "MessageAttributes" && value != "MessageBody" {
			return fmt.Errorf("bad FilterPolicyScope")
		}
		sub.filterScope = value
	case "DeliveryPolicy":
		if len(value) > 8<<10 {
			return fmt.Errorf("bad DeliveryPolicy")
		}
		sub.deliveryPolicy = value
		sub.retries = retriesFromPolicy(value)
	case "RedrivePolicy", "SubscriptionRoleArn":
		// accepted and not acted on (a dead-letter queue is the engine's; there is nothing to redrive from)
	default:
		return fmt.Errorf("unknown attribute")
	}
	return nil
}

// retriesFromPolicy reads numRetries from a delivery policy (healthyRetryPolicy), clamped to 0..5; anything unreadable is the default, 3.
func retriesFromPolicy(policy string) int {
	var doc struct {
		Healthy struct {
			NumRetries *int `json:"numRetries"`
		} `json:"healthyRetryPolicy"`
	}
	if json.Unmarshal([]byte(policy), &doc) != nil || doc.Healthy.NumRetries == nil {
		return 3
	}
	n := *doc.Healthy.NumRetries
	if n < 0 {
		return 0
	}
	if n > 5 {
		return 5
	}
	return n
}

// ---- the tap

// tapInfo names what one tap is made of in the engine.
type tapInfo struct{ queueURL, queueArn, subArn string }

// attachTap makes a tap for the subscription: the queue, the policy SNS needs, and the topic's subscription of the queue. It is made as the
// front's own credential in the TOPIC'S region (the queue's ARN says that region). It does not touch the subscription's own fields.
func (k *snsSink) attachTap(ctx context.Context, sub *snsSub) (tapInfo, error) {
	k.mu.Lock()
	topicArn, region, account, filter, scope := sub.topicArn, sub.region, sub.account, sub.filterPolicy, sub.filterScope
	k.mu.Unlock()
	sqsAs, snsAs := ambientAs("sqs", region), ambientAs("sns", region)
	name := snsTapPrefix + hex.EncodeToString(randBytes(16))
	out, err := k.sqsCall(ctx, sqsAs, "CreateQueue", map[string]interface{}{"QueueName": name})
	if err != nil {
		return tapInfo{}, err
	}
	info := tapInfo{}
	info.queueURL, _ = out["QueueUrl"].(string)
	if info.queueURL == "" {
		return tapInfo{}, fmt.Errorf("no queue url")
	}
	info.queueArn = partitionOf(topicArn) + ":sqs:" + region + ":" + account + ":" + name
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"` +
		info.queueArn + `","Condition":{"ArnEquals":{"aws:SourceArn":"` + topicArn + `"}}}]}`
	if _, err := k.sqsCall(ctx, sqsAs, "SetQueueAttributes", map[string]interface{}{"QueueUrl": info.queueURL, "Attributes": map[string]string{"Policy": policy}}); err != nil {
		k.dropTapInfo(region, info)
		return tapInfo{}, err
	}
	params := url.Values{"TopicArn": {topicArn}, "Protocol": {"sqs"}, "Endpoint": {info.queueArn}, "ReturnSubscriptionArn": {"true"}}
	n := 0
	for _, a := range [][2]string{{"FilterPolicy", filter}, {"FilterPolicyScope", scope}} {
		if a[1] != "" {
			n++
			params.Set(fmt.Sprintf("Attributes.entry.%d.key", n), a[0])
			params.Set(fmt.Sprintf("Attributes.entry.%d.value", n), a[1])
		}
	}
	status, body, _, err := k.snsQuery(ctx, snsAs, "Subscribe", params)
	if err != nil || status >= 300 {
		k.dropTapInfo(region, info)
		return tapInfo{}, fmt.Errorf("the tap could not subscribe")
	}
	m := subArnXMLRe.FindSubmatch(body)
	if m == nil || !subArnShape.Match(m[1]) {
		k.dropTapInfo(region, info)
		return tapInfo{}, fmt.Errorf("the tap has no subscription arn")
	}
	info.subArn = string(m[1])
	return info, nil
}

// dropTap removes the subscription's tap from the engine (best effort, bounded, never blocks the caller for long).
func (k *snsSink) dropTap(sub *snsSub) {
	k.mu.Lock()
	info, region := tapInfo{sub.tapQueueURL, sub.tapQueueArn, sub.tapArn}, sub.region
	k.mu.Unlock()
	k.dropTapInfo(region, info)
}

func (k *snsSink) dropTapInfo(region string, info tapInfo) {
	if info.queueURL == "" && info.subArn == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if info.subArn != "" {
			k.snsQuery(ctx, ambientAs("sns", region), "Unsubscribe", url.Values{"SubscriptionArn": {info.subArn}})
		}
		if info.queueURL != "" {
			k.sqsCall(ctx, ambientAs("sqs", region), "DeleteQueue", map[string]interface{}{"QueueUrl": info.queueURL})
		}
	}()
}

// tapVerifyDefault: how often a tap's subscription is checked to still be on the topic.
const tapVerifyDefault = 10 * time.Second

// tapSubscribed asks the engine whether the tap's own subscription is still on the topic. An answer it cannot get is "yes" (no false repair).
func (k *snsSink) tapSubscribed(sub *snsSub) bool {
	k.mu.Lock()
	topic, region, tapArn := sub.topicArn, sub.region, sub.tapArn
	k.mu.Unlock()
	next := ""
	for page := 0; page < 10; page++ {
		params := url.Values{"TopicArn": {topic}}
		if next != "" {
			params.Set("NextToken", next)
		}
		status, body, _, err := k.snsQuery(sub.ctx, ambientAs("sns", region), "ListSubscriptionsByTopic", params)
		if err != nil || status >= 300 {
			return true
		}
		if bytes.Contains(body, []byte("<SubscriptionArn>"+tapArn+"</SubscriptionArn>")) {
			return true
		}
		if next = sinkXMLField(string(body), "NextToken"); next == "" {
			return false
		}
	}
	return true
}

// repairTap rebuilds a tap that is gone or broken. The subscription is "tap lost" (counted, recorded, shown so) until the new tap is made;
// what was published in between is not delivered. It does not return until it has tried once.
func (k *snsSink) repairTap(sub *snsSub, reason string) {
	k.mu.Lock()
	if sub.repairing || sub.ctx.Err() != nil {
		k.mu.Unlock()
		return
	}
	sub.repairing = true
	first := !sub.tapLost
	sub.tapLost = true
	if first {
		sub.stats.TapLost++
	}
	old := tapInfo{sub.tapQueueURL, sub.tapQueueArn, sub.tapArn}
	k.mu.Unlock()
	if first {
		k.record(sub, snsAttempt{Kind: "Tap", Outcome: "tap lost", Error: reason})
	}
	k.dropTapInfo(sub.region, old)
	info, err := k.attachTap(sub.ctx, sub)
	k.mu.Lock()
	sub.repairing = false
	if err == nil {
		delete(k.tapArns, old.subArn)
		k.tapArns[info.subArn] = true
		sub.tapQueueURL, sub.tapQueueArn, sub.tapArn = info.queueURL, info.queueArn, info.subArn
		sub.tapLost = false
	}
	k.mu.Unlock()
	if err != nil {
		select {
		case <-sub.ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// tapLoop polls the tap queue until the subscription ends, and notices when the tap is gone.
func (k *snsSink) tapLoop(sub *snsSub) {
	every := k.cfg.TapVerifyEvery
	if every <= 0 {
		every = tapVerifyDefault
	}
	nextVerify := time.Now().Add(every)
	for sub.ctx.Err() == nil {
		k.mu.Lock()
		qurl := sub.tapQueueURL
		k.mu.Unlock()
		// one message a poll: an answer is then at most one message, and a batch of large ones cannot overflow what is read
		out, err := k.sqsCall(sub.ctx, ambientAs("sqs", sub.region), "ReceiveMessage", map[string]interface{}{"QueueUrl": qurl, "MaxNumberOfMessages": 1, "WaitTimeSeconds": 1, "VisibilityTimeout": 30})
		switch {
		case queueGone(err):
			k.repairTap(sub, "the tap queue is gone")
		case errors.Is(err, errSinkAnswerTooLarge):
			// a message too large to read is counted and cleared (left alone it would come back after its visibility timeout, for ever)
			k.recordDrop(sub, "Notification", "", "a message too large to read was left on the tap and cleared")
			k.sqsCall(sub.ctx, ambientAs("sqs", sub.region), "PurgeQueue", map[string]interface{}{"QueueUrl": qurl})
		case err != nil:
			select {
			case <-sub.ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		default:
			msgs, _ := out["Messages"].([]interface{})
			for _, mi := range msgs {
				msg, _ := mi.(map[string]interface{})
				body, _ := msg["Body"].(string)
				if rh, _ := msg["ReceiptHandle"].(string); rh != "" {
					k.sqsCall(sub.ctx, ambientAs("sqs", sub.region), "DeleteMessage", map[string]interface{}{"QueueUrl": qurl, "ReceiptHandle": rh})
				}
				k.takeEnvelope(sub, body)
			}
		}
		if time.Now().After(nextVerify) {
			nextVerify = time.Now().Add(every)
			if sub.ctx.Err() == nil && !k.tapSubscribed(sub) {
				k.repairTap(sub, "the tap's subscription is gone from the topic")
			}
		}
	}
}

// takeEnvelope reads one SNS envelope off the tap and queues its delivery.
func (k *snsSink) takeEnvelope(sub *snsSub, body string) {
	if len(body) > snsMaxMessageBytes {
		k.recordDrop(sub, "Notification", "", "the message is larger than the sink holds")
		return
	}
	var env struct {
		Type, MessageId, TopicArn, Subject, Message, Timestamp string
		MessageAttributes                                      json.RawMessage
	}
	var presence struct{ Subject *string }
	if json.Unmarshal([]byte(body), &env) != nil || env.Type != "Notification" {
		return
	}
	json.Unmarshal([]byte(body), &presence)
	if !idShape.MatchString(env.MessageId) {
		k.recordDrop(sub, "Notification", "", "the message id is not an id")
		return
	}
	if env.TopicArn != sub.topicArn {
		// the tap is the front's, and only the engine writes to it; an envelope for another topic is not this subscription's
		k.recordDrop(sub, "Notification", env.MessageId, "the envelope names another topic")
		return
	}
	d := &snsDelivery{kind: "Notification", messageID: env.MessageId, received: time.Now(), subject: env.Subject, hasSubject: presence.Subject != nil, message: env.Message,
		timestamp: env.Timestamp, attrs: env.MessageAttributes, size: int64(len(body))}
	k.enqueue(sub, d)
}

var idShape = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// enqueue holds one delivery for the subscription's goroutine; over a cap, it is dropped and counted.
func (k *snsSink) enqueue(sub *snsSub, d *snsDelivery) {
	k.mu.Lock()
	if len(sub.queue) >= snsMaxPending || k.pending+d.size > snsMaxPendingBytes {
		k.mu.Unlock()
		k.recordDrop(sub, d.kind, d.messageID, "the delivery queue is full")
		return
	}
	sub.queue = append(sub.queue, d)
	sub.queueBytes += d.size
	k.pending += d.size
	k.mu.Unlock()
	select {
	case sub.wake <- struct{}{}:
	default:
	}
}

// ---- tokens

func (k *snsSink) tokenFor(subArn string) string {
	mac := hmac.New(sha256.New, k.secret)
	mac.Write([]byte("sns-confirm|" + subArn))
	return hex.EncodeToString(mac.Sum(nil))
}

// confirmRequest is ConfirmSubscription(TopicArn, Token), from the API or from the SubscribeURL.
func (k *snsSink) confirmRequest(w http.ResponseWriter, p url.Values) {
	topic, token := p.Get("TopicArn"), p.Get("Token")
	k.mu.Lock()
	var found *snsSub
	for _, sub := range k.subs {
		// every candidate is compared, whatever matched, so the time says nothing about which subscription holds a token
		if subtle.ConstantTimeCompare([]byte(sub.token), []byte(token)) == 1 && sub.topicArn == topic {
			found = sub
		}
	}
	var arn string
	if found != nil {
		if found.state != subConfirmed {
			found.state, found.confirmedAt = subConfirmed, time.Now()
		}
		arn = found.arn
	}
	k.mu.Unlock()
	if found == nil {
		snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: Token")
		return
	}
	snsXML(w, 200, snsResponse("ConfirmSubscription", "<ConfirmSubscriptionResult><SubscriptionArn>"+xmlEscape(arn)+"</SubscriptionArn></ConfirmSubscriptionResult>"))
}

// ---- unsubscribe, attributes, lists

func (k *snsSink) ownedByArn(arn string) (sub *snsSub, tap bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.subs[arn], k.tapArns[arn]
}

func (k *snsSink) unsubscribe(w http.ResponseWriter, r *http.Request, p url.Values) bool {
	arn := p.Get("SubscriptionArn")
	sub, tap := k.ownedByArn(arn)
	if tap {
		// the tap is the front's and is not there for a caller: an unsubscribe of it does nothing and says it worked, as AWS does for an ARN it has no record of
		snsXML(w, 200, snsResponse("Unsubscribe", ""))
		return true
	}
	if sub == nil {
		return false
	}
	k.removeSub(sub)
	snsXML(w, 200, snsResponse("Unsubscribe", ""))
	return true
}

// removeSub ends a subscription. The engine's own entry (pending for ever) is hidden from the lists from now on.
func (k *snsSink) removeSub(sub *snsSub) {
	k.mu.Lock()
	if k.subs[sub.arn] != sub {
		k.mu.Unlock()
		return
	}
	delete(k.subs, sub.arn)
	delete(k.byTuple, sub.tuple)
	delete(k.tapArns, sub.tapArn)
	k.hidden[sub.tuple] = true
	k.pending -= sub.queueBytes
	sub.queue, sub.queueBytes = nil, 0
	k.mu.Unlock()
	sub.cancel()
	k.dropTap(sub)
}

func (k *snsSink) deleteTopic(w http.ResponseWriter, r *http.Request, p url.Values, as callAs) bool {
	topic := p.Get("TopicArn")
	status, body, h, err := k.forward(r, "DeleteTopic", p, as)
	if err != nil {
		snsFail(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The local AWS emulator did not answer.")
		return true
	}
	if status < 300 {
		k.mu.Lock()
		var gone []*snsSub
		for _, sub := range k.subs {
			if sub.topicArn == topic {
				gone = append(gone, sub)
			}
		}
		k.mu.Unlock()
		for _, sub := range gone {
			k.removeSub(sub)
		}
	}
	writeEngineAnswer(w, status, body, h)
	return true
}

func (k *snsSink) getAttributes(w http.ResponseWriter, p url.Values) bool {
	arn := p.Get("SubscriptionArn")
	sub, tap := k.ownedByArn(arn)
	if tap {
		snsFail(w, http.StatusNotFound, "NotFound", "Subscription does not exist")
		return true
	}
	if sub == nil {
		return false
	}
	k.mu.Lock()
	attrs := [][2]string{{"Owner", sub.account}, {"RawMessageDelivery", strconv.FormatBool(sub.raw)}, {"TopicArn", sub.topicArn}, {"Endpoint", maskEndpoint(sub.endpoint)},
		{"Protocol", sub.protocol}, {"PendingConfirmation", strconv.FormatBool(sub.state == subPending)}, {"ConfirmationWasAuthenticated", "false"}, {"SubscriptionArn", sub.arn}}
	if sub.filterPolicy != "" {
		attrs = append(attrs, [2]string{"FilterPolicy", sub.filterPolicy})
	}
	if sub.filterScope != "" {
		attrs = append(attrs, [2]string{"FilterPolicyScope", sub.filterScope})
	}
	if sub.deliveryPolicy != "" {
		attrs = append(attrs, [2]string{"DeliveryPolicy", sub.deliveryPolicy})
	}
	k.mu.Unlock()
	var b strings.Builder
	b.WriteString("<GetSubscriptionAttributesResult><Attributes>")
	for _, a := range attrs {
		b.WriteString("<entry><key>" + xmlEscape(a[0]) + "</key><value>" + xmlEscape(a[1]) + "</value></entry>")
	}
	b.WriteString("</Attributes></GetSubscriptionAttributesResult>")
	snsXML(w, 200, snsResponse("GetSubscriptionAttributes", b.String()))
	return true
}

func (k *snsSink) setAttributes(w http.ResponseWriter, r *http.Request, p url.Values) bool {
	arn := p.Get("SubscriptionArn")
	sub, tap := k.ownedByArn(arn)
	if tap {
		snsFail(w, http.StatusNotFound, "NotFound", "Subscription does not exist")
		return true
	}
	if sub == nil {
		return false
	}
	name, value := p.Get("AttributeName"), p.Get("AttributeValue")
	k.mu.Lock()
	err := sub.applyAttribute(name, value)
	tapArn, region := sub.tapArn, sub.region
	k.mu.Unlock()
	if err != nil {
		snsFail(w, http.StatusBadRequest, "InvalidParameter", "Invalid parameter: AttributeName")
		return true
	}
	if name == "FilterPolicy" || name == "FilterPolicyScope" {
		// the engine filters: the tap's subscription follows the caller's
		status, _, _, err := k.snsQuery(r.Context(), ambientAs("sns", region), "SetSubscriptionAttributes", url.Values{"SubscriptionArn": {tapArn}, "AttributeName": {name}, "AttributeValue": {value}})
		if err != nil || status >= 300 {
			snsFail(w, http.StatusInternalServerError, "InternalFailure", "The delivery sink could not update the filter.")
			return true
		}
	}
	snsXML(w, 200, snsResponse("SetSubscriptionAttributes", ""))
	return true
}

// list asks the engine and rewrites what it says: a confirmed subscription shows its ARN, an unsubscribed one is gone, the taps are not there.
func (k *snsSink) list(w http.ResponseWriter, r *http.Request, op string, p url.Values, as callAs) {
	status, body, h, err := k.forward(r, op, p, as)
	if err != nil {
		snsFail(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The local AWS emulator did not answer.")
		return
	}
	if status < 300 {
		body = k.rewriteMembers(body)
	}
	writeEngineAnswer(w, status, body, h)
}

func sinkXMLField(block, name string) string {
	open := "<" + name + ">"
	i := strings.Index(block, open)
	if i < 0 {
		return ""
	}
	rest := block[i+len(open):]
	j := strings.Index(rest, "</"+name+">")
	if j < 0 {
		return ""
	}
	return xmlUnescape(rest[:j])
}

var xmlUnescaper = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&#39;", "'", "&amp;", "&")

func xmlUnescape(s string) string { return xmlUnescaper.Replace(s) }

func (k *snsSink) rewriteMembers(body []byte) []byte {
	return memberRe.ReplaceAllFunc(body, func(block []byte) []byte {
		b := string(block)
		protocol, endpoint, topic := sinkXMLField(b, "Protocol"), sinkXMLField(b, "Endpoint"), sinkXMLField(b, "TopicArn")
		if protocol == "sqs" && strings.Contains(endpoint, ":"+snsTapPrefix) {
			return nil // a tap: not the caller's to see
		}
		if !sinkProtocols[protocol] {
			return block
		}
		tuple := tupleKey(topic, protocol, endpoint)
		k.mu.Lock()
		sub, hidden := k.byTuple[tuple], k.hidden[tuple]
		var arn string
		confirmed := false
		if sub != nil {
			arn, confirmed = sub.arn, sub.state == subConfirmed
		}
		k.mu.Unlock()
		if masked := maskEndpoint(endpoint); masked != endpoint {
			block = endpointXMLRe.ReplaceAll(block, []byte("<Endpoint>"+xmlEscape(masked)+"</Endpoint>"))
		}
		switch {
		case sub == nil && hidden:
			return nil
		case sub != nil && confirmed:
			return subArnXMLRe.ReplaceAll(block, []byte("<SubscriptionArn>"+xmlEscape(arn)+"</SubscriptionArn>"))
		}
		return block
	})
}

var endpointXMLRe = regexp.MustCompile(`<Endpoint>[^<]*</Endpoint>`)

// maskEndpoint writes an http(s) endpoint's user-info password as ****, as AWS does when it shows a subscription's endpoint.
func maskEndpoint(endpoint string) string {
	i := strings.Index(endpoint, "://")
	if i < 0 {
		return endpoint
	}
	rest := endpoint[i+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	at := strings.LastIndex(rest[:end], "@")
	if at < 0 {
		return endpoint
	}
	user, _, hasPass := strings.Cut(rest[:at], ":")
	if !hasPass {
		return endpoint
	}
	return endpoint[:i+3] + user + ":****" + rest[at:]
}

// topicAttributes answers GetTopicAttributes with the subscription counts as a caller sees them: the engine counts the front's taps as
// confirmed subscriptions and every http, https and email subscription as pending for ever.
func (k *snsSink) topicAttributes(w http.ResponseWriter, r *http.Request, p url.Values, as callAs) {
	status, body, h, err := k.forward(r, "GetTopicAttributes", p, as)
	if err != nil {
		snsFail(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The local AWS emulator did not answer.")
		return
	}
	if status < 300 {
		topic := p.Get("TopicArn")
		k.mu.Lock()
		taps, ourConfirmed, ourPending, hidden := 0, 0, 0, 0
		for _, sub := range k.subs {
			if sub.topicArn != topic {
				continue
			}
			if !sub.tapLost {
				taps++
			}
			if sub.state == subConfirmed {
				ourConfirmed++
			} else {
				ourPending++
			}
		}
		for tuple := range k.hidden {
			if strings.HasPrefix(tuple, topic+"\x00") {
				hidden++
			}
		}
		k.mu.Unlock()
		adjust := func(key string, f func(n int) int) {
			re := regexp.MustCompile(`(<key>` + key + `</key><value>)([0-9]+)(</value>)`)
			body = re.ReplaceAllFunc(body, func(m []byte) []byte {
				sm := re.FindSubmatch(m)
				n, _ := strconv.Atoi(string(sm[2]))
				return []byte(string(sm[1]) + strconv.Itoa(max(0, f(n))) + string(sm[3]))
			})
		}
		adjust("SubscriptionsConfirmed", func(n int) int { return n - taps + ourConfirmed })
		adjust("SubscriptionsPending", func(n int) int { return n - ourConfirmed - hidden })
	}
	writeEngineAnswer(w, status, body, h)
}

// ---- the URLs a subscription carries

func (k *snsSink) publicBase(region string) string {
	if k.rt.selfTLS != "" {
		return "https://sns." + region + ".amazonaws.com"
	}
	return k.s.cfg.BaseURL
}

// The ARNs in the two URLs are written as AWS writes them, unescaped (an ARN here is [A-Za-z0-9_.:-]: shape-checked when the subscription is made).
func (k *snsSink) subscribeURL(sub *snsSub) string {
	return k.publicBase(sub.region) + "/?Action=ConfirmSubscription&TopicArn=" + sub.topicArn + "&Token=" + sub.token
}

func (k *snsSink) unsubscribeURL(sub *snsSub) string {
	return k.publicBase(sub.region) + "/?Action=Unsubscribe&SubscriptionArn=" + sub.arn
}

func (k *snsSink) confirmationFor(sub *snsSub) *snsDelivery {
	return &snsDelivery{kind: "SubscriptionConfirmation", messageID: newUUID(), timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		message: "You have chosen to subscribe to the topic " + sub.topicArn + ".\nTo confirm the subscription, visit the SubscribeURL included in this message.", size: 512}
}

// ---- adopting subscriptions the front did not see Subscribe

// reconcile lists the engine's subscriptions and takes over any http, https or email subscription it did not create through the front (a
// CloudFormation stack's AWS::SNS::Subscription, a seeded one). It runs after the calls that can make them.
func (k *snsSink) reconcile(ctx context.Context, topic string) {
	k.mu.Lock()
	gen := k.baseCtx
	regions := map[string]bool{k.s.cfg.Region: true}
	for r := range k.regions {
		regions[r] = true
	}
	k.mu.Unlock()
	if m := topicArnShape.FindStringSubmatch(topic); m != nil {
		regions = map[string]bool{m[1]: true} // one topic: its own region
	}
	for region := range regions {
		k.reconcileRegion(ctx, gen, region, topic)
	}
}

func (k *snsSink) reconcileRegion(ctx context.Context, gen context.Context, region, topic string) {
	as := ambientAs("sns", region)
	next := ""
	op := "ListSubscriptions"
	if topic != "" {
		op = "ListSubscriptionsByTopic"
	}
	for page := 0; page < 10; page++ {
		params := url.Values{}
		if topic != "" {
			params.Set("TopicArn", topic)
		}
		if next != "" {
			params.Set("NextToken", next)
		}
		status, body, _, err := k.snsQuery(ctx, as, op, params)
		if err != nil || status >= 300 {
			return
		}
		for _, block := range memberRe.FindAll(body, -1) {
			b := string(block)
			protocol, endpoint, topic := sinkXMLField(b, "Protocol"), sinkXMLField(b, "Endpoint"), sinkXMLField(b, "TopicArn")
			if !sinkProtocols[protocol] {
				continue
			}
			tuple := tupleKey(topic, protocol, endpoint)
			k.mu.Lock()
			known := k.byTuple[tuple] != nil || k.hidden[tuple]
			k.mu.Unlock()
			m := topicArnShape.FindStringSubmatch(topic)
			if known || m == nil {
				continue
			}
			t, email, err := k.judgeEndpoint(protocol, endpoint)
			if err != nil {
				k.s.ledger.recordUnsupported("sns", "sink:endpoint-refused", protocol)
				continue
			}
			k.createSub(ctx, gen, topic, protocol, endpoint, m, t, email, nil)
		}
		next = sinkXMLField(string(body), "NextToken")
		if next == "" {
			return
		}
	}
}

// ---- the request that reaches the sink from a link: GET /?Action=ConfirmSubscription or Unsubscribe, with no credential

// isLink: the request is one of the two links an SNS message carries (GET /?Action=..., no Authorization, no Version).
func (k *snsSink) isLink(r *http.Request, q url.Values) bool {
	if r.Method != http.MethodGet || (r.URL.Path != "/" && r.URL.Path != "") || r.Header.Get("Authorization") != "" || q.Get("X-Amz-Credential") != "" {
		return false
	}
	a := q.Get("Action")
	return a == "ConfirmSubscription" || a == "Unsubscribe"
}

// linkRequest answers a link (see isLink). An Unsubscribe of an ARN the sink does not hold is the engine's: here it is a no-op that says so.
func (k *snsSink) linkRequest(w http.ResponseWriter, r *http.Request, q url.Values) {
	switch q.Get("Action") {
	case "ConfirmSubscription":
		k.confirmRequest(w, q)
	case "Unsubscribe":
		if !k.unsubscribe(w, r, q) {
			snsXML(w, 200, snsResponse("Unsubscribe", ""))
		}
	}
}

// statusWriter remembers the status an answer was written with (for the ledger).
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) { s.code = code; s.ResponseWriter.WriteHeader(code) }

// ---- keeping the taps out of the caller's reach

// refusesTapAccess: whether an SQS request names one of the front's tap queues, by its path, its form or query, or the top-level strings of
// its JSON body. Such a request is answered as if the queue did not exist.
func refusesTapAccess(path string, q, form url.Values, jsonBody []byte, cbor bool) bool {
	if strings.Contains(path, snsTapPrefix) {
		return true
	}
	for _, vs := range []url.Values{q, form} {
		for _, v := range vs {
			for _, s := range v {
				if strings.Contains(s, snsTapPrefix) {
					return true
				}
			}
		}
	}
	if cbor && bytes.Contains(jsonBody, []byte(snsTapPrefix)) {
		return true // a CBOR text string is plain UTF-8: the name is in the bytes (a name split across chunks is not caught; it cannot be named without being known)
	}
	if len(jsonBody) > 0 && !cbor {
		var top map[string]json.RawMessage
		if json.Unmarshal(jsonBody, &top) == nil {
			for _, raw := range top {
				var s string
				if json.Unmarshal(raw, &s) == nil && strings.Contains(s, snsTapPrefix) {
					return true
				}
			}
		}
	}
	return false
}

// hideTapQueues removes the front's tap queues from a ListQueues answer (JSON). Anything that is not that shape is returned unchanged.
func hideTapQueues(body []byte) []byte {
	if !bytes.Contains(body, []byte(snsTapPrefix)) {
		return body
	}
	var doc map[string]interface{}
	if json.Unmarshal(body, &doc) != nil {
		return body
	}
	urls, ok := doc["QueueUrls"].([]interface{})
	if !ok {
		return body
	}
	kept := make([]interface{}, 0, len(urls))
	for _, u := range urls {
		if s, _ := u.(string); !strings.Contains(s, snsTapPrefix) {
			kept = append(kept, u)
		}
	}
	doc["QueueUrls"] = kept
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

var _ = sort.Strings

// sinkIntercept is the sink's place in api(): it answers the SNS requests the sink owns, refuses the SQS requests that name a tap queue, and
// runs the reconcile before a Publish when a subscription the front never saw may exist. It reports whether it wrote the answer.
func (s *Server) sinkIntercept(w http.ResponseWriter, r *http.Request, q, form url.Values, body *io.Reader, id identified, done func(int, bool)) bool {
	k := s.sink
	switch id.Service.Key {
	case "sns":
		if id.Proto != protoQuery {
			// while the sink is on, SNS is the Query protocol only (the engine's SNS is Query only: JSON and CBOR are refused by it as well)
			writeAWSError(w, id.Proto, http.StatusBadRequest, "InvalidAction", "SNS is served over the Query protocol only.", "")
			done(http.StatusBadRequest, false)
			return true
		}
		params := paramsOf(q, form)
		if (id.Operation == "Publish" || id.Operation == "PublishBatch") && k.mayHaveUnseen.Load() {
			if t := params.Get("TopicArn"); t != "" {
				k.reconcile(r.Context(), t)
			}
		}
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		if k.handle(sw, r, id.Operation, params, callerAs(id, r)) {
			done(sw.code, false)
			return true
		}
	case "sqs":
		var head []byte
		if id.Proto != protoQuery {
			// the body is read to look at its top-level strings: as much as it is long (SQS bodies are small), at most sqsGuardCap, held against the
			// shared byte budget for the length of the request. A body that is longer, or that is not known to be short, is refused (a request too
			// large to be read for the check is not passed unchecked); a busy front says so (503) instead of guessing.
			if r.ContentLength > sqsGuardCap {
				writeAWSError(w, id.Proto, http.StatusBadRequest, "InvalidParameterValue", "The request is too large.", "")
				done(http.StatusBadRequest, false)
				return true
			}
			n := r.ContentLength
			if n < 0 {
				n = sqsGuardCap
			}
			if !s.budget.reserve(n) {
				writeAWSError(w, id.Proto, http.StatusServiceUnavailable, "ServiceUnavailable", "The local AWS emulator is busy.", "")
				done(http.StatusServiceUnavailable, false)
				return true
			}
			defer s.budget.release(n)
			h, _ := io.ReadAll(io.LimitReader(*body, n+1))
			if int64(len(h)) > n {
				writeAWSError(w, id.Proto, http.StatusBadRequest, "InvalidParameterValue", "The request is too large.", "")
				done(http.StatusBadRequest, false)
				return true
			}
			*body = bytes.NewReader(h)
			head = h
		}
		if refusesTapAccess(r.URL.Path, q, form, head, id.Proto == protoCBOR) {
			code := "QueueDoesNotExist"
			if id.Proto == protoQuery {
				code = "AWS.SimpleQueueService.NonExistentQueue"
			}
			writeAWSError(w, id.Proto, http.StatusBadRequest, code, "The specified queue does not exist.", "")
			done(http.StatusBadRequest, false)
			return true
		}
	}
	return false
}

const sqsGuardCap = 2 << 20

// noteRegion records a region the sink has to look in when it asks the engine about subscriptions with no caller of its own (a seed).
func (k *snsSink) noteRegion(region string) {
	k.mu.Lock()
	k.regions[region] = true
	k.mu.Unlock()
}
