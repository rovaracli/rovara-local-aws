// Package standin is Rovara's model stand-in: a fake SageMaker inference container for a sealed test run. It implements the container contract
// (GET /ping, POST /invocations on port 8080) with a deterministic fake model that has the same request and reply SHAPE as the customer's model,
// described by a config the worker writes. It runs no customer code, makes no outbound connection, holds no secret and never logs a request body.
package standin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// The limits. Every one is a bound on what a request or the config can make the process do.
const (
	ConfigVersion  = 1
	MaxBody        = 6 << 20 // SageMaker's own request and reply limit
	MaxReply       = 6 << 20
	MaxConfigBytes = 1 << 20
	MaxEndpoints   = 16
	MaxListeners   = 4 // the primary listener and up to three per-endpoint ports: the catalog entry lists at most four ports
	MaxModels      = 64
	MaxLatencyMS   = 30_000
	MaxChunks      = 1_000
	MaxElements    = 1 << 18 // numbers or cells one reply may hold
	MaxLabels      = 1_000
	MaxColumns     = 1_000
	MaxFields      = 256
	MaxSchemaNodes = 4_096
	MaxSchemaDepth = 8
	MaxGenNodes    = 100_000 // values one schema reply may generate
	MaxTargetModel = 1_024
)

// Kinds of fake model.
const (
	KindJSONEcho = "json_echo"
	KindFixed    = "fixed"
	KindVector   = "vector"
	KindLabel    = "label"
	KindCSV      = "csv"
	KindSchema   = "schema"
)

// Config is the file the worker writes. Unknown fields are refused, so a misspelt option cannot silently do nothing.
type Config struct {
	Version int `json:"version"`
	// Listen is the primary listener, ":8080" by default (SageMaker's container contract). A non-root user binds it with no extra privilege; the port is always 1024 or above.
	Listen string `json:"listen,omitempty"`
	// Seed makes every generated value a function of (seed, endpoint, model, request): the same run configuration gives the same answers.
	Seed string `json:"seed,omitempty"`
	// DefaultEndpoint answers a request on the primary listener that names no endpoint. Optional when there is exactly one endpoint.
	DefaultEndpoint string               `json:"default_endpoint,omitempty"`
	Endpoints       map[string]*Endpoint `json:"endpoints"`
}

// Endpoint is one SageMaker endpoint's behaviour. Model answers a single-model endpoint (and a multi-model endpoint's request that names no target model);
// Models answers a multi-model endpoint by the X-Amzn-SageMaker-Target-Model header.
type Endpoint struct {
	// Port gives this endpoint a listener of its own (the front forwards to <helper>/invocations and does not say which endpoint, so one address per endpoint works
	// with it as it is). Without it the endpoint is reached on the primary listener by the X-Rovara-Endpoint header or as the default.
	Port   int               `json:"port,omitempty"`
	Model  *Model            `json:"model,omitempty"`
	Models map[string]*Model `json:"models,omitempty"`
}

// Model is one fake model: what it answers and how it misbehaves.
type Model struct {
	Kind string `json:"kind"`
	// ContentType of the reply. Default by kind: application/json (text/csv for csv).
	ContentType string `json:"content_type,omitempty"`
	// Accepts lists the request content types the model takes (media type only, case-insensitive). Empty: any. Another type gets 415, as a real container does.
	Accepts []string `json:"accepts,omitempty"`
	// CustomAttributes is sent back as X-Amzn-SageMaker-Custom-Attributes.
	CustomAttributes string `json:"custom_attributes,omitempty"`

	LatencyMS int `json:"latency_ms,omitempty"`
	JitterMS  int `json:"jitter_ms,omitempty"` // up to this much more, from the seeded sequence
	// ErrorRate is the share of requests that fail (0 to 1), drawn from a sequence seeded by Seed, so a run repeats it. FailFirst fails the first N requests then
	// answers (a retry test). Both answer ErrorStatus (default 500) with {"error": ErrorMessage}.
	ErrorRate    float64 `json:"error_rate,omitempty"`
	FailFirst    int     `json:"fail_first,omitempty"`
	ErrorStatus  int     `json:"error_status,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`

	// Stream splits the reply into chunks of a chunked HTTP reply, a pause between them (SageMaker's streaming containers).
	Stream *Stream `json:"stream,omitempty"`

	// json_echo: the request JSON back (or under Wrap), with Fields added.
	Wrap   string                     `json:"wrap,omitempty"`
	Fields map[string]json.RawMessage `json:"fields,omitempty"`
	// fixed: this body (Body) or this JSON (JSON), whatever the request.
	Body *string         `json:"body,omitempty"`
	JSON json.RawMessage `json:"json,omitempty"`
	// vector: Size numbers per instance, in [Min, Max] (default 0 to 1), rounded to Decimals (default 6), or summing to 1 with Normalize. The instances are the
	// array under InstancesKey ("instances") of the request, or the request itself when it is an array; no array means one instance.
	Size         int      `json:"size,omitempty"`
	Scalar       bool     `json:"scalar,omitempty"` // one number per instance instead of a list (Size must then be 1)
	Min          *float64 `json:"min,omitempty"`
	Max          *float64 `json:"max,omitempty"`
	Decimals     *int     `json:"decimals,omitempty"`
	Normalize    bool     `json:"normalize,omitempty"`
	Key          string   `json:"key,omitempty"` // the reply's field, "predictions"
	InstancesKey string   `json:"instances_key,omitempty"`
	// label: one of Labels per instance, with a score; the reply is {LabelKey, ScoreKey} for one instance or {Key: [...]} for a list; WithProbabilities adds each label's.
	Labels            []string `json:"labels,omitempty"`
	LabelKey          string   `json:"label_key,omitempty"`
	ScoreKey          string   `json:"score_key,omitempty"`
	WithProbabilities bool     `json:"with_probabilities,omitempty"`
	// csv: one output row of Columns numbers (or one of Labels) per input row. SkipHeader drops the input's first row; Header is written first when set.
	Columns    int      `json:"columns,omitempty"`
	SkipHeader bool     `json:"skip_header,omitempty"`
	Header     []string `json:"header,omitempty"`
	// schema: a reply generated from this JSON schema (type, properties, required, items, enum, const, minimum, maximum, minLength, maxLength, minItems, maxItems,
	// format date-time, date, uuid, email, uri, ipv4, oneOf, anyOf, nullable). Every property is generated, so the shape is the same every time.
	Schema json.RawMessage `json:"schema,omitempty"`

	// parsed, not read from the file
	fields map[string]json.RawMessage
	fixed  any
	schema *schemaNode
	min    float64
	max    float64
	dec    int
}

// Stream describes a chunked reply.
type Stream struct {
	Chunks  int `json:"chunks"`
	DelayMS int `json:"delay_ms,omitempty"`
}

var endpointName = regexp.MustCompile(`^[a-zA-Z0-9](-*[a-zA-Z0-9]){0,62}$`)

var mediaType = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)

var identKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// ParseConfig reads and checks a config. It never partly succeeds: any problem is an error naming the field.
func ParseConfig(data []byte) (*Config, error) {
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("config: larger than %d bytes", MaxConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("config: more than one JSON document")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Version != ConfigVersion {
		return fmt.Errorf("config: version must be %d", ConfigVersion)
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if _, err := parsePort(c.Listen); err != nil {
		return fmt.Errorf("config: listen: %w", err)
	}
	if len(c.Seed) > 256 {
		return errors.New("config: seed is longer than 256 bytes")
	}
	if len(c.Endpoints) == 0 || len(c.Endpoints) > MaxEndpoints {
		return fmt.Errorf("config: between 1 and %d endpoints", MaxEndpoints)
	}
	ports := map[int]string{}
	primary, _ := parsePort(c.Listen)
	ports[primary] = "listen"
	for _, name := range c.EndpointNames() {
		ep := c.Endpoints[name]
		if !endpointName.MatchString(name) {
			return fmt.Errorf("config: endpoint %q: not a SageMaker endpoint name", name)
		}
		if ep == nil || (ep.Model == nil && len(ep.Models) == 0) {
			return fmt.Errorf("config: endpoint %q: needs model or models", name)
		}
		if ep.Port != 0 {
			if ep.Port < 1024 || ep.Port > 65535 {
				return fmt.Errorf("config: endpoint %q: port must be 1024 to 65535", name)
			}
			if other, dup := ports[ep.Port]; dup {
				return fmt.Errorf("config: endpoint %q: port %d is already used by %s", name, ep.Port, other)
			}
			ports[ep.Port] = "endpoint " + name
		}
		if ep.Model != nil {
			if err := ep.Model.validate(); err != nil {
				return fmt.Errorf("config: endpoint %q: model: %w", name, err)
			}
		}
		if len(ep.Models) > MaxModels {
			return fmt.Errorf("config: endpoint %q: more than %d models", name, MaxModels)
		}
		for target, m := range ep.Models {
			if target == "" || len(target) > MaxTargetModel || strings.ContainsAny(target, "\r\n\x00") {
				return fmt.Errorf("config: endpoint %q: a target model name is empty, too long or has a control character", name)
			}
			if m == nil {
				return fmt.Errorf("config: endpoint %q: model %q is empty", name, target)
			}
			if err := m.validate(); err != nil {
				return fmt.Errorf("config: endpoint %q: model %q: %w", name, target, err)
			}
		}
	}
	if len(ports) > MaxListeners {
		return fmt.Errorf("config: more than %d listeners (the primary one and the endpoints' own ports)", MaxListeners)
	}
	if c.DefaultEndpoint != "" {
		if _, ok := c.Endpoints[c.DefaultEndpoint]; !ok {
			return fmt.Errorf("config: default_endpoint %q is not an endpoint", c.DefaultEndpoint)
		}
	} else if len(c.Endpoints) == 1 {
		c.DefaultEndpoint = c.EndpointNames()[0]
	}
	return nil
}

// EndpointNames are the endpoints' names, sorted.
func (c *Config) EndpointNames() []string {
	names := make([]string, 0, len(c.Endpoints))
	for name := range c.Endpoints {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parsePort(listen string) (int, error) {
	i := strings.LastIndex(listen, ":")
	if i < 0 {
		return 0, errors.New("must be host:port or :port")
	}
	host := listen[:i]
	if host != "" && host != "0.0.0.0" && host != "[::]" {
		// the stand-in listens on all addresses of its own container, which on the run's services network is one address; a named host would only invite a typo
		return 0, errors.New("must be :port (all addresses of the container)")
	}
	var port int
	if _, err := fmt.Sscanf(listen[i+1:], "%d", &port); err != nil || port < 1024 || port > 65535 || fmt.Sprint(port) != listen[i+1:] {
		return 0, errors.New("the port is not 1024 to 65535")
	}
	return port, nil
}

func (m *Model) validate() error {
	switch m.Kind {
	case KindJSONEcho, KindFixed, KindVector, KindLabel, KindCSV, KindSchema:
	default:
		return fmt.Errorf("kind %q is not one of json_echo, fixed, vector, label, csv, schema", m.Kind)
	}
	if m.ContentType != "" && !mediaType.MatchString(strings.ToLower(m.ContentType)) {
		return errors.New("content_type is not a media type")
	}
	if len(m.Accepts) > 16 {
		return errors.New("more than 16 accepts")
	}
	for _, a := range m.Accepts {
		if !mediaType.MatchString(strings.ToLower(a)) {
			return fmt.Errorf("accepts %q is not a media type", a)
		}
	}
	if len(m.CustomAttributes) > 1024 || strings.ContainsAny(m.CustomAttributes, "\r\n\x00") {
		return errors.New("custom_attributes is longer than 1024 bytes or has a control character")
	}
	if m.LatencyMS < 0 || m.JitterMS < 0 || m.LatencyMS+m.JitterMS > MaxLatencyMS {
		return fmt.Errorf("latency_ms plus jitter_ms must be 0 to %d", MaxLatencyMS)
	}
	if math.IsNaN(m.ErrorRate) || m.ErrorRate < 0 || m.ErrorRate > 1 {
		return errors.New("error_rate must be 0 to 1")
	}
	if m.FailFirst < 0 || m.FailFirst > 1_000_000 {
		return errors.New("fail_first must be 0 to 1000000")
	}
	if m.ErrorStatus == 0 {
		m.ErrorStatus = 500
	}
	if m.ErrorStatus < 400 || m.ErrorStatus > 599 {
		return errors.New("error_status must be 400 to 599")
	}
	if len(m.ErrorMessage) > 512 || strings.ContainsAny(m.ErrorMessage, "\x00") {
		return errors.New("error_message is longer than 512 bytes")
	}
	if m.ErrorMessage == "" {
		m.ErrorMessage = "Rovara model stand-in: configured error"
	}
	if m.Stream != nil && (m.Stream.Chunks < 1 || m.Stream.Chunks > MaxChunks || m.Stream.DelayMS < 0 || m.Stream.DelayMS > 10_000) {
		return fmt.Errorf("stream: chunks 1 to %d and delay_ms 0 to 10000", MaxChunks)
	}
	if m.Stream != nil && m.Stream.DelayMS*m.Stream.Chunks > MaxLatencyMS {
		return fmt.Errorf("stream: delay_ms times chunks is over %d", MaxLatencyMS)
	}
	for _, key := range []string{m.Wrap, m.Key, m.InstancesKey, m.LabelKey, m.ScoreKey} {
		if key != "" && !identKey.MatchString(key) {
			return fmt.Errorf("the name %q is not a plain field name", key)
		}
	}
	// A field of another kind is a mistake, not a no-op.
	set := func(names ...string) []string { return names }
	used := map[string]bool{
		"wrap": m.Wrap != "", "fields": m.Fields != nil, "body": m.Body != nil, "json": m.JSON != nil, "size": m.Size != 0, "scalar": m.Scalar, "min": m.Min != nil, "max": m.Max != nil,
		"decimals": m.Decimals != nil, "normalize": m.Normalize, "key": m.Key != "", "instances_key": m.InstancesKey != "", "labels": m.Labels != nil, "label_key": m.LabelKey != "",
		"score_key": m.ScoreKey != "", "with_probabilities": m.WithProbabilities, "columns": m.Columns != 0, "skip_header": m.SkipHeader, "header": m.Header != nil, "schema": m.Schema != nil,
	}
	allowed := map[string][]string{
		KindJSONEcho: set("wrap", "fields"),
		KindFixed:    set("body", "json"),
		KindVector:   set("size", "scalar", "min", "max", "decimals", "normalize", "key", "instances_key"),
		KindLabel:    set("labels", "label_key", "score_key", "key", "instances_key", "with_probabilities", "decimals", "min", "max"),
		KindCSV:      set("columns", "skip_header", "header", "labels", "decimals", "min", "max"),
		KindSchema:   set("schema"),
	}[m.Kind]
	ok := map[string]bool{}
	for _, name := range allowed {
		ok[name] = true
	}
	for name, isSet := range used {
		if isSet && !ok[name] {
			return fmt.Errorf("%s does not apply to kind %s", name, m.Kind)
		}
	}
	m.min, m.max, m.dec = 0, 1, 6
	if m.Min != nil {
		m.min = *m.Min
	}
	if m.Max != nil {
		m.max = *m.Max
	}
	if math.IsNaN(m.min) || math.IsNaN(m.max) || math.IsInf(m.min, 0) || math.IsInf(m.max, 0) || m.min > m.max {
		return errors.New("min and max must be finite numbers with min <= max")
	}
	if m.Decimals != nil {
		if *m.Decimals < 0 || *m.Decimals > 12 {
			return errors.New("decimals must be 0 to 12")
		}
		m.dec = *m.Decimals
	}
	switch m.Kind {
	case KindJSONEcho:
		if len(m.Fields) > MaxFields {
			return fmt.Errorf("more than %d fields", MaxFields)
		}
		m.fields = map[string]json.RawMessage{}
		for name, raw := range m.Fields {
			if !identKey.MatchString(name) {
				return fmt.Errorf("the field name %q is not a plain field name", name)
			}
			if !json.Valid(raw) {
				return fmt.Errorf("field %q is not JSON", name)
			}
			m.fields[name] = raw
		}
	case KindFixed:
		if (m.Body == nil) == (m.JSON == nil) {
			return errors.New("fixed needs exactly one of body and json")
		}
		if m.Body != nil && len(*m.Body) > MaxReply {
			return errors.New("body is over 6 MiB")
		}
		if m.JSON != nil {
			if len(m.JSON) > MaxReply || json.Unmarshal(m.JSON, &m.fixed) != nil {
				return errors.New("json is over 6 MiB or not JSON")
			}
		}
	case KindVector:
		if m.Size < 1 || m.Size > MaxElements {
			return fmt.Errorf("size must be 1 to %d", MaxElements)
		}
		if m.Scalar && m.Size != 1 {
			return errors.New("scalar needs size 1")
		}
	case KindLabel:
		if len(m.Labels) < 1 || len(m.Labels) > MaxLabels {
			return fmt.Errorf("labels: 1 to %d", MaxLabels)
		}
		if err := checkLabels(m.Labels); err != nil {
			return err
		}
	case KindCSV:
		if (m.Columns == 0) == (len(m.Labels) == 0) {
			return errors.New("csv needs exactly one of columns and labels")
		}
		if m.Columns < 0 || m.Columns > MaxColumns {
			return fmt.Errorf("columns: 1 to %d", MaxColumns)
		}
		if len(m.Labels) > MaxLabels {
			return fmt.Errorf("labels: at most %d", MaxLabels)
		}
		if err := checkLabels(m.Labels); err != nil {
			return err
		}
		if len(m.Header) > MaxColumns || (m.Columns > 0 && m.Header != nil && len(m.Header) != m.Columns) || (len(m.Labels) > 0 && m.Header != nil && len(m.Header) != 1) {
			return errors.New("header must name every output column")
		}
	case KindSchema:
		if m.Schema == nil {
			return errors.New("schema kind needs schema")
		}
		node, err := parseSchema(m.Schema)
		if err != nil {
			return fmt.Errorf("schema: %w", err)
		}
		m.schema = node
	}
	if m.Key == "" {
		m.Key = "predictions"
	}
	if m.InstancesKey == "" {
		m.InstancesKey = "instances"
	}
	if m.LabelKey == "" {
		m.LabelKey = "label"
	}
	if m.ScoreKey == "" {
		m.ScoreKey = "score"
	}
	if m.ContentType == "" {
		if m.Kind == KindCSV {
			m.ContentType = "text/csv"
		} else {
			m.ContentType = "application/json"
		}
	}
	return nil
}

func checkLabels(labels []string) error {
	seen := map[string]bool{}
	for _, l := range labels {
		if l == "" || len(l) > 256 || strings.ContainsAny(l, "\x00") || seen[l] {
			return errors.New("a label is empty, longer than 256 bytes, has a NUL or is repeated")
		}
		seen[l] = true
	}
	return nil
}
