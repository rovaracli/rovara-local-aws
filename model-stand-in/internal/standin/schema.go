package standin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
)

// A schemaNode is the subset of JSON Schema the "schema" kind can generate from. Anything outside the subset is refused when the config is read, so a
// constraint the generator would ignore (a pattern, a dependency) is never silently dropped.
type schemaNode struct {
	types        []string // "string", "number", "integer", "boolean", "null", "object", "array"
	props        map[string]*schemaNode
	propOrder    []string
	items        *schemaNode
	enum         []any
	enumSizes    []int // the JSON size of each enum value, counted when a reply is generated
	hasConst     bool
	constVal     any
	constSize    int
	min, max     *float64
	exMin, exMax bool
	minLen       int
	maxLen       int
	minItems     int
	maxItems     int
	format       string
	alts         []*schemaNode // oneOf or anyOf: one of them
}

var schemaKeywords = map[string]bool{
	"type": true, "properties": true, "items": true, "enum": true, "const": true, "minimum": true, "maximum": true, "exclusiveMinimum": true, "exclusiveMaximum": true,
	"minLength": true, "maxLength": true, "minItems": true, "maxItems": true, "format": true, "oneOf": true, "anyOf": true,
	// OpenAPI's nullable: the type stays the one generated, so the shape is the same every time
	"nullable": true, "required": true,
	// annotations that change nothing
	"title": true, "description": true, "default": true, "examples": true, "example": true, "$schema": true, "$id": true, "$comment": true, "additionalProperties": true,
}

var knownFormats = map[string]bool{"date-time": true, "date": true, "uuid": true, "email": true, "uri": true, "ipv4": true}

func parseSchema(raw json.RawMessage) (*schemaNode, error) {
	var count int
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("not JSON")
	}
	return buildSchema(v, 0, &count)
}

func buildSchema(v any, depth int, count *int) (*schemaNode, error) {
	if depth > MaxSchemaDepth {
		return nil, fmt.Errorf("deeper than %d levels", MaxSchemaDepth)
	}
	*count++
	if *count > MaxSchemaNodes {
		return nil, fmt.Errorf("more than %d nodes", MaxSchemaNodes)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("a schema is a JSON object")
	}
	n := &schemaNode{}
	for key := range obj {
		if !schemaKeywords[key] {
			if key == "pattern" {
				return nil, errors.New("pattern is not supported (a value matching a regular expression cannot be generated); use enum, format or lengths")
			}
			return nil, fmt.Errorf("the keyword %q is not supported", key)
		}
	}
	switch t := obj["type"].(type) {
	case nil:
	case string:
		n.types = []string{t}
	case []any:
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, errors.New("type is a name or a list of names")
			}
			n.types = append(n.types, s)
		}
	default:
		return nil, errors.New("type is a name or a list of names")
	}
	for _, t := range n.types {
		switch t {
		case "string", "number", "integer", "boolean", "null", "object", "array":
		default:
			return nil, fmt.Errorf("type %q is not a JSON Schema type", t)
		}
	}
	if props, ok := obj["properties"]; ok {
		pm, ok := props.(map[string]any)
		if !ok || len(pm) > MaxFields {
			return nil, fmt.Errorf("properties is an object of at most %d properties", MaxFields)
		}
		n.props = map[string]*schemaNode{}
		for name := range pm {
			n.propOrder = append(n.propOrder, name)
		}
		sort.Strings(n.propOrder)
		for _, name := range n.propOrder {
			child, err := buildSchema(pm[name], depth+1, count)
			if err != nil {
				return nil, fmt.Errorf("property %q: %w", name, err)
			}
			n.props[name] = child
		}
	}
	if it, ok := obj["items"]; ok {
		child, err := buildSchema(it, depth+1, count)
		if err != nil {
			return nil, fmt.Errorf("items: %w", err)
		}
		n.items = child
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		if list, ok := obj[key]; ok {
			arr, ok := list.([]any)
			if !ok || len(arr) == 0 || len(arr) > 32 || len(n.alts) > 0 {
				return nil, fmt.Errorf("%s is one list of 1 to 32 schemas", key)
			}
			for _, a := range arr {
				child, err := buildSchema(a, depth+1, count)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				n.alts = append(n.alts, child)
			}
		}
	}
	if e, ok := obj["enum"]; ok {
		arr, ok := e.([]any)
		if !ok || len(arr) == 0 || len(arr) > 1000 {
			return nil, errors.New("enum is a list of 1 to 1000 values")
		}
		n.enum = arr
		for _, v := range arr {
			n.enumSizes = append(n.enumSizes, jsonSize(v))
		}
	}
	if c, ok := obj["const"]; ok {
		n.hasConst, n.constVal, n.constSize = true, c, jsonSize(c)
	}
	num := func(key string) (*float64, error) {
		raw, ok := obj[key]
		if !ok {
			return nil, nil
		}
		jn, ok := raw.(json.Number)
		if !ok {
			return nil, fmt.Errorf("%s is a number", key)
		}
		f, err := jn.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("%s is a finite number", key)
		}
		return &f, nil
	}
	var err error
	if n.min, err = num("minimum"); err != nil {
		return nil, err
	}
	if n.max, err = num("maximum"); err != nil {
		return nil, err
	}
	if lo, err := num("exclusiveMinimum"); err != nil {
		return nil, err
	} else if lo != nil {
		n.min, n.exMin = lo, true
	}
	if hi, err := num("exclusiveMaximum"); err != nil {
		return nil, err
	} else if hi != nil {
		n.max, n.exMax = hi, true
	}
	if n.min != nil && n.max != nil && *n.min > *n.max {
		return nil, errors.New("minimum is above maximum")
	}
	count64 := func(key string, def, hi int) (int, error) {
		raw, ok := obj[key]
		if !ok {
			return def, nil
		}
		jn, ok := raw.(json.Number)
		if !ok {
			return 0, fmt.Errorf("%s is a whole number", key)
		}
		i, err := jn.Int64()
		if err != nil || i < 0 || i > int64(hi) {
			return 0, fmt.Errorf("%s is a whole number from 0 to %d", key, hi)
		}
		return int(i), nil
	}
	if n.minLen, err = count64("minLength", 0, 10_000); err != nil {
		return nil, err
	}
	if n.maxLen, err = count64("maxLength", -1, 10_000); err != nil {
		return nil, err
	}
	if n.minItems, err = count64("minItems", 0, 100); err != nil {
		return nil, err
	}
	if n.maxItems, err = count64("maxItems", -1, 100); err != nil {
		return nil, err
	}
	if (n.maxLen >= 0 && n.minLen > n.maxLen) || (n.maxItems >= 0 && n.minItems > n.maxItems) {
		return nil, errors.New("a minimum length or count is above its maximum")
	}
	if f, ok := obj["format"]; ok {
		s, _ := f.(string)
		if !knownFormats[s] {
			return nil, fmt.Errorf("format %q is not one of date-time, date, uuid, email, uri, ipv4", s)
		}
		n.format = s
	}
	return n, nil
}

// jsonSize is the size of a value as it is written in a reply (a value that cannot be written counts as large, so it is refused).
func jsonSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return MaxReply + 1
	}
	return len(b)
}

// generator makes values from a schema, from a seeded sequence, with a bound on how many values and on how many BYTES one reply may hold: every value is counted in the meter before it is
// built, so a schema that fans out (minItems 100 at every level, strings of 10,000 characters) is refused as soon as it passes 6 MiB, not after the whole tree is in memory.
type generator struct {
	rng   *rand.Rand
	nodes int
	m     *meter
}

// Sizes of values as they are written; a number counts its worst case.
const (
	sizeNull   = 4
	sizeBool   = 5
	sizeInt    = 20
	sizeNumber = 24
)

var words = []string{"alpha", "bravo", "cedar", "delta", "ember", "falcon", "garnet", "harbor", "iris", "juniper", "kestrel", "lumen", "maple", "nimbus", "onyx", "pebble", "quartz", "ridge", "sable", "tundra"}

func (g *generator) generate(n *schemaNode) (any, error) {
	g.nodes++
	if g.nodes > MaxGenNodes {
		return nil, errors.New("the generated reply would be too large")
	}
	if len(n.alts) > 0 {
		return g.generate(n.alts[g.rng.IntN(len(n.alts))])
	}
	if n.hasConst {
		if err := g.m.add(n.constSize + 1); err != nil {
			return nil, err
		}
		return n.constVal, nil
	}
	if len(n.enum) > 0 {
		i := g.rng.IntN(len(n.enum))
		if err := g.m.add(n.enumSizes[i] + 1); err != nil {
			return nil, err
		}
		return n.enum[i], nil
	}
	t := ""
	if len(n.types) > 0 {
		t = n.types[0] // the first type is the shape: the same every time
		for _, c := range n.types {
			if c != "null" {
				t = c
				break
			}
		}
	} else if n.props != nil {
		t = "object"
	} else if n.items != nil {
		t = "array"
	} else {
		t = "string"
	}
	switch t {
	case "null":
		return nil, g.m.add(sizeNull + 1)
	case "boolean":
		if err := g.m.add(sizeBool + 1); err != nil {
			return nil, err
		}
		return g.rng.IntN(2) == 1, nil
	case "integer":
		if err := g.m.add(sizeInt + 1); err != nil {
			return nil, err
		}
		lo, hi := int64(0), int64(1000)
		if n.min != nil {
			lo = int64(math.Ceil(*n.min))
			if n.exMin && float64(lo) <= *n.min {
				lo++
			}
			if n.max == nil {
				hi = lo + 1000
			}
		}
		if n.max != nil {
			hi = int64(math.Floor(*n.max))
			if n.exMax && float64(hi) >= *n.max {
				hi--
			}
			if n.min == nil {
				lo = hi - 1000
			}
		}
		if hi < lo {
			return nil, errors.New("an integer range holds no integer")
		}
		span := uint64(hi-lo) + 1
		if span == 0 {
			span = math.MaxUint64
		}
		return lo + int64(g.rng.Uint64N(span)), nil
	case "number":
		if err := g.m.add(sizeNumber + 1); err != nil {
			return nil, err
		}
		lo, hi := 0.0, 1.0
		if n.min != nil {
			lo = *n.min
			if n.max == nil {
				hi = lo + 1
			}
		}
		if n.max != nil {
			hi = *n.max
			if n.min == nil {
				lo = hi - 1
			}
		}
		v := lo + g.rng.Float64()*(hi-lo)
		if (n.exMin && v <= lo) || (n.exMax && v >= hi) {
			v = lo + (hi-lo)/2
		}
		return math.Round(v*1e6) / 1e6, nil
	case "string":
		return g.str(n)
	case "array":
		count := n.minItems
		if n.maxItems >= 0 {
			if n.maxItems > count {
				count += g.rng.IntN(n.maxItems - count + 1)
			}
		} else {
			count += g.rng.IntN(3)
		}
		if n.maxItems < 0 && count == 0 {
			count = 1
		}
		if err := g.m.add(2); err != nil {
			return nil, err
		}
		out := make([]any, 0, count)
		for i := 0; i < count; i++ {
			if n.items == nil {
				v, err := g.str(&schemaNode{maxLen: -1})
				if err != nil {
					return nil, err
				}
				out = append(out, v)
				continue
			}
			v, err := g.generate(n.items)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case "object":
		if err := g.m.add(2); err != nil {
			return nil, err
		}
		out := map[string]any{}
		for _, name := range n.propOrder {
			if err := g.m.add(len(name) + 4); err != nil {
				return nil, err
			}
			v, err := g.generate(n.props[name])
			if err != nil {
				return nil, err
			}
			out[name] = v
		}
		return out, nil
	}
	return nil, nil
}

// str generates one string and counts its bytes BEFORE it is built.
func (g *generator) str(n *schemaNode) (string, error) {
	if n.format != "" {
		if err := g.m.add(48); err != nil { // the longest format (a uri) is under 48 bytes with its quotes and comma
			return "", err
		}
	}
	switch n.format {
	case "uuid":
		b := make([]byte, 16)
		for i := range b {
			b[i] = byte(g.rng.UintN(256))
		}
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
	case "date-time":
		return fmt.Sprintf("2026-%02d-%02dT%02d:%02d:%02dZ", 1+g.rng.IntN(12), 1+g.rng.IntN(28), g.rng.IntN(24), g.rng.IntN(60), g.rng.IntN(60)), nil
	case "date":
		return fmt.Sprintf("2026-%02d-%02d", 1+g.rng.IntN(12), 1+g.rng.IntN(28)), nil
	case "email":
		return fmt.Sprintf("%s.%s@example.com", words[g.rng.IntN(len(words))], words[g.rng.IntN(len(words))]), nil
	case "uri":
		return fmt.Sprintf("https://example.com/%s/%d", words[g.rng.IntN(len(words))], g.rng.IntN(10_000)), nil
	case "ipv4":
		return fmt.Sprintf("192.0.2.%d", 1+g.rng.IntN(254)), nil
	}
	target := n.minLen
	if n.maxLen >= 0 && n.maxLen > n.minLen {
		target += g.rng.IntN(n.maxLen - n.minLen + 1)
	} else if n.maxLen < 0 {
		target += 5 + g.rng.IntN(10)
	}
	// the words overshoot the target by at most one word; the quotes and the comma are three more bytes
	if err := g.m.add(target + 8 + 3); err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(target + 8)
	for b.Len() < target {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(words[g.rng.IntN(len(words))])
	}
	s := b.String()
	if n.maxLen >= 0 && len(s) > n.maxLen {
		s = strings.TrimRight(s[:n.maxLen], " ")
		if len(s) < n.minLen {
			s += strings.Repeat("x", n.minLen-len(s))
		}
	}
	return s, nil
}
