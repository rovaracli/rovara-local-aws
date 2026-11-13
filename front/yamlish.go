package main

import (
	"errors"
	"strings"
)

// parseYAMLish reads the subset of YAML a CloudFormation template is written in, into maps ([string]any), lists ([]any) and
// strings: block mappings and sequences, plain and quoted scalars, flow sequences and one-level flow mappings, block scalars
// (their text is kept), comments, and the short tags of intrinsic functions (!Ref X becomes {"Ref": "X"}, any other tag keeps its
// scalar as a string). It is not a YAML parser: anchors, merge keys, multi-document streams and flow collections nested in
// flow collections are refused (an error), and the caller then treats the template as unreadable. Bounded: at most maxYAMLLines
// lines and a nesting depth of 64.
const maxYAMLLines = 200000

type yline struct {
	indent int
	text   string
}

var errYAML = errors.New("not a template this reader understands")

func parseYAMLish(src string) (any, error) {
	var lines []yline
	raw := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	if len(raw) > maxYAMLLines {
		return nil, errYAML
	}
	for i := 0; i < len(raw); i++ {
		l := raw[i]
		trim := strings.TrimLeft(l, " ")
		if strings.HasPrefix(trim, "\t") || trim == "" || strings.HasPrefix(trim, "#") || trim == "---" {
			continue
		}
		indent := len(l) - len(trim)
		trim = stripComment(strings.TrimRight(trim, " \t"))
		if strings.HasSuffix(trim, "|") || strings.HasSuffix(trim, ">") || strings.HasSuffix(trim, "|-") || strings.HasSuffix(trim, ">-") ||
			strings.HasSuffix(trim, "|+") || strings.HasSuffix(trim, ">+") {
			// a block scalar: the more indented lines that follow are its text
			key := strings.TrimRight(trim, "|>-+ ")
			var text []string
			for i+1 < len(raw) {
				n := raw[i+1]
				nt := strings.TrimLeft(n, " ")
				if nt != "" && len(n)-len(nt) <= indent {
					break
				}
				text = append(text, nt)
				i++
			}
			lines = append(lines, yline{indent, key + " " + quoteBlock(strings.Join(text, "\n"))})
			continue
		}
		lines = append(lines, yline{indent, trim})
	}
	if len(lines) == 0 {
		return nil, errYAML
	}
	p := &yparser{lines: lines}
	v, err := p.block(lines[0].indent, 0)
	if err != nil || p.pos != len(lines) {
		return nil, errYAML
	}
	return v, nil
}

// quoteBlock marks a block scalar's text so the line reader takes it whole: the text goes after the key as a JSON-ish quoted string.
func quoteBlock(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + strings.ReplaceAll(s, "\n", `\n`) + `"`
}

func stripComment(s string) string {
	in := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in != 0:
			if c == in {
				in = 0
			}
		case c == '"' || c == '\'':
			in = c
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return strings.TrimRight(s[:i], " ")
		}
	}
	return s
}

type yparser struct {
	lines []yline
	pos   int
}

func (p *yparser) block(indent, depth int) (any, error) {
	if depth > 64 || p.pos >= len(p.lines) {
		return nil, errYAML
	}
	if strings.HasPrefix(p.lines[p.pos].text, "- ") || p.lines[p.pos].text == "-" {
		return p.sequence(indent, depth)
	}
	return p.mapping(indent, depth)
}

func (p *yparser) sequence(indent, depth int) (any, error) {
	var out []any
	for p.pos < len(p.lines) && p.lines[p.pos].indent == indent && (strings.HasPrefix(p.lines[p.pos].text, "- ") || p.lines[p.pos].text == "-") {
		rest := strings.TrimSpace(strings.TrimPrefix(p.lines[p.pos].text, "-"))
		if rest == "" {
			p.pos++
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				v, err := p.block(p.lines[p.pos].indent, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		if k, _, ok := splitKey(rest); ok && k != "" && !strings.HasPrefix(rest, "{") && !strings.HasPrefix(rest, "[") && !strings.HasPrefix(rest, "\"") {
			// "- key: value": the rest of the line starts a mapping whose later keys are indented to the key
			col := indent + len(p.lines[p.pos].text) - len(rest)
			p.lines[p.pos] = yline{col, rest}
			v, err := p.mapping(col, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		v, err := scalarOrFlow(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.pos++
	}
	return out, nil
}

func splitKey(s string) (key, rest string, ok bool) {
	in := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in != 0:
			if c == in {
				in = 0
			}
		case c == '"' || c == '\'':
			in = c
		case c == ':' && (i+1 == len(s) || s[i+1] == ' '):
			return strings.Trim(strings.TrimSpace(s[:i]), `"'`), strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

func (p *yparser) mapping(indent, depth int) (any, error) {
	out := map[string]any{}
	for p.pos < len(p.lines) && p.lines[p.pos].indent == indent {
		k, rest, ok := splitKey(p.lines[p.pos].text)
		if !ok {
			return nil, errYAML
		}
		p.pos++
		if rest == "" {
			if p.pos < len(p.lines) && (p.lines[p.pos].indent > indent ||
				(p.lines[p.pos].indent == indent && strings.HasPrefix(p.lines[p.pos].text, "- "))) {
				v, err := p.block(p.lines[p.pos].indent, depth+1)
				if err != nil {
					return nil, err
				}
				out[k] = v
			} else {
				out[k] = nil
			}
			continue
		}
		v, err := scalarOrFlow(rest)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, errYAML
	}
	return out, nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"') {
		r := strings.NewReplacer(`\n`, "\n", `\"`, `"`, `\\`, `\`)
		return r.Replace(s[1 : len(s)-1])
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

func scalarOrFlow(s string) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "&") || strings.HasPrefix(s, "*") || strings.HasPrefix(s, "<<"):
		return nil, errYAML
	case strings.HasPrefix(s, "!Ref "):
		return map[string]any{"Ref": unquote(strings.TrimSpace(s[5:]))}, nil
	case strings.HasPrefix(s, "!"):
		if i := strings.Index(s, " "); i > 0 {
			return unquote(strings.TrimSpace(s[i:])), nil
		}
		return "", nil
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") {
			return nil, errYAML
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if strings.ContainsAny(inner, "[]{}") && !strings.Contains(inner, "!") {
			return nil, errYAML
		}
		var out []any
		if inner == "" {
			return out, nil
		}
		for _, part := range splitFlow(inner) {
			v, err := scalarOrFlow(part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case strings.HasPrefix(s, "{"):
		if !strings.HasSuffix(s, "}") || strings.ContainsAny(s[1:len(s)-1], "[]{}") {
			return nil, errYAML
		}
		out := map[string]any{}
		for _, part := range splitFlow(strings.TrimSpace(s[1 : len(s)-1])) {
			k, rest, ok := splitKey(part)
			if !ok {
				return nil, errYAML
			}
			v, err := scalarOrFlow(rest)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	}
	return unquote(s), nil
}

func splitFlow(s string) []string {
	var parts []string
	in, start := byte(0), 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in != 0:
			if c == in {
				in = 0
			}
		case c == '"' || c == '\'':
			in = c
		case c == ',':
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(parts, strings.TrimSpace(s[start:]))
}
