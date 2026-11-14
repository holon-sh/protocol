package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

const draft = "https://json-schema.org/draft/2020-12/schema"

// singleLine is the pattern a SingleLine text must not match.
const singleLine = `[\x00\r\n]`

// patternFeatures are the regular expression features outside the subset that RE2 and ECMA-262 share, or that ECMA-262
// reads only with the u flag.
var patternFeatures = []string{`\A`, `\z`, `\Q`, `\E`, `\C`, `\p`, `\P`, `\x{`, `[[:`}

// Schema writes a JSON Schema 2020-12 document whose root is root and whose $defs also hold defs, which must be named.
// It uses local $defs only, and patterns that RE2 and ECMA-262 read alike.
func Schema(root Rule, description string, defs ...Rule) ([]byte, error) {
	e := emitter{defs: map[string]any{}}
	document, err := e.body(root)
	if err != nil {
		return nil, err
	}
	for _, def := range defs {
		if def.name() == "" {
			return nil, fmt.Errorf("an extra definition needs a name")
		}
		if _, err := e.schema(def); err != nil {
			return nil, err
		}
	}
	document["$schema"] = draft
	if root.name() != "" {
		document["title"] = root.name()
	}
	if description != "" {
		document["description"] = description
	}
	if len(e.defs) > 0 {
		document["$defs"] = e.defs
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type emitter struct{ defs map[string]any }

// schema is a reference to a named rule, which it adds to $defs, or else the rule's own schema.
func (e *emitter) schema(r Rule) (map[string]any, error) {
	name := r.name()
	if name == "" {
		return e.body(r)
	}
	body, err := e.body(r)
	if err != nil {
		return nil, err
	}
	if defined, exists := e.defs[name]; exists {
		before, _ := json.Marshal(defined)
		after, _ := json.Marshal(body)
		if !bytes.Equal(before, after) {
			return nil, fmt.Errorf("two rules are named %s", name)
		}
	}
	e.defs[name] = body
	return map[string]any{"$ref": "#/$defs/" + name}, nil
}

func (e *emitter) body(r Rule) (map[string]any, error) {
	switch r := r.(type) {
	case Text:
		return text(r)
	case Integer:
		s := map[string]any{"type": "integer"}
		if r.Min != nil {
			s["minimum"] = *r.Min
		}
		if r.Max != nil {
			s["maximum"] = *r.Max
		}
		return s, nil
	case Enumeration:
		return map[string]any{"type": "string", "enum": r.Values}, nil
	case List:
		item, err := e.schema(r.Item)
		if err != nil {
			return nil, err
		}
		s := map[string]any{"type": "array", "items": item}
		if r.MinItems > 0 {
			s["minItems"] = r.MinItems
		}
		if r.MaxItems > 0 {
			s["maxItems"] = r.MaxItems
		}
		if r.Set {
			s["uniqueItems"] = true
		}
		return s, nil
	case Map:
		key, err := e.schema(r.Key)
		if err != nil {
			return nil, err
		}
		value, err := e.schema(r.Value)
		if err != nil {
			return nil, err
		}
		s := map[string]any{"type": "object", "additionalProperties": value}
		if len(key) > 1 || key["type"] != "string" {
			s["propertyNames"] = key
		}
		if r.MaxEntries > 0 {
			s["maxProperties"] = r.MaxEntries
		}
		return s, nil
	case Object:
		return e.object(r)
	case Opaque:
		return map[string]any{}, nil
	}
	return nil, fmt.Errorf("rule %T is not a kind of the model", r)
}

func text(r Text) (map[string]any, error) {
	s := map[string]any{"type": "string"}
	// JSON Schema counts characters, and a character takes from one to four bytes.
	if r.MinBytes > 0 {
		s["minLength"] = (r.MinBytes + 3) / 4
	}
	if r.MaxBytes > 0 {
		s["maxLength"] = r.MaxBytes
	}
	if r.Pattern != "" {
		if err := checkPattern(r.Pattern); err != nil {
			return nil, err
		}
		s["pattern"] = r.Pattern
	}
	var excluded []any
	if len(r.Excluded) > 0 {
		excluded = append(excluded, map[string]any{"enum": r.Excluded})
	}
	if r.SingleLine {
		excluded = append(excluded, map[string]any{"pattern": singleLine})
	}
	switch len(excluded) {
	case 1:
		s["not"] = excluded[0]
	case 2:
		s["not"] = map[string]any{"anyOf": excluded}
	}
	return s, nil
}

func checkPattern(pattern string) error {
	if _, err := regexp.Compile(pattern); err != nil {
		return err
	}
	for _, feature := range patternFeatures {
		if strings.Contains(pattern, feature) {
			return fmt.Errorf("pattern %q uses %s, which ECMA-262 does not read as RE2 does", pattern, feature)
		}
	}
	if strings.Contains(strings.ReplaceAll(pattern, "(?:", ""), "(?") {
		return fmt.Errorf("pattern %q uses a group flag, which ECMA-262 does not read as RE2 does", pattern)
	}
	return nil
}

func (e *emitter) object(r Object) (map[string]any, error) {
	properties := map[string]any{}
	required := []string{}
	for _, member := range r.Members {
		s, err := e.schema(member.Rule)
		if err != nil {
			return nil, fmt.Errorf("member %s: %w", member.Name, err)
		}
		if member.Description != "" {
			s["description"] = member.Description
		}
		properties[member.Name] = s
		if member.Required {
			required = append(required, member.Name)
		}
	}
	s := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	var unions []any
	for _, union := range r.Unions {
		variants, err := variants(union, properties)
		if err != nil {
			return nil, err
		}
		unions = append(unions, map[string]any{"oneOf": variants})
	}
	if len(unions) == 1 {
		maps.Copy(s, unions[0].(map[string]any))
	} else if len(unions) > 1 {
		s["allOf"] = unions
	}
	return s, nil
}

// variants writes each variant as the members it requires and the members of the union it forbids.
func variants(union Union, properties map[string]any) ([]any, error) {
	var members, selects []string
	for _, variant := range union.Variants {
		if variant.Select != "" {
			selects = append(selects, variant.Select)
		}
		members = append(members, variant.Select)
		members = append(members, variant.Members...)
	}
	members = slices.DeleteFunc(slices.Compact(slices.Sorted(slices.Values(members))), func(m string) bool { return m == "" })
	var out []any
	for _, variant := range union.Variants {
		allowed := append([]string{variant.Select}, variant.Members...)
		forbidden := map[string]any{}
		for _, member := range members {
			if _, exists := properties[member]; !exists {
				return nil, fmt.Errorf("a union names %s, which is not a member", member)
			}
			if !slices.Contains(allowed, member) {
				forbidden[member] = false
			} else if member != variant.Select && slices.Contains(selects, member) {
				return nil, fmt.Errorf("the variant of %q allows %s, which selects another variant", variant.Select, member)
			}
		}
		s := map[string]any{"properties": forbidden}
		if variant.Select != "" {
			s["required"] = []string{variant.Select}
		}
		out = append(out, s)
	}
	return out, nil
}
