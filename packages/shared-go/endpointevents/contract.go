// Package endpointevents validates the frozen hookd wire contract shared by the
// gateway and control-plane. It is deliberately limited to this schema.
package endpointevents

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed events.v1.schema.json
var schemaBytes []byte
var schema map[string]any

func init() {
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		panic(err)
	}
}

// Decode rejects duplicate object keys and trailing JSON before contract checks.
func Decode(raw []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing event JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("event object required")
	}
	return object, nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("event nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		v := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := k.(string)
			if !ok {
				return nil, errors.New("object key")
			}
			if _, exists := v[key]; exists {
				return nil, errors.New("duplicate event field")
			}
			child, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			v[key] = child
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("object terminator")
		}
		return v, nil
	case '[':
		v := []any{}
		for d.More() {
			child, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			v = append(v, child)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, errors.New("array terminator")
		}
		return v, nil
	}
	return nil, errors.New("unexpected JSON delimiter")
}

func IsNested(v map[string]any) bool {
	for _, key := range []string{"agent", "session", "turn", "context", "tool", "content", "detail", "assets", "health", "error"} {
		if _, ok := v[key]; ok {
			return true
		}
	}
	return false
}
func ValidateHeader(v map[string]any) error {
	if len(v) != 5 {
		return errors.New("batch fields")
	}
	for _, k := range []string{"schema_version", "endpoint_id", "hookd_version", "sent_at", "events"} {
		x, ok := v[k]
		if !ok {
			return errors.New("batch field missing")
		}
		if k != "events" {
			if err := validate(x, schema["properties"].(map[string]any)[k].(map[string]any), 0); err != nil {
				return err
			}
		}
	}
	if v["hookd_version"] == "" {
		return errors.New("hookd version required")
	}
	events, ok := v["events"].([]any)
	if !ok || len(events) == 0 || len(events) > 200 {
		return errors.New("batch events")
	}
	return nil
}

// ValidateEvent enforces wire shape, time window and server-selected capture level.
// Summary strings are supplied by the adapter, never interpreted as trusted identity.
func ValidateEvent(v map[string]any, now time.Time, captureLevel string) error {
	def := schema["$defs"].(map[string]any)["Event"].(map[string]any)
	if err := validate(v, def, 0); err != nil {
		return err
	}
	occurred, _ := time.Parse(time.RFC3339Nano, v["occurred_at"].(string))
	if occurred.Before(now.Add(-30*24*time.Hour)) || occurred.After(now.Add(24*time.Hour)) {
		return errors.New("event time window")
	}
	if captureLevel != "summary" && captureLevel != "full" {
		if content, ok := v["content"].(map[string]any); ok {
			for _, key := range []string{"user_prompt", "assistant_text"} {
				if text, _ := content[key].(string); text != "" {
					return errors.New("capture level excludes content")
				}
			}
		}
		if tool, ok := v["tool"].(map[string]any); ok {
			if text, _ := tool["result_preview"].(string); text != "" {
				return errors.New("capture level excludes result preview")
			}
		}
	}
	return nil
}

// ValidateLegacyCapture applies the same server-selected content permission to
// legacy flat events. Shape and length checks remain with the legacy validator.
func ValidateLegacyCapture(v map[string]any, captureLevel string) error {
	if captureLevel == "summary" || captureLevel == "full" {
		return nil
	}
	for _, object := range []map[string]any{v, legacyPayload(v)} {
		for _, key := range []string{"result", "command"} {
			switch value := object[key].(type) {
			case nil:
			case string:
				if value != "" {
					return errors.New("capture level excludes legacy content")
				}
			default:
				return errors.New("capture level excludes legacy content")
			}
		}
	}
	return nil
}
func legacyPayload(v map[string]any) map[string]any {
	payload, _ := v["payload"].(map[string]any)
	return payload
}

func validate(value any, s map[string]any, depth int) error {
	if depth > 16 {
		return errors.New("event nesting limit")
	}
	if ref, ok := s["$ref"].(string); ok {
		if !strings.HasPrefix(ref, "#/$defs/") {
			return errors.New("unsupported contract reference")
		}
		def, ok := schema["$defs"].(map[string]any)[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		if !ok {
			return errors.New("missing contract reference")
		}
		return validate(value, def, depth+1)
	}
	if fixed, ok := s["const"]; ok && value != fixed {
		return errors.New("unsupported schema version")
	}
	if choices, ok := s["enum"].([]any); ok {
		found := false
		for _, choice := range choices {
			if value == choice {
				found = true
				break
			}
		}
		if !found {
			return errors.New("unknown contract enum")
		}
	}
	switch s["type"] {
	case "object":
		v, ok := value.(map[string]any)
		if !ok {
			return errors.New("object required")
		}
		props, _ := s["properties"].(map[string]any)
		if required, ok := s["required"].([]any); ok {
			for _, key := range required {
				if _, found := v[key.(string)]; !found {
					return errors.New("required event field missing")
				}
			}
		}
		for key, child := range v {
			rule, ok := props[key].(map[string]any)
			if !ok {
				return fmt.Errorf("unknown event field %s", key)
			}
			if err := validate(child, rule, depth+1); err != nil {
				return err
			}
		}
	case "array":
		v, ok := value.([]any)
		if !ok {
			return errors.New("array required")
		}
		if max, ok := s["maxItems"].(float64); ok && len(v) > int(max) {
			return errors.New("array limit")
		}
		if min, ok := s["minItems"].(float64); ok && len(v) < int(min) {
			return errors.New("array minimum")
		}
		rule := s["items"].(map[string]any)
		for _, child := range v {
			if err := validate(child, rule, depth+1); err != nil {
				return err
			}
		}
	case "string":
		v, ok := value.(string)
		if !ok || !utf8.ValidString(v) {
			return errors.New("string required")
		}
		if max, ok := s["maxLength"].(float64); ok && utf8.RuneCountInString(v) > int(max) {
			return errors.New("string limit")
		}
		if pattern, ok := s["pattern"].(string); ok {
			matched, _ := regexp.MatchString(pattern, v)
			if !matched {
				return errors.New("string pattern")
			}
		}
		switch s["format"] {
		case "date-time":
			if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
				return errors.New("timestamp format")
			}
		case "uuid":
			if matched, _ := regexp.MatchString("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", v); !matched {
				return errors.New("event UUID")
			}
		}
	case "integer":
		v, ok := value.(json.Number)
		if !ok {
			return errors.New("integer required")
		}
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			return errors.New("integer range")
		}
		if min, ok := s["minimum"].(float64); ok && n < int64(min) {
			return errors.New("integer minimum")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return errors.New("boolean required")
		}
	default:
		return errors.New("unsupported contract rule")
	}
	return nil
}
