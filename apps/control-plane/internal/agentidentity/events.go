// Package agentidentity strictly parses claim-only identity-events.v1 batches.
package agentidentity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxBodyBytes = 1 << 20
	maxJSONDepth = 16
	maxBatchSize = 200
)

var producerKinds = makeEnumSet("endpoint", "gateway", "service", "import")
var nativeRefKinds = makeEnumSet("carrier", "definition", "asset", "app", "workflow", "run", "instance", "resource")
var subjectClaimKinds = makeEnumSet("user", "service_account", "agent_principal")

// Producer is an untrusted producer claim from the envelope. It is not a
// registered endpoint identity or an authentication principal.
type Producer struct {
	Kind     string `json:"kind"`
	NativeID string `json:"native_id"`
}

// NativeRef is a producer-supplied native reference, not a server-resolved ID.
type NativeRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	NativeID  string `json:"native_id"`
	Revision  string `json:"revision,omitempty"`
}

// Reference preserves the event field that relates one native object to another.
type Reference struct {
	Role string    `json:"role"`
	Ref  NativeRef `json:"ref"`
}

// SubjectClaim is an unverified identity claim supplied by the producer.
type SubjectClaim struct {
	Kind     string `json:"kind"`
	Issuer   string `json:"issuer"`
	NativeID string `json:"native_id"`
}

// Event is a validated claim-only event. Raw is the deterministic JSON
// re-encoding of the validated event, with object keys sorted by encoding/json.
type Event struct {
	EventID       string          `json:"event_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	EventType     string          `json:"event_type"`
	Raw           json.RawMessage `json:"-"`
	References    []Reference     `json:"references,omitempty"`
	SubjectClaim  *SubjectClaim   `json:"subject_claim,omitempty"`
	LegacyEventID string          `json:"legacy_event_id,omitempty"`
}

// Envelope is a validated identity-events.v1 batch. Producer remains an
// untrusted claim and must not be used as authentication identity.
type Envelope struct {
	SchemaVersion string   `json:"schema_version"`
	Producer      Producer `json:"producer"`
	Events        []Event  `json:"events"`
}

// ParseEnvelope parses and validates a claim-only identity-events.v1 envelope.
// It rejects unknown fields, duplicate JSON object keys, malformed UTF-8,
// trailing JSON values, and values exceeding the documented body/depth bounds.
func ParseEnvelope(data []byte) (*Envelope, error) {
	if len(data) == 0 || len(data) > maxBodyBytes {
		return nil, fmt.Errorf("identity-events.v1: body size must be between 1 and %d bytes", maxBodyBytes)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("identity-events.v1: body is not valid UTF-8")
	}
	if err := rejectUnpairedSurrogateEscapes(data); err != nil {
		return nil, fmt.Errorf("identity-events.v1: invalid JSON string: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readJSONValue(decoder, 1)
	if err != nil {
		return nil, fmt.Errorf("identity-events.v1: invalid JSON: %w", err)
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("identity-events.v1: envelope must be an object")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("identity-events.v1: invalid trailing JSON: %w", err)
		}
		return nil, fmt.Errorf("identity-events.v1: trailing JSON value starts with %v", token)
	}
	root := value.(map[string]any)
	if err := checkObjectShape(root,
		[]string{"schema_version", "producer", "events"}, nil); err != nil {
		return nil, fmt.Errorf("identity-events.v1: %w", err)
	}
	schemaVersion, err := stringField(root, "schema_version")
	if err != nil {
		return nil, err
	}
	if schemaVersion != "1.0" {
		return nil, fmt.Errorf("identity-events.v1: unsupported schema_version %q", schemaVersion)
	}
	producer, err := parseProducer(root["producer"])
	if err != nil {
		return nil, fmt.Errorf("identity-events.v1: producer: %w", err)
	}
	rawEvents, ok := root["events"].([]any)
	if !ok {
		return nil, fmt.Errorf("identity-events.v1: events must be an array")
	}
	if len(rawEvents) < 1 || len(rawEvents) > maxBatchSize {
		return nil, fmt.Errorf("identity-events.v1: events must contain between 1 and %d items", maxBatchSize)
	}
	envelope := &Envelope{
		SchemaVersion: schemaVersion,
		Producer:      producer,
		Events:        make([]Event, 0, len(rawEvents)),
	}
	for i, rawEvent := range rawEvents {
		event, err := parseEvent(rawEvent)
		if err != nil {
			return nil, fmt.Errorf("identity-events.v1: events[%d]: %w", i, err)
		}
		envelope.Events = append(envelope.Events, event)
	}
	return envelope, nil
}

func parseProducer(value any) (Producer, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return Producer{}, fmt.Errorf("must be an object")
	}
	if err := checkObjectShape(object, []string{"kind", "native_id"}, nil); err != nil {
		return Producer{}, err
	}
	kind, err := stringField(object, "kind")
	if err != nil {
		return Producer{}, err
	}
	if !producerKinds.has(kind) {
		return Producer{}, fmt.Errorf("kind %q is not supported", kind)
	}
	nativeID, err := stringField(object, "native_id")
	if err != nil {
		return Producer{}, err
	}
	if !validLength(nativeID, 1, 256) {
		return Producer{}, fmt.Errorf("native_id must contain 1 to 256 Unicode code points")
	}
	return Producer{Kind: kind, NativeID: nativeID}, nil
}

func parseEvent(value any) (Event, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return Event{}, fmt.Errorf("must be an object")
	}
	eventType, err := stringField(object, "event_type")
	if err != nil {
		return Event{}, err
	}
	required, optional, refs, err := eventShape(eventType)
	if err != nil {
		return Event{}, err
	}
	if err := checkObjectShape(object, required, optional); err != nil {
		return Event{}, err
	}
	eventID, err := stringField(object, "event_id")
	if err != nil {
		return Event{}, err
	}
	if !validUUID(eventID) {
		return Event{}, fmt.Errorf("event_id must match the UUID form")
	}
	occurredText, err := stringField(object, "occurred_at")
	if err != nil {
		return Event{}, err
	}
	occurredAt, err := parseRFC3339(occurredText)
	if err != nil {
		return Event{}, fmt.Errorf("occurred_at must be RFC3339 date-time")
	}
	event := Event{
		EventID:    eventID,
		OccurredAt: occurredAt,
		EventType:  eventType,
		References: make([]Reference, 0, len(refs)),
	}
	for _, reference := range refs {
		if _, present := object[reference.role]; !present {
			continue
		}
		ref, err := parseNativeRef(object[reference.role], reference.kinds)
		if err != nil {
			return Event{}, fmt.Errorf("%s: %w", reference.role, err)
		}
		event.References = append(event.References, Reference{Role: reference.role, Ref: ref})
	}
	switch eventType {
	case "carrier.observed":
		if !enumField(object, "product", "claude-code", "openclaw", "dify", "business-agent", "other") {
			return Event{}, fmt.Errorf("product is not supported")
		}
		if !enumField(object, "runtime", "cli", "ide", "gateway", "sdk", "service") {
			return Event{}, fmt.Errorf("runtime is not supported")
		}
		if version, present := object["version"]; present {
			if !stringAndLength(version, 1, 64) {
				return Event{}, fmt.Errorf("version must contain 1 to 64 Unicode code points")
			}
		}
	case "definition.observed", "app.observed", "workflow.observed":
		if !stringAndLength(object["name"], 1, 255) {
			return Event{}, fmt.Errorf("name must contain 1 to 255 Unicode code points")
		}
	case "asset.observed":
		if !enumField(object, "asset_type", "model", "mcp_server", "mcp_tool", "skill", "plugin",
			"instruction_file", "hook", "config", "tool", "dataset", "other") {
			return Event{}, fmt.Errorf("asset_type is not supported")
		}
		if digest, present := object["digest"]; present && !validDigest(digest) {
			return Event{}, fmt.Errorf("digest must use the sha256:<lowercase hex> form")
		}
	case "run.ended", "instance.ended":
		if !enumField(object, "status", "completed", "failed", "cancelled", "unknown") {
			return Event{}, fmt.Errorf("status is not supported")
		}
	case "instance.started":
		if claim, present := object["subject_claim"]; present {
			parsed, err := parseSubjectClaim(claim)
			if err != nil {
				return Event{}, fmt.Errorf("subject_claim: %w", err)
			}
			event.SubjectClaim = &parsed
		}
	case "action.observed":
		action, ok := object["action"].(map[string]any)
		if !ok {
			return Event{}, fmt.Errorf("action must be an object")
		}
		if err := checkObjectShape(action, []string{"native_id", "operation"}, nil); err != nil {
			return Event{}, fmt.Errorf("action: %w", err)
		}
		if !stringAndLength(action["native_id"], 1, 256) {
			return Event{}, fmt.Errorf("action.native_id must contain 1 to 256 Unicode code points")
		}
		if !stringAndLength(action["operation"], 1, 128) {
			return Event{}, fmt.Errorf("action.operation must contain 1 to 128 Unicode code points")
		}
		if !enumField(object, "outcome", "attempted", "succeeded", "failed", "denied", "unknown") {
			return Event{}, fmt.Errorf("outcome is not supported")
		}
		if legacyID, present := object["legacy_event_id"]; present {
			legacy, ok := legacyID.(string)
			if !ok || !validUUID(legacy) {
				return Event{}, fmt.Errorf("legacy_event_id must match the UUID form")
			}
			event.LegacyEventID = legacy
		}
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return Event{}, fmt.Errorf("encode canonical event: %w", err)
	}
	event.Raw = append(json.RawMessage(nil), canonical...)
	return event, nil
}

type refRule struct {
	role  string
	kinds []string
}

func eventShape(eventType string) ([]string, []string, []refRule, error) {
	common := []string{"event_id", "event_type", "occurred_at"}
	switch eventType {
	case "carrier.observed":
		return append(common, "carrier", "product", "runtime"), []string{"version"},
			[]refRule{{"carrier", []string{"carrier"}}}, nil
	case "definition.observed":
		return append(common, "definition", "carrier", "name"), nil,
			[]refRule{{"definition", []string{"definition"}}, {"carrier", []string{"carrier"}}}, nil
	case "asset.observed":
		return append(common, "asset", "owner", "asset_type"), []string{"digest"},
			[]refRule{{"asset", []string{"asset"}}, {"owner", []string{"carrier", "definition", "app", "workflow"}}}, nil
	case "app.observed":
		return append(common, "app", "name"), nil, []refRule{{"app", []string{"app"}}}, nil
	case "workflow.observed":
		return append(common, "workflow", "app", "name"), nil,
			[]refRule{{"workflow", []string{"workflow"}}, {"app", []string{"app"}}}, nil
	case "run.started":
		return append(common, "run", "workflow"), []string{"parent_run"},
			[]refRule{{"run", []string{"run"}}, {"workflow", []string{"workflow"}}, {"parent_run", []string{"run"}}}, nil
	case "run.ended":
		return append(common, "run", "status"), nil, []refRule{{"run", []string{"run"}}}, nil
	case "instance.started":
		return append(common, "instance", "definition", "run"), []string{"parent_instance", "subject_claim"},
			[]refRule{{"instance", []string{"instance"}}, {"definition", []string{"definition"}},
				{"run", []string{"run"}}, {"parent_instance", []string{"instance"}}}, nil
	case "instance.ended":
		return append(common, "instance", "status"), nil, []refRule{{"instance", []string{"instance"}}}, nil
	case "action.observed":
		return append(common, "action", "instance", "run", "resource", "outcome"), []string{"legacy_event_id"},
			[]refRule{{"instance", []string{"instance"}}, {"run", []string{"run"}},
				{"resource", []string{"resource"}}}, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported event_type %q", eventType)
	}
}

func parseNativeRef(value any, allowedKinds []string) (NativeRef, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return NativeRef{}, fmt.Errorf("must be an object")
	}
	if err := checkObjectShape(object, []string{"kind", "namespace", "native_id"}, []string{"revision"}); err != nil {
		return NativeRef{}, err
	}
	kind, err := stringField(object, "kind")
	if err != nil {
		return NativeRef{}, err
	}
	if !nativeRefKinds.has(kind) || !makeEnumSet(allowedKinds...).has(kind) {
		return NativeRef{}, fmt.Errorf("kind %q is not valid for this reference", kind)
	}
	namespace, err := stringField(object, "namespace")
	if err != nil {
		return NativeRef{}, err
	}
	if !validLength(namespace, 1, 128) {
		return NativeRef{}, fmt.Errorf("namespace must contain 1 to 128 Unicode code points")
	}
	nativeID, err := stringField(object, "native_id")
	if err != nil {
		return NativeRef{}, err
	}
	if !validLength(nativeID, 1, 256) {
		return NativeRef{}, fmt.Errorf("native_id must contain 1 to 256 Unicode code points")
	}
	ref := NativeRef{Kind: kind, Namespace: namespace, NativeID: nativeID}
	if revision, present := object["revision"]; present {
		value, ok := revision.(string)
		if !ok || !validLength(value, 1, 128) {
			return NativeRef{}, fmt.Errorf("revision must contain 1 to 128 Unicode code points")
		}
		ref.Revision = value
	}
	return ref, nil
}

func parseSubjectClaim(value any) (SubjectClaim, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return SubjectClaim{}, fmt.Errorf("must be an object")
	}
	if err := checkObjectShape(object, []string{"kind", "issuer", "native_id"}, nil); err != nil {
		return SubjectClaim{}, err
	}
	kind, err := stringField(object, "kind")
	if err != nil {
		return SubjectClaim{}, err
	}
	if !subjectClaimKinds.has(kind) {
		return SubjectClaim{}, fmt.Errorf("kind %q is not supported", kind)
	}
	issuer, err := stringField(object, "issuer")
	if err != nil {
		return SubjectClaim{}, err
	}
	if !validLength(issuer, 1, 128) {
		return SubjectClaim{}, fmt.Errorf("issuer must contain 1 to 128 Unicode code points")
	}
	nativeID, err := stringField(object, "native_id")
	if err != nil {
		return SubjectClaim{}, err
	}
	if !validLength(nativeID, 1, 256) {
		return SubjectClaim{}, fmt.Errorf("native_id must contain 1 to 256 Unicode code points")
	}
	return SubjectClaim{Kind: kind, Issuer: issuer, NativeID: nativeID}, nil
}

func checkObjectShape(object map[string]any, required, optional []string) error {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, present := object[key]; !present {
			return fmt.Errorf("missing required field %q", key)
		}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown field %q", key)
		}
	}
	return nil
}

func stringField(object map[string]any, key string) (string, error) {
	value, ok := object[key].(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return value, nil
}

func stringAndLength(value any, min, max int) bool {
	text, ok := value.(string)
	return ok && validLength(text, min, max)
}

func validLength(value string, min, max int) bool {
	length := utf8.RuneCountInString(value)
	return length >= min && length <= max && !strings.ContainsRune(value, 0)
}

func enumField(object map[string]any, key string, choices ...string) bool {
	value, ok := object[key].(string)
	if !ok {
		return false
	}
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return false
			}
		}
	}
	return true
}

func parseRFC3339(value string) (time.Time, error) {
	// Validate the RFC3339 lexical form before time.Parse: Go's parser accepts
	// some non-standard widths and out-of-range numeric offsets.
	if len(value) < 20 || value[4] != '-' || value[7] != '-' ||
		(value[10] != 'T' && value[10] != 't') || value[13] != ':' || value[16] != ':' {
		return time.Time{}, fmt.Errorf("invalid RFC3339 shape")
	}
	for _, index := range []int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18} {
		if !isASCIIDigit(value[index]) {
			return time.Time{}, fmt.Errorf("invalid RFC3339 digit")
		}
	}
	hour := twoDigits(value[11:13])
	minute := twoDigits(value[14:16])
	second := twoDigits(value[17:19])
	if hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, fmt.Errorf("RFC3339 time component out of range")
	}
	i := 19
	if i < len(value) && value[i] == '.' {
		i++
		start := i
		for i < len(value) && isASCIIDigit(value[i]) {
			i++
		}
		if i == start {
			return time.Time{}, fmt.Errorf("empty RFC3339 fractional second")
		}
	}
	if i >= len(value) {
		return time.Time{}, fmt.Errorf("missing RFC3339 time zone")
	}
	switch value[i] {
	case 'Z', 'z':
		if i != len(value)-1 {
			return time.Time{}, fmt.Errorf("trailing RFC3339 data")
		}
	case '+', '-':
		if len(value)-i != 6 || value[i+3] != ':' ||
			!isASCIIDigit(value[i+1]) || !isASCIIDigit(value[i+2]) ||
			!isASCIIDigit(value[i+4]) || !isASCIIDigit(value[i+5]) {
			return time.Time{}, fmt.Errorf("invalid RFC3339 numeric time zone")
		}
		if twoDigits(value[i+1:i+3]) > 23 || twoDigits(value[i+4:i+6]) > 59 {
			return time.Time{}, fmt.Errorf("RFC3339 time zone out of range")
		}
	default:
		return time.Time{}, fmt.Errorf("invalid RFC3339 time zone")
	}
	// The pinned Python FormatChecker accepts lowercase t/z; RFC3339 permits
	// those spellings, while preserving the original text in Event.Raw.
	normalized := []byte(value)
	normalized[10] = 'T'
	if normalized[len(normalized)-1] == 'z' {
		normalized[len(normalized)-1] = 'Z'
	}
	return time.Parse(time.RFC3339Nano, string(normalized))
}

func isASCIIDigit(value byte) bool { return value >= '0' && value <= '9' }

func twoDigits(value string) int { return int(value[0]-'0')*10 + int(value[1]-'0') }

// rejectUnpairedSurrogateEscapes rejects JSON \u escapes that are not valid
// UTF-16 surrogate pairs. encoding/json replaces unmatched surrogates with
// U+FFFD, which would collapse distinct claimed native IDs after decoding.
func rejectUnpairedSurrogateEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); {
		if !inString {
			if data[i] == '"' {
				inString = true
			}
			i++
			continue
		}
		switch data[i] {
		case '"':
			inString = false
			i++
		case '\\':
			if i+1 >= len(data) {
				return nil // The JSON decoder reports the truncated escape.
			}
			if data[i+1] != 'u' || i+6 > len(data) {
				i += 2
				continue
			}
			unit, ok := parseHexCodeUnit(data[i+2 : i+6])
			if !ok {
				i += 2 // Let encoding/json report malformed hex escapes.
				continue
			}
			switch {
			case unit >= 0xD800 && unit <= 0xDBFF:
				if i+12 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
					return fmt.Errorf("unmatched high surrogate escape")
				}
				low, valid := parseHexCodeUnit(data[i+8 : i+12])
				if !valid || low < 0xDC00 || low > 0xDFFF {
					return fmt.Errorf("high surrogate is not followed by a low surrogate")
				}
				i += 12
			case unit >= 0xDC00 && unit <= 0xDFFF:
				return fmt.Errorf("unmatched low surrogate escape")
			default:
				i += 6
			}
		default:
			i++
		}
	}
	return nil
}

func parseHexCodeUnit(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result uint16
	for _, digit := range value {
		result <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			result |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			result |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			result |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

func validDigest(value any) bool {
	digest, ok := value.(string)
	if !ok || len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	for _, ch := range digest[len("sha256:"):] {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func readJSONValue(decoder *json.Decoder, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token := token.(type) {
	case json.Delim:
		if depth > maxJSONDepth {
			return nil, fmt.Errorf("JSON nesting exceeds %d containers", maxJSONDepth)
		}
		switch token {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				if strings.ContainsRune(key, 0) {
					return nil, fmt.Errorf("JSON object keys must not contain U+0000")
				}
				if _, duplicate := object[key]; duplicate {
					return nil, fmt.Errorf("duplicate JSON object key %q", key)
				}
				value, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			closeToken, err := decoder.Token()
			if err != nil || closeToken != json.Delim('}') {
				return nil, fmt.Errorf("malformed JSON object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				value, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			closeToken, err := decoder.Token()
			if err != nil || closeToken != json.Delim(']') {
				return nil, fmt.Errorf("malformed JSON array")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", token)
		}
	case string:
		if strings.ContainsRune(token, 0) {
			return nil, fmt.Errorf("JSON strings must not contain U+0000")
		}
		return token, nil
	default:
		return token, nil
	}
}

type enumSet map[string]struct{}

func makeEnumSet(values ...string) enumSet {
	set := make(enumSet, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func (set enumSet) has(value string) bool {
	_, ok := set[value]
	return ok
}
