package agentidentity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func exampleBatch(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "identity-events.v1.examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var examples map[string]json.RawMessage
	if err := json.Unmarshal(data, &examples); err != nil {
		t.Fatal(err)
	}
	raw, ok := examples[name]
	if !ok {
		t.Fatalf("missing example %q", name)
	}
	var batch map[string]any
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	return batch
}

func eventAt(t *testing.T, batch map[string]any, index int) map[string]any {
	t.Helper()
	events, ok := batch["events"].([]any)
	if !ok || index < 0 || index >= len(events) {
		t.Fatalf("event index %d is unavailable", index)
	}
	event, ok := events[index].(map[string]any)
	if !ok {
		t.Fatalf("event %d is not an object", index)
	}
	return event
}

func nestedObject(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", key)
	}
	return value
}

func marshalBatch(t *testing.T, batch map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func rejectBatch(t *testing.T, data []byte) {
	t.Helper()
	parsed, err := ParseEnvelope(data)
	if err == nil {
		t.Fatalf("ParseEnvelope accepted invalid input: %+v", parsed)
	}
	if parsed != nil {
		t.Fatalf("ParseEnvelope returned a partial envelope on failure: %+v", parsed)
	}
}

func TestGoldenExamplesCoverAllTenVariants(t *testing.T) {
	expectedTypes := map[string]bool{
		"carrier.observed": false, "definition.observed": false, "asset.observed": false,
		"app.observed": false, "workflow.observed": false, "run.started": false,
		"run.ended": false, "instance.started": false, "instance.ended": false,
		"action.observed": false,
	}
	for _, name := range []string{"claude-code", "openclaw", "dify", "business-agent"} {
		t.Run(name, func(t *testing.T) {
			batch := exampleBatch(t, name)
			parsed, err := ParseEnvelope(marshalBatch(t, batch))
			if err != nil {
				t.Fatalf("contract example rejected: %v", err)
			}
			if parsed.SchemaVersion != "1.0" || parsed.Producer.NativeID == "" {
				t.Fatalf("producer/version were not parsed: %+v", parsed)
			}
			if len(parsed.Events) != len(batch["events"].([]any)) {
				t.Fatalf("event count=%d", len(parsed.Events))
			}
			for _, event := range parsed.Events {
				if _, ok := expectedTypes[event.EventType]; !ok {
					t.Errorf("unexpected type %q", event.EventType)
				}
				expectedTypes[event.EventType] = true
				if !validUUID(event.EventID) || event.OccurredAt.IsZero() || len(event.Raw) == 0 {
					t.Errorf("event omitted typed metadata or canonical raw: %+v", event)
				}
				var raw map[string]any
				if err := json.Unmarshal(event.Raw, &raw); err != nil {
					t.Errorf("Raw is not JSON: %v", err)
				}
			}
		})
	}
	for eventType, found := range expectedTypes {
		if !found {
			t.Errorf("golden examples did not cover %s", eventType)
		}
	}
}

func TestParsedValuesRemainClaimsAndRawPreservesEventIDCase(t *testing.T) {
	batch := exampleBatch(t, "claude-code")
	event := eventAt(t, batch, 6)
	event["event_id"] = "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"
	producer := nestedObject(t, batch, "producer")
	producer["native_id"] = "claimed-producer"

	parsed, err := ParseEnvelope(marshalBatch(t, batch))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Producer.NativeID != "claimed-producer" {
		t.Fatalf("producer claim was lost: %+v", parsed.Producer)
	}
	if got := parsed.Events[6].EventID; got != "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB" {
		t.Fatalf("event ID case changed: %q", got)
	}
	if !bytes.Contains(parsed.Events[6].Raw, []byte("ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB")) {
		t.Fatal("canonical Raw did not preserve event_id case")
	}
	if !bytes.HasPrefix(parsed.Events[3].Raw, []byte("{\"app\":")) {
		t.Fatalf("Raw keys are not deterministically sorted: %s", parsed.Events[3].Raw)
	}
	instance := parsed.Events[6]
	if instance.SubjectClaim == nil || instance.SubjectClaim.NativeID != "subject-001" {
		t.Fatalf("subject claim was not preserved: %+v", instance.SubjectClaim)
	}
	if len(instance.References) != 3 {
		t.Fatalf("instance references=%d, want instance/definition/run", len(instance.References))
	}
	if instance.References[1].Role != "definition" || instance.References[1].Ref.Kind != "definition" {
		t.Fatalf("reference role/kind was lost: %+v", instance.References[1])
	}
}

func TestTypedValuesMarshalWithSchemaFieldNames(t *testing.T) {
	batch := exampleBatch(t, "claude-code")
	parsed, err := ParseEnvelope(marshalBatch(t, batch))
	if err != nil {
		t.Fatal(err)
	}

	producerJSON, err := json.Marshal(parsed.Producer)
	if err != nil {
		t.Fatal(err)
	}
	var producer map[string]any
	if err := json.Unmarshal(producerJSON, &producer); err != nil {
		t.Fatal(err)
	}
	if len(producer) != 2 || producer["kind"] != "endpoint" || producer["native_id"] != "example-claude-code" {
		t.Fatalf("producer JSON tags do not match contract: %s", producerJSON)
	}

	plainRefJSON, err := json.Marshal(parsed.Events[0].References[0].Ref)
	if err != nil {
		t.Fatal(err)
	}
	var plainRef map[string]any
	if err := json.Unmarshal(plainRefJSON, &plainRef); err != nil {
		t.Fatal(err)
	}
	if len(plainRef) != 3 || plainRef["kind"] != "carrier" || plainRef["namespace"] != "example-claude-code" ||
		plainRef["native_id"] != "runtime" {
		t.Fatalf("reference JSON tags/revision omission do not match contract: %s", plainRefJSON)
	}

	revisionJSON, err := json.Marshal(parsed.Events[6].References[1].Ref)
	if err != nil {
		t.Fatal(err)
	}
	var revisionRef map[string]any
	if err := json.Unmarshal(revisionJSON, &revisionRef); err != nil {
		t.Fatal(err)
	}
	if len(revisionRef) != 4 || revisionRef["revision"] != "rev-1" {
		t.Fatalf("revision tag missing or wrong: %s", revisionJSON)
	}

	claimJSON, err := json.Marshal(parsed.Events[6].SubjectClaim)
	if err != nil {
		t.Fatal(err)
	}
	var claim map[string]any
	if err := json.Unmarshal(claimJSON, &claim); err != nil {
		t.Fatal(err)
	}
	if len(claim) != 3 || claim["kind"] != "user" || claim["issuer"] != "example-idp" || claim["native_id"] != "subject-001" {
		t.Fatalf("subject-claim JSON tags do not match contract: %s", claimJSON)
	}
}

func TestRejectsUnknownMissingAndInvalidVariantFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown envelope field", func(batch map[string]any) { batch["tenant_id"] = "claim" }},
		{"unknown producer field", func(batch map[string]any) { nestedObject(t, batch, "producer")["tenant_id"] = "claim" }},
		{"missing resource", func(batch map[string]any) { delete(eventAt(t, batch, 7), "resource") }},
		{"unknown event field", func(batch map[string]any) { eventAt(t, batch, 7)["allow"] = true }},
		{"unknown event type", func(batch map[string]any) { eventAt(t, batch, 0)["event_type"] = "permission.granted" }},
		{"wrong schema version", func(batch map[string]any) { batch["schema_version"] = "2.0" }},
		{"invalid product", func(batch map[string]any) { eventAt(t, batch, 0)["product"] = "unknown" }},
		{"wrong revision type", func(batch map[string]any) { nestedObject(t, eventAt(t, batch, 6), "definition")["revision"] = 42 }},
		{"resolved identity injection", func(batch map[string]any) {
			eventAt(t, batch, 6)["resolved_subject"] = map[string]any{"canonical_id": "admin"}
		}},
		{"subject canonical ID injection", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 6), "subject_claim")["user_id"] = "admin"
		}},
		{"subject resolved ID injection", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 6), "subject_claim")["canonical_id"] = "admin"
		}},
		{"invalid legacy ID", func(batch map[string]any) { eventAt(t, batch, 7)["legacy_event_id"] = "legacy" }},
		{"legacy field on other variant", func(batch map[string]any) {
			eventAt(t, batch, 0)["legacy_event_id"] = "00000000-0000-0000-0000-000000000001"
		}},
		{"bad digest", func(batch map[string]any) { eventAt(t, batch, 2)["digest"] = "sha256:ABC" }},
		{"oversized version", func(batch map[string]any) { eventAt(t, batch, 0)["version"] = strings.Repeat("v", 65) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := exampleBatch(t, "claude-code")
			test.mutate(batch)
			rejectBatch(t, marshalBatch(t, batch))
		})
	}
}

func TestRejectsInvalidReferenceKindsAndUnicodeBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"reference kind", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 5), "run")["kind"] = "resource"
		}},
		{"parent run kind", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 8), "parent_run")["kind"] = "instance"
		}},
		{"asset owner kind", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 2), "owner")["kind"] = "resource"
		}},
		{"reference unknown field", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 0), "carrier")["canonical_id"] = "server-id"
		}},
		{"namespace over 128 code points", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 0), "carrier")["namespace"] = strings.Repeat("界", 129)
		}},
		{"native ID over 256 code points", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 0), "carrier")["native_id"] = strings.Repeat("n", 257)
		}},
		{"revision over 128 code points", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 1), "definition")["revision"] = strings.Repeat("界", 129)
		}},
		{"NUL is rejected for JSONB storage safety", func(batch map[string]any) {
			nestedObject(t, eventAt(t, batch, 0), "carrier")["native_id"] = "runtime\x00unsafe"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := exampleBatch(t, "claude-code")
			test.mutate(batch)
			rejectBatch(t, marshalBatch(t, batch))
		})
	}
}

func TestRejectsMalformedJSONAndTimestamps(t *testing.T) {
	valid := marshalBatch(t, exampleBatch(t, "claude-code"))
	rejectBatch(t, append(append([]byte(nil), valid...), []byte(" {}")...))
	rejectBatch(t, append(append([]byte(nil), valid...), 0xff))
	rejectBatch(t, []byte("{\"schema_version\":\"1.0\",\"schema_version\":\"1.0\"}"))
	rejectBatch(t, []byte("{\"schema_version\":\"1.0\",\"producer\":{\"kind\":\"service\",\"native_id\":\"x\"},\"events\":[{\"event_id\":\"00000000-0000-0000-0000-000000000001\",\"event_type\":\"run.ended\",\"occurred_at\":\"2026-09-24T00:00:00Z\",\"run\":{\"kind\":\"run\",\"namespace\":\"n\",\"native_id\":\"r\",\"native_id\":\"duplicate\"},\"status\":\"completed\"}]}"))
	for _, stamp := range []string{"not-a-date", "2026-09-24T00:00:00", "2026-09-24T00:00:00,1Z"} {
		t.Run(stamp, func(t *testing.T) {
			batch := exampleBatch(t, "claude-code")
			eventAt(t, batch, 0)["occurred_at"] = stamp
			rejectBatch(t, marshalBatch(t, batch))
		})
	}
}

func TestSurrogateEscapesPreserveUnicodeIdentity(t *testing.T) {
	valid := marshalBatch(t, exampleBatch(t, "claude-code"))
	target := []byte(`"native_id":"example-claude-code"`)
	for name, escaped := range map[string]string{
		"lone high surrogate":      `"native_id":"\ud800"`,
		"lone low surrogate":       `"native_id":"\udc00"`,
		"high followed by non-low": `"native_id":"\ud800\u0041"`,
		"malformed pair":           `"native_id":"\ud800\ud800"`,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := bytes.Replace(valid, target, []byte(escaped), 1)
			if bytes.Equal(invalid, valid) {
				t.Fatal("producer native ID fixture not found")
			}
			rejectBatch(t, invalid)
		})
	}

	paired := bytes.Replace(valid, target, []byte(`"native_id":"\ud83d\ude00"`), 1)
	parsed, err := ParseEnvelope(paired)
	if err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	if parsed.Producer.NativeID != "😀" {
		t.Fatalf("valid surrogate pair decoded to %q", parsed.Producer.NativeID)
	}

	literalReplacement := bytes.Replace(valid, target, []byte(`"native_id":"�"`), 1)
	parsed, err = ParseEnvelope(literalReplacement)
	if err != nil {
		t.Fatalf("literal U+FFFD rejected: %v", err)
	}
	if parsed.Producer.NativeID != "�" {
		t.Fatalf("literal U+FFFD decoded to %q", parsed.Producer.NativeID)
	}
}

func TestRFC3339LexicalWidthsAndRanges(t *testing.T) {
	for name, stamp := range map[string]string{
		"one digit hour":   "2026-09-24T0:00:00Z",
		"one digit minute": "2026-09-24T00:0:00Z",
		"one digit second": "2026-09-24T00:00:0Z",
		"offset hour 24":   "2026-09-24T00:00:00+24:00",
		"offset minute 60": "2026-09-24T00:00:00+00:60",
		"time hour 24":     "2026-09-24T24:00:00Z",
		"time minute 60":   "2026-09-24T00:60:00Z",
		"time second 60":   "2026-09-24T00:00:60Z",
	} {
		t.Run(name, func(t *testing.T) {
			batch := exampleBatch(t, "claude-code")
			eventAt(t, batch, 0)["occurred_at"] = stamp
			rejectBatch(t, marshalBatch(t, batch))
		})
	}

	batch := exampleBatch(t, "claude-code")
	const lowercase = "2026-09-24t09:30:00.125z"
	eventAt(t, batch, 0)["occurred_at"] = lowercase
	parsed, err := ParseEnvelope(marshalBatch(t, batch))
	if err != nil {
		t.Fatalf("RFC3339 lowercase t/z form rejected: %v", err)
	}
	if !bytes.Contains(parsed.Events[0].Raw, []byte(lowercase)) {
		t.Fatalf("canonical raw event changed timestamp spelling: %s", parsed.Events[0].Raw)
	}
}

func TestBatchAndOperationalLimits(t *testing.T) {
	batch := exampleBatch(t, "claude-code")
	events := batch["events"].([]any)
	batch["events"] = events[:1]
	valid := marshalBatch(t, batch)
	exactLimit := append(append([]byte(nil), valid...), bytes.Repeat([]byte{' '}, maxBodyBytes-len(valid))...)
	if _, err := ParseEnvelope(exactLimit); err != nil {
		t.Fatalf("body at byte limit rejected: %v", err)
	}
	rejectBatch(t, append(exactLimit, ' '))

	batch = exampleBatch(t, "claude-code")
	batch["events"] = []any{}
	rejectBatch(t, marshalBatch(t, batch))

	batch = exampleBatch(t, "claude-code")
	first := eventAt(t, batch, 0)
	many := make([]any, maxBatchSize)
	for i := range many {
		copyEvent := make(map[string]any, len(first))
		for key, value := range first {
			copyEvent[key] = value
		}
		copyEvent["event_id"] = fmt.Sprintf("00000000-0000-0000-0000-%012x", i+1)
		many[i] = copyEvent
	}
	batch["events"] = many
	if _, err := ParseEnvelope(marshalBatch(t, batch)); err != nil {
		t.Fatalf("batch at item limit rejected: %v", err)
	}
	many = append(many, many[0])
	batch["events"] = many
	rejectBatch(t, marshalBatch(t, batch))

	deep := []byte("{\"unknown\":" + strings.Repeat("[", maxJSONDepth) + "0" + strings.Repeat("]", maxJSONDepth) + "}")
	rejectBatch(t, deep)
	oversized := bytes.Repeat([]byte{' '}, maxBodyBytes+1)
	rejectBatch(t, oversized)
}

func TestRFC3339OffsetIsNotNormalizedInTypedValue(t *testing.T) {
	batch := exampleBatch(t, "claude-code")
	const stamp = "2026-09-24T09:30:00+05:30"
	eventAt(t, batch, 0)["occurred_at"] = stamp
	parsed, err := ParseEnvelope(marshalBatch(t, batch))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Events[0].OccurredAt.Format(time.RFC3339Nano); got != stamp {
		t.Fatalf("timestamp offset changed: got %s, want %s", got, stamp)
	}
}
