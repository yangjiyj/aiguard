package audit_chain

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAuditCanonicalRejectsCumulativeNumericExpansion(t *testing.T) {
	payload := map[string]any{}
	for i := 0; i < 20; i++ {
		payload[fmt.Sprintf("n%02d", i)] = json.Number("1e100000")
	}
	if output, err := CanonicalPayload(payload); err == nil || output != nil {
		t.Fatal("many individually valid numbers exceeded the total output budget")
	}
}

func TestAuditCanonicalRejectsCumulativeNestedStrings(t *testing.T) {
	payload := map[string]any{"nested": []any{strings.Repeat("a", 400000), strings.Repeat("b", 400000), strings.Repeat("c", 400000)}}
	if output, err := CanonicalPayload(payload); err == nil || output != nil {
		t.Fatal("combined nested strings exceeded the total output budget")
	}
}

func TestAuditCanonicalChecksEscapedStringsAndKeysBeforeAppend(t *testing.T) {
	nearFull := []byte(strings.Repeat("x", (1<<20)-10))
	for _, value := range []any{"&&&&", map[string]any{"&&&&": ""}, json.Number("1e100000"), strings.Repeat("a", 20)} {
		if output, err := appendCanonicalJSON(nearFull, value); err == nil || output != nil {
			t.Fatal("expanded value appended beyond the remaining budget")
		}
	}
}

func TestAuditCanonicalKeepsNormalPayloadAndBoundedExponent(t *testing.T) {
	input := map[string]any{"a": json.Number("1e1000"), "nested": []any{"<>&", json.Number("9007199254740993"), nil}}
	canonical, err := CanonicalPayload(input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalPayload(canonical)
	if err != nil || string(again) != string(canonical) {
		t.Fatal("bounded payload lost canonical stability")
	}
}
