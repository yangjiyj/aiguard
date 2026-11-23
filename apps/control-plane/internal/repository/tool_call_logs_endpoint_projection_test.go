package repository

import (
	"fmt"
	"strings"
	"testing"
)

type exactNativeTupleScanner struct{}

func (exactNativeTupleScanner) Scan(dest ...interface{}) error {
	if len(dest) != 44 {
		return fmt.Errorf("scan destination count = %d, want 44 including endpoint_id", len(dest))
	}
	endpointID, ok := dest[4].(*string)
	if !ok {
		return fmt.Errorf("endpoint_id destination has type %T, want *string", dest[4])
	}
	toolCallID, ok := dest[30].(*string)
	if !ok {
		return fmt.Errorf("tool_call_id destination has type %T, want *string", dest[30])
	}
	*endpointID = "ep-native-exact"
	*toolCallID = "toolu-native-exact"
	return nil
}

func TestToolCallLogProjectionRetainsExactNativeEndpointTuple(t *testing.T) {
	for name, projection := range map[string]string{
		"unqualified": toolCallLogSelectColumns,
		"qualified":   toolCallLogSelectColumnsQualified,
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(projection, "endpoint_id") {
				t.Fatalf("%s projection omits endpoint_id", name)
			}
		})
	}

	log, err := scanToolCallLog(exactNativeTupleScanner{})
	if err != nil {
		t.Fatalf("scan tool call log: %v", err)
	}
	if log.EndpointID != "ep-native-exact" || log.ToolCallID != "toolu-native-exact" {
		t.Fatalf("exact native tuple = endpoint %q / tool call %q, want ep-native-exact / toolu-native-exact",
			log.EndpointID, log.ToolCallID)
	}
}
