package handler

import (
	"net/url"
	"reflect"
	"testing"
)

func TestContentAuditMultiQueryAcceptsRepeatedAndCSVValues(t *testing.T) {
	values := url.Values{
		"category": {"prompt_injection,secret_leak", "pii"},
	}
	got, err := contentAuditMultiQuery(values, "category", 20)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"prompt_injection", "secret_leak", "pii"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestContentAuditMultiQueryRejectsOversizedSets(t *testing.T) {
	values := url.Values{"severity": {"low,medium,high,critical,info"}}
	if _, err := contentAuditMultiQuery(values, "severity", 4); err == nil {
		t.Fatal("expected oversized filter to fail")
	}
}
