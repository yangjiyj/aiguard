package handler

import (
	"net/http/httptest"
	"testing"
)

func TestAlertOccurrenceDispositionFilter(t *testing.T) {
	for _, status := range []string{"pending", "all", "handled", "false_positive"} {
		f, err := parseAlertOccurrenceFilter(httptest.NewRequest("GET", "/alerts?disposition="+status, nil))
		if err != nil || f.Disposition != status {
			t.Fatalf("%s: %+v %v", status, f, err)
		}
		if (status == "all" || status == "false_positive") && !f.IncludeSuppressed {
			t.Fatal("tab must include suppressed records")
		}
	}
	if _, err := parseAlertOccurrenceFilter(httptest.NewRequest("GET", "/alerts?disposition=anything", nil)); err == nil {
		t.Fatal("unknown status accepted")
	}
}
