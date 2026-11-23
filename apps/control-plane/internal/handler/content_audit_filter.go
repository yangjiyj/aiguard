package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func contentAuditMultiQuery(values url.Values, key string, maxValues int) ([]string, error) {
	seen := map[string]struct{}{}
	result := make([]string, 0)
	for _, raw := range values[key] {
		for _, part := range strings.Split(raw, ",") {
			value := strings.ToLower(strings.TrimSpace(part))
			if value == "" {
				continue
			}
			if len(value) > 128 {
				return nil, fmt.Errorf("%s value is too long", key)
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
			if len(result) > maxValues {
				return nil, fmt.Errorf("%s accepts at most %d values", key, maxValues)
			}
		}
	}
	return result, nil
}

func parseContentAuditAlertFilters(w http.ResponseWriter, r *http.Request) (categories, severities, dispositions []string, ok bool) {
	var err error
	categories, err = contentAuditMultiQuery(r.URL.Query(), "category", 20)
	if err == nil {
		severities, err = contentAuditMultiQuery(r.URL.Query(), "severity", 8)
	}
	if err == nil {
		dispositions, err = contentAuditMultiQuery(r.URL.Query(), "disposition", 8)
	}
	if err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, nil, nil, false
	}
	validSeverity := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "warning": true, "info": true, "informational": true}
	for _, value := range severities {
		if !validSeverity[value] {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "unsupported severity")
			return nil, nil, nil, false
		}
	}
	validDisposition := map[string]bool{
		"open": true, "acknowledged": true, "resolved": true,
		"false_positive": true, "accepted": true, "escalated": true,
	}
	for _, value := range dispositions {
		if !validDisposition[value] {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "unsupported disposition")
			return nil, nil, nil, false
		}
	}
	return categories, severities, dispositions, true
}
