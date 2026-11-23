package headercompat

import (
	"errors"
	"net/http"
	"strings"
)

// ErrConflict deliberately carries no header name or value.
var ErrConflict = errors.New("header value conflict")

type Source string

const (
	SourceNone   Source = "none"
	SourceNew    Source = "new"
	SourceLegacy Source = "legacy"
	SourceBoth   Source = "both"
)

// Resolve reads every field-value for newName and legacyName. It treats the
// headers as scalar security metadata: comma folding and multiple distinct
// non-empty values are rejected. Only ASCII SP/HTAB are trimmed.
func Resolve(header http.Header, newName, legacyName string) (string, Source, error) {
	type seenValue struct {
		value string
		from  Source
	}
	seen := make([]seenValue, 0, 2)
	for key, values := range header {
		from := SourceNone
		switch {
		case newName != "" && strings.EqualFold(key, newName):
			from = SourceNew
		case legacyName != "" && strings.EqualFold(key, legacyName):
			from = SourceLegacy
		default:
			continue
		}
		for _, raw := range values {
			value := strings.Trim(raw, " \t")
			if value == "" {
				continue
			}
			if strings.Contains(value, ",") {
				return "", SourceNone, ErrConflict
			}
			seen = append(seen, seenValue{value: value, from: from})
		}
	}
	if len(seen) == 0 {
		return "", SourceNone, nil
	}
	want := seen[0].value
	source := seen[0].from
	for _, item := range seen[1:] {
		if item.value != want {
			return "", SourceNone, ErrConflict
		}
		if item.from != source {
			source = SourceBoth
		}
	}
	return want, source, nil
}
