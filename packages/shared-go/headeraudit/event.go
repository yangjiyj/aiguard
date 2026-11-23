package headeraudit

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalidEvent = errors.New("invalid header conflict audit event")

var allowedServices = map[string]struct{}{
	"control-plane.internal":           {},
	"control-plane.eval-integration":   {},
	"control-plane.portal-integration": {},
	"gateway-core.api":                 {},
	"gateway-core.reverse-proxy":       {},
	"proxy-server.mitm":                {},
}

var allowedHeaderKinds = map[string]struct{}{
	"internal_token": {},
	"tenant_id":      {},
	"session_id":     {},
	"workspace_id":   {},
	"agent_type":     {},
}

// Event is the authenticated envelope. OccurrenceID is the durable idempotency
// identity; Payload returns the only four fields allowed in persisted detail.
type Event struct {
	OccurrenceID string `json:"occurrence_id"`
	Service      string `json:"service"`
	HeaderKind   string `json:"header_kind"`
	RequestID    string `json:"request_id"`
	SourceIP     string `json:"source_ip"`
}

func (e Event) Validate() error {
	if _, ok := allowedServices[e.Service]; !ok {
		return ErrInvalidEvent
	}
	if _, ok := allowedHeaderKinds[e.HeaderKind]; !ok {
		return ErrInvalidEvent
	}
	if _, err := uuid.Parse(e.OccurrenceID); err != nil {
		return ErrInvalidEvent
	}
	if !validASCII(e.RequestID) {
		return ErrInvalidEvent
	}
	if e.SourceIP != "" && net.ParseIP(e.SourceIP) == nil {
		return ErrInvalidEvent
	}
	return nil
}

func (e Event) Payload() map[string]any {
	return map[string]any{
		"service": e.Service, "header_kind": e.HeaderKind,
		"request_id": e.RequestID, "source_ip": e.SourceIP,
	}
}

func NewEvent(service, headerKind string, header http.Header, remoteAddr string) (Event, error) {
	e := Event{
		OccurrenceID: uuid.NewString(),
		Service:      service,
		HeaderKind:   headerKind,
		RequestID:    safeRequestID(header),
		SourceIP:     sourceIP(remoteAddr),
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}

func safeRequestID(header http.Header) string {
	values := make([]string, 0, 1)
	for key, rawValues := range header {
		if !strings.EqualFold(key, "X-Request-Id") {
			continue
		}
		for _, raw := range rawValues {
			value := strings.Trim(raw, " \t")
			if value != "" {
				values = append(values, value)
			}
		}
	}
	if len(values) == 1 && validASCII(values[0]) {
		return values[0]
	}
	return uuid.NewString()
}

func validASCII(value string) bool {
	if value == "" || len(value) > 128 || strings.Contains(value, ",") {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func sourceIP(remoteAddr string) string {
	host := remoteAddr
	if split, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = split
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}
