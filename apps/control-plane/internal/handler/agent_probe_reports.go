package handler

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
)

type aiprobeReportRepository interface {
	AcceptAiprobeReport(context.Context, string, string, *probereports.Report) (*repository.AiprobeReportReceipt, error)
}

// ProbeReports is the private, endpoint-authenticated intake used by aiprobe.
// Tenant and endpoint scope always come from EndpointAuth, never the report body.
func (h *AgentEndpointAPI) ProbeReports(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return
	}
	ctx := endpointContext(r)
	if ctx == nil || ctx.TenantID == "" || ctx.EndpointID == "" || ctx.Revoked {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if ctx.AgentProduct != "aiprobe" {
		http.Error(w, "aiprobe endpoint required", http.StatusForbidden)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return
	}
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, probereports.MaxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid report body", http.StatusBadRequest)
		}
		return
	}
	report, err := probereports.Decode(data)
	if err != nil {
		http.Error(w, "invalid aiprobe report", http.StatusUnprocessableEntity)
		return
	}
	if report.EndpointID != ctx.EndpointID {
		http.Error(w, "endpoint mismatch", http.StatusUnauthorized)
		return
	}
	repo, ok := h.Repo.(aiprobeReportRepository)
	if !ok || repo == nil {
		http.Error(w, "probe report intake unavailable", http.StatusServiceUnavailable)
		return
	}
	receipt, err := repo.AcceptAiprobeReport(r.Context(), ctx.TenantID, ctx.EndpointID, report)
	switch {
	case errors.Is(err, repository.ErrAiprobeReportInvalid):
		http.Error(w, "invalid aiprobe report", http.StatusUnprocessableEntity)
		return
	case errors.Is(err, repository.ErrAiprobeReportConflict):
		http.Error(w, "report identity conflicts with stored content", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "probe report storage failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeAgentAdminJSON(w, http.StatusOK, receipt)
}
