package handler

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
)

const probeReportBodyLimit = probereports.MaxBodyBytes

func (g *AgentEndpointGateway) probeReports(w http.ResponseWriter, r *http.Request, token string, endpoint map[string]any) {
	if r.URL.RawQuery != "" {
		jsonError(w, http.StatusBadRequest, "AGENT_INVALID_REQUEST", "query parameters are not accepted")
		return
	}
	if stringValue(endpoint["agent_product"]) != "aiprobe" {
		jsonError(w, http.StatusForbidden, "AGENT_PRODUCT_UNSUPPORTED", "aiprobe endpoint required")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		jsonError(w, http.StatusUnsupportedMediaType, "AGENT_CONTENT_TYPE_UNSUPPORTED", "application/json required")
		return
	}
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" && encoding != "gzip" {
		jsonError(w, http.StatusUnsupportedMediaType, "AGENT_CONTENT_ENCODING_UNSUPPORTED", "unsupported content encoding")
		return
	}
	if r.ContentLength > probeReportBodyLimit {
		jsonError(w, http.StatusRequestEntityTooLarge, "AGENT_PAYLOAD_TOO_LARGE", "probe report too large")
		return
	}
	compressedBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, probeReportBodyLimit))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			jsonError(w, http.StatusRequestEntityTooLarge, "AGENT_PAYLOAD_TOO_LARGE", "probe report too large")
		} else {
			jsonError(w, http.StatusBadRequest, "AGENT_INVALID_REQUEST", "invalid report body")
		}
		return
	}
	var body []byte
	if encoding == "gzip" {
		z, err := gzip.NewReader(bytes.NewReader(compressedBody))
		if err != nil {
			jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "invalid compressed report")
			return
		}
		body, err = io.ReadAll(io.LimitReader(z, probeReportBodyLimit+1))
		closeErr := z.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "invalid compressed report")
			return
		}
	} else {
		body = compressedBody
	}
	if int64(len(body)) > probeReportBodyLimit {
		jsonError(w, http.StatusRequestEntityTooLarge, "AGENT_PAYLOAD_TOO_LARGE", "probe report too large")
		return
	}

	report, err := probereports.Decode(body)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "invalid probe report")
		return
	}
	if report.EndpointID != stringValue(endpoint["endpoint_id"]) {
		jsonError(w, http.StatusUnauthorized, "AGENT_UNAUTHORIZED", "endpoint identity mismatch")
		return
	}
	g.proxyBody(w, r, "/admin/v1/internal/agent/probe-reports", token, body)
}
