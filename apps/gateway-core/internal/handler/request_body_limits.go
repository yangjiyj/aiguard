package handler

import (
	"log"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

const maxAPIRequestBodyBytes int64 = 200 << 20

func apiRequestBodyLimitBytes(cfg *config.Config) int64 {
	if cfg != nil && cfg.APIRequestBodyLimitBytes > 0 && cfg.APIRequestBodyLimitBytes <= maxAPIRequestBodyBytes {
		return cfg.APIRequestBodyLimitBytes
	}
	return maxAPIRequestBodyBytes
}

func logRequestBodyTooLarge(r *http.Request, requestID string, limitBytes int64) {
	log.Printf(
		"request body rejected: request=%s path=%s content_length=%d limit_bytes=%d",
		requestID, r.URL.Path, r.ContentLength, limitBytes,
	)
}
