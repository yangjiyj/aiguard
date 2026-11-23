package errmodel

import (
	"encoding/json"
	"net/http"
)

// ErrorCode defines standard error codes for the API
type ErrorCode string

const (
	ErrUnauthorized        ErrorCode = "unauthorized"
	ErrInvalidRequest      ErrorCode = "invalid_request"
	ErrForbiddenModel      ErrorCode = "forbidden_model"
	ErrQuotaExceeded       ErrorCode = "quota_exceeded"
	ErrRateLimited         ErrorCode = "rate_limited"
	ErrSecurityBlocked     ErrorCode = "security_blocked"
	ErrProviderUnavailable ErrorCode = "provider_unavailable"
	ErrNotFound            ErrorCode = "not_found"
	ErrInternal            ErrorCode = "internal_error"
)

// ErrorDetail represents a single error in API responses
type ErrorDetail struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id,omitempty"`
	Action    string    `json:"action,omitempty"`
}

// ErrorResponse is the standard error response envelope
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(code ErrorCode, message, requestID string) *ErrorResponse {
	return &ErrorResponse{
		Error: ErrorDetail{
			Code:      code,
			Message:   message,
			RequestID: requestID,
		},
	}
}

// WriteError writes a structured error response to the HTTP response
func WriteError(w http.ResponseWriter, status int, err *ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if encodeErr := json.NewEncoder(w).Encode(err); encodeErr != nil {
		return
	}
}

// WriteErrorWithCode is a convenience function that determines HTTP status from error code
func WriteErrorWithCode(w http.ResponseWriter, code ErrorCode, message, requestID string) {
	status := GetHTTPStatus(code)
	WriteError(w, status, NewErrorResponse(code, message, requestID))
}

// GetHTTPStatus maps error codes to HTTP status codes
func GetHTTPStatus(code ErrorCode) int {
	switch code {
	case ErrUnauthorized:
		return http.StatusUnauthorized
	case ErrForbiddenModel, ErrSecurityBlocked:
		return http.StatusForbidden
	case ErrQuotaExceeded, ErrRateLimited:
		return http.StatusTooManyRequests
	case ErrInvalidRequest:
		return http.StatusBadRequest
	case ErrNotFound:
		return http.StatusNotFound
	case ErrProviderUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// IsRetryable determines if an error is potentially retryable
func IsRetryable(code ErrorCode) bool {
	switch code {
	case ErrProviderUnavailable, ErrRateLimited:
		return true
	default:
		return false
	}
}
