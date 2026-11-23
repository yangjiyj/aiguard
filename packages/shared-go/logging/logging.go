package logging

import (
	"context"
	"log/slog"
	"os"
)

// Context keys for logging values
type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	TenantIDKey  contextKey = "tenant_id"
	ProjectIDKey contextKey = "project_id"
	UserIDKey    contextKey = "user_id"
)

// Logger is the global logger instance
var Logger *slog.Logger

// Init initializes the global logger
func Init(level string) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(Logger)
}

// WithContext returns a logger with context values attached
func WithContext(ctx context.Context) *slog.Logger {
	if Logger == nil {
		Init("info")
	}

	attrs := []any{}

	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		attrs = append(attrs, slog.String("request_id", requestID.(string)))
	}
	if tenantID := ctx.Value(TenantIDKey); tenantID != nil {
		attrs = append(attrs, slog.String("tenant_id", tenantID.(string)))
	}
	if projectID := ctx.Value(ProjectIDKey); projectID != nil {
		attrs = append(attrs, slog.String("project_id", projectID.(string)))
	}
	if userID := ctx.Value(UserIDKey); userID != nil {
		attrs = append(attrs, slog.String("user_id", userID.(string)))
	}

	if len(attrs) == 0 {
		return Logger
	}

	return Logger.With(attrs...)
}

// Debug logs a debug message
func Debug(msg string, args ...any) {
	if Logger != nil {
		Logger.Debug(msg, args...)
	}
}

// Info logs an info message
func Info(msg string, args ...any) {
	if Logger != nil {
		Logger.Info(msg, args...)
	}
}

// Warn logs a warning message
func Warn(msg string, args ...any) {
	if Logger != nil {
		Logger.Warn(msg, args...)
	}
}

// Error logs an error message
func Error(msg string, args ...any) {
	if Logger != nil {
		Logger.Error(msg, args...)
	}
}

// InfoCtx logs an info message with context
func InfoCtx(ctx context.Context, msg string, args ...any) {
	WithContext(ctx).Info(msg, args...)
}

// WarnCtx logs a warning message with context
func WarnCtx(ctx context.Context, msg string, args ...any) {
	WithContext(ctx).Warn(msg, args...)
}

// ErrorCtx logs an error message with context
func ErrorCtx(ctx context.Context, msg string, args ...any) {
	WithContext(ctx).Error(msg, args...)
}
