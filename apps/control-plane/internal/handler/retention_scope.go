package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const customerRetentionScope = "customer"

type scopedAccessContentRepo interface {
	GetAccessContentLogScoped(context.Context, string, string, time.Time, time.Time, string) (*repository.AccessContentLog, error)
	GetAccessContentLogsScoped(context.Context, string, []string, time.Time, time.Time, string) ([]repository.AccessContentLog, error)
}

type scopedUploadedFileReader interface {
	ResolveUploadedFileBytesScoped(context.Context, string, []string, time.Time, time.Time, string) (map[string]repository.ResolvedUploadedFile, error)
}

type scopedContentLogReader interface {
	ListByRequestScoped(context.Context, string, string, time.Time, time.Time, string) ([]repository.ContentLog, error)
}

type scopedContentLogBatchReader interface {
	ListByRequestsScoped(context.Context, string, []string, time.Time, time.Time, string) ([]repository.ContentLog, error)
}

type scopedContentLogSessionReader interface {
	ListBySessionScoped(context.Context, string, string, time.Time, time.Time, string) ([]repository.ContentLog, error)
	ListBySessionPageScoped(context.Context, string, string, bool, int, int, time.Time, time.Time, string) ([]repository.ContentLog, int, error)
	ListByUserScoped(context.Context, string, string, int, int, time.Time, time.Time, string) ([]repository.ContentLog, int, error)
}

type scopedRetainedArtifactRepo interface {
	GetRetainedArtifactScoped(context.Context, string, string, string, time.Time, time.Time, string) (*repository.RetainedArtifact, error)
	ListRetainedArtifactsScoped(context.Context, string, string, time.Time, time.Time, string) ([]repository.RetainedArtifact, error)
	ListRetainedArtifactsByRequestsScoped(context.Context, string, []string, time.Time, time.Time, string) ([]repository.RetainedArtifact, error)
}

func retentionScopeAndWindow(r *http.Request) (string, time.Time, time.Time, error) {
	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	if r == nil {
		return customerRetentionScope, start, end, nil
	}
	fromValue := strings.TrimSpace(r.URL.Query().Get("from"))
	toValue := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromValue == "" && toValue == "" {
		return customerRetentionScope, start, end, nil
	}
	from, err := time.Parse(time.RFC3339, fromValue)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	end, err = time.Parse(time.RFC3339, toValue)
	if err != nil || !end.After(from) {
		if err == nil {
			err = errors.New("retention window must be half-open and end after start")
		}
		return "", time.Time{}, time.Time{}, err
	}
	return customerRetentionScope, from.UTC(), end.UTC(), nil
}

func getAccessContentLog(
	ctx context.Context,
	repo AccessContentRepo,
	tenantID string,
	requestID string,
	scope string,
	start, end time.Time,
) (*repository.AccessContentLog, error) {
	if scoped, ok := repo.(scopedAccessContentRepo); ok {
		return scoped.GetAccessContentLogScoped(ctx, tenantID, requestID, start, end, scope)
	}
	return repo.GetAccessContentLog(ctx, tenantID, requestID)
}

func getAccessContentLogs(
	ctx context.Context,
	repo AccessContentRepo,
	tenantID string,
	requestIDs []string,
	scope string,
	start, end time.Time,
) ([]repository.AccessContentLog, error) {
	if scoped, ok := repo.(scopedAccessContentRepo); ok {
		return scoped.GetAccessContentLogsScoped(ctx, tenantID, requestIDs, start, end, scope)
	}
	return repo.GetAccessContentLogs(ctx, tenantID, requestIDs)
}

func resolveUploadedFileBytes(
	ctx context.Context,
	repo AccessContentRepo,
	tenantID string,
	referenceIDs []string,
	scope string,
	start, end time.Time,
) (map[string]repository.ResolvedUploadedFile, error) {
	if scoped, ok := repo.(scopedUploadedFileReader); ok {
		return scoped.ResolveUploadedFileBytesScoped(ctx, tenantID, referenceIDs, start, end, scope)
	}
	return repo.ResolveUploadedFileBytes(ctx, tenantID, referenceIDs)
}

func listContentLogsByRequest(
	ctx context.Context,
	reader ContentLogReader,
	tenantID, requestID, scope string,
	start, end time.Time,
) ([]repository.ContentLog, error) {
	if scoped, ok := reader.(scopedContentLogReader); ok {
		return scoped.ListByRequestScoped(ctx, tenantID, requestID, start, end, scope)
	}
	return reader.ListByRequest(ctx, tenantID, requestID)
}

func listContentLogsBySession(ctx context.Context, repo *repository.ContentLogRepository, tenantID, sessionID, scope string, start, end time.Time) ([]repository.ContentLog, error) {
	if scoped, ok := interface{}(repo).(interface {
		ListBySessionScoped(context.Context, string, string, time.Time, time.Time, string) ([]repository.ContentLog, error)
	}); ok {
		return scoped.ListBySessionScoped(ctx, tenantID, sessionID, start, end, scope)
	}
	return repo.ListBySession(ctx, tenantID, sessionID)
}
