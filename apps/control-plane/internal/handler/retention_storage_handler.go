package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

type retentionStorageConfigRequest struct {
	Backend     string `json:"backend"`
	LocalPath   string `json:"local_path"`
	S3Endpoint  string `json:"s3_endpoint"`
	S3Bucket    string `json:"s3_bucket"`
	S3AccessKey string `json:"s3_access_key"`
	S3SecretKey string `json:"s3_secret_key"` // 仅写入/测试时传;为空=保留原密钥
	S3Region    string `json:"s3_region"`
	S3Prefix    string `json:"s3_prefix"`
	S3UseSSL    bool   `json:"s3_use_ssl"`
}

// GetRetentionStorageConfig 返回当前留存存储配置(不含明文 secret,仅 has_secret 标志)。
func GetRetentionStorageConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.GetUser(r.Context()) == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		s, err := retentionstore.ReadSettings(r.Context(), deps.UsageDailyRepo.DB())
		if err != nil {
			writeError(w, "internal_error", "failed to read storage config")
			return
		}
		backend := s.Backend
		if backend == "" {
			backend = retentionstore.BackendLocal
		}
		writeJSON(w, map[string]interface{}{
			"backend": backend, "local_path": s.LocalPath,
			"s3_endpoint": s.S3Endpoint, "s3_bucket": s.S3Bucket, "s3_access_key": s.S3AccessKey,
			"s3_region": s.S3Region, "s3_prefix": s.S3Prefix, "s3_use_ssl": s.S3UseSSL,
			"has_secret": s.HasSecret, "updated_at": s.UpdatedAt, "updated_by": s.UpdatedBy,
		})
	}
}

// UpdateRetentionStorageConfig 保存配置(平台管理员)。s3_secret_key 为空=保留原密钥。
func UpdateRetentionStorageConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		var req retentionStorageConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		settings := retentionstore.StorageSettings{
			Backend:     strings.TrimSpace(req.Backend),
			LocalPath:   strings.TrimSpace(req.LocalPath),
			S3Endpoint:  strings.TrimSpace(req.S3Endpoint),
			S3Bucket:    strings.TrimSpace(req.S3Bucket),
			S3AccessKey: strings.TrimSpace(req.S3AccessKey),
			S3Region:    strings.TrimSpace(req.S3Region),
			S3Prefix:    strings.TrimSpace(req.S3Prefix),
			S3UseSSL:    req.S3UseSSL,
		}
		if err := retentionstore.SaveConfig(r.Context(), deps.UsageDailyRepo.DB(), settings, req.S3SecretKey, user.Username); err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	}
}

// TestRetentionStorageConfig 测试连接。s3 走 Ping(用传入密钥或已存密钥);
// local/挂载目录由 proxy-server 运行时校验,此处不远程测。
func TestRetentionStorageConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.GetUser(r.Context()) == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		var req retentionStorageConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		if strings.TrimSpace(req.Backend) != retentionstore.BackendS3 {
			writeJSON(w, map[string]interface{}{"ok": true, "message": "本地/挂载目录的可写性由留存服务(proxy-server)加载时校验,此处不远程测试"})
			return
		}
		secret := req.S3SecretKey
		if strings.TrimSpace(secret) == "" {
			if cfg, err := retentionstore.LoadConfig(r.Context(), deps.UsageDailyRepo.DB(), ""); err == nil {
				secret = cfg.S3SecretKey
			}
		}
		store, err := retentionstore.NewS3Store(retentionstore.Config{
			Backend: retentionstore.BackendS3, S3Endpoint: req.S3Endpoint, S3Bucket: req.S3Bucket,
			S3AccessKey: req.S3AccessKey, S3SecretKey: secret, S3Region: req.S3Region,
			S3UseSSL: req.S3UseSSL, S3Prefix: req.S3Prefix,
		})
		if err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "message": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := store.Ping(ctx); err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "message": err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "message": "连接成功,bucket 可达"})
	}
}
