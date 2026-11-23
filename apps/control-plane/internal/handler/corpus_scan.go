package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/corpusscan"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

// 训练语料扫描（规格第 5 节）：分片上传到留存卷本地后端，后台逐批调用引擎，生成报告和脱敏副本。
const (
	corpusScanMaxChunkBytes = 8 << 20
	corpusScanListLimit     = 50
	// 下载路由不受全局 30 秒超时约束，写超时按此上限逐次延长。
	corpusScanDownloadWindow = 10 * time.Minute
	corpusScanPollInterval   = 5 * time.Second
	corpusScanCleanupEvery   = time.Hour
)

var corpusScanIDPattern = regexp.MustCompile(`^corpus_[0-9a-f-]{36}$`)

// CorpusScanBlobStore 是本功能用到的留存存储能力。只接受本地后端：S3 后端会把整个对象读进内存。
type CorpusScanBlobStore interface {
	PutObject(ctx context.Context, input retentionstore.PutObjectInput) (retentionstore.ObjectMetadata, error)
	GetObject(ctx context.Context, tenantID, key string) (retentionstore.Object, error)
	DeleteObject(ctx context.Context, tenantID, key string) error
}

// corpusEngine 是执行器用到的引擎能力（测试替换）。
type corpusEngine interface {
	corpusscan.Engine
	Extract(ctx context.Context, tenantID, jobID, fileName, format string, data []byte) (corpusExtractResult, error)
}

// CorpusScanHandler 提供 /admin/v1/security/corpus-scans 路由，并在后台执行扫描任务。
type CorpusScanHandler struct {
	deps      *Dependencies
	store     CorpusScanStore
	blobs     CorpusScanBlobStore
	localOK   bool
	engine    corpusEngine
	lifecycle context.Context
	owner     string
	wake      chan struct{}
	mu        sync.Mutex
	cancels   map[string]context.CancelFunc
	wg        sync.WaitGroup
	now       func() time.Time
}

// NewCorpusScanHandler 装配处理器并启动执行循环与每小时清理。store 为 nil 时所有接口返回 503。
func NewCorpusScanHandler(deps *Dependencies, store CorpusScanStore, lifecycle context.Context) *CorpusScanHandler {
	h := &CorpusScanHandler{deps: deps, store: store, lifecycle: lifecycle, owner: "cp_" + uuid.NewString(),
		wake: make(chan struct{}, 1), cancels: map[string]context.CancelFunc{}, now: time.Now}
	if deps != nil {
		if local, ok := deps.RetentionStore.(*retentionstore.LocalStore); ok && local != nil {
			h.blobs, h.localOK = local, true
		}
		h.engine = newCorpusEngineClient(deps.SecurityEngineURL, deps.SecurityEngineInternalToken)
	}
	if store != nil && lifecycle != nil {
		h.wg.Add(2)
		go h.runLoop()
		go h.cleanupLoop()
	}
	if h.lifecycle == nil {
		// 测试或不启动后台循环时，同步调用 runOnce 也需要一个有效的父上下文。
		h.lifecycle = context.Background()
	}
	return h
}

// Wait 等后台任务退出（停机时调用）。
func (h *CorpusScanHandler) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { h.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// —— 权限 ——

// corpusScanWriter 允许系统管理员和安全保密员（规格 5.7：SoDSecurityWrite）。
func corpusScanWriter(w http.ResponseWriter, r *http.Request) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil || strings.TrimSpace(user.TenantID) == "" {
		writeUnauthorized(w, "no user")
		return nil
	}
	if !roles.CanManageSecurityPolicy(user.Role) && !roles.IsSystemAdmin(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only system administrators or security officers can manage corpus scans")
		return nil
	}
	return user
}

// corpusScanReader 另外允许审计员查看列表、进度和报告（规格 5.7：SoDSecurityRecordRead）。
func corpusScanReader(w http.ResponseWriter, r *http.Request) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil || strings.TrimSpace(user.TenantID) == "" {
		writeUnauthorized(w, "no user")
		return nil
	}
	if !roles.CanManageSecurityPolicy(user.Role) && !roles.IsSystemAdmin(user.Role) && !roles.IsAuditor(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only system administrators, security officers or auditors can read corpus scans")
		return nil
	}
	return user
}

func (h *CorpusScanHandler) ready(w http.ResponseWriter) bool {
	if h == nil || h.store == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "corpus_scan_unavailable", "corpus scan store is unavailable")
		return false
	}
	if !h.localOK {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "local_storage_required", "corpus scan requires the local retention storage backend")
		return false
	}
	return true
}

func corpusJobID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := chi.URLParam(r, "id")
	if !corpusScanIDPattern.MatchString(id) {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "corpus scan job not found")
		return "", false
	}
	return id, true
}

func writeCorpusStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrCorpusScanNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "corpus scan job not found")
	case errors.Is(err, ErrCorpusScanState):
		writeErrorWithStatus(w, http.StatusConflict, "invalid_state", "corpus scan job is not in the required state")
	case errors.Is(err, ErrCorpusScanChunkOrder):
		writeErrorWithStatus(w, http.StatusConflict, "chunk_out_of_order", "chunks must be uploaded in order")
	case errors.Is(err, ErrCorpusScanTooLarge):
		writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "upload_too_large", "upload exceeds the declared size")
	case errors.Is(err, ErrCorpusScanIncomplete):
		writeErrorWithStatus(w, http.StatusConflict, "upload_incomplete", "upload is incomplete")
	case errors.Is(err, ErrCorpusScanDigest):
		writeErrorWithStatus(w, http.StatusConflict, "sha256_mismatch", "uploaded content does not match the declared sha256")
	default:
		log.Printf("corpus scan store error: %v", err)
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "corpus scan operation failed")
	}
}

func writeCorpusJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// —— 路由 ——

type corpusScanCreateRequest struct {
	FileName  string `json:"file_name"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

var corpusSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Create 新建任务：POST /admin/v1/security/corpus-scans。
func (h *CorpusScanHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := corpusScanWriter(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	var req corpusScanCreateRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	name := path.Base(strings.ReplaceAll(strings.TrimSpace(req.FileName), "\\", "/"))
	format := corpusscan.FormatFromFileName(name)
	req.SHA256 = strings.ToLower(strings.TrimSpace(req.SHA256))
	switch {
	case format == "":
		writeErrorWithStatus(w, http.StatusBadRequest, "unsupported_format", "supported formats: jsonl, csv, txt, docx, pdf, xlsx")
		return
	case len([]rune(name)) > 200:
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "file name is too long")
		return
	case req.SizeBytes <= 0:
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "size_bytes must be positive")
		return
	case req.SizeBytes > corpusscan.MaxFileBytes(format):
		writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "file_too_large", fmt.Sprintf("%s files are limited to %d bytes", format, corpusscan.MaxFileBytes(format)))
		return
	case !corpusSHA256Pattern.MatchString(req.SHA256):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "sha256 must be 64 lowercase hex characters")
		return
	}
	job, err := h.store.Create(r.Context(), CorpusScanCreate{TenantID: user.TenantID, CreatedBy: user.ID, FileName: name, Format: format, SizeBytes: req.SizeBytes, SHA256: req.SHA256})
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	logAudit(r, h.deps, "create_corpus_scan", map[string]interface{}{"job_id": job.ID, "file_name": name, "format": format, "size_bytes": req.SizeBytes}, "corpus_scan", job.ID)
	writeCorpusJSON(w, http.StatusCreated, map[string]any{"job_id": job.ID, "job": job, "chunk_size": corpusScanMaxChunkBytes})
}

// UploadChunk 写入一个分片：PUT .../{id}/chunks/{n}。分片先落盘，再在事务里登记序号和累计哈希。
func (h *CorpusScanHandler) UploadChunk(w http.ResponseWriter, r *http.Request) {
	user := corpusScanWriter(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	id, ok := corpusJobID(w, r)
	if !ok {
		return
	}
	index, err := strconv.Atoi(chi.URLParam(r, "n"))
	if err != nil || index < 0 || index > 1<<20 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid chunk index")
		return
	}
	// 全局 ReadTimeout 是 30 秒；只为这一个请求延长读取期限，慢速链路也能传完 8 MiB。
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(corpusScanDownloadWindow))
	data, err := io.ReadAll(io.LimitReader(r.Body, corpusScanMaxChunkBytes+1))
	if err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "failed to read chunk")
		return
	}
	if len(data) == 0 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "chunk is empty")
		return
	}
	if len(data) > corpusScanMaxChunkBytes {
		writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "chunk_too_large", "chunks are limited to 8 MiB")
		return
	}
	job, err := h.store.Get(r.Context(), user.TenantID, id)
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	if job.Status != "uploading" || job.CancelRequested {
		writeCorpusStoreError(w, ErrCorpusScanState)
		return
	}
	if index != job.NextChunk {
		writeCorpusStoreError(w, ErrCorpusScanChunkOrder)
		return
	}
	if job.UploadedBytes+int64(len(data)) > job.SizeBytes {
		writeCorpusStoreError(w, ErrCorpusScanTooLarge)
		return
	}
	meta, err := h.blobs.PutObject(r.Context(), retentionstore.PutObjectInput{
		TenantID: user.TenantID, RequestID: "corpus", Stage: id, FieldName: "source-" + strconv.Itoa(index),
		FileName: job.FileName, ContentType: "application/octet-stream", Reader: bytes.NewReader(data),
		RetentionUntil: h.now().Add(corpusScanUploadingTimeout + corpusScanRetention),
	})
	if err != nil {
		log.Printf("corpus scan chunk write failed job=%s: %v", id, err)
		writeErrorWithStatus(w, http.StatusInternalServerError, "storage_error", "failed to store chunk")
		return
	}
	job, err = h.store.AppendChunk(r.Context(), user.TenantID, id, CorpusScanChunk{Index: index, Size: int64(len(data)), Key: meta.Key, Data: data})
	if err != nil {
		_ = h.blobs.DeleteObject(context.Background(), user.TenantID, meta.Key)
		writeCorpusStoreError(w, err)
		return
	}
	writeCorpusJSON(w, http.StatusOK, job)
}

// Start 校验总大小和 sha256 后排队：POST .../{id}/start。
func (h *CorpusScanHandler) Start(w http.ResponseWriter, r *http.Request) {
	user := corpusScanWriter(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	id, ok := corpusJobID(w, r)
	if !ok {
		return
	}
	if engine, ok := h.engine.(*corpusEngineClient); ok && !engine.configured() {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "engine_unavailable", "security engine is not configured")
		return
	}
	job, err := h.store.Queue(r.Context(), user.TenantID, id)
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	logAudit(r, h.deps, "start_corpus_scan", map[string]interface{}{"job_id": id, "file_name": job.FileName, "size_bytes": job.SizeBytes}, "corpus_scan", id)
	h.signal()
	writeCorpusJSON(w, http.StatusAccepted, job)
}

// List 列出本租户任务：GET /admin/v1/security/corpus-scans。
func (h *CorpusScanHandler) List(w http.ResponseWriter, r *http.Request) {
	user := corpusScanReader(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	jobs, err := h.store.List(r.Context(), user.TenantID, corpusScanListLimit)
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	for i := range jobs {
		// 列表不带样例，减小轮询负载；详情接口返回完整报告。
		jobs[i].Samples = []corpusscan.Sample{}
		jobs[i].Unscanned = []corpusscan.UnscannedLine{}
	}
	writeCorpusJSON(w, http.StatusOK, map[string]any{"items": jobs, "local_storage": h.localOK})
}

// Get 返回进度和报告：GET .../{id}。
func (h *CorpusScanHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := corpusScanReader(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	id, ok := corpusJobID(w, r)
	if !ok {
		return
	}
	job, err := h.store.Get(r.Context(), user.TenantID, id)
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	writeCorpusJSON(w, http.StatusOK, job)
}

// Cancel 取消任务：POST .../{id}/cancel。
func (h *CorpusScanHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	user := corpusScanWriter(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	id, ok := corpusJobID(w, r)
	if !ok {
		return
	}
	job, err := h.store.Cancel(r.Context(), user.TenantID, id)
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	h.mu.Lock()
	cancel := h.cancels[id]
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if job.Status == "canceled" {
		h.deleteSources(job)
	}
	logAudit(r, h.deps, "cancel_corpus_scan", map[string]interface{}{"job_id": id}, "corpus_scan", id)
	writeCorpusJSON(w, http.StatusOK, job)
}

// Delete 删除任务和它的全部文件：DELETE .../{id}。运行中的任务要先取消。
func (h *CorpusScanHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := corpusScanWriter(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	id, ok := corpusJobID(w, r)
	if !ok {
		return
	}
	job, err := h.store.Delete(r.Context(), user.TenantID, id)
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	h.deleteAllFiles(job)
	logAudit(r, h.deps, "delete_corpus_scan", map[string]interface{}{"job_id": id, "file_name": job.FileName}, "corpus_scan", id)
	writeCorpusJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// DownloadReport 流式下载报告：GET .../{id}/report。审计员可下载（只含统计和打码样例）。
func (h *CorpusScanHandler) DownloadReport(w http.ResponseWriter, r *http.Request) {
	user := corpusScanReader(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	h.download(w, r, user, "report")
}

// DownloadMasked 流式下载脱敏副本：GET .../{id}/masked。只有写权限的角色可下载。
func (h *CorpusScanHandler) DownloadMasked(w http.ResponseWriter, r *http.Request) {
	user := corpusScanWriter(w, r)
	if user == nil || !h.ready(w) {
		return
	}
	h.download(w, r, user, "masked")
}

func (h *CorpusScanHandler) download(w http.ResponseWriter, r *http.Request, user *repository.User, kind string) {
	id, ok := corpusJobID(w, r)
	if !ok {
		return
	}
	job, err := h.store.Get(r.Context(), user.TenantID, id)
	if err != nil {
		writeCorpusStoreError(w, err)
		return
	}
	key, name, contentType := job.ReportKey, corpusDownloadName(job.FileName, "report", "json"), "application/json"
	if kind == "masked" {
		key = job.MaskedKey
		name = corpusDownloadName(job.FileName, "masked", job.MaskedFormat)
		contentType = corpusContentType(job.MaskedFormat)
	}
	if job.Status != "succeeded" || key == "" {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "file is not available")
		return
	}
	obj, err := h.blobs.GetObject(r.Context(), user.TenantID, key)
	if err != nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "file is not available")
		return
	}
	defer obj.Body.Close()
	logAudit(r, h.deps, "download_corpus_scan_"+kind, map[string]interface{}{"job_id": id, "file_name": job.FileName, "size_bytes": obj.Metadata.Size}, "corpus_scan", id)
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(corpusScanDownloadWindow))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(obj.Metadata.Size, 10))
	w.Header().Set("Content-Disposition", contentDisposition(name))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 256<<10)
	for {
		n, readErr := obj.Body.Read(buf)
		if n > 0 {
			_ = controller.SetWriteDeadline(time.Now().Add(corpusScanDownloadWindow))
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

func corpusDownloadName(fileName, kind, ext string) string {
	base := strings.TrimSuffix(fileName, path.Ext(fileName))
	if ext == "" {
		ext = "txt"
	}
	return base + "." + kind + "." + ext
}

func corpusContentType(format string) string {
	switch format {
	case corpusscan.FormatJSONL:
		return "application/x-ndjson; charset=utf-8"
	case corpusscan.FormatCSV:
		return "text/csv; charset=utf-8"
	}
	return "text/plain; charset=utf-8"
}

// contentDisposition 生成下载文件名：ASCII 回退名加 RFC 5987 的 UTF-8 文件名。
func contentDisposition(name string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' || r == '/' {
			return '_'
		}
		return r
	}, name)
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, ascii, encodeRFC5987(name))
}

func encodeRFC5987(value string) string {
	var b strings.Builder
	for _, c := range []byte(value) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte("!#$&+-.^_`|~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// —— 执行器 ——

func (h *CorpusScanHandler) signal() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// runLoop 逐个认领排队任务；全局只有一个任务在运行（数据库部分唯一索引保证跨实例）。
func (h *CorpusScanHandler) runLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(corpusScanPollInterval)
	defer ticker.Stop()
	for {
		if h.lifecycle.Err() != nil {
			return
		}
		for h.runOnce() {
			if h.lifecycle.Err() != nil {
				return
			}
		}
		select {
		case <-h.lifecycle.Done():
			return
		case <-ticker.C:
		case <-h.wake:
		}
	}
}

// runOnce 认领并执行一个任务；没有可认领的任务时返回 false。
func (h *CorpusScanHandler) runOnce() bool {
	if !h.localOK {
		return false
	}
	ctx, cancel := context.WithTimeout(h.lifecycle, 5*time.Second)
	job, ok, err := h.store.ClaimNext(ctx, h.owner)
	cancel()
	if err != nil {
		log.Printf("corpus scan claim failed: %v", err)
		return false
	}
	if !ok {
		return false
	}
	h.execute(job)
	return true
}

func (h *CorpusScanHandler) execute(job CorpusScanJob) {
	ctx, cancel := context.WithCancel(h.lifecycle)
	h.mu.Lock()
	h.cancels[job.ID] = cancel
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.cancels, job.ID)
		h.mu.Unlock()
		cancel()
	}()

	var progressMu sync.Mutex
	progress := corpusscan.Progress{}
	stopHeartbeat := make(chan struct{})
	heartbeatDone := make(chan struct{})
	var heartbeatErr error
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(corpusScanHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopHeartbeat:
				return
			case <-ticker.C:
				progressMu.Lock()
				snapshot := progress
				progressMu.Unlock()
				beatCtx, done := context.WithTimeout(ctx, 5*time.Second)
				err := h.store.Heartbeat(beatCtx, job, snapshot)
				done()
				if err != nil {
					heartbeatErr = err
					cancel()
					return
				}
			}
		}
	}()

	outcome, files := h.scan(ctx, job, func(p corpusscan.Progress) error {
		progressMu.Lock()
		progress = p
		progressMu.Unlock()
		return ctx.Err()
	})
	close(stopHeartbeat)
	<-heartbeatDone

	switch {
	case errors.Is(heartbeatErr, ErrCorpusScanCanceled):
		outcome = CorpusScanOutcome{Status: "canceled", ErrorCode: "canceled", Report: outcome.Report}
	case heartbeatErr != nil || h.lifecycle.Err() != nil:
		// 租约丢失或进程停机。租约已被回收时下面的 Finish 不会改动记录。
		outcome = CorpusScanOutcome{Status: "interrupted", ErrorCode: "worker_interrupted", Report: outcome.Report}
	}
	if outcome.Status != "succeeded" {
		h.deleteKeys(job.TenantID, files)
		outcome.ReportKey, outcome.MaskedKey, outcome.MaskedFormat = "", "", ""
	}
	finishCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
	err := h.store.Finish(finishCtx, job, outcome)
	done()
	switch {
	case err != nil:
		if !errors.Is(err, ErrCorpusScanLeaseLost) {
			log.Printf("corpus scan job %s terminal persistence failed: %v", job.ID, err)
		}
		h.deleteKeys(job.TenantID, files)
	case outcome.Status == "succeeded":
		// 收尾前用户请求了取消：Finish 已记为 canceled，报告和副本不保留。
		if current, getErr := h.store.Get(context.Background(), job.TenantID, job.ID); getErr == nil && current.Status != "succeeded" {
			h.deleteKeys(job.TenantID, files)
		}
	}
	// 原始语料是明文：任何终态都立即删除（规格 5.6）。删除失败由每小时清理重试。
	h.deleteSources(job)
}

// scan 读取原始分片、调用引擎、写报告和副本。返回终态和已写入的文件 key（失败时由调用方删除）。
func (h *CorpusScanHandler) scan(ctx context.Context, job CorpusScanJob, onBatch func(corpusscan.Progress) error) (CorpusScanOutcome, []string) {
	fail := func(code string, report corpusscan.Report) (CorpusScanOutcome, []string) {
		if errors.Is(ctx.Err(), context.Canceled) && h.lifecycle.Err() == nil {
			return CorpusScanOutcome{Status: "canceled", ErrorCode: "canceled", Report: report}, nil
		}
		return CorpusScanOutcome{Status: "failed", ErrorCode: code, Report: report}, nil
	}
	source := &corpusSourceReader{ctx: ctx, blobs: h.blobs, tenant: job.TenantID, keys: job.SourceKeys}
	defer source.Close()

	format := job.Format
	maskedFormat := format
	var notes []string
	var input io.Reader = source
	if corpusscan.IsDocument(format) {
		data, err := io.ReadAll(io.LimitReader(source, corpusscan.MaxDocumentFileBytes+1))
		if err != nil {
			return fail("source_unreadable", corpusscan.Report{})
		}
		extracted, err := h.engine.Extract(ctx, job.TenantID, job.ID, job.FileName, format, data)
		if errors.Is(err, errCorpusExtractRejected) {
			return fail("extract_failed", corpusscan.Report{})
		}
		if err != nil {
			return fail("engine_unavailable", corpusscan.Report{})
		}
		if extracted.Truncated || !extracted.Complete {
			notes = append(notes, "document_text_incomplete")
		}
		input = strings.NewReader(corpusscan.SplitDocumentText(extracted.Text))
		format, maskedFormat = corpusscan.FormatTXT, corpusscan.FormatTXT
	}

	maskedFile, err := os.CreateTemp("", "corpus-masked-*")
	if err != nil {
		return fail("storage_error", corpusscan.Report{})
	}
	defer func() {
		maskedFile.Close()
		os.Remove(maskedFile.Name())
	}()
	report, err := corpusscan.Run(ctx, input, maskedFile, corpusscan.Options{Format: format, Engine: h.engine, OnBatch: onBatch})
	if err != nil {
		code := "scan_failed"
		switch {
		case errors.Is(err, corpusscan.ErrEngineMismatch):
			code = "engine_result_mismatch"
		case errors.Is(err, errCorpusEngineUnavailable):
			code = "engine_unavailable"
		case errors.Is(err, errCorpusSourceUnreadable):
			code = "source_unreadable"
		}
		return fail(code, report)
	}
	if _, err := maskedFile.Seek(0, io.SeekStart); err != nil {
		return fail("storage_error", report)
	}
	retention := h.now().Add(corpusScanRetention + time.Hour)
	maskedMeta, err := h.blobs.PutObject(ctx, retentionstore.PutObjectInput{
		TenantID: job.TenantID, RequestID: "corpus", Stage: job.ID, FieldName: "masked",
		FileName: corpusDownloadName(job.FileName, "masked", maskedFormat), ContentType: corpusContentType(maskedFormat),
		Reader: maskedFile, RetentionUntil: retention,
	})
	if err != nil {
		return fail("storage_error", report)
	}
	files := []string{maskedMeta.Key}
	reportBytes, err := corpusscan.MarshalReport(report, map[string]any{
		"job_id": job.ID, "file_name": job.FileName, "format": job.Format, "size_bytes": job.SizeBytes,
		"sha256": job.SHA256, "masked_format": maskedFormat, "notes": nonNil(notes), "generated_at": h.now().UTC(),
	})
	if err != nil {
		return CorpusScanOutcome{Status: "failed", ErrorCode: "report_failed", Report: report}, files
	}
	reportMeta, err := h.blobs.PutObject(ctx, retentionstore.PutObjectInput{
		TenantID: job.TenantID, RequestID: "corpus", Stage: job.ID, FieldName: "report",
		FileName: corpusDownloadName(job.FileName, "report", "json"), ContentType: "application/json",
		Reader: bytes.NewReader(reportBytes), RetentionUntil: retention,
	})
	if err != nil {
		return CorpusScanOutcome{Status: "failed", ErrorCode: "storage_error", Report: report}, files
	}
	files = append(files, reportMeta.Key)
	return CorpusScanOutcome{Status: "succeeded", Report: report, Notes: notes, ReportKey: reportMeta.Key, MaskedKey: maskedMeta.Key, MaskedFormat: maskedFormat}, files
}

var errCorpusSourceUnreadable = errors.New("corpus source chunk is unreadable")

// corpusSourceReader 按顺序拼接读取原始分片。
type corpusSourceReader struct {
	ctx     context.Context
	blobs   CorpusScanBlobStore
	tenant  string
	keys    []string
	current io.ReadCloser
}

func (r *corpusSourceReader) Read(p []byte) (int, error) {
	for {
		if r.current == nil {
			if len(r.keys) == 0 {
				return 0, io.EOF
			}
			obj, err := r.blobs.GetObject(r.ctx, r.tenant, r.keys[0])
			if err != nil {
				return 0, fmt.Errorf("%w: %v", errCorpusSourceUnreadable, err)
			}
			r.current = obj.Body
			r.keys = r.keys[1:]
		}
		n, err := r.current.Read(p)
		if err == io.EOF {
			r.current.Close()
			r.current = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (r *corpusSourceReader) Close() {
	if r.current != nil {
		r.current.Close()
		r.current = nil
	}
}

func (h *CorpusScanHandler) deleteKeys(tenant string, keys []string) {
	for _, key := range keys {
		if err := h.blobs.DeleteObject(context.Background(), tenant, key); err != nil && !errors.Is(err, retentionstore.ErrObjectNotFound) {
			log.Printf("corpus scan file cleanup failed: %v", err)
		}
	}
}

// deleteSources 删除原始语料分片并清空 key；失败时保留 key，由每小时清理重试。
func (h *CorpusScanHandler) deleteSources(job CorpusScanJob) {
	if h.blobs == nil || len(job.SourceKeys) == 0 {
		return
	}
	for _, key := range job.SourceKeys {
		if err := h.blobs.DeleteObject(context.Background(), job.TenantID, key); err != nil && !errors.Is(err, retentionstore.ErrObjectNotFound) {
			log.Printf("corpus scan source cleanup failed job=%s: %v", job.ID, err)
			return
		}
	}
	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := h.store.ClearSourceKeys(ctx, job); err != nil {
		log.Printf("corpus scan source key reset failed job=%s: %v", job.ID, err)
	}
}

func (h *CorpusScanHandler) deleteAllFiles(job CorpusScanJob) {
	if h.blobs == nil {
		return
	}
	keys := append([]string{}, job.SourceKeys...)
	for _, key := range []string{job.ReportKey, job.MaskedKey} {
		if key != "" {
			keys = append(keys, key)
		}
	}
	h.deleteKeys(job.TenantID, keys)
}

// cleanupLoop 每小时删除过期任务的文件和记录，并补删终态任务残留的原始语料（规格 5.6）。
func (h *CorpusScanHandler) cleanupLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(corpusScanCleanupEvery)
	defer ticker.Stop()
	for {
		h.CleanupOnce(h.lifecycle)
		select {
		case <-h.lifecycle.Done():
			return
		case <-ticker.C:
		}
	}
}

// CleanupOnce 执行一轮清理，返回删除的任务数。
func (h *CorpusScanHandler) CleanupOnce(ctx context.Context) int {
	if h == nil || h.store == nil || h.blobs == nil {
		return 0
	}
	if err := h.store.Reap(ctx); err != nil {
		log.Printf("corpus scan reap failed: %v", err)
	}
	if pending, err := h.store.PendingSourceCleanup(ctx, 100); err == nil {
		for _, job := range pending {
			h.deleteSources(job)
		}
	}
	removed := 0
	expired, err := h.store.Expired(ctx, 200)
	if err != nil {
		log.Printf("corpus scan expiry query failed: %v", err)
		return 0
	}
	for _, job := range expired {
		h.deleteAllFiles(job)
		if err := h.store.Purge(ctx, job); err != nil {
			log.Printf("corpus scan purge failed job=%s: %v", job.ID, err)
			continue
		}
		removed++
	}
	return removed
}
