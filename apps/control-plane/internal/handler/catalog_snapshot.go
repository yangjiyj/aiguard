package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type catalogSnapshotStore interface {
	BeginCatalogSync(context.Context, string, string) (string, error)
	FailCatalogSync(context.Context, string, string, string, string) error
	ApplyCatalogSnapshot(context.Context, repository.CatalogSnapshotInput) (repository.CatalogSnapshotResult, error)
	CatalogSyncState(context.Context, string, string) (repository.CatalogSyncState, error)
	SetCatalogSyncInterval(context.Context, string, string, int) error
}

// catalogProbeEvidenceLookup 是 catalogSnapshotStore 的可选扩展：查出探测证据仍可沿用的已纳入模型。
type catalogProbeEvidenceLookup interface {
	CatalogModelsWithValidProbe(context.Context, string, *repository.Provider) (map[string]bool, error)
}
type catalogSyncDiagnosticProber struct {
	base     catalog.ModelProber
	failures map[string]bool
}

func (p *catalogSyncDiagnosticProber) Probe(ctx context.Context, input catalog.ModelProbeRequest) catalog.ModelProbeResult {
	result := p.base.Probe(ctx, input)
	if !result.OK {
		p.failures[safeProbeErrorKind(result.ErrorKind)] = true
	}
	return result
}

type catalogSyncError struct{ code, message string }

// catalogProbeConcurrency 是一次目录同步里同时进行的模型探测数。每个探测是一次真实推理调用
// （文本模型 chat + responses 各一次，图片模型真生成一张图），串行时勾 20 个模型要 5–8 分钟；
// 4 路并发把时间压到原来的约四分之一，又不至于把上游打到限流。
const catalogProbeConcurrency = 4

// probeCatalogSelection 并发探测 items 里已勾选的模型，结果原地写回各自的元素。
// 每个 worker 只写自己领到的那个下标，失败原因各自收集，不会串到别的模型上。
func probeCatalogSelection(ctx context.Context, prober catalog.ModelProber, provider *repository.Provider, key string, items []repository.CatalogSnapshotModel) {
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < catalogProbeConcurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				probeCatalogItem(ctx, prober, provider, key, &items[i])
			}
		}()
	}
	for i := range items {
		if items[i].Approved && !items[i].Reused {
			jobs <- i
		}
	}
	close(jobs)
	wg.Wait()
}

func probeCatalogItem(ctx context.Context, prober catalog.ModelProber, provider *repository.Provider, key string, item *repository.CatalogSnapshotModel) {
	diagnostics := &catalogSyncDiagnosticProber{base: prober, failures: map[string]bool{}}
	protocols, record, probeErr := probeCatalogModelProtocols(ctx, diagnostics, provider, key, item.ID)
	item.HealthObservedAt = time.Now().UTC()
	if probeErr == nil {
		item.Capabilities["protocols"] = protocols
		item.Probe = &record
		return
	}
	reasons := []string{}
	for reason := range diagnostics.failures {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	item.ProbeFailure = strings.Join(reasons, "/")
	if item.ProbeFailure == "" {
		item.ProbeFailure = "unknown"
	}
}

func (e *catalogSyncError) Error() string { return e.message }
func catalogFailureCode(err error) string {
	for _, code := range []string{"401", "403", "429", "500", "502", "503", "504"} {
		if strings.Contains(err.Error(), "status "+code) {
			return "catalog_http_" + code
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
		return "catalog_timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "catalog_cancelled"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "catalog_timeout"
	}
	var requestError *url.Error
	if errors.As(err, &requestError) {
		return "catalog_network_failure"
	}
	for _, word := range []string{"incomplete", "pagination", "total"} {
		if strings.Contains(err.Error(), word) {
			return "catalog_incomplete"
		}
	}
	if strings.Contains(err.Error(), "failure") || strings.Contains(err.Error(), "error envelope") {
		return "catalog_error_response"
	}
	return "catalog_invalid_response"
}
func runCatalogSnapshot(ctx context.Context, deps *Dependencies, store catalogSnapshotStore, tenantID string, provider *repository.Provider, selection []string, source string) (repository.CatalogSnapshotResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	empty := repository.CatalogSnapshotResult{}
	token, err := store.BeginCatalogSync(ctx, tenantID, provider.ID)
	if err != nil {
		if errors.Is(err, repository.ErrCatalogSyncConflict) {
			return empty, &catalogSyncError{"sync_in_progress", "该渠道正在同步，请稍后重试"}
		}
		return empty, &catalogSyncError{"sync_storage_unavailable", "同步状态无法读取，未更改目录"}
	}
	completed := false
	failure := "sync_interrupted"
	defer func() {
		if !completed {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = store.FailCatalogSync(cleanup, tenantID, provider.ID, token, failure)
		}
	}()
	fail := func(code, message string) (repository.CatalogSnapshotResult, error) {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = "sync_timeout"
			message = "同步超时，未提交目录变更，已保留上次有效状态"
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			code = "sync_cancelled"
			message = "同步已取消，未提交目录变更"
		}
		failure = code
		return empty, &catalogSyncError{code, message}
	}
	cred, err := deps.ProviderRepo.GetCredential(ctx, provider.ID)
	if err != nil || cred == nil || cred.Status != "active" {
		return fail("provider_not_configured", "渠道缺少有效凭据，已保留上次目录")
	}
	key, err := secrets.DecryptProviderSecret(cred.SecretCiphertext)
	if err != nil {
		return fail("credential_unavailable", "渠道凭据无法读取，已保留上次目录")
	}
	factory := deps.CatalogFactory
	if factory == nil {
		factory = catalog.NewFactory()
	}
	client, err := factory.GetClient(provider.ProviderType)
	if err != nil {
		return fail("provider_unsupported", "渠道不支持完整模型目录同步")
	}
	proxy, err := loadConfiguredOutboundProxyURL(ctx, deps)
	if err != nil {
		return fail("proxy_configuration_error", "出站代理配置无法读取，已保留上次目录")
	}
	models, err := client.FetchModels(catalog.WithOutboundProxy(ctx, proxy), provider.BaseURL, key)
	if err != nil {
		if catalog.IsProviderUnsupported(err) {
			return fail("provider_unsupported", "渠道不支持模型枚举，请手工维护")
		}
		code := catalogFailureCode(err)
		return fail(code, "上游目录同步失败（"+code+"），已保留上次有效目录")
	}
	if models == nil {
		return fail("catalog_empty_response", "上游未返回明确的目录数组，已保留上次目录")
	}
	wanted := map[string]bool{}
	for _, id := range selection {
		wanted[id] = true
	}
	input := repository.CatalogSnapshotInput{TenantID: tenantID, Provider: provider, CredentialID: cred.ID, LeaseToken: token, Source: source, SelectedIDs: selection}
	seen := map[string]bool{}
	for _, entry := range models {
		if entry.ID == "" || seen[entry.ID] || (entry.Object != "" && entry.Object != "model") {
			return fail("catalog_invalid_identity", "目录包含无效或重复模型标识，已保留上次目录")
		}
		seen[entry.ID] = true
		item := repository.CatalogSnapshotModel{ID: entry.ID, Name: entry.Name, Description: entry.Description, Capabilities: classifyModelModality(entry.ID), Approved: wanted[entry.ID]}
		input.Models = append(input.Models, item)
	}
	// Selection is admission; the complete fetched snapshot always reconciles
	// existing managed sources. Scheduled inventory refreshes never probe or
	// activate new models, so they incur no inference calls.
	if lookup, ok := store.(catalogProbeEvidenceLookup); ok && len(selection) > 0 {
		valid, err := lookup.CatalogModelsWithValidProbe(ctx, tenantID, provider)
		if err != nil {
			return fail("sync_storage_unavailable", "探测记录无法读取，未更改目录")
		}
		for i := range input.Models {
			input.Models[i].Reused = input.Models[i].Approved && valid[input.Models[i].ID]
		}
	}
	if deps.ModelProber != nil {
		probeCatalogSelection(ctx, deps.ModelProber, provider, key, input.Models)
	}
	result, err := store.ApplyCatalogSnapshot(ctx, input)
	if err != nil {
		return fail("snapshot_conflict_or_storage_failure", "同步快照已失效或保存失败，未提交目录变更，请重新同步")
	}
	completed = true
	return result, nil
}
func syncCatalogSnapshotHTTP(w http.ResponseWriter, r *http.Request, deps *Dependencies, store catalogSnapshotStore, tenantID string, provider *repository.Provider, selection []string) {
	result, err := runCatalogSnapshot(r.Context(), deps, store, tenantID, provider, selection, "manual")
	if err != nil {
		e := err.(*catalogSyncError)
		status := http.StatusBadGateway
		if e.code == "sync_in_progress" || e.code == "snapshot_conflict_or_storage_failure" {
			status = http.StatusConflict
		}
		if e.code == "provider_unsupported" {
			status = http.StatusBadRequest
		}
		logAudit(r, deps, "sync_models_failed", map[string]interface{}{"provider_id": provider.ID, "error_code": e.code}, "provider", provider.ID)
		writeErrorWithStatus(w, status, e.code, e.message)
		return
	}
	detail := map[string]interface{}{"provider_id": provider.ID, "result": result}
	logAudit(r, deps, "sync_models", detail, "provider", provider.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		repository.CatalogSnapshotResult
		ProviderID       string `json:"provider_id"`
		SelectionApplied bool   `json:"selection_applied"`
	}{result, provider.ID, len(selection) > 0})
}
func CatalogSyncSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		id := r.URL.Query().Get("provider_id")
		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil || provider == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "渠道不存在")
			return
		}
		store, ok := deps.ModelRepo.(catalogSnapshotStore)
		if !ok {
			writeError(w, "unavailable", "同步记录不可用")
			return
		}
		if r.Method == http.MethodPut {
			var body struct {
				IntervalSeconds int `json:"interval_seconds"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || body.IntervalSeconds != 0 && (body.IntervalSeconds < 300 || body.IntervalSeconds > 86400) {
				writeError(w, "invalid_request", "周期应为 0（关闭）或 300–86400 秒")
				return
			}
			if err = store.SetCatalogSyncInterval(r.Context(), user.TenantID, id, body.IntervalSeconds); err != nil {
				writeError(w, "internal_error", "周期设置保存失败")
				return
			}
			logAudit(r, deps, "model_catalog_schedule", map[string]interface{}{"provider_id": id, "interval_seconds": body.IntervalSeconds}, "provider", id)
		}
		state, err := store.CatalogSyncState(r.Context(), user.TenantID, id)
		if err != nil {
			writeError(w, "internal_error", "同步记录读取失败")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}
}
func StartCatalogSyncScheduler(ctx context.Context, db *pgxpool.Pool, deps *Dependencies) {
	store, ok := deps.ModelRepo.(catalogSnapshotStore)
	if !ok {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			// Database leases coordinate every replica. Buffer rows before HTTP/SQL.
			rows, err := db.Query(ctx, `SELECT p.tenant_id,p.id FROM providers p LEFT JOIN model_catalog_sync_state s ON s.provider_id=p.id
    WHERE p.status='active' AND COALESCE(p.auth_mode,'')<>'authorization_raw' AND p.provider_type NOT IN ('azure','anthropic','bedrock','gemini','vertex')
    AND COALESCE(s.interval_seconds,3600)>0 AND COALESCE(s.next_sync_at,NOW())<=NOW() AND (s.lease_token IS NULL OR s.lease_expires_at<NOW()) ORDER BY COALESCE(s.next_sync_at,NOW()),p.id LIMIT 8`)
			if err != nil {
				continue
			}
			type target struct{ tenant, id string }
			targets := []target{}
			for rows.Next() {
				var t target
				if rows.Scan(&t.tenant, &t.id) == nil {
					targets = append(targets, t)
				}
			}
			rows.Close()
			for _, t := range targets {
				if ctx.Err() != nil {
					return
				}
				p, err := deps.ProviderRepo.GetByID(ctx, t.tenant, t.id)
				if err != nil || p == nil {
					continue
				}
				_, _ = runCatalogSnapshot(ctx, deps, store, t.tenant, p, nil, "scheduled")
			}
		}
	}()
}

// Catalog admission uses the provider's actual protocol, including native
// Anthropic channels. Inventory refresh without selection never invokes it.
func probeCatalogModelProtocols(ctx context.Context, prober catalog.ModelProber, provider *repository.Provider, key, model string) (map[string]interface{}, repository.ModelProtocolProbeRecord, error) {
	if provider == nil || prober == nil {
		return nil, repository.ModelProtocolProbeRecord{}, errors.New("model probing unavailable")
	}
	if !strings.EqualFold(strings.TrimSpace(provider.ProviderType), "anthropic") {
		return probeOpenAIModelProtocols(ctx, prober, provider, key, model)
	}
	result := probeModelSafely(ctx, prober, catalog.ModelProbeRequest{BaseURL: provider.BaseURL, APIKey: key, AuthMode: "x-api-key", DeploymentName: model, Protocol: "messages"})
	if !result.OK || !result.PayloadValidated || result.HTTPStatus < 200 || result.HTTPStatus >= 300 {
		return nil, repository.ModelProtocolProbeRecord{}, errors.New("native Messages endpoint was not verified")
	}
	now := time.Now().UTC()
	record := repository.ModelProtocolProbeRecord{
		SourceVersion: "model-protocol-probe-" + uuid.NewString(), ProviderConfigDigest: repository.VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode),
		VerifiedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), Endpoints: []repository.ModelEndpointProbeResult{{EndpointType: "messages", State: "supported"}},
	}
	return map[string]interface{}{"anthropic_messages": true, "metadata": map[string]interface{}{"verified": true, "source": "live_protocol_probe", "version": record.SourceVersion}}, record, nil
}
