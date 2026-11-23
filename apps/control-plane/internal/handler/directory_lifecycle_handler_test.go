package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type lifecycleDirectoryRuntime struct {
	publishCalls   int
	fullSyncCalls  int
	disableCalls   int
	restoreCalls   int
	last           directoryruntime.DirectoryConfig
	snapshot       directoryruntime.RuntimeSnapshot
	publishErr     error
	fullSyncErr    error
	fullSyncErrors []error
	disableErr     error
	restoreErr     error
	onPublish      func()
	onFullSync     func(int)
	onDisable      func()
}

func (runtime *lifecycleDirectoryRuntime) Publish(_ context.Context, config directoryruntime.DirectoryConfig) (directoryruntime.Publication, error) {
	runtime.publishCalls++
	runtime.last = config
	if runtime.onPublish != nil {
		runtime.onPublish()
	}
	return directoryruntime.Publication{Previous: runtime.snapshot}, runtime.publishErr
}

func (runtime *lifecycleDirectoryRuntime) FullSync(context.Context) error {
	runtime.fullSyncCalls++
	if runtime.onFullSync != nil {
		runtime.onFullSync(runtime.fullSyncCalls)
	}
	if runtime.fullSyncCalls <= len(runtime.fullSyncErrors) {
		return runtime.fullSyncErrors[runtime.fullSyncCalls-1]
	}
	return runtime.fullSyncErr
}

func (runtime *lifecycleDirectoryRuntime) Status(context.Context) (directoryruntime.RuntimeStatus, error) {
	return directoryruntime.RuntimeStatus{}, nil
}

func (runtime *lifecycleDirectoryRuntime) Disable(context.Context) (directoryruntime.RuntimeSnapshot, error) {
	runtime.disableCalls++
	if runtime.onDisable != nil {
		runtime.onDisable()
	}
	return runtime.snapshot, runtime.disableErr
}

func (runtime *lifecycleDirectoryRuntime) Restore(context.Context, directoryruntime.RuntimeSnapshot) error {
	runtime.restoreCalls++
	return runtime.restoreErr
}

func seedTestedDirectorySource(t *testing.T, deps *Dependencies, tenantID string) *repository.DirectorySource {
	t.Helper()
	setupIdentitySecretKey(t)
	encrypted, _, err := secrets.EncryptProviderSecret("directory-bind-secret")
	if err != nil {
		t.Fatal(err)
	}
	source := &repository.DirectorySource{
		TenantID: tenantID, Kind: repository.DirectoryKindLDAP, DisplayName: "Lab LDAP",
		ConnectionURL: "ldaps://openldap:636", BindDN: "cn=admin,dc=jjdguard-lab,dc=test",
		BindPasswordEnc: encrypted, BaseDN: "dc=jjdguard-lab,dc=test",
		UsersDN: "ou=People,dc=jjdguard-lab,dc=test",
	}
	if err := deps.DirectorySourceRepo.UpsertDraft(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	if err := deps.DirectorySourceRepo.UpdateTestResult(context.Background(), tenantID, source.ID, source.Version, &repository.TestResult{Success: true}); err != nil {
		t.Fatal(err)
	}
	tested, err := deps.DirectorySourceRepo.GetActivatable(context.Background(), tenantID)
	if err != nil || tested == nil {
		t.Fatalf("seed tested directory source: %#v %v", tested, err)

	}
	return tested
}

func seedSucceededDirectoryPreview(t *testing.T, deps *Dependencies, tenantID, actorID string, source *repository.DirectorySource) string {
	t.Helper()
	preview := &repository.DirectorySyncPreview{
		TenantID: tenantID, DirectorySourceID: source.ID, SourceVersion: source.Version,
		ConfigDigest: "lifecycle-test-digest", ActorUserID: actorID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := deps.DirectorySyncPreviewRepo.CreatePreview(context.Background(), preview); err != nil {
		t.Fatal(err)
	}
	if err := deps.DirectorySyncPreviewRepo.FinalizePreview(
		context.Background(), tenantID, preview.ID, repository.PreviewStatusSucceeded, repository.PreviewCounts{}, "",
	); err != nil {
		t.Fatal(err)
	}
	return preview.ID
}

func TestActivateDirectorySourceUsesTenantTestedSourceAndNeverLeaksCredential(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &lifecycleDirectoryRuntime{snapshot: directoryruntime.RuntimeSnapshot{Exists: true}}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)
	if err := deps.DirectorySourceRepo.MarkRuntimeReconciliationRequired(
		context.Background(),
		tenantID,
		source.ID,
		repository.DirectoryReconciliationReasonPostSyncFailed,
	); err != nil {
		t.Fatal(err)
	}

	request := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/activate", bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`)), tenantID, userID)
	response := httptest.NewRecorder()
	ActivateDirectorySource(deps)(response, request)

	if response.Code != http.StatusOK || runtime.publishCalls != 1 || runtime.fullSyncCalls != 1 {
		t.Fatalf("activate status=%d publish=%d sync=%d body=%s", response.Code, runtime.publishCalls, runtime.fullSyncCalls, response.Body.String())
	}
	active, err := deps.DirectorySourceRepo.GetActive(context.Background(), tenantID)
	if err != nil || active == nil || active.ID != source.ID {
		t.Fatalf("active source=%#v err=%v", active, err)
	}
	if active.RuntimeReconciliationRequired || active.RuntimeReconciliationReason != "" {
		t.Fatalf("successful activation did not clear reconciliation: %#v", active)
	}
	if runtime.last.BindPassword != "directory-bind-secret" || strings.Contains(response.Body.String(), runtime.last.BindPassword) {
		t.Fatalf("directory credential mapping/leak failure: body=%s", response.Body.String())
	}
}

func TestActivateDirectorySourceClaimConflictStopsBeforeRuntime(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &lifecycleDirectoryRuntime{}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)
	claim, err := deps.DirectorySourceRepo.ClaimActivation(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = claim.Release(context.Background()) }()

	response := httptest.NewRecorder()
	request := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/activate",
		bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`),
	), tenantID, userID)
	ActivateDirectorySource(deps)(response, request)

	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "directory_activation_in_progress") ||
		runtime.publishCalls != 0 || runtime.fullSyncCalls != 0 {
		t.Fatalf("status=%d publish=%d sync=%d body=%s",
			response.Code, runtime.publishCalls, runtime.fullSyncCalls, response.Body.String())
	}
}

func TestActivateDirectorySourceClaimRejectsConcurrentDraftMutation(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	publishStarted := make(chan struct{})
	continuePublish := make(chan struct{})
	runtime := &lifecycleDirectoryRuntime{}
	runtime.onPublish = func() {
		close(publishStarted)
		<-continuePublish
	}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)
	claimedVersion := source.Version

	responseDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		request := withOrgUserCtx(httptest.NewRequest(
			http.MethodPost,
			"/admin/v1/directory/sources/activate",
			bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`),
		), tenantID, userID)
		ActivateDirectorySource(deps)(response, request)
		responseDone <- response
	}()
	select {
	case <-publishStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not reach runtime publish")
	}

	update := *source
	update.DisplayName = "Concurrent LDAP"
	upsertErr := deps.DirectorySourceRepo.UpsertDraft(context.Background(), &update)
	currentDuringActivation, readErr := deps.DirectorySourceRepo.GetByID(context.Background(), tenantID, source.ID)
	close(continuePublish)
	var response *httptest.ResponseRecorder
	select {
	case response = <-responseDone:
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not finish")
	}

	if !errors.Is(upsertErr, repository.ErrDirectorySourceActivating) {
		t.Fatalf("concurrent UpsertDraft err=%v", upsertErr)
	}
	if readErr != nil || currentDuringActivation == nil ||
		currentDuringActivation.Version != claimedVersion ||
		currentDuringActivation.DisplayName != source.DisplayName {
		t.Fatalf("source changed during activation: %#v err=%v", currentDuringActivation, readErr)
	}
	active, err := deps.DirectorySourceRepo.GetActive(context.Background(), tenantID)
	if response.Code != http.StatusOK || err != nil || active == nil || active.Version != claimedVersion {
		t.Fatalf("status=%d active=%#v err=%v body=%s", response.Code, active, err, response.Body.String())
	}
}

func TestActivateDirectorySourceClaimRejectsConcurrentDisableThenReleases(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	publishStarted := make(chan struct{})
	continuePublish := make(chan struct{})
	runtime := &lifecycleDirectoryRuntime{}
	runtime.onPublish = func() {
		close(publishStarted)
		<-continuePublish
	}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)

	activationDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		request := withOrgUserCtx(httptest.NewRequest(
			http.MethodPost,
			"/admin/v1/directory/sources/activate",
			bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`),
		), tenantID, userID)
		ActivateDirectorySource(deps)(response, request)
		activationDone <- response
	}()
	select {
	case <-publishStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not reach runtime publish")
	}

	conflict := httptest.NewRecorder()
	DisableDirectorySource(deps)(conflict, withOrgUserCtx(httptest.NewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/disable",
		bytes.NewBufferString(`{"confirm":true}`),
	), tenantID, userID))
	if conflict.Code != http.StatusConflict ||
		!strings.Contains(conflict.Body.String(), "directory_activation_in_progress") ||
		runtime.disableCalls != 0 {
		close(continuePublish)
		t.Fatalf("disable during activation status=%d calls=%d body=%s",
			conflict.Code, runtime.disableCalls, conflict.Body.String())
	}

	close(continuePublish)
	var activation *httptest.ResponseRecorder
	select {
	case activation = <-activationDone:
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not finish")
	}
	if activation.Code != http.StatusOK {
		t.Fatalf("activation status=%d body=%s", activation.Code, activation.Body.String())
	}

	afterRelease := httptest.NewRecorder()
	DisableDirectorySource(deps)(afterRelease, withOrgUserCtx(httptest.NewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/disable",
		bytes.NewBufferString(`{"confirm":true}`),
	), tenantID, userID))
	if afterRelease.Code != http.StatusOK || runtime.disableCalls != 1 {
		t.Fatalf("disable after activation status=%d calls=%d body=%s",
			afterRelease.Code, runtime.disableCalls, afterRelease.Body.String())
	}
}

func TestActivateDirectorySourceRequiresPreviewIDBeforeRuntime(t *testing.T) {
	runtime := &lifecycleDirectoryRuntime{}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/activate", bytes.NewBufferString(`{"confirm":true}`))
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "owner", TenantID: "tenant-a", Role: "tenant_owner", Status: "active",
	}))
	response := httptest.NewRecorder()
	ActivateDirectorySource(&Dependencies{DirectoryRuntime: runtime})(response, request)

	if response.Code != http.StatusBadRequest || runtime.publishCalls != 0 || runtime.fullSyncCalls != 0 {
		t.Fatalf("status=%d publish=%d sync=%d body=%s", response.Code, runtime.publishCalls, runtime.fullSyncCalls, response.Body.String())
	}
}

func TestActivateDirectorySourceRejectsDeveloperBeforeRuntime(t *testing.T) {
	runtime := &lifecycleDirectoryRuntime{}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/activate", bytes.NewBufferString("{\x22confirm\x22:true}"))
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "developer", TenantID: "tenant-a", Role: "developer", Status: "active",
	}))
	response := httptest.NewRecorder()
	ActivateDirectorySource(&Dependencies{DirectoryRuntime: runtime})(response, request)
	if response.Code != http.StatusForbidden || runtime.publishCalls != 0 {
		t.Fatalf("developer status=%d publish=%d body=%s", response.Code, runtime.publishCalls, response.Body.String())
	}
}

func TestActivateDirectorySourceIsTenantScoped(t *testing.T) {
	pool, tenantID, _ := setupOrgHandlerPool(t)
	runtime := &lifecycleDirectoryRuntime{}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, "u1", source)

	request := httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/activate", bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`))
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "other-owner", TenantID: "other-tenant", Role: "tenant_owner", Status: "active",
	}))
	response := httptest.NewRecorder()
	ActivateDirectorySource(deps)(response, request)
	if response.Code != http.StatusNotFound || runtime.publishCalls != 0 {
		t.Fatalf("cross-tenant status=%d publish=%d body=%s", response.Code, runtime.publishCalls, response.Body.String())
	}
}

func TestActivateDirectorySourceRuntimeFailureLeavesDatabaseTested(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &lifecycleDirectoryRuntime{publishErr: errors.New("runtime unavailable")}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)

	response := httptest.NewRecorder()
	ActivateDirectorySource(deps)(response, withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/activate", bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`)), tenantID, userID))
	current, err := deps.DirectorySourceRepo.GetByID(context.Background(), tenantID, source.ID)
	if response.Code == http.StatusOK || err != nil || current == nil || current.Status != "tested" {
		t.Fatalf("runtime failure status=%d source=%#v err=%v", response.Code, current, err)
	}
	claim, err := deps.DirectorySourceRepo.ClaimActivation(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("activation claim leaked after runtime failure: %v", err)
	}
	if err := claim.Release(context.Background()); err != nil {
		t.Fatalf("release verification claim: %v", err)
	}
}

func TestDirectoryActivationRestoreFailureMarksReconciliationWithoutRawError(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &lifecycleDirectoryRuntime{
		snapshot:       directoryruntime.RuntimeSnapshot{Exists: true},
		fullSyncErrors: []error{errors.New("raw full sync token=secret")},
		restoreErr:     errors.New("raw restore password=secret"),
	}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)

	response := httptest.NewRecorder()
	ActivateDirectorySource(deps)(response, withOrgUserCtx(httptest.NewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/activate",
		bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`),
	), tenantID, userID))
	current, err := deps.DirectorySourceRepo.GetByID(context.Background(), tenantID, source.ID)
	if response.Code == http.StatusOK ||
		!strings.Contains(response.Body.String(), "directory_rollback_failed") ||
		strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if err != nil || current == nil || !current.RuntimeReconciliationRequired ||
		current.RuntimeReconciliationReason != repository.DirectoryReconciliationReasonFullSyncFailed {
		t.Fatalf("reconciliation source=%#v err=%v", current, err)
	}
	if runtime.restoreCalls != 1 || runtime.fullSyncCalls != 1 {
		t.Fatalf("restore=%d fullSync=%d", runtime.restoreCalls, runtime.fullSyncCalls)
	}
}

func TestDirectoryActivationMarkFailureReturnsStableSanitizedError(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &lifecycleDirectoryRuntime{
		snapshot:       directoryruntime.RuntimeSnapshot{Exists: true},
		fullSyncErrors: []error{errors.New("raw keycloak secret=top-secret"), nil},
	}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)
	runtime.onFullSync = func(call int) {
		if call == 1 {
			_, _ = pool.Exec(
				context.Background(),
				"DELETE FROM directory_sources WHERE tenant_id=$1 AND id=$2",
				tenantID,
				source.ID,
			)
		}
	}

	response := httptest.NewRecorder()
	ActivateDirectorySource(deps)(response, withOrgUserCtx(httptest.NewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/activate",
		bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`),
	), tenantID, userID))
	if response.Code == http.StatusOK ||
		!strings.Contains(response.Body.String(), "directory_reconciliation_persistence_failed") ||
		strings.Contains(response.Body.String(), "secret") ||
		strings.Contains(response.Body.String(), "keycloak") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if runtime.restoreCalls != 1 || runtime.fullSyncCalls != 2 {
		t.Fatalf("restore=%d fullSync=%d", runtime.restoreCalls, runtime.fullSyncCalls)
	}
}

func TestDisableDirectorySourceClaimRejectsConcurrentActivationThenReleases(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	disableStarted := make(chan struct{})
	continueDisable := make(chan struct{})
	runtime := &lifecycleDirectoryRuntime{}
	runtime.onDisable = func() {
		close(disableStarted)
		<-continueDisable
	}
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	previewID := seedSucceededDirectoryPreview(t, deps, tenantID, userID, source)
	if err := deps.DirectorySourceRepo.Activate(context.Background(), tenantID, source.ID, source.Version); err != nil {
		t.Fatal(err)
	}

	disableDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		DisableDirectorySource(deps)(response, withOrgUserCtx(httptest.NewRequest(
			http.MethodPost,
			"/admin/v1/directory/sources/disable",
			bytes.NewBufferString(`{"confirm":true}`),
		), tenantID, userID))
		disableDone <- response
	}()
	select {
	case <-disableStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("disable did not reach runtime")
	}

	conflict := httptest.NewRecorder()
	ActivateDirectorySource(deps)(conflict, withOrgUserCtx(httptest.NewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/activate",
		bytes.NewBufferString(`{"preview_id":"`+previewID+`","confirm":true}`),
	), tenantID, userID))
	conflictCode := conflict.Code
	conflictBody := conflict.Body.String()
	publishCalls := runtime.publishCalls
	close(continueDisable)

	var disabled *httptest.ResponseRecorder
	select {
	case disabled = <-disableDone:
	case <-time.After(5 * time.Second):
		t.Fatal("disable did not finish")
	}
	if conflictCode != http.StatusConflict ||
		!strings.Contains(conflictBody, "directory_activation_in_progress") ||
		publishCalls != 0 {
		t.Fatalf("activate during disable status=%d publish=%d body=%s",
			conflictCode, publishCalls, conflictBody)
	}
	if disabled.Code != http.StatusOK || runtime.disableCalls != 1 {
		t.Fatalf("disable status=%d calls=%d body=%s",
			disabled.Code, runtime.disableCalls, disabled.Body.String())
	}

	claim, err := deps.DirectorySourceRepo.ClaimActivation(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("lifecycle claim leaked after disable: %v", err)
	}
	if err := claim.Release(context.Background()); err != nil {
		t.Fatalf("release verification claim: %v", err)
	}
}

func TestDisableDirectorySourceRestoresRuntimeWhenDatabaseCASFails(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &lifecycleDirectoryRuntime{snapshot: directoryruntime.RuntimeSnapshot{Exists: true}}
	deps := buildIdentityDeps(pool)
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryRuntime = runtime
	source := seedTestedDirectorySource(t, deps, tenantID)
	if err := deps.DirectorySourceRepo.Activate(context.Background(), tenantID, source.ID, source.Version); err != nil {
		t.Fatal(err)
	}
	runtime.onDisable = func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM directory_sources WHERE tenant_id=$1 AND id=$2", tenantID, source.ID)
	}

	response := httptest.NewRecorder()
	DisableDirectorySource(deps)(response, withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/disable", bytes.NewBufferString("{\x22confirm\x22:true}")), tenantID, userID))
	if response.Code == http.StatusOK || runtime.disableCalls != 1 || runtime.restoreCalls != 1 {
		t.Fatalf("disable status=%d calls=%d restores=%d body=%s", response.Code, runtime.disableCalls, runtime.restoreCalls, response.Body.String())
	}
}
