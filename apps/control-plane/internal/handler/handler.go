package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/fx"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/notify"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/onboarding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/portalbaseline"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"github.com/yangjiyj/aiguard/packages/shared-go/providercompat"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Interfaces for testable dependency injection
type ProviderRepo interface {
	GetByID(ctx context.Context, tenantID, id string) (*repository.Provider, error)
	GetCredential(ctx context.Context, providerID string) (*repository.ProviderCredential, error)
	ListCredentialHistory(ctx context.Context, providerID string) ([]*repository.ProviderCredential, error)
	List(ctx context.Context, tenantID string) ([]*repository.Provider, error)
	RecentProviderMetrics(ctx context.Context, tenantID string, windowMinutes int) (map[string]repository.ProviderRecentMetrics, error)
	CreateWithCredential(ctx context.Context, provider *repository.Provider, cred *repository.ProviderCredential) error
	UpdateWithCredential(ctx context.Context, provider *repository.Provider, cred *repository.ProviderCredential) error
	Delete(ctx context.Context, tenantID, id string) error
}

type providerBundleCreator interface {
	CreateWithCredentialAndModel(context.Context, *repository.Provider, *repository.ProviderCredential, *repository.Model) error
}

type ProjectRepo interface {
	GetByID(ctx context.Context, tenantID, id string) (*repository.Project, error)
	List(ctx context.Context, tenantID string) ([]*repository.Project, error)
	CountByTenant(ctx context.Context, tenantID string) (int, error)
	Create(ctx context.Context, project *repository.Project) error
	Update(ctx context.Context, project *repository.Project) error
	UpdateModelConfig(ctx context.Context, id string, whitelist, quotaLimits string) error
	Delete(ctx context.Context, tenantID, id string) error
}

type ModelRepo interface {
	GetByID(ctx context.Context, id string) (*repository.Model, error)
	GetByProviderAndName(ctx context.Context, providerID, modelName string) (*repository.Model, error)
	UpsertByProviderAndName(ctx context.Context, model *repository.Model) (bool, error)
	List(ctx context.Context, tenantID string) ([]*repository.Model, error)
	UpdatePricing(ctx context.Context, modelID string, pricingJSON string) error
	UpdateCapabilities(ctx context.Context, modelID string, capabilitiesJSON string) error
	RecordProtocolProbe(ctx context.Context, tenantID, providerID, modelID string, capabilities map[string]interface{}, record repository.ModelProtocolProbeRecord) error
	UpdateStatus(ctx context.Context, modelID string, status string) error
	UpdateProxyConfig(ctx context.Context, modelID string, proxyConfigJSON string) error
	Delete(ctx context.Context, id string) error
	DeleteBatch(context.Context, string, []string) (repository.ModelBatchDeleteResult, error)
	MergeVerifiedProviderModels(ctx context.Context, tenantID, providerID, expectedCredentialID, expectedProviderConfigDigest string, desired []repository.VerifiedProviderModel) (repository.VerifiedModelSyncResult, error)
}

type PermissionAuthorizer interface {
	HasPermission(context.Context, string, string, string, string, string, string) (bool, error)
	InvalidateUserCache(string)
}

type CatalogFactory interface {
	GetClient(providerType string) (catalog.Client, error)
}

type AgentSessionRepo interface {
	List(ctx context.Context, tenantID string, limit, offset int) ([]repository.AgentSession, int, error)
	GetBySessionID(ctx context.Context, tenantID string, sessionID string) (*repository.AgentSession, error)
}

type TenantLookup interface {
	GetByID(ctx context.Context, id string) (*repository.Tenant, error)
}

type ProxyWhitelistRepo interface {
	GetByID(ctx context.Context, tenantID, id string) (*repository.ProxyWhitelist, error)
	List(ctx context.Context, tenantID string) ([]repository.ProxyWhitelist, error)
	Create(ctx context.Context, entry *repository.ProxyWhitelist) error
	Update(ctx context.Context, entry *repository.ProxyWhitelist) error
	Delete(ctx context.Context, tenantID, id string) error
}

type ReverseProxyRouteRepo interface {
	GetByID(ctx context.Context, tenantID, id string) (*repository.ReverseProxyRoute, error)
	List(ctx context.Context, tenantID string) ([]repository.ReverseProxyRoute, error)
	Create(ctx context.Context, entry *repository.ReverseProxyRoute) error
	Update(ctx context.Context, entry *repository.ReverseProxyRoute) error
	Delete(ctx context.Context, tenantID, id string) error
}

type CACertificateRepo interface {
	GenerateCA(ctx context.Context, tenantID string, validityDays int) (*repository.CACertificate, error)
	GetByID(ctx context.Context, tenantID, id string) (*repository.CACertificate, error)
	GetActive(ctx context.Context, tenantID string) (*repository.CACertificate, error)
	List(ctx context.Context, tenantID string) ([]repository.CACertificate, error)
	Activate(ctx context.Context, tenantID, id string) (*repository.CACertificate, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type QuotaPolicyRepo interface {
	GetByProject(ctx context.Context, tenantID, projectID string) (*repository.QuotaPolicy, error)
	GetByScope(ctx context.Context, tenantID, scopeType, projectID, teamID, userID, keyPrefix string) (*repository.QuotaPolicy, error)
	List(ctx context.Context, tenantID string) ([]*repository.QuotaPolicy, error)
	CreateOrUpdate(ctx context.Context, policy *repository.QuotaPolicy) error
}

type QuotaKeyLookup interface {
	GetByID(ctx context.Context, tenantID, keyID string) (*repository.InternalKey, error)
}

type QuotaDepartmentScopeLookup interface {
	ListTeamSubtreeIDsByUser(ctx context.Context, tenantID, userID string) ([]string, error)
	ListProjectIDsByUserTeams(ctx context.Context, tenantID, userID string) ([]string, error)
}

type QuotaProjectMembershipLookup interface {
	GetUserRole(ctx context.Context, projectID, userID string) (string, error)
}

type QuotaUserLookup interface {
	GetByID(ctx context.Context, userID string) (*repository.User, error)
}

type ContentExceptionKeyLookup interface {
	GetByID(ctx context.Context, tenantID, keyID string) (*repository.InternalKey, error)
}

type ContentExceptionTeamLookup interface {
	GetByID(ctx context.Context, id string) (*repository.Team, error)
}

type quotaKeyPrefixLookup interface {
	GetUniqueByPrefix(ctx context.Context, tenantID, keyPrefix string) (*repository.InternalKey, error)
}

type AuditDispositionRepo interface {
	Upsert(ctx context.Context, d *repository.AuditDisposition) (*repository.AuditDisposition, error)
	List(ctx context.Context, tenantID, subjectType, subjectID string, limit, offset int) ([]*repository.AuditDisposition, int, error)
}

type ContentAuditUserSelectorRepo interface {
	ListContentAuditUsers(context.Context, repository.ContentAuditUserSelectorFilter) ([]repository.ContentAuditUserOption, bool, error)
}

type ContentAuditDepartmentScopeRepo interface {
	ListTeamSubtreeIDsByUser(context.Context, string, string) ([]string, error)
}

type ContentAuditSelectorDependencies struct {
	Users       ContentAuditUserSelectorRepo
	Departments ContentAuditDepartmentScopeRepo
}

type UsageRollupRepo interface {
	GetUsageSummaryScoped(ctx context.Context, scope repository.UsageScope, startDate, endDate time.Time) (*repository.UsageRollupSummary, error)
}

type UsageSummaryRepo interface {
	GetSummaryScoped(ctx context.Context, scope repository.UsageScope, startDate, endDate time.Time) (*repository.UsageSummary, error)
}

type AccessRollupRepo interface {
	GetAccessSummaryFiltered(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) (repository.ForwardProxyAccessSummary, error)
}

type ForwardProxyAccessRepo interface {
	ListForwardProxyAccess(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) ([]repository.ForwardProxyAccessRecord, int, error)
	GetForwardProxyAccessSummary(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) (repository.ForwardProxyAccessSummary, error)
}

type ForwardProxyAccessCountsRepo interface {
	GetForwardProxyAccessCounts(ctx context.Context, tenantID string, filter repository.ForwardProxyAccessFilter) (repository.ForwardProxyAccessSummary, error)
}

type EvidenceRunRepo interface {
	ListEvidenceRuns(ctx context.Context, tenantID, view string, filter repository.ForwardProxyAccessFilter) ([]repository.EvidenceRunRecord, int, error)
}

type EvidenceTimelineRepo interface {
	ListEvidenceTimeline(ctx context.Context, tenantID string, requestIDs []string) ([]repository.EvidenceTimelineEvent, error)
}

type AccessContentRepo interface {
	GetAccessContentLog(ctx context.Context, tenantID string, requestID string) (*repository.AccessContentLog, error)
	// GetAccessContentLogs 批量取多个 request_id 的留证内容（按 created_at 升序），
	// 供 SP4 turn 详情合并同一逻辑问答的多条物理记录。
	GetAccessContentLogs(ctx context.Context, tenantID string, requestIDs []string) ([]repository.AccessContentLog, error)
	ResolveUploadedFileBytes(ctx context.Context, tenantID string, referenceIDs []string) (map[string]repository.ResolvedUploadedFile, error)
}

type RetainedArtifactRepo interface {
	ListRetainedArtifacts(ctx context.Context, tenantID, requestID string) ([]repository.RetainedArtifact, error)
	GetRetainedArtifact(ctx context.Context, tenantID, requestID, artifactID string) (*repository.RetainedArtifact, error)
}

type RetainedArtifactBatchRepo interface {
	ListRetainedArtifactsByRequests(ctx context.Context, tenantID string, requestIDs []string) ([]repository.RetainedArtifact, error)
}

// ContentLogReader 读取主链路（反向代理/主对话）写入的 content_logs。
// 当 access_content_logs 没有该请求时，「内容留存」详情用它做读侧回退，
// 避免反向代理请求在合规底账里无记录。*repository.ContentLogRepository 已满足该接口。
type ContentLogReader interface {
	ListByRequest(ctx context.Context, tenantID, requestID string) ([]repository.ContentLog, error)
}

type ContentLogBatchReader interface {
	ListByRequests(ctx context.Context, tenantID string, requestIDs []string) ([]repository.ContentLog, error)
}

type ModelEvalStatusReader interface {
	ListModelEvalStatus(ctx context.Context, tenantID string) ([]repository.ModelEvalStatusRow, error)
}

type SystemRepo interface {
	Get(ctx context.Context, key string) (*repository.SystemSetting, error)
	GetAll(ctx context.Context) ([]*repository.SystemSetting, error)
	// GetByKeys 一次查询读出给定的键；不存在的键不在结果里（执行模式等多键判定用）。
	GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error)
	Set(ctx context.Context, key, value string) error
	SetMultiple(ctx context.Context, settings map[string]string) error
	CreateAuditOperation(ctx context.Context, op *repository.AuditOperation) error
	ListAuditOperations(ctx context.Context, limit, offset int, userID string) ([]*repository.AuditOperation, int, error)
	GetBool(ctx context.Context, key string) (bool, error)
}

// versionedSettingsRepo 是 SystemRepo 的可选扩展：带版本的读取与原子条件写入（语义检测配置的并发控制用）。
// 做成独立接口是因为大量测试桩只实现基础 SystemRepo；生产的 SystemRepository 两个都实现。
type versionedSettingsRepo interface {
	GetUpdatedAt(ctx context.Context, keys []string) (map[string]time.Time, error)
	SetMultipleIfVersion(ctx context.Context, guardKeys []string, expectedVersion string,
		versionOf func(map[string]time.Time) string, settings map[string]string) error
}

type SessionStore interface {
	Create(context.Context, *repository.Session) error
	Delete(context.Context, string) error
	DeleteByUser(context.Context, string) error
}

type FirstAdminInitializer interface {
	Initialize(context.Context, string, string) error
	GetStatus(context.Context, string) (*onboarding.Status, error)
}

type UserStore interface {
	GetByID(ctx context.Context, id string) (*repository.User, error)
	ListAllWithStats(ctx context.Context) ([]*repository.UserWithStats, error)
	Create(ctx context.Context, user *repository.User) error
	Update(ctx context.Context, user *repository.User) error
}

type DepartmentStore interface {
	GetByID(ctx context.Context, id string) (*repository.Team, error)
}

type AgentOperationRepo interface {
	GetPolicy(context.Context, string, string, string) (*repository.AgentOperationPolicy, error)
	SavePolicy(context.Context, repository.AgentOperationPolicyMutation) (*repository.AgentOperationPolicy, error)
	GetEvent(context.Context, string, string) (*repository.AgentOperationEvent, error)
	ListEvents(context.Context, string, repository.AgentOperationEventFilter) ([]repository.AgentOperationEvent, int, error)
	ListChannels(context.Context, string, []string) ([]repository.AgentOperationChannel, error)
	ResolveEffectivePolicy(context.Context, string, repository.AgentOperationEffectivePolicyInput) (*repository.AgentOperationEffectivePolicy, error)
}

type AgentGuardPolicyRepo interface {
	CreatePolicyWithVersion(ctx context.Context, p *repository.AgentGuardPolicy, createdBy string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, error)
	UpdatePolicyWithVersion(ctx context.Context, p *repository.AgentGuardPolicy, createdBy string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, bool, error)
	ListPolicies(ctx context.Context, tenantID string) ([]*repository.AgentGuardPolicy, error)
	GetPolicy(ctx context.Context, tenantID, id string) (*repository.AgentGuardPolicy, error)
	ListVersions(ctx context.Context, tenantID, policyID string) ([]*repository.AgentGuardPolicyVersion, error)
	RollbackPolicy(ctx context.Context, tenantID, policyID, versionID, actorID string) (*repository.AgentGuardPolicy, error)
	CreateException(ctx context.Context, e *repository.AgentGuardException) error
	DeleteException(ctx context.Context, tenantID, id string) (bool, error)
	ListActiveExceptions(ctx context.Context, tenantID string, now time.Time) ([]*repository.AgentGuardException, error)
	CreateConfirmation(ctx context.Context, c *repository.AgentGuardConfirmation) error
	CreateMCPConfirmation(ctx context.Context, c *repository.AgentGuardConfirmation, ciphertext, contextHash string) error
	CreateMCPConfirmationDeduplicated(ctx context.Context, c *repository.AgentGuardConfirmation, identity repository.MCPConfirmationIdentity, ciphertext, contextHash string) (*repository.MCPConfirmationExecution, bool, error)
	ListConfirmations(ctx context.Context, tenantID, status, source string) ([]*repository.AgentGuardConfirmation, error)
	ResolveConfirmation(ctx context.Context, tenantID, id, status, actorID, note string) (*repository.AgentGuardConfirmation, error)
	MarkConfirmationReplayed(ctx context.Context, tenantID, id, replayStatus, toolLogID string) error
	GetMCPConfirmationExecution(ctx context.Context, tenantID, confirmationID string) (*repository.MCPConfirmationExecution, error)
	ClaimMCPConfirmationExecution(ctx context.Context, tenantID, confirmationID string) (*repository.MCPConfirmationExecution, bool, error)
	MarkMCPConfirmationUnknown(ctx context.Context, tenantID, confirmationID, attemptID, errorCode string) error
	ListMCPConfirmationExecutions(ctx context.Context, tenantID string, confirmationIDs []string) (map[string]*repository.MCPConfirmationExecution, error)
	GetFalsePositiveStats(ctx context.Context, tenantID string, days int) (*repository.AgentGuardGovernanceStats, error)
	SuggestException(ctx context.Context, tenantID, toolCallID, reason, actorID string, now time.Time) (*repository.AgentGuardExceptionSuggestion, error)
	SimulatePolicy(ctx context.Context, tenantID string, req repository.AgentGuardPolicySimulationRequest) (*repository.AgentGuardPolicySimulationResult, error)
	GetBehaviorBaseline(ctx context.Context, tenantID string, days int) (*repository.AgentGuardBehaviorBaseline, error)
	CreateRollout(ctx context.Context, rollout *repository.AgentGuardRollout) error
	ListRollouts(ctx context.Context, tenantID, status string) ([]*repository.AgentGuardRollout, error)
}

// MCPPolicyRepo is the smallest MCP policy surface needed by the existing
// handlers. Keeping the dependency at this boundary makes policy projections
// testable without exposing the concrete repository to every handler.
type MCPPolicyRepo interface {
	ListByTenant(ctx context.Context, tenantID, serverID string) ([]*repository.MCPPolicy, error)
	Create(ctx context.Context, policy *repository.MCPPolicy) error
	Update(ctx context.Context, policy *repository.MCPPolicy) error
	Delete(ctx context.Context, tenantID, id string) error
}

// ConfirmationReplayer 在 HITL 确认被批准后，重放原始工具调用。
type ConfirmationReplayer interface {
	ReplayConfirmation(ctx context.Context, c *repository.AgentGuardConfirmation) (string, error)
}
type PolicyCenterAgentBehaviorRepo interface {
	Save(context.Context, repository.PolicyCenterAgentBehaviorMutation) error
}

type AgentGuardBehaviorRepo interface {
	ListPolicies(ctx context.Context, tenantID string) ([]*repository.AgentGuardPolicy, error)
	CreatePolicyWithVersion(ctx context.Context, p *repository.AgentGuardPolicy, createdBy string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, error)
	UpdatePolicyWithVersion(ctx context.Context, p *repository.AgentGuardPolicy, createdBy string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, bool, error)
}

// MCPConfirmationExecutor invokes gateway-core's authenticated single-use
// endpoint. Gateway-core owns decryption, policy re-check and upstream I/O.
type MCPConfirmationExecutor interface {
	ExecuteMCPConfirmation(ctx context.Context, tenantID, confirmationID, attemptID string) error
}

// DispositionAction 描述一次审计处置要落地的真实执行动作。
type DispositionAction struct {
	TenantID string // 操作者所属租户，约束执行作用域
	Action   string // revoke_key / ban_user / block_session
	Target   string // 动作目标（key 前缀 / 用户 ID / 会话暂停 key）
	Operator string // 触发处置的操作者 ID
	Reason   string // 处置说明，落入 pause/审计
}

// DispositionEnforcer 把审计处置（吊销key/封禁用户/阻断会话）派发到真实执行，
// 让「处置」从状态位升级为真生效动作；生产实现复用既有 key 吊销 / 用户停用 /
// 预算暂停链路，不另起执行通道。
type DispositionEnforcer interface {
	Enforce(ctx context.Context, action DispositionAction) error
}

type AlertGroupRepo interface {
	List(ctx context.Context, filter repository.AlertGroupListFilter) ([]*repository.AlertGroup, error)
	GetByID(ctx context.Context, tenantID, id string) (*repository.AlertGroup, error)
	UpdateStatus(ctx context.Context, tenantID, id string, status repository.AlertGroupStatus, actorID, note string) (*repository.AlertGroup, error)
	ListGroupEvents(ctx context.Context, tenantID, groupID string, filter repository.AlertGroupEventListFilter) ([]*repository.AlertGroupEvent, int, error)
}

// AlertGroupPageRepo is optional so existing lightweight test doubles and legacy
// integrations can continue using AlertGroupRepo.List while production uses
// bounded, server-side pagination.
// SecurityEventFalsePositiveMarker is optional: audit disposition remains
// available for historical events that were never bridged, while linked events
// update their tenant-scoped alert group for reversible group suppression.
type SecurityEventFalsePositiveMarker interface {
	MarkFalsePositiveBySecurityEvent(context.Context, string, string, string, string) (*repository.AlertGroup, error)
}

// AlertGroupBatchRepo is optional: the batch disposition endpoint is only
// available when the production repository (or a test double) implements it.
type AlertGroupBatchRepo interface {
	BatchUpdateStatus(ctx context.Context, in repository.AlertGroupBatchStatusInput) (repository.AlertGroupBatchStatusResult, error)
}

type AlertGroupPageRepo interface {
	ListPage(ctx context.Context, filter repository.AlertGroupListFilter) (repository.AlertGroupPage, error)
}

type IdentityTester interface {
	TestConnection(context.Context, identity.TestConfig) *identity.TestConnectionResult
	ResolveDiscovery(context.Context, identity.TestConfig) (*identity.DiscoveryDocument, error)
}

type DirectoryTester interface {
	ListUsers(context.Context, directoryldap.SyncRequest) ([]directoryldap.DirectoryUser, error)
	TestConnection(context.Context, directoryldap.TestRequest) (directoryldap.TestResult, error)
}

type IdentityRuntime interface {
	Publish(context.Context, identityruntime.DesiredIdentitySource) (identityruntime.Publication, error)
	Disable(context.Context, identityruntime.DesiredIdentitySource) (identityruntime.RuntimeSnapshot, error)
	Status(context.Context, identityruntime.DesiredIdentitySource) (identityruntime.RuntimeStatus, error)
	Restore(context.Context, identityruntime.RuntimeSnapshot) error
}

// DirectorySyncPreviewStore 是 handler 依赖的目录预览/历史存储抽象。
// *repository.DirectorySyncPreviewRepository 自动满足本接口；测试可注入
// wrapper（例如模拟 FinalizeSyncRunTx 失败验证事务回滚）。
type DirectorySyncPreviewStore interface {
	CreatePreview(ctx context.Context, preview *repository.DirectorySyncPreview) error
	AppendPreviewEntry(ctx context.Context, entry *repository.DirectorySyncPreviewEntry) error
	FinalizePreview(ctx context.Context, tenantID, previewID, status string, counts repository.PreviewCounts, errorCode string) error
	GetPreview(ctx context.Context, tenantID, previewID string) (*repository.DirectorySyncPreview, error)
	ListPreviewEntries(ctx context.Context, tenantID, previewID string) ([]repository.DirectorySyncPreviewEntry, error)
	MarkPreviewActivated(ctx context.Context, tenantID, previewID, runID string) (string, error)
	MarkPreviewActivatedTx(ctx context.Context, tx pgx.Tx, tenantID, previewID, runID string) (string, error)
	ClaimPreviewForActivation(ctx context.Context, tx pgx.Tx, tenantID, previewID, runID string) (string, bool, error)
	CreateSyncRun(ctx context.Context, run *repository.DirectorySyncRun) error
	CreateSyncRunTx(ctx context.Context, tx pgx.Tx, run *repository.DirectorySyncRun) error
	FinalizeSyncRun(ctx context.Context, tenantID, runID, status string, counts repository.PreviewCounts, errorCode string) error
	FinalizeSyncRunTx(ctx context.Context, tx pgx.Tx, tenantID, runID, status string, counts repository.PreviewCounts, errorCode string) error
	GetSyncRun(ctx context.Context, tenantID, runID string) (*repository.DirectorySyncRun, error)
	ListSyncRuns(ctx context.Context, tenantID string, limit int) ([]repository.DirectorySyncRun, error)
	LatestPreview(ctx context.Context, tenantID string) (*repository.DirectorySyncPreview, error)
	LatestSyncRun(ctx context.Context, tenantID string) (*repository.DirectorySyncRun, error)
	ListBoundDirectoryUserIDs(ctx context.Context, tenantID, sourceID string) (map[string]string, error)
	MarkDirectoryUserDisabled(ctx context.Context, tenantID string, userIDs []string) (int, error)
	MarkDirectoryUserDisabledTx(ctx context.Context, tx pgx.Tx, tenantID string, userIDs []string) (int, error)
	MarkDirectoryUserRestored(ctx context.Context, tenantID string, userIDs []string) (int, error)
	MarkDirectoryUserRestoredTx(ctx context.Context, tx pgx.Tx, tenantID string, userIDs []string) (int, error)
	SnapshotDirectoryUserLinks(ctx context.Context, tenantID, sourceID, runID string, seenExternalIDs []string) error
	SnapshotDirectoryUserLinksTx(ctx context.Context, tx pgx.Tx, tenantID, sourceID, runID string, seenExternalIDs []string) error
	BeginTx(ctx context.Context) (pgx.Tx, error)
	RunInTx(ctx context.Context, fn func(tx pgx.Tx) error) error
}

type IdentityBindingService interface {
	BindAndResolve(context.Context, identitybinding.ExternalIdentity) (identitybinding.Resolution, error)
	AssignManually(context.Context, string, string, string, string) error
	AssignManyManually(context.Context, string, []string, string, string, string) error
	SetAutomatic(context.Context, string, string, string) error
	Unassign(context.Context, string, string, string) error
}

type IdentitySourceActiveLookup interface {
	GetActive(context.Context, string) (*repository.IdentitySource, error)
}

type UserIdentityLinkLookup interface {
	HasExternalCredentialOwner(context.Context, string, string) (bool, error)
	BindLoginSources(context.Context, string, string, string, string) error
}

// ChatDefaultsEnsurer provisions only missing employee-portal context. It is
// intentionally separate from the installer-armed first-admin initializer so
// a fresh deployment never requires customer interaction before Chat works.
type ChatDefaultsEnsurer interface {
	EnsureChatDefaults(context.Context, string) error
}

type IdentityCacheInvalidationReconciler interface {
	ProcessOne(context.Context) (bool, error)
}

// IdentityRuntimeConfig only contains customer-facing protocol coordinates.
// Internal management endpoints and credentials never enter handler responses.
type IdentityRuntimeConfig struct {
	CallbackURL string
	IssuerURL   string
}

// Dependencies holds all repository dependencies for handlers
type Dependencies struct {
	EmployeeKeyRepo       *repository.EmployeeAPIKeyRepository
	ChatLoginTickets      ChatLoginTicketStore
	IntegrationRepo       IntegrationRepo
	IntegrationGatewayURL string
	// BillingStore is nil unless BILLING_ENABLED=true. A nil value leaves
	// billing routes unavailable and preserves existing deployment behaviour.
	BillingStore                 *billing.Store
	BillingMode                  string
	FirstAdminInitializer        FirstAdminInitializer
	SessionRepo                  SessionStore
	UserRepo                     *repository.UserRepository
	UserStore                    UserStore
	DepartmentStore              DepartmentStore
	TenantRepo                   *repository.TenantRepository
	TenantLookup                 TenantLookup
	ProjectRepo                  ProjectRepo
	ProjectUserRepo              *repository.ProjectUserRepository
	UserIdentityLinkLookup       UserIdentityLinkLookup
	LocalIdentityClient          localidentity.Client
	LocalIdentityProvisioner     localidentity.Provisioner
	LocalIdentityCleanupQ        localidentity.CleanupQueue // 删除用户后 Keycloak 孤儿清理的持久化重试队列（迁移 983）
	NativeServiceProvisioner     localidentity.Provisioner
	KeyRepo                      *repository.InternalKeyRepository
	QuotaKeyLookup               QuotaKeyLookup
	QuotaDepartmentScopeLookup   QuotaDepartmentScopeLookup
	QuotaProjectMembershipLookup QuotaProjectMembershipLookup
	QuotaUserLookup              QuotaUserLookup
	ProviderRepo                 ProviderRepo
	ModelRepo                    ModelRepo
	ModelPolicyRepo              *repository.ModelPolicyRepository
	GroupMappingRuleRepo         *repository.GroupMappingRuleRepository
	QuotaPolicyRepo              QuotaPolicyRepo
	RequestLogRepo               *repository.RequestLogRepository
	PortalCallRecordReader       PortalCallRecordReader
	ModelEvalStatusRepo          ModelEvalStatusReader
	SecurityEventRepo            *repository.SecurityEventRepository
	AlertOccurrenceRepo          AlertOccurrenceReader
	// RetentionSecurityEventReader 是 view=raw 留证回退的按请求查询入口；为空时回落到 SecurityEventRepo。
	RetentionSecurityEventReader retentionSecurityEventReader
	SemanticEventReader          SemanticEventReader
	TriageSuppressedReader       TriageSuppressedReader
	AuditDispositionRepo         AuditDispositionRepo
	RetainedArtifactRepo         RetainedArtifactRepo
	ForwardProxyAccessRepo       ForwardProxyAccessRepo
	EvidenceRunRepo              EvidenceRunRepo
	EvidenceTimelineRepo         EvidenceTimelineRepo
	AccessContentRepo            AccessContentRepo
	AccessRollupRepo             AccessRollupRepo
	RetentionStore               retentionstore.Store
	PortalUploadEventRepo        *repository.PortalUploadEventRepository
	UsageDailyRepo               *repository.UsageDailyRepository
	UsageSummaryRepo             UsageSummaryRepo
	UsageRollupRepo              UsageRollupRepo
	RuleSetRepo                  *repository.RuleSetRepository
	AgentOperationRepo           AgentOperationRepo
	ProtectionSettingsStore      ProtectionSettingsStore
	RuleRepo                     *repository.RuleRepository
	ContentExceptionKeyLookup    ContentExceptionKeyLookup
	ContentExceptionTeamLookup   ContentExceptionTeamLookup
	AgentSessionRepo             AgentSessionRepo
	ContentLogRepo               *repository.ContentLogRepository
	ContentLogReader             ContentLogReader
	ContentAuditSelector         ContentAuditSelectorDependencies
	ToolCallLogRepo              *repository.ToolCallLogRepository
	ToolRiskConfigRepo           *repository.ToolRiskConfigRepository
	AgentEndpointBundleRepo      interface {
		RegenerateIfChanged(context.Context, string, string) (int64, error)
	}
	AgentGuardPolicyRepo        AgentGuardPolicyRepo
	AgentGuardBehaviorRepo      AgentGuardBehaviorRepo
	PolicyCenterBehaviorRepo    PolicyCenterAgentBehaviorRepo
	SkillAssetsRepo             SkillAssetsRepo
	SkillArchiveScanner         SkillArchiveScanner
	ConfirmationReplayer        ConfirmationReplayer
	MCPConfirmationExecutor     MCPConfirmationExecutor
	MCPConfirmationScopeSecret  string
	DispositionEnforcer         DispositionEnforcer
	SystemRepo                  SystemRepo
	ProxyWhitelistRepo          ProxyWhitelistRepo
	ReverseProxyRouteRepo       ReverseProxyRouteRepo
	CACertificatesRepo          CACertificateRepo
	SecurityEngineURL           string
	SecurityEngineInternalToken string
	CatalogFactory              CatalogFactory
	ModelProber                 catalog.ModelProber
	ModelSyncProofSecret        string
	ModelSyncVerifyGate         *ModelSyncVerifyGate
	modelSyncGate               providerSyncGate
	// Org module (T17)
	TeamRepo       *repository.TeamRepository
	TeamMemberRepo *repository.TeamMemberRepository
	OrgService     *org.Service
	// Budget module (T22)
	PauseLogRepo   *repository.PauseLogRepository
	BudgetSnapshot *budget.SnapshotReader
	RedisClient    *redis.Client
	// FX module (T33)
	FxService *fx.Service
	// Saving module (T37)
	SavingDB *pgxpool.Pool
	DB       *pgxpool.Pool
	// Alert inbox + notify channels (T38-T42)
	AlertInboxRepo     *repository.AlertInboxRepository
	AlertService       *alert.InboxService
	NotifyChannelsRepo *repository.NotifyChannelsRepository
	NotifyDispatcher   *notify.Dispatcher
	AlertGroupRepo     AlertGroupRepo
	// Proxy access keys (P1-10, task 1.7)
	ProxyAccessKeyRepo *repository.ProxyAccessKeysRepository
	// MCP servers (P1-22, task 1.8)
	MCPServerRepo *repository.MCPServersRepository
	// MCP 安全网关（能力识别 + 权限管控）
	MCPToolRepo        *repository.MCPToolsRepository
	MCPPolicyRepo      MCPPolicyRepo
	MCPSupplyChainRepo MCPSupplyChainRepo
	// Provider price snapshots (P2-2, task 1.9)
	ProviderPriceSnapshotRepo *repository.ProviderPriceSnapshotRepository
	// audit chain WORM (P9-P10)
	AuditAppender  *audit_chain.Appender
	AuditChainRepo *repository.AuditChainRepository
	// OpsAlerts 把计费/审计链运维事件写进告警组并外发；nil 时只打日志。
	OpsAlerts OpsAlertEmitter
	// AuditIntegrity 保存最近一次审计链完整性校验结果与签名密钥状态，供审计日志页展示。
	AuditIntegrity *AuditIntegrityStatus
	// Savings config (P15)
	SavingsConfigRepo SavingsConfigRepo
	// Anomaly detection (P18)
	AnomalyEventRepo AnomalyEventRepo
	AnomalyScanner   AnomalyScanner
	// Security event → alert inbox bridge (P0-2)
	SecEventBridge *alert.SecEventBridge
	// Forecast dry-run (P21)
	ForecastJobRepo ForecastJobRepo
	ForecastWorker  ForecastWorker
	// Routing policies (R15)
	RoutingPolicyRepo *repository.RoutingPolicyRepository
	ModelRoutingRepo  *repository.ModelRoutingRepository
	// RBAC (UAG-spec-rbac)
	PermissionGrantRepo *repository.PermissionGrantRepository
	LoginHistoryRepo    *repository.UserLoginHistoryRepository
	SystemRolesRepo     *repository.SystemRolesRepository
	PermissionChecker   PermissionAuthorizer
	// W3 控制台登录安全：LoginRecorder 缺省时回退 LoginHistoryRepo；ConsoleSecurity 为空时
	// 不做密码历史/定期改密/TOTP（单测夹具不必全部注入）。
	LoginRecorder         ConsoleLoginRecorder
	ConsoleSecurity       ConsoleUserSecurityStore
	PortalBaselineFetcher portalbaseline.Fetcher
	// IAM (enterprise-iam)
	TeamModelRepo        *repository.TeamModelRepository
	UserAccountMergeRepo *repository.UserAccountMergeRepository
	UserModelRepo        *repository.UserModelRepository
	// 组织称谓设置 (org-units Phase B)
	AppSettingsRepo *repository.AppSettingsRepository
	// 身份与访问 — 登录与单点登录 (identity-access-frontdoor)
	IdentitySourceRepo                  *repository.IdentitySourceRepository
	IdentitySourceLookup                IdentitySourceActiveLookup
	IdentityDepartmentMappingRepo       *repository.IdentityDepartmentMappingRepository
	DirectorySourceRepo                 *repository.DirectorySourceRepository
	DirectorySyncPreviewRepo            DirectorySyncPreviewStore
	IdentityBindingService              IdentityBindingService
	ChatDefaultsEnsurer                 ChatDefaultsEnsurer
	IdentityCacheInvalidationReconciler IdentityCacheInvalidationReconciler
	OIDCTester                          IdentityTester
	DirectoryTester                     DirectoryTester
	DirectoryTargetPolicy               directoryldap.TargetPolicy
	DirectoryRuntime                    DirectoryRuntime
	IdentityRuntime                     IdentityRuntime
	IdentityRuntimeConfig               IdentityRuntimeConfig
	RulePackAttestationTokens           map[string]string
	SemanticGatewayAttestationKey       string
}

func getFallbackProviderID(capabilities map[string]interface{}) string {
	if capabilities == nil {
		return ""
	}

	routing, ok := capabilities["routing"].(map[string]interface{})
	if !ok {
		return ""
	}

	fallbackProviderID, _ := routing["fallback_provider_id"].(string)
	return fallbackProviderID
}

// classifyModelModality conservatively infers modality from a catalog label.
// Protocol support is recorded independently and Responses is never inferred
// from a model name.
func classifyModelModality(modelName string) map[string]interface{} {
	lower := strings.ToLower(strings.TrimSpace(modelName))
	typ := "text"
	source := "default"
	switch {
	case strings.Contains(lower, "embedding"):
		typ, source = "embedding", "name_inference"
	case strings.Contains(lower, "whisper") || strings.Contains(lower, "tts"):
		typ, source = "audio", "name_inference"
	case strings.Contains(lower, "dall-e") || strings.Contains(lower, "dalle") ||
		strings.Contains(lower, "stable-diffusion") || strings.Contains(lower, "gpt-image"):
		typ, source = "image", "name_inference"
	}
	capabilities := map[string]interface{}{
		"modality": map[string]interface{}{
			"type":   typ,
			"source": source,
		},
	}
	protocols := map[string]interface{}{}
	switch typ {
	case "image":
		protocols["images"] = true
	case "embedding":
		protocols["embeddings"] = true
	case "text":
		protocols["chat_completions"] = true
	}
	if len(protocols) > 0 {
		capabilities["protocols"] = protocols
	}
	return capabilities
}

// syncedCatalogModelCapabilities adds only protocol facts that have been
// proven against the configured upstream. A catalog entry named "claude-*"
// alone is never enough: many OpenAI-compatible relays advertise Claude names
// but do not implement the native Anthropic Messages contract.
func syncedCatalogModelCapabilities(ctx context.Context, prober catalog.ModelProber, provider *repository.Provider, apiKey, catalogModelID string) (map[string]interface{}, bool) {
	capabilities := classifyModelModality(catalogModelID)
	if prober == nil || provider == nil || !isAnthropicMessagesCatalogCandidate(catalogModelID) {
		return capabilities, false
	}
	probe := probeModelSafely(ctx, prober, catalog.ModelProbeRequest{
		BaseURL:        provider.BaseURL,
		APIKey:         apiKey,
		AuthMode:       provider.AuthMode,
		DeploymentName: catalogModelID,
		Protocol:       "messages",
	})
	if !probe.OK {
		return capabilities, false
	}
	protocols, _ := capabilities["protocols"].(map[string]interface{})
	if protocols == nil {
		protocols = make(map[string]interface{})
		capabilities["protocols"] = protocols
	}
	protocols["anthropic_messages"] = true
	return capabilities, true
}

func isAnthropicMessagesCatalogCandidate(modelID string) bool {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	return strings.HasPrefix(modelID, "claude-") || strings.HasPrefix(modelID, "claude_") || strings.HasPrefix(modelID, "claude/")
}

func protocolCapabilitiesFromSelections(selections []string) (map[string]interface{}, error) {
	if len(selections) == 0 {
		return nil, nil
	}
	protocols := make(map[string]interface{}, len(selections))
	for _, selection := range selections {
		switch strings.ToLower(strings.TrimSpace(selection)) {
		case "", "auto":
			if len(selections) != 1 {
				return nil, errors.New("protocol selection 'auto' cannot be combined with another protocol")
			}
			return nil, nil
		case "chat_completions":
			protocols["chat_completions"] = true
		case "responses":
			protocols["responses_native"] = true
		case "anthropic_messages":
			protocols["anthropic_messages"] = true
		case "gemini":
			protocols["gemini"] = true
		case "images":
			protocols["images"] = true
		case "embeddings":
			protocols["embeddings"] = true
		default:
			return nil, fmt.Errorf("unsupported protocol selection %q", selection)
		}
	}
	return protocols, nil
}

func providerSupportsOpenAIProtocolProbe(providerType string) bool {
	return providercompat.SupportsOpenAIProtocolProbe(providerType) || nativeModelProbeProvider(providerType)
}

// probeOpenAIModelProtocols verifies the generic OpenAI-compatible endpoints
// before a model becomes routable. Claude-family catalog entries additionally
// prove the native Anthropic Messages contract. A failed endpoint remains
// unknown instead of being marked unsupported because timeouts, rate limits
// and provider outages are not durable capability evidence.
func probeOpenAIModelProtocols(ctx context.Context, prober catalog.ModelProber, provider *repository.Provider, apiKey, deploymentName string) (map[string]interface{}, repository.ModelProtocolProbeRecord, error) {
	if prober != nil && provider != nil && nativeModelProbeProvider(provider.ProviderType) {
		return probeNativeModelProtocols(ctx, prober, provider, apiKey, deploymentName)
	}
	if prober == nil || provider == nil || !providerSupportsOpenAIProtocolProbe(provider.ProviderType) {
		return nil, repository.ModelProtocolProbeRecord{}, errors.New("automatic protocol detection is unavailable for this provider")
	}
	now := time.Now().UTC()
	record := repository.ModelProtocolProbeRecord{
		SourceVersion:        "model-protocol-probe-" + uuid.NewString(),
		ProviderConfigDigest: repository.VerifiedModelSyncProviderConfigDigest(provider.ProviderType, provider.BaseURL, provider.AuthMode),
		VerifiedAt:           now,
		ExpiresAt:            now.Add(30 * 24 * time.Hour),
		Endpoints:            make([]repository.ModelEndpointProbeResult, 0, 3),
	}
	protocols := map[string]interface{}{}
	probes := []struct {
		probeProtocol string
		endpointType  string
		capabilityKey string
	}{
		{probeProtocol: "chat_completions", endpointType: "chat", capabilityKey: "chat_completions"},
		{probeProtocol: "responses", endpointType: "responses", capabilityKey: "responses_native"},
	}
	modality, _ := classifyModelModality(deploymentName)["modality"].(map[string]interface{})
	if modality["type"] == "image" {
		probes = []struct {
			probeProtocol string
			endpointType  string
			capabilityKey string
		}{{"images", "images", "images"}}
	}
	if isNativeAnthropicMessagesCandidate(deploymentName) {
		probes = append(probes, struct {
			probeProtocol string
			endpointType  string
			capabilityKey string
		}{probeProtocol: "messages", endpointType: "messages", capabilityKey: "anthropic_messages"})
	}
	verified := 0
	for _, item := range probes {
		timeout := time.Duration(0)
		if item.probeProtocol == "images" {
			timeout = 120 * time.Second
		}
		result := probeModelSafely(ctx, prober, catalog.ModelProbeRequest{
			BaseURL:        provider.BaseURL,
			APIKey:         apiKey,
			AuthMode:       provider.AuthMode,
			DeploymentName: deploymentName,
			Protocol:       item.probeProtocol,
			Timeout:        timeout,
		})
		state := "unknown"
		errorKind := safeProbeErrorKind(result.ErrorKind)
		if result.OK {
			state = "supported"
			errorKind = ""
			protocols[item.capabilityKey] = true
			verified++
		}
		record.Endpoints = append(record.Endpoints, repository.ModelEndpointProbeResult{
			EndpointType: item.endpointType,
			State:        state,
			ErrorKind:    errorKind,
		})
	}
	if verified == 0 {
		return nil, repository.ModelProtocolProbeRecord{}, errors.New("no compatible model endpoint could be verified")
	}
	protocols["metadata"] = map[string]interface{}{
		"verified": true,
		"source":   "live_protocol_probe",
		"version":  record.SourceVersion,
	}
	return protocols, record, nil
}

func isNativeAnthropicMessagesCandidate(deploymentName string) bool {
	deploymentName = strings.ToLower(strings.TrimSpace(deploymentName))
	return strings.HasPrefix(deploymentName, "claude-") || strings.HasPrefix(deploymentName, "claude_") || strings.HasPrefix(deploymentName, "claude/")
}

func isSupportedRuntimeProviderType(providerType string) bool {
	return providercompat.RuntimeSupported(providerType)
}

func supportsAuthorizationRawProviderType(providerType string) bool {
	switch providerType {
	case "openai", "azure", "custom", "deepseek", "moonshot", "doubao", "kimi", "qwen", "zhipu", "hunyuan", "minimax":
		return true
	default:
		return false
	}
}

// Login handles admin login with real authentication
func Login(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req consoleLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		captchaValid, err := validateCaptcha(r.Context(), deps.RedisClient, req.CaptchaID, req.CaptchaCode)
		if err != nil {
			log.Printf("Login error: captcha validation failed: %v", err)
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "captcha_unavailable", "captcha service unavailable")
			return
		}
		if !captchaValid {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_captcha", "captcha is invalid or expired")
			return
		}

		// W3（等保三级）：锁定、统一失败提示、登录留痕、IP 白名单、双因素、会话超时与并发，
		// 统一在 authenticateConsoleLogin 中实现（console_login.go）。
		authenticateConsoleLogin(w, r, deps, req, false)
	}
}

// ServiceLogin issues the gateway's own opaque session token to machine
// identities (platform_connector). It reuses the hardened console login flow
// (lockout guard, equalized bcrypt, session limits) without the human captcha
// step; the Redis limiter fails closed and the permission middleware pins the
// role to the closed connector route contract.
func ServiceLogin(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req consoleLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if !allowServiceLoginAttempt(w, r, deps, req.Username) {
			return
		}
		authenticateConsoleLogin(w, r, deps, req, true)
	}
}

// Logout handles admin logout
func Logout(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session != nil {
			deps.SessionRepo.Delete(r.Context(), session.ID)
			recordConsoleLoginEvent(r, deps, repository.LoginAttempt{
				UserID: session.UserID, AttemptedUsername: session.Username,
				Success: true, Event: repository.LoginEventLogout,
			})
		}
		http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", HttpOnly: true,
			Secure: os.Getenv("SESSION_COOKIE_SECURE") != "false", SameSite: http.SameSiteStrictMode, MaxAge: -1})
		w.WriteHeader(http.StatusNoContent)
	}
}

// GetCurrentUser returns the current authenticated user
func GetCurrentUser(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found in context")
			return
		}

		resp := types.UserInfo{
			ID:                     user.ID,
			Username:               user.Username,
			Role:                   user.Role,
			TenantID:               user.TenantID,
			PasswordChangeRequired: user.MustChangePassword,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// allowedIndustries 是行业白名单（权威小写）：决定一个租户能叠加哪些内置数据安全规则包。
// 收紧在此一处，避免任意字符串落库后挂载到非预期/不存在的行业包（漏检或越权读他行业规则）。
var allowedIndustries = map[string]bool{
	"generic":         true,
	"medical_imaging": true,
	"finance":         true,
}

// normalizeIndustry 把外部传入的行业值收敛到白名单：去首尾空白后精确匹配，
// 空/非白名单/注入样本一律兜底为 generic（恒挂载通用 PII 包，绝不放大权限）。
func normalizeIndustry(s string) string {
	if allowedIndustries[strings.TrimSpace(s)] {
		return strings.TrimSpace(s)
	}
	return "generic"
}

// ListTenants returns all tenants
func ListTenants(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenants, err := deps.TenantRepo.List(r.Context())
		if err != nil {
			writeError(w, "internal_error", "failed to list tenants")
			return
		}

		user := auth.GetUser(r.Context())
		data := make([]types.TenantInfo, 0, len(tenants))
		for _, t := range tenants {
			if user != nil && user.Role != "platform_admin" && t.ID != user.TenantID {
				continue
			}
			data = append(data, types.TenantInfo{
				ID:        t.ID,
				Name:      t.Name,
				Edition:   t.Edition,
				Status:    t.Status,
				Industry:  t.Industry,
				CreatedAt: t.CreatedAt.Format(time.RFC3339),
			})
		}

		resp := types.TenantListResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// CreateTenant blocks runtime creation of additional units.
// The default unit is provisioned by installation/bootstrap code through TenantRepository.
func CreateTenant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeErrorWithStatus(w, http.StatusForbidden, "unit_creation_disabled", "additional units cannot be created in this deployment")
	}
}

// GetTenant returns a specific tenant
func GetTenant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 原本无任何鉴权（跨租户 IDOR）。限管理员档，且非管理员天然不应读租户元数据。
		if !callerIsFullTenant(r) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		tenantID := chi.URLParam(r, "id")

		tenant, err := deps.TenantRepo.GetByID(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to get tenant")
			return
		}

		if tenant == nil {
			writeError(w, "not_found", "tenant not found")
			return
		}

		resp := types.TenantInfo{
			ID:        tenant.ID,
			Name:      tenant.Name,
			Edition:   tenant.Edition,
			Status:    tenant.Status,
			Industry:  normalizeIndustry(tenant.Industry),
			CreatedAt: tenant.CreatedAt.Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateTenant updates a tenant
func UpdateTenant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := chi.URLParam(r, "id")
		var req types.UpdateTenantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		// 行业：显式传入才改（经白名单收敛）；未传则保留原值，
		// 避免「改个单位名把医疗/金融数据安全包静默卸了」导致漏检。
		industry := normalizeIndustry(req.Industry)
		if strings.TrimSpace(req.Industry) == "" {
			if cur, err := deps.TenantRepo.GetByID(r.Context(), tenantID); err == nil && cur != nil {
				industry = cur.Industry
			}
		}

		tenant := &repository.Tenant{
			ID:       tenantID,
			Name:     req.Name,
			Edition:  req.Edition,
			Status:   req.Status,
			Industry: industry,
		}

		if err := deps.TenantRepo.Update(r.Context(), tenant); err != nil {
			writeError(w, "internal_error", "failed to update tenant")
			return
		}

		updatedTenant, _ := deps.TenantRepo.GetByID(r.Context(), tenantID)
		resp := types.TenantInfo{
			ID:        tenantID,
			Name:      req.Name,
			Edition:   req.Edition,
			Status:    req.Status,
			Industry:  updatedTenant.Industry,
			UpdatedAt: updatedTenant.UpdatedAt.Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// ListProjects returns all projects for a tenant
func ListProjects(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		projects, err := deps.ProjectRepo.List(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list projects")
			return
		}

		// dept_manager 等非管理员：只返回本部门（本人所属 team）的项目。
		if isFull, _, projectIDs := callerTeamScope(r, deps); !isFull {
			allow := stringSetFrom(projectIDs)
			filtered := projects[:0:0]
			for _, p := range projects {
				if _, ok := allow[p.ID]; ok {
					filtered = append(filtered, p)
				}
			}
			projects = filtered
		}

		data := make([]types.ProjectInfo, len(projects))
		for i, p := range projects {
			data[i] = projectInfoFromRepo(p)
		}

		resp := types.ProjectListResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// CreateProject creates a new project
func CreateProject(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.CreateProjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		project := &repository.Project{
			TenantID:    user.TenantID,
			Name:        req.Name,
			Code:        req.Code,
			Environment: req.Environment,
			OwnerUserID: user.ID,
			Status:      "active",
		}

		if err := deps.ProjectRepo.Create(r.Context(), project); err != nil {
			writeError(w, "internal_error", "failed to create project")
			return
		}

		resp := projectInfoFromRepo(project)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// projectInfoFromRepo 把应用的完整配置带给控制台。以前列表/详情只回 id、名称、状态，
// 应用页的“代码”“环境”永远显示“-”，应用抽屉里的模型白名单、额度、所属部门永远是空的。
func projectInfoFromRepo(p *repository.Project) types.ProjectInfo {
	return types.ProjectInfo{
		ID:             p.ID,
		Name:           p.Name,
		TenantID:       p.TenantID,
		Code:           p.Code,
		Environment:    p.Environment,
		TeamID:         p.TeamID,
		Status:         p.Status,
		ModelWhitelist: p.ModelWhitelist,
		QuotaLimits:    p.QuotaLimits,
		CreatedAt:      p.CreatedAt.Format(time.RFC3339),
	}
}

// GetProject returns a specific project
func GetProject(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		projectID := chi.URLParam(r, "id")

		project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}

		if project == nil {
			writeError(w, "not_found", "project not found")
			return
		}

		resp := projectInfoFromRepo(project)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateProject updates a project
func UpdateProject(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		projectID := chi.URLParam(r, "id")
		var req types.UpdateProjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		existingProject, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if existingProject == nil {
			writeError(w, "not_found", "project not found")
			return
		}

		project := &repository.Project{
			ID:          projectID,
			TenantID:    user.TenantID,
			Name:        defaultString(req.Name, existingProject.Name),
			Code:        defaultString(req.Code, existingProject.Code),
			Environment: defaultString(req.Environment, existingProject.Environment),
			OwnerUserID: existingProject.OwnerUserID,
			Status:      defaultString(req.Status, existingProject.Status),
			// Update 会把这两列整列写回；不带上现有值就等于每次改名/停用都把模型白名单和额度清空。
			ModelWhitelist: existingProject.ModelWhitelist,
			QuotaLimits:    existingProject.QuotaLimits,
		}

		if err := deps.ProjectRepo.Update(r.Context(), project); err != nil {
			writeError(w, "internal_error", "failed to update project")
			return
		}

		resp := types.ProjectInfo{
			ID:             projectID,
			Name:           project.Name,
			TenantID:       user.TenantID,
			Code:           project.Code,
			Environment:    project.Environment,
			TeamID:         existingProject.TeamID,
			Status:         project.Status,
			ModelWhitelist: project.ModelWhitelist,
			QuotaLimits:    project.QuotaLimits,
			UpdatedAt:      time.Now().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// DeleteProject deletes a project
func DeleteProject(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		projectID := chi.URLParam(r, "id")

		if err := deps.ProjectRepo.Delete(r.Context(), user.TenantID, projectID); err != nil {
			if err.Error() == "project not found" {
				writeError(w, "not_found", "project not found")
				return
			}
			writeError(w, "internal_error", "failed to delete project")
			return
		}

		logAudit(r, deps, "delete_project", map[string]interface{}{"project_id": projectID}, "project", projectID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListKeys returns all keys for a project or all keys if project_id is not specified
func ListKeys(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		projectID := r.URL.Query().Get("project_id")

		var keys []*repository.InternalKey
		var err error

		if projectID != "" {
			keys, err = deps.KeyRepo.List(r.Context(), user.TenantID, projectID)
		} else {
			keys, err = deps.KeyRepo.ListAll(r.Context(), user.TenantID)
		}

		if err != nil {
			writeError(w, "internal_error", "failed to list keys")
			return
		}

		data := make([]types.KeyInfo, len(keys))
		for i, k := range keys {
			data[i] = types.KeyInfo{
				ID:           k.ID,
				ProjectID:    k.ProjectID,
				UserID:       k.UserID,
				Name:         k.Name,
				KeyPrefix:    k.KeyPrefix,
				Scopes:       k.Scopes,
				Status:       k.Status,
				CreatedAt:    k.CreatedAt.Format(time.RFC3339),
				TrafficClass: k.TrafficClass,
			}
			if k.ExpiresAt != nil {
				data[i].ExpiresAt = k.ExpiresAt.Format(time.RFC3339)
			}
		}

		resp := types.KeyListResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// GetUserKeys handles GET /admin/v1/users/{id}/keys —— 列出某用户名下的 vkey（脱敏，不回传 hash/密文）。
// 供用户详情"密钥"tab：员工 SSO 登录自动签的 key 就绑在其 user 上。
func GetUserKeys(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		// 密钥清单敏感：限管理员档（users:read 资源被过度复用，dept_manager 持有它但不应看 key）。
		if !isFullTenantRole(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		userID := chi.URLParam(r, "id")
		keys, err := deps.KeyRepo.ListByUser(r.Context(), user.TenantID, userID)
		if err != nil {
			writeError(w, "internal_error", "failed to list user keys")
			return
		}
		data := make([]types.KeyInfo, len(keys))
		for i, k := range keys {
			data[i] = types.KeyInfo{
				ID:        k.ID,
				ProjectID: k.ProjectID,
				UserID:    k.UserID,
				Name:      k.Name,
				KeyPrefix: k.KeyPrefix,
				Scopes:    k.Scopes,
				Status:    k.Status,
				CreatedAt: k.CreatedAt.Format(time.RFC3339),
			}
			if k.ExpiresAt != nil {
				data[i].ExpiresAt = k.ExpiresAt.Format(time.RFC3339)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.KeyListResponse{Data: data, Total: len(data)})
	}
}

// CreateKey creates a new internal key
func CreateKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.CreateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, req.ProjectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if project == nil {
			writeError(w, "not_found", "project not found")
			return
		}

		// Resolve user_id: empty defaults to current user, non-empty must exist in tenant
		var keyUserID string
		if req.UserID == "" {
			keyUserID = user.ID
		} else {
			// Validate user exists and belongs to current tenant
			targetUser, err := deps.UserRepo.GetByID(r.Context(), req.UserID)
			if err != nil {
				writeError(w, "internal_error", "failed to validate user")
				return
			}
			if targetUser == nil || targetUser.TenantID != user.TenantID {
				writeError(w, "invalid_request", "user not found in tenant")
				return
			}
			keyUserID = req.UserID
		}

		scopes, err := normalizeRequestedKeyScopes(req.Scopes)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		name, err := normalizeKeyName(req.Name)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		expiresAt, err := parseKeyExpiresAt(req.ExpiresAt)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		// Generate 48-character random key
		rawKey := generateSecureKey()

		key := &repository.InternalKey{
			TenantID:  user.TenantID,
			ProjectID: req.ProjectID,
			UserID:    keyUserID,
			Name:      name,
			Scopes:    scopes,
			ExpiresAt: expiresAt,
			Status:    "active",
		}

		if err := deps.KeyRepo.Create(r.Context(), key, rawKey); err != nil {
			writeError(w, "internal_error", "failed to create key")
			return
		}

		// Return full key (only shown once)
		resp := types.KeyInfo{
			ID:        key.ID,
			ProjectID: key.ProjectID,
			UserID:    key.UserID,
			Name:      key.Name,
			KeyPrefix: key.KeyPrefix,
			Scopes:    key.Scopes,
			FullKey:   rawKey,
			Status:    key.Status,
			CreatedAt: key.CreatedAt.Format(time.RFC3339),
		}
		if key.ExpiresAt != nil {
			resp.ExpiresAt = key.ExpiresAt.Format(time.RFC3339)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

var defaultModelKeyScopes = []string{"chat", "responses", "embeddings", "models"}

var allowedKeyScopes = map[string]struct{}{
	"*":          {},
	"chat":       {},
	"responses":  {},
	"embeddings": {},
	"models":     {},
	"mcp":        {},
	"customer":   {},
	"home":       {},
	"claude":     {},
	"codex":      {},
}

func normalizeRequestedKeyScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return append([]string(nil), defaultModelKeyScopes...), nil
	}

	normalized := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		value := strings.ToLower(strings.TrimSpace(scope))
		if value == "" {
			continue
		}
		if _, ok := allowedKeyScopes[value]; !ok {
			return nil, fmt.Errorf("invalid scope %q", scope)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	return normalized, nil
}

// normalizeKeyName 限长按 rune 数（DB 列 VARCHAR(128) 也按字符计），中文名不吃亏。
func normalizeKeyName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if utf8.RuneCountInString(name) > 128 {
		return "", fmt.Errorf("name too long (max 128 chars)")
	}
	// name 会出现在 key 列表与审计追溯展示里，控制字符可伪造多行审计记录
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("name must not contain control characters")
		}
	}
	return name, nil
}

func parseKeyExpiresAt(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("expires_at must be RFC3339 (e.g. 2026-08-01T00:00:00+08:00)")
	}
	if !t.After(time.Now()) {
		return nil, fmt.Errorf("expires_at must be in the future")
	}
	return &t, nil
}

// RevokeKey revokes an internal key
func RevokeKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		keyID := chi.URLParam(r, "id")

		if err := deps.KeyRepo.Revoke(r.Context(), user.TenantID, keyID); err != nil {
			writeError(w, "internal_error", "failed to revoke key")
			return
		}

		logAudit(r, deps, "revoke_key", map[string]interface{}{"key_id": keyID}, "key", keyID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// UpdateKey 更新密钥备注/名称（PATCH /admin/v1/keys/{id}）。仅允许改 name，
// 复用 normalizeKeyName 做限长(128)/控制字符校验；租户隔离在 repo 层。
func UpdateKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		keyID := chi.URLParam(r, "id")

		var req types.UpdateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		name, err := normalizeKeyName(req.Name)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		if err := deps.KeyRepo.UpdateName(r.Context(), user.TenantID, keyID, name); err != nil {
			if err.Error() == "key not found" {
				writeError(w, "not_found", "key not found")
				return
			}
			writeError(w, "internal_error", "failed to update key")
			return
		}

		logAudit(r, deps, "update_key", map[string]interface{}{"key_id": keyID, "name": name}, "key", keyID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// DeleteKey deletes an internal key
func DeleteKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.IsConsoleAdministrator(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		r = withOperationAudit(r, deps)
		keyID := chi.URLParam(r, "id")

		if err := deps.KeyRepo.Delete(r.Context(), user.TenantID, keyID, user.ID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "key not found")
				return
			}
			writeError(w, "internal_error", "failed to delete key")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ListProviders returns all providers
func ListProviders(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		providers, err := deps.ProviderRepo.List(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list providers")
			return
		}

		data := make([]types.ProviderInfo, len(providers))
		for i, p := range providers {
			credentialUpdatedAt := ""
			if p.CredentialUpdatedAt != nil {
				credentialUpdatedAt = p.CredentialUpdatedAt.Format(time.RFC3339)
			}
			data[i] = types.ProviderInfo{
				ID:                  p.ID,
				Name:                p.Name,
				ProviderType:        p.ProviderType,
				BaseURL:             p.BaseURL,
				AuthMode:            p.AuthMode,
				HasCredential:       p.HasCredential,
				CredentialUpdatedAt: credentialUpdatedAt,
				Status:              p.Status,
				CreatedAt:           p.CreatedAt.Format(time.RFC3339),
			}
		}

		resp := types.ProviderListResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// CreateProvider creates a new provider with credentials
func CreateProvider(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.CreateProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		req.ProviderType = strings.ToLower(strings.TrimSpace(req.ProviderType))
		req.Name = strings.TrimSpace(req.Name)
		req.BaseURL = strings.TrimSpace(req.BaseURL)
		req.AuthMode = strings.ToLower(strings.TrimSpace(req.AuthMode))
		req.ModelID = strings.TrimSpace(req.ModelID)
		if req.AuthMode == "" {
			req.AuthMode = "api_key"
		}
		if !isSupportedRuntimeProviderType(req.ProviderType) {
			writeErrorWithStatus(w, http.StatusBadRequest, "provider_unsupported", "provider type is not supported by current gateway runtime")
			return
		}
		if req.AuthMode != "api_key" && req.AuthMode != "authorization_raw" {
			writeError(w, "invalid_request", "unsupported provider authentication mode")
			return
		}
		if req.AuthMode == "authorization_raw" {
			if req.Name == "" || req.BaseURL == "" || strings.TrimSpace(req.APIKey) == "" || req.ModelID == "" {
				writeError(w, "invalid_request", "name, complete chat URL, Authorization value and model ID are required")
				return
			}
			if !supportsAuthorizationRawProviderType(req.ProviderType) {
				writeError(w, "invalid_request", "provider type does not support complete chat endpoints")
				return
			}
			if deps.ModelProber == nil || deps.ModelRepo == nil {
				writeError(w, "config_error", "upstream verification is not configured")
				return
			}
			probe := deps.ModelProber.Probe(r.Context(), catalog.ModelProbeRequest{
				BaseURL: req.BaseURL, APIKey: req.APIKey, AuthMode: req.AuthMode,
				DeploymentName: req.ModelID, Protocol: "chat_completions",
			})
			if !probe.OK || !probe.PayloadValidated {
				writeErrorWithStatus(w, http.StatusBadRequest, "provider_probe_failed", probe.Message)
				return
			}
		}

		provider := &repository.Provider{
			TenantID:     user.TenantID,
			Name:         req.Name,
			ProviderType: req.ProviderType,
			BaseURL:      req.BaseURL,
			AuthMode:     req.AuthMode,
			Status:       "active",
		}

		var credential *repository.ProviderCredential
		if req.APIKey != "" {
			encryptedSecret, kmsKeyRef, err := secrets.EncryptProviderSecret(req.APIKey)
			if err != nil {
				writeError(w, "config_error", "provider secret encryption key not configured")
				return
			}
			credential = &repository.ProviderCredential{
				CredentialName:   "default",
				SecretCiphertext: encryptedSecret,
				KMSKeyRef:        kmsKeyRef,
				Status:           "active",
			}
		}

		var createErr error
		if req.AuthMode == "authorization_raw" {
			creator, ok := deps.ProviderRepo.(providerBundleCreator)
			if !ok {
				writeError(w, "config_error", "atomic provider creation is not configured")
				return
			}
			model := &repository.Model{
				ModelName: req.ModelID, ModelLabel: req.ModelID, UpstreamModelID: req.ModelID,
				Capabilities: map[string]interface{}{
					"modality":  map[string]interface{}{"type": "text", "source": "configured"},
					"protocols": map[string]interface{}{"chat_completions": true},
				},
				Status: "disabled",
			}
			createErr = creator.CreateWithCredentialAndModel(r.Context(), provider, credential, model)
			if createErr == nil {
				capabilities, record := rawChatProtocolProbeRecord(provider)
				if err := deps.ModelRepo.RecordProtocolProbe(r.Context(), user.TenantID, provider.ID, model.ID, capabilities, record); err != nil {
					writeError(w, "internal_error", "failed to persist verified provider protocol")
					return
				}
				if err := deps.ModelRepo.UpdateStatus(r.Context(), model.ID, "active"); err != nil {
					writeError(w, "internal_error", "failed to activate verified provider model")
					return
				}
			}
		} else {
			createErr = deps.ProviderRepo.CreateWithCredential(r.Context(), provider, credential)
		}
		if createErr != nil {
			writeError(w, "internal_error", "failed to create provider")
			return
		}
		provider.CreatedAt = time.Now()

		resp := types.ProviderInfo{
			ID:                  provider.ID,
			Name:                provider.Name,
			ProviderType:        provider.ProviderType,
			BaseURL:             provider.BaseURL,
			AuthMode:            provider.AuthMode,
			HasCredential:       credential != nil,
			CredentialUpdatedAt: map[bool]string{true: provider.CreatedAt.Format(time.RFC3339), false: ""}[credential != nil],
			Status:              provider.Status,
			CreatedAt:           provider.CreatedAt.Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		logAudit(r, deps, "create_provider", map[string]interface{}{
			"provider_name":  provider.Name,
			"provider_type":  provider.ProviderType,
			"base_url":       provider.BaseURL,
			"has_credential": credential != nil,
		}, "provider", provider.ID)
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateProvider updates a provider including credentials
func UpdateProvider(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		providerID := chi.URLParam(r, "id")
		var req types.UpdateProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		existingProvider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, providerID)
		if err != nil {
			writeError(w, "internal_error", "failed to get provider")
			return
		}
		if existingProvider == nil {
			writeError(w, "not_found", "provider not found")
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.BaseURL = strings.TrimSpace(req.BaseURL)
		credentialChanged := strings.TrimSpace(req.APIKey) != ""
		var rawSnapshot *repository.ProviderProtocolProbeSnapshot
		if existingProvider.AuthMode == "authorization_raw" && (req.BaseURL != "" || credentialChanged) {
			if deps.ModelProber == nil || deps.ModelRepo == nil {
				writeError(w, "config_error", "upstream verification is not configured")
				return
			}
			if _, ok := deps.ProviderRepo.(providerProtocolProbeUpdater); !ok {
				writeError(w, "config_error", "atomic provider verification is not configured")
				return
			}
			models, listErr := deps.ModelRepo.List(r.Context(), user.TenantID)
			if listErr != nil {
				writeError(w, "internal_error", "failed to load provider model")
				return
			}
			modelID := ""
			var selectedModel *repository.Model
			for _, candidate := range models {
				if candidate != nil && candidate.ProviderID == providerID && candidate.Status == "active" {
					modelID = strings.TrimSpace(candidate.UpstreamModelID)
					selectedModel = candidate
					if modelID == "" {
						modelID = strings.TrimSpace(candidate.ModelName)
					}
					break
				}
			}
			if modelID == "" {
				writeError(w, "config_error", "complete Chat provider has no active model")
				return
			}
			probeKey := req.APIKey
			stored, credentialErr := deps.ProviderRepo.GetCredential(r.Context(), providerID)
			if credentialErr != nil || stored == nil || stored.Status != "active" || stored.ProviderID != providerID {
				writeError(w, "provider_not_configured", "provider credentials not configured")
				return
			}
			if strings.TrimSpace(probeKey) == "" {
				probeKey, credentialErr = secrets.DecryptProviderSecret(stored.SecretCiphertext)
				if credentialErr != nil || strings.TrimSpace(probeKey) == "" {
					writeError(w, "internal_error", "failed to load provider credentials")
					return
				}
			}
			probeURL := existingProvider.BaseURL
			if req.BaseURL != "" {
				probeURL = req.BaseURL
			}
			rawSnapshot = &repository.ProviderProtocolProbeSnapshot{
				ProviderConfigDigest: repository.VerifiedModelSyncProviderConfigDigest(existingProvider.ProviderType, existingProvider.BaseURL, existingProvider.AuthMode),
				ProviderUpdatedAt:    existingProvider.UpdatedAt, CredentialID: stored.ID, SecretCiphertext: stored.SecretCiphertext,
				ModelID: selectedModel.ID, ModelName: selectedModel.ModelName, UpstreamModelID: selectedModel.UpstreamModelID, ModelStatus: selectedModel.Status,
			}
			probe := deps.ModelProber.Probe(r.Context(), catalog.ModelProbeRequest{
				BaseURL: probeURL, APIKey: probeKey, AuthMode: existingProvider.AuthMode,
				DeploymentName: modelID, Protocol: "chat_completions",
			})
			if !probe.OK || !probe.PayloadValidated {
				writeErrorWithStatus(w, http.StatusBadRequest, "provider_probe_failed", probe.Message)
				return
			}
		}

		provider := &repository.Provider{
			ID:           providerID,
			TenantID:     user.TenantID,
			Name:         defaultString(req.Name, existingProvider.Name),
			ProviderType: existingProvider.ProviderType,
			BaseURL:      defaultString(req.BaseURL, existingProvider.BaseURL),
			AuthMode:     existingProvider.AuthMode,
			IsDefault:    existingProvider.IsDefault,
			Status:       defaultString(req.Status, existingProvider.Status),
		}

		var credential *repository.ProviderCredential
		if req.APIKey != "" {
			encryptedSecret, kmsKeyRef, err := secrets.EncryptProviderSecret(req.APIKey)
			if err != nil {
				writeError(w, "config_error", "provider secret encryption key not configured")
				return
			}
			rotatedAt := time.Now()
			credential = &repository.ProviderCredential{
				CredentialName:   "updated",
				SecretCiphertext: encryptedSecret,
				KMSKeyRef:        kmsKeyRef,
				Status:           "active",
				RotatedAt:        &rotatedAt,
			}
		}

		var updateErr error
		if rawSnapshot != nil {
			capabilities, record := rawChatProtocolProbeRecord(provider)
			updateErr = deps.ProviderRepo.(providerProtocolProbeUpdater).UpdateWithCredentialAndProtocolProbe(r.Context(), provider, credential, *rawSnapshot, capabilities, record)
		} else {
			updateErr = deps.ProviderRepo.UpdateWithCredential(r.Context(), provider, credential)
		}
		if errors.Is(updateErr, repository.ErrProviderProtocolProbeConflict) {
			writeErrorWithStatus(w, http.StatusConflict, "provider_verification_conflict", "provider verification identity changed")
			return
		}
		if updateErr != nil {
			writeError(w, "internal_error", "failed to update provider")
			return
		}

		updatedProvider, _ := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, providerID)
		resp := types.ProviderInfo{
			ID:            providerID,
			Name:          provider.Name,
			ProviderType:  existingProvider.ProviderType,
			BaseURL:       provider.BaseURL,
			HasCredential: existingProvider.HasCredential || req.APIKey != "",
			Status:        provider.Status,
		}
		if updatedProvider != nil {
			resp.HasCredential = updatedProvider.HasCredential
			if updatedProvider.CredentialUpdatedAt != nil {
				resp.CredentialUpdatedAt = updatedProvider.CredentialUpdatedAt.Format(time.RFC3339)
			}
			resp.UpdatedAt = updatedProvider.UpdatedAt.Format(time.RFC3339)
		}

		w.Header().Set("Content-Type", "application/json")
		changedFields := make([]string, 0, 3)
		if req.Name != "" && req.Name != existingProvider.Name {
			changedFields = append(changedFields, "name")
		}
		if req.BaseURL != "" && req.BaseURL != existingProvider.BaseURL {
			changedFields = append(changedFields, "base_url")
		}
		if req.Status != "" && req.Status != existingProvider.Status {
			changedFields = append(changedFields, "status")
		}
		if len(changedFields) > 0 {
			logAudit(r, deps, "update_provider", map[string]interface{}{
				"provider_name":  provider.Name,
				"changed_fields": changedFields,
				"status":         provider.Status,
			}, "provider", providerID)
		}
		if req.APIKey != "" {
			logAudit(r, deps, "rotate_provider_credential", map[string]interface{}{
				"provider_name": provider.Name,
				"provider_type": existingProvider.ProviderType,
			}, "provider", providerID)
		}
		json.NewEncoder(w).Encode(resp)
	}
}

// DeleteProvider deletes a provider
func DeleteProvider(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		providerID := chi.URLParam(r, "id")

		if err := deps.ProviderRepo.Delete(r.Context(), user.TenantID, providerID); err != nil {
			if errors.Is(err, repository.ErrProviderReferencedByRoutingPolicy) {
				logAudit(r, deps, "delete_provider_rejected", map[string]interface{}{"reason": "provider_in_use"}, "provider", providerID)
				writeErrorWithStatus(w, http.StatusConflict, "provider_in_use", "该模型上游正在被已启用的模型路由引用，请先迁移、清理或禁用相关路由。")
				return
			}
			if err.Error() == "provider not found" {
				writeError(w, "not_found", "provider not found")
				return
			}
			writeError(w, "internal_error", "failed to delete provider")
			return
		}

		logAudit(r, deps, "delete_provider", map[string]interface{}{"provider_id": providerID}, "provider", providerID)
		w.WriteHeader(http.StatusNoContent)
	}
}

type providerLifecycleRepository interface {
	ListDeleted(context.Context, string) ([]*repository.Provider, error)
	Restore(context.Context, string, string) (*repository.Provider, error)
}

type deletedProviderInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ProviderType  string `json:"provider_type"`
	HasCredential bool   `json:"has_credential"`
	Status        string `json:"status"`
}

func ListDeletedProviders(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		repo, ok := deps.ProviderRepo.(providerLifecycleRepository)
		if !ok {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "provider recovery is unavailable")
			return
		}
		providers, err := repo.ListDeleted(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list deleted providers")
			return
		}
		items := make([]deletedProviderInfo, 0, len(providers))
		for _, provider := range providers {
			items = append(items, deletedProviderInfo{ID: provider.ID, Name: provider.Name, ProviderType: provider.ProviderType, HasCredential: provider.HasCredential, Status: provider.Status})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
	}
}

func RestoreProvider(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		providerID := chi.URLParam(r, "id")
		repo, ok := deps.ProviderRepo.(providerLifecycleRepository)
		if !ok {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "provider recovery is unavailable")
			return
		}
		provider, err := repo.Restore(r.Context(), user.TenantID, providerID)
		if err != nil {
			switch {
			case errors.Is(err, repository.ErrProviderNotRestorable):
				writeErrorWithStatus(w, http.StatusConflict, "provider_not_restorable", "该上游没有可安全恢复的历史凭据，请新增模型上游。")
			case err.Error() == "provider not found":
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "provider not found")
			default:
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to restore provider")
			}
			return
		}
		logAudit(r, deps, "restore_provider", map[string]interface{}{"restored": true, "models_require_sync": true}, "provider", providerID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deletedProviderInfo{ID: provider.ID, Name: provider.Name, ProviderType: provider.ProviderType, HasCredential: provider.HasCredential, Status: provider.Status})
	}
}

// GetProviderCredentialHistory returns credential history for a provider.
func GetProviderCredentialHistory(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		providerID := chi.URLParam(r, "id")
		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, providerID)
		if err != nil {
			writeError(w, "internal_error", "failed to get provider")
			return
		}
		if provider == nil {
			writeError(w, "not_found", "provider not found")
			return
		}

		history, err := deps.ProviderRepo.ListCredentialHistory(r.Context(), providerID)
		if err != nil {
			writeError(w, "internal_error", "failed to list provider credential history")
			return
		}

		data := make([]types.ProviderCredentialInfo, len(history))
		for i, cred := range history {
			rotatedAt := ""
			if cred.RotatedAt != nil {
				rotatedAt = cred.RotatedAt.Format(time.RFC3339)
			}
			data[i] = types.ProviderCredentialInfo{
				ID:        cred.ID,
				Name:      cred.CredentialName,
				Status:    cred.Status,
				RotatedAt: rotatedAt,
				CreatedAt: cred.CreatedAt.Format(time.RFC3339),
			}
		}

		resp := types.ProviderCredentialHistoryResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// ListModels returns all models
func ListModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		filter := r.URL.Query().Get("available_only")
		if filter != "" && filter != "true" && filter != "false" {
			writeError(w, "invalid_request", "available_only must be true or false")
			return
		}
		onlyAvailable := filter == "true"
		models, err := deps.ModelRepo.List(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list models")
			return
		}
		availability := map[string]modelcatalog.Availability{}
		if projection, ok := deps.ModelRepo.(interface {
			ModelAvailability(context.Context, string) (map[string]modelcatalog.Availability, error)
		}); ok {
			availability, err = projection.ModelAvailability(r.Context(), user.TenantID)
			if err != nil {
				writeError(w, "internal_error", "failed to load current model availability")
				return
			}
		}
		data := make([]types.ModelInfo, 0, len(models))
		for _, m := range models {
			a := availability[m.ID]
			if onlyAvailable && !a.Callable {
				continue
			}
			data = append(data, types.ModelInfo{
				ID: m.ID, ProviderID: m.ProviderID, ModelName: m.ModelName, ModelLabel: m.ModelLabel,
				UpstreamModelID: m.UpstreamModelID, FallbackProviderID: getFallbackProviderID(m.Capabilities),
				ProxyConfig: m.ProxyConfig, Capabilities: m.Capabilities, Status: m.Status,
				CreatedAt: m.CreatedAt.Format(time.RFC3339), Callable: a.Callable, AvailabilityState: a.State,
				InventoryState: a.InventoryState, CallableEndpoints: a.Endpoints, HealthState: a.Health, ProofState: a.ProofState, Advice: a.Advice,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.ModelListResponse{Data: data, Total: len(data)})
	}
}

// CreateModel creates a model route manually. This is used by providers such
// as Vertex AI whose model catalog is not exposed through OpenAI's /v1/models.
func CreateModel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.CreateModelRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		req.ProviderID = strings.TrimSpace(req.ProviderID)
		req.ModelName = strings.TrimSpace(req.ModelName)
		req.ModelLabel = strings.TrimSpace(req.ModelLabel)
		req.UpstreamModelID = strings.TrimSpace(req.UpstreamModelID)
		if req.ProviderID == "" || req.ModelName == "" {
			writeError(w, "invalid_request", "provider_id and model_name are required")
			return
		}
		if req.ModelLabel == "" {
			req.ModelLabel = req.ModelName
		}
		if req.UpstreamModelID == "" {
			req.UpstreamModelID = req.ModelName
		}
		if req.Status == "" {
			req.Status = "active"
		}
		if req.Status != "active" && req.Status != "disabled" {
			writeError(w, "invalid_request", "status must be 'active' or 'disabled'")
			return
		}
		explicitProtocols, err := protocolCapabilitiesFromSelections(req.Protocols)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, req.ProviderID)
		if err != nil {
			writeError(w, "internal_error", "failed to verify provider")
			return
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "provider_not_found", "provider not found or not owned by your tenant")
			return
		}
		capabilities := classifyModelModality(req.ModelName)
		var probeRecord *repository.ModelProtocolProbeRecord
		var nativeSnapshot *repository.NativeModelAdmissionSnapshot
		if nativeModelProbeProvider(provider.ProviderType) && explicitProtocols != nil && (len(explicitProtocols) != 1 || explicitProtocols["chat_completions"] != true) {
			writeError(w, "invalid_request", "native providers use the verified Chat capability; Responses and Messages native facts cannot be declared")
			return
		}
		if nativeModelProbeProvider(provider.ProviderType) {
			existing, loadErr := deps.ModelRepo.GetByProviderAndName(r.Context(), provider.ID, req.ModelName)
			if loadErr != nil {
				writeError(w, "internal_error", "failed to snapshot native model mapping")
				return
			}
			nativeSnapshot = &repository.NativeModelAdmissionSnapshot{ModelName: req.ModelName, ProbedDeployment: req.UpstreamModelID}
			if existing != nil {
				nativeSnapshot.ExistingModelID = existing.ID
				nativeSnapshot.ExistingDeployment = existing.UpstreamModelID
				nativeSnapshot.ExistingStatus = existing.Status
			}
		}
		if explicitProtocols != nil && !nativeModelProbeProvider(provider.ProviderType) {
			capabilities["protocols"] = explicitProtocols
		} else if modality, _ := capabilities["modality"].(map[string]interface{}); modality["type"] == "text" || nativeModelProbeProvider(provider.ProviderType) {
			if !providerSupportsOpenAIProtocolProbe(provider.ProviderType) {
				writeError(w, "invalid_request", "automatic protocol detection is unavailable for this provider type; select the upstream protocol explicitly")
				return
			}
			credential, credentialErr := deps.ProviderRepo.GetCredential(r.Context(), req.ProviderID)
			if credentialErr != nil || credential == nil || credential.Status != "active" {
				writeError(w, "provider_not_configured", "provider credentials not configured")
				return
			}
			apiKey, decryptErr := secrets.DecryptProviderSecret(credential.SecretCiphertext)
			if decryptErr != nil || strings.TrimSpace(apiKey) == "" {
				writeError(w, "internal_error", "failed to load provider credentials")
				return
			}
			prober := deps.ModelProber
			if prober == nil {
				prober = catalog.NewHTTPModelProber()
			}
			probeCtx := r.Context()
			if nativeModelProbeProvider(provider.ProviderType) {
				proxy, proxyErr := loadConfiguredOutboundProxyURL(probeCtx, deps)
				if proxyErr != nil {
					writeError(w, "config_error", "outbound proxy configuration unavailable")
					return
				}
				probeCtx = catalog.WithOutboundProxy(probeCtx, proxy)
			}
			detectedProtocols, detectedRecord, detectErr := probeOpenAIModelProtocols(probeCtx, prober, provider, apiKey, req.UpstreamModelID)
			if nativeModelProbeProvider(provider.ProviderType) {
				detectedRecord.CredentialID = credential.ID
				detectedRecord.SecretCiphertext = credential.SecretCiphertext
			}
			if detectErr != nil {
				writeErrorWithStatus(w, http.StatusBadGateway, "protocol_detection_failed", "upstream model protocol verification failed")
				return
			}
			capabilities["protocols"] = detectedProtocols
			probeRecord = &detectedRecord
		}
		model := &repository.Model{
			ProviderID:      req.ProviderID,
			ModelName:       req.ModelName,
			ModelLabel:      req.ModelLabel,
			UpstreamModelID: req.UpstreamModelID,
			Capabilities:    capabilities,
			Status:          req.Status,
		}
		created := false
		nativeCommitted := false
		if nativeSnapshot != nil {
			writer, ok := deps.ModelRepo.(interface {
				UpsertNativeVerifiedModel(context.Context, string, *repository.Model, repository.ModelProtocolProbeRecord, repository.NativeModelAdmissionSnapshot) (bool, error)
			})
			if !ok || probeRecord == nil {
				writeError(w, "config_error", "atomic native model admission unavailable")
				return
			}
			created, err = writer.UpsertNativeVerifiedModel(r.Context(), user.TenantID, model, *probeRecord, *nativeSnapshot)
			if errors.Is(err, repository.ErrVerifiedModelSyncConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "config_changed", "upstream or model configuration changed during verification; retry verification")
				return
			}
			nativeCommitted = err == nil
		} else {
			created, err = deps.ModelRepo.UpsertByProviderAndName(r.Context(), model)
		}
		if err != nil {
			writeError(w, "internal_error", "failed to create verified model")
			return
		}
		if probeRecord != nil && !nativeCommitted {
			if err := deps.ModelRepo.RecordProtocolProbe(r.Context(), user.TenantID, provider.ID, model.ID, capabilities, *probeRecord); err != nil {
				if created {
					_ = deps.ModelRepo.UpdateStatus(r.Context(), model.ID, "disabled")
				}
				writeError(w, "internal_error", "failed to persist verified model protocols")
				return
			}
		} else if explicitProtocols != nil && !nativeCommitted {
			writer, ok := deps.ModelRepo.(interface {
				UpdateCapabilitiesAndOverrides(context.Context, string, string, string, string, string, map[string]interface{}, []string) error
			})
			if !ok {
				if created {
					_ = deps.ModelRepo.UpdateStatus(r.Context(), model.ID, "disabled")
				}
				writeError(w, "internal_error", "model capability override storage unavailable")
				return
			}
			capabilitiesJSON, marshalErr := json.Marshal(capabilities)
			if marshalErr != nil {
				writeError(w, "internal_error", "failed to serialize model capabilities")
				return
			}
			if overrideErr := writer.UpdateCapabilitiesAndOverrides(
				r.Context(), user.TenantID, user.ID, model.ID, string(capabilitiesJSON),
				"explicit protocol selection during model creation", explicitProtocols, nil,
			); overrideErr != nil {
				if created {
					_ = deps.ModelRepo.UpdateStatus(r.Context(), model.ID, "disabled")
				}
				writeError(w, "internal_error", "failed to persist explicit model protocols")
				return
			}
		}
		logAudit(r, deps, "create_model", map[string]interface{}{
			"model_id":                   model.ID,
			"provider_id":                req.ProviderID,
			"model_name":                 req.ModelName,
			"created":                    created,
			"auto_probed":                probeRecord != nil,
			"explicit_protocol_override": explicitProtocols != nil,
		}, "model", model.ID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":                model.ID,
				"provider_id":       model.ProviderID,
				"model_name":        model.ModelName,
				"model_label":       model.ModelLabel,
				"upstream_model_id": model.UpstreamModelID,
				"status":            model.Status,
				"created":           created,
				"capabilities":      capabilities,
			},
		})
	}
}

// UpdateModelRouting updates model-level fallback provider routing.
func UpdateModelRouting(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		modelID := chi.URLParam(r, "id")
		var req types.UpdateModelRoutingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		model, err := deps.ModelRepo.GetByID(r.Context(), modelID)
		if err != nil {
			writeError(w, "internal_error", "failed to get model")
			return
		}
		if model == nil {
			writeError(w, "not_found", "model not found")
			return
		}

		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, model.ProviderID)
		if err != nil {
			writeError(w, "internal_error", "failed to verify model ownership")
			return
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "not_found", "model not found or not owned by your tenant")
			return
		}

		if req.FallbackProviderID != "" {
			if req.FallbackProviderID == model.ProviderID {
				writeError(w, "invalid_request", "fallback provider must be different from primary provider")
				return
			}

			fallbackProvider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, req.FallbackProviderID)
			if err != nil {
				writeError(w, "internal_error", "failed to verify fallback provider")
				return
			}
			if fallbackProvider == nil {
				writeError(w, "not_found", "fallback provider not found")
				return
			}
			if fallbackProvider.Status != "active" {
				writeError(w, "invalid_request", "fallback provider must be active")
				return
			}
			if !fallbackProvider.HasCredential {
				writeError(w, "invalid_request", "fallback provider must have active credentials")
				return
			}

			fallbackModel, err := deps.ModelRepo.GetByProviderAndName(r.Context(), req.FallbackProviderID, model.ModelName)
			if err != nil {
				writeError(w, "internal_error", "failed to verify fallback model")
				return
			}
			if fallbackModel == nil || fallbackModel.Status != "active" {
				writeError(w, "invalid_request", "fallback provider must have the same active model configured")
				return
			}
		}

		capabilities := model.Capabilities
		if capabilities == nil {
			capabilities = map[string]interface{}{}
		}

		routing, _ := capabilities["routing"].(map[string]interface{})
		if routing == nil {
			routing = map[string]interface{}{}
		}

		if req.FallbackProviderID == "" {
			delete(routing, "fallback_provider_id")
			if len(routing) == 0 {
				delete(capabilities, "routing")
			} else {
				capabilities["routing"] = routing
			}
		} else {
			routing["fallback_provider_id"] = req.FallbackProviderID
			capabilities["routing"] = routing
		}

		capabilitiesBytes, err := json.Marshal(capabilities)
		if err != nil {
			writeError(w, "internal_error", "failed to serialize routing config")
			return
		}

		if err := deps.ModelRepo.UpdateCapabilities(r.Context(), modelID, string(capabilitiesBytes)); err != nil {
			if err.Error() == "model not found" {
				writeError(w, "not_found", "model not found")
				return
			}
			writeError(w, "internal_error", "failed to update routing")
			return
		}

		logAudit(r, deps, "update_model_routing", map[string]interface{}{
			"model_id":             modelID,
			"fallback_provider_id": req.FallbackProviderID,
		}, "model", modelID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"model_id":             modelID,
			"fallback_provider_id": req.FallbackProviderID,
		})
	}
}

// DeleteModel deletes a model
func DeleteModel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		modelID := chi.URLParam(r, "id")

		// Verify model belongs to tenant through provider
		model, err := deps.ModelRepo.GetByID(r.Context(), modelID)
		if err != nil {
			writeError(w, "internal_error", "failed to get model")
			return
		}
		if model == nil {
			writeError(w, "not_found", "model not found")
			return
		}
		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, model.ProviderID)
		if err != nil {
			writeError(w, "internal_error", "failed to verify model ownership")
			return
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "not_found", "model not found or not owned by your tenant")
			return
		}

		if err := deps.ModelRepo.Delete(r.Context(), modelID); err != nil {
			if err.Error() == "model not found" {
				writeError(w, "not_found", "model not found")
				return
			}
			writeError(w, "internal_error", "无法删除模型：该模型已被调用记录引用，请改用「停用」")
			return
		}

		logAudit(r, deps, "delete_model", map[string]interface{}{"model_id": modelID}, "model", modelID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// UpdateModelStatus updates a model's status (active/disabled)
func UpdateModelStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		modelID := chi.URLParam(r, "id")
		var req struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.Status != "active" && req.Status != "disabled" {
			writeError(w, "invalid_request", "status must be 'active' or 'disabled'")
			return
		}

		// Verify model belongs to tenant through provider
		model, err := deps.ModelRepo.GetByID(r.Context(), modelID)
		if err != nil {
			writeError(w, "internal_error", "failed to get model")
			return
		}
		if model == nil {
			writeError(w, "not_found", "model not found")
			return
		}
		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, model.ProviderID)
		if err != nil {
			writeError(w, "internal_error", "failed to verify model ownership")
			return
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "not_found", "model not found or not owned by your tenant")
			return
		}

		var updateErr error
		if store, ok := deps.ModelRepo.(interface {
			UpdateCatalogModelStatus(context.Context, string, string, string) error
		}); ok {
			updateErr = store.UpdateCatalogModelStatus(r.Context(), user.TenantID, modelID, req.Status)
		} else {
			updateErr = deps.ModelRepo.UpdateStatus(r.Context(), modelID, req.Status)
		}
		if updateErr != nil {
			if errors.Is(updateErr, repository.ErrCatalogModelUnavailable) {
				writeErrorWithStatus(w, http.StatusConflict, "model_not_available", "上游已下架该模型，无法启用")
				return
			}
			writeError(w, "internal_error", "failed to update model status")
			return
		}

		logAudit(r, deps, "update_model_status", map[string]interface{}{"model_id": modelID, "status": req.Status}, "model", modelID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": req.Status})
	}
}

// UpdateModelProxyConfig updates a model's proxy access configuration.
func UpdateModelProxyConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		modelID := chi.URLParam(r, "id")
		if modelID == "" {
			writeError(w, "invalid_request", "model id is required")
			return
		}

		var req types.UpdateModelProxyConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.ProxyConfig == nil {
			writeError(w, "invalid_request", "proxy_config is required")
			return
		}

		// Verify model belongs to tenant through provider
		model, err := deps.ModelRepo.GetByID(r.Context(), modelID)
		if err != nil {
			writeError(w, "internal_error", "failed to get model")
			return
		}
		if model == nil {
			writeError(w, "not_found", "model not found")
			return
		}

		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, model.ProviderID)
		if err != nil {
			writeError(w, "internal_error", "failed to verify model ownership")
			return
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "not_found", "model not found or not owned by your tenant")
			return
		}

		proxyBytes, err := json.Marshal(req.ProxyConfig)
		if err != nil {
			writeError(w, "internal_error", "failed to serialize proxy config")
			return
		}

		if err := deps.ModelRepo.UpdateProxyConfig(r.Context(), modelID, string(proxyBytes)); err != nil {
			if err.Error() == "model not found" {
				writeError(w, "not_found", "model not found")
				return
			}
			writeError(w, "internal_error", "failed to update proxy config")
			return
		}

		logAudit(r, deps, "update_model_proxy_config", map[string]interface{}{
			"model_id": modelID,
			"enabled":  req.ProxyConfig["enabled"],
		}, "model", modelID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":           modelID,
				"proxy_config": req.ProxyConfig,
			},
		})
	}
}

// SyncModels syncs models from provider catalog to models table
func SyncModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.SyncModelsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.ProviderID == "" {
			writeError(w, "invalid_request", "provider_id is required")
			return
		}

		// 勾选项在碰上游之前就校验：无效选择不能变成一次目录拉取。
		selection, err := canonicalCatalogSelection(req.CatalogModelIDs)
		if err != nil {
			writeError(w, "invalid_request", "invalid catalog_model_ids selection")
			return
		}

		// Verify provider belongs to current tenant
		provider, err := deps.ProviderRepo.GetByID(r.Context(), user.TenantID, req.ProviderID)
		if err != nil {
			writeError(w, "internal_error", "failed to get provider")
			return
		}
		if provider == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "provider_not_found", "provider not found or not owned by your tenant")
			return
		}
		if provider.Status != "active" {
			writeError(w, "invalid_request", "provider must be active to sync models")
			return
		}
		if provider.AuthMode == "authorization_raw" {
			writeErrorWithStatus(w, http.StatusConflict, "sync_not_required", "完整 Chat 接口已在接入时验证模型，无需同步")
			return
		}

		if provider.ProviderType == "azure" {
			writeErrorWithStatus(w, http.StatusConflict, "selection_required", "Azure requires selecting deployments and verifying them before sync")
			return
		}
		if !deps.modelSyncGate.tryStart(user.TenantID, req.ProviderID) {
			writeErrorWithStatus(w, http.StatusConflict, "sync_in_progress", "该渠道正在同步模型，请等待完成后重试")
			return
		}
		defer deps.modelSyncGate.finish(user.TenantID, req.ProviderID)
		if store, ok := deps.ModelRepo.(catalogSnapshotStore); ok {
			syncCatalogSnapshotHTTP(w, r, deps, store, user.TenantID, provider, selection)
			return
		}

		// Get credentials
		cred, err := deps.ProviderRepo.GetCredential(r.Context(), req.ProviderID)
		if err != nil || cred == nil {
			writeError(w, "provider_not_configured", "provider credentials not configured")
			return
		}

		// Get catalog client
		catalogFactory := deps.CatalogFactory
		if catalogFactory == nil {
			catalogFactory = catalog.NewFactory()
		}

		client, err := catalogFactory.GetClient(provider.ProviderType)
		if err != nil {
			writeError(w, "internal_error", "failed to get catalog client")
			return
		}

		// Fetch models from provider catalog
		apiKey, err := secrets.DecryptProviderSecret(cred.SecretCiphertext)
		if err != nil {
			writeError(w, "internal_error", "failed to decrypt provider credentials")
			return
		}

		proxyURL, err := loadConfiguredOutboundProxyURL(r.Context(), deps)
		if err != nil {
			writeError(w, "config_error", "failed to load outbound proxy configuration")
			return
		}
		models, err := client.FetchModels(catalog.WithOutboundProxy(r.Context(), proxyURL), provider.BaseURL, apiKey)
		if err != nil {
			if catalog.IsProviderUnsupported(err) {
				writeErrorWithStatus(w, http.StatusBadRequest, "provider_unsupported", "provider does not support model catalog fetch")
				return
			}
			writeErrorWithStatus(w, http.StatusBadGateway, "catalog_unavailable", fmt.Sprintf("failed to fetch provider catalog: %s", err.Error()))
			return
		}

		// Sync models to database
		result := types.SyncModelsResponse{
			ProviderID:         req.ProviderID,
			TotalSeen:          len(models),
			Created:            0,
			Updated:            0,
			Deactivated:        0,
			Skipped:            0,
			Verified:           0,
			VerificationFailed: 0,
		}
		// Catalog IDs are the stable upstream identity. model_name may be a
		// human-readable alias, so deactivation must compare upstream_model_id.
		seenUpstreamModelIDs := make(map[string]struct{}, len(models))
		// 勾选同步：只写勾选的目录模型，且不做停用收敛。未勾选的现有模型保持原状，
		// 避免管理员只想新增几个模型时被连带下架。
		selectionSet := make(map[string]struct{}, len(selection))
		for _, id := range selection {
			selectionSet[id] = struct{}{}
		}
		matchedSelection := make(map[string]struct{}, len(selection))

		for _, catalogModel := range models {
			// Skip non-model objects (some providers return other types)
			if catalogModel.ID == "" || (catalogModel.Object != "" && catalogModel.Object != "model") {
				result.Skipped++
				continue
			}
			catalogID := catalogModel.ID
			if len(selectionSet) > 0 {
				catalogID = strings.TrimSpace(catalogModel.ID)
				if _, wanted := selectionSet[catalogID]; !wanted {
					continue
				}
				matchedSelection[catalogID] = struct{}{}
			}
			seenUpstreamModelIDs[catalogID] = struct{}{}

			// When the upstream returns a human-readable name alongside the id,
			// use the name as model_name (what clients call) and the id as
			// upstream_model_id (what we forward to the upstream).  When no
			// name is provided (standard OpenAI / numeric-id-only upstreams)
			// both fields fall back to catalogModel.ID so behaviour is
			// identical to before.
			modelName := catalogModel.ID
			modelLabel := catalogModel.ID
			upstreamModelID := catalogModel.ID
			if catalogModel.Name != "" {
				modelName = catalogModel.Name
				modelLabel = catalogModel.Name
			}

			capabilities, nativeMessagesProbed := syncedCatalogModelCapabilities(r.Context(), deps.ModelProber, provider, apiKey, catalogModel.ID)
			model := &repository.Model{
				ProviderID:           req.ProviderID,
				ModelName:            modelName,
				ModelLabel:           modelLabel,
				UpstreamModelID:      upstreamModelID,
				Capabilities:         capabilities,
				NativeMessagesProbed: nativeMessagesProbed,
				Status:               "active",
			}

			created, err := deps.ModelRepo.UpsertByProviderAndName(r.Context(), model)
			if err != nil {
				// Log error but continue processing other models
				result.Skipped++
				continue
			}

			// A catalog entry proves only that an identifier exists; it does not
			// prove which request protocol that model accepts. Production injects
			// ModelProber, so every OpenAI-compatible catalog sync refreshes real
			// Chat/Responses endpoint facts instead of relying on model-name rules.
			if deps.ModelProber != nil && providerSupportsOpenAIProtocolProbe(provider.ProviderType) {
				modality, _ := model.Capabilities["modality"].(map[string]interface{})
				if modality["type"] == "text" {
					detectedProtocols, probeRecord, probeErr := probeOpenAIModelProtocols(r.Context(), deps.ModelProber, provider, apiKey, upstreamModelID)
					if probeErr != nil {
						result.VerificationFailed++
						if created {
							// Never publish a newly discovered text model without one
							// verified protocol. Existing routes retain their last facts
							// through transient upstream outages.
							_ = deps.ModelRepo.UpdateStatus(r.Context(), model.ID, "disabled")
						}
					} else {
						model.Capabilities["protocols"] = detectedProtocols
						if recordErr := deps.ModelRepo.RecordProtocolProbe(r.Context(), user.TenantID, provider.ID, model.ID, model.Capabilities, probeRecord); recordErr != nil {
							result.VerificationFailed++
							if created {
								_ = deps.ModelRepo.UpdateStatus(r.Context(), model.ID, "disabled")
							}
						} else {
							result.Verified++
						}
					}
				}
			}

			if created {
				result.Created++
			} else {
				result.Updated++
			}
		}

		if len(selectionSet) > 0 {
			result.SelectionApplied = true
			result.SelectedMatched = len(matchedSelection)
			notFound := make([]string, 0, len(selection)-len(matchedSelection))
			for _, id := range selection {
				if _, matched := matchedSelection[id]; !matched {
					notFound = append(notFound, id)
				}
			}
			result.NotFoundModelIDs = notFound
		}

		if len(selectionSet) == 0 {
			existingModels, err := deps.ModelRepo.List(r.Context(), user.TenantID)
			if err == nil {
				for _, existing := range existingModels {
					if existing.ProviderID != req.ProviderID || existing.Status != "active" {
						continue
					}
					stableUpstreamID := strings.TrimSpace(existing.UpstreamModelID)
					if stableUpstreamID == "" {
						stableUpstreamID = existing.ModelName
					}
					if _, ok := seenUpstreamModelIDs[stableUpstreamID]; ok {
						continue
					}
					if err := deps.ModelRepo.UpdateStatus(r.Context(), existing.ID, "disabled"); err != nil {
						result.Skipped++
						continue
					}
					result.Deactivated++
				}
			}
		}

		logAudit(r, deps, "sync_models", map[string]interface{}{
			"provider_id":         req.ProviderID,
			"provider_name":       provider.Name,
			"provider_type":       provider.ProviderType,
			"total_seen":          result.TotalSeen,
			"created":             result.Created,
			"updated":             result.Updated,
			"deactivated":         result.Deactivated,
			"skipped":             result.Skipped,
			"verified":            result.Verified,
			"verification_failed": result.VerificationFailed,
			"selection_applied":   result.SelectionApplied,
			"selected_matched":    result.SelectedMatched,
			"selected_missing":    len(result.NotFoundModelIDs),
		}, "provider", req.ProviderID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// GetModelPolicy returns model policy for a project
func GetModelPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		projectID := r.URL.Query().Get("project_id")
		if projectID == "" {
			writeError(w, "invalid_request", "project_id is required")
			return
		}
		// dept_manager 等非管理员：只能看本部门项目的模型策略。
		if !callerMayAccessProject(r, deps, projectID) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		policy, err := deps.ModelPolicyRepo.GetByProject(r.Context(), user.TenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get model policy")
			return
		}

		if policy == nil {
			// Return default empty policy
			resp := types.ModelPolicyInfo{
				ProjectID: projectID,
				AllowList: []string{},
				DenyList:  []string{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		resp := types.ModelPolicyInfo{
			ID:        policy.ID,
			TenantID:  policy.TenantID,
			ProjectID: policy.ProjectID,
			AllowList: policy.AllowList,
			DenyList:  policy.DenyList,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// SetModelPolicy sets model policy for a project
func SetModelPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.ModelPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, req.ProjectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if project == nil {
			writeError(w, "not_found", "project not found")
			return
		}

		policy := &repository.ModelPolicy{
			TenantID:  user.TenantID,
			ProjectID: req.ProjectID,
			ScopeType: "project",
			AllowList: req.AllowList,
			DenyList:  req.DenyList,
		}

		if err := deps.ModelPolicyRepo.CreateOrUpdate(r.Context(), policy); err != nil {
			writeError(w, "internal_error", "failed to set model policy")
			return
		}

		resp := types.ModelPolicyInfo{
			ID:        policy.ID,
			TenantID:  policy.TenantID,
			ProjectID: policy.ProjectID,
			AllowList: policy.AllowList,
			DenyList:  policy.DenyList,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// GetQuotaPolicy returns quota policy for a project
func GetQuotaPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		// 多维度配额：scope_type 默认为 project；project 维度向后兼容 project_id 参数
		scopeType := r.URL.Query().Get("scope_type")
		if scopeType == "" {
			scopeType = "project"
		}
		scopeID := r.URL.Query().Get("scope_id")
		if scopeType == "project" && scopeID == "" {
			scopeID = r.URL.Query().Get("project_id")
		}

		// 将 scope_id 映射到对应维度的标识参数
		var projectID, teamID, userID, keyID string
		var resolvedKey *repository.InternalKey
		switch scopeType {
		case "tenant":
			// 租户维度无需额外标识
		case "team":
			teamID = scopeID
		case "project":
			projectID = scopeID
		case "user":
			userID = scopeID
		case "key":
			keyID = scopeID
		default:
			writeError(w, "invalid_request", "invalid scope_type")
			return
		}

		if scopeType != "tenant" && scopeID == "" {
			if scopeType == "project" {
				writeError(w, "invalid_request", "project_id is required")
			} else {
				writeError(w, "invalid_request", "scope_id is required")
			}
			return
		}
		if scopeType == "key" {
			key, ok := resolveQuotaKey(w, r, deps, user.TenantID, keyID)
			if !ok {
				return
			}
			resolvedKey = key
			keyID = key.ID
			scopeID = key.ID
		}
		targetExists, err := quotaScopeTargetExists(r.Context(), deps, user.TenantID, scopeType, scopeID, resolvedKey)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to validate quota scope")
			return
		}
		if !targetExists {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "quota scope not found")
			return
		}
		if !authorizeQuotaScope(r, deps, scopeType, scopeID, resolvedKey, false) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions for quota scope")
			return
		}

		policy, err := deps.QuotaPolicyRepo.GetByScope(r.Context(), user.TenantID, scopeType, projectID, teamID, userID, keyID)
		if err != nil {
			writeError(w, "internal_error", "failed to get quota policy")
			return
		}

		if policy == nil {
			// Return default empty policy
			resp := types.QuotaPolicyInfo{
				ProjectID:         projectID,
				ScopeType:         scopeType,
				ScopeID:           scopeID,
				BudgetAmountBasis: "billable_amount",
				OverageAction:     "notify",
				EnforcementMode:   "soft",
				QuotaTimezone:     "Asia/Shanghai",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		resp := types.QuotaPolicyInfo{
			ID:                   policy.ID,
			TenantID:             policy.TenantID,
			ProjectID:            policy.ProjectID,
			ScopeType:            scopeType,
			ScopeID:              scopeID,
			DailyTokenLimit:      policy.DailyTokenLimitCanonical,
			MonthlyTokenLimit:    policy.MonthlyTokenLimitCanonical,
			DailyTokenBlocked:    policy.DailyTokenBlocked,
			MonthlyTokenBlocked:  policy.MonthlyTokenBlocked,
			DailyBudgetLimit:     policy.DailyBudgetLimit,
			MonthlyBudgetLimit:   policy.MonthlyBudgetLimit,
			DailyBudgetMicros:    policy.DailyBudgetMicros,
			MonthlyBudgetMicros:  policy.MonthlyBudgetMicros,
			DailyBudgetBlocked:   policy.DailyBudgetBlocked,
			MonthlyBudgetBlocked: policy.MonthlyBudgetBlocked,
			BudgetAmountBasis:    "billable_amount",
			RPMLimit:             policy.RPMLimitCanonical,
			RPMBlocked:           policy.RPMBlocked,
			TPMLimit:             policy.TPMLimit,
			TPMBlocked:           policy.TPMBlocked,
			ConcurrencyLimit:     policy.ConcurrencyLimitCanonical,
			ConcurrencyBlocked:   policy.ConcurrencyBlocked,
			OverageAction:        defaultString(policy.OverageAction, "notify"),
			EnforcementMode:      defaultString(policy.EnforcementMode, "soft"),
			QuotaTimezone:        defaultString(policy.QuotaTimezone, "Asia/Shanghai"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// SetQuotaPolicy sets quota policy for a project
func SetQuotaPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		req, money, err := decodeQuotaPolicyRequest(w, r)
		if err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.TenantID != "" && req.TenantID != user.TenantID {
			writeError(w, "invalid_request", "tenant_id does not match authenticated tenant")
			return
		}
		if err := validateQuotaCountRequest(req); err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		quotaTimezone, err := normalizeQuotaTimezone(req.QuotaTimezone)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		overageAction := normalizeOverageAction(req.OverageAction)
		if overageAction == "" {
			writeError(w, "invalid_request", "invalid overage_action")
			return
		}
		if overageAction != "notify" && overageAction != "rate_limit" {
			writeError(w, "invalid_request", "overage_action is not supported by all gateway entry points")
			return
		}
		enforcementMode := normalizeEnforcementMode(req.EnforcementMode)
		if enforcementMode == "" {
			writeError(w, "invalid_request", "invalid enforcement_mode")
			return
		}
		// 多维度配额：scope_type 默认为 project；project 维度向后兼容 project_id 字段
		scopeType := req.ScopeType
		if scopeType == "" {
			scopeType = "project"
		}
		scopeID := req.ScopeID
		if scopeType == "project" && scopeID == "" {
			scopeID = req.ProjectID
		}

		policy := &repository.QuotaPolicy{
			TenantID:                   user.TenantID,
			ScopeType:                  scopeType,
			DailyTokenLimit:            int64Value(req.DailyTokenLimit),
			MonthlyTokenLimit:          int64Value(req.MonthlyTokenLimit),
			DailyTokenLimitCanonical:   req.DailyTokenLimit,
			MonthlyTokenLimitCanonical: req.MonthlyTokenLimit,
			DailyTokenBlocked:          req.DailyTokenBlocked,
			MonthlyTokenBlocked:        req.MonthlyTokenBlocked,
			DailyTokenCanonical:        true,
			MonthlyTokenCanonical:      true,
			DailyBudgetLimit:           req.DailyBudgetLimit,
			MonthlyBudgetLimit:         req.MonthlyBudgetLimit,
			DailyBudgetMicros:          money.dailyMicros,
			MonthlyBudgetMicros:        money.monthlyMicros,
			DailyBudgetBlocked:         money.dailyBlocked,
			MonthlyBudgetBlocked:       money.monthlyBlocked,
			DailyBudgetCanonical:       money.dailyCanonical,
			MonthlyBudgetCanonical:     money.monthlyCanonical,
			RPMLimit:                   intValue(req.RPMLimit),
			RPMLimitCanonical:          req.RPMLimit,
			RPMBlocked:                 req.RPMBlocked,
			RPMCanonical:               true,
			TPMLimit:                   req.TPMLimit,
			TPMBlocked:                 req.TPMBlocked,
			ConcurrencyLimit:           intValue(req.ConcurrencyLimit),
			ConcurrencyLimitCanonical:  req.ConcurrencyLimit,
			ConcurrencyBlocked:         req.ConcurrencyBlocked,
			ConcurrencyCanonical:       true,
			OverageAction:              overageAction,
			EnforcementMode:            enforcementMode,
			QuotaTimezone:              quotaTimezone,
			QuotaTimezoneCanonical:     money.timezonePresent,
			Status:                     "active",
		}

		var resolvedKey *repository.InternalKey
		switch scopeType {
		case "project":
			if scopeID == "" {
				writeError(w, "invalid_request", "project_id is required")
				return
			}
			project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, scopeID)
			if err != nil {
				writeError(w, "internal_error", "failed to get project")
				return
			}
			if project == nil {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "project not found")
				return
			}
			policy.ProjectID = scopeID
		case "team":
			if scopeID == "" {
				writeError(w, "invalid_request", "scope_id is required")
				return
			}
			policy.ScopeRef = scopeID
		case "user":
			if scopeID == "" {
				writeError(w, "invalid_request", "scope_id is required")
				return
			}
			policy.UserID = scopeID
		case "key":
			if scopeID == "" {
				writeError(w, "invalid_request", "scope_id is required")
				return
			}
			key, ok := resolveQuotaKey(w, r, deps, user.TenantID, scopeID)
			if !ok {
				return
			}
			resolvedKey = key
			policy.KeyID = key.ID
			policy.KeyPrefix = key.KeyPrefix
			scopeID = key.ID
		case "tenant":
			// 租户维度无需额外标识
		default:
			writeError(w, "invalid_request", "invalid scope_type")
			return
		}
		targetExists, err := quotaScopeTargetExists(r.Context(), deps, user.TenantID, scopeType, scopeID, resolvedKey)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to validate quota scope")
			return
		}
		if !targetExists {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "quota scope not found")
			return
		}
		if !authorizeQuotaScope(r, deps, scopeType, scopeID, resolvedKey, true) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions for quota scope")
			return
		}

		if err := deps.QuotaPolicyRepo.CreateOrUpdate(r.Context(), policy); err != nil {
			writeError(w, "internal_error", "failed to set quota policy")
			return
		}

		var auditTPMLimit interface{}
		if req.TPMLimit != nil {
			auditTPMLimit = *req.TPMLimit
		}
		logAudit(r, deps, "quota_policy.update", map[string]interface{}{
			"scope_type":             scopeType,
			"scope_id":               scopeID,
			"project_id":             policy.ProjectID,
			"daily_token_limit":      req.DailyTokenLimit,
			"daily_token_blocked":    req.DailyTokenBlocked,
			"monthly_token_limit":    req.MonthlyTokenLimit,
			"monthly_token_blocked":  req.MonthlyTokenBlocked,
			"daily_budget_limit":     policy.DailyBudgetLimit,
			"monthly_budget_limit":   policy.MonthlyBudgetLimit,
			"daily_budget_micros":    policy.DailyBudgetMicros,
			"monthly_budget_micros":  policy.MonthlyBudgetMicros,
			"daily_budget_blocked":   policy.DailyBudgetBlocked,
			"monthly_budget_blocked": policy.MonthlyBudgetBlocked,
			"budget_amount_basis":    "billable_amount",
			"rpm_limit":              req.RPMLimit,
			"rpm_blocked":            req.RPMBlocked,
			"tpm_limit":              auditTPMLimit,
			"tpm_blocked":            req.TPMBlocked,
			"concurrency_limit":      req.ConcurrencyLimit,
			"concurrency_blocked":    req.ConcurrencyBlocked,
			"overage_action":         overageAction,
			"enforcement_mode":       enforcementMode,
			"quota_timezone":         quotaTimezone,
			"runtime_status":         "configuration_only",
		}, "quota_policy", policy.ID)

		resp := types.QuotaPolicyInfo{
			ID:                   policy.ID,
			TenantID:             policy.TenantID,
			ProjectID:            policy.ProjectID,
			ScopeType:            scopeType,
			ScopeID:              scopeID,
			DailyTokenLimit:      policy.DailyTokenLimitCanonical,
			MonthlyTokenLimit:    policy.MonthlyTokenLimitCanonical,
			DailyTokenBlocked:    policy.DailyTokenBlocked,
			MonthlyTokenBlocked:  policy.MonthlyTokenBlocked,
			DailyBudgetLimit:     policy.DailyBudgetLimit,
			MonthlyBudgetLimit:   policy.MonthlyBudgetLimit,
			DailyBudgetMicros:    policy.DailyBudgetMicros,
			MonthlyBudgetMicros:  policy.MonthlyBudgetMicros,
			DailyBudgetBlocked:   policy.DailyBudgetBlocked,
			MonthlyBudgetBlocked: policy.MonthlyBudgetBlocked,
			BudgetAmountBasis:    "billable_amount",
			RPMLimit:             policy.RPMLimitCanonical,
			RPMBlocked:           policy.RPMBlocked,
			TPMLimit:             policy.TPMLimit,
			TPMBlocked:           policy.TPMBlocked,
			ConcurrencyLimit:     policy.ConcurrencyLimitCanonical,
			ConcurrencyBlocked:   policy.ConcurrencyBlocked,
			OverageAction:        defaultString(policy.OverageAction, "notify"),
			EnforcementMode:      defaultString(policy.EnforcementMode, "soft"),
			QuotaTimezone:        policy.QuotaTimezone,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func resolveQuotaKey(w http.ResponseWriter, r *http.Request, deps *Dependencies, tenantID, keyID string) (*repository.InternalKey, bool) {
	lookup := deps.QuotaKeyLookup
	if lookup == nil && deps.KeyRepo != nil {
		lookup = deps.KeyRepo
	}
	if lookup == nil {
		writeError(w, "internal_error", "key lookup unavailable")
		return nil, false
	}
	key, err := lookup.GetByID(r.Context(), tenantID, keyID)
	if err != nil {
		writeError(w, "internal_error", "failed to get key")
		return nil, false
	}
	if key == nil {
		if prefixLookup, ok := lookup.(quotaKeyPrefixLookup); ok {
			key, err = prefixLookup.GetUniqueByPrefix(r.Context(), tenantID, keyID)
			if err != nil {
				writeError(w, "internal_error", "failed to get key")
				return nil, false
			}
		}
	}
	if key == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "key not found")
		return nil, false
	}
	return key, true
}

// Security and audit handlers (Phase 3-4 placeholders)

// ListRuleSets returns all rule sets for a tenant
func ListRuleSets(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		ruleSets, err := deps.RuleSetRepo.List(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list rule sets")
			return
		}

		data := make([]types.RuleSetInfo, len(ruleSets))
		for i, rs := range ruleSets {
			data[i] = types.RuleSetInfo{
				ID:        rs.ID,
				Name:      rs.Name,
				Version:   rs.Version,
				Published: rs.Published,
			}
		}

		resp := types.RuleSetListResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// CreateRuleSet creates a new rule set
func CreateRuleSet(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.CreateRuleSetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.Name == "" {
			writeError(w, "invalid_request", "name is required")
			return
		}

		ruleSet := &repository.RuleSet{
			TenantID:   user.TenantID,
			Name:       req.Name,
			Version:    "1.0.0",
			SourceType: "manual",
			Published:  false,
			CreatedBy:  user.ID,
		}

		if err := deps.RuleSetRepo.Create(r.Context(), user.TenantID, ruleSet); err != nil {
			writeError(w, "internal_error", "failed to create rule set")
			return
		}

		resp := types.RuleSetInfo{
			ID:        ruleSet.ID,
			Name:      ruleSet.Name,
			Version:   ruleSet.Version,
			Published: ruleSet.Published,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// PublishRuleSet marks a rule set as published
func PublishRuleSet(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		ruleSetID := chi.URLParam(r, "id")

		// Verify rule set exists and belongs to tenant
		existingRuleSet, err := deps.RuleSetRepo.GetByID(r.Context(), user.TenantID, ruleSetID)
		if err != nil {
			writeError(w, "internal_error", "failed to get rule set")
			return
		}
		if existingRuleSet == nil {
			writeError(w, "not_found", "rule set not found")
			return
		}

		if err := deps.RuleSetRepo.Publish(r.Context(), user.TenantID, ruleSetID); err != nil {
			writeError(w, "internal_error", "failed to publish rule set")
			return
		}

		resp := types.RuleSetInfo{
			ID:        ruleSetID,
			Name:      existingRuleSet.Name,
			Version:   existingRuleSet.Version,
			Published: true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// TestSecurity proxies security test request to security-engine
func TestSecurity(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		var req types.SecurityTestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.Text == "" {
			writeError(w, "invalid_request", "text is required")
			return
		}

		// Validate project_id if provided - must belong to current tenant
		if req.ProjectID != "" {
			project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, req.ProjectID)
			if err != nil {
				writeError(w, "internal_error", "failed to validate project")
				return
			}
			if project == nil {
				writeErrorWithStatus(w, http.StatusForbidden, "invalid_project", "project not found or not owned by your tenant")
				return
			}
		}

		// Proxy to security-engine
		securityURL := "http://localhost:8000/test/"
		// Try to get URL from config if available in deps
		if deps.SecurityEngineURL != "" {
			securityURL = deps.SecurityEngineURL + "/test/"
		}

		proxyReq := map[string]interface{}{
			"text":        req.Text,
			"project_id":  req.ProjectID,
			"model":       req.Model,
			"client_type": req.ClientType,
		}

		proxyBody, err := json.Marshal(proxyReq)
		if err != nil {
			writeError(w, "internal_error", "failed to marshal proxy request")
			return
		}

		proxyHTTPReq, err := http.NewRequest("POST", securityURL, bytes.NewReader(proxyBody))
		if err != nil {
			writeError(w, "internal_error", "failed to create proxy request")
			return
		}
		// security-engine 在配置了 JJD_INTERNAL_API_SECRET 时拒绝无令牌请求（401），
		// 与其他内部调用共用同一套请求头。
		newSecurityEngineClient(securityURL, deps.SecurityEngineInternalToken).setRequestHeaders(proxyHTTPReq)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(proxyHTTPReq)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "security engine is not available")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			writeErrorWithStatus(w, resp.StatusCode, "security_error", string(bodyBytes))
			return
		}

		// Read and decode the response
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			writeError(w, "internal_error", "failed to read security engine response")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(bodyBytes) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- this endpoint relays security-engine JSON.
	}
}

func ListAuditRequests(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		limit := 100
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			limit = parseIntParam(l, 100)
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			offset = parseIntParam(o, 0)
		}
		startTime, endTime, err := defaultBoundedTimeWindow(r, 24*time.Hour)
		if err != nil {
			writeError(w, "invalid_request", "invalid time range")
			return
		}

		logs, total, err := deps.RequestLogRepo.ListFiltered(r.Context(), repository.RequestLogListFilter{
			TenantID:  user.TenantID,
			StartTime: startTime,
			EndTime:   endTime,
			Limit:     limit,
			Offset:    offset,
			SkipTotal: parseBoolParam(r.URL.Query().Get("skip_total")),
		})
		if err != nil {
			log.Printf("ListAuditRequests error: tenant=%s, err=%v", user.TenantID, err)
			writeError(w, "internal_error", "failed to list audit requests")
			return
		}

		data := make([]types.AuditRequestInfo, len(logs))
		for i, l := range logs {
			data[i] = types.AuditRequestInfo{
				RequestID:          l.RequestID,
				SessionID:          l.SessionID,
				ConversationID:     l.ConversationID,
				ModelID:            l.ModelID,
				Model:              l.ModelName,
				Status:             l.RequestStatus,
				InputAuditResult:   l.InputAuditResult,
				OutputAuditResult:  l.OutputAuditResult,
				CreatedAt:          l.CreatedAt.Format(time.RFC3339),
				ContentCount:       l.ContentCount,
				ToolCallCount:      l.ToolCallCount,
				SecurityEventCount: l.SecurityEventCount,
			}
		}

		resp := types.AuditRequestListResponse{Data: data, Total: total}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func GetAuditRequestDetail(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		requestID := chi.URLParam(r, "request_id")
		if requestID == "" {
			writeError(w, "invalid_request", "request_id is required")
			return
		}
		scope, windowStart, windowEnd, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		eventsOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("events_only")), "true")

		// Check feature flags
		contentAuditEnabled, _ := deps.SystemRepo.GetBool(r.Context(), "content_audit_enabled")
		toolAuditEnabled, _ := deps.SystemRepo.GetBool(r.Context(), "tool_audit_enabled")

		// Get security events (always returned)
		var securityEvents []*repository.SecurityEvent
		var err error
		if scoped, ok := interface{}(deps.SecurityEventRepo).(interface {
			ListByRequestScoped(context.Context, string, string, time.Time, time.Time, string) ([]*repository.SecurityEvent, error)
		}); ok {
			securityEvents, err = scoped.ListByRequestScoped(r.Context(), user.TenantID, requestID, windowStart, windowEnd, scope)
		} else {
			securityEvents, err = deps.SecurityEventRepo.ListByRequest(r.Context(), user.TenantID, requestID)
		}
		if err != nil {
			writeError(w, "internal_error", "failed to get security events")
			return
		}
		if eventsOnly {
			resp := types.AuditRequestDetailResponse{
				RequestID:           requestID,
				AuditSummary:        buildAuditSummary(requestID, nil, nil, securityEvents),
				SecurityEvents:      make([]types.SecurityEventInfo, len(securityEvents)),
				ContentLogs:         make([]types.ContentLogInfo, 0),
				ToolCallLogs:        make([]types.ToolCallLogInfo, 0),
				DetectionIssues:     buildDetectionIssues(securityEvents),
				ContentAuditEnabled: contentAuditEnabled,
				ToolAuditEnabled:    toolAuditEnabled,
			}
			for i, event := range securityEvents {
				resp.SecurityEvents[i] = mapSecurityEventToInfo(event)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("GetAuditRequestDetail events-only encode error: request_id=%s err=%v", requestID, err)
			}
			return
		}

		// 告警/审计详情的请求-响应内容是事件取证证据（五要素之"怎么证明"），
		// 不随 content_audit_enabled（常规内容浏览的隐私总开关）一起关闭。
		var contentLogs []repository.ContentLog
		var accessContent *repository.AccessContentLog
		var evidenceMetadata *repository.RequestEvidenceMetadata
		var evidenceReadErr error
		if deps.ContentLogReader != nil {
			contentLogs, err = listContentLogsByRequest(r.Context(), deps.ContentLogReader, user.TenantID, requestID, scope, windowStart, windowEnd)
		} else if deps.ContentLogRepo != nil {
			contentLogs, err = deps.ContentLogRepo.ListByRequestScoped(r.Context(), user.TenantID, requestID, windowStart, windowEnd, scope)
		}
		if err != nil {
			evidenceReadErr = err
			contentLogs = nil
		}
		if deps.AccessContentRepo != nil {
			accessContent, err = getAccessContentLog(r.Context(), deps.AccessContentRepo, user.TenantID, requestID, scope, windowStart, windowEnd)
			if err != nil {
				evidenceReadErr = err
				accessContent = nil
			}
		}
		if deps.RequestLogRepo != nil {
			evidenceMetadata, err = deps.RequestLogRepo.GetEvidenceMetadataScoped(r.Context(), user.TenantID, requestID, windowStart, windowEnd, scope)
			if err != nil {
				evidenceReadErr = err
				evidenceMetadata = nil
			}
		}
		contentEvidence := buildContentEvidenceInfo(
			time.Now(), contentLogs, accessContent, evidenceMetadata, evidenceReadErr,
		)

		// Get tool call logs (only if feature enabled)
		var toolCallLogs []repository.ToolCallLog
		if toolAuditEnabled {
			toolCallLogs, err = deps.ToolCallLogRepo.ListByRequest(r.Context(), user.TenantID, requestID)
			if err != nil {
				writeError(w, "internal_error", "failed to get tool call logs")
				return
			}
		}

		// Build response
		resp := types.AuditRequestDetailResponse{
			RequestID:           requestID,
			AuditSummary:        buildAuditSummary(requestID, contentLogs, toolCallLogs, securityEvents),
			SecurityEvents:      make([]types.SecurityEventInfo, len(securityEvents)),
			ContentLogs:         make([]types.ContentLogInfo, len(contentLogs)),
			ToolCallLogs:        make([]types.ToolCallLogInfo, len(toolCallLogs)),
			ContentEvidence:     contentEvidence,
			DetectionIssues:     buildDetectionIssues(securityEvents),
			ContentAuditEnabled: contentAuditEnabled,
			ToolAuditEnabled:    toolAuditEnabled,
		}

		// Convert security events
		for i, e := range securityEvents {
			resp.SecurityEvents[i] = mapSecurityEventToInfo(e)
		}

		// Convert content logs
		for i, l := range contentLogs {
			resp.ContentLogs[i] = types.ContentLogInfo{
				ID:        l.ID,
				RequestID: l.RequestID,
				Role:      l.Role,
				Content:   l.Content,
				Tokens:    l.Tokens,
				CreatedAt: l.CreatedAt.Format(time.RFC3339),
			}
		}

		// Convert tool call logs
		for i, l := range toolCallLogs {
			resp.ToolCallLogs[i] = types.ToolCallLogInfo{
				ID:                    l.ID,
				RequestID:             l.RequestID,
				ToolName:              l.ToolName,
				ToolType:              l.ToolType,
				RiskLevel:             l.RiskLevel,
				MatchedPolicyID:       l.MatchedPolicyID,
				MatchedPolicyName:     l.MatchedPolicyName,
				MatchedAction:         l.MatchedAction,
				MatchReason:           l.MatchReason,
				Status:                l.Status,
				EventKind:             l.EventKind,
				ExecutionObserved:     l.ExecutionObserved,
				ResultObserved:        l.ResultObserved,
				ToolCallID:            l.ToolCallID,
				AssetID:               l.AssetID,
				SkillInvocationID:     l.SkillInvocationID,
				MCPServerID:           l.MCPServerID,
				MCPToolID:             l.MCPToolID,
				DefinitionHash:        l.DefinitionHash,
				AttributionMode:       l.AttributionMode,
				AttributionConfidence: l.AttributionConfidence,
				CreatedAt:             l.CreatedAt.Format(time.RFC3339),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func buildContentEvidenceInfo(
	now time.Time,
	contentLogs []repository.ContentLog,
	accessContent *repository.AccessContentLog,
	metadata *repository.RequestEvidenceMetadata,
	readErr error,
) types.AuditContentEvidenceInfo {
	if readErr != nil {
		return types.AuditContentEvidenceInfo{
			Status:     "unavailable",
			ReasonCode: "evidence_read_failed",
			Summary:    "内容留证暂时读取失败，请稍后重试。",
			CanView:    false,
		}
	}

	for _, item := range contentLogs {
		if strings.TrimSpace(item.Content) != "" {
			return types.AuditContentEvidenceInfo{
				Status:     "available",
				ReasonCode: "content_present",
				Summary:    "已有脱敏内容留证，可查看请求与响应详情。",
				CanView:    true,
			}
		}
	}
	if accessContent != nil {
		fileMetadata := strings.TrimSpace(string(accessContent.FileMetadataJSON))
		hasFileMetadata := fileMetadata != "" && fileMetadata != "[]" && fileMetadata != "null"
		if strings.TrimSpace(accessContent.RequestContent) != "" ||
			strings.TrimSpace(accessContent.ResponseContent) != "" ||
			hasFileMetadata {
			return types.AuditContentEvidenceInfo{
				Status:     "available",
				ReasonCode: "content_present",
				Summary:    "已有脱敏内容留证，可查看请求与响应详情。",
				CanView:    true,
			}
		}
	}
	if metadata != nil && metadata.ProxyContentRetained &&
		metadata.RetentionUntil != nil && metadata.RetentionUntil.Before(now) {
		return types.AuditContentEvidenceInfo{
			Status:     "expired",
			ReasonCode: "retention_expired",
			Summary:    "内容留证已超过保留期限，当前仅保留安全事件元数据。",
			CanView:    false,
		}
	}
	return types.AuditContentEvidenceInfo{
		Status:     "not_collected",
		ReasonCode: "collection_disabled",
		Summary:    "本次请求未采集内容，无法展示请求或模型回复原文。",
		CanView:    false,
	}
}

func mapSecurityEventToInfo(e *repository.SecurityEvent) types.SecurityEventInfo {
	info := types.SecurityEventInfo{
		AgentInstanceID: e.AgentInstanceID,
		ID:              e.ID,
		RequestID:       e.RequestID,
		EventType:       e.EventType,
		Severity:        e.Severity,
		RuleID:          e.RuleID,
		RuleName:        e.RuleName,
		RuleType:        e.RuleType,
		ActionTaken:     e.ActionTaken,
		EvidenceRef:     e.EvidenceRef,
		CreatedAt:       e.CreatedAt.Format(time.RFC3339),
	}
	if len(e.MatchedSummary) > 0 {
		info.MatchedSummary = e.MatchedSummary
	}
	return info
}

func ListSecurityEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		limit := 100
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			limit = parseIntParam(l, 100)
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			offset = parseIntParam(o, 0)
		}

		// 可选过滤（G3）：无参数即零值 filter = 老行为；会话端点刻意不套默认时间窗，
		// 保持既有分页语义向后兼容（机器通道的 24h 默认窗在 portal_integration.go）。
		q := r.URL.Query()
		agentID := strings.TrimSpace(q.Get("agent_instance_id"))
		if agentID != "" && !validIntegrationAgentFilter(agentID) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		filter := repository.SecurityEventFilter{
			AgentInstanceID: agentID,
			UserID:          strings.TrimSpace(q.Get("user_id")),
			ClientID:        strings.TrimSpace(q.Get("client_id")),
			Severity:        strings.TrimSpace(q.Get("severity")),
			EventType:       strings.TrimSpace(q.Get("event_type")),
		}
		if user.Role == "platform_connector" && (limit < 1 || limit > 200 || offset < 0) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		if firstQuery(r, "start_time", "start", "start_date", "from") != "" || firstQuery(r, "end_time", "end", "end_date", "to") != "" {
			start, end, err := defaultBoundedTimeWindow(r, 24*time.Hour)
			if err != nil {
				integrationError(w, ai.ErrInvalid)
				return
			}
			filter.StartTime, filter.EndTime = &start, &end
		}
		// dept_manager 等非管理员：安全事件只看本部门（本人所在团队的 project 集）。
		// 本部门无 project → 直接返回空（fail-closed；否则空集合会被 builder 当"无过滤"而漏全租户）。
		if scope, ok := resolveUsageScope(r, deps); user.Role != "platform_connector" && ok && !scope.FullTenant {
			if len(scope.ProjectIDs) == 0 {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(types.SecurityEventListResponse{Data: []types.SecurityEventInfo{}, Total: 0})
				return
			}
			filter.ProjectIDs = scope.ProjectIDs
		}

		events, total, err := deps.SecurityEventRepo.ListFiltered(r.Context(), user.TenantID, filter, limit, offset)
		if err != nil {
			log.Printf("ListSecurityEvents error: tenant=%s, err=%v", user.TenantID, err)
			writeError(w, "internal_error", "failed to list security events")
			return
		}

		if user.Role == "platform_connector" {
			// Explicit metadata projection: never expose matched_summary, rule
			// names, evidence pointers or event bodies to the connector.
			data := make([]map[string]interface{}, len(events))
			for i, e := range events {
				data[i] = connectorRiskMetadata(e)
			}
			writeJSON(w, map[string]interface{}{"data": data, "total": total})
			return
		}

		// 命中原文（2.9.22 起入库）只给有内容证据权限的角色；按部门、按项目授权的角色只拿剔除原文后的摘要。
		canReadEvidence := canReadFullTenantContentEvidence(user)
		data := make([]types.SecurityEventInfo, len(events))
		for i, e := range events {
			data[i] = securityEventInfoForViewer(e, canReadEvidence)
		}

		resp := types.SecurityEventListResponse{Data: data, Total: total}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func usageSummaryLegacyRepo(deps *Dependencies) UsageSummaryRepo {
	if deps == nil {
		return nil
	}
	if deps.UsageSummaryRepo != nil {
		return deps.UsageSummaryRepo
	}
	if deps.UsageDailyRepo != nil {
		return deps.UsageDailyRepo
	}
	return nil
}

func usageRollupSummaryAvailable(summary *repository.UsageRollupSummary) bool {
	return summary != nil && (summary.Requests > 0 || summary.InputTokens > 0 || summary.OutputTokens > 0 || summary.TotalCost != 0)
}

func writeUsageSummaryResponse(w http.ResponseWriter, tenantID string, requests int, inputTokens, outputTokens int64, totalCost float64, dataFreshUntil *time.Time) {
	resp := types.UsageSummary{
		TenantID:       tenantID,
		Requests:       requests,
		InputTokens:    int(inputTokens),
		OutputTokens:   int(outputTokens),
		TotalCost:      totalCost,
		DataFreshUntil: "",
	}
	if dataFreshUntil != nil {
		resp.DataFreshUntil = dataFreshUntil.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func GetUsageSummary(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		startDate, endDate := parseUsageRange(r)

		if deps != nil && deps.UsageRollupRepo != nil {
			rollupSummary, err := deps.UsageRollupRepo.GetUsageSummaryScoped(r.Context(), scope, startDate, endDate)
			if err == nil && usageRollupSummaryAvailable(rollupSummary) {
				writeUsageSummaryResponse(w, scope.TenantID, rollupSummary.Requests, rollupSummary.InputTokens, rollupSummary.OutputTokens, rollupSummary.TotalCost, rollupSummary.DataFreshUntil)
				return
			}
			if err != nil && usageSummaryLegacyRepo(deps) == nil {
				writeError(w, "internal_error", "failed to get usage summary")
				return
			}
		}

		legacyRepo := usageSummaryLegacyRepo(deps)
		if legacyRepo == nil {
			writeError(w, "internal_error", "failed to get usage summary")
			return
		}
		summary, err := legacyRepo.GetSummaryScoped(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage summary")
			return
		}

		writeUsageSummaryResponse(w, summary.TenantID, summary.Requests, summary.InputTokens, summary.OutputTokens, summary.TotalCost, nil)
	}
}

func GetUsageByProject(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		startDate, endDate := parseUsageRange(r)

		usages, err := deps.UsageDailyRepo.GetByProjectScoped(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage by project")
			return
		}

		writeJSON(w, mapCostDimensionRows(usages))
	}
}

func ListAgentSessions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		tenantID, ok := resolveAgentSessionTarget(w, r, deps, user)
		if !ok {
			return
		}
		limit := 100
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			limit = parseIntParam(l, 100)
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			offset = parseIntParam(o, 0)
		}

		sessions, total, err := deps.AgentSessionRepo.List(r.Context(), tenantID, limit, offset)
		if err != nil {
			writeError(w, "internal_error", "failed to list agent sessions")
			return
		}

		data := make([]types.AgentSessionInfo, len(sessions))
		for i, s := range sessions {
			data[i] = types.AgentSessionInfo{
				SessionID:    s.SessionID,
				AgentType:    s.AgentType,
				WorkspaceID:  s.WorkspaceID,
				RiskScore:    s.RiskScore,
				RequestCount: s.RequestCount,
				FirstRequest: s.FirstRequestAt.Format(time.RFC3339),
				LastRequest:  s.LastRequestAt.Format(time.RFC3339),
			}
		}

		resp := types.AgentSessionListResponse{Data: data, Total: total}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func resolveAgentSessionTarget(w http.ResponseWriter, r *http.Request, deps *Dependencies, user *repository.User) (string, bool) {
	query := r.URL.Query()
	scope := strings.ToLower(strings.TrimSpace(query.Get("tenant_scope")))
	tenantID := strings.TrimSpace(query.Get("tenant_id"))
	if scope == "" {
		scope = "tenant"
	}
	switch scope {
	case "all":
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can list all tenants")
			return "", false
		}
		if tenantID != "" {
			writeError(w, "invalid_request", "tenant_id is not allowed for all tenants")
			return "", false
		}
		return "", true
	case "tenant":
		if tenantID == "" {
			tenantID = strings.TrimSpace(user.TenantID)
		}
		if tenantID == "" {
			writeError(w, "invalid_request", "tenant_id is required")
			return "", false
		}
		if user.Role != "platform_admin" && tenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "cannot access another tenant")
			return "", false
		}
		if user.Role == "platform_admin" {
			if tenantID == repository.SystemTenantID {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "tenant not found")
				return "", false
			}
			if !agentOperationTenantExists(w, r, deps, tenantID) {
				return "", false
			}
		}
		return tenantID, true
	default:
		writeError(w, "invalid_request", "tenant_scope must be all or tenant")
		return "", false
	}
}

func GetAgentSession(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		sessionID := chi.URLParam(r, "session_id")

		session, err := deps.AgentSessionRepo.GetBySessionID(r.Context(), user.TenantID, sessionID)
		if err != nil {
			writeError(w, "internal_error", "failed to get agent session")
			return
		}
		if session == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent session not found")
			return
		}

		resp := types.AgentSessionInfo{
			SessionID:    session.SessionID,
			AgentType:    session.AgentType,
			WorkspaceID:  session.WorkspaceID,
			RiskScore:    session.RiskScore,
			RequestCount: session.RequestCount,
			FirstRequest: session.FirstRequestAt.Format(time.RFC3339),
			LastRequest:  session.LastRequestAt.Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// Helper functions

func writeError(w http.ResponseWriter, code, message string) {
	writeErrorWithStatus(w, http.StatusBadRequest, code, message)
}

func writeErrorWithStatus(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(types.ErrorResponse{Error: types.ErrorDetail{Code: code, Message: message}})
}

func writeErrorWithStatusAndDetails(w http.ResponseWriter, status int, code, message string, details interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(types.ErrorResponse{Error: types.ErrorDetail{Code: code, Message: message, Details: details}})
}

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(types.ErrorResponse{Error: types.ErrorDetail{Code: "unauthorized", Message: message}})
}

// generateSecureKey generates a 192-bit secure random key with the JJDGuard prefix.
func generateSecureKey() string {
	bytes := make([]byte, 24)
	rand.Read(bytes)
	return "jjd_" + hex.EncodeToString(bytes)
}

// parseIntParam parses an integer parameter with a default value
func parseIntParam(s string, defaultValue int) int {
	n := defaultValue
	if parsed, err := strconv.Atoi(s); err == nil && parsed > 0 {
		n = parsed
	}
	return n
}

func normalizeOverageAction(action string) string {
	switch action {
	case "", "notify":
		return "notify"
	case "rate_limit":
		return action
	default:
		return ""
	}
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// logAudit logs an audit operation
func logAudit(r *http.Request, deps *Dependencies, actionType string, actionDetail interface{}, targetType, targetID string) {
	if deps == nil || deps.SystemRepo == nil {
		return
	}
	user := auth.GetUser(r.Context())
	if user == nil {
		return
	}

	detail := map[string]interface{}{}
	if d, ok := actionDetail.(map[string]interface{}); ok {
		detail = d
	}

	op := &repository.AuditOperation{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		ActionType:   actionType,
		ActionDetail: detail,
		TargetType:   targetType,
		TargetID:     targetID,
		IPAddress:    r.RemoteAddr,
	}

	if err := deps.SystemRepo.CreateAuditOperation(r.Context(), op); err != nil {
		log.Printf("Failed to log audit operation: %v", err)
	}
	appendAuditChain(r.Context(), deps, user.TenantID, actionType, op.ID, detail)
}

// UpdateModelCapabilities 更新模型的 capabilities_json（管理面配置对话能力 vision/web_search 等）。
// 保守原则：只接受 chat_features 数组 + modality（保留既有）；不编造、不推断，管理员显式配。
func UpdateModelCapabilities(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		modelID := chi.URLParam(r, "id")
		var req types.UpdateModelCapabilitiesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		var model *repository.Model
		var err error
		if scoped, ok := deps.ModelRepo.(interface {
			GetByIDForTenant(context.Context, string, string) (*repository.Model, error)
		}); ok {
			model, err = scoped.GetByIDForTenant(r.Context(), user.TenantID, modelID)
		} else {
			model, err = deps.ModelRepo.GetByID(r.Context(), modelID)
		}
		if err != nil {
			writeError(w, "internal_error", "failed to get model")
			return
		}
		if model == nil {
			writeError(w, "not_found", "model not found")
			return
		}
		// 合并：保留既有 modality/routing，覆盖 chat_features（管理员显式配的能力标签）
		merged := map[string]interface{}{}
		for k, v := range model.Capabilities {
			merged[k] = v
		}
		for k, v := range req.Capabilities {
			merged[k] = v
		}
		capJSON, err := json.Marshal(merged)
		if err != nil {
			writeError(w, "invalid_request", "failed to marshal capabilities")
			return
		}
		protocolOverrides := map[string]interface{}{}
		if raw, ok := req.Capabilities["protocols"]; ok {
			var valid bool
			protocolOverrides, valid = raw.(map[string]interface{})
			if !valid {
				writeError(w, "invalid_request", "protocols must be an object")
				return
			}
		}
		var updateErr error
		if len(protocolOverrides)+len(req.ClearProtocolOverrides) > 0 {
			if strings.TrimSpace(req.OverrideReason) == "" {
				writeError(w, "invalid_request", "override_reason is required for protocol capability changes")
				return
			}
			writer, ok := deps.ModelRepo.(interface {
				UpdateCapabilitiesAndOverrides(context.Context, string, string, string, string, string, map[string]interface{}, []string) error
			})
			if !ok {
				writeError(w, "internal_error", "capability override persistence unavailable")
				return
			}
			updateErr = writer.UpdateCapabilitiesAndOverrides(r.Context(), user.TenantID, user.ID, modelID, string(capJSON), req.OverrideReason, protocolOverrides, req.ClearProtocolOverrides)
		} else {
			updateErr = deps.ModelRepo.UpdateCapabilities(r.Context(), modelID, string(capJSON))
		}
		if updateErr != nil {
			writeError(w, "internal_error", "failed to update capabilities")
			return
		}
		logAudit(r, deps, "model.capabilities.update", map[string]interface{}{"model_id": modelID, "capabilities": merged}, "model", modelID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(merged)
	}
}
