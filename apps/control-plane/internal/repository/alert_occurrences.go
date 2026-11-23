package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AgentEndpointEvidence struct {
	Status        string         `json:"status"`
	AgentEventID  string         `json:"agent_event_id,omitempty"`
	EndpointID    string         `json:"endpoint_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	EventType     string         `json:"event_type,omitempty"`
	ToolUseID     string         `json:"tool_use_id,omitempty"`
	ToolName      string         `json:"tool_name,omitempty"`
	ToolType      string         `json:"tool_type,omitempty"`
	LocalDecision map[string]any `json:"local_decision,omitempty"`
}

// A finding row never inherits a sibling finding's severity, evidence or identity.
type AlertOccurrence struct {
	// Lane 是案件的处理车道：action 需行动 / watch 观察 / eval 测评流量。
	// 只读判定结果，来源见 alertLaneSQL；客户端不能提交或覆盖。
	Lane               string `json:"lane"`
	DetectionMethod    string `json:"detection_method"`
	ConfidenceKind     string `json:"confidence_kind"`
	ValidationStatus   string `json:"validation_status"`
	CredentialValidity string `json:"credential_validity"`
	ModelReviewStatus  string `json:"model_review_status"`
	RiskBasis          string `json:"risk_basis"`

	RawEvidenceSHA256       string      `json:"raw_evidence_sha256,omitempty"`
	EvidenceContextSHA256   string      `json:"evidence_context_sha256,omitempty"`
	EvidenceRecovered       bool        `json:"evidence_recovered,omitempty"`
	SemanticStatus          string      `json:"semantic_status,omitempty"`
	SemanticReason          string      `json:"semantic_reason,omitempty"`
	CaseID                  string      `json:"case_id,omitempty"`
	FirstSeen               *time.Time  `json:"first_seen,omitempty"`
	LastSeen                *time.Time  `json:"last_seen,omitempty"`
	LastDetectedAt          *time.Time  `json:"last_detected_at,omitempty"`
	OccurredAt              *time.Time  `json:"occurred_at,omitempty"`
	TimeKnown               bool        `json:"time_known"`
	HitCount                int         `json:"hit_count,omitempty"`
	RequestCount            int         `json:"request_count,omitempty"`
	BlockedCount            int         `json:"blocked_count,omitempty"`
	GroupingBasis           string      `json:"grouping_basis,omitempty"`
	TargetHost              string      `json:"target_host"`
	ModelName               string      `json:"model_name"`
	ModelID                 string      `json:"model_id"`
	DeliveryOutcome         string      `json:"delivery_outcome"`
	RequestStatus           string      `json:"request_status"`
	ID                      string      `json:"id"`
	EventID                 string      `json:"event_id"`
	RequestID               string      `json:"request_id"`
	ProjectID               string      `json:"project_id"`
	CreatedAt               time.Time   `json:"created_at"`
	FindingIndex            *int        `json:"finding_index"`
	DuplicateCount          int         `json:"duplicate_count"`
	RuleIDs                 []string    `json:"rule_ids"`
	Type                    string      `json:"type"`
	Category                string      `json:"category"`
	Severity                string      `json:"severity"`
	RuleID                  string      `json:"rule_id"`
	RuleName                string      `json:"rule_name"`
	RuleType                string      `json:"rule_type,omitempty"`
	PolicyCode              string      `json:"policy_code,omitempty"`
	RuleNameCount           int         `json:"rule_name_count,omitempty"`
	SeverityDowngradeReason string      `json:"severity_downgrade_reason,omitempty"`
	PolicyLink              *PolicyLink `json:"policy_link,omitempty"`
	// RawEvidenceCount 是该请求在原文留证（content_raw_evidence）里的条数；大于 0 时控制台显示“查看原文”。
	// 按案件分组的视图下，它只反映该行代表请求的条数，不是整个案件的条数。仅在 CanViewRawEvidence 为真时填充。
	RawEvidenceCount int `json:"raw_evidence_count"`
	// ManagedBehavior 是阻断事件里网关记的托管行为键，只用来推导 PolicyLink，不对外输出。
	ManagedBehavior   string `json:"-"`
	ActionTaken       string `json:"action_taken"`
	EventActionTaken  string `json:"event_action_taken"`
	Suppressed        bool   `json:"suppressed"`
	SuppressionReason string `json:"suppression_reason"`
	ReviewState       string `json:"review_state"`
	DispositionStatus string `json:"disposition_status"`
	AlertGroupID      string `json:"alert_group_id"`
	MessageIndex      *int   `json:"message_index"`
	AttachmentIndex   *int   `json:"attachment_index"`
	MessageRole       string `json:"message_role"`
	ContentSource     string `json:"content_source"`
	Stage             string `json:"stage"`
	MatchedLocation   string `json:"matched_location"`
	LocationStatus    string `json:"location_status"`
	Reason            string `json:"reason"`
	ReasonStatus      string `json:"reason_status"`
	EvidenceKind      string `json:"evidence_kind"`
	RedactedEvidence  string `json:"redacted_evidence"`
	EvidenceStatus    string `json:"evidence_status"`
	RawEvidence       string `json:"raw_evidence,omitempty"`
	// RawEvidenceTruncated：命中原文超过数据面上限（4096 字）被截断，只随原文一起返回。
	RawEvidenceTruncated bool `json:"raw_evidence_truncated,omitempty"`
	// RawEvidenceOmitted：事件原文总量超限，数据面没存这条命中的原文（哈希照存，可从留存回捞）；不是敏感信息，各角色都给。
	RawEvidenceOmitted      bool                   `json:"raw_evidence_omitted,omitempty"`
	MatchedTextPreview      string                 `json:"matched_text_preview,omitempty"`
	EvidenceContext         string                 `json:"evidence_context,omitempty"`
	RawEvidenceStatus       string                 `json:"raw_evidence_status"`
	ActorUserID             string                 `json:"actor_user_id"`
	ActorName               string                 `json:"actor_name"`
	ActorDepartmentID       string                 `json:"actor_department_id"`
	ActorDepartmentName     string                 `json:"actor_department_name"`
	KeyOwnerUserID          string                 `json:"key_owner_user_id"`
	KeyOwnerName            string                 `json:"key_owner_name"`
	DepartmentID            string                 `json:"department_id"`
	DepartmentName          string                 `json:"department_name"`
	AgentType               string                 `json:"agent_type"`
	CredentialID            string                 `json:"credential_id"`
	CredentialName          string                 `json:"credential_name"`
	PrincipalKey            string                 `json:"principal_key"`
	IdentitySource          string                 `json:"identity_source"`
	IdentityReliability     string                 `json:"identity_reliability"`
	SourceIP                string                 `json:"source_ip"`
	AccessDirection         string                 `json:"access_direction"`
	AccessType              string                 `json:"access_type"`
	ClientProduct           string                 `json:"client_product"`
	ConversationKey         string                 `json:"conversation_key"`
	ConversationID          string                 `json:"conversation_id"`
	SessionID               string                 `json:"session_id"`
	AgentSessionID          string                 `json:"agent_session_id"`
	AgentEndpointEvidence   *AgentEndpointEvidence `json:"agent_endpoint_evidence,omitempty"`
	ConversationSource      string                 `json:"conversation_source"`
	ConversationReliability string                 `json:"conversation_reliability"`
}

type AlertOccurrenceCounts struct {
	RawHits       int `json:"raw_hits"`
	Delayed24h    int `json:"delayed_24h"`
	UnknownTime   int `json:"unknown_time"`
	Handled       int `json:"handled"`
	FalsePositive int `json:"false_positive"`
	Last24h       int `json:"last_24h"`
	Previous24h   int `json:"previous_24h"`
	Blocked24h    int `json:"blocked_24h"`
	PendingHigh   int `json:"pending_high"`
	PendingMedium int `json:"pending_medium"`
	PendingLow    int `json:"pending_low"`
	Total         int `json:"total"`
	Active        int `json:"active"`
	Suppressed    int `json:"suppressed"`
	// Pending is the customer-facing backlog: disposition still 'open' and not
	// suppressed. Active only means "not suppressed" and never answers 待处置.
	Pending  int `json:"pending"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	// 车道页签的计数：同一范围内、按车道分别统计的问题数，不随当前选中的车道变化。
	// 只在 LaneAware 查询里有值。
	LaneAction int `json:"lane_action"`
	LaneWatch  int `json:"lane_watch"`
	LaneEval   int `json:"lane_eval"`
}

type AlertOccurrencePage struct {
	// EvidenceReadable：本次读的账号有没有内容证据权限（命中原文、检测理由、留存）。控制台据此决定是否
	// 请求原文、是否显示证据入口，不只看角色名。
	EvidenceReadable        bool                    `json:"evidence_readable"`
	FoldedDevelopmentGroups int                     `json:"folded_development_groups"`
	CountUnit               string                  `json:"count_unit"`
	Operational             AlertOperationalSummary `json:"operational"`
	Items                   []AlertOccurrence       `json:"items"`
	Total                   int                     `json:"total"`
	Limit                   int                     `json:"limit"`
	Offset                  int                     `json:"offset"`
	Counts                  AlertOccurrenceCounts   `json:"counts"`
}

type AlertOccurrenceFilter struct {
	IncludeDevTraffic bool
	// LaneAware 打开车道分流：每个案件带 Lane，并按车道各自截取最近 RecentLimit 个、各自计数。
	// 关闭时（老客户端、导出、详情下钻）保持原有的全局口径，行为逐字节不变。
	LaneAware bool
	// Lane 只显示某个车道（action/watch/eval），空为全部。仅 LaneAware 时生效。
	Lane                      string
	useReadMetadata           bool
	Grouping, CaseID, EventID string
	Disposition               string
	TenantID                  string
	// nil means full tenant; an empty non-nil slice means no authorized projects.
	ProjectIDs                                               []string
	ProjectID, RequestID, ConversationKey, SessionID, UserID string
	Severity, Category                                       string
	Reason                                                   string // coverage-gap runtime reason; attack rows never carry one
	StartTime, EndTime                                       *time.Time
	IncludeSuppressed, IncludeRaw, CanReadEvidence           bool
	// CanViewRawEvidence 仅系统管理员、安全保密员为真（与原文留证接口同一判断）；为假时不查也不返回原文留证条数。
	CanViewRawEvidence bool
	RecentLimit        int // cap the scoped case set before disposition tabs and pagination
	Limit, Offset      int
	// eventIDs 只供物化维护重算指定事件的命中行，接口参数不会设置它。
	eventIDs []string
}

type AlertOccurrenceRepository struct {
	db                                 *pgxpool.Pool
	metadataMu                         sync.Mutex
	metadataChecked, metadataAvailable bool
	// caseStoreDisabled 为真时告警读一律实时查询，不用物化表（JJD_ALERT_CASE_STORE=off 时设置，供现场紧急回退）。
	caseStoreDisabled bool
}

func (r *AlertOccurrenceRepository) useReadMetadata(ctx context.Context) (bool, error) {
	r.metadataMu.Lock()
	defer r.metadataMu.Unlock()
	if r.metadataChecked {
		return r.metadataAvailable, nil
	}
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('security_events') AND attname='alert_read_metadata_v1' AND attgenerated='s' AND NOT attisdropped)`).Scan(&r.metadataAvailable)
	if err != nil {
		return false, err
	}
	r.metadataChecked = true
	return r.metadataAvailable, nil
}

func NewAlertOccurrenceRepository(db *pgxpool.Pool) *AlertOccurrenceRepository {
	return &AlertOccurrenceRepository{db: db, caseStoreDisabled: alertCaseStoreOff}
}

// alertQuery 能由物化表回答时用物化表（见 alert_case_store.go），否则照旧实时查询。两者结果一致。
func (r *AlertOccurrenceRepository) alertQuery(ctx context.Context, f AlertOccurrenceFilter) (string, []any, bool, error) {
	if !r.caseStoreDisabled && alertCaseMaterializable(f) {
		ready, err := prepareAlertCaseReads(ctx, r.db, f.useReadMetadata, f.TenantID, false)
		if err != nil {
			return "", nil, false, err
		}
		if ready {
			query, args, err := buildMaterializedAlertQuery(f)
			if err == nil {
				return query, args, true, nil
			}
			logAlertCaseShapeError(err)
		}
	}
	query, args := buildAlertOccurrenceQuery(f)
	return query, args, false, nil
}

func (r *AlertOccurrenceRepository) List(ctx context.Context, f AlertOccurrenceFilter) (*AlertOccurrencePage, error) {
	if strings.TrimSpace(f.TenantID) == "" {
		return nil, fmt.Errorf("alert occurrences require tenant scope")
	}
	if f.Limit <= 0 {
		f.Limit = 20
	}
	if f.Limit > 100 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	var metadataErr error
	f.useReadMetadata, metadataErr = r.useReadMetadata(ctx)
	if metadataErr != nil {
		return nil, metadataErr
	}
	query, args, materialized, err := r.alertQuery(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("prepare alert cases: %w", err)
	}
	// Both totals and page share one PostgreSQL statement/snapshot. Even a page
	// beyond the end returns exact scoped counts; no all-events Go-side paging.
	var rowsJSON, countsJSON []byte
	page := &AlertOccurrencePage{Items: []AlertOccurrence{}, Limit: f.Limit, Offset: f.Offset,
		Operational: AlertOperationalSummary{CountUnit: "security_events", CountKnown: f.Grouping != "cases" && f.CaseID == ""}}
	if err := r.queryAlertRead(ctx, query, args, &rowsJSON, &page.Total, &countsJSON, &page.Operational.EventCount); err != nil {
		return nil, fmt.Errorf("list alert occurrences: %w", err)
	}
	if err := json.Unmarshal(rowsJSON, &page.Items); err != nil {
		return nil, err
	}
	if err := fillManagedBehaviors(rowsJSON, page.Items); err != nil {
		return nil, err
	}
	for index := range page.Items {
		normalizeOccurrenceEvidence(&page.Items[index], f.IncludeRaw && f.CanReadEvidence)
	}
	if err := r.recoverOccurrenceEvidenceBatch(ctx, f, page.Items); err != nil {
		return nil, fmt.Errorf("recover occurrence evidence: %w", err)
	}
	if err := r.attachAlertPolicyLinks(ctx, f.TenantID, page.Items); err != nil {
		return nil, err
	}
	if f.CanViewRawEvidence {
		r.attachRawEvidenceCounts(ctx, f.TenantID, page.Items)
	}
	page.CountUnit = "findings"
	if f.Grouping == "cases" {
		page.CountUnit = "triage_cases"
	}
	if err := json.Unmarshal(countsJSON, &page.Counts); err != nil {
		return nil, err
	}
	folded, err := r.countFoldedDevelopmentGroups(ctx, f, materialized)
	if err != nil {
		return nil, fmt.Errorf("count development groups: %w", err)
	}
	page.FoldedDevelopmentGroups = folded
	return page, nil
}

// Complex JSON reports otherwise spend seconds compiling hundreds of JIT
// functions before reading any rows. Keep the setting inside this read-only
// transaction so it cannot affect other users of the connection pool.
func (r *AlertOccurrenceRepository) queryAlertRead(ctx context.Context, query string, args []any, dest ...any) error {
	return pgx.BeginTxFunc(ctx, r.db, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL jit = off"); err != nil {
			return err
		}
		return tx.QueryRow(ctx, query, args...).Scan(dest...)
	})
}

func buildAlertOccurrenceQuery(f AlertOccurrenceFilter) (string, []any) {
	args := []any{f.TenantID, f.IncludeRaw && f.CanReadEvidence, f.CanReadEvidence, f.IncludeSuppressed, f.Limit, f.Offset}
	eventFilter := f
	if f.Grouping == "cases" || f.CaseID != "" {
		eventFilter.StartTime = nil
	}
	eventWhere, args := alertOccurrenceEventScope(eventFilter, args)
	if f.Grouping == "cases" || f.CaseID != "" {
		eventWhere = strings.ReplaceAll(eventWhere, "se.created_at", "COALESCE(cm.request_created_at,se.created_at)")
	}
	rowWhere := []string{"TRUE"}
	if f.CaseID != "" {
		args = append(args, f.CaseID)
		rowWhere = append(rowWhere, fmt.Sprintf("case_id = $%d", len(args)))
	}
	if f.Grouping == "cases" && f.StartTime != nil {
		args = append(args, f.StartTime.UTC())
		rowWhere = append(rowWhere, fmt.Sprintf("last_seen >= $%d", len(args)))
	}
	if f.Severity != "" {
		args = append(args, f.Severity)
		rowWhere = append(rowWhere, fmt.Sprintf("severity = $%d", len(args)))
	}
	categoryPrefilter := "TRUE"
	if f.Category != "" {
		categories := []string{}
		for _, value := range strings.Split(f.Category, ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if f.Grouping == "cases" {
				value = canonicalAlertCategory(value)
			}
			categories = append(categories, value)
		}
		field := "category"
		if f.Grouping == "cases" {
			field = "case_category"
		}
		if len(categories) == 1 {
			args = append(args, categories[0])
			rowWhere = append(rowWhere, fmt.Sprintf(field+" = $%d", len(args)))
		} else {
			args = append(args, categories)
			rowWhere = append(rowWhere, fmt.Sprintf(field+" = ANY($%d::text[])", len(args)))
		}
	}
	if f.Category != "" {
		categoryPrefilter = rowWhere[len(rowWhere)-1]
	}
	statusWhere := "TRUE"
	switch f.Disposition {
	case "", "all":
	case "pending":
		statusWhere = "NOT suppressed AND disposition_status='open'"
	case "handled":
		statusWhere = "NOT suppressed AND disposition_status IN ('resolved','closed','accepted','escalated','acknowledged','confirmed')"
	case "false_positive":
		statusWhere = "disposition_status='false_positive' OR suppression_reason='false_positive'"
	default:
		statusWhere = "FALSE"
	}
	operationalWhere := strings.ReplaceAll(eventWhere, "COALESCE(cm.request_created_at,se.created_at)", "se.created_at")

	cte, projection, fields, join, key := alertCaseTemplates(f)
	evidenceKey := "''::text"
	if f.Grouping == "cases" {
		evidenceKey = alertEvidenceIdentitySQL(f.useReadMetadata)
	}
	if f.useReadMetadata {
		cte = strings.ReplaceAll(cte, "COALESCE(se.matched_summary,'{}'::jsonb) AS summary", "COALESCE(se.alert_read_metadata_v1,'{}'::jsonb) AS summary")
	}
	if f.Grouping == "cases" {
		statusWhere = strings.ReplaceAll(strings.ReplaceAll(statusWhere, "disposition_status", "case_disposition_status"), "suppressed", "case_suppressed")
	}
	operationalCount := "(SELECT COUNT(*) FROM security_events se " + operationalScopeJoin(f) + " WHERE " + operationalWhere + " AND (" + operationalEventCondition("se") + "))"
	if f.Grouping == "cases" || f.CaseID != "" {
		operationalCount = "0"
	}
	query := strings.NewReplacer(
		"@case_category@", alertCaseCategorySQL(),
		"@case_evidence_key@", evidenceKey,
		"@case_event_fields@", fields, "@case_join@", join, "@case_key@", key,
		"@status_where@", statusWhere,
		"@event_where@", eventWhere,
		"@row_where@", strings.Join(rowWhere, " AND "),
		"@category_prefilter@", categoryPrefilter,
		"@actor@", occurrenceActorExpr,
		"@request_join@", operationalScopeJoin(f),
		"@page_request_join@", alertOccurrenceRequestJoin,
		"@operational_finding@", operationalFindingCondition("finding", "event_action_taken"),
		"@operational_legacy@", operationalRootCondition("finding", "event_type", "event_action_taken"),
		"@operational_count@", operationalCount,
	).Replace(cte + projection)
	return query, args
}

// alertEvidenceIdentitySQL 是案件里一条命中的证据身份（判断“有无新证据”用），需要 finding、event_id、
// finding_index 三个列。有生成列 alert_read_metadata_v1 时取它算好的 _jjd_evidence_identity（迁移 850，
// 1010 起优先取数据面写的 evidence_identity_sha256）。没有生成列时口径与 1010 一致：带 evidence_identity_sha256
// 的命中（2.9.22 起存了原文）取它，空值表示 2.9.21 下没有证据身份、按事件与命中序号；不带这个键的存量命中
// 按原口径：语义类前后文优先，其余原文优先，再退到预览、事件与命中序号。不能对 2.9.22 起入库的原文求哈希，
// 否则同一命中升级前后身份不同，已处置的案件会被当成有新证据重新打开。
func alertEvidenceIdentitySQL(useReadMetadata bool) string {
	fallback := "encode(sha256(convert_to(event_id||':'||COALESCE(finding_index::text,''),'UTF8')),'hex')"
	legacy := "encode(sha256(convert_to(CASE WHEN finding->>'type'='semantic_attack' OR COALESCE(finding->>'category','') LIKE 'semantic_%' THEN COALESCE(NULLIF(finding->>'evidence_context',''),NULLIF(finding->>'raw_evidence',''),NULLIF(finding->>'matched_text_preview',''),event_id||':'||COALESCE(finding_index::text,'')) ELSE COALESCE(NULLIF(finding->>'raw_evidence',''),NULLIF(finding->>'evidence_context',''),NULLIF(finding->>'matched_text_preview',''),event_id||':'||COALESCE(finding_index::text,'')) END,'UTF8')),'hex')"
	identity := "CASE WHEN finding ? 'evidence_identity_sha256' THEN COALESCE(CASE WHEN finding->>'evidence_identity_sha256' ~ '^[0-9a-f]{64}$' THEN finding->>'evidence_identity_sha256' END," + fallback + ") ELSE " + legacy + " END"
	if useReadMetadata {
		identity = "COALESCE(finding->>'_jjd_evidence_identity'," + identity + ")"
	}
	return identity
}

func alertOccurrenceEventScope(f AlertOccurrenceFilter, args []any) (string, []any) {
	eventWhere := []string{"se.tenant_id = $1"}
	add := func(dest *[]string, expr string, value any) {
		args = append(args, value)
		*dest = append(*dest, fmt.Sprintf(expr, len(args)))
	}
	if f.ProjectIDs != nil {
		add(&eventWhere, "se.project_id = ANY($%d::text[])", f.ProjectIDs)
	}
	if f.ProjectID != "" {
		add(&eventWhere, "se.project_id = $%d", f.ProjectID)
	}
	if f.EventID != "" {
		add(&eventWhere, "se.id = $%d", f.EventID)
	}
	if f.eventIDs != nil {
		add(&eventWhere, "se.id = ANY($%d::text[])", f.eventIDs)
	}
	if f.RequestID != "" {
		add(&eventWhere, "se.request_id = $%d", f.RequestID)
	}
	if f.ConversationKey != "" {
		add(&eventWhere, "se.conversation_key = $%d", f.ConversationKey)
	}
	if f.SessionID != "" {
		// 只有可信的端点入库路径才允许从 matched_summary 回退会话关联。
		args = append(args, f.SessionID, f.SessionID)
		eventWhere = append(eventWhere, fmt.Sprintf("(rl.session_id = $%d OR (se.matched_summary->>'source' = 'agent_endpoint' AND se.matched_summary->>'session_id' = $%d))", len(args)-1, len(args)))
	}
	if f.UserID != "" {
		add(&eventWhere, "("+occurrenceActorExpr+") = $%d", f.UserID)
	}
	if f.StartTime != nil {
		add(&eventWhere, "se.created_at >= $%d", f.StartTime.UTC())
	}
	if f.EndTime != nil {
		add(&eventWhere, "se.created_at < $%d", f.EndTime.UTC())
	}
	// Evidence drill-down is an audit view and always retains the requested event.
	if !f.IncludeDevTraffic && f.EventID == "" && f.RequestID == "" && f.CaseID == "" {
		eventWhere = append(eventWhere, "NOT ("+developmentFoldedEventExpr("se")+")")
	}
	return strings.Join(eventWhere, " AND "), args
}

// Key-bound identities describe credential ownership, never the acting employee.
// Legacy records without a principal trust declaration retain their recorded user.
const occurrenceActorExpr = `CASE
 WHEN pc.value->>'trust_level' = 'authenticated' THEN COALESCE(pc.value->>'actor_user_id','')
 WHEN pc.value ? 'trust_level' OR pc.value ? 'key_owner_user_id'
   OR pc.value->>'identity_source' IN ('upstream_credential','upstream_account') THEN ''
 ELSE COALESCE(NULLIF(rl.user_id,''),se.user_id,'') END`
