// alert-evidence-review is a maintenance client of the same scoped disposition
// repository used by the console. Read-only unless --apply is explicit. It
// never updates security_events, policies, or creates detection exceptions.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"regexp"
	"strings"
	"time"
)

func validateHits(items []repository.AlertOccurrence, expected map[string]bool, category, rawHash, contextHash string) error {
	if len(items) != len(expected) || len(items) == 0 {
		return errors.New("case membership differs from reviewed event set")
	}
	seen := map[string]bool{}
	for _, item := range items {
		// 证据可复核：从留存回捞到的旧事件，或 2.9.22 起直接存了原文的新事件。
		hasEvidence := item.EvidenceRecovered || strings.TrimSpace(item.RawEvidence) != ""
		if !expected[item.EventID] || seen[item.EventID] || item.Category != category || !hasEvidence ||
			item.RawEvidenceSHA256 != rawHash || item.EvidenceContextSHA256 != contextHash || item.ContentSource != "tool_result" {
			return errors.New("case evidence does not match the reviewed snapshot")
		}
		seen[item.EventID] = true
	}
	return nil
}
func run() error {
	tenant := flag.String("tenant", "", "exact tenant")
	events := flag.String("events", "", "comma-separated reviewed event IDs")
	category := flag.String("category", "", "exact reviewed category")
	rawHash := flag.String("raw-sha256", "", "reviewed literal digest")
	contextHash := flag.String("context-sha256", "", "reviewed surrounding-context digest")
	operator := flag.String("operator", "", "maintenance service identity (not an impersonated user)")
	note := flag.String("note", "", "auditable review rationale")
	apply := flag.Bool("apply", false, "record the reviewed case as false_positive")
	flag.Parse()
	hex := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if *tenant == "" || *category == "" || !hex.MatchString(*rawHash) || !hex.MatchString(*contextHash) {
		return errors.New("tenant, category and both digests are required")
	}
	ids := strings.Split(*events, ",")
	expected := map[string]bool{}
	for _, id := range ids {
		if id == "" || expected[id] {
			return errors.New("event IDs must be nonempty and distinct")
		}
		expected[id] = true
	}
	if *apply && (*operator == "" || strings.TrimSpace(*note) == "") {
		return errors.New("apply requires operator and review rationale")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return errors.New("database configuration invalid")
	}
	defer db.Close()
	repo := repository.NewAlertOccurrenceRepository(db)
	seed, err := repo.List(ctx, repository.AlertOccurrenceFilter{TenantID: *tenant, Grouping: "cases", EventID: ids[0], Category: *category, IncludeSuppressed: true, Limit: 2})
	if err != nil {
		return err
	}
	if seed.Total != 1 || len(seed.Items) != 1 || seed.Items[0].CaseID == "" {
		return errors.New("reviewed case is not unique")
	}
	caseID := seed.Items[0].CaseID
	cases, err := repo.List(ctx, repository.AlertOccurrenceFilter{TenantID: *tenant, Grouping: "cases", CaseID: caseID, IncludeSuppressed: true, Limit: 2})
	if err != nil {
		return err
	}
	if cases.Total != 1 || len(cases.Items) != 1 || cases.Items[0].LastDetectedAt == nil {
		return errors.New("case snapshot unavailable")
	}
	item := cases.Items[0]
	hits, err := repo.List(ctx, repository.AlertOccurrenceFilter{TenantID: *tenant, Grouping: "hits", CaseID: caseID, IncludeSuppressed: true, CanReadEvidence: true, IncludeRaw: true, Limit: 100})
	if err != nil {
		return err
	}
	if hits.Total != len(expected) {
		return errors.New("case contains unreviewed findings")
	}
	if err := validateHits(hits.Items, expected, *category, *rawHash, *contextHash); err != nil {
		return err
	}
	summary := map[string]any{"case_id": caseID, "tenant": *tenant, "event_ids": ids, "category": *category, "hits": hits.Total, "case_seen_through": item.LastDetectedAt, "raw_sha256": *rawHash, "context_sha256": *contextHash, "status": item.DispositionStatus, "applied": false}
	if *apply && item.DispositionStatus != "open" && item.DispositionStatus != "false_positive" {
		return errors.New("case already has a review disposition; refusing to overwrite it")
	}
	if *apply && item.DispositionStatus != "false_positive" {
		var projects []string
		if item.ProjectID != "" {
			projects = []string{item.ProjectID}
		}
		saved, err := repository.NewAuditDispositionRepository(db).UpsertAuthorized(ctx, &repository.AuditDisposition{TenantID: *tenant, SubjectType: "alert_case", SubjectID: caseID, Status: "false_positive", Note: *note, OperatorID: *operator, OperatorName: *operator, CaseSeenThrough: item.LastDetectedAt}, projects, "", "")
		if err != nil {
			return err
		}
		summary["status"] = saved.Status
		summary["applied"] = true
		summary["disposition_id"] = saved.ID
		err = repository.NewSystemRepository(db).CreateAuditOperation(ctx, &repository.AuditOperation{ID: "ao_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24], ActionType: "audit_disposition.upsert", ActionDetail: map[string]any{"tenant_id": *tenant, "actor_type": "maintenance", "operator": *operator, "subject_type": "alert_case", "subject_id": caseID, "status": "false_positive", "event_ids": ids, "raw_sha256": *rawHash, "context_sha256": *contextHash, "note": *note}, TargetType: "alert_case", TargetID: caseID, IPAddress: ""})
		if err != nil {
			return fmt.Errorf("disposition saved but operation audit failed: %w", err)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(summary)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
