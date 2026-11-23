package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func skillListQuery(r *http.Request, allowed ...string) (url.Values, int, int, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, 0, 0, errors.New("invalid query")
	}
	keys := map[string]bool{"limit": true, "offset": true}
	for _, key := range allowed {
		keys[key] = true
	}
	for key, values := range q {
		if !keys[key] || len(values) != 1 {
			return nil, 0, 0, errors.New("unknown or repeated query parameter")
		}
	}
	limit, offset := 20, 0
	if raw := q.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			return nil, 0, 0, errors.New("limit must be 1..200")
		}
	}
	if raw := q.Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 || offset > 1000000 {
			return nil, 0, 0, errors.New("offset must be 0..1000000")
		}
	}
	return q, limit, offset, nil
}
func skillAssetListFilter(r *http.Request) (repository.SkillAssetFilter, error) {
	q, limit, offset, err := skillListQuery(r, "query", "source_type", "admission_status")
	if err != nil {
		return repository.SkillAssetFilter{}, err
	}
	f := repository.SkillAssetFilter{Limit: limit, Offset: offset, Query: strings.TrimSpace(q.Get("query")), SourceType: q.Get("source_type"), AdmissionStatus: q.Get("admission_status")}
	if (f.SourceType != "" && !oneOfSkill(f.SourceType, "uploaded", "observed")) || (f.AdmissionStatus != "" && !oneOfSkill(f.AdmissionStatus, "unverified", "approved", "quarantined", "revoked")) || validateSkillText("query", f.Query, 255, false) != nil {
		return f, errors.New("invalid asset filter")
	}
	return f, nil
}
func skillInvocationListFilter(r *http.Request) (repository.SkillInvocationFilter, error) {
	q, limit, offset, err := skillListQuery(r, "asset_id", "version_id", "canonical_name", "status", "effective_decision")
	if err != nil {
		return repository.SkillInvocationFilter{}, err
	}
	f := repository.SkillInvocationFilter{Limit: limit, Offset: offset, AssetID: q.Get("asset_id"), VersionID: q.Get("version_id"), CanonicalName: canonicalSkillAssetName(q.Get("canonical_name")), Status: q.Get("status"), EffectiveDecision: q.Get("effective_decision")}
	if validateSkillText("asset_id", f.AssetID, 128, false) != nil || validateSkillText("version_id", f.VersionID, 128, false) != nil || validateSkillText("canonical_name", q.Get("canonical_name"), 255, false) != nil || (f.Status != "" && !oneOfSkill(f.Status, "proposed", "confirmed", "blocked", "forwarded", "result_observed", "completed", "failed")) || (f.EffectiveDecision != "" && !oneOfSkill(f.EffectiveDecision, "allow", "audit", "confirm", "block")) {
		return f, errors.New("invalid invocation filter")
	}
	return f, nil
}
