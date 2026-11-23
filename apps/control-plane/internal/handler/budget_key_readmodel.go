package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
)

// GetBudgetKeyReadModel handles GET /admin/v1/budgets/keys/{key_id}/readmodel.
//
// It answers the console key-detail budget questions with real evidence only:
//   - attribution comes from api_keys (project_id/user_id; user_id may be NULL
//     for portal-issued keys, reported as unattributed, never guessed);
//   - confirmed usage comes from the shared Redis budget buckets the gateway
//     writes for scope "key" (no token values are echoed back);
//   - in-flight reservation is reported as NOT available at key level because
//     billing_reservations are wallet(user)-scoped; the owner's wallet rows are
//     attached and explicitly labelled level=user;
//   - window/reset boundaries are derived from the bucket labels actually
//     read, so the window can never drift across midnight from the data;
//   - a failed effective-quota lookup fails the request explicitly instead of
//     silently querying a default-timezone bucket that may not match the
//     buckets the gateway wrote.
func GetBudgetKeyReadModel(deps ReadModelDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		// Same scope-visibility stance as GetBudgetSnapshot: scope identity is
		// caller-controlled, so the read model stays admin-tier.
		if !isFullTenantRole(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		if deps.KeyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "key repository not configured")
			return
		}

		keyID := chi.URLParam(r, "key_id")
		if keyID == "" {
			writeError(w, "invalid_request", "key_id required")
			return
		}
		key, err := deps.KeyRepo.GetByID(r.Context(), user.TenantID, keyID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "key_lookup_failed")
			return
		}
		if key == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "key not found")
			return
		}

		// Effective quota is required: its quota_timezone selects the Redis
		// bucket. A lookup failure must not silently fall back to a default
		// bucket that may not match what the gateway wrote.
		if deps.OrgService == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_unavailable")
			return
		}
		ref := org.ScopeRef{TenantID: user.TenantID, KeyID: keyID}
		// The key's ACCOUNTING BUCKET is decided by the key scope's own policy,
		// not by the whole scope path. EffectiveQuota merges every scope and
		// keeps only the most specific policy's timezone, which loses the scope
		// attribution: with a tenant/project/user policy in, say,
		// America/New_York and no effective key policy, the gateway still
		// accounts the key in its hardcoded Asia/Shanghai default
		// (addAdmissionAccountingScopes), so reading the merged timezone would
		// HGetAll a bucket the gateway never wrote and report usage as a silent
		// zero. KeyAccountingTimezone answers for the key scope alone, mirrors
		// the gateway's policy SQL, and applies the same accounting-default
		// fallback the gateway does.
		keyTimezone, err := deps.OrgService.KeyAccountingTimezone(r.Context(), user.TenantID, keyID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_failed")
			return
		}
		// An empty timezone would silently normalise to the default, so it is
		// treated as a failed lookup rather than papered over: a lookup that
		// cannot name the bucket must not read a guessed one.
		if strings.TrimSpace(keyTimezone) == "" {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_unavailable")
			return
		}
		timezone := budget.NormalizedQuotaTimezone(keyTimezone)
		// The limits shown to the operator stay the merged effective quota —
		// that is what actually constrains this key — but the timezone used to
		// pick the Redis bucket comes from the key scope alone. The two are
		// deliberately sourced differently and both are reported.
		effectiveQuota, err := deps.OrgService.EffectiveQuota(r.Context(), ref)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_failed")
			return
		}
		// EffectiveQuota always returns non-nil on success (a missing policy
		// yields a zero quota). It is checked explicitly because a nil
		// dereference here would panic instead of degrading.
		if effectiveQuota == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_unavailable")
			return
		}

		confirmed := map[string]interface{}{"available": false, "reason_code": "budget_snapshot_unavailable"}
		var window map[string]interface{}
		if deps.BudgetSnapshot == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget_snapshot_unavailable")
			return
		}
		scopes := []budget.SnapshotScope{{Scope: "key", ID: keyID, Timezone: timezone}}
		snapshot, err := deps.BudgetSnapshot.Get(r.Context(), user.TenantID, scopes)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget_snapshot_failed")
			return
		}
		usage, ok := snapshot["key:"+keyID]
		if !ok {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget_snapshot_failed")
			return
		}
		confirmed = map[string]interface{}{
			"available":         true,
			"scope":             "key",
			"month_bucket":      usage.MonthBucket,
			"day_bucket":        usage.DayBucket,
			"month_tokens":      usage.MonthTokens,
			"month_cost_micros": usage.MonthCostMicros,
			"month_requests":    usage.MonthRequests,
			"day_tokens":        usage.DayTokens,
			"day_cost_micros":   usage.DayCostMicros,
			"day_requests":      usage.DayRequests,
			"rpm":               usage.Rpm,
			"concurrency":       usage.Concurrency,
			// Day and month cost quality are reported separately and are NOT
			// folded into the totals above. cost_micros is incremented
			// unconditionally by the gateway's settle script, so it blends
			// actual, estimated and unpriced money; these blocks say how much
			// of each window is not an actual price. The gateway tracks the two
			// windows independently, so they are never combined.
			//
			// Cost availability is also kept apart from the volume counters:
			// tokens and requests are observed volumes, while cost_micros is
			// money whose pricing provenance is what the quality label
			// qualifies. One does not imply the other.
			"month_cost_quality": costQualityBody(
				usage.MonthCostMicros, usage.MonthCostEstimatedRequests, usage.MonthCostUnpricedRequests, usage.MonthFields),
			"day_cost_quality": costQualityBody(
				usage.DayCostMicros, usage.DayCostEstimatedRequests, usage.DayCostUnpricedRequests, usage.DayFields),
			"cost_quality_note": "quality is per window and reports pricing provenance only: 'unpriced' = at least one request had neither an actual price nor an estimate (the total then understates real spend); 'estimated' = at least one was billed from an estimate; 'unknown' = no positive counter, which is NOT evidence that every request was priced at a real price. 'actual' is deliberately unreachable: the budget hash has no settled-request total written by the same writer as these counters, so full coverage cannot be proven. cost_micros is always the observed sum and is never adjusted by these labels",
			// Currency note: these micros mirror the existing
			// /admin/v1/budgets/snapshot semantics; prepaid settlement
			// currency is the owner wallet's currency, exposed below.
			"cost_currency":            nil,
			"cost_currency_available":  false,
			"cost_currency_note":       "budget hashes have no currency dimension; owner wallet currency does not establish key cost currency",
			"month_tokens_available":   usage.MonthFields["tokens"],
			"month_requests_available": usage.MonthFields["requests"],
			"day_tokens_available":     usage.DayFields["tokens"],
			"day_requests_available":   usage.DayFields["requests"],
		}
		// Which policy decided the bucket, and where the limits come from, are
		// different questions: the bucket follows the key scope's own policy,
		// the limits follow the merged scope path. Reporting both keeps the
		// timezone the buckets were read from auditable.
		confirmed["bucket_timezone"] = timezone
		confirmed["bucket_timezone_source"] = "key scope policy quota_timezone; falls back to the gateway accounting default when the key has no policy"
		// Window boundaries are derived from the bucket labels that were
		// actually read, guaranteeing window and usage never disagree around
		// midnight (the snapshot reader uses Redis server time; the buckets
		// carry the authoritative period).
		window = budgetWindow(timezone, usage.MonthBucket, usage.DayBucket)

		// effectiveQuota is non-nil here (guarded above), so the effective
		// quota block is always reported: a scope with no policy still has a
		// real effective quota (all limits zero, default timezone), and
		// omitting it would read as "no quota information".
		quotaBody := map[string]interface{}{
			"daily_token_limit":     effectiveQuota.DailyTokenLimit,
			"monthly_token_limit":   effectiveQuota.MonthlyTokenLimit,
			"daily_budget_micros":   effectiveQuota.DailyBudgetMicros,
			"monthly_budget_micros": effectiveQuota.MonthlyBudgetMicros,
			"rpm_limit":             effectiveQuota.RPMLimit,
			"concurrency_limit":     effectiveQuota.ConcurrencyLimit,
			"triggered_scope":       effectiveQuota.TriggeredScope,
			"quota_timezone":        budget.NormalizedQuotaTimezone(effectiveQuota.QuotaTimezone),
		}

		// Owner attribution and user-level wallet evidence.
		attribution := "unattributed"
		if key.UserID != "" {
			attribution = "user"
		} else if key.ProjectID != "" {
			attribution = "project"
		}
		ownerWallets := []map[string]interface{}{}
		inFlightAvailable := false
		if key.UserID != "" && deps.DB != nil {
			repo := repositoryForReadModels(deps)
			// A real database failure must surface: silently degrading to an
			// empty wallet list would read the owner in-flight evidence as
			// absent instead of unavailable.
			wallets, err := repo.OwnerWallets(r.Context(), user.TenantID, key.UserID)
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "wallet_query_failed")
				return
			}
			for _, wl := range wallets {
				ownerWallets = append(ownerWallets, map[string]interface{}{
					"level":            "user",
					"user_id":          wl.UserID,
					"wallet_id":        wl.WalletID,
					"currency":         wl.Currency,
					"balance_micros":   wl.BalanceMicros,
					"reserved_micros":  wl.ReservedMicros,
					"available_micros": wl.BalanceMicros - wl.ReservedMicros,
				})
				inFlightAvailable = true
			}
		}

		writeJSON(w, map[string]interface{}{
			"data": map[string]interface{}{
				"key": map[string]interface{}{
					"id":         key.ID,
					"key_prefix": key.KeyPrefix,
					"name":       key.Name,
					"status":     key.Status,
					"project_id": key.ProjectID,
					// user_id may be empty for portal-issued keys: reported as
					// attribution=unattributed, never guessed from usage.
					"user_id":      key.UserID,
					"attribution":  attribution,
					"last_used_at": key.LastUsedAt,
					"expires_at":   key.ExpiresAt,
				},
				"confirmed_usage": confirmed,
				"effective_quota": quotaBody,
				"window":          window,
				"in_flight": map[string]interface{}{
					// billing_reservations carry no key dimension; claiming a
					// key-level hold would be fabrication.
					"key_level_available":   false,
					"key_level_reason":      "billing_reservations are wallet(user)-scoped; no key attribution exists",
					"owner_level_available": inFlightAvailable,
					"owner_wallets":         ownerWallets,
				},
				"generated_at": time.Now().UTC(),
			},
		})
	}
}

// costQualityBody renders one window's cost-quality evidence. The total is
// reported verbatim next to its label so a reader can see the money and judge
// it at the same time, rather than receiving a single blended number.
func costQualityBody(totalMicros, estimatedRequests, unpricedRequests int64, fields map[string]bool) map[string]interface{} {
	return map[string]interface{}{
		"observed_available": fields["cost_micros"],
		"actual_available":   false,
		"actual_micros":      nil,
		"coverage_verified":  false,
		"fields_present":     fields,
		"reason_code":        "settled_request_coverage_unverified",
		"total_micros":       totalMicros,
		"estimated_requests": estimatedRequests,
		"unpriced_requests":  unpricedRequests,
		"quality":            string(budget.ClassifyCostQuality(totalMicros, estimatedRequests, unpricedRequests)),
		"estimated_note":     "requests settled without an actual price but with a billable estimate",
		"unpriced_note":      "requests settled with neither an actual price nor an estimate; their cost contribution is not a billable figure",
	}
}

// budgetWindow derives the period boundaries from the bucket labels that the
// snapshot actually read (never from a separate clock reading), so the
// window and the usage buckets cannot disagree around midnight. Bucket
// labels may carry a "@<tz-hash>" suffix which is stripped before parsing.
// DST-safe: all arithmetic happens inside the quota location.
func budgetWindow(timezone, monthBucket, dayBucket string) map[string]interface{} {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return map[string]interface{}{"available": false, "reason_code": "invalid_quota_timezone"}
	}
	day := bucketPeriod(dayBucket, 10) // "2006-01-02"
	month := bucketPeriod(monthBucket, 7)
	if day == "" || month == "" {
		return map[string]interface{}{"available": false, "reason_code": "invalid_bucket_labels"}
	}
	dayStart, err := time.ParseInLocation("2006-01-02", day, loc)
	if err != nil {
		return map[string]interface{}{"available": false, "reason_code": "invalid_bucket_labels"}
	}
	monthStart, err := time.ParseInLocation("2006-01", month, loc)
	if err != nil {
		return map[string]interface{}{"available": false, "reason_code": "invalid_bucket_labels"}
	}
	return map[string]interface{}{
		"available":        true,
		"timezone":         timezone,
		"month_bucket":     monthBucket,
		"day_bucket":       dayBucket,
		"day_started_at":   dayStart,
		"day_reset_at":     dayStart.AddDate(0, 0, 1),
		"month_started_at": monthStart,
		"month_reset_at":   monthStart.AddDate(0, 1, 0),
	}
}

// bucketPeriod strips the timezone-hash suffix ("@xxxxxx") from a bucket
// label and keeps at most keep characters ("2026-01-02" / "2026-01").
func bucketPeriod(bucket string, keep int) string {
	bucket = strings.SplitN(bucket, "@", 2)[0]
	if len(bucket) < keep {
		return ""
	}
	return bucket[:keep]
}
