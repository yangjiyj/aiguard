package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A prepaid settlement fact shares the (tenant_id, request_id) key with a
// metering measurement. Replaying metering against a fact the settlement path
// wrote must CONFLICT rather than hand back a settled charge the caller never
// made, so billing_mode is part of the compared input.
func TestMeteringReplayRejectsCrossBillingModeFact(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	admittedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	// A fact written by the prepaid settlement path: billing_mode='prepaid'.
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_id,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at,
			request_status,admitted_at,raw_usage_json
		) VALUES ($1,$2,'req-cross-mode','prepaid',$3,'legacy','cross-mode-model',4,2,'CNY','settled',NOW(),$4,$5,$6)
	`, "usage_fact_cross_"+tenantID, tenantID, userID, "success", admittedAt,
		`{"usage_source":"upstream"}`); err != nil {
		t.Fatal(err)
	}
	// Every token and evidence field matches the metering input, so only the
	// billing mode can catch this.
	if _, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-cross-mode", ModelName: "cross-mode-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 4, OutputTokens: 2},
		AdmittedAt: admittedAt, RawUsage: []byte(`{"usage_source":"upstream"}`),
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("cross-mode replay err=%v want ErrIdempotencyConflict", err)
	}
}

// A genuine replay whose raw usage differs only in NUMERIC FORM is the same
// input: jsonb normalizes literals, so 1e2 and 100 are one value, as are 1.0
// and 1. Deciding this in Go by comparing bytes (the earlier approach) failed
// such replays and would also have mangled token counts beyond 2^53. The
// verdict belongs to PostgreSQL.
func TestMeteringReplayAcceptsEquivalentJSONNumericForms(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	base := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-jsonb-numeric", ModelName: "jsonb-numeric-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 4, OutputTokens: 2},
		AdmittedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond),
		RawUsage:   []byte(`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":1e2,"ratio":1.0}}`),
	}
	first, err := store.RecordMeteringUsage(ctx, base)
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	for _, equivalent := range []string{
		`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":100,"ratio":1}}`,
		`{"upstream_usage":{"ratio":1,"prompt_tokens":1e2},"usage_source":"upstream"}`,
	} {
		replay := base
		replay.RawUsage = []byte(equivalent)
		got, err := store.RecordMeteringUsage(ctx, replay)
		if err != nil {
			t.Fatalf("equivalent numeric form %s: err=%v", equivalent, err)
		}
		if got.ID != first.ID {
			t.Fatalf("equivalent form produced a different fact: %+v vs %+v", got, first)
		}
	}
	// A genuinely different value still conflicts: normalization must not blur
	// a real difference into a match.
	different := base
	different.RawUsage = []byte(`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":101,"ratio":1.0}}`)
	if _, err := store.RecordMeteringUsage(ctx, different); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different numeric value err=%v want ErrIdempotencyConflict", err)
	}
}

// EvidenceVerified must mean "every caller-supplied field was compared and
// agreed on this call", not "a post-942 row exists" and not "a timestamp was
// present". A replay that omits admitted_at compares the ABSENCE, and a
// matching absence is a completed comparison: the store's default is an
// internal value needing no upstream attestation, so it must not downgrade the
// verification. Changing presence between writes is a real input change and
// still conflicts.
func TestMeteringEvidenceVerifiedTracksComparedFields(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	admittedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	full := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-presence", ModelName: "presence-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 5, OutputTokens: 3},
		AdmittedAt: admittedAt,
		RawUsage:   []byte(`{"usage_source":"upstream"}`),
	}
	first, err := store.RecordMeteringUsage(ctx, full)
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	if !first.EvidenceVerified {
		t.Fatal("a first write with every field present must be verified")
	}
	// Replay with everything: all three compared -> verified.
	complete, err := store.RecordMeteringUsage(ctx, full)
	if err != nil || !complete.EvidenceVerified {
		t.Fatalf("complete replay=%+v err=%v want verified", complete, err)
	}
	// Dropping admitted_at when the first write supplied one changes caller
	// intent, so it is a conflict rather than a pass. The persisted presence bit
	// is what makes this decidable; the value alone could not.
	noTime := full
	noTime.AdmittedAt = time.Time{}
	if _, err := store.RecordMeteringUsage(ctx, noTime); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("dropping a supplied timestamp err=%v want ErrIdempotencyConflict", err)
	}
	// A row whose first write omitted the time replays cleanly when the replay
	// also omits it, and reports unverified because nothing was compared.
	omitted := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-presence-omitted", ModelName: "presence-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 5, OutputTokens: 3},
		RawUsage: []byte(`{"usage_source":"upstream"}`),
	}
	omittedFirst, err := store.RecordMeteringUsage(ctx, omitted)
	if err != nil {
		t.Fatalf("omitted first write: %v", err)
	}
	if !omittedFirst.EvidenceVerified {
		t.Fatal("an omitted timestamp is compared as absence and must verify")
	}
	omittedReplay, err := store.RecordMeteringUsage(ctx, omitted)
	if err != nil {
		t.Fatalf("omitted replay must stay compatible: %v", err)
	}
	if omittedReplay.ID != omittedFirst.ID {
		t.Fatalf("omitted replay returned a different fact: %+v vs %+v", omittedReplay, omittedFirst)
	}
	if !omittedReplay.AdmittedAt.Equal(omittedFirst.AdmittedAt) {
		t.Fatalf("defaulted timestamp drifted: %v vs %v", omittedReplay.AdmittedAt, omittedFirst.AdmittedAt)
	}
	// Dropping the raw usage against a fact that CARRIES it is a real
	// contradiction, not an unchecked field: the replay would be asserting a
	// smaller input under the same key. It must conflict rather than silently
	// inherit the richer fact.
	noRaw := full
	noRaw.RawUsage = nil
	if _, err := store.RecordMeteringUsage(ctx, noRaw); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("replay dropping raw usage err=%v want ErrIdempotencyConflict", err)
	}
	// When BOTH sides carry no raw usage, PostgreSQL still compared the
	// absence explicitly (NULL IS NOT DISTINCT FROM NULL), so this is a
	// compared fact rather than an unchecked field. With the admission time
	// also supplied and equal, every field that carries caller intent was
	// genuinely compared and the result is verified.
	bothBare := full
	bothBare.RawUsage = nil
	bothBare.RequestID = "req-presence-bare"
	if _, err := store.RecordMeteringUsage(ctx, bothBare); err != nil {
		t.Fatalf("first bare write: %v", err)
	}
	bare, err := store.RecordMeteringUsage(ctx, bothBare)
	if err != nil {
		t.Fatalf("bare replay must stay compatible: %v", err)
	}
	if !bare.EvidenceVerified {
		t.Fatal("a replay comparing an explicitly-absent raw usage and an equal supplied time is verified")
	}
	// The same row with the admission time omitted is NOT verified: the time was
	// never compared, only defaulted.
	bareOmitted := bothBare
	bareOmitted.AdmittedAt = time.Time{}
	bareOmitted.RequestID = "req-presence-bare-omitted"
	if _, err := store.RecordMeteringUsage(ctx, bareOmitted); err != nil {
		t.Fatalf("first bare omitted write: %v", err)
	}
	bareOmittedReplay, err := store.RecordMeteringUsage(ctx, bareOmitted)
	if err != nil {
		t.Fatalf("bare omitted replay: %v", err)
	}
	if !bareOmittedReplay.EvidenceVerified {
		t.Fatal("omitted time plus absent raw usage is still a compared match")
	}
	// Pre-942 legacy rows stay unverified even on a full match.
	legacyTenant := tenantID + "P"
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')
	`, legacyTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at
		) VALUES ($1,$2,'req-presence-legacy','metering','legacy','presence-model',5,3,'CNY','unpriced',NOW())
	`, "usage_fact_presence_"+tenantID, legacyTenant); err != nil {
		t.Fatal(err)
	}
	legacy, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: legacyTenant, UserID: "", RequestID: "req-presence-legacy", ModelName: "presence-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 5, OutputTokens: 3},
		AdmittedAt: time.Now().UTC(), RawUsage: []byte(`{"usage_source":"upstream"}`),
	})
	if err != nil {
		t.Fatalf("legacy replay must stay compatible: %v", err)
	}
	if legacy.EvidenceVerified {
		t.Fatal("a pre-942 row can never be evidence-verified")
	}
}

// The caller's admitted_at PRESENCE is persisted (migration 942,
// admitted_at_supplied) because the timestamp value alone cannot express
// intent: a store-defaulted time is a real time. These cases pin all four
// directions against a real PostgreSQL, including the two that must conflict.
func TestMeteringAdmittedAtPresenceIsPersistedAndComparedBothWays(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	suppliedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)

	t.Run("both supplied and equal replays idempotently", func(t *testing.T) {
		input := MeteringInput{
			TenantID: tenantID, UserID: userID, RequestID: "req-pres-both", ModelName: "pres-model",
			RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 1},
			AdmittedAt: suppliedAt,
			RawUsage:   []byte(`{"usage_source":"upstream"}`),
		}
		first, err := store.RecordMeteringUsage(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if !first.EvidenceVerified {
			t.Fatal("a supplied, fully compared first write must be verified")
		}
		replay, err := store.RecordMeteringUsage(ctx, input)
		if err != nil || replay.ID != first.ID || !replay.EvidenceVerified {
			t.Fatalf("replay=%+v err=%v want the same verified fact", replay, err)
		}
		// The presence bit really is in the row, not just in memory.
		var persisted *bool
		if err := db.QueryRow(ctx,
			`SELECT admitted_at_supplied FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`,
			tenantID, "req-pres-both").Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if persisted == nil || !*persisted {
			t.Fatalf("persisted admitted_at_supplied=%v want true", persisted)
		}
	})

	t.Run("both omitted reuses the first default", func(t *testing.T) {
		input := MeteringInput{
			TenantID: tenantID, UserID: userID, RequestID: "req-pres-neither", ModelName: "pres-model",
			RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 1},
			// AdmittedAt zero: the store defaults it and derives presence=false.
			RawUsage: []byte(`{"usage_source":"upstream"}`),
		}
		first, err := store.RecordMeteringUsage(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if !first.EvidenceVerified {
			t.Fatal("a matching absence is a compared input; it must verify")
		}
		time.Sleep(2 * time.Millisecond)
		replay, err := store.RecordMeteringUsage(ctx, input)
		if err != nil {
			t.Fatalf("both-omitted replay must reuse the first default: %v", err)
		}
		if replay.ID != first.ID {
			t.Fatalf("replay produced a different fact: %+v vs %+v", replay, first)
		}
		if !replay.AdmittedAt.Equal(first.AdmittedAt) {
			t.Fatalf("defaulted timestamp drifted: %v vs %v", replay.AdmittedAt, first.AdmittedAt)
		}
		if !replay.EvidenceVerified {
			t.Fatal("replaying the same absence is still a full-input match")
		}
		var persisted *bool
		if err := db.QueryRow(ctx,
			`SELECT admitted_at_supplied FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`,
			tenantID, "req-pres-neither").Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if persisted == nil || *persisted {
			t.Fatalf("persisted admitted_at_supplied=%v want false (not NULL)", persisted)
		}
	})

	t.Run("supplied then omitted conflicts", func(t *testing.T) {
		first := MeteringInput{
			TenantID: tenantID, UserID: userID, RequestID: "req-pres-to-less", ModelName: "pres-model",
			RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 1},
			AdmittedAt: suppliedAt,
			RawUsage:   []byte(`{"usage_source":"upstream"}`),
		}
		if _, err := store.RecordMeteringUsage(ctx, first); err != nil {
			t.Fatal(err)
		}
		omitted := first
		omitted.AdmittedAt = time.Time{}
		if _, err := store.RecordMeteringUsage(ctx, omitted); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("supplied->omitted err=%v want ErrIdempotencyConflict", err)
		}
	})

	t.Run("omitted then supplied conflicts", func(t *testing.T) {
		first := MeteringInput{
			TenantID: tenantID, UserID: userID, RequestID: "req-pres-less-to", ModelName: "pres-model",
			RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 1},
			RawUsage: []byte(`{"usage_source":"upstream"}`),
		}
		if _, err := store.RecordMeteringUsage(ctx, first); err != nil {
			t.Fatal(err)
		}
		supplied := first
		supplied.AdmittedAt = suppliedAt
		if _, err := store.RecordMeteringUsage(ctx, supplied); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("omitted->supplied err=%v want ErrIdempotencyConflict", err)
		}
	})

	t.Run("both supplied but different conflicts", func(t *testing.T) {
		first := MeteringInput{
			TenantID: tenantID, UserID: userID, RequestID: "req-pres-diff", ModelName: "pres-model",
			RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 1},
			AdmittedAt: suppliedAt,
			RawUsage:   []byte(`{"usage_source":"upstream"}`),
		}
		if _, err := store.RecordMeteringUsage(ctx, first); err != nil {
			t.Fatal(err)
		}
		changed := first
		changed.AdmittedAt = suppliedAt.Add(time.Hour)
		if _, err := store.RecordMeteringUsage(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("different supplied time err=%v want ErrIdempotencyConflict", err)
		}
	})
}

// A NULL presence bit means the row predates the column. It must never be
// coerced to false or backfilled: the row stays an honestly unverified legacy
// fact while remaining replay-compatible.
func TestMeteringNullPresenceBitStaysLegacyUnverified(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	legacyTenant := tenantID + "N"
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`,
		legacyTenant); err != nil {
		t.Fatal(err)
	}
	// A 942-era row: request_status present but admitted_at_supplied NULL.
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at,
			request_status,admitted_at,raw_usage_json
		) VALUES ($1,$2,'req-null-presence','metering','legacy','null-presence-model',
		          2,1,'CNY','unpriced',NOW(),'success',$3,$4)
	`, "usage_fact_nullpres_"+tenantID, legacyTenant, time.Now().UTC().Truncate(time.Microsecond),
		`{"usage_source":"upstream"}`); err != nil {
		t.Fatal(err)
	}
	var before *bool
	if err := db.QueryRow(ctx,
		`SELECT admitted_at_supplied FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`,
		legacyTenant, "req-null-presence").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != nil {
		t.Fatalf("fixture must start NULL, got %v", *before)
	}
	// Replaying the same input stays compatible and honestly unverified.
	fact, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: legacyTenant, UserID: "", RequestID: "req-null-presence", ModelName: "null-presence-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 1},
		AdmittedAt: time.Now().UTC(),
		RawUsage:   []byte(`{"usage_source":"upstream"}`),
	})
	if err != nil {
		t.Fatalf("legacy replay must stay compatible: %v", err)
	}
	if fact.EvidenceVerified {
		t.Fatal("a NULL presence bit can never be reported as verified")
	}
	// The read must not have backfilled the bit.
	var after *bool
	if err := db.QueryRow(ctx,
		`SELECT admitted_at_supplied FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`,
		legacyTenant, "req-null-presence").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != nil {
		t.Fatalf("presence bit was fabricated on a legacy row: %v", *after)
	}
}

// A raw usage blob that is NULL on both sides is an explicitly compared
// absence (PostgreSQL decides it), not an unchecked field. This is what lets a
// metering call that carries no evidence blob replay cleanly while still being
// distinguishable from a call that carries a DIFFERENT blob.
func TestMeteringNullRawUsageIsExplicitlyCompared(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	base := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-null-raw", ModelName: "null-raw-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 1},
		AdmittedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond),
		// RawUsage intentionally absent on both sides.
	}
	first, err := store.RecordMeteringUsage(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.RecordMeteringUsage(ctx, base)
	if err != nil {
		t.Fatalf("both-absent raw usage must replay cleanly: %v", err)
	}
	if replay.ID != first.ID {
		t.Fatalf("replay produced a different fact: %+v vs %+v", replay, first)
	}
	// A blob appearing on the replay is a real difference in the input.
	withBlob := base
	withBlob.RawUsage = []byte(`{"usage_source":"upstream"}`)
	if _, err := store.RecordMeteringUsage(ctx, withBlob); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("absent->present raw usage err=%v want ErrIdempotencyConflict", err)
	}
}

// A fresh Store over the same database (as after a process restart) must reach
// the same idempotency verdict: the decision is made from the persisted
// evidence, not from anything cached in the Store value.
func TestMeteringPresenceVerdictSurvivesNewStoreOverSameDatabase(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	suppliedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	supplied := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-restart", ModelName: "restart-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 3, OutputTokens: 2},
		AdmittedAt: suppliedAt,
		RawUsage:   []byte(`{"usage_source":"upstream"}`),
	}
	first, err := store.RecordMeteringUsage(ctx, supplied)
	if err != nil {
		t.Fatal(err)
	}
	// A brand new Store value over the same pool, as a restarted process would
	// build: no in-memory carry-over of the first write.
	restarted := &Store{db: db, defaultCurrency: store.DefaultCurrency(), redemptionPrefix: store.redemptionPrefix}
	replay, err := restarted.RecordMeteringUsage(ctx, supplied)
	if err != nil {
		t.Fatalf("replay through a new Store: %v", err)
	}
	if replay.ID != first.ID || !replay.EvidenceVerified {
		t.Fatalf("new-Store replay=%+v want the same verified fact %+v", replay, first)
	}
	// And the mismatch verdict is identical across the restart too.
	changed := supplied
	changed.AdmittedAt = time.Time{}
	if _, err := restarted.RecordMeteringUsage(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("new-Store mismatch err=%v want ErrIdempotencyConflict", err)
	}
}

// Old code never names the four evidence columns, so it must still work
// unchanged against the 942 schema. This writes a row the way the pre-942
// INSERT did — omitting every evidence column — and then reads it back through
// the current store.
func TestOldCodeInsertShapeWorksAgainst942Schema(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	legacyTenant := tenantID + "O"
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`,
		legacyTenant); err != nil {
		t.Fatal(err)
	}
	// Exactly the pre-942 column list: no request_status, no admitted_at, no
	// raw_usage_json, no admitted_at_supplied. All four must default to NULL.
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at
		) VALUES ($1,$2,'req-oldcode','metering','legacy','oldcode-model',4,2,'CNY','settled',NOW())
	`, "usage_fact_oldcode_"+tenantID, legacyTenant); err != nil {
		t.Fatalf("old-code INSERT shape must still succeed: %v", err)
	}
	var requestStatus *string
	var admittedAt *time.Time
	var rawUsage []byte
	var supplied *bool
	if err := db.QueryRow(ctx, `
		SELECT request_status, admitted_at, raw_usage_json, admitted_at_supplied
		FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2
	`, legacyTenant, "req-oldcode").Scan(&requestStatus, &admittedAt, &rawUsage, &supplied); err != nil {
		t.Fatal(err)
	}
	if requestStatus != nil || admittedAt != nil || rawUsage != nil || supplied != nil {
		t.Fatalf("old-code insert must leave all four columns NULL: status=%v admitted=%v raw=%v supplied=%v",
			requestStatus, admittedAt, rawUsage, supplied)
	}
	// And the current store reads that row as the legacy family comparison,
	// unverified, without erroring.
	fact, err := store.RecordMeteringUsage(ctx, MeteringInput{
		TenantID: legacyTenant, UserID: "", RequestID: "req-oldcode", ModelName: "oldcode-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 4, OutputTokens: 2},
		AdmittedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("old-code row replay: %v", err)
	}
	if fact.EvidenceVerified {
		t.Fatal("an old-code row must never be reported as evidence-verified")
	}
}

// A metering input that omits admitted_at must still replay idempotently. The
// store defaults the missing timestamp for storage, but a defaulted now() must
// stay out of the idempotency fingerprint: comparing it would make every
// genuine replay of the same input differ and report a false conflict, which
// would drop a real measurement on any gateway retry that does not echo
// admitted_at back.
func TestMeteringReplayWithoutAdmittedAtIsIdempotent(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	input := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-metering-no-admitted", ModelName: "no-admitted-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 4, OutputTokens: 2},
		RawUsage: []byte(`{"usage_source":"upstream"}`),
	}
	first, err := store.RecordMeteringUsage(ctx, input)
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	if first.AdmittedAt.IsZero() {
		t.Fatal("stored fact must carry the defaulted admitted_at")
	}
	// A short gap guarantees the two defaulting calls differ at nanosecond
	// precision, so a fingerprint including the default would conflict.
	time.Sleep(2 * time.Millisecond)
	replay, err := store.RecordMeteringUsage(ctx, input)
	if err != nil {
		t.Fatalf("replay without admitted_at must not conflict: %v", err)
	}
	if replay.ID != first.ID {
		t.Fatalf("replay returned a different fact: %+v vs %+v", replay, first)
	}
	// The durable fact wins: the replay reports the FIRST write's timestamp, not
	// a recomputed one.
	if !replay.AdmittedAt.Equal(first.AdmittedAt) {
		t.Fatalf("replay admitted_at drifted: %v vs first %v", replay.AdmittedAt, first.AdmittedAt)
	}
	// The first write OMITTED the timestamp, so a replay that supplies one is
	// the conflict direction: caller intent changed even though the value could
	// have been made to match.
	supplied := input
	supplied.AdmittedAt = first.AdmittedAt
	if _, err := store.RecordMeteringUsage(ctx, supplied); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("omitted->supplied replay err=%v want ErrIdempotencyConflict", err)
	}
}

// A replayed metering input must return the persisted result — including the
// attribution and price snapshot taken at first write — and a different input
// under the same request key must be rejected as a conflict.
func TestMeteringReplayReturnsPersistedSnapshotAndConflictsOnDifferentInput(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	// PostgreSQL stores TIMESTAMPTZ at microsecond precision and the store
	// normalizes inputs to that precision, so the fixture pre-truncates.
	admittedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	input := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-metering-idem", ModelName: "idem-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 7, OutputTokens: 3},
		AdmittedAt: admittedAt,
		RawUsage:   []byte(`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":7}}`),
	}
	fact, err := store.RecordMeteringUsage(ctx, input)
	if err != nil || fact.Status != "unpriced" || fact.BillableAmountMicros != nil {
		t.Fatalf("first fact=%+v err=%v", fact, err)
	}
	if !fact.AdmittedAt.Equal(admittedAt) {
		t.Fatalf("admitted_at drift: fact=%v input=%v", fact.AdmittedAt, admittedAt)
	}
	// A price created after the first recording must not change the replayed
	// snapshot: the durable fact wins over recomputation.
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "idem-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.RecordMeteringUsage(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ID != fact.ID || replayed.Status != "unpriced" || replayed.BillableAmountMicros != nil {
		t.Fatalf("replayed fact drifted: %+v first=%+v", replayed, fact)
	}
	if !replayed.EvidenceVerified {
		t.Fatal("post-942 replay must carry EvidenceVerified=true")
	}
	conflicting := input
	conflicting.Usage = Usage{PromptTokens: 9, OutputTokens: 3}
	if _, err := store.RecordMeteringUsage(ctx, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting input err=%v want ErrIdempotencyConflict", err)
	}
	// Full-input idempotency: the same token evidence but a different outcome
	// family (failed vs success) is a different input and must conflict.
	statusConflicting := input
	statusConflicting.RequestStatus = "failed"
	if _, err := store.RecordMeteringUsage(ctx, statusConflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("status-family replay err=%v want ErrIdempotencyConflict", err)
	}
	// The raw request status is persisted since migration 942, so even a
	// same-family but different raw status conflicts.
	rawStatusConflicting := input
	rawStatusConflicting.RequestStatus = "incomplete"
	if _, err := store.RecordMeteringUsage(ctx, rawStatusConflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("raw-status replay err=%v want ErrIdempotencyConflict", err)
	}
	// A changed usage_source evidence is a different input.
	sourceConflicting := input
	sourceConflicting.RawUsage = []byte(`{"usage_source":"estimated_reservation"}`)
	if _, err := store.RecordMeteringUsage(ctx, sourceConflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("usage-source replay err=%v want ErrIdempotencyConflict", err)
	}
	// A missing raw usage on the replay can never pass against a fact that
	// carries one.
	rawMissing := input
	rawMissing.RawUsage = nil
	if _, err := store.RecordMeteringUsage(ctx, rawMissing); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("raw-usage-missing replay err=%v want ErrIdempotencyConflict", err)
	}
	// A different admitted_at is a different input.
	admittedChanged := input
	admittedChanged.AdmittedAt = admittedAt.Add(time.Second)
	if _, err := store.RecordMeteringUsage(ctx, admittedChanged); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("admitted-at replay err=%v want ErrIdempotencyConflict", err)
	}
	// Dropping the timestamp on a replay whose first write supplied one is also
	// a different input.
	admittedDropped := input
	admittedDropped.AdmittedAt = time.Time{}
	if _, err := store.RecordMeteringUsage(ctx, admittedDropped); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("admitted-at dropped replay err=%v want ErrIdempotencyConflict", err)
	}
	// Semantically identical raw usage with reordered JSON keys is the same
	// input: canonical comparison must accept it.
	keyOrderEqual := input
	keyOrderEqual.RawUsage = []byte(`{"upstream_usage":{"prompt_tokens":7},"usage_source":"upstream"}`)
	keyOrderReplay, err := store.RecordMeteringUsage(ctx, keyOrderEqual)
	if err != nil || keyOrderReplay.ID != fact.ID || !keyOrderReplay.EvidenceVerified {
		t.Fatalf("key-order-equal replay=%+v err=%v", keyOrderReplay, err)
	}
	// Pre-942 legacy fact (NULL evidence columns) stays conservatively
	// accepted: same family, same token evidence, no conflict despite the
	// missing columns.
	legacyTenant := tenantID + "L"
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')
	`, legacyTenant); err != nil {
		t.Fatal(err)
	}
	legacyFactID := "usage_fact_legacy_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,model_name,
			prompt_tokens,output_tokens,currency,status,occurred_at
		) VALUES ($1,$2,'req-metering-legacy','metering','legacy','idem-model',7,3,'CNY','unpriced',NOW())
	`, legacyFactID, legacyTenant); err != nil {
		t.Fatal(err)
	}
	legacyInput := MeteringInput{
		TenantID: legacyTenant, UserID: "", RequestID: "req-metering-legacy", ModelName: "idem-model",
		RequestStatus: "incomplete", Usage: Usage{PromptTokens: 7, OutputTokens: 3},
		AdmittedAt: time.Now().UTC(),
	}
	legacy, err := store.RecordMeteringUsage(ctx, legacyInput)
	if err != nil || legacy.ID != legacyFactID {
		t.Fatalf("legacy fact replay=%+v err=%v want id=%s", legacy, err, legacyFactID)
	}
	// A legacy fact is accepted conservatively from its derived status only:
	// the result is explicitly marked as not fully evidence-verified.
	if legacy.EvidenceVerified {
		t.Fatal("legacy fact replay must carry EvidenceVerified=false")
	}
}

// Two concurrent writers replaying DIFFERENT inputs under the same
// (tenant, request) key: exactly one durably wins, the other gets a conflict,
// and the surviving fact keeps the winner's snapshot. No third fact may be
// created and no update may partially apply.
func TestMeteringConcurrentDifferentInputsExactlyOneWins(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	requestID := "req-metering-race"
	base := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: requestID, ModelName: "race-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 7, OutputTokens: 3},
		AdmittedAt: time.Now().UTC().Truncate(time.Microsecond),
		RawUsage:   []byte(`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":7}}`),
	}
	other := base
	other.Usage = Usage{PromptTokens: 11, OutputTokens: 3}
	other.RawUsage = []byte(`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":11}}`)

	const workers = 8
	results := make(chan error, workers)
	won := make(chan *UsageFact, workers)
	for i := 0; i < workers; i++ {
		input := base
		if i%2 == 1 {
			input = other
		}
		go func(in MeteringInput) {
			fact, err := store.RecordMeteringUsage(ctx, in)
			if err != nil {
				results <- err
				return
			}
			won <- fact
			results <- nil
		}(input)
	}
	succeeded := 0
	conflicted := 0
	var winnerID string
	for i := 0; i < workers; i++ {
		err := <-results
		switch {
		case err == nil:
			succeeded++
			fact := <-won
			if winnerID == "" {
				winnerID = fact.ID
			} else if fact.ID != winnerID {
				t.Fatalf("two distinct facts won: %s and %s", winnerID, fact.ID)
			}
		case errors.Is(err, ErrIdempotencyConflict):
			conflicted++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded < 1 || succeeded+conflicted != workers {
		t.Fatalf("succeeded=%d conflicted=%d workers=%d", succeeded, conflicted, workers)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("facts=%d want exactly 1", count)
	}
}

// The evidence fingerprint must preserve the exact numeric literals of the
// raw usage JSON: decoding into float64 would rewrite large integers (beyond
// 2^53) and turn a byte-identical replay into a false conflict.
func TestMeteringReplayKeepsLargeIntegerPrecisionInRawUsage(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	raw := []byte(`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":9007199254740993,"output_tokens":3}}`)
	input := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-metering-bigint", ModelName: "bigint-model",
		RequestStatus: "success", Usage: Usage{PromptTokens: 7, OutputTokens: 3},
		AdmittedAt: time.Now().UTC().Truncate(time.Microsecond),
		RawUsage:   raw,
	}
	if _, err := store.RecordMeteringUsage(ctx, input); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.RecordMeteringUsage(ctx, input)
	if err != nil {
		t.Fatalf("byte-identical replay with large integers must be accepted, got %v", err)
	}
	if !replayed.EvidenceVerified {
		t.Fatal("exact replay must carry EvidenceVerified=true")
	}
	// A one-unit difference in a large integer is a real difference and must
	// still be detected: float64-based comparison would miss it.
	tampered := MeteringInput(input)
	tampered.RawUsage = []byte(`{"usage_source":"upstream","upstream_usage":{"prompt_tokens":9007199254740994,"output_tokens":3}}`)
	if _, err := store.RecordMeteringUsage(ctx, tampered); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("tampered large-integer replay err=%v want ErrIdempotencyConflict", err)
	}
}
