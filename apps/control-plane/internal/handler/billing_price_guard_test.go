package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 价格写入防护（现场「价格被反复清零」事故的后端防线）：
//  1. 把当前有非零价格的模型改成「输入、输出都为 0」必须显式带 confirm_zero_price=true；
//  2. 与当前生效版本完全相同的提交不再追加新版本（幂等）；
//  3. 审计 action_detail 记录旧值与新值，只含价格数字。

type priceGuardEnv struct {
	t        *testing.T
	store    *billing.Store
	deps     *Dependencies
	db       *pgxpool.Pool
	userID   string
	tenantID string
}

func newPriceGuardEnv(t *testing.T, prefix string) *priceGuardEnv {
	t.Helper()
	db := openBillingHandlerTestDB(t)
	tenantID := billingHandlerTestTenant(t, prefix)
	if _, err := db.Exec(context.Background(), `
		INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')
		ON CONFLICT (id) DO NOTHING
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	// 审计在价格事务里写 audit_operations，user_id 有外键，所以操作人必须是真实用户。
	userID := tenantID + "-admin"
	if _, err := db.Exec(context.Background(), `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($1, $2, $1, $3, 'x', 'platform_admin', 'active')
		ON CONFLICT (id) DO NOTHING
	`, userID, tenantID, userID+"@test.invalid"); err != nil {
		t.Fatal(err)
	}
	store := billing.NewStore(db)
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
	})
	return &priceGuardEnv{t: t, store: store, db: db, userID: userID, tenantID: tenantID,
		deps: &Dependencies{BillingStore: store}}
}

func (e *priceGuardEnv) seedDirect(model, currency string, input, output int64, cachedRead, cacheWrite *int64) *billing.ModelPrice {
	e.t.Helper()
	price := billing.NewModelPrice{
		TenantID: e.tenantID, ModelName: model, CustomerGroup: billing.DefaultCustomerGroup,
		PricingMode: billing.PricingModeDirect, Currency: currency, Status: billing.PriceStatusActive,
		EffectiveAt: time.Now().UTC().Add(-time.Hour), CreatedBy: "seed-admin",
		DirectPrice: billing.DirectPrice{
			InputPerMillionMicros: billing.Micros(input), OutputPerMillionMicros: billing.Micros(output),
		},
	}
	if cachedRead != nil {
		price.DirectPrice.HasCachedInputPrice = true
		price.DirectPrice.CachedInputPerMillionMicros = billing.Micros(*cachedRead)
	}
	if cacheWrite != nil {
		price.DirectPrice.HasCacheWritePrice = true
		price.DirectPrice.CacheWritePerMillionMicros = billing.Micros(*cacheWrite)
	}
	created, err := e.store.CreateModelPrice(context.Background(), price)
	if err != nil {
		e.t.Fatalf("seed price %s: %v", model, err)
	}
	return created
}

func (e *priceGuardEnv) post(h http.HandlerFunc, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	e.t.Helper()
	body["tenant_id"] = e.tenantID
	encoded, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/billing/prices", bytes.NewReader(encoded))
	req = billingHandlerAdminRequest(req, e.userID, e.tenantID, "platform_admin")
	rec := httptest.NewRecorder()
	h(rec, req)
	var decoded map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	return rec, decoded
}

func (e *priceGuardEnv) versions(model string) []billing.ModelPrice {
	e.t.Helper()
	all, err := e.store.ListModelPrices(context.Background(), e.tenantID, 500)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []billing.ModelPrice
	for _, item := range all {
		if item.ModelName == model {
			out = append(out, item)
		}
	}
	return out
}

// auditOps 直接读 audit_operations：审计是价格事务的一部分，不再经过 SystemRepo。
func (e *priceGuardEnv) auditOps(action string) []*repository.AuditOperation {
	e.t.Helper()
	rows, err := e.db.Query(context.Background(),
		`SELECT id, COALESCE(user_id,''), action_type, action_detail, COALESCE(target_id,'') FROM audit_operations WHERE tenant_id=$1 AND action_type=$2 ORDER BY created_at, id`,
		e.tenantID, action)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []*repository.AuditOperation
	for rows.Next() {
		op := &repository.AuditOperation{}
		var raw []byte
		if err := rows.Scan(&op.ID, &op.UserID, &op.ActionType, &raw, &op.TargetID); err != nil {
			e.t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &op.ActionDetail)
		out = append(out, op)
	}
	return out
}

func micros(v int64) *int64 { return &v }

func errorCode(body map[string]any) string {
	detail, _ := body["error"].(map[string]any)
	code, _ := detail["code"].(string)
	return code
}

func errorMessage(body map[string]any) string {
	detail, _ := body["error"].(map[string]any)
	message, _ := detail["message"].(string)
	return message
}

func TestCreateBillingPriceRefusesToZeroNonZeroPriceWithoutConfirmation(t *testing.T) {
	env := newPriceGuardEnv(t, "pzero1")
	env.seedDirect("opus-5-5", "USD", 4_000_000, 20_000_000, micros(200_000), micros(5_000_000))
	handlerFunc := CreateBillingPrice(env.deps)

	rec, body := env.post(handlerFunc, map[string]any{
		"model_name": "opus-5-5", "currency": "USD", "status": "active",
		"input_per_million_micros": 0, "output_per_million_micros": 0,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("zeroing a non-zero price status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	if errorCode(body) != "price_zero_confirmation_required" {
		t.Fatalf("error code = %q, want price_zero_confirmation_required (body=%s)", errorCode(body), rec.Body.String())
	}
	if message := errorMessage(body); !strings.Contains(message, "非零") || !strings.Contains(message, "0") {
		t.Fatalf("error message must explain the refusal in Chinese, got %q", message)
	}
	if got := len(env.versions("opus-5-5")); got != 1 {
		t.Fatalf("refused request must not append a version, versions=%d", got)
	}
	if rejected := env.auditOps("billing.price.zero_rejected"); len(rejected) != 1 {
		t.Fatalf("a refused zeroing attempt must be audited, got %d records", len(rejected))
	}
	if created := env.auditOps("billing.price.create"); len(created) != 0 {
		t.Fatalf("a refused request must not write a create audit, got %d", len(created))
	}
}

func TestCreateBillingPriceAllowsExplicitlyConfirmedZeroPrice(t *testing.T) {
	env := newPriceGuardEnv(t, "pzero2")
	env.seedDirect("opus-5-5", "USD", 4_000_000, 20_000_000, micros(200_000), micros(5_000_000))
	handlerFunc := CreateBillingPrice(env.deps)

	rec, body := env.post(handlerFunc, map[string]any{
		"model_name": "opus-5-5", "currency": "USD", "status": "active",
		"input_per_million_micros": 0, "output_per_million_micros": 0, "confirm_zero_price": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed zero price status=%d body=%s", rec.Code, rec.Body.String())
	}
	data, _ := body["data"].(map[string]any)
	if version, _ := data["version"].(float64); version != 2 {
		t.Fatalf("confirmed zero price version=%v, want 2 (body=%s)", data["version"], rec.Body.String())
	}
	created := env.auditOps("billing.price.create")
	if len(created) != 1 {
		t.Fatalf("create audit records=%d, want 1", len(created))
	}
	if confirmed, _ := created[0].ActionDetail["zero_price_confirmed"].(bool); !confirmed {
		t.Fatalf("audit must record that the zero price was explicitly confirmed: %#v", created[0].ActionDetail)
	}
}

func TestCreateBillingPriceDoesNotGuardFirstPriceOrAlreadyFreeModels(t *testing.T) {
	env := newPriceGuardEnv(t, "pzero3")
	handlerFunc := CreateBillingPrice(env.deps)

	// 没有任何旧价格：首次配置成免费是正常用法。
	rec, _ := env.post(handlerFunc, map[string]any{
		"model_name": "free-model", "currency": "CNY", "status": "active",
		"input_per_million_micros": 0, "output_per_million_micros": 0,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("first free price status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 旧价格本来就是 0：再改成 0 不是「清零」，也不需要确认。
	rec, body := env.post(handlerFunc, map[string]any{
		"model_name": "free-model", "currency": "CNY", "status": "active",
		"input_per_million_micros": 0, "output_per_million_micros": 0,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("free to free status=%d body=%s", rec.Code, rec.Body.String())
	}
	if data, _ := body["data"].(map[string]any); data["unchanged"] != true {
		t.Fatalf("free to free must be an idempotent no-op: %s", rec.Body.String())
	}
}

func TestCreateBillingPriceIsIdempotentForIdenticalTerms(t *testing.T) {
	env := newPriceGuardEnv(t, "pidem1")
	seed := env.seedDirect("haiku-5-5", "USD", 1_000_000, 5_000_000, micros(100_000), micros(1_250_000))
	handlerFunc := CreateBillingPrice(env.deps)
	identical := func() map[string]any {
		return map[string]any{
			"model_name": "haiku-5-5", "currency": "USD", "status": "active",
			"input_per_million_micros": 1_000_000, "output_per_million_micros": 5_000_000,
			"cached_input_per_million_micros": 100_000, "cache_write_per_million_micros": 1_250_000,
		}
	}

	for attempt := 1; attempt <= 3; attempt++ {
		rec, body := env.post(handlerFunc, identical())
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d status=%d body=%s", attempt, rec.Code, rec.Body.String())
		}
		data, _ := body["data"].(map[string]any)
		if data["unchanged"] != true {
			t.Fatalf("attempt %d must report unchanged=true: %s", attempt, rec.Body.String())
		}
		if data["id"] != seed.ID {
			t.Fatalf("attempt %d must return the version already in force (%s), got %v", attempt, seed.ID, data["id"])
		}
	}
	if got := len(env.versions("haiku-5-5")); got != 1 {
		t.Fatalf("identical submissions must not append versions, versions=%d", got)
	}
	if got := len(env.auditOps("billing.price.create")); got != 0 {
		t.Fatalf("a no-op submission changes nothing and must not write a create audit, got %d", got)
	}

	// 只要有一个字段不同（缓存读价），就必须产生新版本。
	changed := identical()
	changed["cached_input_per_million_micros"] = 200_000
	rec, body := env.post(handlerFunc, changed)
	if rec.Code != http.StatusOK {
		t.Fatalf("changed cache price status=%d body=%s", rec.Code, rec.Body.String())
	}
	data, _ := body["data"].(map[string]any)
	if data["unchanged"] == true || data["version"].(float64) != 2 {
		t.Fatalf("a changed field must create version 2: %s", rec.Body.String())
	}
	// 再清空缓存读价（NULL）也是变化。
	cleared := identical()
	delete(cleared, "cached_input_per_million_micros")
	rec, body = env.post(handlerFunc, cleared)
	data, _ = body["data"].(map[string]any)
	if rec.Code != http.StatusOK || data["version"].(float64) != 3 {
		t.Fatalf("dropping the cache read price must create version 3: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateBillingPriceAuditRecordsOldAndNewNumbers(t *testing.T) {
	env := newPriceGuardEnv(t, "paud1")
	env.seedDirect("sonnet-5-5", "USD", 3_000_000, 15_000_000, micros(300_000), micros(3_750_000))
	handlerFunc := CreateBillingPrice(env.deps)

	rec, _ := env.post(handlerFunc, map[string]any{
		"model_name": "sonnet-5-5", "currency": "USD", "status": "active",
		"input_per_million_micros": 2_000_000, "output_per_million_micros": 10_000_000,
		"cached_input_per_million_micros": 200_000, "cache_write_per_million_micros": 2_500_000,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("price update status=%d body=%s", rec.Code, rec.Body.String())
	}
	ops := env.auditOps("billing.price.create")
	if len(ops) != 1 {
		t.Fatalf("create audit records=%d, want 1", len(ops))
	}
	detail := ops[0].ActionDetail
	oldValues, _ := detail["old"].(map[string]any)
	newValues, _ := detail["new"].(map[string]any)
	if oldValues == nil || newValues == nil {
		t.Fatalf("audit detail must carry old and new snapshots: %#v", detail)
	}
	wantOld := map[string]int64{
		"input_per_million_micros": 3_000_000, "cached_input_per_million_micros": 300_000,
		"cache_write_per_million_micros": 3_750_000, "output_per_million_micros": 15_000_000,
	}
	wantNew := map[string]int64{
		"input_per_million_micros": 2_000_000, "cached_input_per_million_micros": 200_000,
		"cache_write_per_million_micros": 2_500_000, "output_per_million_micros": 10_000_000,
	}
	for key, want := range wantOld {
		if got, ok := numeric(oldValues[key]); !ok || got != want {
			t.Fatalf("audit old.%s = %v, want %d (old=%#v)", key, oldValues[key], want, oldValues)
		}
	}
	for key, want := range wantNew {
		if got, ok := numeric(newValues[key]); !ok || got != want {
			t.Fatalf("audit new.%s = %v, want %d (new=%#v)", key, newValues[key], want, newValues)
		}
	}
	for _, snapshot := range []map[string]any{oldValues, newValues} {
		if snapshot["currency"] != "USD" || snapshot["pricing_mode"] != billing.PricingModeDirect {
			t.Fatalf("snapshots must record currency and pricing mode: %#v", snapshot)
		}
	}
	if detail["model_name"] != "sonnet-5-5" || detail["old_version"] == nil {
		t.Fatalf("audit must keep the original keys and add old_version: %#v", detail)
	}
	if summary, _ := detail["change_summary"].(string); !strings.Contains(summary, "输入") || !strings.Contains(summary, "→") {
		t.Fatalf("audit should carry a readable Chinese change summary, got %q", summary)
	}
	encoded, _ := json.Marshal(detail)
	for _, forbidden := range []string{"api_key", "secret", "password", "token\":\"", "authorization"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("audit detail must only contain price numbers, found %q in %s", forbidden, encoded)
		}
	}
}

func TestCreateBillingPriceAuditMarksFirstVersionWithoutOldValues(t *testing.T) {
	env := newPriceGuardEnv(t, "paud2")
	handlerFunc := CreateBillingPrice(env.deps)
	rec, _ := env.post(handlerFunc, map[string]any{
		"model_name": "brand-new", "currency": "CNY", "status": "active",
		"input_per_million_micros": 1_000_000, "output_per_million_micros": 2_000_000,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("first version status=%d body=%s", rec.Code, rec.Body.String())
	}
	ops := env.auditOps("billing.price.create")
	if len(ops) != 1 {
		t.Fatalf("audit records=%d", len(ops))
	}
	if old, present := ops[0].ActionDetail["old"]; present && old != nil {
		t.Fatalf("first version has no previous price, old must be absent/null: %#v", old)
	}
	if _, ok := ops[0].ActionDetail["new"].(map[string]any); !ok {
		t.Fatalf("first version must still record the new snapshot: %#v", ops[0].ActionDetail)
	}
}

func TestCreateBillingRatioPriceHasTheSameGuards(t *testing.T) {
	env := newPriceGuardEnv(t, "prat1")
	handlerFunc := CreateBillingRatioPrice(env.deps)
	ratio := func(base int64, modelRatio int64) map[string]any {
		return map[string]any{
			"model_name": "ratio-model", "currency": "USD", "status": "active",
			"base_input_per_million_micros": base, "model_ratio_ppm": modelRatio, "completion_ratio_ppm": 5_000_000,
		}
	}
	rec, _ := env.post(handlerFunc, ratio(2_000_000, 1_000_000))
	if rec.Code != http.StatusOK {
		t.Fatalf("first ratio price status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 基础价为 0 → 折算后输入、输出都是 0。
	rec, body := env.post(handlerFunc, ratio(0, 1_000_000))
	if rec.Code != http.StatusConflict || errorCode(body) != "price_zero_confirmation_required" {
		t.Fatalf("zero base ratio price status=%d body=%s, want 409 price_zero_confirmation_required", rec.Code, rec.Body.String())
	}
	// 模型倍率为 0 同样折算成 0。
	rec, body = env.post(handlerFunc, ratio(2_000_000, 0))
	if rec.Code != http.StatusConflict || errorCode(body) != "price_zero_confirmation_required" {
		t.Fatalf("zero model ratio status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	// 相同参数重复提交是空操作。
	rec, body = env.post(handlerFunc, ratio(2_000_000, 1_000_000))
	if data, _ := body["data"].(map[string]any); rec.Code != http.StatusOK || data["unchanged"] != true {
		t.Fatalf("identical ratio price status=%d body=%s, want unchanged", rec.Code, rec.Body.String())
	}
	if got := len(env.versions("ratio-model")); got != 1 {
		t.Fatalf("ratio versions=%d, want 1", got)
	}
	// 带确认标志可以改成 0。
	confirmed := ratio(0, 1_000_000)
	confirmed["confirm_zero_price"] = true
	rec, _ = env.post(handlerFunc, confirmed)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed zero ratio price status=%d body=%s", rec.Code, rec.Body.String())
	}
	ops := env.auditOps("billing.ratio_price.create")
	if len(ops) != 2 {
		t.Fatalf("ratio create audit records=%d, want 2 (first + confirmed zero)", len(ops))
	}
	last := ops[len(ops)-1].ActionDetail
	if _, ok := last["old"].(map[string]any); !ok {
		t.Fatalf("ratio audit must carry the old snapshot: %#v", last)
	}
	if newValues, _ := last["new"].(map[string]any); newValues == nil || newValues["pricing_mode"] != billing.PricingModeNewAPIRatio {
		t.Fatalf("ratio audit must carry the new snapshot with its pricing mode: %#v", last["new"])
	}
}

func numeric(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}

// 被拦截的清零尝试与真正的价格变更一样是关键审计：同步写入审计链，不因队列满而丢失，
// 失败时有「关键审计写入失败」告警；在告警里按「修改价格」归类。
func TestPriceZeroRejectedIsACriticalAuditAction(t *testing.T) {
	if !isCriticalAudit("billing.price.zero_rejected", nil) {
		t.Fatal("a refused price-zeroing attempt must be a critical audit event")
	}
	if label := auditActionLabel("billing.price.zero_rejected"); label != "修改价格" {
		t.Fatalf("alert label = %q, want 修改价格", label)
	}
}

// ---- 审查返工：同事务审计、过去生效时间、未变化审计 ----

func TestCreateBillingPriceRejectsEffectiveTimeInThePast(t *testing.T) {
	env := newPriceGuardEnv(t, "ppast1")
	env.seedDirect("opus-5-5", "USD", 4_000_000, 20_000_000, nil, nil)
	for name, handlerFunc := range map[string]http.HandlerFunc{"direct": CreateBillingPrice(env.deps), "ratio": CreateBillingRatioPrice(env.deps)} {
		body := map[string]any{"model_name": "opus-5-5", "currency": "USD", "status": "active",
			"effective_at": time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)}
		if name == "ratio" {
			body["base_input_per_million_micros"], body["model_ratio_ppm"], body["completion_ratio_ppm"] = 2_000_000, 1_000_000, 5_000_000
		} else {
			body["input_per_million_micros"], body["output_per_million_micros"] = 9_000_000, 9_000_000
		}
		rec, decoded := env.post(handlerFunc, body)
		if rec.Code != http.StatusBadRequest || errorCode(decoded) != "price_effective_at_in_past" {
			t.Fatalf("%s: status=%d body=%s, want 400 price_effective_at_in_past", name, rec.Code, rec.Body.String())
		}
		if message := errorMessage(decoded); !strings.Contains(message, "生效时间") {
			t.Fatalf("%s: message must be Chinese and name the field, got %q", name, message)
		}
	}
	if got := len(env.versions("opus-5-5")); got != 1 {
		t.Fatalf("a refused backdated price must not add a version, versions=%d", got)
	}
	// 60 秒内的时钟误差与将来时间都能通过。
	handlerFunc := CreateBillingPrice(env.deps)
	for _, offset := range []time.Duration{-30 * time.Second, time.Hour} {
		rec, _ := env.post(handlerFunc, map[string]any{"model_name": "opus-5-5", "currency": "USD", "status": "active",
			"input_per_million_micros": 3_000_000 + int64(offset/time.Second), "output_per_million_micros": 9_000_000,
			"effective_at": time.Now().UTC().Add(offset).Format(time.RFC3339)})
		if rec.Code != http.StatusOK {
			t.Fatalf("offset %s must be accepted, status=%d body=%s", offset, rec.Code, rec.Body.String())
		}
	}
}

func TestCreateBillingPriceWritesAuditInThePriceTransaction(t *testing.T) {
	env := newPriceGuardEnv(t, "ptx1")
	env.seedDirect("sonnet-5-5", "USD", 3_000_000, 15_000_000, nil, nil)
	// 审计已经在价格事务里落库：handler 不再用 SystemRepo 补写第二条（避免重复）。
	rec, _ := env.post(CreateBillingPrice(env.deps), map[string]any{"model_name": "sonnet-5-5", "currency": "USD", "status": "active",
		"input_per_million_micros": 2_000_000, "output_per_million_micros": 10_000_000})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var count int
	var detail string
	if err := env.db.QueryRow(context.Background(), `SELECT COUNT(*), COALESCE(MAX(action_detail::text),'') FROM audit_operations WHERE tenant_id=$1 AND action_type='billing.price.create'`, env.tenantID).Scan(&count, &detail); err != nil {
		t.Fatal(err)
	}
	if count != 1 || !strings.Contains(detail, "change_summary") || !strings.Contains(detail, "old_version") {
		t.Fatalf("the audit row must be committed with the price (count=%d detail=%s)", count, detail)
	}
}

func TestCreateBillingPriceFailsLoudlyWhenAuditCannotBeWritten(t *testing.T) {
	env := newPriceGuardEnv(t, "ptx2")
	handlerFunc := CreateBillingPrice(env.deps)
	body, _ := json.Marshal(map[string]any{"tenant_id": env.tenantID, "model_name": "audit-fail", "currency": "CNY", "status": "active",
		"input_per_million_micros": 1_000_000, "output_per_million_micros": 2_000_000})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/billing/prices", bytes.NewReader(body))
	// 操作人不在 users 表：审计的外键失败 → 价格必须一起回滚，且不能返回成功。
	req = billingHandlerAdminRequest(req, "ghost-user-not-in-users", env.tenantID, "platform_admin")
	rec := httptest.NewRecorder()
	handlerFunc(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("a failed audit write must not report success: %s", rec.Body.String())
	}
	if got := len(env.versions("audit-fail")); got != 0 {
		t.Fatalf("the price must be rolled back with its audit, versions=%d", got)
	}
}

func TestCreateBillingPriceAuditsUnchangedSubmissionsAsNonCritical(t *testing.T) {
	env := newPriceGuardEnv(t, "punc1")
	env.seedDirect("haiku-5-5", "USD", 1_000_000, 5_000_000, nil, nil)
	rec, body := env.post(CreateBillingPrice(env.deps), map[string]any{"model_name": "haiku-5-5", "currency": "USD", "status": "active",
		"input_per_million_micros": 1_000_000, "output_per_million_micros": 5_000_000})
	if data, _ := body["data"].(map[string]any); rec.Code != http.StatusOK || data["unchanged"] != true {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created, unchanged int
	if err := env.db.QueryRow(context.Background(), `SELECT COUNT(*) FILTER (WHERE action_type='billing.price.create'), COUNT(*) FILTER (WHERE action_type='billing.price.unchanged') FROM audit_operations WHERE tenant_id=$1`, env.tenantID).Scan(&created, &unchanged); err != nil {
		t.Fatal(err)
	}
	if created != 0 || unchanged != 1 {
		t.Fatalf("an unchanged submission leaves one billing.price.unchanged and no create record, got create=%d unchanged=%d", created, unchanged)
	}
	if isCriticalAudit("billing.price.unchanged", nil) {
		t.Fatal("an unchanged submission is not a critical audit event")
	}
}
