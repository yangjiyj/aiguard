package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	PricingModeDirect      = "direct"
	PricingModeNewAPIRatio = "newapi_ratio"
	PriceStatusDraft       = "draft"
	PriceStatusActive      = "active"
	PriceStatusRetired     = "retired"
)

var ErrPriceNotFound = errors.New("billing model price not found")

// ErrPriceCurrencyMismatch 表示准入价格与系统计价币种不一致。
var ErrPriceCurrencyMismatch = errors.New("model price currency differs from system currency")

// ErrPriceCurrencyUnsupported rejects prices outside the single billing currency.
var ErrPriceCurrencyUnsupported = errors.New("billing price currency is not the billing currency")

type NewModelPrice struct {
	TenantID      string
	ModelName     string
	CustomerGroup string
	PricingMode   string
	Currency      string
	DirectPrice   DirectPrice
	Extensions    PriceExtensions
	RatioPrice    RatioPrice
	Status        string
	EffectiveAt   time.Time
	ExpiresAt     *time.Time
	CreatedBy     string
}

type ModelPrice struct {
	ID            string
	TenantID      string
	ModelName     string
	CustomerGroup string
	Version       int
	PricingMode   string
	Currency      string
	DirectPrice   DirectPrice
	Extensions    PriceExtensions
	RatioPrice    RatioPrice
	Status        string
	EffectiveAt   time.Time
	ExpiresAt     *time.Time
	CreatedBy     string
	CreatedAt     time.Time
}

func (p ModelPrice) AsDirectPrice() (DirectPrice, error) {
	switch p.PricingMode {
	case PricingModeDirect:
		if err := validateDirectPrice(p.DirectPrice); err != nil {
			return DirectPrice{}, err
		}
		price := p.DirectPrice
		price.Extensions = p.Extensions
		return price, nil
	case PricingModeNewAPIRatio:
		price, err := NormalizeNewAPIRatioPrice(p.RatioPrice)
		price.Extensions = p.Extensions
		return price, err
	default:
		return DirectPrice{}, ErrInvalidPrice
	}
}

// CreateModelPrice 总是追加一个新版本，不做清零/重复检查；管理接口应使用 SaveModelPrice。
func (s *Store) CreateModelPrice(ctx context.Context, input NewModelPrice) (*ModelPrice, error) {
	result, err := s.saveModelPrice(ctx, input, nil)
	if err != nil {
		return nil, err
	}
	return result.Price, nil
}

// saveModelPrice 是价格写入的唯一实现。opts 为 nil 时不做防护（保持 CreateModelPrice 的原语义）。
func (s *Store) saveModelPrice(ctx context.Context, input NewModelPrice, opts *SavePriceOptions) (*SavePriceResult, error) {
	normalized, err := normalizeNewModelPrice(input, s.defaultCurrency)
	if err != nil {
		return nil, err
	}
	// 价格表只追加：补录一个更早生效的版本会悄悄改写已经计费的那段历史（也会让列表和计费选价不一致）。
	// 管理接口一律拒绝过去的生效时间，只留约 60 秒时钟误差，保证「立即生效」不被误拒。
	if opts != nil && !input.EffectiveAt.IsZero() && input.EffectiveAt.Before(time.Now().UTC().Add(-PriceEffectiveSkew)) {
		return nil, ErrPriceEffectiveInPast
	}
	if err := s.EnsureDefaultCustomerGroup(ctx, normalized.TenantID); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin create billing model price: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+normalized.TenantID); err != nil {
		return nil, err
	}
	cfg, err := s.employeeSettings(ctx, tx, normalized.TenantID)
	if err != nil {
		return nil, err
	}
	var currencyConfigured, currentPricesExist bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_employee_settings WHERE tenant_id=$1) OR EXISTS(SELECT 1 FROM billing_employee_allowances WHERE tenant_id=$1 AND monthly_micros>0) OR EXISTS(SELECT 1 FROM billing_wallets w WHERE w.tenant_id=$1 AND `+fundedWalletPredicate+`), EXISTS(SELECT 1 FROM billing_model_prices WHERE tenant_id=$1 AND customer_group='default' AND status='active' AND effective_at<=NOW() AND (expires_at IS NULL OR expires_at>NOW()))`, normalized.TenantID).Scan(&currencyConfigured, &currentPricesExist); err != nil {
		return nil, err
	}
	if input.Currency == "" || currencyConfigured || currentPricesExist {
		cfg.Currency, err = s.billingCurrencyForTenant(ctx, tx, normalized.TenantID)
		if errors.Is(err, ErrMixedCurrency) && input.Currency != "" && !currencyConfigured {
			// Legacy mixed prices may only be repaired by versioning an existing
			// model into an already effective denomination. New models/currencies
			// and ambiguous implicit prices remain rejected.
			var repairAllowed bool
			if queryErr := tx.QueryRow(ctx, `WITH current_prices AS (SELECT DISTINCT ON(model_name) model_name,currency FROM billing_model_prices WHERE tenant_id=$1 AND customer_group='default' AND status='active' AND effective_at<=NOW() AND (expires_at IS NULL OR expires_at>NOW()) ORDER BY model_name,effective_at DESC,version DESC) SELECT EXISTS(SELECT 1 FROM current_prices WHERE model_name=$2) AND EXISTS(SELECT 1 FROM current_prices WHERE currency=$3)`, normalized.TenantID, normalized.ModelName, normalized.Currency).Scan(&repairAllowed); queryErr != nil {
				return nil, queryErr
			}
			if repairAllowed {
				cfg.Currency, err = normalized.Currency, nil
			}
		}
		if err != nil {
			return nil, err
		}
		if input.Currency == "" {
			normalized.Currency = cfg.Currency
		}
		if (currencyConfigured || currentPricesExist) && cfg.Currency != normalized.Currency {
			return nil, ErrAllowanceCurrency
		}
	}
	lockKey := fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(normalized.TenantID), normalized.TenantID,
		len(normalized.ModelName), normalized.ModelName, len(normalized.CustomerGroup), normalized.CustomerGroup)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return nil, fmt.Errorf("lock billing model price version: %w", err)
	}
	// 防护必须在版本锁之后判断：并发提交同一份价格时，后到的提交会看到先到的版本而成为空操作。
	var previous *ModelPrice
	var zeroConfirmed bool
	if opts != nil && normalized.Status == PriceStatusActive {
		// 生效时刻晚于现在的定时版本，比较的是它将要替换的那个版本。
		at := time.Now().UTC()
		if normalized.EffectiveAt.After(at) {
			at = normalized.EffectiveAt
		}
		previous, err = currentModelPriceAt(ctx, tx, normalized.TenantID, normalized.ModelName, at)
		if err != nil {
			return nil, fmt.Errorf("load current billing model price: %w", err)
		}
		if samePriceTerms(previous, normalized) {
			result := &SavePriceResult{Price: previous, Previous: previous, Unchanged: true}
			if audit := opts.Audit; audit != nil && audit.UnchangedAction != "" {
				// 没有新增版本，只留一条非关键审计，方便事后看到「有人提交了相同价格」。
				detail := audit.Detail(PriceAuditRecord{Price: previous, Previous: previous})
				if result.AuditID, err = insertPriceAudit(ctx, tx, normalized.TenantID, audit.ActorUserID, audit.IPAddress,
					audit.UnchangedAction, detail, previous.ID); err != nil {
					return nil, err
				}
				result.AuditAction, result.AuditDetail = audit.UnchangedAction, detail
				if err := tx.Commit(ctx); err != nil {
					return nil, fmt.Errorf("commit billing price unchanged audit: %w", err)
				}
			}
			return result, nil
		}
		if zeroesPrice(previous, normalized) {
			if !opts.ConfirmZeroPrice {
				zeroErr := &ZeroPriceError{Previous: *previous, Attempted: normalized}
				if audit := opts.Audit; audit != nil && audit.ZeroRejectedAction != "" && audit.RejectedDetail != nil {
					// 拒绝没有写任何价格，事务会回滚；拦截审计在自己的事务里落库，保证「谁试图清零」不丢。
					zeroErr.AuditDetail = audit.RejectedDetail(zeroErr)
					if zeroErr.AuditID, err = insertPriceAudit(ctx, s.db, normalized.TenantID, audit.ActorUserID, audit.IPAddress,
						audit.ZeroRejectedAction, zeroErr.AuditDetail, previous.ID); err != nil {
						return nil, err
					}
				}
				return nil, zeroErr
			}
			zeroConfirmed = true
		}
	}
	var version int
	if err := tx.QueryRow(ctx, `
        SELECT COALESCE(MAX(version), 0) + 1
        FROM billing_model_prices
        WHERE tenant_id = $1 AND model_name = $2 AND customer_group = $3
    `, normalized.TenantID, normalized.ModelName, normalized.CustomerGroup).Scan(&version); err != nil {
		return nil, fmt.Errorf("next billing model price version: %w", err)
	}

	price := &ModelPrice{
		ID: "price_" + uuid.NewString(), TenantID: normalized.TenantID,
		ModelName: normalized.ModelName, CustomerGroup: normalized.CustomerGroup,
		Version: version, PricingMode: normalized.PricingMode, Currency: normalized.Currency,
		DirectPrice: normalized.DirectPrice, RatioPrice: normalized.RatioPrice, Extensions: normalized.Extensions,
		Status: normalized.Status, EffectiveAt: normalized.EffectiveAt,
		ExpiresAt: normalized.ExpiresAt, CreatedBy: normalized.CreatedBy,
	}
	columns := priceColumns(price)
	err = tx.QueryRow(ctx, `
        INSERT INTO billing_model_prices (
            id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
            input_per_million_micros, cached_input_per_million_micros,
            cache_write_per_million_micros, output_per_million_micros,
            base_input_per_million_micros, model_ratio_ppm, completion_ratio_ppm,
            group_ratio_ppm, cached_input_ratio_ppm, cache_write_ratio_ppm,
            status, effective_at, expires_at, created_by, pricing_extras
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NULLIF($21,''),$22::jsonb
        ) RETURNING created_at
    `, price.ID, price.TenantID, price.ModelName, price.CustomerGroup, price.Version,
		price.PricingMode, price.Currency,
		columns.input, columns.cachedInput, columns.cacheWrite, columns.output,
		columns.baseInput, columns.modelRatio, columns.completionRatio, columns.groupRatio,
		columns.cachedRatio, columns.cacheWriteRatio,
		price.Status, price.EffectiveAt, price.ExpiresAt, price.CreatedBy, jsonObject(price.Extensions),
	).Scan(&price.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert billing model price: %w", err)
	}
	// 写入系统币种的新版本时，旧币种价格退出当前目录，历史引用仍然保留。
	if price.Currency == cfg.Currency {
		tag, retireErr := tx.Exec(ctx, `UPDATE billing_model_prices SET status='retired',expires_at=CASE WHEN effective_at<NOW() THEN NOW() ELSE expires_at END WHERE tenant_id=$1 AND model_name=$2 AND currency<>$3 AND status='active'`, price.TenantID, price.ModelName, price.Currency)
		if retireErr != nil {
			return nil, fmt.Errorf("退役旧币种价格：%w", retireErr)
		}
		if tag.RowsAffected() > 0 {
			detail, marshalErr := json.Marshal(map[string]any{"model_name": price.ModelName, "currency": price.Currency, "retired_count": tag.RowsAffected(), "price_id": price.ID})
			if marshalErr != nil {
				return nil, marshalErr
			}
			auditID := uuid.NewString()
			if _, auditErr := tx.Exec(ctx, `INSERT INTO audit_operations(id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address) VALUES($1,$2,NULLIF($3,''),'billing.price.retire_other_currencies',$4::jsonb,'billing_model_price',$5,'')`, auditID, price.TenantID, price.CreatedBy, detail, price.ID); auditErr != nil {
				return nil, fmt.Errorf("记录价格退役审计：%w", auditErr)
			}
			// 作废其他币种价格是关键审计：审计链与价格变更同一事务，写不进去则整体回滚。
			if chainErr := s.appendAuditChainTx(ctx, tx, price.TenantID, auditID, map[string]any{
				"action_type": "billing.price.retire_other_currencies", "tenant_id": price.TenantID,
				"actor_user_id": price.CreatedBy, "model_name": price.ModelName, "currency": price.Currency,
				"retired_count": tag.RowsAffected(), "price_id": price.ID,
			}); chainErr != nil {
				return nil, fmt.Errorf("写入价格退役审计链：%w", chainErr)
			}
		}
	}
	result := &SavePriceResult{Price: price, Previous: previous, ZeroConfirmed: zeroConfirmed}
	if opts != nil && opts.Audit != nil && opts.Audit.CreateAction != "" {
		// 审计与价格同一个事务：审计写不进去，价格也不会留下，调用方会看到错误而不是静默丢审计。
		audit := opts.Audit
		detail := audit.Detail(PriceAuditRecord{Price: price, Previous: previous, ZeroConfirmed: zeroConfirmed})
		if result.AuditID, err = insertPriceAudit(ctx, tx, price.TenantID, audit.ActorUserID, audit.IPAddress,
			audit.CreateAction, detail, price.ID); err != nil {
			return nil, err
		}
		result.AuditAction, result.AuditDetail = audit.CreateAction, detail
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit billing model price: %w", err)
	}
	return result, nil
}

// resolveModelPriceSQL 选出某时刻对租户/模型生效的价格版本（$1 租户、$2 模型、$3 时刻）。
// 租户明确设置了币种时优先该币种；没有设置（历史安装）时沿用最近生效、版本最高的旧顺序，混币也不报错。
// ResolveModelPrice 与写入防护共用，保证防护比较的就是计费实际使用的版本。
const resolveModelPriceSQL = `
        SELECT id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
               COALESCE(input_per_million_micros, -1),
               COALESCE(cached_input_per_million_micros, -1),
               COALESCE(cache_write_per_million_micros, -1),
               COALESCE(output_per_million_micros, -1),
               COALESCE(base_input_per_million_micros, -1),
               COALESCE(model_ratio_ppm, -1),
               COALESCE(completion_ratio_ppm, -1),
               COALESCE(group_ratio_ppm, -1),
               COALESCE(cached_input_ratio_ppm, -1),
               COALESCE(cache_write_ratio_ppm, -1),
               status, effective_at, expires_at, COALESCE(created_by, ''), created_at, pricing_extras
        FROM billing_model_prices
        WHERE tenant_id = $1 AND model_name = $2 AND status = 'active'
          AND customer_group = 'default'
          AND effective_at <= $3 AND (expires_at IS NULL OR expires_at > $3)
        ORDER BY COALESCE(currency = (SELECT s.currency FROM billing_employee_settings s WHERE s.tenant_id = $1), false) DESC,
                 effective_at DESC, version DESC
        LIMIT 1
    `

func (s *Store) ResolveModelPrice(ctx context.Context, tenantID, modelName, _ string, at time.Time) (*ModelPrice, error) {
	if tenantID == "" || modelName == "" {
		return nil, ErrInvalidPrice
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	price, err := scanModelPrice(s.db.QueryRow(ctx, resolveModelPriceSQL, tenantID, modelName, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPriceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve billing model price: %w", err)
	}
	return price, nil
}

// GetModelPriceByID returns the historic price version referenced by an
// existing reservation. Retired versions remain chargeable for that purpose.
func (s *Store) GetModelPriceByID(ctx context.Context, tenantID, priceID string) (*ModelPrice, error) {
	if tenantID == "" || priceID == "" {
		return nil, ErrInvalidPrice
	}
	price, err := scanModelPrice(s.db.QueryRow(ctx, `
        SELECT id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
               COALESCE(input_per_million_micros, -1),
               COALESCE(cached_input_per_million_micros, -1),
               COALESCE(cache_write_per_million_micros, -1),
               COALESCE(output_per_million_micros, -1),
               COALESCE(base_input_per_million_micros, -1),
               COALESCE(model_ratio_ppm, -1), COALESCE(completion_ratio_ppm, -1),
               COALESCE(group_ratio_ppm, -1), COALESCE(cached_input_ratio_ppm, -1),
               COALESCE(cache_write_ratio_ppm, -1), status, effective_at, expires_at,
               COALESCE(created_by, ''), created_at, pricing_extras
        FROM billing_model_prices
        WHERE tenant_id = $1 AND id = $2
    `, tenantID, priceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPriceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get billing model price: %w", err)
	}
	return price, nil
}

func normalizeNewModelPrice(input NewModelPrice, defaultCurrency string) (NewModelPrice, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ModelName = strings.TrimSpace(input.ModelName)
	if input.TenantID == "" || input.ModelName == "" {
		return NewModelPrice{}, ErrInvalidPrice
	}
	input.CustomerGroup = DefaultCustomerGroup
	if input.Currency == "" {
		input.Currency = defaultCurrency
	}
	if !currencyPattern.MatchString(input.Currency) {
		return NewModelPrice{}, ErrInvalidPrice
	}
	input.Currency = strings.ToUpper(strings.TrimSpace(input.Currency))
	if input.Currency != "CNY" && input.Currency != "USD" {
		return NewModelPrice{}, ErrPriceCurrencyUnsupported
	}
	if err := input.Extensions.Validate(); err != nil {
		return NewModelPrice{}, err
	}
	if input.Status == "" {
		input.Status = PriceStatusActive
	}
	if input.Status != PriceStatusDraft && input.Status != PriceStatusActive && input.Status != PriceStatusRetired {
		return NewModelPrice{}, ErrInvalidPrice
	}
	if input.EffectiveAt.IsZero() {
		input.EffectiveAt = time.Now().UTC()
	} else {
		input.EffectiveAt = input.EffectiveAt.UTC()
	}
	if input.ExpiresAt != nil {
		expires := input.ExpiresAt.UTC()
		input.ExpiresAt = &expires
		if !expires.After(input.EffectiveAt) {
			return NewModelPrice{}, ErrInvalidPrice
		}
	}
	switch input.PricingMode {
	case PricingModeDirect:
		if err := validateDirectPrice(input.DirectPrice); err != nil {
			return NewModelPrice{}, err
		}
	case PricingModeNewAPIRatio:
		input.RatioPrice.GroupRatioPPM = ratioScale
		input.RatioPrice.HasCachedInputRatio = input.RatioPrice.HasCachedInputRatio || input.RatioPrice.CachedInputRatioPPM != 0
		input.RatioPrice.HasCacheWriteRatio = input.RatioPrice.HasCacheWriteRatio || input.RatioPrice.CacheWriteRatioPPM != 0
		if _, err := NormalizeNewAPIRatioPrice(input.RatioPrice); err != nil {
			return NewModelPrice{}, err
		}
	default:
		return NewModelPrice{}, ErrInvalidPrice
	}
	return input, nil
}

type persistedPriceColumns struct {
	input, cachedInput, cacheWrite, output                                           any
	baseInput, modelRatio, completionRatio, groupRatio, cachedRatio, cacheWriteRatio any
}

func priceColumns(price *ModelPrice) persistedPriceColumns {
	if price.PricingMode == PricingModeDirect {
		columns := persistedPriceColumns{
			input:  int64(price.DirectPrice.InputPerMillionMicros),
			output: int64(price.DirectPrice.OutputPerMillionMicros),
		}
		if price.DirectPrice.HasCachedInputPrice {
			columns.cachedInput = int64(price.DirectPrice.CachedInputPerMillionMicros)
		}
		if price.DirectPrice.HasCacheWritePrice {
			columns.cacheWrite = int64(price.DirectPrice.CacheWritePerMillionMicros)
		}
		return columns
	}
	columns := persistedPriceColumns{
		baseInput:       int64(price.RatioPrice.BaseInputPerMillionMicros),
		modelRatio:      price.RatioPrice.ModelRatioPPM,
		completionRatio: price.RatioPrice.CompletionRatioPPM,
		groupRatio:      price.RatioPrice.GroupRatioPPM,
	}
	if price.RatioPrice.HasCachedInputRatio {
		columns.cachedRatio = price.RatioPrice.CachedInputRatioPPM
	}
	if price.RatioPrice.HasCacheWriteRatio {
		columns.cacheWriteRatio = price.RatioPrice.CacheWriteRatioPPM
	}
	return columns
}

func scanModelPrice(row rowScanner) (*ModelPrice, error) {
	price := &ModelPrice{}
	var extras []byte
	var input, cachedInput, cacheWrite, output int64
	var baseInput, modelRatio, completionRatio, groupRatio, cachedRatio, cacheWriteRatio int64
	err := row.Scan(
		&price.ID, &price.TenantID, &price.ModelName, &price.CustomerGroup,
		&price.Version, &price.PricingMode, &price.Currency,
		&input, &cachedInput, &cacheWrite, &output,
		&baseInput, &modelRatio, &completionRatio, &groupRatio, &cachedRatio, &cacheWriteRatio,
		&price.Status, &price.EffectiveAt, &price.ExpiresAt, &price.CreatedBy, &price.CreatedAt, &extras,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(extras, &price.Extensions); err != nil {
		return nil, err
	}
	if price.PricingMode == PricingModeDirect {
		price.DirectPrice = DirectPrice{
			InputPerMillionMicros: Micros(input), OutputPerMillionMicros: Micros(output),
			HasCachedInputPrice: cachedInput >= 0, HasCacheWritePrice: cacheWrite >= 0,
		}
		if cachedInput >= 0 {
			price.DirectPrice.CachedInputPerMillionMicros = Micros(cachedInput)
		}
		if cacheWrite >= 0 {
			price.DirectPrice.CacheWritePerMillionMicros = Micros(cacheWrite)
		}
	} else {
		price.RatioPrice = RatioPrice{
			BaseInputPerMillionMicros: Micros(baseInput), ModelRatioPPM: modelRatio,
			CompletionRatioPPM: completionRatio, GroupRatioPPM: groupRatio,
			HasCachedInputRatio: cachedRatio >= 0, HasCacheWriteRatio: cacheWriteRatio >= 0,
		}
		if cachedRatio >= 0 {
			price.RatioPrice.CachedInputRatioPPM = cachedRatio
		}
		if cacheWriteRatio >= 0 {
			price.RatioPrice.CacheWriteRatioPPM = cacheWriteRatio
		}
	}
	return price, nil
}
