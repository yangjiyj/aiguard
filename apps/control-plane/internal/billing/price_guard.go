package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// 价格写入防护。
//
// 现场事故：价格表被控制台批量套价反复写成「输入=输出=0」。价格表是版本化、只追加的，
// 所以防护只能放在「写新版本之前」：
//  1. 把一个当前有非零价格的模型改成「输入、输出都为 0」，必须带显式确认；
//  2. 与当前生效版本完全相同的提交不再追加新版本（幂等）；
//  3. 把写入前后的价格交还调用方，由审计记录「旧值→新值」。
//
// 这些检查都在同一个事务内、持有「租户+模型+客户组」咨询锁之后执行，
// 并发提交相同价格只会产生一个版本。草稿与已停用版本不参与计费，因此不受这两条规则约束。

// ErrZeroPriceNotConfirmed 表示本次提交会把非零价格改成 0，但没有带确认标志。
var ErrZeroPriceNotConfirmed = errors.New("billing price change would zero a non-zero price without confirmation")

// ErrPriceEffectiveInPast 表示新价格的生效时间早于当前时间（超出时钟误差）。
// 价格表只追加，补录一个更早生效的版本会悄悄改写已经计费的那段历史，所以拒绝。
var ErrPriceEffectiveInPast = errors.New("billing price effective_at is in the past")

// PriceEffectiveSkew 是允许的时钟误差：控制台与服务端时间略有差异时，不应误拒「立即生效」。
const PriceEffectiveSkew = 60 * time.Second

// ZeroPriceError 携带被拒绝提交的上下文，供 handler 生成中文提示并写审计链。
type ZeroPriceError struct {
	// Previous 是拒绝时正在生效的版本。
	Previous ModelPrice
	// Attempted 是被拒绝的新价格（已规范化）。
	Attempted NewModelPrice
	// AuditID 是已落库的「清零被拦截」审计记录 id；未配置审计时为空。
	AuditID string
	// AuditDetail 是已落库的审计详情，供 handler 写入审计链。
	AuditDetail map[string]any
}

func (e *ZeroPriceError) Error() string { return ErrZeroPriceNotConfirmed.Error() }

func (e *ZeroPriceError) Unwrap() error { return ErrZeroPriceNotConfirmed }

// PriceAuditRecord 是组装审计详情所需的上下文。
type PriceAuditRecord struct {
	Price         *ModelPrice
	Previous      *ModelPrice
	ZeroConfirmed bool
}

// PriceAuditSpec 描述价格写入要在「同一个事务」里写的审计。审计只记价格数字，不含任何密钥。
// 价格写入和审计要么一起提交，要么一起回滚；审计写不进去时价格也不会留下。
type PriceAuditSpec struct {
	ActorUserID string
	IPAddress   string
	// CreateAction 是新版本落库时的审计动作，例如 billing.price.create。
	CreateAction string
	// Detail 组装新版本的审计详情。
	Detail func(PriceAuditRecord) map[string]any
	// UnchangedAction 非空时，「价格没变、没有新增版本」也记一条审计（非关键）。
	UnchangedAction string
	// ZeroRejectedAction / RejectedDetail 非空时，清零被拦截也会在独立事务里落一条审计。
	ZeroRejectedAction string
	RejectedDetail     func(*ZeroPriceError) map[string]any
}

// SavePriceOptions 控制 SaveModelPrice 的安全检查。
type SavePriceOptions struct {
	// ConfirmZeroPrice 允许把非零价格改成 0。它只能来自操作员的明确确认，不能有默认值。
	ConfirmZeroPrice bool
	// Audit 非空时，审计与价格在同一个事务里写入。
	Audit *PriceAuditSpec
}

// SavePriceResult 描述一次价格写入实际做了什么。
type SavePriceResult struct {
	// Price 是本次提交对应的版本：新写入的版本，或（Unchanged 时）已在生效的版本。
	Price *ModelPrice
	// Previous 是写入前正在生效的版本；此前没有价格时为 nil。
	Previous *ModelPrice
	// Unchanged 为 true 表示价格与生效版本完全相同，没有写入新版本。
	Unchanged bool
	// ZeroConfirmed 为 true 表示本次把非零价格改成了 0，且操作员已显式确认。
	ZeroConfirmed bool
	// AuditID / AuditAction / AuditDetail 是已随价格一起提交的审计记录，供 handler 写入审计链。
	AuditID     string
	AuditAction string
	AuditDetail map[string]any
}

// insertPriceAudit 在给定事务（或连接）上写一条 audit_operations。
// user_id 是 users(id) 外键，空串落 NULL；target_id 列长 64，价格 id 远小于此。
func insertPriceAudit(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, tenantID, actor, ip, action string, detail map[string]any, targetID string) (string, error) {
	payload, err := json.Marshal(detail)
	if err != nil {
		return "", fmt.Errorf("encode billing price audit: %w", err)
	}
	id := uuid.NewString()
	if _, err := q.Exec(ctx, `INSERT INTO audit_operations(id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address)
		VALUES($1,$2,NULLIF($3,''),$4,$5::jsonb,'billing_model_price',$6,$7)`, id, tenantID, actor, action, payload, targetID, ip); err != nil {
		return "", fmt.Errorf("write billing price audit: %w", err)
	}
	return id, nil
}

// SaveModelPrice 在 CreateModelPrice 的基础上增加价格防护。管理接口必须用它；
// CreateModelPrice 保持原语义（总是追加版本），仅供测试夹具与内部种子数据使用。
func (s *Store) SaveModelPrice(ctx context.Context, input NewModelPrice, opts SavePriceOptions) (*SavePriceResult, error) {
	return s.saveModelPrice(ctx, input, &opts)
}

// currentModelPriceAt 返回 at 时刻对租户/模型生效的价格版本，没有时返回 nil。
// 与 ResolveModelPrice 共用同一条 SQL，保证防护比较的就是计费实际使用的版本。
func currentModelPriceAt(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantID, modelName string, at time.Time) (*ModelPrice, error) {
	price, err := scanModelPrice(q.QueryRow(ctx, resolveModelPriceSQL, tenantID, modelName, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return price, nil
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// samePriceTerms 判断新价格的计费条款是否与已生效版本完全相同。
// 只比较会影响计费的字段：计价模式、币种、各档单价/倍率（含「未设置」与「设置为 0」的区别）、附加收费、失效时间。
func samePriceTerms(prev *ModelPrice, next NewModelPrice) bool {
	if prev == nil {
		return false
	}
	if prev.PricingMode != next.PricingMode || prev.Currency != next.Currency || prev.CustomerGroup != next.CustomerGroup {
		return false
	}
	if !sameExpiry(prev.ExpiresAt, next.ExpiresAt) || jsonObject(prev.Extensions) != jsonObject(next.Extensions) {
		return false
	}
	switch next.PricingMode {
	case PricingModeDirect:
		a, b := prev.DirectPrice, next.DirectPrice
		return a.InputPerMillionMicros == b.InputPerMillionMicros &&
			a.OutputPerMillionMicros == b.OutputPerMillionMicros &&
			a.HasCachedInputPrice == b.HasCachedInputPrice &&
			(!a.HasCachedInputPrice || a.CachedInputPerMillionMicros == b.CachedInputPerMillionMicros) &&
			a.HasCacheWritePrice == b.HasCacheWritePrice &&
			(!a.HasCacheWritePrice || a.CacheWritePerMillionMicros == b.CacheWritePerMillionMicros)
	case PricingModeNewAPIRatio:
		a, b := prev.RatioPrice, next.RatioPrice
		return a.BaseInputPerMillionMicros == b.BaseInputPerMillionMicros &&
			a.ModelRatioPPM == b.ModelRatioPPM &&
			a.CompletionRatioPPM == b.CompletionRatioPPM &&
			a.GroupRatioPPM == b.GroupRatioPPM &&
			a.HasCachedInputRatio == b.HasCachedInputRatio &&
			(!a.HasCachedInputRatio || a.CachedInputRatioPPM == b.CachedInputRatioPPM) &&
			a.HasCacheWriteRatio == b.HasCacheWriteRatio &&
			(!a.HasCacheWriteRatio || a.CacheWriteRatioPPM == b.CacheWriteRatioPPM)
	}
	return false
}

// effectiveDirectPrice 把新价格折算成计费实际使用的直接单价（倍率模式按基础价×倍率折算）。
// 客户组倍率在价格表里恒为 1（规范化时固定），这里同样固定，避免未规范化输入把结果误算成 0。
func effectiveDirectPrice(next NewModelPrice) (DirectPrice, error) {
	if next.PricingMode == PricingModeNewAPIRatio {
		ratio := next.RatioPrice
		ratio.GroupRatioPPM = ratioScale
		return NormalizeNewAPIRatioPrice(ratio)
	}
	return next.DirectPrice, nil
}

// zeroesPrice 判断这次提交是否把「有非零输入或输出价」的生效版本改成「输入、输出都为 0」。
// 旧价格本来就是 0 时不算清零；折算失败的新价格交给后续校验处理，这里不拦。
func zeroesPrice(prev *ModelPrice, next NewModelPrice) bool {
	if prev == nil {
		return false
	}
	if old, err := prev.AsDirectPrice(); err == nil && old.InputPerMillionMicros == 0 && old.OutputPerMillionMicros == 0 {
		return false
	}
	now, err := effectiveDirectPrice(next)
	if err != nil {
		return false
	}
	return now.InputPerMillionMicros == 0 && now.OutputPerMillionMicros == 0
}
