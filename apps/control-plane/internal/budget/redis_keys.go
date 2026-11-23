package budget

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// scope: tenant | team | project | user | key

// DefaultQuotaTimezone is the accounting timezone used when a scope has no
// policy (or the policy leaves quota_timezone empty).
const DefaultQuotaTimezone = "Asia/Shanghai"

// BudgetKey returns the monthly budget hash key for a given scope.
// yyyymm must already carry the timezone suffix from QuotaPeriodBucket.
func BudgetKey(scope, id, yyyymm string) string {
	return fmt.Sprintf("budget:%s:%s:%s", scope, id, yyyymm)
}

// BudgetKeyDay returns the daily budget hash key for a given scope.
func BudgetKeyDay(scope, id, yyyymmdd string) string {
	return fmt.Sprintf("budget:%s:%s:%s", scope, id, yyyymmdd)
}

// NormalizedQuotaTimezone mirrors gateway-core providers.normalizedQuotaTimezone.
func NormalizedQuotaTimezone(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return DefaultQuotaTimezone
	}
	return value
}

// QuotaPeriodBucket mirrors gateway-core providers.quotaPeriodBucket: the
// Asia/Shanghai bucket is the bare period, every other timezone gets an
// "@<sha256(tz)[:6] hex>" suffix so buckets of different timezones never mix.
func QuotaPeriodBucket(timezone, period string) string {
	timezone = NormalizedQuotaTimezone(timezone)
	if timezone == DefaultQuotaTimezone {
		return period
	}
	digest := sha256.Sum256([]byte(timezone))
	return period + "@" + hex.EncodeToString(digest[:6])
}

// OrgQuotaKeyPrefix mirrors gateway-core providers.atomicKeyPrefix.
func OrgQuotaKeyPrefix(tenantID string) string {
	digest := sha256.Sum256([]byte(tenantID))
	return "orgquota:{" + hex.EncodeToString(digest[:8]) + "}:"
}

// RpmKey returns the per-minute request counter (STRING) written by
// gateway-core AtomicAdmission for scopes whose policy sets rpm_limit.
func RpmKey(tenantID, scope, id string, minuteBucket int64) string {
	return fmt.Sprintf("%srpm:%s:%s:%d", OrgQuotaKeyPrefix(tenantID), scope, base64.RawURLEncoding.EncodeToString([]byte(id)), minuteBucket)
}

// ConcurrencyKey returns the in-flight lease ZSET (score = lease expiry in
// Unix ms) written by gateway-core AtomicAdmission for scopes whose policy
// sets concurrency_limit.
func ConcurrencyKey(tenantID, scope, id string) string {
	return fmt.Sprintf("%sconcurrency:%s:%s", OrgQuotaKeyPrefix(tenantID), scope, base64.RawURLEncoding.EncodeToString([]byte(id)))
}

// PauseKey returns the Redis key that marks a key-prefix as paused.
func PauseKey(keyPrefix string) string {
	return fmt.Sprintf("pause:%s", keyPrefix)
}
