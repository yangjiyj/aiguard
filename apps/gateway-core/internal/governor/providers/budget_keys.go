// Package providers contains gateway-core-local copies of budget helper types.
// gateway-core cannot import apps/control-plane/internal/budget directly
// (apps must not cross-import each other), so we maintain a minimal copy here.
package providers

import "fmt"

// scope: tenant | team | project | user | key

// BudgetKey returns the monthly budget hash key for a given scope.
func BudgetKey(scope, id, yyyymm string) string {
	return fmt.Sprintf("budget:%s:%s:%s", scope, id, yyyymm)
}

// BudgetKeyDay returns the daily budget hash key for a given scope.
func BudgetKeyDay(scope, id, yyyymmdd string) string {
	return fmt.Sprintf("budget:%s:%s:%s", scope, id, yyyymmdd)
}
